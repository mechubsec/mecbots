"""socbot (daily): the security side of the last 24h from SSDF: alerts grouped by signature,
severity and observing firewall (🆕 for a signature not seen before), the sources and
destinations with the most denied flows, and firewalls or ingest subjects that went quiet
(a firewall that stopped logging is a finding).
Only aggregates are posted, never raw log lines.
It also writes an escalation queue (at most 3 items) that socagent investigates; see escalations()."""

import fcntl
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
from mcp import mcp_call_tools  # noqa: E402

SSDF_MCP = os.environ.get("SOCBOT_MCP", "ssdf")  # MCP server name in the Hermes config; give it its own read-only token
# (tools used: alert_counts, query_flows, ingest_status, fabric_status)
STATE = Path(os.environ.get("SOCBOT_STATE", Path.home() / ".local/state/labbots/socbot.json"))
# the queue socagent reads: at most MAX_ESCALATIONS items, rewritten every successful run
ESCALATIONS = Path(os.environ.get("SOCBOT_ESCALATIONS", Path.home() / ".local/state/labbots/socbot-escalations.json"))
MAX_ESCALATIONS = 3
ESCALATE_SEVERITIES = ("critical", "high")  # new-high-alert: a NEW alert group at one of these severities
DENY_SPIKE_FACTOR, DENY_SPIKE_MIN = 3, 100  # deny-spike: total denies >= 3x the previous run's total and >= 100
QUIET_ESCALATE_HOURS = 6  # firewall-quiet: logging at the previous run, now quiet longer than this (and not long-quiet)
# highest first: a critical or high new alert, then a deny spike, then a quiet firewall
ESCALATION_PRIORITY = {"new-high-alert": 0, "deny-spike": 1, "firewall-quiet": 2}
# a signature unseen this long is forgotten, so its return counts as new
FORGET_SECONDS = 30 * 86400
LONG_QUIET_HOURS = 48
SHOWN = 10
# SRX: flow_session_deny; PAN-OS traffic logs become "flow_" + subtype (flow_deny, flow_drop)
DENY_ACTIONS = ("flow_session_deny", "flow_deny", "flow_drop")
DENY_LIMIT = 1000
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def unwrap(value):
    """SSDF wraps log-derived text as {value, truncated, untrusted}; socbot handles it as plain text."""
    return value["value"] if isinstance(value, dict) and "value" in value else value


def checked(tool: str, reply: dict) -> dict:
    """The tool reply; an {error} reply raises instead of reading as a night with nothing to report."""
    if "error" in reply:
        raise RuntimeError(f"{tool}: {reply['error']}: {str(reply.get('detail', ''))[:150]}")
    return reply


def safe(text: str, limit: int = 80) -> str:
    """Log text as inert Discord text: no mentions, code spans or control characters."""
    text = re.sub(r"[\x00-\x1f\x7f`]", " ", str(text)).replace("@", "@​")
    return text[:limit] + ("…" if len(text) > limit else "")


def group_alerts(rows: list[dict]) -> list[dict]:
    """alert_counts rows as [{signature, severity, observer, count}], worst severity then biggest count first.
    Rows sharing signature, severity and observer (different providers) are summed into one group."""
    counts = Counter()
    for row in rows:
        counts[(str(unwrap(row["signature"])), str(row["severity"]).lower(), str(unwrap(row["observer"])))] += int(row["count"])
    groups = [{"signature": signature, "severity": severity, "observer": observer, "count": count}
              for (signature, severity, observer), count in counts.items()]
    return sorted(groups, key=lambda group: (SEVERITY_ORDER.get(group["severity"], 9), -group["count"], group["signature"]))


def classify_signatures(groups: list[dict], known: dict, now: float, baseline: bool) -> tuple[set, dict]:
    """Return (new signatures, known'): the signatures not in the memory (none on the baseline run,
    which learns them all) and the memory updated and pruned of those unseen for 30 days."""
    known = {signature: seen for signature, seen in known.items() if now - seen <= FORGET_SECONDS}
    new = set() if baseline else {group["signature"] for group in groups if group["signature"] not in known}
    known.update({group["signature"]: now for group in groups})
    return new, known


def top_denied(rows: list[dict], side: str) -> list[tuple[str, int]]:
    """The most common source_ip or destination_ip (side) among denied flow rows."""
    return Counter(str(unwrap(row[side])) for row in rows if row.get(side)).most_common(5)


def quiet_subjects(ingest: dict, fabric: dict) -> tuple[list[str], list[str]]:
    """(🔇 lines for firewalls/subjects stale for less than 2 days, names stale for longer).
    A switched-off lab is flagged until it is 2 days quiet, then stays info."""
    stale = [(item["name"], item.get("hours_since"), item.get("provider") or item.get("kind") or "")
             for item in ingest.get("firewalls", []) + fabric.get("subjects", []) if item.get("stale")]
    recent = [f"🔇 {safe(name, 40)}{f' ({safe(kind, 20)})' if kind else ''}: "
              + (f"last event {hours:.0f}h ago" if isinstance(hours, (int, float)) else "no event seen")
              for name, hours, kind in stale if not isinstance(hours, (int, float)) or hours <= LONG_QUIET_HOURS]
    long_quiet = [safe(name, 40) for name, hours, _ in stale if isinstance(hours, (int, float)) and hours > LONG_QUIET_HOURS]
    return recent, sorted(set(long_quiet))


def plain(text, limit: int = 200) -> str:
    """Log-derived text for the escalation queue: control characters removed, capped; no other change."""
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(text))[:limit]


def escalations(run: dict, previous: dict | None) -> list[dict]:
    """The items socbot hands to socagent, [{id, kind, summary, facts}], at most MAX_ESCALATIONS, most urgent first.
    Deterministic: only socbot's own structured findings. `previous` is the last run's snapshot (see snapshot); the
    baseline run, and a run with no previous, escalate nothing (everything is new on a first night)."""
    if run["baseline"] or previous is None:
        return []
    found = []
    for group in run["alerts"]:
        if group["signature"] in run["new"] and group["severity"] in ESCALATE_SEVERITIES:
            found.append((ESCALATION_PRIORITY["new-high-alert"], SEVERITY_ORDER[group["severity"]], "new-high-alert",
                          f"new {group['severity']} alert x{group['count']} on {safe(group['observer'], 40)}: {safe(group['signature'])}",
                          {"signature": plain(group["signature"]), "severity": group["severity"], "observer": plain(group["observer"], 80), "count": group["count"]}))
    total, before = run["denied_total"], previous.get("denied_total", 0)
    if total >= DENY_SPIKE_MIN and total >= DENY_SPIKE_FACTOR * before:
        found.append((ESCALATION_PRIORITY["deny-spike"], 0, "deny-spike", f"{total} denied flows in 24h, previous run {before}",
                      {"denied_total": total, "previous_total": before, "top_sources": run["denied_src"], "top_destinations": run["denied_dst"]}))
    for item in run["ingest"].get("firewalls", []):
        hours = item.get("hours_since")
        if (item.get("stale") and isinstance(hours, (int, float)) and QUIET_ESCALATE_HOURS < hours <= LONG_QUIET_HOURS
                and item["name"] in previous.get("logging", [])):
            found.append((ESCALATION_PRIORITY["firewall-quiet"], -hours, "firewall-quiet", f"{safe(item['name'], 40)} quiet for {hours:.0f}h, was logging at the previous run",
                          {"firewall": plain(item["name"], 80), "provider": plain(item.get("provider") or "", 40), "hours_since": round(hours, 1), "last_event": plain(item.get("last_event") or "", 40)}))
    found.sort(key=lambda entry: entry[:2])
    return [{"id": f"{position}-{kind}", "kind": kind, "summary": summary, "facts": facts}
            for position, (_, _, kind, summary, facts) in enumerate(found[:MAX_ESCALATIONS], start=1)]


def snapshot(run: dict) -> dict:
    """What the next run compares against: tonight's denied total and the firewalls that were logging."""
    return {"denied_total": run["denied_total"],
            "logging": sorted(item["name"] for item in run["ingest"].get("firewalls", []) if not item.get("stale"))}


def write_escalations(path: Path, items: list[dict], now: float) -> None:
    """The queue file {at, items}, written atomically with mode 600 (an empty list is a valid, deliberate queue)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump({"at": now, "items": items}, handle, indent=1)
    os.replace(temporary, path)


def build_report(run: dict) -> str:
    """The finished Discord report from one run's findings."""
    stamp = datetime.fromtimestamp(run["at"])
    if "error" in run:
        return f"**socbot**\n❓ SSDF query failed at {stamp:%H:%M}: {safe(run['error'], 300)}"
    groups, new = run["alerts"], set(run["new"])
    recent_quiet, long_quiet = quiet_subjects(run["ingest"], run["fabric"])
    lines = [f"**socbot** ({stamp:%d %b %H:%M}, last 24h)"]
    if run["baseline"]:
        lines.append("📚 first run: learned the alert signatures as the baseline; from tomorrow new ones get a 🆕")
    if groups:
        total = sum(group["count"] for group in groups)
        lines.append(f"Alerts: {total} in {len(groups)} groups" + (" (list cut at SSDF's 500-group limit)" if run["alerts_truncated"] else ""))
    # a new signature is always shown: it is recorded as known tonight, so it never gets a second 🆕
    shown = [group for position, group in enumerate(groups) if group["signature"] in new or position < SHOWN]
    for group in shown:
        lines.append(f"{'🆕 ' if group['signature'] in new else ''}{group['severity']} ×{group['count']} "
                     f"{safe(group['observer'], 40)}: {safe(group['signature'])}")
    if len(groups) > len(shown):
        lines.append(f"+{len(groups) - len(shown)} more groups")
    if run["alerts_truncated"]:
        lines.append("⚠️ alert_counts hit its 500-group limit: the smallest groups are not listed")
    if run["denied_total"]:
        lines.append(f"Denied flows: {run['denied_total']}"
                     + (f" (rankings use only the newest {DENY_LIMIT} per action: a sample)" if run["denied_truncated"] else "")
                     + (f", {run['denied_unranked']} without an IPv4 address (IPv6) not ranked" if run["denied_unranked"] else ""))
    for label, side in (("sources", "denied_src"), ("destinations", "denied_dst")):
        if run[side]:
            lines.append(f"Top denied {label}: " + ", ".join(f"{safe(address, 45)} ×{count}" for address, count in run[side]))
    lines += recent_quiet[:SHOWN]
    if len(recent_quiet) > SHOWN:
        lines.append(f"🔇 +{len(recent_quiet) - SHOWN} more quiet")
    if long_quiet:
        lines.append(f"Quiet over {LONG_QUIET_HOURS // 24} days (info, flagged before): {', '.join(long_quiet)}")
    escalated = run.get("escalated", [])
    if escalated:
        lines.append(f"➡️ escalated to socagent: {len(escalated)} item(s): {', '.join(item['kind'] for item in escalated)}")
    if not (groups or run["alerts_truncated"] or run["denied_total"] or recent_quiet):
        lines.append("✅ no alerts, no denies, every firewall is logging")
    return "\n".join(lines)


def collect(call, now: float, known: dict, baseline: bool, previous: dict | None = None) -> tuple[dict, dict]:
    """Query SSDF and return (run, known'). call(tool, arguments) returns one raw tool reply; `previous` is the last run's snapshot."""
    alert_reply = checked("alert_counts", call("alert_counts", {"since": "now-24h", "min_severity": "medium", "providers": ""}))
    denied_replies = [checked("query_flows", call("query_flows", {"action": action, "since": "now-24h", "limit": DENY_LIMIT}))
                      for action in DENY_ACTIONS]
    denied_rows = [row for reply in denied_replies for row in reply["rows"]]
    ingest = checked("ingest_status", call("ingest_status", {}))
    fabric = checked("fabric_status", call("fabric_status", {}))
    groups = group_alerts(alert_reply["rows"])
    new, known = classify_signatures(groups, known, now, baseline)
    run = {"at": now, "baseline": baseline, "alerts": groups, "new": sorted(new), 
           # alert_counts' own flag: more than 500 groups matched
           "alerts_truncated": bool(alert_reply["truncated"]),
           "denied_src": top_denied(denied_rows, "source_ip"), "denied_dst": top_denied(denied_rows, "destination_ip"),
           "denied_total": sum(reply["row_count"] for reply in denied_replies),
           "denied_truncated": any(reply["truncated"] for reply in denied_replies),
           # IPv6 flows have no source_ip/destination_ip (Nullable(IPv4)), so they cannot be ranked
           "denied_unranked": sum(1 for row in denied_rows if not row.get("source_ip")),
           "ingest": ingest, "fabric": fabric}
    run["escalated"] = escalations(run, previous)
    return run, known


def main() -> int:
    """Query SSDF, update the state, print the report between the markers run_bot.py expects."""
    STATE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE.with_suffix(".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(STATE.read_text()) if STATE.exists() else {}
        now = time.time()
        try:
            # stored apart from `known`: a quiet first night leaves `known` empty but is still the baseline
            run, state["known"] = collect(lambda tool, arguments: mcp_call_tools(SSDF_MCP, [(tool, arguments)])[0],
                                          now, state.get("known", {}), not state.get("baselined", False), state.get("last"))
            state["baselined"] = True
            state["last"] = snapshot(run)
            write_escalations(ESCALATIONS, run["escalated"], now)
        except Exception as exc:
            run = {"at": now, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        STATE.write_text(json.dumps({"known": state.get("known", {}), "baselined": state.get("baselined", False), "last": state.get("last")}, indent=1))
    print("REPORT START")
    print(build_report(run))
    print("REPORT END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
