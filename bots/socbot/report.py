"""socbot (daily): the security side of the last 24h from SSDF: alerts grouped by signature,
severity and observing firewall (🆕 for a signature not seen before), the sources and
destinations with the most denied flows, and firewalls or ingest subjects that went quiet
(a firewall that stopped logging is a finding).
Only aggregates are posted, never raw log lines."""

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
# (tools used: recent_alerts, query_flows, ingest_status, fabric_status)
STATE = Path.home() / ".local/state/labbots/socbot.json"
# a signature unseen this long is forgotten, so its return counts as new
FORGET_SECONDS = 30 * 86400
LONG_QUIET_HOURS = 48
SHOWN = 10
DENY_ACTION = "flow_session_deny"  # the SRX deny event; other vendors use other action names
ALERT_LIMIT = 500
# recent_alerts with no provider filter returns nothing (SSDF applies min_severity after its row limit,
# so PAN-OS low-severity system events crowd everything out): ask per provider that raises real alerts
ALERT_PROVIDERS = ("juniper", "paloalto", "unifi")
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
    """Alert rows as [{signature, severity, observer, count}], worst severity then biggest count first."""
    counts = Counter((str(unwrap(row["signature"])), str(row["severity"]).lower(), str(row["observer"])) for row in rows)
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
        lines.append(f"Alerts: {total} in {len(groups)} groups" + (" (SSDF row limit hit, counts are a floor)" if run["alerts_truncated"] else ""))
    for group in groups[:SHOWN]:
        lines.append(f"{'🆕 ' if group['signature'] in new else ''}{group['severity']} ×{group['count']} "
                     f"{safe(group['observer'], 40)}: {safe(group['signature'])}")
    if len(groups) > SHOWN:
        lines.append(f"+{len(groups) - SHOWN} more groups")
    for label, side in (("sources", "denied_src"), ("destinations", "denied_dst")):
        if run[side]:
            lines.append(f"Top denied {label} ({run['denied_total']}{'+' if run['denied_truncated'] else ''} denies): " + ", ".join(f"{safe(address, 45)} ×{count}" for address, count in run[side]))
    lines += recent_quiet[:SHOWN]
    if len(recent_quiet) > SHOWN:
        lines.append(f"🔇 +{len(recent_quiet) - SHOWN} more quiet")
    if long_quiet:
        lines.append(f"Quiet over {LONG_QUIET_HOURS // 24} days (info, flagged before): {', '.join(long_quiet)}")
    if not (groups or run["denied_src"] or recent_quiet):
        lines.append("✅ no alerts, no denies, every firewall is logging")
    return "\n".join(lines)


def collect(call, now: float, known: dict, baseline: bool) -> tuple[dict, dict]:
    """Query SSDF and return (run, known'). call(tool, arguments) returns one raw tool reply."""
    alert_replies = [checked("recent_alerts", call("recent_alerts", {"since": "now-24h", "min_severity": "medium", "providers": provider,
                                                                      "limit": ALERT_LIMIT})) for provider in ALERT_PROVIDERS]
    denied = checked("query_flows", call("query_flows", {"action": DENY_ACTION, "since": "now-24h", "limit": DENY_LIMIT}))
    ingest = checked("ingest_status", call("ingest_status", {}))
    fabric = checked("fabric_status", call("fabric_status", {}))
    groups = group_alerts([row for reply in alert_replies for row in reply["rows"]])
    new, known = classify_signatures(groups, known, now, baseline)
    run = {"at": now, "baseline": baseline, "alerts": groups, "new": sorted(new), 
           # SSDF flags truncated on an empty page too: only a full page is a real cut-off
           "alerts_truncated": any(reply["row_count"] >= ALERT_LIMIT for reply in alert_replies),
           "denied_src": top_denied(denied["rows"], "source_ip"), "denied_dst": top_denied(denied["rows"], "destination_ip"),
           "denied_total": denied["row_count"], "denied_truncated": denied["row_count"] >= DENY_LIMIT,
           "ingest": ingest, "fabric": fabric}
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
                                          now, state.get("known", {}), not state.get("baselined", False))
            state["baselined"] = True
        except Exception as exc:
            run = {"at": now, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        STATE.write_text(json.dumps({"known": state.get("known", {}), "baselined": state.get("baselined", False)}, indent=1))
    print("REPORT START")
    print(build_report(run))
    print("REPORT END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
