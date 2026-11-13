"""skillbot report (07:35): what the 01:30 collect found. Skills installed on your hosts that a source repo has a newer release of (with review flags and a local model's unverified
reading of the change), drift, gstack per host, newly discovered other skills and unreachable hosts.
Posts only when something is new since the last collect or, on Monday, while anything is outdated;
otherwise prints an empty report so run_bot.py posts nothing."""

import fcntl
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

STATE = Path(os.environ.get("SKILLBOT_STATE", Path.home() / ".local/state/labbots/skillbot.json"))
STALE_SECONDS = 20 * 3600
MESSAGE_LIMIT = 1900  # Discord allows 2000
FLAGS_SHOWN = 3
OTHERS_SHOWN = 8


def defang(text: str, limit: int = 160) -> str:
    """Untrusted text (source files, model replies) as inert Discord text: no mentions, masked links,
    code spans, invisible or control characters."""
    text = re.sub(r"[\x00-\x1f\x7f​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f`]", " ", text)
    text = text.replace("@", "@​").replace("](", "] (")
    return text[:limit] + ("…" if len(text) > limit else "")


def ver(version) -> str:
    """A version printed with a leading v ('1.99.2.0' -> 'v1.99.2.0'), which the runner's scrub() recognises as a
    version, not an address. Anything not starting with a digit ('unversioned', 'v2') is left alone."""
    text = str(version)
    return "v" + text if text[:1].isdigit() else text


def should_post(run: dict, now: float) -> bool:
    """Post a stale or failed collect, anything new since the last collect, or on Monday anything outdated."""
    if not run or "fatal" in run or now - run["at"] > STALE_SECONDS:
        return True
    if run["changed"]:
        return True
    outdated = (run["findings"]["outdated"] or any(info["kind"] == "outdated" for info in run["gstack"].values())
                or any(info.get("error") for info in run["sources"].values()))  # a failing source nags like an outdated skill
    return bool(outdated) and datetime.fromtimestamp(now).weekday() == 0


def pairs(targets: list[dict]) -> str:
    """'hosta/hermes 1.1.3, hostb/claude 1.1.3'."""
    return ", ".join(f"{defang(target['host'], 20)}/{defang(target['harness'], 10)} {defang(ver(target['installed'] or 'unversioned'), 20)}" for target in targets)


def model_lines(model: dict | None) -> list[str]:
    """The model's reply, clearly labelled and defanged; or why there is none."""
    if not model:
        return []
    if "error" in model:
        return [f"  🤖 no model reading: {defang(model['error'], 80)}"]
    lines = [defang(line, 150) for line in model["reply"].splitlines() if line.strip()][:5]
    return ["  🤖 model's reading (unverified, a local model, may be wrong):"] + [f"    {line}" for line in lines]


def outdated_block(skill: str, entry: dict, screen: dict | None) -> list[str]:
    """One 🔺 block: versions, who needs it, review flags, the model's reading."""
    tag = f" ({defang(entry['tag'], 30)})" if entry["tag"] else ""
    available = defang(ver(entry["available"]), 20)
    installed = sorted({ver(target["installed"]) for target in entry["targets"]})
    lines = [f"🔺 {defang(skill, 50)} {defang('/'.join(installed), 30)} → {available}{tag}", f"  update: {pairs(entry['targets'])}"]
    if not screen:
        return lines
    grouped: dict[tuple[str, str], list[str]] = {}  # one line per source line, listing every rule it tripped
    for flag in screen["flags"]:
        grouped.setdefault((flag["file"], flag["snippet"]), []).append(flag["rule"])
    unscanned = screen.get("unscanned") or {}
    lines.append(f"  review flags ({defang(screen['mode'], 70)}): " + (str(len(screen["flags"])) if grouped else ("none in the scanned part" if unscanned else "none")))
    if unscanned:
        lines.append(f"  ⚠️ scan incomplete ({unscanned.get('files', 0)} files / {unscanned.get('bytes', 0)} bytes not scanned)")
    lines += [f"  🚩 {', '.join(rules)} in {defang(file, 40)}: `{defang(snippet, 100)}`" for (file, snippet), rules in list(grouped.items())[:FLAGS_SHOWN]]
    if len(grouped) > FLAGS_SHOWN:
        lines.append(f"  🚩 +{len(grouped) - FLAGS_SHOWN} more flagged lines")
    return lines + model_lines(screen.get("model"))


def gstack_lines(run: dict) -> list[str]:
    """One gstack item per host: installed suite version vs upstream."""
    upstream = run["sources"].get("gstack") or {}
    if not run["gstack"]:
        return []
    if not upstream.get("version"):
        return [f"gstack: upstream unknown ({defang(upstream.get('error', 'no data'), 80)})"]
    marks = {"outdated": "🔺", "current": "✅", "ahead": "⬆️", "unknown": "❔"}
    per_host = ", ".join(f"{marks[info['kind']]} {defang(host, 20)} {defang(ver(info['installed']), 20)}" for host, info in sorted(run["gstack"].items()))
    return [f"**gstack** upstream {defang(ver(upstream['version']), 20)} ({defang(upstream['basis'], 60)}): {per_host}"]


def others_lines(run: dict) -> list[str]:
    """Newly appeared skills outside the known sources (the first night is a silent baseline)."""
    if not run["new_other"]:
        return []
    shown = [f"{defang(key.split('|')[2], 40)} ({defang(key.split('|')[0], 12)}/{defang(key.split('|')[1], 10)})" for key in run["new_other"][:OTHERS_SHOWN]]
    more = f" +{len(run['new_other']) - OTHERS_SHOWN} more" if len(run["new_other"]) > OTHERS_SHOWN else ""
    return [f"🆕 other skills (no known source): {', '.join(shown)}{more}"]


def fit(lines: list[str]) -> str:
    """Join lines, dropping from the bottom of the list to stay within one Discord message."""
    kept, size = [], 0
    for index, line in enumerate(lines):
        if size + len(line) + 1 > MESSAGE_LIMIT - 60:
            kept.append(f"… {len(lines) - index} more lines, see ~/.local/state/labbots/skillbot.json")
            break
        kept.append(line)
        size += len(line) + 1
    return "\n".join(kept)


def build_report(state: dict, now: float) -> str:
    """The Discord post, or '' when nothing is worth one."""
    run = state.get("run")
    if not should_post(run, now):
        return ""
    if not run or now - run.get("at", 0) > STALE_SECONDS:
        return "**skillbot**\n❓ no collect run in the last 20h: check `labbot@skillbot.collect.service`"
    if "fatal" in run:
        return f"**skillbot**\n❓ collect failed: {defang(run['fatal'], 300)}"
    findings = run["findings"]
    outdated_gstack = [host for host, info in run["gstack"].items() if info["kind"] == "outdated"]
    tally = (f"{len(findings['outdated'])} outdated · {len(findings['drift'])} drifted · "
             f"gstack outdated on {len(outdated_gstack)} · {len(run['new_other'])} new other skills · {len(run['errors'])} hosts unreachable")
    lines = [f"**skillbot** ({datetime.fromtimestamp(run['at']):%d %b %H:%M})", f"Findings: {tally}"]
    for source, info in run["sources"].items():
        if info.get("error"):
            lines.append(f"⚠️ {source}: source fetch failed: {defang(info['error'], 100)}")
    for source in ("fwskillsshare",):
        info = run["sources"].get(source) or {}
        if findings["outdated"] and info.get("version"):
            lines.append(f"**{source}** latest {defang(ver(info['tag'] or info['version']), 20)} ({defang(info['basis'], 40)})")
    for skill, entry in sorted(findings["outdated"].items()):
        lines += outdated_block(skill, entry, run["screens"].get(skill))
    lines += gstack_lines(run)
    for skill, entry in sorted(findings["drift"].items()):
        lines.append(f"〰️ drift {defang(skill, 50)} same version {defang(ver(entry['available']), 20)}, SKILL.md differs: {pairs(entry['targets'])}")
    for skill, entry in sorted(findings["ahead"].items()):
        lines.append(f"⬆️ ahead {defang(skill, 50)} installed {defang(ver(entry['targets'][0]['installed']), 20)} > release {defang(ver(entry['available']), 20)} on {len(entry['targets'])} host/harness")
    lines += others_lines(run)
    for host in run.get("old_collectors", []):
        lines.append(f"⚠️ {defang(host, 20)}: old collector: update it (no end marker, so a failed run cannot be told from a complete one)")
    for host, error in sorted(run["errors"].items()):
        lines.append(f"⚠️ {defang(host, 20)} unreachable: {defang(error, 80)}; its skills were not checked")
    if len(lines) == 2:
        lines.append("✅ nothing outdated")
    return fit(lines)


def acknowledge(run_at: float) -> None:
    """Record that the report read the collect run made at run_at; collect.py advances its night-to-night
    baseline only past an acknowledged run. Same lock and atomic replace as collect.py's save_state."""
    with open(STATE.with_suffix(".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(STATE.read_text())
        state["acked"] = max(state.get("acked", 0), run_at)
        temporary = STATE.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, indent=1))
        temporary.replace(STATE)


def main() -> int:
    """Print the report between the markers run_bot.py expects."""
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    run = state.get("run")
    if run and "fatal" not in run and time.time() - run["at"] <= STALE_SECONDS:  # a stale or failed collect was not reported on
        acknowledge(run["at"])
    print("REPORT START")
    print(build_report(state, time.time()))
    print("REPORT END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
