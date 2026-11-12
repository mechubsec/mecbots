"""skillbot report (morning): what the nightly collect found. Per SRX skill, whether a local model's config for a concrete task
passed `commit check` on the lab vSRX, the first error for failures, what changed since the previous night, and skills with no task."""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

STATE = Path.home() / ".local/state/labbots/skillbot.json"
SKILLS_DIR = Path(os.environ.get("SKILLBOT_SKILLS_DIR", Path.home() / ".hermes/skills/devops"))
STALE_SECONDS = 20 * 3600
ICONS = {"pass": "🟢", "fail": "🔴", "error": "❓"}


def changes(current: dict, previous: dict) -> tuple[list[str], list[str]]:
    """(newly failing, newly passing) skill names versus the previous night. Skills missing last night are not changes."""
    failing = [skill for skill, result in current.items()
               if result["status"] == "fail" and previous.get(skill, {}).get("status") == "pass"]
    passing = [skill for skill, result in current.items()
               if result["status"] == "pass" and previous.get(skill, {}).get("status") == "fail"]
    return failing, passing


def build_report(state: dict, now: float, all_skills: list[str]) -> str:
    """The finished Discord report; all_skills are the srx-* skills that exist, for the no-task list."""
    run = state.get("run")
    if not run or now - run["at"] > STALE_SECONDS:
        return "**skillbot**\n❓ no collect run in the last 20h: check `labbot@skillbot.collect.service`"
    results = run["results"]
    previous = state.get("previous", {}).get("results", {})
    counts = {status: sum(1 for result in results.values() if result["status"] == status) for status in ICONS}
    models = sorted({result["model"] for result in results.values()})
    lines = [f"**skillbot** ({datetime.fromtimestamp(run['at']):%d %b %H:%M}, {', '.join(models)}, commit check)",
             f"🟢 {counts['pass']} pass · 🔴 {counts['fail']} fail · ❓ {counts['error']} could not run"]
    planned = run.get("planned", list(results))
    if not run.get("complete"):
        lines.insert(1, f"⚠️ collect did not finish ({len(results)} of {len(planned)} tasks)")
    for skill, result in sorted(results.items()):
        if result["status"] == "pass":
            lines.append(f"🟢 {skill} ({result['lines']} lines)")
            continue
        lines.append(f"{ICONS[result['status']]} {skill}: {result['error'].replace('@', '@' + chr(0x200b))}")  # set lines may hold @
    failing, passing = changes(results, previous)
    if not previous:
        lines.append("📚 first night: no earlier results to compare")
    for skill in failing:
        note = " (skill edited)" if results[skill]["skill_hash"] != previous[skill]["skill_hash"] else ""
        note += " (model changed)" if results[skill]["model"] != previous[skill]["model"] else ""
        lines.append(f"🔴 newly failing: {skill}{note}")
    lines += [f"🟢 newly passing: {skill}" for skill in passing]
    if previous and not (failing or passing):
        lines.append("No change since last night.")
    uncovered = [name for name in all_skills if name not in planned]
    if uncovered:
        lines.append("No task: " + ", ".join(uncovered))
    return "\n".join(lines)


def main() -> int:
    """Print the report between the markers run_bot.py expects."""
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    all_skills = sorted(path.parent.name for path in SKILLS_DIR.glob("srx-*/SKILL.md"))
    print("REPORT START")
    print(build_report(state, time.time(), all_skills))
    print("REPORT END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
