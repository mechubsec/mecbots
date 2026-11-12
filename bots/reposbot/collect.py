"""reposbot collect (nightly): for each task in tasks.py, give the local model the skill's SKILL.md plus the task and ask
for Junos set commands only, then run them through `commit check` on a lab vSRX. Nothing is committed.
Posts nothing; the morning report reads what this saves. A regression rig: does skill + task still yield config
that a real vSRX accepts?

Safety: the only device ever addressed is DEVICE and the only tools called are ALLOWED_TOOLS. Model output is
untrusted, so only strictly matching `set` lines reach the device."""

import fcntl
import hashlib
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp import mcp_call_tools  # noqa: E402
from tasks import FACTS, TASKS  # noqa: E402

DEVICE = os.environ.get("REPOSBOT_DEVICE", "lab-vsrx")  # the one device name in the Junos MCP inventory reposbot may address
MCP_SERVER = os.environ.get("REPOSBOT_MCP", "junos")  # Junos MCP server name in the Hermes config
ALLOWED_TOOLS = {"commit_check_config"}  # a check discards its own candidate
SKILLS_DIR = Path(os.environ.get("REPOSBOT_SKILLS_DIR", Path.home() / ".hermes/skills/devops"))  # <skill>/SKILL.md per task
STATE = Path.home() / ".local/state/labbots/reposbot.json"
OLLAMA_URL = os.environ.get("LABBOTS_OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("REPOSBOT_MODEL", "qwen3-coder-next:latest")
MAX_LINE_CHECKS = 60  # extra single-line checks when a whole config fails with a bare syntax error
SET_LINE = re.compile(r'^set [\w ./:\-"*,\[\]@]+$')
# a commit check does not apply these, but the blast radius stays zero anyway
REFUSED_PREFIXES = ("set system login", "set system root-authentication", "set system services", "delete", "deactivate")
SYSTEM_PROMPT = ("You write Juniper Junos configuration. Follow the skill below. Reply with ONLY Junos `set` commands, one per line: "
                 "no prose, no comments, no code fences, no delete or deactivate.\n\n<skill>\n{skill}\n</skill>")


def assert_device(device: str | None) -> None:
    """Raise unless the device is the one lab device reposbot may touch."""
    if device != DEVICE:
        raise ValueError(f"reposbot may only address {DEVICE}, not {device!r}")


def extract_set_lines(text: str) -> tuple[list[str], list[str]]:
    """Split model output into (set lines safe to send, rejection reasons). Blank lines, code fences, comments
    and prose are ignored; a set line that is malformed or refused, or any delete/deactivate, is a rejection."""
    accepted, rejected = [], []
    for raw in text.splitlines():
        line = " ".join(raw.split())
        if not line or line.startswith(("```", "#")):
            continue
        refused = [prefix for prefix in REFUSED_PREFIXES if line.startswith(prefix)]
        if refused:
            rejected.append(f"refused '{refused[0]}': {line[:60]}")
        elif line.startswith("set "):
            if SET_LINE.match(line):
                accepted.append(line)
            else:
                rejected.append(f"bad characters: {line[:60]}")
    return accepted, rejected


def first_error(message: str) -> str:
    """The first meaningful line of a commit-check error, without the netconf wrapper."""
    message = re.sub(r"^.*?\[OperationFailed\]", "", message, flags=re.S) if "[OperationFailed]" in message else message
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    return (lines[0] if lines else "unknown error")[:200]


def ask_model(skill_text: str, task: str) -> str:
    """The local model's reply to one skill + task."""
    body = {"model": MODEL, "stream": False, "think": False, "options": {"temperature": 0, "num_ctx": 32768},
            "messages": [{"role": "system", "content": SYSTEM_PROMPT.format(skill=skill_text)},
                         {"role": "user", "content": f"{FACTS}\n\nTask: {task}"}]}
    request = urllib.request.Request(f"{OLLAMA_URL}/api/chat", json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=1500) as response:
        return json.loads(response.read())["message"]["content"]


def commit_check(lines: list[str]) -> tuple[str, str]:
    """(status, first error) of a commit check on DEVICE: pass, fail (the config is wrong) or error
    (the check itself could not run, which says nothing about the config)."""
    arguments = {"device": DEVICE, "config_text": "\n".join(lines), "config_format": "set"}
    assert_device(arguments["device"])
    try:
        reply = mcp_call_tools(MCP_SERVER, [("commit_check_config", arguments)])[0]
    except RuntimeError as exc:
        # the server relays Junos' refusal as a tool error: "netconf error: RPC error: server error: [OperationFailed] ..."
        return ("fail" if "[OperationFailed]" in str(exc) else "error"), first_error(str(exc).removeprefix("commit_check_config: "))
    except Exception as exc:
        return "error", f"{type(exc).__name__}: {str(exc)[:150]}"
    if reply.get("success"):
        return "pass", ""
    # outcome "check_failed" = the server reached no verdict: neither a rejection nor a pass
    return ("error" if reply.get("outcome") == "check_failed" else "fail"), first_error(str(reply.get("error", "")))


def find_syntax_error_line(lines: list[str], is_syntax_failure, limit: int = MAX_LINE_CHECKS) -> str | None:
    """The first of the first `limit` lines for which is_syntax_failure(line) is true, else None."""
    return next((line for line in lines[:limit] if is_syntax_failure(line)), None)


def lone_line_is_syntax_error(line: str) -> bool:
    """True when `commit check` on this line alone fails with a syntax error; a line that parses but fails
    a semantic check (missing statement, undefined name) is not the culprit. One session per line: the
    client raises on the first hard error, which ends its session."""
    status, error = commit_check([line])
    return status == "fail" and error.startswith("syntax error")


def run_task(skill: str, task: str) -> dict:
    """One task's recorded result."""
    started = time.time()
    skill_text = (SKILLS_DIR / skill / "SKILL.md").read_text()
    result = {"skill_hash": hashlib.sha256(skill_text.encode()).hexdigest()[:12], "model": MODEL, "lines": 0}
    try:
        lines, rejected = extract_set_lines(ask_model(skill_text, task))
        result["lines"] = len(lines)
        if rejected:
            result.update(status="fail", error=f"rejected output: {rejected[0]}")
        elif not lines:
            result.update(status="fail", error="model returned no set commands")
        else:
            result["status"], result["error"] = commit_check(lines)
            if result["status"] == "fail":
                if result["error"].startswith("syntax error"):  # Junos names no line, so find it
                    culprit = find_syntax_error_line(lines, lone_line_is_syntax_error)
                    result["error"] = f"syntax error at: {culprit[:120]}" if culprit else result["error"]
                result["config"] = "\n".join(lines)[:4000]
    except Exception as exc:
        result.update(status="error", error=f"{type(exc).__name__}: {str(exc)[:150]}")
    result["seconds"] = round(time.time() - started)
    return result


def main() -> int:
    """Run every task, keep yesterday's results beside today's; an empty report means no post."""
    STATE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE.with_suffix(".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(STATE.read_text()) if STATE.exists() else {}
        today = time.strftime("%Y-%m-%d")
        # a second run on the same day replaces today's, so yesterday stays yesterday's
        if state.get("run") and state["run"]["day"] != today:
            state["previous"] = state["run"]
        run = {"at": time.time(), "day": today, "results": {}, "planned": list(TASKS), "complete": False}
        for skill, task in TASKS.items():
            run["results"][skill] = run_task(skill, task)
            state["run"] = run
            STATE.write_text(json.dumps(state, indent=1))
        run["complete"] = True  # only a finished loop; a killed collect leaves a run the report calls partial
        STATE.write_text(json.dumps(state, indent=1))
    print("REPORT START\nREPORT END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
