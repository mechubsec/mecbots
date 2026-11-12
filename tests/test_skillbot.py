"""Checks for skillbot's output filtering, device guard and nightly diff. Run: python3 -m pytest tests"""

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def load(name: str, path: Path):
    """Import a script file as a module."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


collect = load("skillbot_collect", REPO / "bots" / "skillbot" / "collect.py")
report = load("skillbot_report", REPO / "bots" / "skillbot" / "report.py")


def test_extract_keeps_set_lines_and_ignores_prose():
    text = "Here you go:\n```junos\nset security zones security-zone dmz\n  set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.129/26\n```\n# note\n"
    accepted, rejected = collect.extract_set_lines(text)
    assert accepted == ["set security zones security-zone dmz", "set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.129/26"]
    assert rejected == []


@pytest.mark.parametrize("line", ["set system login user x class super-user", "set  system   root-authentication plain-text-password",
                                  "set system services ssh", "delete security policies", "deactivate security nat",
                                  "set security zones security-zone a; delete interfaces", "set system host-name $(reboot)",
                                  "set security policies global policy p then log | no-more"])
def test_extract_rejects_refused_and_dangerous_lines(line):
    accepted, rejected = collect.extract_set_lines(f"set security zones security-zone ok\n{line}")
    assert accepted == ["set security zones security-zone ok"] and len(rejected) == 1


def test_device_assertion():
    collect.assert_device(collect.DEVICE)
    for other in ("other-device", "lab-vsrx-2", "", None):
        with pytest.raises(ValueError):
            collect.assert_device(other)


def test_commit_check_outcomes(monkeypatch):
    calls = []

    def fake(server, tool_calls):
        calls.append(tool_calls)
        return [reply]

    monkeypatch.setattr(collect, "mcp_call_tools", fake)
    reply = {"success": True}
    assert collect.commit_check(["set a b"]) == ("pass", "")
    assert calls[0][0][0] == "commit_check_config" and calls[0][0][1]["device"] == collect.DEVICE
    reply = {"success": False, "outcome": "check_failed", "error": "netconf error: RPC error: server error: [LockDenied]"}
    assert collect.commit_check(["set a b"])[0] == "error"  # inconclusive: neither a rejection nor a pass
    reply = {"success": False, "outcome": "invalid", "error": "netconf error: RPC error: server error: [OperationFailed] \nMissing mandatory statement: 'then'\n"}
    assert collect.commit_check(["set a b"]) == ("fail", "Missing mandatory statement: 'then'")

    def refused(server, tool_calls):
        raise RuntimeError("commit_check_config: netconf error: RPC error: server error: [OperationFailed] invalid value in ip address")

    monkeypatch.setattr(collect, "mcp_call_tools", refused)
    assert collect.commit_check(["set a b"])[0] == "fail"

    def down(server, tool_calls):
        raise RuntimeError("commit_check_config: ssh connect timed out")

    monkeypatch.setattr(collect, "mcp_call_tools", down)
    assert collect.commit_check(["set a b"])[0] == "error"  # not the config's fault


def result(status: str, skill_hash: str = "h1", model: str = "m") -> dict:
    """One recorded task result."""
    return {"status": status, "skill_hash": skill_hash, "model": model, "lines": 4, "error": "syntax error"}


def test_changes_since_yesterday():
    previous = {"a": result("pass"), "b": result("fail"), "c": result("pass"), "d": result("fail")}
    current = {"a": result("fail"), "b": result("pass"), "c": result("pass"), "d": result("fail"), "e": result("fail")}
    assert report.changes(current, previous) == (["a"], ["b"])


def test_report_diff_notes_and_not_covered():
    now = 1_800_000_000.0
    state = {"run": {"at": now, "complete": True, "planned": ["srx-nat", "srx-ips"], "results": {"srx-nat": result("fail", "h2", "new"), "srx-ips": result("pass")}},
             "previous": {"results": {"srx-nat": result("pass"), "srx-ips": result("pass")}}}
    text = report.build_report(state, now + 3600, ["srx-ips", "srx-mnha", "srx-nat"])
    assert "🔴 newly failing: srx-nat (skill edited) (model changed)" in text
    assert "🟢 srx-ips (4 lines)" in text and "No task: srx-mnha" in text
    assert "first night" in report.build_report({"run": state["run"]}, now, [])
    assert "no collect run" in report.build_report({}, now, [])


def test_find_syntax_error_line_stops_at_first_and_caps():
    checked = []

    def fake(line):
        checked.append(line)
        return "bad" in line

    lines = ["set a 1", "set b bad", "set c bad"]
    assert collect.find_syntax_error_line(lines, fake) == "set b bad" and checked == ["set a 1", "set b bad"]
    assert collect.find_syntax_error_line(["set x"] * 5 + ["set bad"], fake, limit=5) is None
    assert collect.find_syntax_error_line(["set ok"], fake) is None


def test_partial_run_is_flagged_and_unexecuted_tasks_are_not_no_task():
    now = 1_800_000_000.0
    run = {"at": now, "complete": False, "planned": ["srx-nat", "srx-ips"], "results": {"srx-nat": result("pass")}}
    text = report.build_report({"run": run}, now, ["srx-ips", "srx-mnha", "srx-nat"])
    assert "⚠️ collect did not finish (1 of 2 tasks)" in text and "No task: srx-mnha" in text
    assert "srx-ips" not in text
    assert "did not finish" not in report.build_report({"run": {**run, "complete": True}}, now, [])
