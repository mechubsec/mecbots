"""Checks for canarybot's pure functions. Run: python3 -m pytest tests/test_canarybot.py"""

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("canarybot", REPO / "bots" / "canarybot" / "report.py")
canarybot = importlib.util.module_from_spec(spec)
sys.modules["canarybot"] = canarybot
spec.loader.exec_module(canarybot)


def tool(name, **properties):
    return {"name": name, "inputSchema": {"type": "object", "properties": properties}}


def test_diff_tools_added_removed_and_schema_change():
    old = canarybot.tool_digests([tool("a", x={"type": "string"}), tool("b"), tool("c")])
    new = canarybot.tool_digests([tool("a", x={"type": "integer"}), tool("c"), tool("d")])
    assert canarybot.diff_tools(old, new) == (["d"], ["b"], ["a"])
    assert canarybot.diff_tools(new, new) == ([], [], [])


def test_already_canaried_means_empty_report():
    state = {"rustjunosmcp": {"tag": "2.7.5"}}
    assert not canarybot.needs_canary(state, "rustjunosmcp", "2.7.5")
    assert canarybot.needs_canary(state, "rustjunosmcp", "2.7.6")
    assert canarybot.needs_canary(state, "rustpanosmcp", "0.17.1")  # never canaried: baseline


def test_version_mismatch_verdict():
    assert canarybot.verdict("2.7.5", "2.7.5") == ""
    assert canarybot.verdict("2.7.5", "v2.7.5") == ""
    assert "2.7.4" in canarybot.verdict("2.7.5", "2.7.4")
    assert canarybot.verdict("2.7.5", None)


def test_format_result_failure_keeps_last_ten_log_lines():
    text = canarybot.format_result("rustjunosmcp", "2.7.5", "boom", 1.0, {}, None, [f"line{n}" for n in range(30)])
    assert text.startswith("🔴") and "line20" in text and "line19" not in text
    baseline = canarybot.format_result("rustjunosmcp", "2.7.5", "", 0.8, {"a": "x"}, None, [])
    assert "baseline" in baseline


def test_parse_stdio_tools_takes_the_tools_list_reply_and_ignores_log_noise():
    out = 'INFO started\n{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{}}}\n{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"confirm_commit"}]}}\n'
    assert canarybot.parse_stdio_tools(out) == [{"name": "confirm_commit"}]
    assert canarybot.parse_stdio_tools("garbage\n") == []


def test_no_hand_kept_write_tool_table():
    assert not hasattr(canarybot, "WRITE_TOOLS")  # the registry comes from the image over stdio


def test_stdio_tools_runs_the_image_without_network_or_token(monkeypatch, tmp_path):
    seen = {}
    def fake_docker(*args, **kwargs):
        seen["args"], seen["input"] = args, kwargs["input"]
        return canarybot.subprocess.CompletedProcess(args, 0, '{"id":2,"result":{"tools":[{"name":"a"},{"name":"b"}]}}\n', "")
    monkeypatch.setattr(canarybot, "docker", fake_docker)
    assert [t["name"] for t in canarybot.stdio_tools("img:1", "bin", tmp_path, "1:1", [])] == ["a", "b"]
    assert "--network" in seen["args"] and "none" in seen["args"] and "tools/list" in seen["input"]


def test_canary_turns_a_hung_docker_call_into_a_red_result(monkeypatch):
    def hang(*args, **kwargs):
        raise canarybot.subprocess.TimeoutExpired("docker", 60)
    monkeypatch.setattr(canarybot, "docker", hang)
    problem, _, tools, _ = canarybot.canary("rustjunosmcp", "2.7.5")
    assert problem.startswith("canary error: TimeoutExpired") and tools == {}


def test_a_paginated_stdio_tool_list_fails_the_canary_instead_of_recording_a_truncated_baseline(monkeypatch):
    import pytest
    page = '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}],"nextCursor":"page2"}}\n'
    with pytest.raises(RuntimeError, match="tool list is paginated: not supported"):
        canarybot.parse_stdio_tools(page)
    monkeypatch.setattr(canarybot, "docker", lambda *args, **kwargs: canarybot.subprocess.CompletedProcess(args, 0, "a" * 30 if "token" in args else page, ""))  # mint, then stdio
    problem, _, tools, _ = canarybot.canary("rustjunosmcp", "2.7.5")
    assert "tool list is paginated: not supported" in problem and tools == {}
