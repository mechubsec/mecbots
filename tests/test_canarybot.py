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
