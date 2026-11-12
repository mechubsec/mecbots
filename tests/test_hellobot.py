"""Checks for hellobot's report. Run: python3 -m pytest tests"""

import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("hellobot_report", Path(__file__).resolve().parent.parent / "bots" / "hellobot" / "report.py")
hellobot = importlib.util.module_from_spec(spec)
sys.modules["hellobot_report"] = hellobot
spec.loader.exec_module(hellobot)


def test_report_flags_low_disk():
    assert "🔴 / has 5% free" in hellobot.build_report(5, 0.1)
    assert "✅ / has 50% free, 1-minute load 0.25" in hellobot.build_report(50, 0.25)
