"""Checks for run_bot's Discord-safe model text. Run: python3 -m pytest tests"""

import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("run_bot", Path(__file__).resolve().parent.parent / "bin" / "run_bot.py")
run_bot = importlib.util.module_from_spec(spec)
sys.modules["run_bot"] = run_bot
spec.loader.exec_module(run_bot)


def test_defang_mentions_links_and_controls():
    text = run_bot.defang('ping @everyone <@123> [docs](https://evil.example/x) [t](https://e.example "Trusted")\x07\n- ok')
    assert "@everyone" not in text and "<@123>" not in text and "](" not in text
    assert "\x07" not in text and "\n- ok" in text
