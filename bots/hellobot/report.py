"""hellobot: the smallest bot. Copy this directory to start your own."""

import os
import shutil
import sys

FREE_PERCENT_WARN = 10


def build_report(free_percent: int, load_1min: float) -> str:
    """The finished report: deterministic text, no model involved."""
    icon = "🔴" if free_percent < FREE_PERCENT_WARN else "✅"
    return f"**hellobot**\n{icon} / has {free_percent}% free, 1-minute load {load_1min:.2f}"


def main() -> int:
    """Print the report between the markers run_bot.py expects."""
    usage = shutil.disk_usage("/")
    print("REPORT START")
    print(build_report(usage.free * 100 // usage.total, os.getloadavg()[0]))
    print("REPORT END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
