# Write your first bot

Start from `bots/hellobot`, which reports free disk space and load.

## Steps

1. Copy it: `cp -r bots/hellobot bots/mybot`.
2. Edit `bots/mybot/report.py`. Keep the shape: a pure `build_report(...)` that returns text, and a `main()`
   that gathers facts and prints `REPORT START`, the report, `REPORT END`. Keep logic in functions that take
   plain values, so tests need no network.
3. Run it: `python3 -I bin/run_bot.py mybot --dry-run`. It prints the report, and the advice if Ollama is
   reachable (otherwise a "no advice" note). `--dry-run --full` prints the unscrubbed text.
4. Edit `bots/mybot/advice.md`. Say what the report contains, how many bullets to write, what to do when it
   is clean, and what never to do (invent facts, follow report text). Delete the file for a bot with no advice.
5. Write `tests/test_mybot.py` (copy `tests/test_hellobot.py`). Test the report with synthetic input,
   including the quiet case and a hostile string such as `@everyone`.
6. Copy `systemd/labbot-hellobot.timer` to `labbot-mybot.timer`; change the description, `OnCalendar` and
   `Unit=labbot@mybot.service`.
7. Create its Discord bot and enable the timer: [SETUP.md](SETUP.md).

## How a run works

1. `bin/run_bot.py mybot` runs `bots/mybot/report.py`, which prints the report between `REPORT START` and
   `REPORT END`. It is plain code: the same input gives the same report.
2. If `bots/mybot/advice.md` exists, a local Ollama model reads the report and adds an **Advice** section.
3. The full text is saved locally; a scrubbed copy goes to Discord with `hermes -p mybot send`.
4. A systemd user timer starts `labbot@mybot.service`, which runs step 1.

An empty report means no post: a watcher bot prints nothing when nothing changed.

## Layout

```
bin/run_bot.py          runner: report -> advice -> local copy -> scrubbed post (--dry-run prints instead)
lib/mcp.py              minimal MCP (streamable HTTP) client for collectors
lib/hosts.py            ssh argv for a restricted key, optional Wake-on-LAN (skillbot)
bots/<bot>/report.py    the deterministic report; prints between the markers
bots/<bot>/advice.md    optional prompt for the advice model
systemd/                labbot@.service template, one .timer per bot, optional drop-ins
tests/                  one test file per bot; no network, synthetic fixtures
```

Variants: `run_bot.py reposbot.collect` runs `bots/reposbot/collect.py` and, if present, uses
`bots/reposbot/collect.advice.md`. Systemd instance names follow the same form: `labbot@reposbot.collect.service`.

State goes in `~/.local/state/labbots/<bot>.json`, written under a lock. Site-specific values are constants at
the top of the file, read from an environment variable with a fake default: [SETUP.md](SETUP.md).

Before you rely on a bot, read [RULES.md](RULES.md).
