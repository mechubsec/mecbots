# hellobot

<img src="../assets/icons/hellobot.png" width="64" alt="">

Reports free disk space on `/` and the 1-minute load average. The smallest bot: copy it to start your own
([FIRST-BOT.md](../FIRST-BOT.md)).

- **Pattern:** daily report. A pure `build_report()` plus a `main()` that gathers two facts.
- **Needs:** nothing beyond the runner.
- **Env vars:** none of its own; the `LABBOTS_*` ones apply ([SETUP.md](../SETUP.md)).
- **Schedule:** daily 08:00 (`systemd/labbot-hellobot.timer`).
- **Rules it enforces:** the report is code; the advice prompt says to use only what the report says and
  to write "Nothing needs you today" on a clean day.
- **Known limits:** it reads one filesystem; it has no state.
