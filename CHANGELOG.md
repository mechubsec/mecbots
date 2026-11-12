# Changelog

## 0.2.0

- Runner: two-tier reporting. The full report is saved locally with an index page; Discord gets a scrubbed
  copy (addresses, MACs, names from a private redact list). `--dry-run --full`. New
  `systemd/labbots-reports.service` (loopback only).
- socbot: exact alert counts from one `alert_counts` call instead of capped per-vendor pages. An escalation
  queue (at most three items) for an agent; a tighter advice prompt.
- skillbot: seven fixes. Ahead-of-upstream skills are reported; sources without a release tag are read from
  the default branch; targets on different versions get the whole release scanned; an incomplete scan is
  flagged; the collector ends with a sentinel line; setup fails fast; a catch-up collect is not rolled past.
- canarybot: the tool surface comes from the image's own registry over stdio; no hand-copied write-tool table.
- Docs split: a short README, with setup, rules, caveats, ideas, versioning and per-bot details in their own files.

## 0.1.0

First public state: the runner (`bin/run_bot.py`), the MCP client and host helpers, and the example bots
hellobot, socbot, skillbot, reposbot and canarybot, with tests and systemd units.
