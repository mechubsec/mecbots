# Changelog

## 0.2.0

- Runner: two-tier reporting. The full report is saved locally with an index page; Discord gets a scrubbed
  copy (addresses, MACs, names from a private redact list). `--dry-run --full`. There is no always-on report
  page: read the files, or serve them only while your own SSH session is open. Review fixes: an unreadable redact
  list stops the post (only a missing one is tolerated); IPv4-mapped IPv6 and dotted MACs are scrubbed; the
  "version" exemption stays on one line; reports are named to the second with a suffix on collision; the index is
  rewritten atomically under a lock.
- socbot: exact alert counts from one `alert_counts` call instead of capped per-vendor pages. An escalation
  queue (at most three items) for an agent; a tighter advice prompt. Review fixes: the deny-spike trigger is
  skipped, and the brief says so, when a deny total is capped at the row limit in this or the previous run; state
  is saved only after the escalation queue was written; a missing or forbidden `alert_counts` is reported as such
  (needs an SSDF version that has it, and a token that lists it).
- skillbot: seven fixes. Ahead-of-upstream skills are reported; sources without a release tag are read from
  the default branch; targets on different versions get the whole release scanned; an incomplete scan is
  flagged; the collector ends with a sentinel line; setup fails fast; a catch-up collect is not rolled past.
  Review fixes: a host on the old collector (no sentinel) is accepted and flagged; the sentinel is printed only
  when every step succeeded; the baseline advances only past a collect the report acknowledged; a release or tag
  API failure is a source error, not a reason to scan `HEAD`.
- canarybot: the tool surface comes from the image's own registry over stdio; no hand-copied write-tool table. A paginated
  stdio tool list fails the canary instead of recording a truncated baseline.
- Docs split: a short README, with setup, rules, caveats, ideas, versioning and per-bot details in their own files.

## 0.1.0

First public state: the runner (`bin/run_bot.py`), the MCP client and host helpers, and the example bots
hellobot, socbot, skillbot, reposbot and canarybot, with tests and systemd units.
