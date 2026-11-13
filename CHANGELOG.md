# Changelog

## 0.0.2

Still alpha quality.

- socbot: the escalation queue is stamped after its queries ran, so socagent's evidence window covers the alert that caused the escalation.
- run_bot: a report that prints empty markers and then exits non-zero is no longer recorded as delivered.
- skillbot: the delivered marker is read from `LABBOTS_STATE_DIR`, where the runner writes it, so setting `SKILLBOT_STATE` alone no longer hides deliveries.
- skillbot: a marker written after a failed collect (its failure notice) no longer acknowledges the run before it.

## 0.0.1

Still alpha quality.

- README: Discord is not sovereign; a self-hosted ntfy option is planned.
- Tests: the skillbot fake matches the API host exactly (a code scanning finding).

## 0.0.1-alpha

First public release, alpha. The runner (`bin/run_bot.py`), the MCP client and host helpers, and the example bots
hellobot, socbot, skillbot, reposbot and canarybot, with tests and systemd units.

Also in this release:

- Runner: two-tier reporting. The full report is saved locally with an index page; Discord gets a scrubbed
  copy (addresses, MACs, names from a private redact list). `--dry-run --full`. There is no always-on report
  page: read the files, or serve them only while your own SSH session is open. Review fixes: an unreadable redact
  list stops the post (only a missing one is tolerated); IPv4-mapped IPv6 and dotted MACs are scrubbed; the
  "version" exemption stays on one line; reports are named to the second with a suffix on collision; the index is
  rewritten atomically under a lock. After a real, delivered run (or an intentionally empty report) the runner
  writes `<bot>.delivered` in the state directory; a dry run or a failed post does not.
- socbot: exact alert counts from one `alert_counts` call instead of capped per-vendor pages. An escalation
  queue (at most three items) for an agent; a tighter advice prompt. Review fixes: the deny-spike trigger is
  skipped, and the brief says so, only when the previous run's total was capped; a capped current total is a floor
  and still escalates as "at least N" when it meets the trigger; state
  is saved only after the escalation queue was written; a missing or forbidden `alert_counts` is reported as such
  (needs an SSDF version that has it, and a token that lists it).
- skillbot: seven fixes. Ahead-of-upstream skills are reported; sources without a release tag are read from
  the default branch; targets on different versions get the whole release scanned; an incomplete scan is
  flagged; the collector ends with a sentinel line; setup fails fast; a catch-up collect is not rolled past.
  Review fixes: a host on the old collector (no sentinel) is accepted and flagged; the sentinel is printed only
  when every step succeeded; the baseline advances only past a collect whose report the runner marked delivered (a dry run no longer counts);
  old-collector warnings are listed first and counted in the tally; a release or tag
  API failure is a source error, not a reason to scan `HEAD`.
  Versions are printed with a leading `v` (also canarybot's tags), so the runner's scrub keeps four-part ones such
  as `v1.99.2.0` instead of turning them into `[ip]`.
- canarybot: the tool surface comes from the image's own registry over stdio; no hand-copied write-tool table. A paginated
  stdio tool list (any `nextCursor`, even an empty one) fails the canary instead of recording a truncated baseline.
- Docs split: a short README, with setup, rules, caveats, ideas, versioning and per-bot details in their own files.
