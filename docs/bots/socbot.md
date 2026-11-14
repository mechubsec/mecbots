# socbot

<img src="../assets/icons/socbot.png" width="64" alt="">

The security side of the last 24 hours, from SSDF: alerts grouped by signature, severity and observing
firewall (🆕 for a signature not seen before), the sources and destinations with the most denied flows, and
firewalls or ingest subjects that went quiet. Only aggregates are posted, never raw log lines.

- **Pattern:** daily report with a new-versus-known state file; the first run is a silent baseline.
- **Needs:** an SSDF MCP server **with the `alert_counts` tool** (older SSDF installs lack it) and a read-only
  token limited to `alert_counts`, `query_flows`, `ingest_status` and `fabric_status`. The token must list
  `alert_counts` too: an older token is not allowed to call it. If the tool is missing or forbidden, socbot's
  report says exactly that ("needs an SSDF version that has alert_counts, and its token must list it"). There is
  no fallback to another query.
- **Env vars:** `SOCBOT_MCP`, `SOCBOT_STATE`, `SOCBOT_ESCALATIONS`, `LABBOTS_*` ([SETUP.md](../SETUP.md)).
- **Schedule:** daily 09:30 (`systemd/labbot-socbot.timer`); the shipped drop-in picks a bigger model.

## How it counts

One `alert_counts` call at `min_severity="medium"` returns exact counts per provider, observer, signature
and severity, up to 500 groups. socbot sums rows with the same signature, severity and observer into one group.
A signature is "known" when it was seen in the last 30 days; one unseen for longer is new again. A new
signature is always listed, even below the top ten. If SSDF says the reply was truncated (more than 500
groups), the report says the smallest groups are not listed. Denied flows are counted per action
(`query_flows`); rankings use a sample when a reply is capped, and the report says so.

## Escalation queue

socbot writes `~/.local/state/labbots/socbot-escalations.json` after each successful run, for an agent such
as [socagent](https://github.com/mechubsec/mecagents) to read:

```json
{"at": 1767225600.0, "since": 1767139190.0, "items": [{"id": "1-new-high-alert", "kind": "new-high-alert", "summary": "...", "facts": {}}]}
```

`since` is the start time every query of the run was given and `at` is stamped after the last one, so the two bound what the run
looked at. At most three items, most urgent first, ids numbered in that order. The kinds:

| Kind | Fires when |
|---|---|
| `new-high-alert` | a new alert group at `critical` or `high` severity |
| `deny-spike` | denied flows are at least 100 and at least 3x the previous run's total, and the previous total was exact (see below) |
| `firewall-quiet` | a firewall was logging at the previous run and has been quiet for more than 6 hours, but not for more than 48 |

`query_flows` replies stop at 1,000 rows per action. A capped total for tonight is a floor, so if the previous
total was exact and the floor already meets the trigger, the spike is escalated as "at least N" (the brief says
"Denied flows: at least N" too). When the previous run's total was capped the ratio cannot be established: the
spike check is skipped and the report says `deny total capped: spike check skipped`. A previous snapshot that does
not record this counts as capped.

The baseline run and a run with no previous snapshot escalate nothing. An empty list is a valid queue. The
file is written atomically with mode 600. A failed run leaves the old queue alone, and the state (known
signatures, last totals) is saved only after the queue was written, so a failed write is retried against the
same comparison instead of losing the escalation. The report gains one line
when something was escalated.

## Safety rules it enforces

- An `{error}` reply raises; it never reads as a quiet night.
- A truncated reply is never an all-clear.
- Log text is made inert before posting (`safe()`): no mentions, code spans or control characters.
- A firewall quiet for more than 2 days is flagged until then and listed as info afterwards.

## Known limits

- It needs SSDF; another log store needs a new collector.
- A dry run writes the state file and the queue; delete both if the real first run must be the baseline.
- The advice model sees only the report.
