# socbot

<img src="../assets/icons/socbot.png" width="64" alt="">

The security side of the last 24 hours, from SSDF: alerts grouped by signature, severity and observing
firewall (🆕 for a signature not seen before), the sources and destinations with the most denied flows, and
firewalls or ingest subjects that went quiet. Only aggregates are posted, never raw log lines.

- **Pattern:** daily report with a new-versus-known state file; the first run is a silent baseline.
- **Needs:** an SSDF MCP server and a read-only token limited to `alert_counts`, `query_flows`,
  `ingest_status` and `fabric_status`.
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
{"at": 1767225600.0, "items": [{"id": "1-new-high-alert", "kind": "new-high-alert", "summary": "...", "facts": {}}]}
```

At most three items, most urgent first, ids numbered in that order. The kinds:

| Kind | Fires when |
|---|---|
| `new-high-alert` | a new alert group at `critical` or `high` severity |
| `deny-spike` | denied flows are at least 100 and at least 3x the previous run's total |
| `firewall-quiet` | a firewall was logging at the previous run and has been quiet for more than 6 hours, but not for more than 48 |

The baseline run and a run with no previous snapshot escalate nothing. An empty list is a valid queue. The
file is written atomically with mode 600. A failed run leaves the old queue alone. The report gains one line
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
