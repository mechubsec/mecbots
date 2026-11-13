# Caveats

- **Discord is a cloud service.** Reports are scrubbed before they are posted, and the full copy stays on your
  machine. Scrubbing is a safety net, not a guarantee: still do not point a bot at a server you do not trust.
- **The redact list only catches names it contains.** Nothing refreshes it. A new host or device is posted by
  name until you add it.
- **Version numbers that look like addresses may be redacted.** `1.2.3.4` is treated as an address unless the
  word "version", "upstream" or similar is just before it on the same line. Numbers over 255 in a part are kept.
- **A dry run of some bots writes state.** socbot writes its state file and its escalation queue; so does
  reposbot's and skillbot's collect. Delete them if the real first run must be the baseline.
- **The advice model cannot see evidence the report omits.** It reads only the report. It may blame the wrong
  thing or stay vague; its text is advice, never a finding.
- **skillbot's review flags are prompts to read a diff, not verdicts.** Its screening has only been exercised
  on fixtures; do not install or skip anything because of a flag, or the lack of one.
- **canarybot proves an image boots and lists its tools,** not that it works against a device.
- **reposbot's failures can be the skill, the model or the task.** A red line needs a person to tell which.
- **socbot needs an SSDF MCP server** with the tools it calls; there is no adapter for other log stores.
- **Do not put a self-hosted CI runner on a repo that may go public.** A pull request can run code on it.

## Known issues (from review, not yet fixed)

- **A report script that prints empty markers and then exits non-zero is still recorded as delivered.** The
  runner does not check the exit code on the empty-report path, so a bot that reads the delivered marker
  (skillbot) could move its baseline past a failed run.
- **skillbot's delivered marker is a time, not a run.** If a collect fails after an earlier run's post also
  failed, the marker written for the failure notice can be taken as acknowledging the earlier run.
- **Changing `SKILLBOT_STATE` or `LABBOTS_STATE_DIR` alone splits the marker's path.** Set both, or neither, or
  skillbot never sees a delivery and reports the same items as new every night.
