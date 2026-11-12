# Rules and lessons

## Rules

- **The report is deterministic.** Every number and name in it comes from code, never from a model.
- **The model only adds advice, and has no tools.** It cannot run commands, edit the report or call anything.
  It gets the report text and returns text.
- **Report text is data, not instructions.** Reports carry machine text (log lines, device names) that an
  attacker can write. The runner tells the model to ignore instructions in it, and each advice prompt repeats that.
- **Output is defanged.** Model text is cleaned before posting (`defang()` in `run_bot.py`): no `@mentions`,
  no masked links, no control characters. Collectors do the same to log text (`safe()` in socbot).
- **One Discord identity per bot.** Each bot is its own Hermes profile and Discord application, so one token
  can be revoked alone and you can see which bot spoke.
- **State lives in files** under `~/.local/state/labbots/`, written under a lock. This is how a bot tells "new"
  from "known" and "yesterday" from "today". The first run learns a baseline and says so.
- **Watchers stay silent.** An empty report means no post. A bot that talks every hour gets muted.
- **A check that fails for every item is a broken check.** If all devices, hosts or skills fail the same way,
  suspect the test, the credentials or the network before the estate. Report "could not run" (`error`)
  separately from "ran and failed" (`fail`).
- **Discord gets a scrubbed copy.** The full report stays on your machine; see [SETUP.md](SETUP.md).

## Lessons

- **One scoped, read-only token per bot.** A bot that only reads cannot write, and revoking one bot does not
  break the others.
- **Count on the server.** A capped list gives a floor, and a noisy source hides the rest. Use a counting tool
  (socbot's `alert_counts`) and warn only on that tool's own truncation flag.
- **An error reply is not a quiet night.** Raise on `{error}` replies (`checked()` in socbot), so a broken
  collector cannot look like a clean estate. A capped or partial result is never an all-clear.
- **A stale collector is a finding.** The morning report says when no collect ran.
- **A scan that was cut short says so.** "None found" and "none found in the part we read" are different.
- **An advice model that cannot see the evidence blames the wrong thing.** Put what it needs in the report,
  tell it to use only what the report says, and forbid inventing facts. Test the prompt on a clean day: it
  must say nothing needs you.
- **Narrow a locationless error deterministically.** Junos reports a syntax error without naming the line;
  reposbot re-checks lines one at a time instead of asking a model where the mistake is.
- **A collector behind a forced command should print facts, not files.** Names, versions and hashes are enough;
  a key that can only print them is cheap to lose.
- **Untrusted text can be scanned by rules and read by a model, but neither result should trigger an
  action.** Both are advice to a human: label them, defang them, let a person decide.
- **Keep the first run quiet.** Learn a baseline, then mark new things from the next run on.
- **Keep prompts short and rules explicit.** A smaller model turns "background, not a task" into a task; pick
  a bigger model per bot with a drop-in when it matters.
- **Scrub for the cloud, keep the whole thing at home.** Redact what leaves; save the full text locally.
