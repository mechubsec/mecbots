# Versioning

[Semantic versioning](https://semver.org). The version is in `VERSION`; changes are in `CHANGELOG.md`.

## What is breaking

While below 1.0 a breaking change bumps the minor number; from 1.0 on, the major number. Breaking means any of:

- the **runner command line** (`bin/run_bot.py` arguments, the `REPORT START`/`REPORT END` markers);
- a **state-file format** under `~/.local/state/labbots/` (keys or shapes that a later run reads);
- an **environment variable** renamed, removed or given a different meaning;
- the **escalation queue format** written by socbot (`socbot-escalations.json`: `{at, items: [{id, kind,
  summary, facts}]}` and its kinds), which [mecagents](https://github.com/mechubsec/mecagents) reads.

New bots, new optional variables and tighter checks are minor; fixes and docs are patch.

## Agents

mecagents 0.0.1 needs mecbots 0.0.1-alpha or later.
