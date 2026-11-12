# reposbot

<img src="../assets/icons/reposbot.png" width="64" alt="">

A nightly regression rig for SRX skills. For each task in `tasks.py` a local model gets the skill's `SKILL.md`
plus the task and writes Junos `set` commands; they go through `commit check` on one lab device. The report
says which skills still yield config the device accepts, the first error for each failure, and what changed
since the previous night.

- **Pattern:** collect at night, report in the morning; a model writes, code validates.
- **Needs:** Ollama with a coding model; a Junos MCP server with `commit_check_config`; your own `srx-*`
  skills as `<skill>/SKILL.md`; edits to `TASKS` and `FACTS` in `bots/reposbot/tasks.py` to describe your device.
- **Env vars:** `REPOSBOT_DEVICE`, `REPOSBOT_MCP`, `REPOSBOT_MODEL`, `REPOSBOT_SKILLS_DIR`, `LABBOTS_OLLAMA_URL`
  ([SETUP.md](../SETUP.md)).
- **Schedule:** collect 00:30 (`reposbot.collect`, prints nothing), report 07:40; the report waits for the collect.

## Safety rules it enforces

Hard rules in code, not in the prompt:

- Exactly one allow-listed device (`assert_device`) and one allow-listed tool (`ALLOWED_TOOLS`).
- Model output is untrusted: only lines matching a strict regex reach the device, and `delete`, `deactivate`
  and anything touching logins or services is refused.
- The tool cannot change the device: a commit check discards its own candidate. Use a token that is
  read-only or check-only on the server as well.
- A locationless syntax error is narrowed by re-checking lines one at a time, not by asking a model.
- A stale collect is reported as a finding.

## Known limits

- A failure can be the skill, the model or the task; a person has to read it.
- `FACTS` and the tasks describe one device; they will not fit yours until edited.
- Skills that need two nodes or hardware are not tested.
