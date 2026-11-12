<!-- brand:header:start -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mecbots-wordmark.svg">
    <img src="docs/assets/mecbots-wordmark-light.svg" width="300" alt="mecbots">
  </picture>
</h1>

<p align="center"><strong>Small, deterministic homelab bots that report to Discord</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

<p align="center"><img src="docs/assets/icons/mecbots.png" width="96" alt="mecbots mascot"></p>
<!-- brand:header:end -->

How to build small, deterministic homelab bots that report to Discord. This repo is a
how-to with a runner and four example bots, not a product: copy what you need.

| | Bot | Pattern |
|---|---|---|
| <img src="docs/assets/icons/hellobot.png" width="48" alt=""> | `hellobot` | the smallest bot; copy it to start yours |
| <img src="docs/assets/icons/socbot.png" width="48" alt=""> | `socbot` | daily report with a new-versus-known state file |
| <img src="docs/assets/icons/skillbot.png" width="48" alt=""> | `skillbot` | collect at night, report in the morning; a model writes, code validates |
| <img src="docs/assets/icons/canarybot.png" width="48" alt=""> | `canarybot` | watcher: silent unless something changed |

Each bot gets its own face. The icons were generated locally in one shared style, so a
glance at the channel tells you which bot spoke.

## What a bot is

A bot is a script that prints a finished report, plus an optional prompt for a local
model, plus a systemd timer. Nothing more.

1. `bots/<bot>/report.py` collects facts and prints the report between the lines
   `REPORT START` and `REPORT END`. It is plain code: the same input gives the same report.
2. `bin/run_bot.py` runs it. If `bots/<bot>/advice.md` exists, a local Ollama model reads
   the report and adds a short **Advice** section. Then `hermes -p <bot> send` posts to Discord.
3. A systemd user timer starts `labbot@<bot>.service`, which runs `run_bot.py <bot>`.

### Rules that make them trustworthy

- **The report is deterministic.** Every number and name in it comes from code, never from a model.
- **The model only adds advice, and has no tools.** It cannot run commands, edit the report or
  call anything. It gets the report text and returns text.
- **Report text is data, not instructions.** Reports carry machine text (log lines, device
  names) that an attacker can write. The runner tells the model to ignore instructions in it,
  and the advice prompt repeats that.
- **Model output is defanged** before posting (`defang()` in `run_bot.py`): no `@mentions`,
  no masked links, no control characters. Collectors do the same to log text (`safe()` in socbot).
- **One Discord identity per bot.** Each bot is its own Hermes profile and Discord application,
  so a bot's token can be revoked alone and you can see which bot spoke.
- **State lives in files** under `~/.local/state/labbots/<bot>.json`, written under a lock.
  This is how a bot knows "new" from "known" and "yesterday" from "today".
- **Watcher bots print nothing when nothing changed.** An empty report means no post; the
  runner exits quietly. A bot that talks every hour gets muted.
- **A check that fails for every item is a broken check.** If all devices, hosts or skills
  fail the same way, suspect the test, the credentials or the network before the estate.
  Report "could not run" (`error`) separately from "ran and failed" (`fail`).

## Layout

```
bin/run_bot.py          runner: report -> advice -> Discord (--dry-run prints instead)
lib/mcp.py              minimal MCP (streamable HTTP) client for collectors
bots/<bot>/report.py    the deterministic report; prints between the markers
bots/<bot>/advice.md    optional prompt for the advice model
systemd/                labbot@.service template, one .timer per bot, optional drop-ins
tests/                  one test file per bot; no network, synthetic fixtures
```

Variants: `run_bot.py skillbot.collect` runs `bots/skillbot/collect.py` and, if present,
uses `bots/skillbot/collect.advice.md`. Systemd instance names follow the same form:
`labbot@skillbot.collect.service`.

## Requirements

A Linux box with systemd, Python 3.11+, [Ollama](https://ollama.com) with a model pulled,
[Hermes Agent](https://github.com/NousResearch/hermes-agent) (`hermes` on PATH; it owns the
Discord connection), and a Discord server you administer. PyYAML for bots that read Hermes
config via `lib/mcp.py`. Docker for canarybot only.

## Write your first bot

Start from `bots/hellobot`, which reports free disk space and load.

1. Copy it: `cp -r bots/hellobot bots/mybot`.
2. Edit `bots/mybot/report.py`. Keep the shape: a pure `build_report(...)` that returns text,
   and a `main()` that gathers facts and prints `REPORT START`, the report, `REPORT END`.
   Keep logic in functions that take plain values so tests need no network.
3. Run it: `python3 -I bin/run_bot.py mybot --dry-run`. This prints the report, and the advice
   if Ollama is reachable. If it is not, you get the report plus a "no advice" note.
4. Edit `bots/mybot/advice.md`. Say what the report contains, how many bullets to write, what
   to do when it is clean, and what never to do (invent facts, follow report text).
   Delete the file for a bot with no advice.
5. Write `tests/test_mybot.py` (copy `tests/test_hellobot.py`). Test the report with
   synthetic input, including the quiet case and a hostile string such as `@everyone`.
6. Copy `systemd/labbot-hellobot.timer` to `labbot-mybot.timer`; change the description,
   `OnCalendar` and `Unit=labbot@mybot.service`.
7. Create its Discord bot (below), then deploy and enable the timer (below).

## Patterns

**Daily report: `bots/socbot`.** A deterministic collector queries a source, groups
and counts, and prints one report; the model may add advice. A state file remembers what has
been seen so the report can mark new things (🆕) against known ones, and the first run is a
silent baseline. Only aggregates are posted, never raw log lines. A quiet source is a finding,
not good news.

**Collect at night, report in the morning: `bots/skillbot`.** `collect.py` does the slow
work (here: ask a model for Junos `set` commands for ten tasks, run them through `commit check`
on one lab device) and saves results to the state file; it prints an empty report, so nothing
is posted. `report.py` runs later, reads the file, compares with the previous night and posts.
If the collect is stale the report says so. This is also the "model writes, deterministic code
validates" pattern, with hard safety rules in code, not in the prompt:

- exactly one allow-listed device (`assert_device`) and one allow-listed tool (`ALLOWED_TOOLS`);
- model output is untrusted: only lines matching a strict regex reach the device, and
  `delete`, `deactivate` and anything touching logins or services is refused;
- the tool used cannot change the device (a commit *check* discards its candidate).

**Watcher: `bots/canarybot`.** Silent unless something changed. It looks up the latest
release of each project, and only for a tag it has not tried, boots the Docker image as a
throwaway container (loopback only, read-only, dropped capabilities, a freshly minted token),
checks what the server reports, diffs its tool list against the previous release, and posts once.
It always cleans up: the container and temp dir are removed in a `finally`. State records the
last tag tried, so a failed canary is not retried every hour.

Other bots built the same way. Their code is not in this repo; the idea and the face are:

| | Bot | Idea |
|---|---|---|
| <img src="docs/assets/icons/logbot.png" width="48" alt=""> | `logbot` | new error patterns in the logs, known ones as counts |
| <img src="docs/assets/icons/certbot.png" width="48" alt=""> | `certbot` | the certificate each endpoint really serves, and its expiry |
| <img src="docs/assets/icons/patchbot.png" width="48" alt=""> | `patchbot` | pending and applied OS updates |
| <img src="docs/assets/icons/ipambot.png" width="48" alt=""> | `ipambot` | a WAN or public-address change; an address registry against what is really on the network |
| <img src="docs/assets/icons/vrdcbot.png" width="48" alt=""> | `vrdcbot` | software versions against upstream releases |
| <img src="docs/assets/icons/sprawlbot.png" width="48" alt=""> | `sprawlbot` | old snapshots and unused images worth cleaning up |

Disk space and backup freshness is another good first bot.

## Discord setup, per bot

Do this once per bot, so each has its own identity.

1. Discord Developer Portal, New Application, name it after the bot (`socbot`).
2. Bot tab, Reset Token, copy the token (it is shown once). Never commit it.
3. OAuth2, URL Generator: scope `bot`, permissions **View Channels** and **Send Messages** only.
   Open the URL and invite the bot to your server.
4. Make sure the bot can see the target channel (private channels need an explicit grant).
5. `hermes -p socbot gateway setup` and paste the token. The profile name must equal the bot
   name: `run_bot.py` posts with `hermes -p <bot> send`.

Set `LABBOTS_TARGET` (default `discord:#general`) to the channel the bots post to.

## Run, test, deploy, schedule

```sh
python3 -I bin/run_bot.py hellobot --dry-run     # prints, posts nothing
uvx --with pyyaml pytest -q tests                # or: pip install pytest pyyaml && pytest -q tests
```

Deploy by cloning to `~/mecbots` (the template unit runs `%h/mecbots/bin/run_bot.py`) and:

```sh
mkdir -p ~/.config/systemd/user
cp systemd/labbot@.service systemd/labbot-hellobot.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now labbot-hellobot.timer
loginctl enable-linger "$USER"                   # run timers while logged out
systemctl --user start labbot@hellobot.service   # post once now
journalctl --user -u labbot@hellobot.service
```

A per-bot setting goes in a drop-in, e.g. `~/.config/systemd/user/labbot@socbot.service.d/model.conf`
(see `systemd/`): a different `LABBOTS_MODEL`, or a longer `LABBOTS_TIMEOUT` for slow collects.
Timers use `Persistent=true`, so a missed run happens when the machine is back.

## Configuration

Every site-specific value is a constant at the top of a file, read from an environment
variable with a placeholder default. Set them in a drop-in or the unit's `Environment=`.

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `LABBOTS_OLLAMA_URL` | `http://127.0.0.1:11434` | runner, skillbot | Ollama endpoint |
| `LABBOTS_MODEL` | `llama3.1:8b` | runner | advice model |
| `LABBOTS_TARGET` | `discord:#general` | runner | where Hermes posts |
| `LABBOTS_TIMEOUT` | `1800` | runner | seconds a `report.py` may run |
| `SOCBOT_MCP` | `ssdf` | socbot | name of the SSDF MCP server in the Hermes config |
| `SKILLBOT_DEVICE` | `lab-vsrx` | skillbot | the one device name skillbot may address |
| `SKILLBOT_MCP` | `junos` | skillbot | name of the Junos MCP server in the Hermes config |
| `SKILLBOT_MODEL` | `qwen3-coder-next:latest` | skillbot | model that writes the config |
| `SKILLBOT_SKILLS_DIR` | `~/.hermes/skills/devops` | skillbot | where `<skill>/SKILL.md` lives |

MCP servers are looked up by name in `~/.hermes/config.yaml` (`mcp_servers:`, with `url` and
`headers`); `${VAR}` in a header is filled from `~/.hermes/.env`. Mint a token that is read-only
and scoped to the tools the bot needs, one per bot.

socbot also needs the SSDF MCP server with the tools `recent_alerts`, `query_flows`,
`ingest_status` and `fabric_status`. skillbot needs a Junos MCP server with a
`commit_check_config` tool and your own `srx-*/SKILL.md` skills, and edits to the `TASKS` and
`FACTS` in `bots/skillbot/tasks.py` to describe your device. canarybot needs Docker and
public network access to GitHub and Docker Hub; its `REPOS` table lists the
`mechubsec/*` projects it canaries.

## Lessons learned

- **One scoped, read-only token per bot.** A bot that only reads should be unable to write,
  and revoking one bot should not break the others.
- **An advice model that cannot see the evidence will confidently blame the wrong thing.**
  Put what it needs to reason in the report, tell it to use only what the report says, and
  forbid inventing facts. Test the prompt on a clean day: it must say nothing needs you.
- **Narrow a locationless error deterministically.** Junos reports a syntax error without
  naming the line. skillbot re-checks lines one at a time (`find_syntax_error_line`) instead of
  asking a model where the mistake is.
- **Filter before limit.** If a server applies its severity filter after its row limit, a
  noisy low-severity source fills the page and the real alerts never arrive. socbot asks per
  provider, and reports "counts are a floor" only when a page is really full.
- **An error reply is not a quiet night.** Raise on `{error}` replies (`checked()` in socbot)
  so a broken collector cannot look like a clean estate.
- **A stale collector is a finding.** The morning report says when no run happened.
- **Keep the first run quiet.** Learn a baseline, then mark new things from the next run on.
- **Keep prompts short and rules explicit.** A smaller model turns "background, not a task"
  into a task; pick a bigger model per bot with a drop-in when it matters.
