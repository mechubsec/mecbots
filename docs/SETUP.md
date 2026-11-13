# Setup

## Prerequisites

- Linux with systemd user units, Python 3.11+, PyYAML (for bots that read the Hermes config via `lib/mcp.py`).
- [Ollama](https://ollama.com) with a model pulled (set `LABBOTS_MODEL`).
- [Hermes Agent](https://github.com/NousResearch/hermes-agent), `hermes` on PATH. It owns the Discord connection.
- A Discord server you administer. Docker for canarybot only.

```sh
git clone https://github.com/mechubsec/mecbots ~/mecbots
```

The template unit runs `%h/mecbots/bin/run_bot.py`, so clone to `~/mecbots` or edit the unit.

## Discord, per bot

Once per bot, so each has its own identity.

1. Discord Developer Portal, New Application, name it after the bot (`hellobot`).
2. Bot tab, Reset Token, copy the token (shown once). Never commit it.
3. OAuth2, URL Generator: scope `bot`, permissions **View Channels** and **Send Messages** only. Open the URL
   and invite the bot to your server.
4. Make sure the bot can see the target channel (private channels need an explicit grant).
5. `hermes -p hellobot gateway setup` and paste the token. The profile name must equal the bot name:
   the runner posts with `hermes -p <bot> send`.

Set `LABBOTS_TARGET` (default `discord:#general`) to the channel the bots post to.

## Deploy and schedule

```sh
mkdir -p ~/.config/systemd/user
cp systemd/labbot@.service systemd/labbot-hellobot.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now labbot-hellobot.timer
loginctl enable-linger "$USER"                   # run timers while logged out
systemctl --user start labbot@hellobot.service   # post once now
journalctl --user -u labbot@hellobot.service
```

Other bots: copy `systemd/labbot-<bot>*.timer` and any `labbot@<bot>*.service.d/` folder the same way. Collect
and report bots have two timers; a drop-in makes the report wait for its collect. Times are in the `.timer`
files. Timers use `Persistent=true`, so a missed run happens when the machine is back.

A per-bot setting goes in a drop-in, for example `~/.config/systemd/user/labbot@socbot.service.d/model.conf`
(see `systemd/`): a different `LABBOTS_MODEL`, or a longer `LABBOTS_TIMEOUT` for slow collects.

### Optional: quiet hours

No unit in this repo skips any hours. To keep bots from starting while the machine is busy, add a drop-in for
all bots, `~/.config/systemd/user/labbot@.service.d/quiet-hours.conf`, here skipping 09:00 to 17:00:

```ini
[Service]
ExecCondition=/bin/sh -c 'h=$$(date +%%H); [ "$$h" -lt 9 ] || [ "$$h" -ge 17 ]'
```

A start that fails the condition is skipped without marking the unit failed, and it is not retried; move the
timers outside those hours if you need the run.

## Configuration

Every site-specific value is a constant at the top of a file, read from an environment variable with a fake
default. Set them in a drop-in or the unit's `Environment=`.

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `LABBOTS_OLLAMA_URL` | `http://127.0.0.1:11434` | runner, reposbot, skillbot | Ollama endpoint |
| `LABBOTS_MODEL` | `llama3.1:8b` | runner | advice model |
| `LABBOTS_TARGET` | `discord:#general` | runner | where Hermes posts |
| `LABBOTS_TIMEOUT` | `1800` | runner | seconds a `report.py` may run |
| `LABBOTS_REPORTS` | `~/labbots-reports` | runner | where full reports are kept |
| `LABBOTS_REDACT` | `~/.config/labbots/redact.txt` | runner | the private redact list |
| `SOCBOT_MCP` | `ssdf` | socbot | name of the SSDF MCP server in the Hermes config |
| `SOCBOT_STATE` | `~/.local/state/labbots/socbot.json` | socbot | state file |
| `SOCBOT_ESCALATIONS` | `~/.local/state/labbots/socbot-escalations.json` | socbot | the queue an agent reads |
| `REPOSBOT_DEVICE` | `lab-vsrx` | reposbot | the one device name reposbot may address |
| `REPOSBOT_MCP` | `junos` | reposbot | name of the Junos MCP server in the Hermes config |
| `REPOSBOT_MODEL` | `qwen3-coder-next:latest` | reposbot | model that writes the config |
| `REPOSBOT_SKILLS_DIR` | `~/.hermes/skills/devops` | reposbot | where `<skill>/SKILL.md` lives |
| `SKILLBOT_HOSTS` | `hosta,hostb` | skillbot | hosts to inventory; the one running the job is read locally, the rest over SSH |
| `SKILLBOT_SSH_KEY` | `id_ed25519_skillbot` | skillbot | file in `~/.ssh` whose forced command runs `collect.sh` |
| `SKILLBOT_MODEL` | `llama3.1:8b` | skillbot | model that reads each diff |
| `SKILLBOT_STATE` | `~/.local/state/labbots/skillbot.json` | skillbot | state file |
| `SKILLBOT_WAKE_MACS` | empty | skillbot | `name=MAC,...` for hosts that sleep; empty wakes nothing |
| `SKILLBOT_WAKE_BROADCAST` | `255.255.255.255` | skillbot | broadcast address for the wake packet |
| `SKILLBOT_PUBKEY`, `SKILLBOT_FROM` | none, `198.51.100.10` | `setup.sh` | the collector's public key, and its address as remote hosts see it |

## MCP servers

MCP servers are looked up by name in `~/.hermes/config.yaml` (`mcp_servers:`, with `url` and `headers`);
`${VAR}` in a header is filled from `~/.hermes/.env`. Mint a token that is read-only and scoped to the tools the
bot needs, one per bot. Per-bot needs are in [docs/bots/](bots/). socbot needs an SSDF version that has the
`alert_counts` tool, and its token must list that tool ([socbot](bots/socbot.md)).

## Two-tier reporting

Every post has two copies.

- **Full report**, kept local: `~/labbots-reports/<bot>/YYYY-MM-DD_HHMMSS.md` (directories mode 700, files 600,
  newest 60 per bot; a second run in the same second gets `_2`, `_3`), plus an `index.html` listing each bot's
  newest 20, rewritten atomically under a lock so bots finishing together cannot interleave. The bot's post says
  where it is.
- **Discord copy**, scrubbed: IPv4 and IPv6 addresses become `[ip]`, MAC addresses `[mac]`, and every name in the
  redact list `[name]`. Dotted MACs (`aabb.ccdd.eeff`) and IPv4-mapped IPv6 (`::ffff:192.0.2.10`) are scrubbed too.
  Version numbers that look like addresses are kept when the word "version", "upstream" or similar is just before
  them on the same line.

A scrub failure stops the post, and so does a redact list that exists but cannot be read (permissions, a
directory, an I/O error): only a list that does not exist is tolerated. A failed local copy does not stop it; the
post says so.

### The redact list

`~/.config/labbots/redact.txt`, one name per line, `#` starts a comment. Names are hosts, domains, devices,
people: anything you would not paste into a public chat. Matching is whole-token and case-insensitive, longest
first; a domain also covers its subdomains; a leading `*.` is allowed.

```
# example only
labhost-1
labhost-2
example.org
*.corp.example
```

With this list `labhost-1 and a.b.example.org` becomes `[name] and [name]`, and `labhost-10` is left alone. Keep
the file private and out of any repository. If it does not exist, only addresses are scrubbed and the post says so.

### Reading the full reports

There is deliberately no always-on report server: a web server on loopback would let any local process on the
host read the unscrubbed reports and bypass the 700/600 modes. Read them on demand, inside your own SSH session.

```sh
ssh you@bot-host cat '~/labbots-reports/<bot>/<file>.md'
```

or a page that exists only while that session is open (it stops when you disconnect):

```sh
ssh -L 8801:127.0.0.1:8801 you@bot-host 'python3 -m http.server 8801 --bind 127.0.0.1 --directory ~/labbots-reports'
```

then open `http://127.0.0.1:8801/` on your own machine. Never bind it to a LAN address: the reports are unscrubbed.

To see what Discord would get without posting: `python3 -I bin/run_bot.py <bot> --dry-run`. Add `--full` for the
unscrubbed text.

## First check

`python3 -I bin/run_bot.py <bot> --dry-run` for every bot before enabling its timer. Some dry runs write state;
see [CAVEATS.md](CAVEATS.md).
