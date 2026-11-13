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

<p align="center"><em>a mechub project — sovereign network-security automation</em></p>

<p align="center"><img src="docs/assets/icons/mecbots.png" width="96" alt="mecbots mascot"></p>

<p align="center"><img alt="license" src="https://img.shields.io/badge/license-MIT-262B38"></p>
<!-- brand:header:end -->

## What this is

Small, deterministic bots that report to Discord. A bot is a script that prints a finished report, an
optional prompt for a local model, and a systemd timer. The model only adds a few lines of advice and has
no tools. A how-to with a runner and five example bots, not a product: copy what you need.

**Discord is not sovereign.** It is a cloud service, used here only as the exit point for scrubbed reports;
the full report never leaves your machine. A self-hosted push option ([ntfy](https://ntfy.sh)) is planned.

## Install

Needs Linux with systemd, Python 3.11+, PyYAML, [Ollama](https://ollama.com), [Hermes Agent](https://github.com/NousResearch/hermes-agent) and a Discord server you administer.

```sh
git clone https://github.com/mechubsec/mecbots ~/mecbots && cd ~/mecbots
mkdir -p ~/.config/systemd/user && cp systemd/labbot@.service systemd/labbot-hellobot.timer ~/.config/systemd/user/ && systemctl --user daemon-reload && systemctl --user enable --now labbot-hellobot.timer
```

Then give hellobot its Discord identity: [docs/SETUP.md](docs/SETUP.md).

## Use

```sh
python3 -I bin/run_bot.py hellobot --dry-run     # prints the report, posts nothing
uvx --with pyyaml pytest -q tests                # the tests
```

To start your own, copy `bots/hellobot`: [docs/FIRST-BOT.md](docs/FIRST-BOT.md).

| | Bot | What it does |
|---|---|---|
| <img src="docs/assets/icons/hellobot.png" width="48" alt=""> | [`hellobot`](docs/bots/hellobot.md) | free disk space and load; the smallest bot |
| <img src="docs/assets/icons/socbot.png" width="48" alt=""> | [`socbot`](docs/bots/socbot.md) | daily security report from SSDF, with a queue for an agent |
| <img src="docs/assets/icons/skillbot.png" width="48" alt=""> | [`skillbot`](docs/bots/skillbot.md) | installed agent skills against upstream releases |
| <img src="docs/assets/icons/reposbot.png" width="48" alt=""> | [`reposbot`](docs/bots/reposbot.md) | nightly check that skills still produce config a device accepts |
| <img src="docs/assets/icons/canarybot.png" width="48" alt=""> | [`canarybot`](docs/bots/canarybot.md) | boots each new release image; silent unless one appeared |

## More

- [docs/SETUP.md](docs/SETUP.md) · [docs/FIRST-BOT.md](docs/FIRST-BOT.md) · [docs/RULES.md](docs/RULES.md) · [docs/IDEAS.md](docs/IDEAS.md)
- [docs/CAVEATS.md](docs/CAVEATS.md) · [docs/VERSIONING.md](docs/VERSIONING.md) · [CHANGELOG.md](CHANGELOG.md) · [LICENSE](LICENSE)
- Agents: a riskier tier that gives the model read-only tools: [mecagents](https://github.com/mechubsec/mecagents).
