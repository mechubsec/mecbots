# skillbot

<img src="../assets/icons/skillbot.png" width="64" alt="">

Which AI-agent skills (Claude, Codex, Hermes) are installed on your hosts, against the latest release of the
public repos they come from, with every newer version screened before anyone installs it.

- **Pattern:** inventory versus upstream. `collect.py` runs at night, `report.py` in the morning.
- **Needs:** Ollama; GitHub reachable without a token (1-3 calls per source); for remote hosts, SSH and the
  forced-command key below. No MCP server.
- **Env vars:** `SKILLBOT_HOSTS`, `SKILLBOT_SSH_KEY`, `SKILLBOT_MODEL`, `SKILLBOT_STATE`, `SKILLBOT_WAKE_MACS`,
  `SKILLBOT_WAKE_BROADCAST`, `SKILLBOT_PUBKEY`, `SKILLBOT_FROM`, `LABBOTS_OLLAMA_URL` ([SETUP.md](../SETUP.md)).
- **Schedule:** collect 01:30, report 07:35; the report waits for the collect (drop-in).

## Setup

Generate a key, list your hosts in `SKILLBOT_HOSTS` (names `ssh` can resolve), and run
`SKILLBOT_PUBKEY="$(cat ~/.ssh/id_ed25519_skillbot.pub)" bots/skillbot/setup.sh <remote-host>...` once. Edit
`SOURCES` in `collect.py` if you track other repos (its two defaults are public).

## Safety rules it enforces

- **A forced-command SSH key.** Each remote host runs `collect.sh` whatever the caller asks, via a
  `restrict,from=...,command=...` line in `authorized_keys`. The collector prints names, versions and hashes,
  never file contents, and takes no arguments. `setup.sh` fails fast and backs up `authorized_keys` first.
- **A sentinel line.** `collect.sh` ends with `ok collector 1`, so a reachable host with no skills is not
  "unreachable", and output without the sentinel counts as unfinished.
- **Numeric version comparison.** `1.10.0` is newer than `1.9.9`. Each skill is `outdated`, `drift` (same or no
  version, different file hash), `ahead` (installed is newer; posted too) or current.
- **Tagless sources work.** A repo with no release tag is read from its default branch.
- **Mixed versions.** If targets run different versions, the whole new release is scanned, not just what is
  new against one host's copy.
- **An untrusted tarball is extracted safely.** Regular files and directories only, below the target, with caps
  on size and member count; links, absolute names and `..` are refused; nothing is executed.
- **An incomplete scan says so.** Files and bytes the read limits left out are counted, and the report shows
  "scan incomplete" instead of "none".
- **Review flags are prompts to read the diff, not verdicts.** Regexes look for instruction override, hiding
  things from the user, fetch-and-run, outbound data, credential paths, hidden characters, new domains and
  widened `allowed-tools`. Nothing is blocked or installed because of a flag.
- **Flag only what is new.** Against an installed copy only lines not already there are flagged.
- **A model's reading is labelled unverified.** A local model summarises the diff with no tools; the text is
  defanged and never changes a flag.
- **Post only on change.** The report speaks when something is new since the last collect, or on Mondays while
  anything is outdated. A catch-up collect is not rolled past before a report has run.

## Known limits

- The screening has only been exercised on fixtures.
- It tracks the repos in `SOURCES` only; other installed skills are listed as "other", not compared.
- A host that is off is "unreachable" unless Wake-on-LAN is configured and works.
