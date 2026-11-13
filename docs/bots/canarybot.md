# canarybot

<img src="../assets/icons/canarybot.png" width="64" alt="">

Looks up the latest release of each `mechubsec` MCP project. For a tag it has not tried, it boots the Docker
image as a throwaway container, checks what the server reports, diffs its tool list against the previous
release, and posts once.

- **Pattern:** watcher. Silent unless something changed; the last tag tried is in the state file, so a failed
  canary is not retried every hour.
- **Needs:** Docker; public access to GitHub and Docker Hub. Its `REPOS` table lists the projects it canaries.
- **Env vars:** none of its own.
- **Schedule:** hourly at :40 (`systemd/labbot-canarybot.timer`).

## How it checks

The container runs loopback only, read-only, with all capabilities dropped and a freshly minted token. The
check compares `serverInfo.version` with the tag. The tool surface comes from the image's own registry,
listed over stdio with no network and no token, so write tools that a token scope would hide are included;
the HTTP listing under a `*` token must be a subset of it. The one-shot stdio session reads a single page of
`tools/list`; if the reply carries a `nextCursor` (even an empty string) the canary fails with "tool list is paginated: not supported"
instead of recording a truncated baseline (later tools would read as removed).

## Safety rules it enforces

- The container and temp directory are removed in a `finally`, including the stdio one.
- State records the last tag tried.
- Only the tag two releases back is removed from Docker, never a blanket prune.
- One bad image becomes one red line, not a failed run.

## Known limits

- It proves an image boots and lists its tools, not that it works against a device.
- A new release that passes the canary can still break on live calls.
