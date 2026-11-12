"""canarybot (release canary, hourly): when a mechubsec MCP repo's latest release has a Docker Hub
image canarybot has not tried yet, boots it as a throwaway container (empty inventory, freshly minted
token, loopback only), checks serverInfo.version against the tag and diffs the tool surface against
the previous release's. Posts once per new release; prints an empty report when nothing is new."""

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# repo -> (binary in the image, port, minimal inventory, extra flags). Both mecmcp servers boot the same
# way: a devices.json (0600), a tokens file minted by `token add`, streamable-http. The image
# entrypoint's /var/lib paths are not writable by our uid, so every state path points into /cfg. The
# other mechubsec servers are left out until someone checks their inventory format and flags.
REPOS = {
    "rustjunosmcp": ("rust-junosmcp", 30030, {}, ["--device-lease-dir", "/cfg/leases", "--staging-dir", "/cfg/staging", "--known-hosts-file", "/cfg/known_hosts", "--state-file", "/cfg/state.json"]),
    "rustpanosmcp": ("rust-panosmcp", 30031, {"version": 1, "devices": [{"name": "canary-dummy", "endpoint": "https://192.0.2.1", "vsys": "vsys1",
                                                         "api_key": {"type": "env", "name": "CANARY_KEY"}}]},
                     ["--state-file", "/cfg/state.json"]),
}
ORG = "mechubsec"  # GitHub org whose releases are canaried; the images are mechub/<repo> on Docker Hub
DOCKER_TAG = "https://hub.docker.com/v2/repositories/mechub/{repo}/tags/{version}"
USER_AGENT = "labbots/1"
STATE_FILE = Path.home() / ".local/state/labbots/canarybot.json"
BOOT_TIMEOUT_SECONDS = 60
PULL_TIMEOUT_SECONDS = 600
LOG_LINES = 10

# shortcut: the canary proves the image boots and exposes its tool surface; it does not exercise a
# real device, so a release that breaks only on live NETCONF/PAN-OS calls passes. Upgrade when such a
# release gets through: add a mock-device call per repo.


def fetch(url: str) -> str:
    """GET a URL as text with the labbots user agent (Cloudflare refuses Python-urllib)."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/html, */*"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode()


def latest_release(repo: str) -> str:
    """Latest release tag without the leading v, or "" when the repo has none."""
    try:
        return json.loads(fetch(f"https://api.github.com/repos/{ORG}/{repo}/releases/latest"))["tag_name"].lstrip("v")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return ""
        raise


def needs_canary(state: dict, repo: str, tag: str) -> bool:
    """True when this repo's latest tag differs from the last one canaried."""
    return state.get(repo, {}).get("tag") != tag


def tool_digests(tools: list[dict]) -> dict[str, str]:
    """{tool name: short digest of its inputSchema} from a tools/list result."""
    return {tool["name"]: hashlib.sha256(json.dumps(tool.get("inputSchema"), sort_keys=True).encode()).hexdigest()[:12] for tool in tools}


def diff_tools(old: dict[str, str], new: dict[str, str]) -> tuple[list[str], list[str], list[str]]:
    """(added, removed, schema-changed) tool names between two digest maps."""
    return sorted(new.keys() - old.keys()), sorted(old.keys() - new.keys()), sorted(name for name in old.keys() & new.keys() if old[name] != new[name])


def verdict(tag: str, server_version: str | None) -> str:
    """"" when the server reports the tag as its version, else the reason it is a failure."""
    if server_version is None:
        return "no serverInfo.version in the initialize reply"
    return "" if server_version.lstrip("v") == tag else f"serverInfo.version is {server_version}, tag is {tag}"


def format_result(repo: str, tag: str, problem: str, boot_seconds: float, tools: dict[str, str], previous: dict[str, str] | None, log_tail: list[str]) -> str:
    """One repo's report block. previous is None on a baseline (first canary of the repo)."""
    if problem:
        return f"🔴 **{repo} {tag}**: {problem}\n```\n" + "\n".join(log_tail[-LOG_LINES:]) + "\n```"
    head = f"✅ **{repo} {tag}** · booted in {boot_seconds:.1f}s · {len(tools)} tools"
    if previous is None:
        return head + " · baseline recorded, nothing to compare"
    added, removed, changed = diff_tools(previous, tools)
    lines = [head + ("" if added or removed or changed else " · tool surface unchanged")]
    for icon, names in (("➕ added", added), ("➖ removed", removed), ("✏️ schema changed", changed)):
        if names:
            lines.append(f"{icon}: {', '.join(names)}")
    return "\n".join(lines)


def mcp_tools(url: str, token: str) -> tuple[dict, list[dict]]:
    """(serverInfo, every tool) over streamable HTTP: initialize, then tools/list across its pages."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    session = {}
    counter = iter(range(1, 100))

    def rpc(method: str, params: dict | None = None, notify: bool = False) -> dict:
        body = {"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {}), **({} if notify else {"id": next(counter)})}
        request = urllib.request.Request(url, json.dumps(body).encode(), {**headers, **session}, method="POST")
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.headers.get("Mcp-Session-Id"):
                session["Mcp-Session-Id"] = response.headers["Mcp-Session-Id"]
            raw = response.read().decode()
        if notify or not raw.strip():
            return {}
        if raw.lstrip().startswith("{"):
            return json.loads(raw)
        return json.loads([line[5:].strip() for line in raw.splitlines() if line.startswith("data:")][-1])

    info = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "canarybot", "version": "1"}}).get("result", {}).get("serverInfo") or {}
    rpc("notifications/initialized", notify=True)
    tools, cursor = [], None
    while True:
        result = rpc("tools/list", {"cursor": cursor} if cursor else {}).get("result", {})
        tools += result.get("tools", [])
        cursor = result.get("nextCursor")
        if not cursor:
            return info, tools


def free_port() -> int:
    """An unused TCP port on loopback."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def docker(*args: str, timeout: int = 60, **kwargs) -> subprocess.CompletedProcess:
    """Run a docker command, capturing text output."""
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, **kwargs)


def canary(repo: str, tag: str) -> tuple[str, float, dict[str, str], list[str]]:
    """Boot mechub/<repo>:<tag> throwaway and return (problem, boot seconds, tool digests, log tail).
    The container and temp dir are always removed."""
    binary, port, inventory, extra_flags = REPOS[repo]
    image, name, host_port = f"mechub/{repo}:{tag}", f"canarybot-{repo}-{os.getpid()}", free_port()
    user = f"{os.getuid()}:{os.getgid()}"
    workdir = Path(tempfile.mkdtemp(prefix="canarybot-"))
    log_path, container, token = workdir / "container.log", None, ""
    try:
        devices = workdir / "devices.json"
        devices.write_text(json.dumps(inventory))
        devices.chmod(0o600)  # the servers refuse a looser inventory
        for subdir in ("leases", "staging"):
            (workdir / subdir).mkdir(mode=0o700)
        minted = docker("run", "--rm", "--network", "none", "--cap-drop", "ALL", "--user", user, "-e", "CANARY_KEY=unused", "-v", f"{workdir}:/cfg", "--entrypoint", f"/usr/local/bin/{binary}",
                        image, "token", "add", "-f", "/cfg/devices.json", "--tokens-file", "/cfg/tokens.json", "--name", "canary", "--devices", "*", "--tools", "*")
        secrets = re.findall(r"[A-Za-z0-9_\-.]{24,}", minted.stdout)  # the secret is the only long word it prints
        if minted.returncode or not secrets:
            return f"could not mint a token: {minted.stderr.strip()[-200:]}", 0.0, {}, []
        token = max(secrets, key=len)
        started = time.monotonic()
        with log_path.open("w") as log:
            container = subprocess.Popen(
                ["docker", "run", "--rm", "--name", name, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/tmp", "--user", user, "-e", "CANARY_KEY=unused",
                 "-v", f"{workdir}:/cfg", "-p", f"127.0.0.1:{host_port}:{port}", "--entrypoint", f"/usr/local/bin/{binary}", image,
                 "-f", "/cfg/devices.json", "--tokens-file", "/cfg/tokens.json", "-t", "streamable-http", "-H", "0.0.0.0", "-p", str(port),
                 "--allow-insecure-bind", "--allowed-host", f"127.0.0.1:{host_port}", "--allowed-origin", f"http://127.0.0.1:{host_port}", *extra_flags], stdout=log, stderr=subprocess.STDOUT)
        info, tools, problem = {}, [], "did not answer MCP initialize within the boot timeout"
        while time.monotonic() - started < BOOT_TIMEOUT_SECONDS:
            if container.poll() is not None:
                problem = f"container exited with code {container.returncode} before answering"
                break
            try:
                info, tools = mcp_tools(f"http://127.0.0.1:{host_port}/mcp", token)
                problem = ""
                break
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
                time.sleep(0.5)
        boot_seconds = time.monotonic() - started
        problem = problem or verdict(tag, info.get("version")) or ("tools/list is empty" if not tools else "")
        log_tail = [line.replace(token, "<token>") for line in log_path.read_text(errors="replace").splitlines()]
        return problem, boot_seconds, tool_digests(tools), log_tail
    finally:
        docker("rm", "-f", name)
        if container:
            container.kill()
            container.wait()
        shutil.rmtree(workdir, ignore_errors=True)


def main() -> None:
    """Canary each repo's new release, update the state, print what happened."""
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    blocks, errors = [], []
    for repo in REPOS:
        try:
            tag = latest_release(repo)
            if not tag or not needs_canary(state, repo, tag):
                continue
            fetch(DOCKER_TAG.format(repo=repo, version=tag))
        except urllib.error.HTTPError as exc:
            if exc.code != 404:  # 404 on the Docker tag = image not published yet, try again next hour
                errors.append(f"❓ {repo}: lookup failed (HTTP {exc.code})")
            continue
        except Exception as exc:
            errors.append(f"❓ {repo}: lookup failed ({type(exc).__name__})")
            continue
        pulled = docker("pull", "-q", f"mechub/{repo}:{tag}", timeout=PULL_TIMEOUT_SECONDS)
        if pulled.returncode:
            errors.append(f"❓ {repo} {tag}: docker pull failed: {pulled.stderr.strip()[-150:]}")
            continue
        entry = state.get(repo, {})
        problem, boot_seconds, tools, log_tail = canary(repo, tag)
        blocks.append(format_result(repo, tag, problem, boot_seconds, tools, entry.get("tools"), log_tail))
        # a failed canary keeps the last good tool list as the baseline for the next release
        state[repo] = {"tag": tag, "previous": entry.get("tag", ""), "tools": entry.get("tools") if problem else tools}
        if entry.get("previous") and entry["previous"] not in (tag, entry.get("tag")):
            docker("rmi", f"mechub/{repo}:{entry['previous']}")  # only the tag two releases back, never a blanket prune
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=1))

    print("REPORT START")
    if blocks or errors:
        print("**canarybot** · new mechubsec MCP releases\n" + "\n".join(blocks + errors))
    print("REPORT END")


if __name__ == "__main__":
    main()
