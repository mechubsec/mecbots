"""Minimal MCP client for the bots: streamable-HTTP JSON-RPC against the servers
registered in Hermes (~/.hermes/config.yaml mcp_servers), tokens from ~/.hermes/.env."""

import json
import os
import re
import ssl
import urllib.request
from pathlib import Path


def mcp_endpoint(server_name: str) -> tuple[str, dict]:
    """Return (url, headers) for an MCP server from Hermes config, expanding ${VAR} from ~/.hermes/.env."""
    import yaml
    hermes_dir = Path.home() / ".hermes"
    env = {}
    for line in (hermes_dir / ".env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip("'\"")
    server = yaml.safe_load((hermes_dir / "config.yaml").read_text())["mcp_servers"][server_name]
    expand = lambda value: re.sub(r"\$\{([A-Za-z0-9_]+)\}", lambda m: env.get(m.group(1), os.environ.get(m.group(1), "")), str(value))
    return server["url"], {key: expand(value) for key, value in (server.get("headers") or {}).items()}


def mcp_server_info(server_name: str) -> dict:
    """The server's initialize reply serverInfo ({name, version, ...}), without calling any tool."""
    info = {}
    mcp_call_tools(server_name, [], info)
    return info


def mcp_call_tools(server_name: str, calls: list[tuple[str, dict]], server_info: dict | None = None) -> list:
    """Open one MCP session and return the parsed JSON text result of each (tool, arguments) call.
    server_info, when given, is filled with the initialize reply's serverInfo."""
    url, auth_headers = mcp_endpoint(server_name)
    base_headers = {**auth_headers, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    session_id = None
    next_id = 0

    def rpc(method: str, params: dict | None = None, notify: bool = False):
        nonlocal session_id, next_id
        body = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not notify:
            next_id += 1
            body["id"] = next_id
        headers = dict(base_headers)
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        request = urllib.request.Request(url, json.dumps(body).encode(), headers, method="POST")
        with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response:
            session_id = response.headers.get("Mcp-Session-Id") or session_id
            raw = response.read().decode()
        if notify or not raw.strip():
            return None
        if raw.lstrip().startswith("{"):
            return json.loads(raw)
        events = [line[5:].strip() for line in raw.splitlines() if line.startswith("data:")]
        return json.loads(events[-1])

    try:
        init = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "labbots", "version": "1"}})
        if server_info is not None:
            server_info.update((init or {}).get("result", {}).get("serverInfo") or {})
        rpc("notifications/initialized", notify=True)
        results = []
        for tool, arguments in calls:
            reply = rpc("tools/call", {"name": tool, "arguments": arguments})
            result = reply.get("result") or {}
            if "error" in reply or result.get("isError"):
                # keep the server's message: it is the bug report
                detail = reply.get("error", {}).get("message") or (result.get("content") or [{}])[0].get("text", "")
                raise RuntimeError(f"{tool}: {str(detail)[:200]}")
            results.append(json.loads(result["content"][0]["text"]))
        return results
    finally:
        # servers may cap sessions per token: end ours rather than leak it
        if session_id:
            try:
                urllib.request.urlopen(urllib.request.Request(url, headers={**auth_headers, "Mcp-Session-Id": session_id}, method="DELETE"),
                                       timeout=10, context=ssl.create_default_context()).close()
            except Exception:
                pass  # a server that doesn't support DELETE reaps the session itself

