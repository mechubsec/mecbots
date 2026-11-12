"""Reaching other machines: optional Wake-on-LAN for hosts that sleep, and SSH through a bot's restricted key."""

import os
import socket
import time
from pathlib import Path

# shortcut: wake-on-LAN is best effort and IPv4 broadcast only; no per-host retry policy. Upgrade if a host
# needs a directed packet or a longer wait.
# Hosts that sleep or hibernate: "name=MAC,name=MAC" in SKILLBOT_WAKE_MACS. Empty (the default) wakes nothing.
WAKE_MACS = dict(pair.split("=", 1) for pair in os.environ.get("SKILLBOT_WAKE_MACS", "").split(",") if "=" in pair)
WAKE_BROADCAST = os.environ.get("SKILLBOT_WAKE_BROADCAST", "255.255.255.255")  # your subnet's broadcast address is better
WAKE_WAIT_SECONDS = 180


def ssh_port_open(host: str) -> bool:
    """True when host accepts a TCP connection on port 22."""
    try:
        with socket.create_connection((host, 22), timeout=3):
            return True
    except OSError:
        return False


def wake_host(host: str) -> None:
    """Wake a sleeping host with a magic packet and wait until SSH answers (best effort)."""
    mac = WAKE_MACS.get(host)
    if not mac or ssh_port_open(host):
        return
    packet = b"\xff" * 6 + bytes.fromhex(mac.replace(":", "")) * 16
    deadline = time.monotonic() + WAKE_WAIT_SECONDS
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while time.monotonic() < deadline:
            sock.sendto(packet, (WAKE_BROADCAST, 9))
            if ssh_port_open(host):
                time.sleep(5)  # let sshd and the network settle after resume
                return
            time.sleep(5)


def ssh_command(key_name: str, host: str, remote_command: str) -> list[str]:
    """ssh argv using only ~/.ssh/<key_name>; the host's forced command decides what actually runs."""
    return ["ssh", "-i", str(Path.home() / ".ssh" / key_name), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10", host, remote_command]
