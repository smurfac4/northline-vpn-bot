#!/usr/bin/env python3
"""Restricted WireGuard peer operations, invoked by the SSH key or local timer."""
import base64
import fcntl
import ipaddress
import json
import subprocess
import sys
import time
from pathlib import Path

DIRECTORY = Path("/var/lib/northline-wg")
INTERFACE = "wg0"


def wg(*args):
    return subprocess.run(
        ["/usr/bin/wg", *args], check=True, text=True, capture_output=True, timeout=5
    ).stdout


def valid_key(key):
    return len(base64.b64decode(key, validate=True)) == 32


def save(state_path, peers):
    temporary = state_path.with_suffix(".tmp")
    with temporary.open("w") as file:
        json.dump(peers, file)
    temporary.chmod(0o600)
    temporary.replace(state_path)


def control(command):
    subnet = ipaddress.IPv4Network((DIRECTORY / "subnet").read_text().strip())
    state_path = DIRECTORY / "peers.json"
    peers = json.loads(state_path.read_text()) if state_path.exists() else {}
    now = int(time.time())
    if command == ["ping"]:
        print(wg("show", INTERFACE, "public-key").strip())
        return

    if command == ["metrics"]:
        rows = [line.split() for line in wg("show", INTERFACE, "transfer").splitlines() if line.strip()]
        print(json.dumps({"rx_bytes":sum(int(row[1]) for row in rows),
                          "tx_bytes":sum(int(row[2]) for row in rows), "peer_count":len(rows)}))
        return

    if command == ["sync"]:
        existing = set(wg("show", INTERFACE, "peers").split())
        for key, peer in list(peers.items()):
            if peer.get('revoked') or (not peer.get('unlimited') and peer["expires"] <= now):
                if key in existing:
                    wg("set", INTERFACE, "peer", key, "remove")
                del peers[key]
            elif key not in existing:
                wg("set", INTERFACE, "peer", key, "allowed-ips", peer["address"])
        save(state_path, peers)
        return

    if len(command) == 2 and command[0] == "remove" and valid_key(command[1]):
        key = command[1]
        if key in peers:
            # Persist revocation intent before touching the interface. A failed
            # final save must never make the sync timer re-enable this peer.
            peers[key] = {**peers[key], "expires": 0, 'unlimited': False, 'revoked': True}
            save(state_path, peers)
        wg("set", INTERFACE, "peer", key, "remove")
        if key in peers:
            del peers[key]
            save(state_path, peers)
        return

    if len(command) == 4 and command[0] == "add" and valid_key(command[1]):
        _, key, raw_address, raw_expiry = command
        address = ipaddress.IPv4Interface(raw_address)
        expiry = int(raw_expiry)
        if (address.network.prefixlen != 32 or address.ip not in subnet
                or int(address.ip) - int(subnet.network_address) not in range(2, 255)
                or not (expiry == 0 or now < expiry <= now + 721 * 3600)):
            raise ValueError("Invalid address or expiry.")
        if any(other != key and value["address"] == str(address) for other, value in peers.items()):
            raise ValueError("VPN address already reserved.")
        peers[key] = {"address": str(address), "expires": expiry, 'unlimited': expiry == 0}
        save(state_path, peers)
        wg("set", INTERFACE, "peer", key, "allowed-ips", str(address))
        return

    raise ValueError("Unsupported command.")


def main():
    try:
        if sys.argv[1:] == ["sync"]:
            command = ["sync"]
        elif len(sys.argv) == 1:
            command = sys.stdin.readline(512).split()
            if command == ["sync"]:
                raise ValueError("Sync is available to the local timer.")
        else:
            raise ValueError("Invalid invocation.")
        with (DIRECTORY / "lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            control(command)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"WireGuard control failed: {type(error).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
