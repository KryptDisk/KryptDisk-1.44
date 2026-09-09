#!/usr/bin/env python3
"""Configure a local KryptDisk node for the public beta."""
from __future__ import annotations

import json
from pathlib import Path

PATH = Path(__file__).resolve().with_name("mesh_config.json")

DEFAULT_NAME = "Kryptonaut"
DEFAULT_PORT = 6001
DEFAULT_BOOTSTRAP = "49.13.141.184:6001"


def _read_config() -> dict:
    if not PATH.exists():
        return {}
    try:
        data = json.loads(PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not read {PATH.name}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"{PATH.name} must contain a JSON object")
    return data


def _ask_name() -> str:
    raw = input(f"Node name [{DEFAULT_NAME}]: ").strip()
    name = raw or DEFAULT_NAME

    if any(ch in name for ch in "\\/:*?\"<>|"):
        raise SystemExit('Node name contains a character not suitable for a profile name')
    if name in {".", ".."}:
        raise SystemExit("Invalid node name")
    return name


def _ask_port() -> int:
    raw = input(f"KryptDisk port [{DEFAULT_PORT}]: ").strip()
    try:
        port = int(raw) if raw else DEFAULT_PORT
    except ValueError:
        raise SystemExit("Port must be a number")

    if not 1 <= port <= 65535:
        raise SystemExit("Port must be between 1 and 65535")
    return port


def main() -> None:
    cfg = _read_config()

    name = _ask_name()
    port = _ask_port()

    # Public installs define only the node running on this machine.
    cfg["nodes"] = {
        name: {
            "host": "127.0.0.1",
            "port": port,
            "relay": True,
        }
    }

    # Bootstrap endpoints are remote discovery seeds, not local nodes.
    peers = cfg.get("bootstrap_peers", [])
    if not isinstance(peers, list):
        peers = []

    cleaned = []
    for peer in peers:
        peer = str(peer).strip()
        if peer and peer not in cleaned:
            cleaned.append(peer)

    if DEFAULT_BOOTSTRAP not in cleaned:
        cleaned.insert(0, DEFAULT_BOOTSTRAP)

    cfg["bootstrap_peers"] = cleaned

    # Remove the old LAN-test configuration key if present.
    cfg.pop("laptop", None)

    PATH.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")

    print()
    print(f"Configured KryptDisk node: {name}")
    print(f"Local endpoint: 127.0.0.1:{port}")
    print(f"Relay: enabled")
    print(f"Bootstrap: {DEFAULT_BOOTSTRAP}")


if __name__ == "__main__":
    main()
