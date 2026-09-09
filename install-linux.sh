#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

VENV=".venv"

for required in requirements.txt configure_mesh.py launch_node.py kdk_core.py; do
    if [[ ! -f "$required" ]]; then
        printf 'Missing required file: %s\n' "$required" >&2
        exit 1
    fi
done

if ! command -v python3 >/dev/null 2>&1; then
    printf 'Python 3 is required but was not found.\n' >&2
    exit 1
fi

printf 'KryptDisk 1.44 - Linux beta setup\n\n'

if [[ ! -x "$VENV/bin/python" ]]; then
    printf 'Creating Python virtual environment...\n'
    if ! python3 -m venv "$VENV"; then
        printf '\nCould not create the virtual environment.\n' >&2
        printf 'On Debian/Ubuntu, install python3-venv and run this script again.\n' >&2
        exit 1
    fi
else
    printf 'Using existing Python virtual environment.\n'
fi

printf 'Installing Python requirements...\n'
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -r requirements.txt

printf '\nConfigure this KryptDisk node:\n\n'
"$VENV/bin/python" configure_mesh.py

NODE_NAME="$("$VENV/bin/python" - <<'PY'
import json
from pathlib import Path

path = Path("mesh_config.json")
try:
    cfg = json.loads(path.read_text(encoding="utf-8"))
    nodes = cfg.get("nodes", {})
    if not isinstance(nodes, dict) or len(nodes) != 1:
        raise ValueError
    print(next(iter(nodes)))
except Exception:
    raise SystemExit("Could not determine the configured local node")
PY
)"

printf '\nSetup complete.\n'
printf 'Node: %s\n' "$NODE_NAME"
printf 'To start it later, run:\n'
printf '  %s launch_node.py %q\n\n' "$VENV/bin/python" "$NODE_NAME"

read -r -p "Start KryptDisk now? [Y/n]: " START_NOW
START_NOW="${START_NOW:-Y}"

case "$START_NOW" in
    [Yy]|[Yy][Ee][Ss])
        printf '\nStarting %s...\n\n' "$NODE_NAME"
        exec "$VENV/bin/python" launch_node.py "$NODE_NAME"
        ;;
    *)
        printf 'KryptDisk is configured and ready.\n'
        ;;
esac
