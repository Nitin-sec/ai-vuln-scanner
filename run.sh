#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python"
if [ ! -f "$VENV_PYTHON" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
    venv/bin/pip install --quiet -r requirements.txt
fi
venv/bin/pip install --quiet -r requirements.txt 2>/dev/null || true
exec "$VENV_PYTHON" main.py "$@"
