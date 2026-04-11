#!/usr/bin/env bash
# run.sh — ThreatMap Infra launcher
#
# Auto-activates the virtual environment and starts the scanner.
# Usage:  ./run.sh
#
# No need to manually run `source venv/bin/activate` first.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/venv"
VENV_PYTHON="$VENV_DIR/bin/python"

# ── Create venv if it doesn't exist ──────────────────────────────────────
if [ ! -f "$VENV_PYTHON" ]; then
    echo "[*] Virtual environment not found. Creating..."
    python3 -m venv "$VENV_DIR"
    echo "[*] Installing dependencies..."
    "$VENV_DIR/bin/pip" install --quiet -r requirements.txt
    echo "[✔] Environment ready."
    echo ""
fi

# ── Sync deps (fast no-op if already installed) ───────────────────────────
"$VENV_DIR/bin/pip" install --quiet -r requirements.txt 2>/dev/null || true

# ── Launch ────────────────────────────────────────────────────────────────
exec "$VENV_PYTHON" main.py "$@"
