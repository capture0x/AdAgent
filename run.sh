#!/usr/bin/env bash
# AdAgent — AI-Powered Active Directory Attack Orchestrator
# Usage: ./run.sh [--agent] [--session path/to/session.json] [--no-banner]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Python interpreter ─────────────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/venv/bin/python3" ]]; then
    PYTHON="$SCRIPT_DIR/venv/bin/python3"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
else
    echo "[!] Python 3 not found. Run ./install.sh first."
    exit 1
fi

# ── Environment ────────────────────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
    set +a
fi

export PYTHONPATH="$SCRIPT_DIR"
export PYTHONDONTWRITEBYTECODE=1

# ── Launch ─────────────────────────────────────────────────────────────────────
exec "$PYTHON" "$SCRIPT_DIR/main.py" "$@"
