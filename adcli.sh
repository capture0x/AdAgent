#!/usr/bin/env bash
# AdAgent CLI mode launcher
# All flags are forwarded to cli/adcli.py
#
# Quick examples:
#   ./adcli.sh --dc 10.10.10.10 --domain corp.local --user john --pass Password123
#   ./adcli.sh --dc 10.10.10.10 --domain corp.local --user admin --hash :abc123 --backend claude --model sonnet
#   ./adcli.sh --dc 10.10.10.10 --domain corp.local --user john --ccache /tmp/john.ccache --opsec stealth
#   ./adcli.sh --dc 10.10.10.10 --domain corp.local --user john --pass Password123 --mode plan
#   ./adcli.sh --help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/venv/bin/python3" ]]; then
    PYTHON="$SCRIPT_DIR/venv/bin/python3"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
else
    echo "[!] Python 3 not found. Run ./install.sh first."
    exit 1
fi

export PYTHONDONTWRITEBYTECODE=1

exec "$PYTHON" "$SCRIPT_DIR/cli/adcli.py" "$@"
