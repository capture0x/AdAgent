#!/usr/bin/env bash
# AdAgent — AI-Powered Active Directory Attack Agent
#
# Interactive menu mode (default):
#   ./run.sh
#   ./run.sh --agent
#   ./run.sh --session path/to/session.json
#
# CLI mode (all settings as flags, agent starts immediately):
#   ./run.sh --dc 10.10.10.10 --domain corp.local --user john --pass Password123
#   ./run.sh --dc 10.10.10.10 --domain corp.local --user admin --hash :abc123 --backend claude --model sonnet
#   ./run.sh --dc 10.10.10.10 --domain corp.local --user john --ccache /tmp/john.ccache --opsec stealth
#   ./run.sh --dc 10.10.10.10 --domain corp.local --user john --pass Password123 --mode plan
#   ./run.sh --help-cli   (show CLI mode help)

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

# ── Route: CLI mode if --dc is present, or --help-cli requested ───────────────
_is_cli=0
for _arg in "$@"; do
    case "$_arg" in
        --dc|--domain|--help-cli) _is_cli=1; break ;;
    esac
done

if [[ $_is_cli -eq 1 ]]; then
    # Translate --help-cli → --help for the CLI parser
    _args=()
    for _arg in "$@"; do
        [[ "$_arg" == "--help-cli" ]] && _args+=("--help") || _args+=("$_arg")
    done
    exec "$PYTHON" "$SCRIPT_DIR/cli/adcli.py" "${_args[@]}"
fi

# ── Interactive menu mode (original behaviour) ─────────────────────────────────
exec "$PYTHON" "$SCRIPT_DIR/main.py" "$@"
