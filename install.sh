#!/usr/bin/env bash
# AdAgent — Installation Script
# Creates a Python virtual environment and installs all dependencies.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BOLD="\033[1m"
BLUE="\033[38;5;45m"
RED="\033[38;2;253;38;54m"
WHITE="\033[97m"
DIM="\033[2m"
RST="\033[0m"

banner() { echo -e "\n${RED}${BOLD}[*]${RST} ${WHITE}${BOLD}$*${RST}"; }
ok()     { echo -e "  ${BLUE}[+]${RST} $*"; }
warn()   { echo -e "  ${RED}[!]${RST} $*"; }
die()    { echo -e "  ${RED}[-] FATAL:${RST} $*" >&2; exit 1; }

# ── Header ─────────────────────────────────────────────────────────────────────
echo -e "${RED}${BOLD}"
cat << 'EOF'
     ___       __   ___                    __
    /   | ____/ /  /   | ____ ____  ____  / /_
   / /| |/ __  /  / /| |/ __ `/ _ \/ __ \/ __/
  / ___ / /_/ /  / ___ / /_/ /  __/ / / / /_
 /_/  |_\__,_/  /_/  |_\__, /\___/_/ /_/\__/
                       /____/
EOF
echo -e "${RST}${BLUE}${BOLD}  AdAgent Installer${RST}  ${DIM}— AI-Powered AD Attack Orchestrator${RST}"
echo ""

# ── Python check ───────────────────────────────────────────────────────────────
banner "Checking Python version..."
if ! command -v python3 &>/dev/null; then
    die "Python 3 is required but not found. Install Python 3.10+ first."
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [[ $PY_MAJOR -lt 3 || ($PY_MAJOR -eq 3 && $PY_MINOR -lt 8) ]]; then
    die "Python 3.8+ required (found $PY_VER)"
fi
ok "Python $PY_VER found"

# ── Virtual environment ────────────────────────────────────────────────────────
banner "Setting up virtual environment..."
if [[ ! -d "$SCRIPT_DIR/venv" ]]; then
    python3 -m venv "$SCRIPT_DIR/venv"
    ok "Created venv at $SCRIPT_DIR/venv"
else
    ok "venv already exists — skipping creation"
fi

VENV_PIP="$SCRIPT_DIR/venv/bin/pip"
VENV_PY="$SCRIPT_DIR/venv/bin/python3"

banner "Upgrading pip..."
"$VENV_PIP" install --quiet --upgrade pip

# ── Python dependencies ────────────────────────────────────────────────────────
banner "Installing Python dependencies..."
"$VENV_PIP" install --quiet -r "$SCRIPT_DIR/requirements.txt"
ok "Python packages installed"

# ── Anthropic SDK (optional) ───────────────────────────────────────────────────
if ! "$VENV_PY" -c "import anthropic" 2>/dev/null; then
    banner "Installing Anthropic SDK..."
    "$VENV_PIP" install --quiet anthropic
    ok "anthropic SDK installed"
else
    ok "anthropic SDK already present"
fi

# ── .env setup ─────────────────────────────────────────────────────────────────
if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
    banner "Creating .env from template..."
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    ok ".env created — edit it with your target details"
else
    ok ".env already exists — skipping"
fi

# ── Output directories ─────────────────────────────────────────────────────────
banner "Creating output directories..."
mkdir -p "$SCRIPT_DIR/output/agent_logs"
mkdir -p "$SCRIPT_DIR/output/agent_runtime"
mkdir -p "$SCRIPT_DIR/output/reports"
ok "Output directories ready"

# ── Permissions ────────────────────────────────────────────────────────────────
chmod +x "$SCRIPT_DIR/run.sh"
chmod +x "$SCRIPT_DIR/install.sh"

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${RED}${BOLD}┌──────────────────────────────────────────────┐${RST}"
echo -e "${RED}${BOLD}│${RST}   ${BLUE}${BOLD}AdAgent installation complete!${RST}               ${RED}${BOLD}│${RST}"
echo -e "${RED}${BOLD}└──────────────────────────────────────────────┘${RST}"
echo ""
echo -e "  ${WHITE}1. Edit ${BLUE}.env${RST}${WHITE} with your target credentials${RST}"
echo -e "  ${WHITE}2. Start Ollama (local AI) — optional but recommended:${RST}"
echo -e "     ${DIM}ollama pull qwen2.5:14b${RST}"
echo -e "  ${WHITE}3. Or set ${BLUE}ANTHROPIC_API_KEY${RST}${WHITE} in .env for Claude backend${RST}"
echo -e "  ${WHITE}4. Launch: ${BLUE}${BOLD}./run.sh${RST}"
echo ""
echo -e "  ${RED}${BOLD}[!]${RST} Authorised penetration testing engagements only."
echo ""
