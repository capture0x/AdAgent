#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# AdAgent — Installer
# Tested on Kali Linux 2024+ / Parrot OS
# AUTHORISED PENETRATION TESTING ONLY
# by TMRSWRR
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── AdAgent synthwave palette ──────────────────────────────────────────────
CYN='\033[38;2;45;226;230m'    # #2DE2E6 cyan
PNK='\033[38;2;255;106;193m'   # #FF6AC1 pink
VIO='\033[38;2;185;103;255m'   # #B967FF violet
GRN='\033[38;2;54;241;205m'    # #36F1CD mint
YLW='\033[38;2;255;196;0m'     # #FFC400 amber
RED='\033[38;2;255;56;100m'    # #FF3864 hot red
DIM='\033[2m';  RST='\033[0m';  BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ADAGENT_VENV_DIR:-$SCRIPT_DIR/venv}"
REQ_FILE="$SCRIPT_DIR/requirements.txt"
TOOLS_DIR="$SCRIPT_DIR/tools"
BIN_DIR="$TOOLS_DIR/bin"
LOCAL_TOOLS_SOURCE="${ADAGENT_LOCAL_TOOLS_SOURCE:-$SCRIPT_DIR/tools}"
export PATH="$BIN_DIR:$PATH"

banner() {
    echo -e "${VIO}${BOLD}"
    echo '     ___       __   ___                    __'
    echo '    /   | ____/ /  /   | ____ ____  ____  / /_'
    echo '   / /| |/ __  /  / /| |/ __ `/ _ \/ __ \/ __/'
    echo '  / ___ / /_/ /  / ___ / /_/ /  __/ / / / /_'
    echo ' /_/  |_\__,_/  /_/  |_\__, /\___/_/ /_/\__/'
    echo -e "                       /____/${RST}"
    echo -e "  ${CYN}${BOLD}AdAgent — Installer${RST}  ${DIM}AI-Powered AD Attack · 52 agent tools · 8 kill-chain phases${RST}"
    echo -e "  ${DIM}──────────────────────────────────────────────────────────────────${RST}"
    echo
}

step() { echo -e "\n  ${CYN}[*]${RST} ${BOLD}$*${RST}"; }
ok()   { echo -e "  ${GRN}[+]${RST} $*"; }
warn() { echo -e "  ${YLW}[!]${RST} $*"; }
die()  { echo -e "  ${RED}[-]${RST} $* — aborting"; exit 1; }

clone_or_update() {
    local url="$1"
    local dest="$2"
    local name="$3"

    if [[ -d "$dest/.git" ]]; then
        git -C "$dest" pull --ff-only >/dev/null 2>&1 \
            && ok "$name updated" \
            || warn "$name update failed — keeping existing copy"
        return
    fi

    if [[ -e "$dest" ]]; then
        ok "$name already present"
        return
    fi

    git clone -q "$url" "$dest" \
        && ok "$name cloned to ${dest#$SCRIPT_DIR/}" \
        || warn "$name clone failed"
}

copy_local_tool_dir() {
    local name="$1"
    local src="$LOCAL_TOOLS_SOURCE/$name"
    local dest="$TOOLS_DIR/$name"

    [[ -d "$src" ]] || return 0
    # Source and destination are the same dir (repo-local tools) → nothing to copy
    [[ "$src" -ef "$dest" ]] && { ok "$name already present (repo-local)"; return 0; }
    if [[ -e "$dest" ]]; then
        cp -an "$src/." "$dest/" 2>/dev/null \
            && ok "$name already present; missing local files synced" \
            || ok "$name already present"
        return 0
    fi

    cp -a "$src" "$dest" \
        && ok "$name copied from $LOCAL_TOOLS_SOURCE" \
        || warn "$name copy failed from $LOCAL_TOOLS_SOURCE"
}

copy_local_bin_tool() {
    local name="$1"
    local src="$LOCAL_TOOLS_SOURCE/bin/$name"
    local dest="$BIN_DIR/$name"

    [[ -f "$src" ]] || return 0
    [[ "$src" -ef "$dest" ]] && { ok "tools/bin/$name already present (repo-local)"; return 0; }
    if [[ -e "$dest" || -L "$dest" ]]; then
        ok "tools/bin/$name already present"
        return 0
    fi

    cp -a "$src" "$dest" \
        && ok "tools/bin/$name copied from local source" \
        || warn "tools/bin/$name copy failed from $LOCAL_TOOLS_SOURCE/bin"
    chmod +x "$dest" 2>/dev/null || true
}

link_tool() {
    local src="$1"
    local name="$2"
    [[ -f "$src" ]] || return 0

    mkdir -p "$BIN_DIR"
    local rel_src
    rel_src="$(realpath --relative-to="$BIN_DIR" "$src" 2>/dev/null || printf '%s' "$src")"
    ln -sfn "$rel_src" "$BIN_DIR/$name"
    chmod +x "$src" "$BIN_DIR/$name" 2>/dev/null || true
    ok "tools/bin/$name linked"
}

banner

# Do not run the installer itself as root. It creates repo-local files such as
# venv/ and .env; root-owned artifacts break normal-user runs. The script
# uses sudo only for system package installation.
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    die "Do not run install.sh with sudo. Run: bash install.sh"
fi

# ── Python version check ──────────────────────────────────────────────────────
step "Checking Python version"
command -v python3 &>/dev/null || die "python3 not found"
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
(( PY_MINOR >= 10 )) || die "Python $PY_VER detected — requires 3.10+"
ok "Python $PY_VER"

# ── APT — install system packages ────────────────────────────────────────────
step "Installing system packages"
sudo apt-get update -qq 2>/dev/null || warn "apt update had warnings — continuing"

APT_PKGS=(
    impacket-scripts crackmapexec evil-winrm
    bloodhound bloodhound-python
    ldap-utils smbclient enum4linux-ng
    hashcat john hydra
    nmap masscan nbtscan netdiscover
    responder
    krb5-user dnsutils samba-common-bin
    net-tools git wget curl zip unzip
    python3-pip python3-venv python3-dev
)

sudo apt-get install -y -qq "${APT_PKGS[@]}" 2>/dev/null \
    && ok "System packages installed" \
    || warn "Some apt packages failed — check manually"

# ── SecLists (skip if already installed — large package ~450MB) ───────────────
if dpkg -s seclists &>/dev/null; then
    ok "seclists already installed — skipping"
else
    step "Installing seclists (wordlists)"
    sudo apt-get install -y -qq seclists 2>/dev/null \
        && ok "seclists installed" \
        || warn "seclists install failed — install manually: sudo apt install seclists"
fi

# ── Python virtual environment ────────────────────────────────────────────────
step "Setting up virtual environment → ${VENV_DIR#$SCRIPT_DIR/}"
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    ok "venv created"
else
    ok "venv already exists"
fi

VENV_PY="$VENV_DIR/bin/python"
if [[ ! -x "$VENV_PY" ]] || ! "$VENV_PY" -c 'import sys; raise SystemExit(0 if sys.prefix != sys.base_prefix else 1)' >/dev/null 2>&1; then
    warn "${VENV_DIR#$SCRIPT_DIR/} is broken or not isolated — recreating it"
    rm -rf "$VENV_DIR"
    python3 -m venv "$VENV_DIR"
    VENV_PY="$VENV_DIR/bin/python"
    ok "venv recreated"
fi

PIP_CMD=("$VENV_PY" -m pip)

if ! "${PIP_CMD[@]}" --version >/dev/null 2>&1; then
    warn "pip module missing in ${VENV_DIR#$SCRIPT_DIR/} — bootstrapping with ensurepip"
    "$VENV_PY" -m ensurepip --upgrade >/dev/null 2>&1 \
        || die "Could not bootstrap pip inside ${VENV_DIR#$SCRIPT_DIR/}"
fi

if [[ -f "$VENV_DIR/bin/pip" ]] && ! head -n 1 "$VENV_DIR/bin/pip" | grep -Fq "$VENV_DIR"; then
    warn "pip entrypoint points outside this repo — repairing ${VENV_DIR#$SCRIPT_DIR/}/bin/pip"
    "${PIP_CMD[@]}" install -q --force-reinstall pip \
        || die "Could not repair pip entrypoint inside ${VENV_DIR#$SCRIPT_DIR/}"
fi

step "Upgrading pip / setuptools / wheel"
"${PIP_CMD[@]}" install -q --upgrade pip setuptools wheel && ok "pip upgraded"

step "Installing Python dependencies"
[[ -f "$REQ_FILE" ]] && "${PIP_CMD[@]}" install -q -r "$REQ_FILE" && ok "requirements.txt installed"

step "Installing extra pip-only tools"
for pkg in netexec certipy-ad bloodhound mitm6 lsassy dploot roadrecon roadtx ldap3; do
    "${PIP_CMD[@]}" install -q "$pkg" 2>/dev/null && ok "$pkg" \
        || warn "$pkg failed — may already be installed system-wide"
done

# coercer declares impacket<0.11.0 which would downgrade impacket and break
# certipy shadow_credentials. Install without deps, then re-pin impacket.
"${PIP_CMD[@]}" install -q --no-deps coercer 2>/dev/null && ok "coercer (no-deps)" \
    || warn "coercer failed — may already be installed system-wide"

# GitHub-only tools — pre2k and sccmhunter are NOT published to PyPI and pin very
# old deps (impacket==0.10.0, rich==12.5.1, typer<0.7 ...). Installing them into the
# main venv triggers pip dependency-resolver conflicts and can break AdAgent's
# modern impacket/rich/typer. So install them in ISOLATED pipx environments instead;
# their console entrypoints land on PATH (~/.local/bin) and shutil.which() finds them.
step "Installing GitHub-only tools (pre2k, sccmhunter) via pipx (isolated)"

# Resolve a usable pipx invocation: prefer system pipx, else python3 -m pipx,
# else bootstrap pipx into the venv (it still isolates each app in its own venv).
PIPX_CMD=()
if command -v pipx >/dev/null 2>&1; then
    PIPX_CMD=(pipx)
elif python3 -m pipx --version >/dev/null 2>&1; then
    PIPX_CMD=(python3 -m pipx)
else
    warn "pipx not found — bootstrapping it"
    if "${PIP_CMD[@]}" install -q pipx 2>/dev/null; then
        PIPX_CMD=("$VENV_PY" -m pipx)
    else
        warn "pipx bootstrap failed — falling back to plain git install (may cause dep conflicts)"
    fi
fi

if [[ ${#PIPX_CMD[@]} -gt 0 ]]; then
    # Make sure ~/.local/bin (pipx default bin dir) is on PATH now and in future shells
    "${PIPX_CMD[@]}" ensurepath >/dev/null 2>&1 || true
    export PATH="$HOME/.local/bin:$PATH"
fi

for spec in "pre2k=https://github.com/garrettfoster13/pre2k" \
            "sccmhunter=https://github.com/garrettfoster13/sccmhunter"; do
    name="${spec%%=*}"; url="${spec#*=}"
    if [[ ${#PIPX_CMD[@]} -gt 0 ]]; then
        if "${PIPX_CMD[@]}" install --force "git+${url}" >/dev/null 2>&1; then
            ok "$name (isolated pipx env)"
        else
            warn "$name pipx install failed — trying plain git install"
            "${PIP_CMD[@]}" install -q "git+${url}" 2>/dev/null \
                && ok "$name (from git, shared venv)" \
                || warn "$name install failed — clone manually: git clone ${url}"
        fi
    else
        "${PIP_CMD[@]}" install -q "git+${url}" 2>/dev/null \
            && ok "$name (from git, shared venv)" \
            || warn "$name install failed — clone manually: git clone ${url}"
    fi
done

# Re-pin impacket after all tools are installed. Some tools (coercer) declare
# outdated impacket pins that would downgrade it and break certipy shadow_credentials.
step "Re-pinning impacket>=0.13.0 (ensures shadow_credentials support)"
"${PIP_CMD[@]}" install -q "impacket>=0.13.0" --upgrade 2>/dev/null \
    && ok "impacket pinned to $(${PIP_CMD[@]} show impacket 2>/dev/null | grep ^Version | cut -d' ' -f2)" \
    || warn "impacket re-pin failed — shadow_credentials may not work"

# Verify shadow_credentials is importable
if "$VENV_PY" -c "from impacket.examples.ntlmrelayx.utils import shadow_credentials" 2>/dev/null; then
    ok "shadow_credentials import verified"
else
    warn "shadow_credentials import failed — certipy shadow may not work"
fi

# ── Repo-local helper tools ───────────────────────────────────────────────────
step "Installing repo-local helper tools"
mkdir -p "$TOOLS_DIR" "$BIN_DIR"

if [[ -d "$LOCAL_TOOLS_SOURCE" ]]; then
    ok "Local tool source found: $LOCAL_TOOLS_SOURCE"
    copy_local_tool_dir "krbrelayx"
    copy_local_tool_dir "PetitPotam"
    copy_local_tool_dir "ADExplorerSnapshot.py"

    for helper in \
        ADExplorerSnapshot.py dnstool.py gMSADumper.py gmsa_grant_and_dump.py \
        PetitPotam.py printerbug.py
    do
        copy_local_bin_tool "$helper"
    done
else
    warn "Local tool source not found: $LOCAL_TOOLS_SOURCE"
    warn "Set ADAGENT_LOCAL_TOOLS_SOURCE=/path/to/tools to use a different local source"
fi

if command -v git &>/dev/null; then
    clone_or_update "https://github.com/dirkjanm/krbrelayx" "$TOOLS_DIR/krbrelayx" "krbrelayx"
    clone_or_update "https://github.com/topotam/PetitPotam" "$TOOLS_DIR/PetitPotam" "PetitPotam"
    clone_or_update "https://github.com/c3c/ADExplorerSnapshot.py" "$TOOLS_DIR/ADExplorerSnapshot.py" "ADExplorerSnapshot.py"
else
    warn "git not found — skipping GitHub helper tool clones"
fi

link_tool "$TOOLS_DIR/krbrelayx/dnstool.py" "dnstool.py"
link_tool "$TOOLS_DIR/krbrelayx/printerbug.py" "printerbug.py"
link_tool "$TOOLS_DIR/PetitPotam/PetitPotam.py" "PetitPotam.py"
link_tool "$TOOLS_DIR/ADExplorerSnapshot.py/ADExplorerSnapshot.py" "ADExplorerSnapshot.py"

[[ -f "$TOOLS_DIR/krbrelayx/dnstool.py" ]] && ln -sf "$TOOLS_DIR/krbrelayx/dnstool.py" "$TOOLS_DIR/dnstool.py"
[[ -f "$TOOLS_DIR/krbrelayx/printerbug.py" ]] && ln -sf "$TOOLS_DIR/krbrelayx/printerbug.py" "$TOOLS_DIR/printerbug.py"
[[ -f "$TOOLS_DIR/PetitPotam/PetitPotam.py" ]] && ln -sf "$TOOLS_DIR/PetitPotam/PetitPotam.py" "$TOOLS_DIR/PetitPotam.py"

if [[ -f "$BIN_DIR/dnstool.py" || -f "$TOOLS_DIR/krbrelayx/dnstool.py" || -f /opt/krbrelayx/dnstool.py ]] || command -v dnstool.py &>/dev/null; then
    ok "dnstool.py available"
else
    warn "dnstool.py missing — ADIDNS write actions may fail"
fi

# ── Fix nxc impacket import (regsecrets.py missing from pip impacket) ────────
step "Fixing impacket/nxc version compatibility"
# System nxc was built against system impacket which has gkdi.py, dpapi_ng.py,
# WIN_VERSIONS etc. The pip-installed impacket (0.14.0) is missing these.
# The _nxc() agent wrapper sets PYTHONPATH to use system impacket for nxc calls.
# As a belt-and-suspenders fix, also copy the missing files to pip impacket.
PIP_IMP=$("$VENV_PY" -c "import impacket, os; print(os.path.dirname(impacket.__file__))" 2>/dev/null || true)
SYS_IMP="/usr/lib/python3/dist-packages/impacket"
if [[ -n "$PIP_IMP" && -d "$SYS_IMP" ]]; then
    copied=0
    for f in dpapi_ng.py msada_guids.py regsecrets.py; do
        if [[ -f "$SYS_IMP/$f" && ! -f "$PIP_IMP/$f" ]]; then
            cp "$SYS_IMP/$f" "$PIP_IMP/$f" && ((copied++)) || true
        fi
    done
    for f in gkdi.py icpr.py tsts.py; do
        if [[ -f "$SYS_IMP/dcerpc/v5/$f" && ! -f "$PIP_IMP/dcerpc/v5/$f" ]]; then
            cp "$SYS_IMP/dcerpc/v5/$f" "$PIP_IMP/dcerpc/v5/$f" && ((copied++)) || true
        fi
    done
    # Always overwrite utils.py — system version has parse_identity needed by getTGT.py
    if [[ -f "$SYS_IMP/examples/utils.py" ]]; then
        cp "$SYS_IMP/examples/utils.py" "$PIP_IMP/examples/utils.py" && ((copied++)) || true
    fi
    ok "impacket compatibility: $copied missing files synced from system to pip"
else
    warn "Could not sync impacket files — nxc ldap may have import errors"
    warn "Workaround: the agent uses PYTHONPATH fix automatically"
fi

# ── kerbrute ─────────────────────────────────────────────────────────────────
step "Checking kerbrute"
if command -v kerbrute &>/dev/null; then
    ok "kerbrute found in PATH"
else
    warn "kerbrute not found — downloading latest release binary"
    case "$(uname -m)" in
        x86_64|amd64) KB_ARCH="amd64" ;;
        aarch64|arm64) KB_ARCH="arm64" ;;
        *) KB_ARCH="" ;;
    esac
    if [[ -z "$KB_ARCH" ]]; then
        warn "kerbrute: unsupported arch $(uname -m) — install manually from https://github.com/ropnop/kerbrute/releases"
    else
        KB_URL="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_${KB_ARCH}"
        KB_TMP="$(mktemp)"
        if curl -fsSL "$KB_URL" -o "$KB_TMP" 2>/dev/null && [[ -s "$KB_TMP" ]]; then
            sudo install -m 755 "$KB_TMP" /usr/local/bin/kerbrute \
                && ok "kerbrute installed to /usr/local/bin/kerbrute" \
                || warn "kerbrute install failed — copy $KB_TMP to /usr/local/bin/kerbrute manually"
        else
            warn "kerbrute download failed — install manually:"
            echo -e "  ${DIM}https://github.com/ropnop/kerbrute/releases${RST}"
        fi
        rm -f "$KB_TMP" 2>/dev/null || true
    fi
fi

# ── cypher-shell (optional — for BloodHound auto-queries) ─────────────────────
# Only the lightweight cypher-shell CLI is attempted, NOT the full neo4j stack.
# If unavailable, AdAgent still exports BloodHound JSON for manual GUI import.
step "Checking cypher-shell (optional)"
if command -v cypher-shell &>/dev/null; then
    ok "cypher-shell found in PATH"
else
    sudo apt-get install -y -qq cypher-shell 2>/dev/null \
        && ok "cypher-shell installed" \
        || warn "cypher-shell not available — optional; BloodHound JSON is still exported for manual GUI import"
fi

# ── .env setup ────────────────────────────────────────────────────────────────
step "Setting up .env"
if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
    if [[ -f "$SCRIPT_DIR/.env.example" ]]; then
        cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
        ok ".env created from template — edit with your engagement details"
    else
        touch "$SCRIPT_DIR/.env"
        ok ".env.example not found — created empty .env"
    fi
else
    ok ".env already exists"
fi

mkdir -p "$SCRIPT_DIR/output"

# ── Done ─────────────────────────────────────────────────────────────────────
echo
echo -e "  ${VIO}──────────────────────────────────────────────────────────────────${RST}"
echo -e "  ${GRN}${BOLD} AdAgent installation complete!${RST}"
echo -e "  ${VIO}──────────────────────────────────────────────────────────────────${RST}"
echo
echo -e "  ${CYN}Run:${RST}  ${BOLD}bash run.sh${RST}  or  ${BOLD}source ${VENV_DIR#$SCRIPT_DIR/}/bin/activate && python main.py${RST}"
echo -e "  ${DIM}Pip:${RST}  ${BOLD}$VENV_PY -m pip${RST}  ${DIM}(safe even if the repo path changes)${RST}"
echo -e "  ${DIM}Repo-local helper tools are available under tools/ and tools/bin/.${RST}"
echo -e "  ${DIM}For authorised penetration testing only.${RST}"
echo
