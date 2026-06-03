#!/usr/bin/env bash
# AdStrike missing-tool repair helper
# Installs or repairs commonly required system packages, Python tools, and
# repo-local third-party helper scripts. Authorized lab/engagement use only.

set -uo pipefail

RED='\033[91m'; GRN='\033[92m'; YLW='\033[93m'; CYN='\033[96m'
DIM='\033[2m'; BOLD='\033[1m'; RST='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="${ADSTRIKE_VENV_DIR:-$ROOT_DIR/venv}"
TOOLS_DIR="$ROOT_DIR/tools"
BIN_DIR="$TOOLS_DIR/bin"
REQ_FILE="$ROOT_DIR/requirements.txt"

DO_APT=1
DO_PIP=1
DO_GITHUB=1
CHECK_ONLY=0
ASSUME_YES=0

ok()   { echo -e "  ${GRN}[+]${RST} $*"; }
warn() { echo -e "  ${YLW}[!]${RST} $*"; }
err()  { echo -e "  ${RED}[-]${RST} $*"; }
step() { echo -e "\n  ${CYN}[*]${RST} ${BOLD}$*${RST}"; }

usage() {
    cat <<EOF
Usage: bash scripts/repair_tools.sh [options]

Options:
  --check       Only print missing tools; do not install anything
  --no-apt      Skip apt package repair
  --no-pip      Skip Python package repair
  --no-github   Skip repo-local GitHub helper clones
  -y, --yes     Do not prompt before installing
  -h, --help    Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) CHECK_ONLY=1 ;;
        --no-apt) DO_APT=0 ;;
        --no-pip) DO_PIP=0 ;;
        --no-github) DO_GITHUB=0 ;;
        -y|--yes) ASSUME_YES=1 ;;
        -h|--help) usage; exit 0 ;;
        *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    SUDO=()
elif command -v sudo >/dev/null 2>&1; then
    SUDO=(sudo)
else
    SUDO=()
    warn "sudo not found; apt/system installs may fail"
fi

confirm() {
    [[ "$ASSUME_YES" -eq 1 ]] && return 0
    read -r -p "  Continue with installs/repairs? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]]
}

have() {
    command -v "$1" >/dev/null 2>&1
}

have_any() {
    local item
    for item in "$@"; do
        have "$item" && return 0
    done
    return 1
}

apt_installed() {
    dpkg -s "$1" >/dev/null 2>&1
}

pip_bin() {
    if [[ -x "$VENV_DIR/bin/pip" ]]; then
        echo "$VENV_DIR/bin/pip"
    else
        echo "python3 -m pip"
    fi
}

clone_or_update() {
    local url="$1"
    local dest="$2"
    local name="$3"

    if [[ -d "$dest/.git" ]]; then
        git -C "$dest" pull --ff-only >/dev/null 2>&1 \
            && ok "$name updated" \
            || warn "$name update failed; keeping existing copy"
        return
    fi

    rm -rf "$dest"
    git clone -q "$url" "$dest" \
        && ok "$name cloned" \
        || warn "$name clone failed"
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
}

print_path_hint() {
    if [[ -d "$BIN_DIR" ]]; then
        echo
        echo -e "  ${DIM}Optional PATH for repo-local tools:${RST}"
        echo "  export PATH=\"$BIN_DIR:\$PATH\""
    fi
}

APT_PKGS=(
    impacket-scripts crackmapexec evil-winrm bloodhound bloodhound-python
    ldap-utils smbclient enum4linux-ng hashcat john hydra cewl
    nmap masscan nbtscan netdiscover responder krb5-user dnsutils
    samba-common-bin net-tools git wget curl zip unzip jq faketime ntpdate
    python3-pip python3-venv python3-dev
)

PIP_PKGS=(
    netexec certipy-ad bloodhound mitm6 lsassy dploot roadrecon roadtx
    coercer ldap3 pypykatz bloodyAD
)

COMMANDS=(
    nxc crackmapexec evil-winrm bloodhound-python ldapsearch certipy
    enum4linux-ng bloodyAD hashcat john hydra cewl nmap masscan nbtscan
    netdiscover responder mitm6 ntlmrelayx.py klist kinit kdestroy faketime
    ntpdate coercer lsassy dploot pypykatz dig rpcclient smbclient jq
)

banner() {
    echo -e "${CYN}${BOLD}AdStrike missing-tool repair${RST}"
    echo -e "${DIM}Root: $ROOT_DIR${RST}"
}

banner

step "Checking current tool availability"
missing=()
for cmd in "${COMMANDS[@]}"; do
    if have "$cmd"; then
        ok "$cmd"
    else
        warn "$cmd missing"
        missing+=("$cmd")
    fi
done

if have dnstool.py || [[ -f "$TOOLS_DIR/krbrelayx/dnstool.py" ]] || [[ -f /opt/krbrelayx/dnstool.py ]]; then
    ok "dnstool.py"
else
    warn "dnstool.py missing"
    missing+=("dnstool.py")
fi

if have kerbrute; then
    ok "kerbrute"
else
    warn "kerbrute missing"
    missing+=("kerbrute")
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo
    if [[ "${#missing[@]}" -eq 0 ]]; then
        ok "No missing tools detected"
        exit 0
    fi
    warn "Missing: ${missing[*]}"
    exit 1
fi

confirm || { warn "Cancelled"; exit 1; }

if [[ "$DO_APT" -eq 1 ]]; then
    step "Repairing apt packages"
    if have apt-get; then
        "${SUDO[@]}" apt-get update -qq || warn "apt update failed; continuing"
        for pkg in "${APT_PKGS[@]}"; do
            if apt_installed "$pkg"; then
                ok "$pkg already installed"
            else
                "${SUDO[@]}" apt-get install -y -qq "$pkg" >/dev/null 2>&1 \
                    && ok "$pkg installed" \
                    || warn "$pkg install failed or package unavailable"
            fi
        done
    else
        warn "apt-get not found; skipping apt repair"
    fi
fi

if [[ "$DO_PIP" -eq 1 ]]; then
    step "Repairing Python environment"
    if [[ ! -d "$VENV_DIR" ]]; then
        python3 -m venv "$VENV_DIR" \
            && ok "venv created: $VENV_DIR" \
            || warn "venv creation failed"
    fi

    PIP="$(pip_bin)"
    $PIP install -q --upgrade pip setuptools wheel \
        && ok "pip upgraded" \
        || warn "pip upgrade failed"

    if [[ -f "$REQ_FILE" ]]; then
        $PIP install -q -r "$REQ_FILE" \
            && ok "requirements.txt repaired" \
            || warn "requirements.txt install failed"
    fi

    for pkg in "${PIP_PKGS[@]}"; do
        $PIP install -q "$pkg" >/dev/null 2>&1 \
            && ok "$pkg" \
            || warn "$pkg failed"
    done
fi

if [[ "$DO_GITHUB" -eq 1 ]]; then
    step "Repairing repo-local helper tools"
    mkdir -p "$TOOLS_DIR"

    if have git; then
        clone_or_update "https://github.com/dirkjanm/krbrelayx" "$TOOLS_DIR/krbrelayx" "krbrelayx"
        link_tool "$TOOLS_DIR/krbrelayx/dnstool.py" "dnstool.py"
        link_tool "$TOOLS_DIR/krbrelayx/printerbug.py" "printerbug.py"

        clone_or_update "https://github.com/topotam/PetitPotam" "$TOOLS_DIR/PetitPotam" "PetitPotam"
        link_tool "$TOOLS_DIR/PetitPotam/PetitPotam.py" "PetitPotam.py"

        clone_or_update "https://github.com/c3c/ADExplorerSnapshot.py" "$TOOLS_DIR/ADExplorerSnapshot.py" "ADExplorerSnapshot.py"
        link_tool "$TOOLS_DIR/ADExplorerSnapshot.py/ADExplorerSnapshot.py" "ADExplorerSnapshot.py"
    else
        warn "git not found; skipping helper clones"
    fi

    if ! have kerbrute && have curl; then
        step "Attempting kerbrute install"
        arch="$(uname -m)"
        case "$arch" in
            x86_64|amd64) kb_arch="amd64" ;;
            aarch64|arm64) kb_arch="arm64" ;;
            *) kb_arch="" ;;
        esac
        if [[ -n "$kb_arch" ]]; then
            tmp="$(mktemp -d)"
            url="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_${kb_arch}"
            if curl -fsSL "$url" -o "$tmp/kerbrute"; then
                chmod +x "$tmp/kerbrute"
                "${SUDO[@]}" install -m 755 "$tmp/kerbrute" /usr/local/bin/kerbrute \
                    && ok "kerbrute installed to /usr/local/bin" \
                    || {
                        mkdir -p "$BIN_DIR"
                        cp "$tmp/kerbrute" "$BIN_DIR/kerbrute"
                        ok "kerbrute installed to $BIN_DIR/kerbrute"
                    }
            else
                warn "kerbrute download failed: $url"
            fi
            rm -rf "$tmp"
        else
            warn "Unsupported architecture for automatic kerbrute install: $arch"
        fi
    fi
fi

print_path_hint

step "Final health check"
python3 "$ROOT_DIR/main.py" --check || warn "AdStrike self-check reported issues"

echo
ok "Repair pass complete"
