#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║  AdAgent — AI-Powered Active Directory Attack Orchestrator           ║
║  AUTHORISED PENETRATION TESTING & RED TEAM ENGAGEMENTS ONLY          ║
║                                               By TMRSWRR             ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import sys, os, json, time, argparse, platform, datetime, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.helpers import (
    R, G, Y, B, M, C, W, DIM, BOLD, ITAL, UND, RST,
    NEON_RED, NEON_ORG, NEON_YEL, NEON_GRN, NEON_CYN, NEON_BLU,
    NEON_PUR, NEON_PNK, BABY_BLUE, SKY_BLUE, LIGHT_PINK, SOFT_PINK,
    PURE_WHITE, SOFT_WHITE, MIST, SLATE, STEEL, SILVER, fg,
    success, warn, info, error, prompt, pause, cprint,
    print_banner, print_table, spinner,
)
from config.settings import SESSION, CONFIG, save_session, load_session, get_auth_mode, redact_obj

VERSION  = "1.0"
CODENAME = "AdAgent"
AUTHOR   = "tmrswrr"
BUILD    = "2026.05"

# ══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════════════════════
_ART = r"""
     ___       __   ___                    __
    /   | ____/ /  /   | ____ ____  ____  / /_
   / /| |/ __  /  / /| |/ __ `/ _ \/ __ \/ __/
  / ___ / /_/ /  / ___ / /_/ /  __/ / / / /_
 /_/  |_\__,_/  /_/  |_\__, /\___/_/ /_/\__/
                       /____/
"""

# ── Professional palette — easy on the eyes, high readability ─────────────────
CYAN    = "\033[38;2;0;180;216m"    # #00B4D8 — primary labels / info
VIOLET  = "\033[38;2;123;47;190m"   # #7B2FBE — secondary accent
GREEN   = "\033[38;2;6;214;160m"    # #06D6A0 — success / ready
YELLOW  = "\033[38;2;255;183;3m"    # #FFB703 — warning
RED     = "\033[38;2;239;35;60m"    # #EF233C — error / critical
WHITE   = "\033[38;2;237;242;244m"  # #EDF2F4 — primary text / values
GRAY    = "\033[38;2;141;153;174m"  # #8D99AE — secondary / dim text

# Legacy aliases kept so nothing breaks
PURPLE  = VIOLET
MAGENTA = CYAN

_C1   = CYAN
_C2   = VIOLET
_C3   = GRAY
_CDIM = GRAY

SHOW_MAIN_BANNER  = True
_BANNER_ANIMATED  = False


def _render_banner(offset: int = 0, indent: int = 0) -> str:
    palette = [CYAN, VIOLET]
    prefix  = " " * max(indent, 0)
    out     = []
    for i, line in enumerate(ln for ln in _ART.splitlines() if ln.strip()):
        color = palette[(i + offset) % len(palette)]
        out.append(f"{prefix}{color}{BOLD}{line}{RST}")
    return "\n".join(out)


def _tagline() -> str:
    sep  = f"{GRAY}{'─' * 80}{RST}"

    row1 = (
        f"  {CYAN}{BOLD}AI ACTIVE DIRECTORY ATTACK ORCHESTRATOR{RST}"
        f"  {GRAY}|{RST}  "
        f"{VIOLET}{BOLD}v{VERSION} «{CODENAME}»{RST}"
        f"  {GRAY}|  build {BUILD}{RST}"
    )
    row2 = (
        f"  {GRAY}59 agent tools  |  139 techniques  |  Ollama + Claude  |  creator: tmrswrr{RST}"
    )
    row3 = (
        f"  {YELLOW}{BOLD}[!]{RST}  "
        f"{WHITE}Authorised penetration testing and red-team engagements only{RST}"
    )
    return f"{sep}\n{row1}\n{row2}\n{row3}\n{sep}"


def _clear_screen():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def _animate_banner_once():
    if not sys.stdout.isatty() or os.environ.get("ADAGENT_NO_ANIMATION"):
        return False
    sys.stdout.write("\033[?25l")
    try:
        for frame, indent in enumerate([18, 14, 10, 6, 3, 0]):
            sys.stdout.write("\033[H\033[J")
            print()
            print(_render_banner(offset=frame, indent=indent))
            sys.stdout.flush()
            time.sleep(0.055)
        sys.stdout.write("\033[H\033[J")
        print()
        print(_render_banner())
        sys.stdout.flush()
        time.sleep(1)
        return True
    finally:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()


def show_banner(clear: bool = True, animate: bool = False):
    global _BANNER_ANIMATED
    if not SHOW_MAIN_BANNER:
        return
    if clear:
        _clear_screen()
    banner_already_drawn = False
    if animate and not _BANNER_ANIMATED:
        banner_already_drawn = _animate_banner_once()
        _BANNER_ANIMATED = True
    if not banner_already_drawn:
        print()
        print(_render_banner())
    print(_tagline())
    print()


# ══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
def _auth_badge():
    if SESSION.get("use_kerberos"):
        return f"{CYAN}{BOLD}⚷  KERBEROS{RST}"
    if SESSION.get("nt_hash"):
        return f"{CYAN}{BOLD}#  PASS-THE-HASH{RST}"
    if SESSION.get("password"):
        return f"{GREEN}{BOLD}✓  PASSWORD{RST}"
    return f"{GRAY}○  NOT SET{RST}"


def _status_dot(val: str) -> str:
    """Green dot if value set, dim circle if not."""
    if val and val != "—":
        return f"{GREEN}●{RST}"
    return f"{GRAY}○{RST}"


def _dashboard():
    from utils.helpers import _strip_ansi

    W = max(60, min(100, shutil.get_terminal_size((100, 24)).columns - 4))

    dc      = SESSION.get("dc_ip",     "") or "—"
    dom     = SESSION.get("domain",    "") or "—"
    user    = SESSION.get("username",  "") or "—"
    fqdn    = SESSION.get("dc_fqdn",   "") or "—"
    eng     = SESSION.get("engagement","") or "—"
    att_ip  = SESSION.get("attacker_ip","") or "—"

    findings  = SESSION.get("findings", [])
    cmds      = len(SESSION.get("commands_run", []))
    pwned_u   = SESSION.get("owned_users",    [])
    pwned_m   = SESSION.get("owned_machines", [])
    loot      = SESSION.get("loot", {})

    crits  = sum(1 for f in findings if f.get("severity") == "Critical")
    highs  = sum(1 for f in findings if f.get("severity") == "High")
    meds   = sum(1 for f in findings if f.get("severity") == "Medium")
    now    = datetime.datetime.now().strftime("%d/%m/%Y  %H:%M:%S")

    P  = CYAN      # primary labels
    MG = VIOLET    # secondary / borders
    GR = GREEN     # success dots
    DG = DIM
    PW = WHITE     # values
    SW = GRAY      # secondary text

    def row(content: str) -> str:
        vis = _strip_ansi(content)
        pad = max(W - 2 - len(vis), 0)
        return f"  {MG}│{RST} {content}{' ' * pad} {MG}│{RST}"

    def divider(label: str = "") -> str:
        if label:
            lbl  = f" {label} "
            line = f"{'─' * 2}{lbl}{'─' * max(W - 4 - len(lbl), 0)}"
        else:
            line = '─' * (W - 2)
        return f"  {MG}├{line}┤{RST}"

    top = f"  {MG}╔{'═' * (W-2)}╗{RST}"
    bot = f"  {MG}╚{'═' * (W-2)}╝{RST}"
    mid = f"  {MG}╠{'═' * (W-2)}╣{RST}"

    # ── Header ────────────────────────────────────────────────────────────────
    title    = f"{P}{BOLD}  ADAGENT{RST}  {SW}v{VERSION}  ·  Active Directory Attack Orchestrator{RST}"
    time_str = f"{SW}{now}{RST}"
    title_v  = _strip_ansi(title)
    time_v   = _strip_ansi(time_str)
    gap      = max(W - 2 - len(title_v) - len(time_v) - 2, 1)
    header   = f"  {MG}║{RST} {title}{' ' * gap}{time_str} {MG}║{RST}"

    print(top)
    print(header)
    print(mid)

    # ── Target ────────────────────────────────────────────────────────────────
    print(row(
        f"{MG}{BOLD}TARGET{RST}   "
        f"{_status_dot(dc)} {PW}{BOLD}{user}{RST}{SW}@{RST}{PW}{BOLD}{dom}{RST}"
        f"   {SW}▶{RST}   {P}{BOLD}{dc}{RST}"
        f"  {DG}({fqdn}){RST}"
    ))
    print(row(
        f"{MG}{BOLD}AUTH  {RST}   {_auth_badge()}"
        f"   {DG}│{RST}   "
        f"{MG}{BOLD}ATTACKER{RST}  {_status_dot(att_ip)} {P}{BOLD}{att_ip}{RST}"
        f"   {DG}│{RST}   "
        f"{MG}{BOLD}ENGAGE{RST}  {PW}{eng}{RST}"
    ))
    print(divider())

    # ── Stats ─────────────────────────────────────────────────────────────────
    def sev(label, n, color):
        return f"{color}{BOLD}{n:>2}{RST} {SW}{label}{RST}" if n else f"{GRAY} {n:>2} {label}{RST}"

    print(row(
        f"{MG}{BOLD}STATS {RST}   "
        f"{PW}{BOLD}{cmds}{RST}{SW} cmds{RST}  "
        f"{DG}│{RST}  "
        f"{PW}{BOLD}{len(findings)}{RST}{SW} findings{RST}  "
        f"{DG}({RST}"
        f"{sev('crit', crits, RED)}  "
        f"{sev('high', highs, YELLOW)}  "
        f"{sev('med',  meds,  GRAY)}"
        f"{DG}){RST}  "
        f"{DG}│{RST}  "
        f"{PW}{BOLD}{len(pwned_u)}{RST}{SW} users  {RST}"
        f"{PW}{BOLD}{len(pwned_m)}{RST}{SW} hosts  {RST}"
        f"{PW}{BOLD}{len(loot)}{RST}{SW} hashes owned{RST}"
    ))
    print(bot)


# ══════════════════════════════════════════════════════════════════════════════
#  AUTO-DISCOVERY  —  LDAP rootDSE → nxc → nmap
# ══════════════════════════════════════════════════════════════════════════════
def _auto_discover(ip: str) -> dict:
    import subprocess, re
    result = {}

    print(f"\n  {BABY_BLUE}[1/3]{RST} Querying LDAP rootDSE {SOFT_WHITE}(fast){RST}...")
    try:
        from ldap3 import Server, Connection, ALL
        srv = Server(ip, get_info=ALL, connect_timeout=2)
        con = Connection(srv, receive_timeout=3)
        if con.bind():
            info_ = srv.info
            if info_:
                ctx = info_.other.get("defaultNamingContext")
                if ctx:
                    base_dn = str(ctx[0])
                    result["base_dn"] = base_dn
                    result["domain"]  = base_dn.replace("DC=","").replace(",",".").lower()
                dns = info_.other.get("dnsHostName")
                if dns:
                    result["dc_fqdn"] = str(dns[0])
            con.unbind()
            success("LDAP rootDSE successful")
    except Exception:
        warn("LDAP rootDSE failed or blocked")

    if not result.get("domain"):
        print(f"  {BABY_BLUE}[2/3]{RST} nxc smb fallback {SOFT_WHITE}(quick){RST}...")
        try:
            out = subprocess.run(
                ["nxc", "smb", ip],
                capture_output=True, text=True, timeout=6
            ).stdout
            m = re.search(r"\(domain:([^)]+)\)", out)
            if m:
                dom = m.group(1).strip()
                result["domain"]  = dom
                result["base_dn"] = "DC=" + dom.replace(".", ",DC=")
            m = re.search(r"\(name:([^)]+)\)", out)
            if m:
                host = m.group(1).strip()
                dom  = result.get("domain","")
                result["dc_fqdn"] = f"{host}.{dom}" if dom else host
        except Exception:
            warn("nxc fallback failed or timed out")
    else:
        print(f"  {BABY_BLUE}[2/3]{RST} Domain found — skipping nxc fallback")

    if result.get("domain") and os.environ.get("ADAGENT_PORT_CHECK", "").lower() not in ("1", "true", "yes"):
        print(f"  {BABY_BLUE}[3/3]{RST} Port check skipped {SOFT_WHITE}(set ADAGENT_PORT_CHECK=1 to enable){RST}")
        if result.get("dc_fqdn") and not result.get("hostname"):
            result["hostname"] = result["dc_fqdn"].split(".")[0]
        return result

    print(f"  {BABY_BLUE}[3/3]{RST} Quick AD port check {SOFT_WHITE}(~5-10 s){RST}...")
    try:
        _AD_PORTS = "53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389"
        nmap_out  = subprocess.run(
            ["nmap", "-Pn", "-n", "-p", _AD_PORTS, "--open",
             "--max-retries", "1", "--host-timeout", "10s", ip],
            capture_output=True, text=True, timeout=12
        ).stdout
        for line in nmap_out.splitlines():
            m = re.search(r"Domain:\s*([\w\.-]+)", line)
            if m and not result.get("domain"):
                dom = m.group(1).rstrip("0")
                result["domain"]  = dom
                result["base_dn"] = "DC=" + dom.replace(".", ",DC=")
            m = re.match(r"\s*(\d+)/tcp\s+open", line)
            if m:
                result.setdefault("open_ports", []).append(m.group(1))
    except Exception as e:
        warn(f"nmap skipped: {e}")

    if result.get("dc_fqdn") and not result.get("hostname"):
        result["hostname"] = result["dc_fqdn"].split(".")[0]
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION SETUP
# ══════════════════════════════════════════════════════════════════════════════
def session_setup(announce_loaded: bool = True):
    if SESSION.get("dc_ip") and SESSION.get("domain") and SESSION.get("username"):
        if announce_loaded:
            info(
                f"Session loaded  "
                f"{_C1}{SESSION.get('username')}@{SESSION.get('domain')}{RST}"
                f"  {DIM}▶{RST}  "
                f"{_C2}{SESSION.get('dc_ip')}{RST}"
            )
        return

    print_banner("SESSION SETUP", "Configure target — press Enter to skip a field")
    discovered_values = {}

    current_ip = SESSION.get("dc_ip", "")
    hint       = f"{DIM}[{current_ip}]{RST}" if current_ip else ""
    ip_val     = input(f"  {MAGENTA}[?]{RST} {'DC IP Address':<30} {hint}: ").strip()
    if ip_val:
        SESSION["dc_ip"] = ip_val
    elif current_ip:
        ip_val = current_ip

    if ip_val:
        discovered = _auto_discover(ip_val)
        if discovered:
            discovered_values = dict(discovered)
            for k, v in discovered.items():
                if k == "open_ports":
                    continue
                if v and not SESSION.get(k):
                    SESSION[k] = v
            skew = discovered.get("clock_skew")
            if skew:
                SESSION["_clock_skew"] = skew
                warn(f"Clock skew detected: {skew}  — Sync before Kerberos attacks!")
                print(f"  {DIM}  sudo ntpdate {ip_val}{RST}")
            dom  = SESSION.get("domain","")
            fqdn = SESSION.get("dc_fqdn","")
            if dom:
                success(f"Discovered  domain={_C1}{dom}{RST}  fqdn={_C1}{fqdn}{RST}")

    fields = [
        ("domain",        f"Domain (e.g. {discovered_values.get('domain') or 'corp.local'})"),
        ("dc_fqdn",       f"DC FQDN (e.g. {discovered_values.get('dc_fqdn') or 'DC01.corp.local'})"),
        ("username",      "Username"),
        ("password",      "Password (blank to use hash)"),
        ("nt_hash",       "NTLM Hash (blank if using password)"),
        ("attacker_ip",   "Attacker / Listener IP"),
        ("attacker_iface","Network Interface (e.g. tun0, eth0)"),
        ("engagement",    "Engagement Name"),
    ]
    for key, label in fields:
        current  = SESSION.get(key, "")
        disp     = "***" if key in ("password", "nt_hash") and current else current
        detected = discovered_values.get(key, "")
        if detected and detected != current:
            hint = f"{DIM}[current: {disp or '-'} | detected: {detected}]{RST}"
        else:
            hint = f"{DIM}[{disp}]{RST}" if current else ""
        val = input(f"  {MAGENTA}[?]{RST} {label:<30} {hint}: ").strip()
        if val:
            SESSION[key] = val

    success("Session configured!")
    save_session()


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION MANAGER
# ══════════════════════════════════════════════════════════════════════════════
def session_manager():
    _clear_screen()
    P  = CYAN
    MG = VIOLET
    PW = WHITE
    SW = GRAY
    GR = GREEN

    W = max(60, min(96, shutil.get_terminal_size((100, 24)).columns - 4))
    print()
    print(f"  {MG}╔{'═' * (W-2)}╗{RST}")
    print(f"  {MG}║{RST}  {P}{BOLD}SESSION MANAGER{RST}"
          f"{'':>{W - 19}}{MG}║{RST}")
    print(f"  {MG}╚{'═' * (W-2)}╝{RST}")

    # Current session summary
    dc   = SESSION.get("dc_ip",    "") or f"{DIM}not set{RST}"
    dom  = SESSION.get("domain",   "") or f"{DIM}not set{RST}"
    user = SESSION.get("username", "") or f"{DIM}not set{RST}"
    auth = _auth_badge()
    eng  = SESSION.get("engagement","") or f"{DIM}not set{RST}"

    print()
    print(f"  {DIM}  Current session:{RST}")
    print(f"  {MG}  ●{RST}  Target   {PW}{BOLD}{user}@{dom}{RST}  {DIM}▶{RST}  {P}{dc}{RST}")
    print(f"  {MG}  ●{RST}  Auth     {auth}")
    print(f"  {MG}  ●{RST}  Engage   {SW}{eng}{RST}")
    print()
    print(f"  {DIM}{'─' * (W-2)}{RST}")
    print(f"  {MG}[{RST}{PW}{BOLD}1{RST}{MG}]{RST}  {PW}Configure session{RST}       {SW}Set target, credentials, engagement{RST}")
    print(f"  {MG}[{RST}{PW}{BOLD}2{RST}{MG}]{RST}  {PW}Show current session{RST}    {SW}Display all session values{RST}")
    print(f"  {MG}[{RST}{PW}{BOLD}3{RST}{MG}]{RST}  {PW}Save session to file{RST}    {SW}Persist session.json{RST}")
    print(f"  {MG}[{RST}{PW}{BOLD}4{RST}{MG}]{RST}  {PW}Load session from file{RST}  {SW}Restore a saved session{RST}")
    print(f"  {MG}[{RST}{PW}{BOLD}5{RST}{MG}]{RST}  {PW}Clear credentials{RST}       {SW}Wipe target/auth from session{RST}")
    print(f"  {DIM}{'─' * (W-2)}{RST}")
    print(f"  {P}[{RST}{PW}{BOLD}0{RST}{P}]{RST}  {PW}Back{RST}")
    print()

    c = input(f"  {MG}┌─[Session]─▶{RST} ").strip()

    if c == "1":
        session_setup(announce_loaded=False)
    elif c == "2":
        safe = {k: v for k, v in SESSION.items() if k not in ("commands_run",)}
        safe = redact_obj(safe)
        print()
        print(f"  {DIM}{'─' * 40}{RST}")
        for k, v in safe.items():
            if isinstance(v, (list, dict)) and not v:
                continue
            val = json.dumps(v, default=str) if isinstance(v, (list, dict)) else str(v)
            if len(val) > 60:
                val = val[:57] + "..."
            dot = f"{GR}●{RST}" if v and v not in ("", "—", False, [], {}) else f"{DIM}○{RST}"
            print(f"  {dot}  {MG}{k:<22}{RST}  {SW}{val}{RST}")
        print(f"  {DIM}{'─' * 40}{RST}")
    elif c == "3":
        save_session()
        success("Session saved → output/session.json")
    elif c == "4":
        path = input(f"  {MG}[?]{RST} Session file path: ").strip()
        if os.path.exists(path):
            with open(path) as f:
                SESSION.update(json.load(f))
            success(f"Session loaded from {path}")
        else:
            error("File not found")
    elif c == "5":
        for k in ["dc_ip", "domain", "username", "password",
                  "nt_hash", "dc_fqdn", "hostname", "base_dn",
                  "attacker_ip", "attacker_iface"]:
            SESSION[k] = ""
        SESSION["use_kerberos"] = False
        SESSION["krb5_ccache"]  = ""
        success("Credentials cleared")

    if c != "0":
        input(f"\n  {MG}[Enter]{RST} to return...")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════
def _ready(key: str) -> str:
    """Green dot if session key populated, dim circle if not."""
    return f"{GREEN}●{RST}" if SESSION.get(key) else f"{DIM}○{RST}"


def print_menu():
    show_banner(clear=True, animate=True)
    _dashboard()

    P  = CYAN
    MG = VIOLET
    PW = WHITE
    SW = GRAY
    GR = GREEN

    W = max(60, min(100, shutil.get_terminal_size((100, 24)).columns - 4))

    def section(label: str):
        line = f"{'─' * 3} {label} {'─' * max(W - 8 - len(label), 0)}"
        print(f"\n  {GRAY}{line}{RST}")

    # ── SETUP ─────────────────────────────────────────────────────────────────
    section("SETUP")
    has_session = bool(SESSION.get("dc_ip") and SESSION.get("domain"))
    dot1    = f"{GR}●{RST}" if has_session else f"{GRAY}○{RST}"
    status1 = f"{GR}READY{RST}" if has_session else f"{YELLOW}NOT CONFIGURED{RST}"
    print(f"  {dot1} {P}[{RST}{PW}{BOLD}1{RST}{P}]{RST}  "
          f"{PW}{BOLD}{'Session Manager':<26}{RST}  "
          f"{SW}Target · credentials · workspace{RST}   {status1}")

    # ── ATTACK ────────────────────────────────────────────────────────────────
    section("ATTACK")
    has_agent_req = bool(SESSION.get("dc_ip") and SESSION.get("domain"))
    dot2  = f"{GR}●{RST}" if has_agent_req else f"{GRAY}○{RST}"
    stat2 = f"{GR}READY{RST}" if has_agent_req else f"{YELLOW}SESSION REQUIRED{RST}"
    print(f"  {dot2} {P}[{RST}{PW}{BOLD}2{RST}{P}]{RST}  "
          f"{PW}{BOLD}{'AdAgent  (AI)':<26}{RST}  "
          f"{SW}59 tools · 139 techniques · Ollama + Claude{RST}   {stat2}")

    # ── OUTPUT ────────────────────────────────────────────────────────────────
    section("OUTPUT")
    findings = SESSION.get("findings", [])
    has_data  = bool(findings or SESSION.get("owned_users") or SESSION.get("loot"))
    dot3  = f"{GR}●{RST}" if has_data else f"{GRAY}○{RST}"
    stat3 = f"{GR}{len(findings)} findings ready{RST}" if has_data else f"{GRAY}no data yet{RST}"
    print(f"  {dot3} {P}[{RST}{PW}{BOLD}3{RST}{P}]{RST}  "
          f"{PW}{BOLD}{'Generate Report':<26}{RST}  "
          f"{SW}HTML · Markdown · JSON pentest report{RST}   {stat3}")

    # ── FOOTER ────────────────────────────────────────────────────────────────
    print(f"\n  {GRAY}{'─' * (W - 2)}{RST}")
    print(f"  {GRAY}[{RST}{PW}{BOLD}0{RST}{GRAY}]{RST}  "
          f"{WHITE}{'Exit':<26}{RST}  {GRAY}Save session & quit{RST}")
    print()


# ══════════════════════════════════════════════════════════════════════════════
#  REPORT
# ══════════════════════════════════════════════════════════════════════════════
def run_report():
    import importlib
    try:
        mod = importlib.import_module("modules.reporting")
        importlib.reload(mod)
        mod.run()
    except Exception as e:
        error(f"Report error: {e}")
    pause()


# ══════════════════════════════════════════════════════════════════════════════
#  CLI ARGS
# ══════════════════════════════════════════════════════════════════════════════
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="AdAgent — AI-powered Active Directory attack orchestrator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--session", metavar="PATH", help="load a session JSON file before running")
    parser.add_argument("--no-banner", action="store_true", help="suppress the main ASCII banner")
    parser.add_argument("--agent",  action="store_true", help="launch agent directly (skip menu)")
    return parser.parse_args(argv)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main(argv=None):
    global SHOW_MAIN_BANNER
    args = parse_args(argv)
    if args.no_banner:
        SHOW_MAIN_BANNER = False

    if args.session:
        from pathlib import Path
        if not load_session(Path(args.session)):
            sys.exit(1)

    try:
        if tuple(map(int, platform.python_version().split("."))) < (3, 8):
            warn("Python 3.10+ recommended")
    except Exception:
        pass

    try:
        session_setup(announce_loaded=False)

        if args.agent:
            from modules.agent._core import run as agent_run
            agent_run()
            save_session()
            # The agent completion screen explicitly promises a return to the
            # main menu after Enter, so direct-launch mode should rejoin the
            # normal menu loop instead of terminating the process here.

        while True:
            print_menu()
            _prompt_str = (
                f"\n  {GRAY}┌─[{RST}{CYAN}{BOLD}AdAgent{RST}{GRAY}]─[{RST}{GRAY}v{VERSION}{GRAY}]{RST}\n"
                f"  {GRAY}└──▶{RST} "
            )
            try:
                choice = input(_prompt_str).strip()
            except EOFError:
                try:
                    sys.stdin = open("/dev/tty", "r")
                    choice    = input(_prompt_str).strip()
                except Exception:
                    choice = ""

            if choice == "0":
                save_session()
                _clear_screen()
                W = max(50, min(70, shutil.get_terminal_size((80,24)).columns - 4))
                cmds    = len(SESSION.get("commands_run", []))
                finds   = len(SESSION.get("findings", []))
                owned_u = len(SESSION.get("owned_users", []))
                owned_m = len(SESSION.get("owned_machines", []))
                loot    = len(SESSION.get("loot", {}))
                print()
                print(f"  {GRAY}╔{'═' * (W-2)}╗{RST}")
                print(f"  {GRAY}║{RST}  {CYAN}{BOLD}SESSION SAVED{RST}"
                      f"{'':>{W-17}}{GRAY}║{RST}")
                print(f"  {GRAY}╠{'═' * (W-2)}╣{RST}")
                for label, val in [
                    ("Commands run",  cmds),
                    ("Findings",      finds),
                    ("Users owned",   owned_u),
                    ("Hosts owned",   owned_m),
                    ("Hashes loot",   loot),
                ]:
                    dot = f"{GREEN}●{RST}" if val else f"{GRAY}○{RST}"
                    line = f"  {dot}  {GRAY}{label:<16}{RST}  {WHITE}{BOLD}{val}{RST}"
                    vis  = __import__('re').sub(r'\033\[[^m]*m','', line)
                    pad  = max(W - 2 - len(vis), 1)
                    print(f"  {GRAY}║{RST}{line}{' ' * pad}{GRAY}║{RST}")
                print(f"  {GRAY}╠{'═' * (W-2)}╣{RST}")
                msg = f"  {CYAN}{BOLD}Happy hunting.{RST}"
                vis = __import__('re').sub(r'\033\[[^m]*m','', msg)
                print(f"  {GRAY}║{RST}{msg}{' ' * max(W-2-len(vis),1)}{GRAY}║{RST}")
                print(f"  {GRAY}╚{'═' * (W-2)}╝{RST}")
                print()
                sys.exit(0)
            elif choice == "1":
                session_manager()
            elif choice == "2":
                from modules.agent._core import run as agent_run
                agent_run()
            elif choice == "3":
                run_report()
            else:
                warn("Invalid choice — enter 0, 1, 2, or 3")

    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}{BOLD}[!] Caught Ctrl-C — saving session…{RST}")
        save_session()
        sys.exit(0)


if __name__ == "__main__":
    main()
