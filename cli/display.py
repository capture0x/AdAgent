"""
cli/display.py — Banner, profile summary table, and countdown for CLI mode.
"""
import os, re, shutil, time, sys

# ── Colour palette (matches AdAgent main.py) ──────────────────────────────────
RST    = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

CYAN   = "\033[38;2;0;180;216m"
VIOLET = "\033[38;2;123;47;190m"
GREEN  = "\033[38;2;6;214;160m"
YELLOW = "\033[38;2;255;183;3m"
RED    = "\033[38;2;239;35;60m"
WHITE  = "\033[38;2;237;242;244m"
GRAY   = "\033[38;2;141;153;174m"

_ART = r"""
     ___       __   ___                    __
    /   | ____/ /  /   | ____ ____  ____  / /_
   / /| |/ __  /  / /| |/ __ `/ _ \/ __ \/ __/
  / ___ / /_/ /  / ___ / /_/ /  __/ / / / /_
 /_/  |_\__,_/  /_/  |_\__, /\___/_/ /_/\__/
                       /____/
"""


def _cols() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def _strip(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


def print_banner() -> None:
    os.system("clear")
    palette = [CYAN, VIOLET]
    print()
    for i, line in enumerate(l for l in _ART.splitlines() if l.strip()):
        print(f"{palette[i % 2]}{BOLD}{line}{RST}")
    sep = f"{GRAY}{'─' * min(80, _cols() - 2)}{RST}"
    print(sep)
    print(
        f"  {CYAN}{BOLD}AI ACTIVE DIRECTORY ATTACK AGENT{RST}"
        f"  {GRAY}|{RST}  {VIOLET}{BOLD}CLI Mode{RST}"
    )
    print(f"  {GRAY}59 tools  ·  139 techniques  ·  Ollama + Claude  ·  by tmrswrr{RST}")
    print(
        f"  {YELLOW}{BOLD}[!]{RST}  "
        f"{WHITE}Authorised penetration testing and red-team engagements only{RST}"
    )
    print(sep)
    print()


def _dot(val: str) -> str:
    return f"{GREEN}●{RST}" if val else f"{GRAY}○{RST}"


def _auth_label(args) -> str:
    if args.ccache:
        return f"{CYAN}{BOLD}⚷  KERBEROS{RST}  {GRAY}ccache: {args.ccache}{RST}"
    if args.hash:
        return f"{CYAN}{BOLD}#  PASS-THE-HASH{RST}"
    if args.password:
        return f"{GREEN}{BOLD}✓  PASSWORD{RST}"
    return f"{GRAY}○  NULL SESSION  (anon LDAP → RID cycle → AS-REP){RST}"


def _backend_label(args, ollama_model: str) -> str:
    if args.backend == "ollama":
        return f"Ollama  /  {ollama_model}"
    model_map = {
        "opus":   "claude-opus-4-7-20250514",
        "sonnet": "claude-sonnet-4-6",
        "haiku":  "claude-haiku-4-5-20251001",
    }
    return f"Claude  /  {model_map.get(args.model.lower(), args.model)}"


def print_profile(args, ollama_model: str) -> None:
    """Print a styled summary table of all attack settings."""
    W  = min(78, _cols() - 4)
    MG = VIOLET
    P  = CYAN
    PW = WHITE
    GR = GRAY

    top = f"  {MG}╔{'═' * (W - 2)}╗{RST}"
    bot = f"  {MG}╚{'═' * (W - 2)}╝{RST}"
    div = f"  {MG}╠{'═' * (W - 2)}╣{RST}"

    def row(content: str) -> str:
        pad = max(W - 2 - len(_strip(content)), 0)
        return f"  {MG}║{RST} {content}{' ' * pad} {MG}║{RST}"

    mode_lbl    = "FULL AUTO" if args.mode == "auto" else "PLAN ONLY"
    backend_lbl = _backend_label(args, ollama_model)

    print(top)
    print(row(f"{P}{BOLD}  ATTACK PROFILE{RST}  {GR}— review before launch{RST}"))
    print(div)
    print(row(
        f"  {GR}TARGET    {RST}"
        f"{_dot(args.dc)} {PW}{BOLD}{args.user or 'anonymous'}{RST}"
        f"{GR}@{RST}{PW}{BOLD}{args.domain}{RST}"
        f"  {GR}▶  {RST}{CYAN}{BOLD}{args.dc}{RST}"
    ))
    print(row(f"  {GR}AUTH      {RST}{_auth_label(args)}"))
    print(row(
        f"  {GR}ATTACKER  {RST}{_dot(args.attacker)}{CYAN} {args.attacker or 'not set'}{RST}"
        f"  {GR}│  ENGAGEMENT  {RST}{PW}{args.engagement or '—'}{RST}"
    ))
    print(div)
    print(row(f"  {GR}BACKEND   {RST}{PW}{BOLD}{backend_lbl}{RST}"))
    print(row(
        f"  {GR}OPSEC     {RST}{PW}{BOLD}{args.opsec.upper()}{RST}"
        f"  {GR}│  MODE  {RST}{PW}{BOLD}{mode_lbl}{RST}"
        + (f"  {GR}│  MAX ROUNDS  {RST}{PW}{args.rounds}{RST}" if args.rounds else "")
    ))
    print(bot)
    print()


def countdown(seconds: int = 5) -> None:
    """Print a live countdown, raises KeyboardInterrupt passthrough on Ctrl+C."""
    print(f"  {GRAY}Press {YELLOW}Ctrl+C{GRAY} to abort  ·  use {CYAN}--yes{GRAY} to skip{RST}")
    print(f"  {WHITE}Starting in…{RST} ", end="", flush=True)
    for i in range(seconds, 0, -1):
        print(f"{CYAN}{BOLD}{i}{RST} ", end="", flush=True)
        time.sleep(1)
    print()
    print()


def abort_msg() -> None:
    print(f"\n\n  {YELLOW}Aborted.{RST}\n")
