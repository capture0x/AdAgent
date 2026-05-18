"""
modules/agent/constants.py
Configuration constants and runtime settings for AdAgent.
All agent submodules import from here so settings live in one place.
"""
import os
from pathlib import Path

from config.settings import OUTPUT_DIR
from utils.helpers import (
    BABY_BLUE, LIGHT_PINK, SOFT_PINK, PURE_WHITE, SOFT_WHITE,
    NEON_GRN, NEON_CYN, NEON_RED, NEON_YEL, NEON_PUR,
    BOLD, DIM, RST, fg,
)

# ── AdAgent professional palette — consistent with main.py ───────────────────
_CYAN    = "\033[38;2;0;180;216m"     # #00B4D8 — primary labels / info
_VIOLET  = "\033[38;2;123;47;190m"    # #7B2FBE — secondary accent
_GREEN   = "\033[38;2;6;214;160m"     # #06D6A0 — success / findings
_YELLOW  = "\033[38;2;255;183;3m"     # #FFB703 — warning
_WHITE   = "\033[38;2;237;242;244m"   # #EDF2F4 — primary text / values
_GRAY    = "\033[38;2;141;153;174m"   # #8D99AE — secondary text

# ── Claude model selection ────────────────────────────────────────────────────
MODEL      = "claude-sonnet-4-20250514"   # balanced default
MAX_TOKENS = 4096
MAX_ROUNDS = 50                            # safety cap on autonomous rounds

# ── Directory layout ──────────────────────────────────────────────────────────
LOG_DIR           = Path(OUTPUT_DIR) / "agent_logs"
AGENT_RUNTIME_DIR = Path(OUTPUT_DIR) / "agent_runtime"
LOG_DIR.mkdir(exist_ok=True)
AGENT_RUNTIME_DIR.mkdir(exist_ok=True)

# ── Behavioural toggles (env-overridable) ────────────────────────────────────
AGENT_CLEAN_OUTPUT_ON_START = os.environ.get(
    "AGENT_CLEAN_OUTPUT_ON_START", "true"
).lower() in ("1", "true", "yes", "on")

AGENT_ARCHIVE_OLD_RUNS = os.environ.get(
    "AGENT_ARCHIVE_OLD_RUNS", "true"
).lower() in ("1", "true", "yes", "on")

AGENT_LIVE_COMMANDS = os.environ.get(
    "ADSTRIKE_AGENT_LIVE_COMMANDS", "true"
).lower() in ("1", "true", "yes", "on")

# ── Ollama settings ───────────────────────────────────────────────────────────
OLLAMA_API_TIMEOUT = int(os.environ.get("ADSTRIKE_OLLAMA_TIMEOUT", "20"))
OLLAMA_MAX_TOOLS   = max(1, int(os.environ.get("ADSTRIKE_OLLAMA_MAX_TOOLS", "1")))
OLLAMA_SHOW_FALLBACK_WARNINGS = os.environ.get(
    "ADSTRIKE_OLLAMA_SHOW_FALLBACK_WARNINGS", "false"
).lower() in ("1", "true", "yes", "on")
OLLAMA_FORCE_LLM_DECISION = os.environ.get(
    "ADSTRIKE_OLLAMA_FORCE_LLM_DECISION", "false"
).lower() in ("1", "true", "yes", "on")

# ── OPSEC / Red Team settings ─────────────────────────────────────────────────
# "loud"   — fast, no jitter, use all tools (labs/CTF)
# "normal" — moderate jitter, avoid obvious detection (default)
# "stealth"— aggressive OPSEC, native tools first, max jitter
OPSEC_MODE = os.environ.get("ADSTRIKE_OPSEC", "normal").lower()

# ── Port overrides ────────────────────────────────────────────────────────────
LDAP_PORT  = int(os.environ.get("ADSTRIKE_LDAP_PORT",  "389"))
LDAPS_PORT = int(os.environ.get("ADSTRIKE_LDAPS_PORT", "636"))
SMB_PORT   = int(os.environ.get("ADSTRIKE_SMB_PORT",   "445"))
WINRM_PORT = int(os.environ.get("ADSTRIKE_WINRM_PORT", "5985"))

# ── Agent UI colour aliases ───────────────────────────────────────────────────
AGENT_BLUE  = _CYAN      # cyan    — round headers / labels
AGENT_PINK  = _VIOLET    # violet  — borders / secondary accent
AGENT_TEXT  = _GRAY      # gray    — body text
AGENT_WHITE = _WHITE     # white   — values
AGENT_GREEN = _GREEN     # green   — success / findings
AGENT_WARN  = _YELLOW    # yellow  — warnings
