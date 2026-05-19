"""
cli/runner.py — Session injection and agent launch logic for CLI mode.
"""
import os, sys, getpass


# ── Claude model shorthands ────────────────────────────────────────────────────
_CLAUDE_MODELS = {
    "opus":   "claude-opus-4-7-20250514",
    "sonnet": "claude-sonnet-4-6",
    "haiku":  "claude-haiku-4-5-20251001",
}


def resolve_claude_model(alias: str) -> str:
    return _CLAUDE_MODELS.get(alias.lower(), alias) if alias else "claude-sonnet-4-6"


def pick_ollama_model(hint: str) -> str:
    """
    Return the best available local Ollama model.
    Honours --model hint; auto-selects a tool-calling model if no hint given.
    Exits with a helpful message if Ollama is not running or no models exist.
    """
    import subprocess
    from cli.display import YELLOW, CYAN, GRAY, RST

    try:
        raw = subprocess.run(
            ["ollama", "list"], capture_output=True, text=True, timeout=5
        ).stdout
        installed = [l.split()[0] for l in raw.splitlines()[1:] if l.strip()]
    except FileNotFoundError:
        print(f"\n  {YELLOW}[!]{RST}  ollama not found in PATH.")
        print(f"  {GRAY}    Install: https://ollama.com{RST}\n")
        sys.exit(1)
    except Exception:
        installed = []

    if hint:
        if hint in installed:
            return hint
        prefix_match = [m for m in installed if m.startswith(hint.split(":")[0])]
        if prefix_match:
            return prefix_match[0]
        # Trust the user even if model isn't found locally yet
        return hint

    if not installed:
        print(f"\n  {YELLOW}[!]{RST}  No Ollama models found.")
        print(f"  {GRAY}    Pull one:  ollama pull qwen2.5-coder:7b{RST}\n")
        sys.exit(1)

    preferred = ["qwen2.5-coder", "mistral", "llama3", "deepseek", "command-r"]
    for pref in preferred:
        for m in installed:
            if pref in m:
                return m
    return installed[0]


def resolve_api_key(args) -> str:
    """Return Claude API key from --api-key flag, env var, or interactive prompt."""
    from cli.display import CYAN, RED, RST

    key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        try:
            key = getpass.getpass(f"  {CYAN}Anthropic API key:{RST} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
    if not key:
        print(f"\n  {RED}[!]{RST}  API key required for Claude backend.")
        sys.exit(1)
    os.environ["ANTHROPIC_API_KEY"] = key
    return key


def maybe_prompt_password(args) -> None:
    """
    If a username was supplied but no credential flag was given,
    interactively ask for a password (can be left blank for NULL / hash flow).
    """
    from cli.display import CYAN, GRAY, RST

    if args.user and not args.password and not args.hash and not args.ccache:
        try:
            args.password = getpass.getpass(
                f"  {CYAN}Password for {args.user}{RST}"
                f"  {GRAY}(Enter = hash / NULL session){RST}: "
            ).strip()
        except (KeyboardInterrupt, EOFError):
            print()


def inject_session(args) -> None:
    """Populate AdAgent's global SESSION dict from CLI args."""
    from config.settings import SESSION, _refresh_derived

    SESSION["dc_ip"]       = args.dc
    SESSION["domain"]      = args.domain
    SESSION["username"]    = args.user
    SESSION["password"]    = args.password
    SESSION["nt_hash"]     = args.hash
    SESSION["attacker_ip"] = args.attacker
    SESSION["engagement"]  = args.engagement

    if args.ccache:
        SESSION["use_kerberos"] = True
        SESSION["krb5_ccache"]  = args.ccache
        os.environ["KRB5CCNAME"] = args.ccache
    else:
        SESSION["use_kerberos"] = False

    _refresh_derived()


def run_plan(args, api_key: str, ollama_model: str) -> None:
    """Generate a text-only attack plan without executing any tools."""
    from modules.agent._core import SYSTEM_PROMPT
    from cli.display import CYAN, RST

    plan_prompt = (
        f"Target: {args.user or 'anonymous'}@{args.domain} → {args.dc}\n"
        f"Auth: password={bool(args.password)}, "
        f"hash={bool(args.hash)}, kerberos={bool(args.ccache)}\n\n"
        "Produce a detailed Active Directory attack plan in priority order. "
        "For each vector explain why it is valuable and the expected outcome. "
        "Do NOT call any tools — text only."
    )

    if args.backend == "ollama":
        from modules.agent.backends import _ollama_chat_completion
        print(f"\n  {CYAN}[*]{RST}  Generating attack plan via Ollama / {ollama_model}…\n")
        resp = _ollama_chat_completion(
            model=ollama_model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": plan_prompt},
            ],
            temperature=0.1,
        )
        print(resp.choices[0].message.content)
    else:
        import anthropic
        model = resolve_claude_model(args.model)
        print(f"\n  {CYAN}[*]{RST}  Generating attack plan via Claude / {model}…\n")
        client = anthropic.Anthropic(api_key=api_key)
        resp   = client.messages.create(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": plan_prompt}],
        )
        for block in resp.content:
            if hasattr(block, "text"):
                print(block.text)


def run_agent(args, api_key: str, ollama_model: str) -> None:
    """Launch the full autonomous 59-tool attack agent."""
    import modules.agent.constants as _const
    from modules.agent._core import (
        run_agent as _run_claude,
        run_agent_ollama as _run_ollama,
    )

    _const.OPSEC_MODE = args.opsec
    os.environ["ADSTRIKE_OPSEC"] = args.opsec

    if args.rounds > 0:
        _const.MAX_ROUNDS = args.rounds

    if args.backend == "ollama":
        _run_ollama(
            args.dc, args.domain, args.user,
            args.password, args.hash,
            ollama_model,
        )
    else:
        _run_claude(
            args.dc, args.domain, args.user,
            args.password, args.hash,
            api_key,
        )

    from config.settings import save_session
    save_session()
