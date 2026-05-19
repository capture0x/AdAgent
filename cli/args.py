"""
cli/args.py — Argument parser for AdAgent CLI mode.
"""
import argparse


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="adagent-cli",
        description="AdAgent CLI — one-command launcher for the autonomous AD attack agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Password auth, Ollama backend (local / free)
  ./adcli.sh --dc 10.10.10.10 --domain corp.local --user john --pass Password123

  # NT Hash / Pass-the-Hash, Claude backend
  ./adcli.sh --dc 10.10.10.10 --domain corp.local --user admin \\
             --hash aad3b435b51404eeaad3b435b51404ee:abc123... \\
             --backend claude --model sonnet --opsec loud

  # Kerberos ccache
  ./adcli.sh --dc 10.10.10.10 --domain corp.local --user john \\
             --ccache /tmp/john.ccache

  # Generate attack plan only (no tool execution)
  ./adcli.sh --dc 10.10.10.10 --domain corp.local --user john \\
             --pass Password123 --mode plan

  # Skip countdown and start immediately
  ./adcli.sh --dc 10.10.10.10 --domain corp.local --user john \\
             --pass Password123 --yes
""",
    )

    # ── Target ─────────────────────────────────────────────────────────────────
    tgt = p.add_argument_group("Target")
    tgt.add_argument("--dc",         metavar="IP",     required=True,
                     help="Domain Controller IP address")
    tgt.add_argument("--domain",     metavar="DOMAIN", required=True,
                     help="Active Directory domain  (e.g. corp.local)")
    tgt.add_argument("--user",       metavar="USER",   default="",
                     help="Username  (omit for NULL session / pre-auth recon)")
    tgt.add_argument("--attacker",   metavar="IP",     default="",
                     help="Attacker / listener IP  (used by reverse-shell tools)")
    tgt.add_argument("--engagement", metavar="NAME",   default="",
                     help="Engagement name written into reports")

    # ── Credentials (mutually exclusive) ───────────────────────────────────────
    creds = p.add_argument_group("Credentials  (choose one)")
    mx = creds.add_mutually_exclusive_group()
    mx.add_argument("--pass",   dest="password", metavar="PASS",
                    default="", help="Plaintext password")
    mx.add_argument("--hash",   dest="hash",     metavar="HASH",
                    default="", help="NT hash  (LM:NT  or  just NT part)")
    mx.add_argument("--ccache", dest="ccache",   metavar="FILE",
                    default="", help="Kerberos ccache file path (.ccache)")

    # ── AI Backend ─────────────────────────────────────────────────────────────
    ai = p.add_argument_group("AI Backend")
    ai.add_argument("--backend", choices=["ollama", "claude"], default="ollama",
                    help="AI backend  (default: ollama)")
    ai.add_argument("--model",   metavar="NAME", default="",
                    help="Model name or shorthand  "
                         "(ollama: qwen2.5-coder:7b, mistral, …  |  "
                         "claude: opus / sonnet / haiku)")
    ai.add_argument("--api-key", dest="api_key", metavar="KEY", default="",
                    help="Anthropic API key  (or set ANTHROPIC_API_KEY env var)")

    # ── Behaviour ──────────────────────────────────────────────────────────────
    beh = p.add_argument_group("Agent Behaviour")
    beh.add_argument("--opsec", choices=["loud", "normal", "stealth"], default="normal",
                     help="OPSEC level  loud=fast/no-jitter  normal=default  "
                          "stealth=max-opsec  (default: normal)")
    beh.add_argument("--mode",  choices=["auto", "plan"], default="auto",
                     help="auto=full autonomous run  |  plan=text attack plan only  "
                          "(default: auto)")
    beh.add_argument("--rounds", type=int, default=0,
                     help="Override max agent rounds  (default: AdAgent built-in limit)")
    beh.add_argument("--yes",   action="store_true",
                     help="Skip the 5-second confirmation countdown")
    beh.add_argument("--no-banner", action="store_true",
                     help="Suppress the ASCII art banner")

    return p
