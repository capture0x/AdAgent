#!/usr/bin/env python3
"""
AdAgent CLI Mode — entry point.

Run via:  ./adcli.sh  [flags]
     or:  python3 -m cli.adcli  [flags]
"""
import sys
import os

# Ensure AdAgent root is on sys.path when run directly
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from cli.args    import build_parser
from cli.display import print_banner, print_profile, countdown, abort_msg
from cli.runner  import (
    pick_ollama_model,
    resolve_api_key,
    maybe_prompt_password,
    inject_session,
    run_plan,
    run_agent,
)


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # Prompt for password if user given but no credential flag
    maybe_prompt_password(args)

    # ── Resolve backend details ───────────────────────────────────────────────
    ollama_model = ""
    api_key      = ""

    if args.backend == "ollama":
        ollama_model = pick_ollama_model(args.model)
    else:
        api_key = resolve_api_key(args)
        if not args.model:
            args.model = "sonnet"

    # ── Banner + profile summary ──────────────────────────────────────────────
    if not args.no_banner:
        print_banner()

    print_profile(args, ollama_model)

    # ── Inject settings into AdAgent session ─────────────────────────────────
    inject_session(args)

    # ── Countdown / immediate start ───────────────────────────────────────────
    if not args.yes:
        try:
            countdown(5)
        except KeyboardInterrupt:
            abort_msg()
            sys.exit(0)

    # ── Launch ────────────────────────────────────────────────────────────────
    if args.mode == "plan":
        run_plan(args, api_key, ollama_model)
    else:
        run_agent(args, api_key, ollama_model)


if __name__ == "__main__":
    main()
