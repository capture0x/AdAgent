#!/usr/bin/env python3
"""
NightShade MCP server - exposes the full NightShade toolset over the Model Context
Protocol so an MCP host can drive engagements using NightShade as the toolbox.

Launch:
    python3 mcp_server.py
"""
import contextlib
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Tool implementations use repo-relative output paths. Anchor the process so
# MCP hosts can launch this server from any working directory.
os.chdir(_ROOT)

# MCP stdio uses stdout for JSON-RPC. Keep import-time and runtime tool chatter
# off stdout so colored agent output cannot corrupt the protocol stream.
with contextlib.redirect_stdout(sys.stderr):
    from modules.agent._core import (
        TOOLS,
        TOOL_MAP,
        dispatch_tool,
        SESSION,
        save_session,
    )
    from config.settings import reset_session_for_target_change, _refresh_derived

import anyio
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

server = Server("nightshade")

_SET_ENGAGEMENT = types.Tool(
    name="set_engagement",
    description=(
        "Set the engagement target and credentials once before running any attack "
        "tool. NightShade injects these into later tool calls, so the host does not "
        "need to pass the password again. Provide password OR nt_hash."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "dc_ip": {"type": "string", "description": "Domain Controller IP"},
            "domain": {"type": "string", "description": "AD domain FQDN, e.g. corp.local"},
            "username": {"type": "string", "description": "Authenticating user (sAMAccountName)"},
            "password": {"type": "string", "description": "User password (omit if using nt_hash)"},
            "nt_hash": {"type": "string", "description": "NTLM hash (omit if using password)"},
            "dc_fqdn": {"type": "string", "description": "DC FQDN, e.g. dc1.corp.local (optional)"},
        },
        "required": ["dc_ip", "domain", "username"],
    },
)


@server.list_tools()
async def _list_tools():
    """Expose set_engagement plus every executable NightShade tool."""
    tools = [_SET_ENGAGEMENT]
    for t in TOOLS:
        if t["name"] in TOOL_MAP:
            tools.append(
                types.Tool(
                    name=t["name"],
                    description=t.get("description", ""),
                    inputSchema=t["input_schema"],
                )
            )
    return tools


def _set_engagement(args: dict) -> str:
    dc_ip = str(args.get("dc_ip") or "").strip()
    domain = str(args.get("domain") or "").strip()
    username = str(args.get("username") or "").strip()
    password = args.get("password") or ""
    nt_hash = args.get("nt_hash") or ""
    dc_fqdn = str(args.get("dc_fqdn") or "").strip()

    missing = [k for k, v in (("dc_ip", dc_ip), ("domain", domain), ("username", username)) if not v]
    if missing:
        return (
            "set_engagement rejected: missing required field(s): "
            f"{', '.join(missing)}. Session unchanged."
        )
    if password and nt_hash:
        return "set_engagement rejected: provide password OR nt_hash, not both. Session unchanged."

    prev_username = str(SESSION.get("username", "")).strip()
    changed = reset_session_for_target_change(dc_ip=dc_ip, domain=domain)
    identity_changed = changed or (
        bool(prev_username) and username.lower() != prev_username.lower()
    )

    SESSION["username"] = username
    if dc_fqdn:
        SESSION["dc_fqdn"] = dc_fqdn

    if password:
        SESSION["password"], SESSION["nt_hash"] = password, ""
    elif nt_hash:
        SESSION["password"], SESSION["nt_hash"] = "", nt_hash
    elif identity_changed:
        SESSION["password"], SESSION["nt_hash"] = "", ""

    SESSION["base_dn"] = ""
    _refresh_derived()
    with contextlib.suppress(Exception):
        save_session()

    ident = (
        f"{SESSION.get('username', '?')}@{SESSION.get('domain', '?')} -> "
        f"{SESSION.get('dc_ip', '?')}"
    )
    auth = "password" if SESSION.get("password") else ("nt_hash" if SESSION.get("nt_hash") else "none")
    if changed:
        note = " stale engagement state cleared;"
    elif identity_changed and auth == "none":
        note = " previous user's credential cleared (new user, none supplied);"
    else:
        note = ""
    return f"Engagement set: {ident} (auth={auth}).{note} Run nmap_scan / enumerate_ldap next."


@server.call_tool(validate_input=False)
async def _call_tool(name: str, arguments: dict | None):
    args = arguments or {}
    if name == "set_engagement":
        return [types.TextContent(type="text", text=_set_engagement(args))]
    if name not in TOOL_MAP:
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

    out = await anyio.to_thread.run_sync(dispatch_tool, name, args)
    return [types.TextContent(type="text", text=str(out))]


async def _main():
    async with stdio_server() as (read_stream, write_stream):
        sys.stdout = sys.stderr
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(_main)
