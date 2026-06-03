# AdAgent as an MCP server — **no API key**

> **TL;DR — No `ANTHROPIC_API_KEY`, no Ollama, no local model.**
> On this path AdAgent runs **no LLM of its own**. It exposes its AD-attack tools
> over the [Model Context Protocol](https://modelcontextprotocol.io), and a host
> that already has an LLM — **Claude Code, Cursor, Claude Desktop, …** — drives the
> engagement with its **own subscription**. The host is the brain; AdAgent is the
> toolbox.

All **53 tools** are published: the **52 attack tools** the standalone agent uses
(`nmap_scan`, `enumerate_ldap`, `adcs_scan`, `evil_winrm`, `gmsa_read`,
`dcsync_attack`, `kerberoast`, …) **plus `set_engagement`**. They use the exact
schemas from `modules/agent/_core.py` — one source of truth, no duplication.

---

## 1. Requirements

- The `mcp` Python package, plus AdAgent's normal dependencies, available to the
  **same interpreter** you launch the server with. `mcp` is in `requirements.txt`,
  so `install.sh` puts it in the project venv alongside everything else.

Verify the server can import everything and see all tools:

```bash
./venv/bin/python3 -c "import mcp; from modules.agent._core import TOOLS, TOOL_MAP; \
print('mcp ok; executable tools:', sum(1 for t in TOOLS if t['name'] in TOOL_MAP), '(+ set_engagement = 53)')"
```

If that errors, install into the venv:

```bash
./venv/bin/python3 -m pip install -r requirements.txt
```

Any interpreter that has both `mcp` and AdAgent's deps works — just adjust the
paths below to match.

---

## 2. Register the server

Use the **absolute path** to both the interpreter and `mcp_server.py`. The server
`chdir`s to the repo root on start, so loot/runtime files land in `output/` as
usual regardless of where the host launches it. Tool status text goes to
**stderr** (the host shows it as server logs); **stdout carries only JSON-RPC**.

### Claude Code

**Option A — shipped project file (default).** The repo already contains a
`.mcp.json` at its root with repo-relative paths:

```json
{
  "mcpServers": {
    "adagent": {
      "command": "venv/bin/python3",
      "args": ["mcp_server.py"]
    }
  }
}
```

Because the paths are relative, this works as-is **when you launch Claude Code
from the AdAgent folder** (the paths resolve against that cwd, and the install
puts the interpreter at `venv/`). No edit needed — just approve the server on
first launch. If your venv lives elsewhere, point `command` at that interpreter.

**Option B — global registration via CLI** (works from any directory; use
absolute paths):

```bash
claude mcp add adagent -- /path/to/AdAgent/venv/bin/python3 /path/to/AdAgent/mcp_server.py
```

Confirm it registered and the tools are listed:

```bash
claude mcp list
```

### Cursor

Add to `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per-project):

```json
{
  "mcpServers": {
    "adagent": {
      "command": "/path/to/AdAgent/venv/bin/python3",
      "args": ["/path/to/AdAgent/mcp_server.py"]
    }
  }
}
```

### Claude Desktop

Add to the config file
(`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS,
`%APPDATA%\Claude\claude_desktop_config.json` on Windows), then restart the app:

```json
{
  "mcpServers": {
    "adagent": {
      "command": "/path/to/AdAgent/venv/bin/python3",
      "args": ["/path/to/AdAgent/mcp_server.py"]
    }
  }
}
```

All three hosts use the same `command` + `args` shape.

---

## 3. Usage

0. **Start the host from the AdAgent folder.** With Claude Code, a project
   `.mcp.json` is only loaded when `claude` launches from the directory that
   contains it:

   ```bash
   cd /path/to/AdAgent
   claude
   ```

   Approve the `adagent` server on first launch, then confirm with `/mcp` (or
   `claude mcp list`). Cursor and Claude Desktop pick the server up after a
   restart. (Skip this step if you registered the server globally.)

1. **Set the engagement once.** Ask the host to call `set_engagement` with the
   target and credentials:

   > set_engagement: dc_ip `10.0.0.1`, domain `corp.local`, username `alice`,
   > password `…` (or `nt_hash`)

   Required: `dc_ip`, `domain`, `username`. Provide `password` **or** `nt_hash`
   (not both). `dc_fqdn` is optional.

   AdAgent stores these in the session and **injects them into every later tool
   call** (`_sanitize_tool_inputs`), so the model never has to repeat the password
   and can't accidentally target the wrong host/account.

2. **Let the host drive.** From there the host LLM reads each tool's output and
   chooses the next tool — nmap → LDAP enum → BloodHound → the matching abuse
   primitive — just like the built-in agent loop, but funded by the host
   subscription.

A typical opening, in plain language to the host:

> Set the engagement to `10.0.0.1` / `corp.local` as `alice:…`, run an nmap scan,
> then enumerate LDAP and collect BloodHound, and tell me the shortest path to
> Domain Admin.

---

## 4. The 53 tools at a glance

`set_engagement` (session/credentials) + the 52 attack tools, grouped:

| Phase | Tools |
|---|---|
| Recon / no-cred | `nmap_scan`, `no_cred_surface_recon`, `kerbrute_enum` |
| Enumeration | `enumerate_ldap`, `enumerate_shares`, `collect_bloodhound`, `query_bloodhound_paths`, `user_hunt`, `discover_winrm_access` |
| Roasting / spray | `asrep_roast`, `kerberoast`, `targeted_kerberoast`, `password_spray`, `pre2k_attack`, `timeroast` |
| ADCS / certs | `adcs_scan`, `pass_the_cert`, `shadow_credentials_attack` |
| ACL / delegation | `acl_abuse_scan`, `force_change_password_pivot`, `rbcd_attack`, `unconstrained_delegation`, `gmsa_read`, `gmsa_takeover`, `bloodyad` |
| Coercion | `coercion_attack`, `adidns_abuse` |
| Cred access | `credential_loot`, `credential_dump`, `dcsync_attack`, `laps_read`, `shadow_copies_dump`, `test_credential` |
| Lateral / exec | `lateral_movement`, `evil_winrm`, `mssql_abuse`, `logon_script_abuse`, `jea_enum` |
| Persistence / tickets | `golden_ticket`, `silver_ticket`, `request_tgt`, `gpo_abuse`, `sccm_abuse`, `rodc_attack`, `trust_attack` |
| Privesc / recon | `windows_privesc_recon` |
| Orchestration | `auto_loot_chain`, `chain_planner`, `run_module`, `update_session`, `generate_report`, `agent_complete` |

The authoritative list (names, descriptions, input schemas) is always
`modules/agent/_core.py` → `TOOLS` / `TOOL_MAP`.

---

## 5. Notes

- This path does **not** start AdAgent's own agent loop; it never imports an
  Ollama model or an Anthropic client. The standalone `python3 main.py` agent
  (Ollama local / Claude API) is unchanged and still available.
- Tools shell out to `nmap`/`certipy`/`evil-winrm`/… and run blocking; each call
  is offloaded to a worker thread so the protocol stays responsive.
- Provide `password` **or** `nt_hash` to `set_engagement`, not both.
- **Authorized use only.** The host LLM can chain real attack primitives against
  whatever you point it at — only run against systems you have explicit written
  permission to test.
