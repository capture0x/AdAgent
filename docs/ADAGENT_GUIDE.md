# AdAgent — Complete Operator Guide

**Version:** AdAgent v1.0  
**Audience:** Authorised red team operators, penetration testers, lab users, and maintainers  
**Scope:** AdAgent framework internals, session model, agent architecture, all 59 tools, SAST knowledge base, decision engine, workflows, troubleshooting, and extension guidance

> **Use AdAgent only in environments where you have explicit written permission to test.**
> The tool automates offensive Active Directory techniques and can cause account lockouts,
> service disruption, or domain compromise if used outside an authorised engagement.

---

## 1. What AdAgent Is

AdAgent is a standalone AI-powered Active Directory attack orchestrator. It wraps common AD offensive workflows into a shared session model and drives them autonomously using an AI backend (Ollama or Claude).

Unlike interactive frameworks, AdAgent makes its own decisions about which tool to run next based on what it has discovered, tracks evidence across rounds, adapts when paths fail, and produces structured reports.

> **MCP server path:** AdAgent can also run as a [Model Context Protocol](https://modelcontextprotocol.io)
> tool server inside **Claude Code / Cursor / Claude Desktop** — exposing all 53 tools with **no API key
> and no local model** (the host LLM is the brain). See [`docs/mcp.md`](mcp.md).

**Key capabilities:**
- 59 specialised attack tools covering the full AD kill chain
- 139 attack techniques in 22 SAST categories loaded into the agent's system prompt
- Three ways to drive it: Ollama (local, free, offline), Anthropic Claude (API), or as an **MCP server** (host LLM, no key) — see [`docs/mcp.md`](mcp.md)
- Kerberos-first design for NTLM-disabled environments
- Dead-path tracking per principal — no wasted loops
- OPSEC modes: `loud`, `normal`, `stealth`
- Live Markdown + JSON reports written round-by-round

---

## 2. Design Goals

AdAgent is built around these principles:

- **Preserve state across rounds:** target, domain, user, password, NT hash, Kerberos ccache, findings, owned users, owned machines, and loot all flow between tools
- **Evidence-gated findings:** a finding is only raised when concrete evidence exists — never speculatively
- **Per-principal dead-path tracking:** if `evil_winrm` fails for `user1`, that principal is skipped; a newly discovered account still gets a chance
- **Correct credential pairing:** a gMSA account always uses its own NT hash, never the session user's password
- **Kerberos-first:** auto-detects NTLM-disabled environments and requests TGT transparently
- **OPSEC-aware:** in `stealth` and `normal` modes, noisy tools are suppressed until a confirmed path exists
- **Avoid hard-coded assumptions:** all logic generalises across AD environments — no hard-coded domain names, usernames, or hostnames

---

## 3. Repository Layout

```
AdAgent/
├── main.py                   ← Entry point, session setup, 3-item menu
├── run.sh                    ← Launch script
├── install.sh                ← venv + dependency installer
├── requirements.txt
├── .env.example              ← Configuration template
├── config/
│   └── settings.py           ← Global SESSION dict, Kerberos helpers, redaction
├── utils/
│   └── helpers.py            ← Console UI, command execution, findings helpers
├── modules/
│   ├── agent/
│   │   ├── _core.py          ← 59 tool handlers, orchestration loop, intel engine,
│   │   │                        decision engine, SAST loader, system prompt builder
│   │   ├── backends.py       ← Ollama + Claude API adapters
│   │   ├── constants.py      ← Runtime settings, env toggles, UI colour palette
│   │   └── logger.py         ← Live Markdown report writer (AgentMarkdownLog)
│   ├── reporting.py          ← HTML / Markdown / JSON report generator
│   └── mitre_data.py         ← MITRE ATT&CK reference data and CVSS enrichment
├── ActiveDirectory-SAST/     ← YAML knowledge base (22 files, 139 techniques)
└── output/                   ← Session, logs, reports, runtime artefacts
```

---

## 4. Runtime Model — The SESSION Dictionary

AdAgent keeps all engagement state in a shared `SESSION` dictionary from `config/settings.py`.

| Field | Meaning |
|---|---|
| `dc_ip` | Domain Controller IP address |
| `dc_fqdn` | Domain Controller FQDN |
| `domain` | AD DNS domain |
| `base_dn` | LDAP base DN derived from domain |
| `username` | Current primary principal |
| `password` | Current primary password |
| `nt_hash` | Current primary NT hash |
| `use_kerberos` | Whether Kerberos mode is active |
| `krb5_ccache` | Current Kerberos ccache path |
| `krb5_config` | Target-specific krb5 config path |
| `attacker_ip` | Operator host IP |
| `attacker_iface` | Operator network interface |
| `engagement` | Engagement/report name |
| `commands_run` | Command history list |
| `findings` | Report findings list |
| `owned_users` | Compromised users/service accounts |
| `owned_machines` | Hosts with confirmed shell/admin access |
| `loot` | Discovered NT hashes and credential material |
| `agent_intel` | Agent-specific structured evidence; created when agent runs |

The session is loaded from `.env` at startup and persisted to `output/session.json` automatically.

### Agent Intel Fields

`agent_intel` accumulates structured evidence from every tool run:

| Field | Populated By |
|---|---|
| `users` | LDAP enum, kerbrute, RID cycling |
| `spns` | LDAP enum, GetUserSPNs |
| `asrep_users` | GetNPUsers, LDAP preauth check |
| `admin_users` | LDAP adminCount=1 |
| `esc_vulns` | Certipy find |
| `winrm_targets` | NXC, evil-winrm probing |
| `nt_hashes` | secretsdump, certipy auth, gMSA |
| `gmsa_hashes` | gMSA read/takeover |
| `ccaches` | certipy auth, getTGT |
| `acl_paths` | ACL abuse scan, BloodHound |
| `gmsa_candidates` | LDAP msDS-ManagedPassword enum |
| `valid_creds` | auto_loot_chain, credential testing |
| `adfs_servers` | LDAP SCP, nmap, metadata |
| `wsus_servers_confirmed` | NXC wsus module, registry |
| `rodc_controllers` | LDAP IsReadOnly |
| `sccm_servers` | mSSMSSiteCode LDAP |
| `trust_domains` | trustPartner LDAP, nltest |
| `local_privesc_paths` | SeImpersonatePrivilege, writable services |
| `c2_sessions` | C2 session confirmation |
| `opsec_notes` | EDR/AV/Sysmon/MDI detection results |

---

## 5. Secret Redaction

AdAgent supports redaction through `ADSTRIKE_SHOW_SECRETS`.

- If `ADSTRIKE_SHOW_SECRETS=false` (default), passwords, hashes, and loot values are replaced with `***` in reports and logs
- If `true`, real values appear in output — use only in a private workspace

Redaction protects display and report output. Tools still use real session values internally. Redacted placeholders `***` are scrubbed before reuse as credentials.

---

## 6. Kerberos Handling

Kerberos support is critical because modern AD targets may restrict NTLM. AdAgent handles:

- Target-specific `krb5.conf` generation
- TGT requests via Impacket or kinit
- `KRB5CCNAME` and `KRB5_CONFIG` environment management
- Time skew handling through `faketime`
- LDAP and GC service-ticket prefetch for GSSAPI tools
- ccache validation before use — expired caches are cleared

**Important behaviour:**
- A ccache is only used if it exists and is valid
- Expired or missing ccaches are cleared from session
- Password or NT hash authentication is preferred when appropriate
- Kerberos is used when NTLM is blocked or a Kerberos-only path is required

---

## 7. All 59 Agent Tools

### Reconnaissance & Discovery

| Tool | Description |
|---|---|
| `nmap_scan` | Port scan, OS, domain detection, clock skew |
| `kerbrute_enum` | Username enumeration over Kerberos (no creds required) |
| `no_cred_surface_recon` | LDAP rootDSE, SMB null/guest, HTTP/ADCS/WSUS surface |
| `rediscover_target` | Re-run LDAP/NXC/nmap discovery mid-engagement |

### Enumeration

| Tool | Description |
|---|---|
| `enumerate_ldap` | Users, groups, computers, GPOs, trusts, SPNs, LAPS, delegation |
| `enumerate_shares` | SMB share access, SYSVOL, GPP password files |
| `collect_bloodhound` | BloodHound data collection (Kerberos + password + fallbacks) |
| `query_bloodhound_paths` | Neo4j/BloodHound shortest path queries |
| `user_hunt` | Session hunting, PSRemoting checks |

### Credential Attacks

| Tool | Description |
|---|---|
| `asrep_roast` | AS-REP roastable account discovery and hash collection |
| `kerberoast` | SPN account roasting |
| `targeted_kerberoast` | Targeted SPN abuse against writable account |
| `password_spray` | Credential spraying with jitter |
| `timeroast` | MS-SNTP NTP authentication hash extraction (no creds) |
| `pre2k_attack` | Pre-Windows 2000 default password abuse |

### Privilege Escalation

| Tool | Description |
|---|---|
| `adcs_scan` | ADCS ESC1–ESC13 enumeration and auto-exploitation via Certipy |
| `shadow_credentials_attack` | `msDS-KeyCredentialLink` injection via GenericWrite |
| `acl_abuse_scan` | GenericWrite/GenericAll/WriteDACL/ForceChangePassword + gMSA edge discovery |
| `force_change_password_pivot` | Reset target user via ForceChangePassword ACE |
| `rbcd_attack` | Resource-Based Constrained Delegation full chain |
| `unconstrained_delegation` | Unconstrained delegation abuse and TGT capture |
| `local_privesc_chain` | Potato privileges, AlwaysInstallElevated, unquoted service paths, writable binaries |
| `jea_enum` | JEA endpoint checks, PSReadLine history |
| `windows_privesc_recon` | Post-WinRM local escalation reconnaissance |

### Lateral Movement

| Tool | Description |
|---|---|
| `evil_winrm` | WinRM shell via password / NT hash / Kerberos |
| `discover_winrm_access` | Find hosts that accept WinRM for a credential |
| `lateral_movement` | WMI / WinRM / PSExec-style command execution |
| `mssql_abuse` | xp_cmdshell, linked server RCE, PowerUpSQL |
| `logon_script_abuse` | Abuse writable `scriptPath` on user objects |

### Credential Access

| Tool | Description |
|---|---|
| `dcsync_attack` | Full domain hash dump via replication |
| `credential_dump` | Remote LSASS / SAM / NTDS extraction |
| `credential_loot` | Post-exploitation credential hunting on owned host |
| `laps_read` | LAPS local admin password read via LDAP |
| `shadow_copies_dump` | VSS-based NTDS.dit and SAM hive extraction |
| `auto_loot_chain` | Download readable shares → parse creds → test → pivot |

### gMSA Attacks

| Tool | Description |
|---|---|
| `gmsa_read` | Read gMSA managed password (NXC / bloodyAD / gMSADumper / Kerberos) |
| `gmsa_takeover` | Modify `msDS-GroupMSAMembership` → dump hash → PTH |
| `bloodyad` | Generic bloodyAD LDAP object operations |

### Certificate and Kerberos

| Tool | Description |
|---|---|
| `pass_the_cert` | Pass-the-Certificate: PKINIT → NT hash |
| `golden_ticket` | Forge TGT using krbtgt hash |
| `silver_ticket` | Forge TGS using service account hash |
| `request_tgt` | Obtain Kerberos TGT (handles NTLM-disabled environments) |

### Persistence and Coercion

| Tool | Description |
|---|---|
| `coercion_attack` | PrinterBug / PetitPotam / Coercer forced authentication |
| `gpo_abuse` | GPO create / link / exec / hijack / logon script |
| `adidns_abuse` | DNS wildcard injection, WPAD, record add/remove |
| `rodc_attack` | RODC PRP cached creds, Key List attack, RODC Golden Ticket |

### Cloud / Hybrid / ADFS

| Tool | Description |
|---|---|
| `adfs_attack` | ADFS DKM enumeration, token signing cert, Golden SAML, MSOL/PHS DCSync |
| `sccm_abuse` | NAA credential extraction, client push relay, AdminService |
| `wsus_attack` | WSUS HTTP vuln check, pywsus injection guide, SharpWSUS |

### Trust / Multi-Domain

| Tool | Description |
|---|---|
| `trust_attack` | Trust key extraction, SID history, cross-domain enumeration |
| `trust_chain_planner` | Multi-domain/forest trust enum, ExtraSID attack plan, cross-forest Kerberoast |

### OPSEC and Post-Ex

| Tool | Description |
|---|---|
| `opsec_check` | EDR/AV, Sysmon, MDI, LAPS, Defender detection + evasion guidance |
| `c2_stage` | Sliver / Havoc / MSF payload generation, delivery, verification |

### Utility

| Tool | Description |
|---|---|
| `test_credential` | Test password/hash across SMB, LDAP, WinRM |
| `update_session` | Persist newly discovered credentials and intel |
| `chain_planner` | Rank attack chains from collected intel and graph data |
| `generate_report` | Produce HTML / Markdown / JSON reports |
| `run_module` | Run arbitrary tool reference |
| `agent_complete` | End mission with status summary |

---

## 8. SAST Knowledge Base — 139 Techniques

AdAgent loads a YAML-based knowledge base from `ActiveDirectory-SAST/` at startup. Every technique title, description, commands, and detection notes are injected into the AI system prompt, teaching the model exactly what to run and in what order.

| Category | Techniques |
|---|---|
| ACL Abuse | 7 |
| ADFS Attacks | 5 |
| Azure / Entra ID | 6 |
| Certificate Abuse (ADCS) | 8 |
| Coercion Attacks | 9 |
| Credential Dumping | 8 |
| DCSync / DCShadow | 4 |
| EDR Evasion | 8 |
| gMSA Attacks | 4 |
| GPO Abuse | 6 |
| Kerberos Attacks | 8 |
| Lateral Movement | 8 |
| Password Attacks | 5 |
| Persistence | 9 |
| Pre-2K / Timeroasting | 3 |
| RBCD Attacks | 6 |
| RODC Attacks | 4 |
| SCCM / MECM Attacks | 4 |
| Shadow Copies | 3 |
| Tool SAST Analysis (OPSEC signatures) | 14 |
| Trust Attacks | 7 |
| WSUS Attacks | 3 |
| **Total** | **139** |

`tool_sast_analysis.yml` is loaded separately into `OPSEC_SIGNATURES` and used to suppress noisy tools in `stealth` and `normal` OPSEC modes.

### Decision Rules (injected into system prompt)

```
If WriteDACL/GenericAll on domain → grant DCSync rights first
If SMB signing disabled → NTLM relay (Responder + ntlmrelayx)
If ADCS found → certipy find -vulnerable, exploit highest ESC
If unconstrained delegation host → coerce DC to capture TGT
If gMSA writable → Shadow Credentials chain
If SPN exists → kerberoast, crack with hashcat -m 13100
If Protected Users (STATUS_ACCOUNT_RESTRICTION) → Kerberos + faketime
If GPO write access → code execution via SharpGPOAbuse
If trust relationship → enumerate for ExtraSID/SID History
If ADFS found → adfs_attack for Golden SAML / PHS DCSync
If WSUS on HTTP → wsus_attack for SYSTEM code exec
If shell access → opsec_check → local_privesc_chain first
OPSEC: noisy tools suppressed until confirmed path
```

---

## 9. Tool Argument Sanitisation

The agent never fully trusts model-supplied arguments. `_sanitize_tool_inputs()` normalises arguments before execution:

- Replaces placeholder values with session values
- Forces authoritative `dc_ip` and `domain`
- Injects real password/hash from session
- Prevents self-targeting
- Converts UPN-style usernames to bare names where needed
- Replaces invalid target names with evidence-backed targets from `agent_intel`
- If a selected account has a known NT hash in `loot` or `agent_intel`, uses that hash

**Critical rule:** a gMSA account (`some_gmsa$`) is always paired with its own NT hash, never the session user's password. The sanitiser enforces this automatically.

---

## 10. Decision Engine — `_pick_next_tool()`

When the AI model does not call a tool, repeats a blocked path, or loops, `_pick_next_tool()` selects the next useful action using a deterministic priority ladder:

| Priority | Action |
|---|---|
| -1 | krbtgt hash available → `golden_ticket` |
| -1b | PFX available, no NT hash yet → `pass_the_cert` |
| 0a | Fresh gMSA hash → `evil_winrm` immediately |
| **0** | **Shell exists → `opsec_check` → `local_privesc_chain` → post-ex chain** |
| 1 | NT hash in loot → `discover_winrm_access` / `evil_winrm` |
| 2 | NTLM disabled → `request_tgt` |
| 3 | `nmap_scan` (always first) |
| 3.5 | No creds → null session → kerbrute → AS-REP → timeroast → pre2k → coercion |
| 4 | `enumerate_ldap` → `enumerate_shares` |
| 4.5 | Loot-shaped shares → `auto_loot_chain` |
| 4.6 | SPNs/AS-REP known → `kerberoast` / `asrep_roast` |
| 4.7 | NTLM on + creds → WinRM attempt |
| 5 | `adcs_scan` + ESC exploitation |
| 6 | ACL / gMSA edge exploitation |
| 7 | Kerberoast / AS-REP roast |
| 8 | `evil_winrm` with current creds |
| 9 | BloodHound collect + query |
| 11 | `auto_loot_chain` |
| 13a | `trust_chain_planner` (multi-domain) |
| 13b | `trust_attack` enumerate |
| 13b-ext | `adfs_attack` when ADFS intel found |
| 13b-ext2 | `wsus_attack` when WSUS intel found |
| 13c | Unconstrained delegation → RBCD |
| 14 | MSSQL abuse |
| Last | `generate_report` → `agent_complete` |

---

## 11. Loop Guards and Dead-Path Handling

The agent has multiple safeguards against repeated failures:

- **Recent call signature tracking** — same tool + same args in last 3 rounds is blocked
- **Tool failure counters** — a tool exceeding max failures is excluded
- **Per-principal WinRM dead-path** — `winrm_dead_for` set
- **Per-principal gMSA read dead-path** — `gmsa_read_dead_for` set
- **Per-principal ACL scan dead-path** — `acl_scan_dead_for` set
- **Network unreachable detection** — stops pointless probing
- **Completion guard** — blocks premature `agent_complete` when progress is still possible
- **Auto-repair** — handles Protected Users, NTLM-disabled auth, Kerberos time skew

New credentials always get a fresh chance. Dead-paths are per-principal, not global.

---

## 12. gMSA Workflows

### Direct Read

Use `gmsa_read` when the current principal has `ReadGMSAPassword` or is in the allowed readers list.

Attempts in order:
1. NetExec `ldap --gmsa`
2. bloodyAD raw search for `msDS-ManagedPassword`
3. `gMSADumper.py`
4. Kerberos retry when NTLM bind is denied

Only creates a Critical finding when a valid `account$ → NT hash` is extracted.

### Takeover via ACL

Use `gmsa_takeover` when the current principal has write rights on the gMSA object (GenericWrite, GenericAll, WriteDACL, WriteOwner, WriteProperty).

Flow:
1. Pick a reader identity
2. Resolve reader SID
3. Write `msDS-GroupMSAMembership`
4. Dump `msDS-ManagedPassword`
5. Convert blob to NT hash
6. Store hash in loot and owned users
7. Try shell or credential testing with the gMSA hash

---

## 13. ADCS Workflow

`adcs_scan` uses Certipy-oriented workflows to:
- Detect Enterprise CAs
- Enumerate templates
- Identify ESC1–ESC13 vulnerabilities
- Attempt exploitation where automation is safe
- Store hashes, ccaches, PFX files, or shell-ready state

If ADCS exploitation yields shell-ready material, the agent automatically attempts WinRM with the new credential material, not the old credential.

---

## 14. BloodHound Workflow

`collect_bloodhound` supports fallback behaviour:
- Kerberos collection with generated krb5 config
- Password/NTLM collection
- IPv4-forced wrapper to avoid bad DNS/AAAA resolution
- DCOnly fallback for unstable DNS
- NetExec BloodHound fallback
- Inline ACL/gMSA fallback if BloodHound collectors fail

`query_bloodhound_paths` runs after data exists in Neo4j.

---

## 15. ADFS and Cloud Attack Paths

### ADFS (Golden SAML)

`adfs_attack` covers:
1. ADFS SCP discovery via LDAP
2. DKM container read (token signing cert)
3. ADFS metadata enumeration
4. Azure AD Connect MSOL account detection
5. PTA spy check

If DKM is readable, a Critical finding is raised and extraction commands are provided.

### WSUS

`wsus_attack` covers:
1. WSUS server discovery via NXC module
2. Registry-based discovery via WinRM
3. HTTP vs HTTPS check
4. pywsus injection guide if HTTP found

### Trust Chains (Multi-Domain)

`trust_chain_planner` covers:
1. Trust enumeration via LDAP and nltest
2. Cross-domain delegation discovery
3. Cross-forest Kerberoast
4. ExtraSID attack plan generation

---

## 16. OPSEC Mode

| Mode | Behaviour |
|---|---|
| `loud` | Fast, no jitter, all tools — use in labs and CTF |
| `normal` | Moderate jitter, avoids obviously noisy tools (default) |
| `stealth` | Aggressive OPSEC, native tools first, maximum jitter |

In `stealth` and `normal` modes, `OPSEC_SIGNATURES` from `tool_sast_analysis.yml` suppresses high-noise tools until a confirmed path exists.

Set via environment: `ADSTRIKE_OPSEC=stealth`

---

## 17. Agent Output Cleanup

Each new full-auto run starts with a clean runtime state:

- `output/agent_runtime/*` is removed before the new run
- `output/agent_logs/agent_*.md` and `output/agent_logs/agent_*.json` are archived to `output/agent_logs/archive/<run_timestamp>/`
- `output/session.json` is never removed by agent cleanup
- Manual module output is left untouched

Environment switches:

| Variable | Default | Meaning |
|---|---|---|
| `AGENT_CLEAN_OUTPUT_ON_START` | `true` | Enables runtime cleanup on run start |
| `AGENT_ARCHIVE_OLD_RUNS` | `true` | Archives old logs (false = deletes) |

---

## 18. Output Structure

```
output/
├── session.json                    ← Persistent session state
├── agent_logs/
│   ├── agent_<timestamp>.md        ← Live Markdown round-by-round report
│   ├── agent_<timestamp>.json      ← JSON conversation/session snapshot
│   └── archive/                    ← Previous runs archived on new run start
├── agent_runtime/
│   ├── *.ccache                    ← Kerberos ticket caches
│   └── krb5_*.conf                 ← Target-specific Kerberos configs
└── reports/
    ├── adagent_report_*.html       ← Full HTML pentest report
    ├── adagent_report_*.md         ← Markdown report
    ├── adagent_report_*.json       ← JSON findings export
    └── adagent_report_*_navigator.json ← ATT&CK Navigator layer
```

### Markdown Log Content (per round)

- Round number and tool name
- Model-supplied arguments
- Final sanitised tool input
- Tool output (truncated at 2000 chars)
- Mission summary at completion

---

## 19. Running AdAgent

### Quick Start

```bash
git clone https://github.com/capture0x/AdAgent.git
cd AdAgent
chmod +x install.sh run.sh
./install.sh
cp .env.example .env
# Edit .env: DC_IP, DOMAIN, USERNAME, PASSWORD
./run.sh
```

### CLI Flags

```bash
./run.sh                        # interactive menu
./run.sh --agent                # launch agent directly
./run.sh --session path/to.json # load saved session
./run.sh --no-banner            # suppress ASCII banner
```

### Menu Options

```
[1]  Session Manager   — configure target, credentials, workspace
[2]  AdAgent (AI)      — autonomous attack orchestrator (59 tools)
[3]  Generate Report   — HTML · Markdown · JSON pentest report
[0]  Exit
```

---

## 20. Running the Agent

From the menu, choose **AdAgent (AI)**.

### Backend Choices

| Backend | When to Use |
|---|---|
| Ollama | Local, free, offline — recommended for labs |
| Claude | Highest quality reasoning — requires API key |

### Required Session Fields

- `dc_ip`
- `domain`
- `username` (optional in null-session mode)
- `password` or `nt_hash` (or Kerberos ccache)

### Recommended Starting Point

1. Confirm VPN and DNS reachability
2. Configure session with `[1] Session Manager`
3. Start agent with `[2] AdAgent (AI)` → Ollama → Full Auto
4. Watch rounds for repeated auth failures or environment issues
5. Review `output/agent_logs/*.md`
6. Generate final report with `[3] Generate Report`

---

## 21. Common Agent Paths

### Standard Credential Path

```
nmap_scan
enumerate_ldap
enumerate_shares
auto_loot_chain
acl_abuse_scan
adcs_scan
collect_bloodhound
query_bloodhound_paths
exploit concrete ACL/ADCS path
dcsync_attack
generate_report
```

### gMSA Direct Read

```
enumerate_ldap         → discover gMSA candidates
gmsa_read              → extract account$ NT hash
evil_winrm             → get shell with gMSA hash
windows_privesc_recon
credential_dump
dcsync_attack
```

### gMSA Takeover via ACL

```
acl_abuse_scan         → discover GenericWrite on gMSA
gmsa_takeover          → write msDS-GroupMSAMembership → dump hash
evil_winrm             → use gMSA NT hash
post-exploitation chain
```

### ADCS ESC Path

```
adcs_scan              → detect ESC1/ESC4/ESC8/etc.
pass_the_cert          → PFX → PKINIT → NT hash
evil_winrm / dcsync
generate_report
```

### No-Credential Path

```
nmap_scan
enumerate_ldap         → anonymous LDAP
no_cred_surface_recon  → ADCS/WSUS/SMB exposure
kerbrute_enum          → valid users
asrep_roast            → no-preauth hashes
timeroast / pre2k_attack
coercion_attack        → capture Net-NTLMv2
→ pivot to credential path
```

### Multi-Domain Trust Path

```
enumerate_ldap         → discover trust relationships
trust_chain_planner    → ExtraSID attack plan
trust_attack           → cross-forest Kerberoast
→ ExtraSID ticket forgery
```

---

## 22. Session Fields Reference

| Field | `.env` Key | Description |
|---|---|---|
| `dc_ip` | `DC_IP` | Domain Controller IP |
| `dc_fqdn` | `DC_FQDN` | Domain Controller FQDN |
| `domain` | `DOMAIN` | AD DNS domain |
| `username` | `USERNAME` | Primary username |
| `password` | `PASSWORD` | Password (mutually exclusive with nt_hash) |
| `nt_hash` | `NT_HASH` | NTLM hash for Pass-the-Hash |
| `use_kerberos` | `USE_KERBEROS` | Enable Kerberos mode |
| `krb5_ccache` | `KRB5_CCACHE` | Path to ccache file |
| `attacker_ip` | `ATTACKER_IP` | Listener / attacker IP |
| `attacker_iface` | `ATTACKER_IFACE` | Network interface (e.g. `tun0`) |
| `engagement` | `ENGAGEMENT_NAME` | Engagement name for reports |

---

## 23. Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Enable Claude backend |
| `ADSTRIKE_OPSEC` | `normal` | OPSEC mode: `loud` / `normal` / `stealth` |
| `ADSTRIKE_AGENT_LIVE_COMMANDS` | `true` | Actually execute commands |
| `AGENT_CLEAN_OUTPUT_ON_START` | `true` | Wipe `agent_runtime/` before each run |
| `AGENT_ARCHIVE_OLD_RUNS` | `true` | Archive previous agent logs |
| `ADSTRIKE_SHOW_SECRETS` | `false` | Show real credentials in reports |
| `ADAGENT_PORT_CHECK` | — | Set `1` to run nmap during session setup |
| `ADSTRIKE_OLLAMA_TIMEOUT` | `20` | Ollama API timeout (seconds) |
| `ADSTRIKE_OLLAMA_MAX_TOOLS` | `1` | Max tool calls per Ollama round |

---

## 24. Troubleshooting

### `invalidCredentials` with Known Good Password

Possible causes:
- NTLM blocked on DC
- Protected Users group membership
- Kerberos-only principal
- Clock skew
- Wrong DC hostname/IP mapping
- Stale ccache

Expected agent behaviour:
- Request TGT
- Generate target krb5 config
- Retry Kerberos-aware tools
- If still failing, mark path dead for that principal

### `KRB_AP_ERR_SKEW`

Cause: local time differs from DC time.

Fix:
```bash
sudo ntpdate <dc_ip>
# or: sudo rdate -n <dc_ip>
```

The agent auto-detects clock skew from nmap output and warns. Use `faketime` where ntpdate is not available.

### `from ccache 576`

Cause: invalid, expired, or wrong-principal ccache.

Fix:
- Validate ccache: `klist -c <path>`
- Clear stale state from session
- Request a fresh TGT via `request_tgt` tool

### bloodyAD Traceback

Cause: bloodyAD bind or client failure.

Expected behaviour:
- Compact failure output
- Continue with LDAP, dacledit, BloodHound, or other fallback
- Do not treat traceback as proof of exploitability

### gMSA Critical Finding Without Hash

Should not happen. A gMSA Critical finding requires:
- Account name ending in `$`
- Valid 32-character NT hash
- Evidence from NXC, bloodyAD blob decode, gMSADumper, or takeover helper

### Agent Loops

Common patterns and their guards:

| Loop Pattern | Guard |
|---|---|
| Repeating `evil_winrm` same user | `winrm_dead_for` |
| Repeating `acl_abuse_scan` after empty | `acl_scan_dead_for` |
| Repeating `gmsa_read` after bind fail | `gmsa_read_dead_for` |
| Repeating same tool/args | recent signature anti-loop |
| Premature `agent_complete` | completion guard |

### Enter Key Not Returning to Menu After Agent

Cause: agent subprocess calls may leave `sys.stdin` in a broken state.

The agent always reads the pause prompt from `/dev/tty` directly, bypassing any stdin corruption. If this still fails, the agent falls back to a 2-second delay. Use `./run.sh` (not piped invocation) for best results.

---

## 25. Prerequisites

### System Tools

```bash
sudo apt install -y impacket-scripts nxc evil-winrm bloodhound-python \
  certipy-ad ldap-utils krb5-user nmap responder coercer seclists
```

### Python Packages

```bash
pip install -r requirements.txt
```

### Optional Extensions

```bash
pip install bloodyad           # ACL / gMSA object operations
pip install lsassy             # Remote LSASS credential dumping
pip install dploot             # DPAPI and credential vault
pip install roadtx roadrecon   # Azure AD / Entra ID attacks
pip install sccmhunter         # SCCM / MECM attacks
pip install pywsus             # WSUS fake-update injection
```

### C2 Frameworks (Optional)

| Framework | Install |
|---|---|
| Sliver | https://github.com/BishopFox/sliver |
| Havoc | https://github.com/HavocFramework/Havoc |
| Metasploit | `sudo apt install metasploit-framework` |

---

## 26. Development Guidelines

When adding new tools or modifying the agent:

- Do not hard-code lab names, domains, users, hashes, or hostnames
- Store new evidence in `SESSION` or `agent_intel`
- Add findings only after concrete evidence exists
- Include remediation text for all reportable findings
- Mark dead paths per principal, not globally
- Prefer structured parsing over brittle string checks
- Keep fallback output concise and actionable
- Never pair a selected account with the wrong credential material
- Respect Kerberos vs NTLM mode throughout
- Preserve existing changes when editing — avoid unrelated refactors

### Adding a New Agent Tool

1. Implement `tool_<name>()` in `_core.py`
2. Add schema to `TOOLS` list
3. Add function to `TOOL_MAP`
4. Update `_analyze_result()` if output creates new intel
5. Update `_pick_next_tool()` if it affects decision priority
6. Add dead-path tracking if tool can fail repeatedly for the same principal
7. Add report findings only when evidence is concrete

Minimal tool pattern:

```python
def tool_example(dc_ip: str, domain: str, username: str,
                 password: str = "", nt_hash: str = "") -> str:
    password = _real_secret(password)
    nt_hash  = _real_nt_hash(nt_hash)
    auth     = _auth_args_nxc(username, password, nt_hash, domain, dc_ip)
    out      = _nxc(f"ldap {shell_quote(dc_ip)} {auth} --example", timeout=30)
    return out
```

### Adding a New SAST Category

Create `ActiveDirectory-SAST/<category>.yml` following the existing YAML structure:

```yaml
title: AdAgent - <Category> Detection Rules
id: sast-<category>-001
rules:
  - id: <category>-<technique>-001
    title: <Human readable title>
    technique: T<MITRE_ID>
    severity: critical|high|medium|low
    description: >
      <One paragraph description of the technique and its impact.>
    tools_used:
      - "<command with {placeholders}>"
    remediation:
      - "<Remediation step>"
```

The loader picks up new files automatically on next run.

---

## 27. Quality Checklist

Before committing changes:

- `python3 -m py_compile modules/agent/_core.py` passes
- No target-specific strings remain in generic logic
- Findings are evidence-gated — no speculative raising
- Redaction still works — test with `ADSTRIKE_SHOW_SECRETS=false`
- Agent does not loop on repeated failures
- Kerberos ccache is validated before use
- Password/hash injection matches the selected principal
- Reports are readable and do not include full tracebacks

---

## 28. Operator Checklist

### Before Running

- Confirm target scope and written permission
- Confirm VPN route and DNS resolution
- Set target domain and DC IP
- Set valid credential or hash
- Decide: password / hash / Kerberos
- Check `faketime`, Impacket, NetExec, Certipy, Kerberos tools are installed
- Ensure output directories are writable by current user (not owned by root)

### During the Run

- Watch for repeated tool pairs (indicates guard is needed)
- Watch for stale ccache messages
- Confirm findings have real evidence before reporting
- Stop the run if a destructive path is not authorised

### After the Run

- Review `output/agent_logs/*.md`
- Review `output/session.json`
- Generate final report with `[3] Generate Report`
- Remove temporary ccaches if required by engagement policy

---

## 29. Known Limitations

- Tool behaviour depends on installed versions of NetExec, Certipy, bloodyAD, Impacket, ldap3, and system Python packages
- Some AD labs intentionally block NTLM or require exact FQDN/KDC mapping
- BloodHound collection may fail due to DNS, IPv6, LDAP signing, or collector version mismatch
- AI backends can propose poor actions; guards reduce but do not eliminate this
- Redaction hides values in reports; operators may need secure raw logs for internal validation
- Some techniques are guided playbooks rather than fully automated exploits

---

## 30. Security and OPSEC Notes

- Password spraying can lock accounts — verify lockout policy first
- Coercion and relay attacks generate significant network noise
- ADCS exploitation may create certificate artifacts on the CA
- GPO and logon script abuse can impact many users simultaneously
- WSUS attacks affect patch infrastructure for all managed systems
- DCSync and DCShadow are high-impact — use only with explicit scope approval
- Always prefer read-only enumeration until a path is confirmed and authorised
- ADFS Golden SAML attacks persist until the token signing certificate is rotated

---

## 31. Summary

AdAgent is a focused AI orchestration layer for Active Directory attack automation. Its core strength is the shared session model: credentials, Kerberos tickets, findings, loot, and owned assets flow between all 59 tools automatically. The SAST knowledge base teaches the AI model 139 real attack techniques. The decision engine falls back to deterministic priority selection when the model loops.

For reliable use across different environments:

- Avoid hard-coded target assumptions in all code
- Treat every finding as evidence-gated
- Track dead paths per principal
- Use correct credential material for the selected identity
- Validate Kerberos before using a ccache
- Keep fallback behaviour concise and actionable

---

*Generated by AdAgent v1.0 — creator: tmrswrr — Authorised penetration testing only*
