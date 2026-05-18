"""
modules/mitre_data.py
MITRE ATT&CK technique registry and CVSS v3.1 defaults for Active Directory attacks.
"""
from __future__ import annotations

# Tactic ID → display label
TACTICS: dict[str, str] = {
    "reconnaissance":       "Reconnaissance",
    "initial-access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion":      "Defense Evasion",
    "credential-access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral Movement",
    "collection":           "Collection",
    "command-and-control":  "Command & Control",
    "impact":               "Impact",
}

TACTIC_COLORS: dict[str, str] = {
    "reconnaissance":       "#4a90d9",
    "initial-access":       "#e74c3c",
    "execution":            "#e67e22",
    "persistence":          "#9b59b6",
    "privilege-escalation": "#c0392b",
    "defense-evasion":      "#27ae60",
    "credential-access":    "#f39c12",
    "discovery":            "#2980b9",
    "lateral-movement":     "#16a085",
    "collection":           "#8e44ad",
    "command-and-control":  "#d35400",
    "impact":               "#c0392b",
}

# Technique registry: ID → {name, tactic, description}
TECHNIQUES: dict[str, dict] = {
    # Reconnaissance
    "T1590":     {"name": "Gather Victim Network Info",                "tactic": "reconnaissance",       "description": "Gather information about the target network infrastructure, topology, and IP ranges."},
    "T1592":     {"name": "Gather Victim Host Information",            "tactic": "reconnaissance",       "description": "Gather details about the victim's hosts including OS, hardware, and software."},
    "T1595.002": {"name": "Vulnerability Scanning",                    "tactic": "reconnaissance",       "description": "Scan for vulnerabilities and open services in the target environment."},
    "T1596":     {"name": "Search Open Technical Databases",           "tactic": "reconnaissance",       "description": "DNS queries, certificate transparency logs, WHOIS lookups."},
    "T1598":     {"name": "Phishing for Information",                  "tactic": "reconnaissance",       "description": "Email harvesting and external OSINT collection."},
    # Initial Access
    "T1078.002": {"name": "Valid Accounts: Domain Accounts",           "tactic": "initial-access",       "description": "Use compromised domain credentials to gain initial foothold."},
    "T1078.004": {"name": "Valid Accounts: Cloud Accounts",            "tactic": "initial-access",       "description": "Use compromised Azure AD / Entra ID accounts for cloud access."},
    "T1133":     {"name": "External Remote Services",                  "tactic": "initial-access",       "description": "Abuse externally accessible services such as RDP, WinRM, or VPN."},
    "T1187":     {"name": "Forced Authentication",                     "tactic": "initial-access",       "description": "LLMNR/NBT-NS/mDNS poisoning and NTLM hash capture via coercion."},
    # Execution
    "T1047":     {"name": "Windows Management Instrumentation",        "tactic": "execution",            "description": "Execute code on remote hosts via WMI."},
    "T1053.005": {"name": "Scheduled Task/Job",                        "tactic": "execution",            "description": "Create or modify scheduled tasks for code execution."},
    "T1059.001": {"name": "Command and Scripting: PowerShell",         "tactic": "execution",            "description": "Execute malicious PowerShell commands or scripts."},
    "T1072":     {"name": "Software Deployment Tools",                 "tactic": "execution",            "description": "Abuse WSUS or SCCM/MECM for domain-wide code execution."},
    # Persistence
    "T1098":     {"name": "Account Manipulation",                      "tactic": "persistence",          "description": "Modify accounts or permissions to maintain access."},
    "T1136.002": {"name": "Create Account: Domain Account",            "tactic": "persistence",          "description": "Create a new domain account to maintain persistent access."},
    "T1207":     {"name": "Rogue Domain Controller (DCShadow)",        "tactic": "defense-evasion",      "description": "Register a rogue DC to push malicious changes via AD replication."},
    "T1484.001": {"name": "Domain Policy Modification: GPO",           "tactic": "persistence",          "description": "Modify Group Policy Objects to maintain persistence or execute code."},
    "T1505.001": {"name": "Server Software Component: SQL",            "tactic": "persistence",          "description": "Abuse MSSQL stored procedures (xp_cmdshell) for persistence."},
    "T1543":     {"name": "Create or Modify System Process",           "tactic": "persistence",          "description": "Modify system services for persistence (DNSAdmins DLL injection, Skeleton Key)."},
    "T1547":     {"name": "Boot/Logon Autostart Execution",            "tactic": "persistence",          "description": "Configure registry run keys or startup items for persistent execution."},
    # Privilege Escalation
    "T1068":     {"name": "Exploitation for Privilege Escalation",     "tactic": "privilege-escalation", "description": "Exploit a vulnerability (NoPac, Zerologon, PrintNightmare) to elevate privileges."},
    "T1134.001": {"name": "Access Token Manipulation: Impersonation",  "tactic": "privilege-escalation", "description": "Steal or impersonate access tokens (Potato attacks, RBCD, constrained delegation)."},
    "T1134.002": {"name": "Access Token Manipulation: Create Process", "tactic": "privilege-escalation", "description": "Create new processes using a stolen or forged access token."},
    "T1484.002": {"name": "Domain Trust Modification",                 "tactic": "privilege-escalation", "description": "Modify domain trust relationships for cross-domain privilege escalation."},
    "T1548.002": {"name": "Abuse Elevation Control: Bypass UAC",       "tactic": "privilege-escalation", "description": "Bypass UAC via fodhelper, eventvwr, CMSTP, or token impersonation."},
    # Defense Evasion
    "T1027":     {"name": "Obfuscated Files or Information",           "tactic": "defense-evasion",      "description": "Obfuscate payloads and scripts to evade detection."},
    "T1222":     {"name": "File and Directory Permissions Modification","tactic": "defense-evasion",      "description": "Modify DACL/ACE entries to escalate privileges or maintain access."},
    "T1562.001": {"name": "Impair Defenses: Disable Security Tools",   "tactic": "defense-evasion",      "description": "Disable or bypass AMSI, EDR, AV, or AppLocker."},
    # Credential Access
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory",       "tactic": "credential-access",    "description": "Dump LSASS process memory to extract plaintext credentials and NTLM hashes."},
    "T1003.002": {"name": "OS Credential Dumping: SAM",                "tactic": "credential-access",    "description": "Extract credentials from the Security Account Manager hive."},
    "T1003.003": {"name": "OS Credential Dumping: NTDS",               "tactic": "credential-access",    "description": "Dump the NTDS.dit Active Directory database for all domain hashes."},
    "T1003.006": {"name": "OS Credential Dumping: DCSync",             "tactic": "credential-access",    "description": "Replicate domain password data using DCSync (mimics DC replication)."},
    "T1110.001": {"name": "Brute Force: Password Guessing",            "tactic": "credential-access",    "description": "Attempt to guess passwords through repeated login attempts."},
    "T1110.002": {"name": "Brute Force: Password Cracking",            "tactic": "credential-access",    "description": "Crack captured password hashes offline with hashcat/john."},
    "T1110.003": {"name": "Brute Force: Password Spraying",            "tactic": "credential-access",    "description": "Try one or few passwords against many accounts to avoid lockout."},
    "T1552":     {"name": "Unsecured Credentials",                     "tactic": "credential-access",    "description": "Find credentials stored in GPP, scripts, SYSVOL, or configuration files."},
    "T1555":     {"name": "Credentials from Password Stores",          "tactic": "credential-access",    "description": "Extract credentials from DPAPI, browser stores, KeePass, or gMSA."},
    "T1557.001": {"name": "Adversary-in-the-Middle: LLMNR/NBT-NS",    "tactic": "credential-access",    "description": "Poison LLMNR/NBT-NS/mDNS to capture NTLMv2 hashes."},
    "T1558.001": {"name": "Steal/Forge Kerberos Tickets: Golden",      "tactic": "credential-access",    "description": "Forge a Kerberos TGT using the krbtgt hash for persistent domain access."},
    "T1558.002": {"name": "Steal/Forge Kerberos Tickets: Silver",      "tactic": "credential-access",    "description": "Forge a Kerberos TGS for a specific service using its account hash."},
    "T1558.003": {"name": "Steal/Forge Kerberos Tickets: Kerberoasting","tactic": "credential-access",  "description": "Request TGS tickets for SPNs and crack service account passwords offline."},
    "T1558.004": {"name": "Steal/Forge Kerberos Tickets: AS-REP Roast","tactic": "credential-access",   "description": "Request AS-REP hashes for accounts without pre-auth required and crack offline."},
    "T1558":     {"name": "Steal/Forge Kerberos Tickets",              "tactic": "credential-access",    "description": "Steal or forge Kerberos authentication tickets (Shadow Credentials, PKINIT)."},
    "T1606.002": {"name": "Forge Web Credentials: SAML Tokens",        "tactic": "credential-access",    "description": "Forge SAML tokens for unauthorized cloud/federated access (Golden SAML)."},
    "T1528":     {"name": "Steal Application Access Token",            "tactic": "credential-access",    "description": "Steal OAuth tokens, PRT, or device tokens for cloud service access."},
    "T1649":     {"name": "Steal or Forge Authentication Certificates", "tactic": "credential-access",   "description": "Abuse ADCS (ESC1-ESC16) to steal or forge client authentication certificates."},
    # Discovery
    "T1018":     {"name": "Remote System Discovery",                   "tactic": "discovery",            "description": "Enumerate remote systems and domain-joined computers."},
    "T1046":     {"name": "Network Service Scanning",                  "tactic": "discovery",            "description": "Scan for open network services and ports with nmap/masscan."},
    "T1049":     {"name": "System Network Connections Discovery",      "tactic": "discovery",            "description": "Enumerate active network connections and listening services."},
    "T1069.002": {"name": "Permission Groups Discovery: Domain Groups","tactic": "discovery",            "description": "Enumerate domain groups, memberships, and privileged group members."},
    "T1082":     {"name": "System Information Discovery",              "tactic": "discovery",            "description": "Gather OS version, architecture, and system configuration details."},
    "T1083":     {"name": "File and Directory Discovery",              "tactic": "discovery",            "description": "Enumerate files, shares, and directories (Snaffler, SYSVOL)."},
    "T1087.002": {"name": "Account Discovery: Domain Account",         "tactic": "discovery",            "description": "Enumerate domain user accounts, SPNs, and account attributes."},
    "T1482":     {"name": "Domain Trust Discovery",                    "tactic": "discovery",            "description": "Enumerate domain and forest trust relationships."},
    # Lateral Movement
    "T1021.002": {"name": "Remote Services: SMB/Admin Shares",         "tactic": "lateral-movement",     "description": "Use SMB/admin shares and PsExec for lateral movement."},
    "T1021.006": {"name": "Remote Services: Windows Remote Management","tactic": "lateral-movement",     "description": "Use WinRM / Evil-WinRM for lateral movement."},
    "T1550.002": {"name": "Use Alternate Auth Material: Pass the Hash","tactic": "lateral-movement",     "description": "Authenticate using a captured NTLM hash without cracking it."},
    "T1550.003": {"name": "Use Alternate Auth Material: Pass the Ticket","tactic": "lateral-movement",  "description": "Authenticate using a stolen or forged Kerberos ticket."},
}

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 defaults per severity level
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_CVSS: dict[str, dict] = {
    "Critical": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"},
    "High":     {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "Medium":   {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"},
    "Low":      {"score": 3.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"},
    "Info":     {"score": 0.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
}

# ─────────────────────────────────────────────────────────────────────────────
# Keyword → [technique_ids]  (lowercase)
# ─────────────────────────────────────────────────────────────────────────────
KEYWORD_TECHNIQUES: dict[str, list[str]] = {
    "kerberoast":           ["T1558.003"],
    "asrep":                ["T1558.004"],
    "as-rep":               ["T1558.004"],
    "timeroast":            ["T1558.004"],
    "golden ticket":        ["T1558.001"],
    "diamond ticket":       ["T1558.001"],
    "sapphire ticket":      ["T1558.001"],
    "silver ticket":        ["T1558.002"],
    "dcsync":               ["T1003.006"],
    "dc sync":              ["T1003.006"],
    "dcshadow":             ["T1207"],
    "lsass":                ["T1003.001"],
    "nanodump":             ["T1003.001"],
    "sam dump":             ["T1003.002"],
    "ntds":                 ["T1003.003"],
    "shadow cop":           ["T1003.003"],
    "shadow copies":        ["T1003.003"],
    "dpapi":                ["T1555"],
    "keepass":              ["T1555"],
    "lazagne":              ["T1555"],
    "gmsa":                 ["T1555"],
    "password spray":       ["T1110.003"],
    "spraying":             ["T1110.003"],
    "kerbrute":             ["T1110.003"],
    "hashcat":              ["T1110.002"],
    "crack":                ["T1110.002"],
    "llmnr":                ["T1557.001"],
    "nbt-ns":               ["T1557.001"],
    "ntlm relay":           ["T1557.001", "T1550.002"],
    "responder":            ["T1557.001"],
    "mitm6":                ["T1557.001"],
    "dhcpv6":               ["T1557.001"],
    "golden saml":          ["T1606.002"],
    "adfs":                 ["T1606.002"],
    "adcs":                 ["T1649"],
    "esc1":                 ["T1649"],
    "esc2":                 ["T1649"],
    "esc3":                 ["T1649"],
    "esc4":                 ["T1649"],
    "esc6":                 ["T1649"],
    "esc8":                 ["T1649"],
    "esc13":                ["T1649"],
    "esc15":                ["T1649"],
    "esc16":                ["T1649"],
    "certificate":          ["T1649"],
    "certipy":              ["T1649"],
    "certsync":             ["T1649"],
    "pass the hash":        ["T1550.002"],
    "pass-the-hash":        ["T1550.002"],
    "pth":                  ["T1550.002"],
    "pass the ticket":      ["T1550.003"],
    "pass-the-ticket":      ["T1550.003"],
    "ptt":                  ["T1550.003"],
    "shadow credential":    ["T1558"],
    "pywhisker":            ["T1558"],
    "pkinit":               ["T1558", "T1649"],
    "enumerat":             ["T1087.002", "T1069.002"],
    "bloodhound":           ["T1087.002", "T1069.002", "T1482"],
    "soaphound":            ["T1087.002", "T1069.002", "T1482"],
    "rusthound":            ["T1087.002", "T1069.002", "T1482"],
    "powerview":            ["T1087.002", "T1069.002"],
    "trust":                ["T1482"],
    "snaffler":             ["T1083", "T1552"],
    "sysvol":               ["T1552"],
    "gpp":                  ["T1552"],
    "laps":                 ["T1552"],
    "nmap":                 ["T1046"],
    "masscan":              ["T1046"],
    "rustscan":             ["T1046"],
    "network scan":         ["T1046"],
    "psexec":               ["T1021.002"],
    "smbexec":              ["T1021.002"],
    "wmiexec":              ["T1047"],
    "evil-winrm":           ["T1021.006"],
    "winrm":                ["T1021.006"],
    "gpo":                  ["T1484.001"],
    "acl":                  ["T1222"],
    "ace":                  ["T1222"],
    "dacl":                 ["T1222"],
    "genericall":           ["T1222"],
    "writedacl":            ["T1222"],
    "rbcd":                 ["T1134.001"],
    "constrained deleg":    ["T1134.001"],
    "unconstrained deleg":  ["T1134.001"],
    "s4u":                  ["T1134.001"],
    "uac bypass":           ["T1548.002"],
    "fodhelper":            ["T1548.002"],
    "eventvwr":             ["T1548.002"],
    "cmstp":                ["T1548.002"],
    "amsi":                 ["T1562.001"],
    "edr":                  ["T1562.001"],
    "av bypass":            ["T1562.001"],
    "applocker":            ["T1562.001"],
    "skeleton key":         ["T1543"],
    "dnsadmin":             ["T1543"],
    "nppspy":               ["T1543"],
    "wsus":                 ["T1072"],
    "sccm":                 ["T1072"],
    "mecm":                 ["T1072"],
    "mssql":                ["T1505.001"],
    "xp_cmdshell":          ["T1505.001"],
    "rodc":                 ["T1558.001"],
    "azure":                ["T1078.004"],
    "entra":                ["T1078.004"],
    "aadconnect":           ["T1078.004"],
    "prt":                  ["T1528"],
    "device code":          ["T1528"],
    "zerologon":            ["T1068"],
    "nopac":                ["T1068"],
    "printnightmare":       ["T1068"],
    "local privesc":        ["T1068"],
    "potato":               ["T1134.001"],
    "krb relay":            ["T1134.001"],
    "krbrelayup":           ["T1134.001"],
    "coer":                 ["T1187"],
    "petitpotam":           ["T1187"],
    "printerbug":           ["T1187"],
    "dfscoerce":            ["T1187"],
    "pre2k":                ["T1078.002"],
    "recon":                ["T1590", "T1596"],
    "osint":                ["T1596", "T1598"],
    "whois":                ["T1596"],
    "dnsdump":              ["T1590"],
}

# CVSS scores for specific well-known AD findings
FINDING_CVSS: dict[str, dict] = {
    "zerologon":             {"score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
    "nopac":                 {"score": 9.9,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
    "dcsync":                {"score": 9.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"},
    "dcshadow":              {"score": 9.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"},
    "golden ticket":         {"score": 9.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"},
    "golden saml":           {"score": 9.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"},
    "ntds":                  {"score": 9.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"},
    "unconstrained deleg":   {"score": 9.9,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
    "adcs":                  {"score": 9.9,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
    "esc1":                  {"score": 9.9,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
    "printnightmare":        {"score": 8.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    "rbcd":                  {"score": 8.0,  "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N"},
    "acl abuse":             {"score": 8.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"},
    "gpo abuse":             {"score": 8.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"},
    "shadow credential":     {"score": 8.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"},
    "pass the hash":         {"score": 8.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    "ntlm relay":            {"score": 8.1,  "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "asrep":                 {"score": 7.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "as-rep":                {"score": 7.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "wsus":                  {"score": 8.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"},
    "sccm":                  {"score": 8.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"},
    "kerberoast":            {"score": 6.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
    "password spray":        {"score": 6.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"},
    "lsass":                 {"score": 6.8,  "vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N"},
    "dpapi":                 {"score": 5.5,  "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
    "gpp":                   {"score": 7.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "uac bypass":            {"score": 7.8,  "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
}


def suggest_techniques(finding_name: str, description: str = "") -> list[str]:
    """Auto-detect MITRE technique IDs from a finding name and description."""
    text = (finding_name + " " + description).lower()
    found: set[str] = set()
    for kw, ids in KEYWORD_TECHNIQUES.items():
        if kw in text:
            found.update(ids)
    return sorted(found)


def suggest_cvss(finding_name: str, severity: str) -> dict:
    """Return CVSS score/vector from known finding keywords or severity default."""
    name_l = finding_name.lower()
    for kw, cvss in FINDING_CVSS.items():
        if kw in name_l:
            return dict(cvss)
    return dict(SEVERITY_CVSS.get(severity, SEVERITY_CVSS["Info"]))


def technique_info(tid: str) -> dict:
    """Return technique data by ID; partial match so T1558 finds T1558.003."""
    if tid in TECHNIQUES:
        return TECHNIQUES[tid]
    for k, v in TECHNIQUES.items():
        if k.startswith(tid + "."):
            return v
    return {}


def techniques_by_tactic() -> dict[str, list[dict]]:
    """Group all techniques by tactic for the coverage matrix."""
    groups: dict[str, list[dict]] = {t: [] for t in TACTICS}
    for tid, data in TECHNIQUES.items():
        tactic = data.get("tactic", "")
        if tactic in groups:
            groups[tactic].append({"id": tid, **data})
    return groups


def enrich_finding(finding: dict) -> dict:
    """
    Return a copy of a finding enriched with mitre_ids and cvss fields
    if they are not already present.
    """
    f = dict(finding)
    name = str(f.get("name", ""))
    desc = str(f.get("description", ""))
    sev  = str(f.get("severity", "Info"))

    if not f.get("mitre_ids"):
        f["mitre_ids"] = suggest_techniques(name, desc)

    if not f.get("cvss"):
        f["cvss"] = suggest_cvss(name, sev)

    return f
