# Credential Flow & Reuse Tree

## Entry Conditions
- Any credential obtained (cleartext, NTLM hash, Kerberos ticket, SSH key, API token)
- From: LSASS dump, SAM dump, config file, responder capture, SQLi extract, etc.

## Decision Tree

```
CREDENTIAL OBTAINED
│
├── [CLASSIFY] What type?
│   │
│   ├── CLEARTEXT PASSWORD
│   │   ├── Source: (config file, LSASS, hashcat, keylog, web form)
│   │   ├── Context: (domain user, local user, service account, app user)
│   │   └── [→ STEP 2 - TEST]
│   │
│   ├── NT HASH (NTLM)
│   │   ├── Source: (SAM dump, LSASS, Responder, SMB capture)
│   │   ├── Context: (local account, domain account, cached cred)
│   │   ├── [PARALLEL] Start hashcat immediately (Module 06)
│   │   └── [PARALLEL] Try Pass-the-Hash immediately (Module 12)
│   │
│   ├── KERBEROS TICKET (TGS/TGT)
│   │   ├── Source: (Kerberoast, LSASS, ticket dump)
│   │   ├── Type: (TGS for service, TGT for user auth)
│   │   ├── [ACTION] Crack TGS with hashcat -m 13100
│   │   └── [ACTION] Pass-the-Ticket immediately
│   │
│   ├── SSH PRIVATE KEY
│   │   ├── Source: (config file, share, home directory)
│   │   ├── [ACTION] Determine which user/key it belongs to
│   │   ├── [ACTION] Test against all hosts on port 22
│   │   └── chmod 600 key && ssh -i key user@host
│   │
│   └── API TOKEN / SESSION COOKIE
│       ├── Source: (web app, config file, browser steal)
│       ├── [ACTION] Use for API access
│       └── [ACTION] Use for web session impersonation
│
├── [STEP 2 - TEST ON CURRENT HOST]
│   ├── Test credential on ALL services on SAME host:
│   │   ├── SMB (445) → netexec smb
│   │   ├── WinRM (5985) → evil-winrm
│   │   ├── RDP (3389) → xfreerdp
│   │   ├── SSH (22) → ssh
│   │   ├── MSSQL (1433) → mssqlclient
│   │   ├── MySQL (3306) → mysql
│   │   └── Web app → Login page
│   │
│   ├── Was credential found on this host?
│   │   ├── YES → Check if it's for a DIFFERENT user on this host
│   │   └── NO → Skip
│   │
│   └── Does the credential work on this host?
│       ├── YES → [→ Module 13 - Post-exploitation] (extended)
│       └── NO → Proceed to Step 3
│
├── [STEP 3 - SPRAY ACROSS ALL HOSTS]
│   ├── Test credential against ALL hosts in scope:
│   │   ├── Same subnet: netexec smb <subnet>/24 -u user -p pass
│   │   ├── All known targets: netexec smb targets.txt -u user -p pass
│   │   └── Different services on each host
│   │
│   └── Results:
│       ├── Works on other hosts? → [→ Module 12 - Lateral Movement]
│       └── Works nowhere? → Move to Step 4
│
├── [STEP 4 - PASSWORD REUSE PATTERN]
│   ├── If password cracked/obtained, test VARIATIONS:
│   │   ├── Same password, DIFFERENT user (password spray)
│   │   │   └── netexec smb dc -u users.txt -p 'cracked_password'
│   │   ├── Same password + number variations
│   │   │   └── Password1, Password2, Password123
│   │   ├── Same password + year variations
│   │   │   └── Password2023, Password2024
│   │   ├── Same base, different pattern
│   │   │   └── P@ssword, Passw0rd, password!
│   │   └── Company name + numbers
│   │       └── Contoso1, Contoso2024!
│   │
│   └── Test variations against:
│       ├── ALL domain users (if AD)
│       ├── ALL local users on accessible hosts
│       └── ALL service accounts
│
├── [STEP 5 - DOMAIN CREDENTIAL PATH]
│   ├── Is it a domain credential?
│   │   ├── YES → CRITICAL PATH
│   │   │   ├── BloodHound enumeration (immediate)
│   │   │   ├── Kerberoasting (immediate)
│   │   │   ├── LDAP domain dump
│   │   │   ├── Password spray (same password, other domain users)
│   │   │   ├── Check if user is local admin on any host
│   │   │   └── [→ Module 11 - Full AD attack chain]
│   │   └── NO → Local credential
│   │       ├── Check if local admin on other hosts (same password)
│   │       ├── Check if password works on other services
│   │       └── Move to next host for credential harvesting
│   │
│   └── Service account credential?
│       ├── YES → Determine what service it runs
│       │   ├── MSSQL? → SQL admin → xp_cmdshell → RCE
│       │   ├── Other? → Service-specific exploitation
│       │   └── Check for SPN → Kerberoast already done?
│       └── NO → Continue
│
└── [STEP 6 - DOCUMENT]
    ├── Save credential to credential tracking DB:
    │   ├── Username
    │   ├── Password / Hash
    │   ├── Domain (if applicable)
    │   ├── Source (how obtained)
    │   ├── Access level (domain admin, local admin, user)
    │   ├── Hosts where it works
    │   └── Services where it works
    │
    └── Tag for report evidence

## Credential Priority Matrix

| Credential Type | Immediate Action | Priority |
|-----------------|------------------|----------|
| Domain Admin cleartext | DCSync, Golden Ticket | CRITICAL |
| Domain User cleartext | BloodHound, Kerberoast, Spray | HIGH |
| Local Admin cleartext | SMB exec, LSASS dump | HIGH |
| Service Account cleartext | Service exploitation | HIGH |
| Domain NTLM hash | PTH, then crack | HIGH |
| Local NTLM hash | PTH on same-password hosts | MEDIUM |
| Kerberos TGS | Crack, Silver Ticket | HIGH |
| SSH key | Test all hosts | HIGH |
| API token | API access, pivot | MEDIUM |

## Cross-References
- Hash cracking → [Module 06](../modules/06-password-attacks.md)
- Lateral movement → [Module 12](../modules/12-lateral-pivot.md)
- AD attacks → [Module 11](../modules/11-active-directory.md)
- Credential harvesting → [Module 13](../modules/13-post-exploitation.md)
- Pass-the-Hash → [Module 12](../modules/12-lateral-pivot.md)
- Attack Graph navigation → [Module 99](../modules/99-attack-graph.md)
