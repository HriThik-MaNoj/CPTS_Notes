# Attack Path Prioritization

## The Core Question

> "I have 10 possible things to try. Which one should I do first?"

## How to Use This

Every attack path is classified into one of three tiers. Start at TRY FIRST. Work down. If nothing in TRY FIRST applies, move to TRY NEXT. If you're stuck, TRY IF STUCK.

No math required.

---

## TRY FIRST

These paths have the highest success rate per minute invested. Check them before anything else.

| Path | Why | Signal to check |
|------|-----|-----------------|
| **SMB null session** | Free user list + password policy in 5 min | Port 445 open |
| **SMB signing disabled** | Relay path to shells or DA | Port 445 + signing not required |
| **LDAP anonymous bind** | Full domain dump without creds | Port 389 open |
| **Password spray (top 3 patterns)** | Domain user from one attempt | Any username list |
| **AS-REP roasting** | Free domain user hash | Port 88 (Kerberos) open |
| **Web app injection check** | SQLi/LFI/CMDi = fastest shell | Web server found |
| **MSSQL default creds** | xp_cmdshell → SYSTEM | Port 1433 open |
| **Local admin password reuse** | Rapid lateral movement | Any local admin credential |
| **GPP cpassword** | Decrypts 100% of the time | SYSVOL readable |
| **Responder + active coercion** | NetNTLM capture → crack or relay | Domain environment |

---

## TRY NEXT

These paths require more time or a prerequisite foothold. Pursue after TRY FIRST paths are exhausted.

| Path | Why | Prerequisite |
|------|-----|-------------|
| **BloodHound analysis** | Maps the exact path to DA | Any domain credential |
| **Kerberoasting** | Service account password | Domain credential |
| **ACL abuse (ForceChangePassword, GenericAll, WriteDACL)** | Direct DA path | BloodHound findings |
| **ADCS enumeration (certipy)** | Certificate → authenticate as any user | Domain credential |
| **Delegation abuse** | Impersonate DA via S4U | Domain + delegation host |
| **LAPS reading** | Local admin on any host | ReadLAPSPassword permission |
| **Shadow Credentials** | Add key credential → authenticate as target | GenericAll/GenericWrite/WriteOwner |
| **SQLi exploitation** | DB dump → creds → lateral | SQL injection found |
| **LFI exploitation** | Config files → creds → lateral | LFI found |
| **File upload → RCE** | Web shell → OS user | File upload found |
| **Command injection** | Direct OS command execution | CMDi found |
| **SeImpersonate → Potato** | User to SYSTEM in seconds | Windows shell as service account |
| **NFS exports → SSH keys** | Passwordless shell | Port 2049 open |
| **FTP anonymous** | Config file download | Port 21 open |
| **Password spray (extended)** | More users from more patterns | Username list + no lockout |
| **Crack all hashes** | Cleartext passwords from captured hashes | Any NT hash, NetNTLMv2, or TGS |
| **Pass-the-Hash sweep** | Lateral to same-password hosts | Any NTLM hash |

---

## TRY IF STUCK

These paths are lower probability, time-intensive, or only apply in specific scenarios. Do not touch these until TRY FIRST and TRY NEXT are fully exhausted.

| Path | Why it's here | When to use |
|------|---------------|-------------|
| **Full TCP port scan (-p-)** | Missed services on initial sweep | No foothold after 2+ hours |
| **UDP scan (top 100)** | SNMP/TFTP may provide foothold | All TCP paths exhausted |
| **Kernel exploit** | Direct root/SYSTEM | Known vulnerable version confirmed |
| **Brute force (SSH/RDP)** | Password discovery | No lockout + username known |
| **DNS zone transfer** | Subdomain discovery | DNS server found |
| **SNMP read** | User/process enumeration | Port 161 open |
| **SMTP user enum (VRFY)** | Username validation | Port 25 open |
| **Web CMS deep dive (wpscan/joomscan)** | Plugin/theme CVE | CMS identified + no faster path |
| **Docker group abuse** | Container escape → root | User in docker group |
| **AlwaysInstallElevated** | MSI → SYSTEM | Registry key enabled |
| **Detailed OSINT** | External info gathering | No other path forward |
| **MSSQL Agent Jobs** | Alternative to xp_cmdshell | MSSQL access + xp_cmdshell blocked |

---

## Phase-Based Priority

### Foothold Hunting

```
CHECK IN THIS ORDER:
1. SMB: null session + signing + shares   (5 min per host)
2. LDAP: anonymous bind                    (2 min)
3. Web: injection check + dir busting     (20 min per app)
4. MSSQL: default creds                    (2 min)
5. Responder + coercion running            (background)
6. FTP/NFS: anonymous + mount              (5 min each)
```

### After First Shell

```
PRIORITY (do in this order, don't skip ahead):
1. Extract credentials (LSASS/SAM/bash_history/configs)
2. Test ALL extracted creds via netexec sweep
3. Check domain join + BloodHound (if domain)
4. Check privesc on current host
5. Check pivoting (multi-homed + routes)
6. Deploy pivot to reach new subnets
```

### Domain Access

```
PRIORITY (overwrites everything else until DA is found or disproven):
1. BloodHound collection + analysis
2. Kerberoast (while BH runs)
3. AS-REP roast
4. ADCS (certipy find)
5. Delegation check
6. ACL abuse from BH paths
7. LAPS enumeration
8. Shadow Credentials
9. Trust enumeration
```

---

## "I'm Stuck" Framework

| Situation | Reset action |
|-----------|--------------|
| No foothold, no web | Did you check SMB null + LDAP anon? Did you run -p-? Did you try UDP? |
| Web apps all filtered | Check ports 8000, 8080, 8443, 8888, 9001, 9090, 5000 |
| Shell but no lateral | Sweep ALL hosts with ALL creds. Check SSH keys. Check pivoting. |
| Domain user but stuck | Did you run BloodHound with ALL collection methods? Did you check ADCS? |
| No AD path from BH | Run manual AD enumeration — BH may be incomplete |
| Privileges limited | Re-run enumeration tools. Check kernel. Check cron/scheduled tasks. |
| No AD present | Pivot deeper. Check internal DNS. Scan from compromised host. |

---

## Quick Reference Card

```
SITUATION              → TRY FIRST
───────────────────────  ────────────────────────────────
SMB (445)               → Null session + signing check
Web (80/443)            → Injection check + dir busting
MSSQL (1433)            → sa:sa → xp_cmdshell
WinRM (5985)            → Spray + evil-winrm
LDAP (389)              → Anonymous bind
Kerberos (88)           → AS-REP roast
Found cred              → netexec sweep → BloodHound (if domain)
Found NTLM hash         → PTH NOW → crack (bg)
Found ticket            → PTT or crack
Shell                   → Extract creds → test everywhere → privesc → pivot
Stuck                   → -p- scan → UDP scan → re-read scope → break
```
