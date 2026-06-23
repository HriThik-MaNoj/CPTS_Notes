# Loot Priority Framework

## How to Use This Document

When you find a credential, hash, key, or sensitive file, look it up here to understand its value. This framework tells you why it matters, where to use it, and what it can unlock. Use it to decide what to pursue immediately vs. what to queue for later.

---

## Tier 0 — IMMEDIATE GAME OVER

These credentials win the exam. Stop all other work and exploit immediately.

### Domain Admin Credentials

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Complete domain control. Can access every host, read every file, reset every password. |
| **How found** | LSASS dump, DCSync, Kerberos ticket, config file, password spray |
| **Where to test** | DC: SMB (psexec), WinRM (evil-winrm), RDP, LDAP |
| **Reuse opportunities** | Reuse password everywhere — admin on every domain host |
| **Escalation opportunities** | DCSync → KRBTGT → Golden Ticket → Domain persistence, Forest trust → Parent domain |
| **Commands** | `secretsdump.py domain/DA:pass@DC`, `psexec.py domain/DA:pass@target` |
| **Time sensitivity** | IMMEDIATE — exploit before password rotates or session ends |

### DCSync Rights

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Can replicate all domain hashes including KRBTGT. Effectively Domain Admin without being DA. |
| **How found** | BloodHound: DCSync edge, PowerView: Get-DomainUser -Properties objectsid |
| **Where to test** | DC: `impacket-secretsdump -just-dc` |
| **Reuse opportunities** | All domain user passwords become known |
| **Escalation opportunities** | KRBTGT hash → Golden Ticket → Domain persistence |
| **Commands** | `secretsdump.py -just-dc domain/user:pass@DC` |
| **Time sensitivity** | IMMEDIATE — this IS domain compromise |

### KRBTGT Hash

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Can forge Golden Tickets — access any resource as any user, no expiration |
| **How found** | DCSync, DC compromise, LSASS on DC |
| **Where to test** | Any domain service (forged TGT authenticates everywhere) |
| **Reuse opportunities** | Forged DA TGT for any host/service |
| **Escalation opportunities** | Golden Ticket → Domain persistence → Forest trust abuse |
| **Commands** | `ticketer.py -nthash KRBTGT_HASH -domain DOMAIN -user DA`, `psexec.py -k DOMAIN/DA@target` |
| **Time sensitivity** | HIGH — use for persistence but don't stop looking for DA |

---

## Tier 1 — IMMEDIATE HIGH VALUE

These are your primary targets during the exam. They directly enable lateral movement or privilege escalation.

### Local Administrator Credentials (Windows)

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Full control of that Windows host. Can dump LSASS, access all files, install tools. |
| **How found** | SAM dump, LSASS dump, configuration files, password reuse |
| **Where to test** | Origin host: SMB, WinRM, RDP. Other hosts: same password often reused |
| **Reuse opportunities** | **CRITICAL:** Test same password against ALL hosts. Local admin reuse is common. |
| **Escalation opportunities** | LSASS dump → Domain user creds, host is domain-joined → AD foothold |
| **Commands** | `netexec smb subnet -u Administrator -H hash`, `psexec.py -hashes :hash Admin@target` |
| **Time sensitivity** | HIGH — test immediately across subnet |

### Root Credentials (Linux)

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Full control of Linux host. Can read /etc/shadow, SSH keys, pivot setup. |
| **How found** | sudo exploit, SUID, kernel exploit, SSH key, config file |
| **Where to test** | Origin host: SSH. Other Linux hosts: SSH key reuse |
| **Reuse opportunities** | **Test root password on other Linux hosts** (high reuse rate) |
| **Escalation opportunities** | Multi-homed → Pivot host. Domain-joined → AD access. Creds in /root. |
| **Commands** | `ssh root@target`, `cat /etc/shadow`, `cat /root/.ssh/id_rsa` |
| **Time sensitivity** | HIGH — harvest credentials immediately |

### NTLM Hash (Crackable)

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Can pass-the-hash immediately without cracking. If cracked, password works everywhere. |
| **How found** | SAM, LSASS, secretsdump, Responder (-m 5600), mimikatz |
| **Where to test** | SMB (pth), WinRM (-H), RDP (/pth), WMI (wmiexec) |
| **Reuse opportunities** | Spray cracked password against all users. PTH against all hosts. |
| **Escalation opportunities** | If admin hash → full host control. If domain hash → AD enumeration. |
| **Commands** | `psexec.py -hashes :hash user@target`, `evil-winrm -i target -u user -H hash` |
| **Time sensitivity** | HIGH — PTH immediately, crack in background |

### Reused Domain Credentials

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Password reused across services = multiplied attack surface |
| **How found** | Password spray, config file, LSASS, browser saved |
| **Where to test** | SMB, WinRM, SSH, RDP, MSSQL, web apps, VPN — literally everywhere |
| **Reuse opportunities** | Test username:password against ALL authentication points |
| **Escalation opportunities** | Domain user → BloodHound → DA path. Access new services. |
| **Commands** | `netexec smb subnet -u user -p pass`, `netexec winrm subnet -u user -p pass` |
| **Time sensitivity** | HIGH — test across entire subnet immediately |

---

## Tier 2 — HIGH VALUE

These credentials often lead to lateral movement or privilege escalation. Pursue actively.

### Service Account Credentials

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Service accounts often have elevated privileges. MSSQL service = possible xp_cmdshell. |
| **How found** | Kerberoast (TGS ticket → crack → password), config files, LSASS, LSA secrets |
| **Where to test** | Service host (SMB/WinRM). Check SPN for target service. |
| **Reuse opportunities** | Test against ALL hosts — service accounts sometimes local admin |
| **Escalation opportunities** | Check domain privileges. Service accounts can be in privileged groups. Delegation targets. |
| **Commands** | `netexec smb target -u svc_account -p pass`, `BloodHound: check DA path from service account` |
| **Time sensitivity** | MEDIUM-HIGH — crack in background, use when found |

### Kerberoastable User TGS Ticket

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Service account password crackable offline. High value if service account is privileged. |
| **How found** | `GetUserSPNs -request`, BloodHound: Kerberoastable |
| **Where to test** | Crack with hashcat -m 13100. Use password on service host. |
| **Reuse opportunities** | Service account password may work on other services |
| **Escalation opportunities** | Service account → DA path (BloodHound). Silver Ticket for persistent service access. |
| **Commands** | `hashcat -m 13100 ticket.txt rockyou.txt` |
| **Time sensitivity** | MEDIUM — run in background while doing other work |

### MSSQL Credentials (sa or sysadmin)

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | xp_cmdshell → RCE → Windows shell. Can enable system commands. |
| **How found** | Config files, SQLi, default creds (sa:sa), LSASS |
| **Where to test** | MSSQL server (port 1433): `mssqlclient.py user:pass@target` |
| **Reuse opportunities** | Test same creds against other MSSQL servers, SMB, WinRM |
| **Escalation opportunities** | xp_cmdshell → SYSTEM. Linked servers → lateral to other DB servers. |
| **Commands** | `mssqlclient.py sa:pass@target`, `enable_xp_cmdshell`, `xp_cmdshell whoami` |
| **Time sensitivity** | HIGH — xp_cmdshell gives shell |

### AS-REP Roastable User Hash

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | User doesn't require Kerberos pre-authentication. Hash cracks offline — free credential. |
| **How found** | `GetNPUsers -dc-ip DC domain/ -usersfile users.txt -format hashcat` |
| **Where to test** | Crack hashcat -m 18200. Use cleartext password as domain user. |
| **Reuse opportunities** | Password spray (same password, other users). Test on all hosts. |
| **Escalation opportunities** | Domain user → BloodHound → DA path |
| **Commands** | `hashcat -m 18200 hash.txt rockyou.txt` |
| **Time sensitivity** | MEDIUM — run in background while enumerating |

---

## Tier 3 — MEDIUM VALUE

Worth pursuing, but don't block on them. Queue them while working higher-priority targets.

### Config File Credentials

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Application database credentials, API keys, service passwords in plaintext |
| **How found** | Web configs (web.config, config.php, .env), backup files, database connection strings |
| **Where to test** | DB server (MSSQL/MySQL), application admin panel, SMB/WinRM |
| **Reuse opportunities** | High reuse rate — developers use same passwords everywhere |
| **Escalation opportunities** | DB access → SQLi → RCE. API keys → cloud access. |
| **Common files** | `web.config`, `wp-config.php`, `.env`, `config.php`, `database.yml`, `appsettings.json` |
| **Time sensitivity** | MEDIUM — batch search then test |

### SSH Private Key

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Passwordless SSH access to hosts. No brute force needed. |
| **How found** | LFI (`/home/user/.ssh/id_rsa`), readable share, NFS mount, /root/.ssh |
| **Where to test** | SSH to the host the key belongs to. Test on other hosts with same user. |
| **Reuse opportunities** | Same key often deployed across multiple hosts |
| **Escalation opportunities** | SSH as user → Linux privesc chain |
| **Commands** | `ssh -i id_rsa user@host`, `chmod 600 id_rsa` |
| **Time sensitivity** | MEDIUM — test key, then crack passphrase if needed |

### Browser Saved Credentials

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Users save passwords in browsers. Often includes domain credentials, web app passwords. |
| **How found** | Windows: Chrome/Firefox decrypt tools. Linux: browser profile access. |
| **Where to test** | SMB, WinRM, SSH, web apps |
| **Reuse opportunities** | Significant — users don't create unique passwords |
| **Escalation opportunities** | Domain creds → AD attack chain. Admin creds → web app admin → RCE. |
| **Commands** | `SharpChrome.exe`, `firefox_decrypt.py` |
| **Time sensitivity** | MEDIUM — run on any Windows host you access |

### Backup Files

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Backup files often contain full database dumps, configs, and sometimes plaintext passwords |
| **How found** | SMB shares, FTP, web directories (backup.sql, backup.zip, *.bak, *.old) |
| **Where to test** | Extract files → search for passwords in content |
| **Reuse opportunities** | Any credential found in backup → test everywhere |
| **Escalation opportunities** | DB dump → admin hashes → cracking. Configs → service creds. |
| **Commands** | `grep -r "password" backup/`, `strings backup-file` |
| **Time sensitivity** | LOW — examine between attack waves |

---

## Tier 4 — LOW VALUE / NON-URGENT

Collect but don't prioritize. These rarely lead to escalation directly.

### NTLMv2 Hash (Responder Capture)

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Can be cracked offline (-m 5600). Also used for SMB relay. |
| **How found** | Responder capture |
| **Where to test** | Crack first. Then use password everywhere. Relay (if signing disabled). |
| **Reuse opportunities** | Cracked password → spray. Relay → code execution. |
| **Escalation opportunities** | Domain user → BloodHound. Relay to DC → ADCS certificate → DA. |
| **Commands** | `hashcat -m 5600 hash.txt rockyou.txt`, `ntlmrelayx.py -tf targets.txt` |
| **Time sensitivity** | MEDIUM — run crack in background immediately |

### GPP / CPassword

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Microsoft published AES key. Always decryptable. Often contains local admin password. |
| **How found** | SYSVOL share: `\\domain\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml` |
| **Where to test** | SMB/WinRM on domain hosts |
| **Reuse opportunities** | Local admin password → all hosts |
| **Escalation opportunities** | Local admin on domain host → LSASS → Domain user creds |
| **Commands** | `gpp-decrypt "cpassword"` |
| **Time sensitivity** | MEDIUM — quick decrypt, quick test |

### Kerberos TGT/TGS Ticket

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Can pass-the-ticket for authenticated access without password |
| **How found** | Linux: `klist`. Windows: mimikatz `kerberos::list`. |
| **Where to test** | SMB with ticket (`psexec.py -k`), or convert to hash |
| **Reuse opportunities** | Ticket is valid for authentication across domain |
| **Escalation opportunities** | If ticket is for DA → immediate DA access |
| **Commands** | `export KRB5CCNAME=ticket.ccache`, `psexec.py -k domain/user@target` |
| **Time sensitivity** | LOW to HIGH — HIGH if ticket is for privileged user |

### LAPS Password

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Local admin password for domain-joined Windows hosts. Managed per-machine. |
| **How found** | AD: Read ms-Mcs-AdmPwd attribute. BloodHound: `ReadLAPSPassword` edge. |
| **Where to test** | SMB/WinRM on the specific host whose password you read |
| **Reuse opportunities** | None — LAPS per-machine password is unique. But each host is separate access. |
| **Escalation opportunities** | Local admin on additional domain hosts → LSASS → more domain creds |
| **Commands** | `netexec ldap dc -u user -p pass -M laps` |
| **Time sensitivity** | HIGH for that specific host, LOW for DA path |

---

## Tier 5 — INFORMATION ONLY

Useful for building attack paths but doesn't provide direct access.

### Domain Usernames

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Required for password spray, AS-REP roast, Kerbrute |
| **How found** | SMB null session, LDAP anonymous, Kerbrute, Responder, email harvesting |
| **Where to test** | Password spray, AS-REP roast, Kerberoast |
| **Escalation opportunities** | Enable all user-based attacks |
| **Time sensitivity** | HIGH — required for every AD attack |

### Password Policy

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Determines spray strategy. Lockout threshold = spray limit. |
| **How found** | `rpcclient -U "" -N target getdompwinfo`, `net accounts /domain` (if domain user) |
| **Where to use** | Planning password spray strategy |
| **Escalation opportunities** | Indirect — enables successful spray |
| **Time sensitivity** | MEDIUM — useful before spray |

### BloodHound Path Information

| Attribute | Detail |
|-----------|--------|
| **Why it matters** | Maps the exact path from your current position to DA |
| **How found** | BloodHound analysis with domain credentials |
| **Where to use** | Planning next attack steps |
| **Escalation opportunities** | Direct DA path execution |
| **Time sensitivity** | HIGH — once you have domain creds, run BH immediately |

---

## Loot Discovery Priority — Cheat Sheet

```
FOUND THIS? → YOUR NEXT ACTION:

Domain Admin creds    → DCSync → Golden Ticket → All flags
DCSync rights         → secretsdump -just-dc → Done
Local admin cred      → netexec --sam → LSASS dump → Domain creds
NTLM hash             → PTH (now) + crack (bg) → Password
Responder hash        → crack (bg) + check relay
SSH key               → SSH to host → check domain + privesc
Config file creds     → test DB + SMB + WinRM
Service account cred  → BloodHound + Kerberoast + test host
Browser creds         → test all services
GPP password          → decrypt → test local admin
LAPS password         → SMB/WinRM that specific host
AS-REP hash           → crack (bg) → domain user
Kerberos ticket       → PTT → access service
Backup file           → extract → grep for passwords
Domain usernames      → password spray + AS-REP
Password policy       → plan spray rate
```

---

## Cross-References

- Credential handling → [credential-reuse-matrix.md](./credential-reuse-matrix.md)
- Attack chain execution → [high-probability-paths.md](./high-probability-paths.md)
- Quick decision lookup → [exam-dashboard.md](./exam-dashboard.md)
- Credential harvesting techniques → [Module 13: Post-Exploitation](../modules/13-post-exploitation.md)
- Password cracking → [Module 06: Password Attacks](../modules/06-password-attacks.md)
- AD attack paths → [Module 11: Active Directory](../modules/11-active-directory.md)
