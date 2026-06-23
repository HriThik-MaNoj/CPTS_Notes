# Module 02: Enumeration (Active Scanning & Service Discovery)

## When to Use This Module
Use this module when you have a target IP list from passive recon. This is the active scanning phase — every packet you send touches the target. The goal is to identify live hosts, open ports, running services, and operating systems.

## Prerequisites
- Target IP list from Module 01 (or scope document)
- VPN connectivity to target network (if internal)
- Root/sudo access for raw packet scans

## Entry Check

```
Target list ready?
├── Single host → Full TCP scan immediately
│   └── nmap -p- --min-rate=10000 -oA full_tcp <target>
├── Small range (≤256) → Ping sweep then full scan on live hosts
│   ├── nmap -sn <range> -oA live_hosts
│   └── nmap -p- -iL live_hosts.txt -oA full_tcp
└── Large range → Top 1000 first, then targeted deep scans
    └── nmap -sC -sV --top-ports=1000 -iL targets.txt -oA top1000
```

## Nmap Scan Strategy

### Phase 1: Host Discovery

```
Network range to scan?
├── All hosts should respond to ICMP?
│   ├── Yes → Ping sweep
│   └── No → Use TCP SYN to common ports (-sn with -PS)
├── Windows hosts expected? → Use ARP ping (local network only)
└── Cloud/VM hosts? → Expect ICMP disabled, use port-based discovery
```

```bash
# Quick ping sweep
nmap -sn <target_range> -oA ping_sweep

# Extract live hosts
grep "Host is up" ping_sweep.gnmap | cut -d" " -f2 > live_hosts.txt

# TCP-based discovery (when ICMP is blocked)
nmap -sn -PS22,80,443,445,3389 <target_range> -oA tcp_ping
```

### Phase 2: Port Scanning

```
Live hosts identified?
├── Perform port scan on each
│   └── Which scan type?
│       ├── Full TCP (65535 ports) → -p- (time-consuming but thorough)
│       │   └── Single host / small range → Always do full TCP
│       ├── Top ports (fast) → --top-ports=1000 (large ranges)
│       │   └── If on internal: --top-ports=1000 first, then -p- on interesting hosts
│       └── UDP scan → -sU (only top UDP ports, very slow)
│           └── Justify: only if DNS, SNMP, TFTP, or DHCP expected
└── No live hosts? → Verify VPN/routing, try different discovery methods
```

```bash
# Full TCP port scan (single host)
nmap -p- --min-rate=10000 -oA full_tcp <target>

# Top 1000 TCP ports with service detection (multiple hosts)
nmap -sC -sV --top-ports=1000 -iL targets.txt -oA top1000

# Top UDP ports (slow, be selective)
nmap -sU --top-ports=100 -oA top_udp <target>

# Aggressive scan (service + OS + scripts + traceroute)
nmap -A -p- <target> -oA aggressive
```

### Phase 3: Service Enumeration

```
Open ports found?
├── For EACH port: determine service + version
│   ├── Version detection: -sV
│   ├── Default scripts: -sC (NSE safe scripts)
│   └── Banner grab: nc -nv <target> <port>
│
├── Check service version for vulnerabilities
│   ├── searchsploit <service> <version>
│   ├── Google/CVE lookup
│   └── Metasploit: search <service>
│
└── Prioritize exploitation candidates:
    ├── High: RCE-capable services (SMB, RDP, web apps)
    ├── Medium: Authentication services (SSH, RDP, WinRM)
    └── Low: Information services (DNS, SNMP) — enumerate first
```

```bash
# Targeted service version scan on specific ports
nmap -sV -p <port1,port2,...> <target> -oA service_versions

# NSE script scan (safe category)
nmap -sV -sC -p <port> <target> -oA script_scan

# Specific NSE scripts
nmap --script <script-name> -p <port> <target>
```

### Phase 4: OS Detection

```bash
# OS detection (requires open ports, ideally TCP)
nmap -O <target> -oA os_detect

# OS detection + version + scripts (aggressive)
nmap -A <target> -oA aggressive
```

**OS indicators:**
| Finding | Likely OS |
|---|---|
| TTL=64 | Linux/Unix |
| TTL=128 | Windows |
| TTL=254 | Solaris/AIX |
| Port 3389 open | Windows |
| Port 22 open + TTL=64 | Linux |
| SMB + RDP | Windows |

### Phase 5: NSE Script Scan

Run appropriate scripts based on identified services:

```bash
# List all scripts for a service
ls /usr/share/nmap/scripts/<service>-*

# Run service-specific scripts
nmap --script <service>-* -p <port> <target>

# Vuln scan
nmap --script vuln -p <port> <target>

# Safe enumeration scripts
nmap --script safe -p <port> <target>
```

## Firewall & IDS/IPS Evasion

```
Firewall blocking scans?
├── Packets dropped (filtered ports) →
│   ├── Try different scan types:
│   │   ├── TCP SYN (-sS) — default, often detected
│   │   ├── TCP Connect (-sT) — more stealthy, more logging
│   │   ├── TCP ACK (-sA) — bypasses some firewalls
│   │   └── TCP FIN/Null/Xmas (-sF/-sN/-sX) — evades stateless firewalls
│   ├── Fragment packets: -f (bypass packet inspection)
│   │   └── --mtu <size> (more control over fragmentation)
│   ├── Use decoys: -D RND:5 (hide among noise)
│   ├── Specify source port: --source-port 53 (trusted port)
│   └── Change timing: -T0 or -T1 (slow, avoid rate limits)
│
├── Specific services blocked?
│   ├── Try non-standard port access (SSH on 2222?)
│   └── Use different source IP: -S <spoofed-ip>
│
└── Everything filtered?
    ├── Host may be fully firewalled
    ├── Check if internal access is needed (pivot required)
    └── Move to other targets
```

```bash
# ACK scan (determine if port is filtered by firewall)
nmap -sA -p <ports> <target>

# Fragment packets
nmap -f -p <ports> <target>

# Decoy scan
nmap -D RND:5 -p <ports> <target>

# Source port spoof (53 is often trusted)
nmap --source-port 53 -p <ports> <target>

# Slow scan to evade rate-based detection
nmap -T1 -p <ports> <target>

# Custom timing
nmap --min-rate=10 --max-rate=100 -p <ports> <target>
```

## UDP Scanning

```
UDP services expected?
├── Check common UDP services:
│   ├── DNS (53) → dns enumeration
│   ├── SNMP (161) → community string brute force
│   ├── DHCP (67/68) → potential DHCP spoofing
│   ├── TFTP (69) → file transfer without auth
│   ├── NTP (123) → ntpq enumeration, DDoS amplification
│   └── Memcached (11211) → data extraction
├── UDP scan is SLOW → only scan top 100 UDP ports unless justified
└── Use --max-retries=1 to speed up
```

```bash
# Fast UDP scan (top 100 ports)
nmap -sU --top-ports=100 --max-retries=1 <target>

# Specific UDP service
nmap -sU -p 161 <target> --script snmp-*
```

## Port-Specific Post-Scan Actions

After scanning, for each open port, determine next steps:

```
Port 21 (FTP) →
├── Anonymous login? → ls -la, download files
├── Write access? → Upload webshell, overwrite files
└── Version vuln? → searchsploit

Port 22 (SSH) →
├── Version vuln? → searchsploit (limited, most SSH vulns are auth bypass)
└── Creds found elsewhere? → Try login

Port 25 (SMTP) →
├── Open relay? → Send spoofed email
└── VRFY/EXPN? → Enumerate users

Port 53 (DNS) →
├── Zone transfer? → dig axfr @<target> <domain>
└── Subdomain brute force possible? → dnsrecon

Port 80/443 (HTTP/S) →
├── → Module 04: Web Application Testing
└── Content discovery → ffuf/gobuster

Port 88 (Kerberos) →
├── → Module 11: Active Directory
└── AS-REP roasting if no creds

Port 110/143 (POP3/IMAP) →
├── Login with creds found elsewhere
└── Read email for sensitive data

Port 135 (RPC) →
├── rpcclient enumeration
└── Check for SMB named pipes

Port 139/445 (SMB/NetBIOS) →
├── Null session? → enum4linux, smbclient -L
├── Creds found? → netexec, smbmap
└── EternalBlue check → nmap --script smb-vuln-ms17-010

Port 389/636 (LDAP) →
├── Anonymous bind? → ldapsearch
└── → Module 11: Active Directory

Port 1433 (MSSQL) →
├── Default creds? → sa:sa or sa:empty
├── Linked servers? → Enumerate for lateral movement
└── xp_cmdshell? → Enable and execute commands

Port 1521 (Oracle) →
├── Default creds? → system:manager, scott:tiger
└── TNS poisoning? → odat.py

Port 2049 (NFS) →
├── showmount -e <target> → List exports
├── Mount accessible shares → mount -t nfs <target>:/share /mnt
└── Look for SUID binaries, SSH keys

Port 3306 (MySQL) →
├── Default creds? → root:root
├── Read files? → LOAD_FILE('/etc/passwd')
└── Write files? → INTO OUTFILE webshell

Port 3389 (RDP) →
├── Creds found? → xfreerdp
├── BlueKeep (CVE-2019-0708) → nmap script check
└── Session hijack (with SYSTEM) → tscon

Port 5432 (PostgreSQL) →
├── Default creds? → postgres:postgres
└── RCE via COPY ... TO PROGRAM (read files via pg_read_file)

Port 5900 (VNC) →
├── No auth? → Direct connect
└── Brute force? → hydra

Port 5985/5986 (WinRM) →
├── Creds found? → evil-winrm
└── → Module 12: Lateral Movement

Port 6379 (Redis) →
├── No auth? → keys *; CONFIG GET *
└── Write SSH key to /root/.ssh

Port 27017 (MongoDB) →
├── No auth? → show dbs, use admin, db.getUsers()
└── Find creds in databases
```

## Decision Flow: Scan Results Prioritization

```
Nmap complete. Prioritize targets:
├── Web servers (80/443/8080/8443) → HIGH: Most common initial access
│   └── Start Module 04 immediately
├── AD-related (88/389/445/636/3268) → HIGH: Domain compromise potential
│   └── If domain-joined host found → Module 11
├── SMB/RDP/WinRM with open auth → HIGH: Immediate access if creds found
├── Database ports (1433/3306/5432) → MEDIUM: Data access, potential RCE
├── Mail services (25/110/143/993) → MEDIUM: User enumeration, data
└── DNS/SNMP/NTP → LOW: Information only, exploit later
```

## Cross-References
- For web service exploitation → [Module 04: Web Application](04-web-application.md)
- For service-specific attacks → [Module 07: Common Services](07-common-services.md)
- For AD environments → [Module 11: Active Directory](11-active-directory.md)
- For vulnerability lookup on found versions → [Module 03: Vulnerability Assessment](03-vuln-assessment.md)
- For payloads after finding RCE vector → [Module 05: Initial Access](05-initial-access.md)
- Nmap cheat sheet → [assets/cheatsheets/nmap-cheatsheet.md](nmap-cheatsheet.md)

## Output Summary
- [ ] All live hosts identified
- [ ] Full TCP port scan completed on each host
- [ ] Service versions fingerprinted
- [ ] Operating systems identified where possible
- [ ] NSE scripts run against interesting services
- [ ] UDP scan completed (if justified)
- [ ] Priority target list created
- [ ] All scan output saved to workspace/scans/
- [ ] Firewall/IDS behavior noted
