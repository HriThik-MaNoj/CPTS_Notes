# Module 00: Pre-Engagement

## When to Use This Module
Use this module at the very start of any penetration test, before any scanning or enumeration begins. It covers everything from reading the legal scope documents through setting up your attack infrastructure. Without completing this phase, you risk legal exposure, wasted time, or missing critical scope boundaries.

## Prerequisites
- Signed contract / Statement of Work from client
- Scope document with in-scope targets and exclusions
- Contact information for emergency escalation

## Entry Check

```
Signed contract in hand?
├── Yes → Read scope documents
│   ├── Scope specifies IPs/CIDR/domains?
│   │   ├── Yes → Extract target list, note exclusions
│   │   └── No → Request clarification before scanning
│   ├── Testing window defined?
│   │   ├── Yes → Note start/end timestamps
│   │   └── No → Confirm with client
│   ├── Rules of Engagement (RoE) defined?
│   │   ├── Yes → Note allowed techniques, prohibited actions
│   │   └── No → Default to least-invasive approach
│   └── Emergency contact provided?
│       ├── Yes → Save contact info
│       └── No → Request escalation point
└── No → STOP. Do not scan without authorization.
```

## Key Documents to Review

### Letter of Engagement / Statement of Work
- In-scope assets (IPs, CIDR ranges, domains, applications)
- Excluded IPs (often domain controllers, production DBs, third-party SaaS)
- Allowed techniques (DoS allowed? social engineering? physical?)
- Testing window (start/end timestamps, business hours only?)
- Emergency contact (who to call if production breaks)
- Reporting deliverables (final report, evidence pack, attestation)

### Scoping Questionnaire
- Technology stack hints (Windows/Linux mix, cloud presence, AD version)
- Sensitive systems that must be handled carefully
- Third-party dependencies (AWS, Azure, SaaS providers)
- Expected number of hosts and subnets

### Contractor Agreement / NDA
- Data handling rules for findings and client data
- Retention period for test data
- Confidentiality obligations

## Testing Methods & Types

```
Testing starting point?
├── External (from internet) → Use VPN/VPS, target perimeter
│   ├── Blackbox → Only IPs/domains provided, full recon required
│   ├── Greybox → Extended info (subnets, URLs, hostnames)
│   └── Whitebox → Full access (configs, creds, source code)
└── Internal (inside network) → Assumed breach or after perimeter breach
    ├── Network pentest → Focus on lateral movement, AD
    ├── Web app test → Focus on OWASP Top 10
    └── Red team → Scenario-based, specific objective
```

## Attack Infrastructure Setup

### Virtual Machine Requirements
```
Fresh VM per engagement?
├── Yes → Clean install, no cross-client contamination
└── No → Risk of leaking client data in reports
```

### VPN Setup
```bash
# Connect to client VPN
sudo openvpn client.ovpn

# Verify connection
ifconfig                  # Look for tun0 adapter
netstat -rn               # Verify routes to target networks
ping <target-ip>          # Test connectivity
```

### Workspace Organization
```
Projects/
└── Client_Name/
    ├── EPT/                    # External penetration test
    │   ├── evidence/
    │   │   ├── credentials/    # Found creds saved here
    │   │   ├── data/           # Downloaded files
    │   │   └── screenshots/    # Evidence screenshots
    │   ├── logs/               # Tool output logs
    │   ├── scans/              # Nmap and other scan results
    │   ├── scope/              # Scope documents
    │   └── tools/              # Custom tools for this engagement
    └── IPT/                    # Internal penetration test
        └── (same structure)
```

### Tool Checklist
Verify all critical tools are installed before starting:
```bash
# Network enumeration
which nmap netexec smbclient smbmap rpcclient enum4linux

# Web testing
which ffuf gobuster nikto whatweb wappalyzer burpsuite

# Exploitation
which msfconsole msfvenom nc ncat socat python3

# AD testing
which responder impacket-GetUserSPNs bloodhound-python certipy

# Password attacks
which hashcat john hydra

# Pivoting
which ligolo-ng chisel sshuttle proxychains4

# Post-exploitation
which evil-winrm xfreerdp psexec.py wmiexec.py
```

### Note-Taking Setup
Choose a tool and prepare templates before testing starts:
- CherryTree (hierarchical notes with code blocks)
- Obsidian (markdown with graph view)
- VS Code with markdown preview
- Notion (rich collaboration features)

**Critical rule:** Store all client data locally. Do not sync to cloud.

## 6-Layer Enumeration Methodology
Use this mental model across every phase to ensure thorough coverage:
1. **Internet Presence** — domains, subdomains, vHosts, ASN, netblocks, IPs, cloud
2. **Gateway** — firewalls, DMZ, IPS/IDS, EDR, proxies, NAC, VPN, Cloudflare
3. **Accessible Services** — service type, functionality, config, port, version, interface
4. **Processes** — PID, processed data, tasks, source, destination
5. **Privileges** — groups, users, permissions, restrictions, environment
6. **OS Setup** — OS type, patch level, network config, config files, sensitive files

## Common Ports Reference
Memorize these. You should recognize them instantly:
```
20/21  TCP  FTP
22     TCP  SSH
23     TCP  Telnet
25     TCP  SMTP
53     TCP/UDP  DNS
80     TCP  HTTP
88     TCP  Kerberos
110    TCP  POP3
135    TCP  RPC
139    TCP  NetBIOS-SSN
143    TCP  IMAP
161    TCP/UDP  SNMP
389    TCP/UDP  LDAP
443    TCP  HTTPS (SSL/TLS)
445    TCP  SMB
464    TCP/UDP  Kerberos password change
465    TCP  SMTPS
587    TCP  SMTP (submission)
593    TCP  HTTP RPC Endpoint Mapper
636    TCP  LDAPS
993    TCP  IMAPS
995    TCP  POP3S
1433   TCP  MSSQL
1521   TCP  Oracle DB
2049   TCP  NFS
3306   TCP  MySQL
3389   TCP  RDP
3632   TCP  DistCC
5432   TCP  PostgreSQL
5900   TCP  VNC
5985   TCP  WinRM HTTP
5986   TCP  WinRM HTTPS
6379   TCP  Redis
8080   TCP  HTTP Proxy
8443   TCP  HTTPS Alt
9090   TCP  Cockpit
11211  TCP  Memcached
27017  TCP  MongoDB
```

## Penetration Testing Process Overview

```
PTES Phases (mental model for where you are):
Pre-Engagement → Information Gathering → Threat Modeling
→ Vulnerability Analysis → Exploitation → Post-Exploitation
→ Reporting
```

### Phase Transition Rules

```
Starting point reached?
├── Prepare scope docs & infrastructure → PRE-ENGAGEMENT DONE
│   
├── Then: INFORMATION GATHERING
│   └── Found enough data? → VULNERABILITY ASSESSMENT
│       └── Identified vulns? → EXPLOITATION
│           ├── Success → POST-EXPLOITATION
│           │   ├── Need more hosts? → LATERAL MOVEMENT
│           │   └── Goal reached? → REPORTING
│           └── Failure → Back to INFORMATION GATHERING
│
└── Throughout: DOCUMENT EVERYTHING → REPORTING PHASE
```

## Ethical & Legal Boundaries

**Golden rules:**
1. **Stay in scope** — Only attack what's authorized. Out-of-scope hit = report fail
2. **Do no harm** — Consider if running a PoC could crash production
3. **Document everything** — Get approvals IN WRITING, not verbal
4. **Client data is confidential** — Store locally, encrypt, destroy after retention period

## Output Summary
When pre-engagement is complete:
- [ ] Scope documents read and understood
- [ ] Target list extracted and saved
- [ ] Exclusions noted and configured in scanning tools
- [ ] Attack VM(s) provisioned and isolated
- [ ] Workspace folder structure created
- [ ] Tools verified installed
- [ ] VPN connectivity tested
- [ ] Note-taking tool configured
- [ ] Emergency contact saved

## Cross-References
- When scanning begins → [Module 02: Enumeration](../modules/02-enumeration.md)
- When you need web recon setup → [Module 04: Web Application](../modules/04-web-application.md)
- For exam-specific setup → [Module 15: Exam Strategy](../modules/15-exam-strategy.md)
- For report structure → [Module 14: Reporting](../modules/14-reporting.md)
- For tool-specific cheat sheets → [assets/cheatsheets/](../assets/cheatsheets/)
