# CPTS Master Methodology

## When to Use This Document
This is the top-level orchestration layer that ties all 16 modular methodologies together. Read this FIRST before any assessment or exam to understand the overall flow. Then drill into individual modules for the detailed decision trees and commands.

## Overall Penetration Test Lifecycle

```
START → Pre-Engagement (Module 00)
  │
  ▼
Information Gathering (Module 01) ←─────┐
  │                                       │
  ▼                                       │
Vulnerability Assessment (Module 03)      │ (loop back when
  │                                       │  new info found)
  ▼                                       │
Exploitation ───────────┐                 │
  │                     │                 │
  ├── Web App (04)      │                 │
  ├── Services (07)     │                 │
  ├── Applications (08) │                 │
  └── AD (11) ──────────┤                 │
                        │                 │
  ▼                     ▼                 │
Initial Access (05) → Post-Exploitation ──┘
                           │
                     ┌─────┼─────┐
                     ▼     ▼     ▼
                Linux   Windows  AD
                Privesc  Privesc Enum
                (09)     (10)    (11)
                     │     │     │
                     └─────┼─────┘
                           ▼
                   Password Attacks (06)
                   Lateral Movement (12)
                   Pivoting (12)
                           │
                           ▼ (loop back to Info Gathering for new hosts)
                   Goal Achieved?
                     ├── Yes → Reporting (14) + Exam Strategy (15)
                     └── No → Continue iteration
```

## Phase Transition Rules

```
Current Phase: What triggers the next phase?

Module 00 (Pre-Engagement)
├── Scope read and understood → 01 (Info Gathering)
└── NOT ready → Stay in 00

Module 01 (Info Gathering)
├── IPs/domains identified → 02 (Enumeration)
└── Nothing found → Try deeper OSINT, then 02 anyway

Module 02 (Enumeration)
├── Live hosts + open ports identified → 03 (Vuln Assessment)
├── Web servers found → Also → 04 (Web Application)
└── No hosts found → Check VPN/routing, return to 01

Module 03 (Vuln Assessment)
├── RCE vulnerability found → 05 (Initial Access) or 04/07/11
├── Credential attacks promising → 06 (Password Attacks)
├── Service-specific vuln → 07 (Common Services)
├── Low-hanging fruit found → Exploit immediately
└── Nothing found → Return to 02 for deeper scan

Module 04/07/08/11 (Exploitation)
├── Successful shell → 05 (Initial Access) then 13 (Post-Exploit)
├── Partial access (/etc/passwd read only) → Use for other attacks
└── Failed → Try alternative attack vectors, return to 03

Module 05 (Initial Access)
├── Interactive shell obtained → 13 (Post-Exploitation)
└── Shell failed → Try different payload type/port/protocol

Module 13 (Post-Exploitation)
├── Credentials found → 06 (Password Attacks)
├── Linux host → 09 (Linux PrivEsc)
├── Windows host → 10 (Windows PrivEsc)
├── Domain-joined host → 11 (Active Directory)
├── Multi-homed host → 12 (Lateral Movement & Pivoting)
└── Loop: After each success, return to 13 for more harvesting

Module 06 (Password Attacks)
├── Cracked password → Use for lateral movement (12)
├── Cracked password for new user → 11 (AD Enumeration)
└── Failed to crack → Try larger wordlist, rules, or longer time

Module 09/10 (PrivEsc)
├── Root/System achieved → 13 (Post-Exploitation, elevated)
└── Failed → Check for other users, kernel exploits, missed vectors

Module 11 (AD)
├── Domain Admin achieved → DCSync → Golden Ticket → 12 (Pivot)
├── Partial AD compromise → Continue BloodHound paths
└── No AD access → Return to credential attacks (06)

Module 12 (Lateral Movement & Pivoting)
├── New host accessed → Restart from 13 (Post-Exploit on new host)
├── New subnet accessible → Restart from 02 (Enumeration on new subnet)
└── No new hosts → Return to AD enumeration (11) or go to 14

Module 14 (Reporting)
├── Testing complete → Write report, clean up
└── Testing NOT complete → Return to appropriate phase
```

## Parallel Execution Model

Some phases run in parallel:

```
Phase 5 (Password Attacks)
├── Starts in parallel when hashes are obtained
└── Runs in background while other phases continue

Phase 12 (Documentation & Reporting)
├── Starts at Module 00 and runs continuously
└── Screenshots and notes taken throughout

Phase 10B (File Transfers)
└── Runs as needed throughout (called by any module)
```

## Exam Priority Matrix

```
What to do first in the CPTS exam:
├── 1. Full network scan (all TCP ports on all hosts)
│   └── While scanning runs, do web recon on found web servers
├── 2. Web applications (most common initial access)
│   └── SQLi, LFI, and file upload are the highest success vectors
├── 3. Service enumeration (SMB, FTP, MSSQL)
│   └── Check for null/anonymous sessions immediately
├── 4. Password attacks (start as soon as you have usernames)
│   └── Spray first, brute force second
└── 5. AD attacks (start as soon as you have domain creds)
    └── BloodHound runs while you continue enumeration
```

## Quick Reference: After Every Foothold

```
New host compromised?
├── Check privileges (whoami / id)
├── Check network (ipconfig / netstat / route)
├── Enumerate host for credentials (Module 13)
├── Crack any hashes found (Module 06)
├── Check privesc paths (Module 09/10)
├── Check if domain-joined (Module 11)
├── Check for pivoting opportunities (Module 12)
└── RESTART from Module 02 on new hosts
```

## Quick Reference: When Stuck

```
Stuck?
├── Did you scan ALL 65535 TCP ports?
├── Did you scan top 1000 UDP ports?
├── Did you use ffuf for content discovery?
├── Did you try default credentials on all services?
├── Did you check for null/anonymous sessions?
├── Did you run full privesc enumeration?
├── Did you check for other subnets via routing table?
├── Take a break, review notes from the start
└── Try a completely different attack vector
```

## Module Dependency Graph

```
Module 02 (Enumeration) depends on: 01 (Info Gathering)
Module 03 (Vuln Assessment) depends on: 02 (Enumeration)
Module 04 (Web) depends on: 02 (Enumeration)
Module 05 (Shells) depends on: 03/04/07/08 (RCE vector)
Module 06 (Password Attacks) depends on: 13 (Credentials obtained)
Module 07 (Services) depends on: 02 (Enumeration)
Module 08 (Apps) depends on: 04 (Web discovery)
Module 09 (Linux PrivEsc) depends on: 05 (Linux shell)
Module 10 (Windows PrivEsc) depends on: 05 (Windows shell)
Module 11 (AD) depends on: 07 (SMB/LDAP) or 13 (Domain creds)
Module 12 (Lateral/Pivot) depends on: 13 (Credentials) or 05 (Host access)
Module 13 (Post-Exploit) depends on: 05 (Shell)
Module 14 (Reporting) depends on: ALL (continuous)
Module 15 (Exam Strategy) depends on: ALL (strategic overlay)
```

## Module Reference Index

| Module | File | Purpose |
|---|---|---|
| 00 | [modules/00-pre-engagement.md](00-pre-engagement.md) | Scope, setup, legal, tool checklist |
| 01 | [modules/01-info-gathering.md](01-info-gathering.md) | Passive recon, OSINT, DNS, WHOIS |
| 02 | [modules/02-enumeration.md](02-enumeration.md) | Nmap scanning, service discovery, firewall evasion |
| 03 | [modules/03-vuln-assessment.md](03-vuln-assessment.md) | Nessus, OpenVAS, CVE research, CVSS |
| 04 | [modules/04-web-application.md](04-web-application.md) | Full web app testing pipeline |
| 05 | [modules/05-initial-access.md](05-initial-access.md) | Shells, payloads, file transfer, MSF |
| 06 | [modules/06-password-attacks.md](06-password-attacks.md) | Hash cracking, spraying, brute force |
| 07 | [modules/07-common-services.md](07-common-services.md) | FTP, SMB, MSSQL, MySQL, RDP, etc. |
| 08 | [modules/08-common-apps.md](08-common-apps.md) | WordPress, Tomcat, Jenkins, Splunk, etc. |
| 09 | [modules/09-linux-privesc.md](09-linux-privesc.md) | Linux privilege escalation |
| 10 | [modules/10-windows-privesc.md](10-windows-privesc.md) | Windows privilege escalation |
| 11 | [modules/11-active-directory.md](11-active-directory.md) | Full AD attack chain |
| 12 | [modules/12-lateral-pivot.md](12-lateral-pivot.md) | Lateral movement, pivoting, tunneling |
| 13 | [modules/13-post-exploitation.md](13-post-exploitation.md) | Credential harvesting, data collection |
| 14 | [modules/14-reporting.md](14-reporting.md) | Documentation, reporting, cleanup |
| 15 | [modules/15-exam-strategy.md](15-exam-strategy.md) | Exam-specific strategy and time management |
