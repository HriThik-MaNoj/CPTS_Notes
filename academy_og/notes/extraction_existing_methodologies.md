# Extraction & Analysis of Existing CPTS Methodologies

> **Purpose:** Summarize what approaches and structures have already been tried across 8 reference files. Identify what works, what's missing, and unique insights from each.
>
> **Date:** 2026-06-21

---

## Table of Contents

1. [File-by-File Analysis](#file-by-file-analysis)
2. [Cross-File Comparison Matrix](#cross-file-comparison-matrix)
3. [What Works Well (Common Strengths)](#what-works-well)
4. [Gaps & Areas for Improvement](#gaps--areas-for-improvement)
5. [Unique Insights Worth Preserving](#unique-insights-worth-preserving)
6. [Recommendations for a Unified Methodology](#recommendations)

---

## File-by-File Analysis

---

### 1. `academy_og/m3_ad_methodology.md` (4,372 lines, ~152 KB)

**Structure/Format:**
- 20 sequential phases (Phase 0–20) plus 9 appendices
- Decision-tree format at every phase transition (ASCII flowcharts)
- Dual-platform commands: Linux AND Windows for every technique
- Source-verified — explicitly notes all content comes from the HTB Academy AD module

**Key Strengths:**
- **Most comprehensive AD-only document** — exhaustive coverage of every AD attack surface
- Decision trees at every phase prevent "what do I do next?" paralysis
- Dual-platform approach (Linux + Windows commands side-by-side) is exam-realistic
- Appendices provide quick-lookup tables (hashcat modes, event IDs, common SIDs, ports, SPNs, default passwords)
- Excellent credential theft catalogue (12 sub-categories in Phase 12 alone — LAPS, GPP, DPAPI, KeePass, browser creds, ADCS, etc.)
- Pre-spray filtering (`badpwdcount=0`) is a practical exam tip often missed
- Cleanup checklist (Phase 19) ensures responsible testing

**Gaps:**
- **AD-only** — zero coverage of web exploitation, Linux privesc, pivoting mechanics, or general service attacks
- No web application attack vectors (no LFI, SQLi, CMDi, file upload)
- No Linux privilege escalation (SUID, capabilities, cron, etc.)
- No pivoting/tunneling mechanics (Ligolo, Chisel, SSH tunnels)
- No shells & payloads section (msfvenom, web shells, AMSI bypass)
- Extremely long (4,372 lines) — difficult to use under exam time pressure
- No quick-reference cards at the top for rapid access
- Missing ADCS ESC1–ESC15 exploitation details (listed in TOC but attack steps are sparse)
- No iterative loop guidance ("after each foothold, restart from X")

**Unique Insights:**
- SCF file attack for NTLMv2 capture on writable shares (Phase 3.1.3)
- Responder `-A` (analyze-only) mode for safe passive recon
- PowerShell downgrade attack (`-Version 2`) to bypass AMSI/CLM/logging
- `adidnsdump` for finding hidden internal DNS records
- ADRecon and PingCastle for client-facing audit reports
- Comprehensive BloodHound custom Cypher query list

---

### 2. `academy_og/mimo_methodology.md` (6,633 lines, ~225 KB)

**Structure/Format:**
- 12 phases covering the FULL CPTS scope (28 Academy modules)
- Quick Reference Cards at the top (First 5 Minutes, Got Creds, Got Admin, Pivot)
- "Flow Reality" section explaining linear vs iterative exam behavior
- Phase cross-references (e.g., "see §11 for CMS exploitation")

**Key Strengths:**
- **Most complete single document** — covers every CPTS exam domain (web, AD, privesc, pivoting, services, applications)
- Quick Reference Cards are excellent for exam use — "first 5 minutes" and "got creds → spray everywhere" cards
- "Flow Reality" section is critical — explicitly states phases are iterative, not linear
- 6-Layer Enumeration Methodology (Internet Presence → Gateway → Services → Processes → Privileges → OS Setup)
- Injection Type Quick Reference (SQL, CMDi, LDAP, XPath, Code, Directory Traversal — all in one table)
- Burp Suite workflow patterns are exam-grade (session handling, match-and-replace, Intruder modes explained)
- Massive service enumeration coverage (FTP, SSH, SMTP, TFTP, SNMP, Oracle, IPMI, Rsync, R-Services, Telnet, Finger, Redis, MongoDB, Elasticsearch, Memcached, CouchDB, Java RMI/JDWP/JMX, Cassandra, RabbitMQ)
- GraphQL enumeration and introspection attacks included
- WAF detection before scanning (wafw00f)
- LFI/RFI bypass matrix with PHP wrappers, log poisoning, session poisoning, ZIP/PHAR wrappers
- Command injection bypass encyclopedia (space, slash, semicolon, case, reverse, base64, glob, wildcard bypasses)

**Gaps:**
- **Extremely long** (6,633 lines) — impractical as a quick-reference during an exam
- No personal experience annotations (e.g., "this worked on Lab X")
- Some sections are reference-only with no decision-tree guidance
- Missing explicit "I'm stuck" troubleshooting loops integrated per-phase
- ADCS exploitation details (ESC1–ESC15) are referenced but not fully fleshed out
- File transfer methods are mentioned but Phase 10B appears to be a stub
- Common Applications (Phase 11) coverage is referenced via cross-links but may be incomplete
- No exam-specific timing advice (how long to spend per phase)

**Unique Insights:**
- Vulnerability assessment workflow (Nessus → searchsploit → NVD → GitHub PoC → Metasploit chain)
- Audit log credential harvesting on Linux (`aureport --tty` for cleartext passwords)
- CVSS 3.1 risk severity triage (Critical → validate now, High → next 24h, etc.)
- IDS/IPS evasion techniques (source port 53, decoys, idle scan, fragmentation, FTP bounce scan)
- Second-order LFI attacks (poison DB entry → another function includes it)
- `allow_url_include` check via LFI + PHP filter to read `php.ini`

---

### 3. `CPTS_MEMORY.md` (112 lines, ~5 KB)

**Structure/Format:**
- 7 numbered sections — compact "DNA" summary
- High-level topic areas only (no deep commands)
- "I'm Stuck" loop at the top
- Labeled as "Refinement Pass 20 – Final Synthesis"

**Key Strengths:**
- **Extremely concise** — can be read in 2 minutes
- "I'm Stuck" loop is a critical mental model (re-enumerate → config review → local services → fallback vectors)
- Documentation standards section (always include `whoami`, `hostname`, `ipconfig/ifconfig`)
- Focus on *impact-based reporting* rather than just listing technical flaws
- Good as a pre-exam "mental warm-up" document

**Gaps:**
- **Too shallow** — almost no actionable commands
- No decision trees, no attack chains
- Missing pivoting details (mentions Ligolo-ng but no commands)
- Missing web attack vectors (no LFI, SQLi, CMDi, file upload)
- No ADCS, delegation abuse, or bleeding-edge CVEs
- No privesc enumeration beyond the basics (no capabilities, no path hijack, no DLL hijack)
- No service-specific enumeration (no FTP, SMTP, SNMP, NFS, etc.)
- Outdated tool references (`crackmapexec` instead of `netexec`)

**Unique Insights:**
- "Fallback vectors" concept: if `psexec` fails → try `wmiexec`; if `wget` fails → `certutil` or `bitsadmin`
- Command injection bypass techniques (space filters: `${IFS}`, `%09`; slash filters: `${PATH:0:1}`; blacklist bypass: `w'h'o'am'i`)

---

### 4. `AD Methodology.md` (1,422 lines, ~54 KB)

**Structure/Format:**
- 9 phases + Defensive Evasion + Quick Reference Tool Index
- Heavy use of ASCII decision trees at every phase
- Structured as "scenarios" with clear requirements/prerequisites
- Tool index table at the end with Phase mapping

**Key Strengths:**
- **Best decision-tree structure** — nearly every section starts with "YOU HAVE: X → DO: Y"
- Clean phase progression (External → Internal → Creds → Enum → Privesc → Lateral → Dominate → Trusts → Post)
- Cleanup checklist with specific revert commands
- Evidence collection checklist for reporting
- Defensive evasion section with practical OPSEC tips
- Event ID reference table (4625, 4768, 4769, 4771, 4697, etc.)
- Tool index with phase mapping — easy to find which tool to use when
- Cross-trust attacks well-covered (ExtraSids, cross-forest Kerberoasting, foreign group abuse)
- ACL abuse scenarios organized by ACE type (ForceChangePassword, GenericWrite, GenericAll, WriteDACL, WriteOwner)

**Gaps:**
- **AD-only** — same limitation as m3 file, no web/Linux/pivoting
- No web application attacks
- No Linux privilege escalation
- No service-specific enumeration (FTP, SMTP, NFS, etc.)
- No pivoting/tunneling
- No shells & payloads
- ADCS is mentioned but only PetitPotam + ESC8 is detailed — missing ESC1–ESC7, ESC9–ESC15
- No "Common Applications" section (WordPress, Jenkins, Tomcat, etc.)
- Missing gMSA dumping, RBCD detailed attack flow, Shadow Credentials
- No hashcat mode reference table

**Unique Insights:**
- WinRM Double-Hop fix via `Register-PSSessionConfiguration`
- `net1` instead of `net` to bypass basic command monitoring
- MSSQL lateral movement → `SeImpersonatePrivilege` → JuicyPotato/PrintSpoofer → SYSTEM chain
- AdminSDHolder persistence mechanism
- SID History abuse across forests when SID filtering is disabled
- `raiseChild.py` for fully automated child → parent domain escalation

---

### 5. `Ligolo-ng.md` (248 lines, ~6 KB)

**Structure/Format:**
- Step-by-step tutorial with numbered phases
- Multi-pivot scenario walkthrough (single → double → triple pivot)
- Screenshots referenced (Obsidian `![[Pasted image...]]` embeds)

**Key Strengths:**
- **Clear multi-pivot escalation** — shows how to chain 3 pivots using separate TUN interfaces
- Phase-by-phase breakdown (Install → TUN Setup → Proxy Start → Agent Deploy → Route → Verify)
- `listener_add` for chaining pivots through intermediate hosts
- Naming convention for interfaces (`ligolo`, `ligolo-double`, `ligolo-triple`)
- Includes Windows agent deployment path (`C:\Users\mlefay\AppData\Local\Temp\agent.exe`)

**Gaps:**
- **Single-tool focus** — no Chisel, SSH tunneling, sshuttle, dnscat2, or SocksOverRDP
- No reverse port forwarding with Ligolo
- No file transfer through the tunnel
- Missing `autoroute` command explanation (mentioned once but not detailed)
- No troubleshooting section (what if agent can't connect back?)
- No comparison with other pivoting tools
- Version-specific (v0.8.2) — may become outdated
- Typos in commands (`addd` instead of `add`, inconsistent `-adddr` flags)
- No OPSEC considerations for pivoting

**Unique Insights:**
- The triple-pivot pattern with dedicated TUN interfaces per network segment
- `listener_add` command for forwarding the proxy port through hop chains
- `autoroute` command as an alternative to manual `ip route add`

---

### 6. `WORKFLOW_GUIDE.md` (756 lines, ~26 KB)

**Structure/Format:**
- Beginner's guide for blog publishing workflow (Hugo + Obsidian)
- Step-by-step tutorial format with FAQ section
- Template descriptions (CTF walkthrough, tutorial, security analysis, quick reference)
- Troubleshooting section

**Key Strengths:**
- N/A for methodology purposes — this is a *blog publishing workflow*, not a pentest methodology
- However, the template structure (CTF walkthrough, tutorial, security analysis, quick reference) could inform how methodology notes are organized

**Gaps:**
- **Not a pentest methodology** — entirely about writing/publishing blog content
- No security content whatsoever

**Unique Insights (for methodology organization):**
- Template-based approach to structuring different types of content
- Front matter metadata pattern (categories, tags, difficulty, platforms, tools) could be adapted for methodology sections

---

### 7. `Comprehensive_Methodology.md` (254 lines, ~8 KB)

**Structure/Format:**
- 9 phases (Prep → Network Enum → Services → Web → AD → Exploitation → Post-Exploit → Privesc → Reporting)
- Compact, actionable format
- Uses `$IP` variable convention for consistency
- Core philosophy quote: "Distinguish between what we see and what we do not see"

**Key Strengths:**
- **Most concise actionable methodology** — every command is immediately usable
- Good balance between breadth and brevity
- `$IP` variable convention makes commands copy-paste ready
- Phase ordering is practical (services before web before AD — realistic engagement flow)
- Layer-based mental model (External → Perimeter → Services → Internal → Host)
- Nmap port extraction one-liner (`grep open | awk | tr | sed`)
- NFS `no_root_squash` exploitation mentioned (SUID binary upload)

**Gaps:**
- **Too shallow for exam use** — only 254 lines for all of CPTS
- No decision trees — flat command lists
- Missing ADCS, delegation, trust abuse, bleeding-edge CVEs
- No ACL abuse details
- Web attacks limited to basic LFI/SQLi mentions
- No command injection bypasses
- No file transfer matrix (just 3 basic methods)
- Pivoting section only covers SSH/Chisel/sshuttle — no Ligolo-ng
- No "I'm stuck" loop or iterative methodology
- No credential theft catalogue
- No BloodHound query list
- No Burp Suite workflow
- No service-specific enumeration beyond basics

**Unique Insights:**
- `$IP` variable convention — simple but effective for rapid command execution
- Clean nmap output → targeted scan workflow (`allports.nmap` → extract ports → `detailed` scan)
- Mental model layers (5-layer visualization) — simpler than 6-layer version

---

### 8. `0. Prep.md` (14 lines, ~577 bytes)

**Structure/Format:**
- Simple checklist with checkboxes
- Links to external resources (IppSec, HTB Academy, TryHackMe)
- Cross-references to other notes via Obsidian wikilinks

**Key Strengths:**
- **Clear preparation roadmap** — lists exactly what to complete before attempting CPTS
- References IppSec's unofficial CPTS prep playlist
- Includes Pro Labs (P.O.O, Dante) and practical exercises
- TryHackMe "Attacking Enterprises" room as end-to-end methodology practice

**Gaps:**
- **Not a methodology** — just a prep checklist
- No timeline or priority order
- No study strategy (spaced repetition, weak-area focus, etc.)
- No module-by-module completion tracking
- No lab environment setup instructions
- Missing links to tools/resources needed

**Unique Insights:**
- "Run your own methodology end-to-end with no hints" — the ultimate test of exam readiness
- Dante Pro Lab as a realistic multi-machine practice environment

---

## Cross-File Comparison Matrix

| Capability | m3_AD | MIMO | MEMORY | AD_Meth | Ligolo | Workflow | Comp_Meth | Prep |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **External Recon** | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Network Enum** | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Web Enum** | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Web Attacks (LFI/SQLi/CMDi)** | ❌ | ✅ | ⚠️ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| **Service Attacks** | ⚠️ | ✅ | ⚠️ | ⚠️ | ❌ | ❌ | ✅ | ❌ |
| **AD Attacks** | ✅ | ✅ | ⚠️ | ✅ | ❌ | ❌ | ⚠️ | ❌ |
| **ADCS (ESC1–ESC15)** | ⚠️ | ⚠️ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ |
| **Privesc (Linux)** | ❌ | ✅ | ⚠️ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Privesc (Windows)** | ⚠️ | ✅ | ⚠️ | ⚠️ | ❌ | ❌ | ✅ | ❌ |
| **Pivoting** | ❌ | ✅ | ⚠️ | ❌ | ✅ | ❌ | ⚠️ | ❌ |
| **Shells & Payloads** | ❌ | ✅ | ⚠️ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **File Transfers** | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Common Applications** | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Decision Trees** | ✅ | ⚠️ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Quick Ref Cards** | ⚠️ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Iterative Loop** | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Reporting** | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ⚠️ | ❌ |
| **Cleanup** | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ⚠️ | ❌ |

> ✅ = Comprehensive | ⚠️ = Partial/Shallow | ❌ = Missing

---

## What Works Well

### 1. Decision-Tree Methodology (m3_AD, AD_Methodology)
The ASCII decision trees are the single most effective structural pattern. They answer "what do I do next?" instantly based on current state. **This should be the foundation of any unified methodology.**

### 2. Quick Reference Cards (MIMO)
The "First 5 Minutes", "Got Creds", "Got Admin", and "Pivot" cards are invaluable under exam time pressure. **Every phase should have a 10-line quick-ref card.**

### 3. Iterative Flow Awareness (MIMO, CPTS_MEMORY)
The explicit acknowledgment that phases are NOT linear and that each foothold restarts the loop is critical for exam success. The "I'm Stuck" loop from CPTS_MEMORY is a must-keep.

### 4. Dual-Platform Commands (m3_AD)
Showing Linux AND Windows commands side-by-side is exam-realistic and prevents the "I only know how to do this from Linux" problem.

### 5. Credential Theft Catalogue (m3_AD)
The 12-subcategory credential theft enumeration ensures no credential source is missed. This level of detail is what separates passing from failing.

### 6. Phase-Appropriate Tool Selection (AD_Methodology)
The tool index table with phase mapping is immediately useful — "I'm in Phase 4, which tools do I need?"

### 7. `$IP` Variable Convention (Comprehensive_Methodology)
Simple but effective — makes every command copy-paste ready with minimal modification.

---

## Gaps & Areas for Improvement

### Critical Gaps (Would Cause Exam Failure)

| Gap | Files Affected | Impact |
|---|---|---|
| **No unified methodology covering ALL domains** | All files | Each covers part of the exam; no single reference covers everything |
| **ADCS ESC1–ESC15 exploitation** | All files | Listed in TOCs but attack steps are minimal or missing |
| **Delegation abuse (RBCD, constrained, unconstrained)** | All except partial MIMO | Key AD privesc path with incomplete coverage |
| **Shadow Credentials (Whisker/pyWhisker)** | All | Modern AD attack path not detailed |
| **gMSA password dumping** | All except MIMO quick-ref | Mentioned in 1 line, no full attack flow |
| **Common Applications deep-dive** | All except MIMO (refs only) | WordPress/Jenkins/Tomcat/Splunk exploitation |
| **Password attacks module** | Missing dedicated section | Hashcat rules, john, pattern generation, mutation |
| **File transfer matrix** | Incomplete everywhere | No comprehensive table of all transfer methods per OS |

### Structural Gaps

| Gap | Impact |
|---|---|
| **No tiered document system** (quick-ref → medium → deep-dive) | Forces reading 4,000+ lines for a single technique |
| **No "per-foothold" checklist** | After getting a shell, what are the first 10 things to check? |
| **No exam timing guidance** | How long to spend on each phase before moving on |
| **No troubleshooting / "what if this fails"** per technique | Decision trees show happy path but not failure recovery |
| **No credential tracking template** | No standard format for recording discovered creds |
| **No host tracking template** | No standard format for recording compromised hosts |

### Missing Techniques

- **SCCM/MECM/WSUS abuse** (covered in CPTS modules)
- **Thick client testing** (decompilation, traffic interception)
- **LDAP injection** (beyond basic filter)
- **NoSQL injection** (MongoDB, CouchDB)
- **JWT attacks** (none/alg confusion, key injection, claim modification)
- **Mass assignment / IDOR / verb tampering** (web attacks)
- **XXE (XML External Entity)** attacks
- **SSRF (Server-Side Request Forgery)** attacks
- **Citrix breakout** (mentioned in MIMO TOC but no content)
- **AV/AMSI bypass techniques** (beyond PowerShell downgrade)

---

## Unique Insights Worth Preserving

These are techniques and tips that appear in only one file and should not be lost in any consolidation:

| Insight | Source | Why It Matters |
|---|---|---|
| SCF file attack on writable SMB shares | m3_AD | NTLMv2 capture without LLMNR poisoning |
| `aureport --tty` for cleartext passwords in audit logs | MIMO | Rare cred source often overlooked |
| Second-order LFI (poison DB entry → another function includes it) | MIMO | Advanced LFI variant for hardened apps |
| WinRM Double-Hop fix (`Register-PSSessionConfiguration`) | AD_Meth | Solves a common exam frustration |
| AdminSDHolder persistence | AD_Meth | Stealthy persistence mechanism |
| Triple-pivot with dedicated TUN interfaces | Ligolo | Practical multi-network pivoting |
| `listener_add` for hop chain forwarding | Ligolo | Key for multi-hop pivoting |
| Fallback vectors (psexec → wmiexec, wget → certutil) | MEMORY | Mental model for tool failure recovery |
| `net1` bypass for command monitoring | AD_Meth | Simple OPSEC trick |
| Pre-spray `badpwdcount=0` filtering | m3_AD | Prevents accidental lockouts |
| `allow_url_include` check via LFI + PHP filter | MIMO | Determines RFI/data/input/expect viability |
| "Run your own methodology end-to-end with no hints" as readiness test | Prep | The ultimate self-assessment |
| Blog template structure (ctf-walkthrough, tutorial, etc.) | Workflow | Could inform methodology section organization |

---

## Recommendations

### 1. Build a Three-Tier Document System
- **Tier 1 — Quick Reference** (~50 lines per domain): Decision trees + top 3 commands per scenario. Print-friendly.
- **Tier 2 — Operational Playbook** (~500 lines per domain): Full attack chains with decision trees, copy-paste commands, and failure recovery.
- **Tier 3 — Deep Reference** (current m3/MIMO level): Complete technique encyclopedia. Consulted only when Tier 2 doesn't have the answer.

### 2. Unify Around Decision Trees
Adopt the `AD Methodology.md` decision-tree pattern as the universal structure. Every section should start with:
```
YOU HAVE: [current state]
├── Condition A → Action A
├── Condition B → Action B
└── Nothing works → Fallback actions
```

### 3. Add Per-Foothold Restart Checklist
After every new shell, run this checklist:
```
□ whoami / hostname / ipconfig-ifconfig (screenshot)
□ Check user privileges (sudo -l / whoami /priv)
□ Check network interfaces (new subnets?)
□ Dump credentials (SAM/shadow/memory/history)
□ Check for domain join (AD attacks applicable?)
□ Check internal services (127.0.0.1 listeners)
□ Transfer enumeration tools
□ Run automated enumeration (linpeas/winpeas)
```

### 4. Fill the ADCS Gap
Create a dedicated ADCS section covering ESC1 through ESC15 with:
- Detection commands (certipy/Certify)
- Exploitation steps
- Post-exploitation (certificate → TGT → auth)

### 5. Create a Credential Tracking Template
```
| Timestamp | Username | Password/Hash | Type | Source | Tested Against | Result |
```

### 6. Add Exam Timing Guidance
```
Phase 1 (Recon/Enum): 30-60 min max
Web Attack per target: 45-60 min before pivoting to another vector
Password Cracking: run in background, check periodically
"I'm stuck" threshold: 30 min → trigger stuck loop
```

---

*Analysis compiled from 8 source files totaling ~12,000+ lines and ~474 KB of content.*
