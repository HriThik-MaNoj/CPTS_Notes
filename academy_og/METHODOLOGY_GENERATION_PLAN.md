# CPTS Methodology Generation — Execution Plan

## 1. Current State Assessment

### What Exists
- **28 raw HTB Academy notes** (scraped markdown, ~464 files including 428 images)
- **1 existing methodology** (`mimo_methodology.md`) — 13-phase decision-tree, ~20K+ words
- **No cross-references** between individual notes
- **Flat structure** — all files at root, no modular organization

### What's Missing
- Notes are **reference material**, not an operational methodology
- No decision trees that answer "why" and "what next" — only the existing methodology has this
- No modular breakdown — can't use "just the AD section" independently
- No cross-references between modules ("when you find X during web testing, see AD section for Y")

---

## 2. Methodology Generation Workflow

### Phase 1: Note Chunking & Topic Mapping

**Goal:** Break the 28 notes into machine-extractable chunks and map each to a CPTS topic/skill.

**Process:**
1. Process each of the 28 notes through a chunking pass:
   - Split by H2 headings (major sections)
   - Extract: section title, tools used, attack types, commands, decision indicators
   - Tag each chunk with: `topic`, `phase`, `prerequisites`, `outputs` (what it produces)
2. Create a **topic map** that shows which note covers which CPTS exam domain
3. Identify overlap between notes (e.g., SQLi appears in both SQLi Fundamentals and Web Attacks)

**Output:** `00_topic_master_index.md` — every chunk mapped to phase + topic + source note

### Phase 2: Technique Extraction & Normalization

**Goal:** Extract standalone techniques from notes, normalize naming, remove redundancy.

**Process:**
1. For each chunk, extract a structured record:
   ```
   technique: Kerberoasting
   source_note: Active Directory Enumeration & Attacks.md
   sub_phase: 09-AD
   prerequisites: [domain credentials, SPN discovery]
   tools: [impacket-GetUserSPNs, Rubeus, BloodHound]
   commands: |
     impacket-GetUserSPNs -dc-ip <DC> <domain>/<user>:<pass> -request
   evidence_triggers: [Service Principal Name, SPN, service account]
   success_next: [crack TGS with hashcat, Silver Ticket]
   failure_next: [check delegation, check AS-REP]
   ```
2. Deduplicate: if SQLi extraction appears in multiple notes, merge into one canonical entry
3. Resolve conflicts: if two notes disagree on a command flag, resolve by CPTS exam convention
4. Tag each technique with preconditions and postconditions

**Output:** `01_technique_library.md` — ~200-300 normalized technique entries

### Phase 3: Decision Tree Construction

**Goal:** For each technique and phase, build branching decision logic.

**Process:**
1. For each technique, create a decision tree starting from its trigger condition:
   ```
   Port 445 open?
   ├── Yes → Enumerate SMB
   │   ├── Anonymous/Null session?
   │   │   ├── Yes → enum4linux, smbclient -L, rpcclient
   │   │   │   ├── Accessible shares?
   │   │   │   │   ├── Read → download sensitive files (Phase 12 loot)
   │   │   │   │   └── Write → upload webshell/malicious files
   │   │   │   └── No → check SMB version for vulns
   │   │   └── No → try credentials (Phase 5)
   │   └── Credentials found?
   │       ├── Yes → netexec, smbmap, psexec
   │       └── No → check for NTLM relay (SMB signing?)
   └── No → continue service enumeration
   ```
2. Add explicit "if X fails, try Y" branches
3. Add cross-references to other phases (e.g., "if you get creds → Phase 5 Password Attacks")
4. Format decision trees as ASCII trees (consistent with existing `mimo_methodology.md` style)

**Output:** One decision tree file per phase

### Phase 4: Modular Methodology Construction

**Goal:** Write individual methodology modules that are independently usable.

**Process:**
1. Create one file per phase using the template (see Section 5)
2. Populate from normalized techniques + decision trees
3. Add "Cross-References" section at the bottom of each module
4. Add "When do I use this module?" preamble
5. Add "What did I get from this module?" output summary

**Output:** `modules/01-info-gathering.md` through `modules/14-exam-strategy.md`

### Phase 5: Master Methodology Assembly

**Goal:** Tie all modules into a single master workflow.

**Process:**
1. Create the master `MASTER_METHODOLOGY.md` with:
   - Overall penetration testing lifecycle diagram
   - Phase transition rules (when to move from Phase 2 to Phase 3 vs. loop back)
   - Parallel execution guidance (when to run Phase 5 in parallel with Phase 7)
   - Decision routing table: "If you found X in Phase N, go to Phase M"
2. Each section in the master file is a link/reference to the individual module
3. Add exam-specific flow: "Typical CPTS exam path" overlay

**Output:** `MASTER_METHODOLOGY.md` — ~10-15 pages, high-level workflow manager

### Phase 6: Quality Assurance

**Goal:** Verify completeness and correctness.

**Checks:**
1. **Coverage scan**: Compare technique library against CPTS exam objectives from `modules.txt`
2. **Gap analysis**: Are there techniques in the notes that aren't in the methodology?
3. **Decision tree validation**: Every branch must end in either an action or a reference
4. **Cross-reference audit**: Every module references the correct sibling modules
5. **Redundancy check**: No duplicate technique entries across modules
6. **Readability test**: Can a fresh reader follow the decision tree without prior context?

---

## 3. Folder Structure

```
academy_og/
├── MASTER_METHODOLOGY.md              # Top-level workflow orchestrator
├── 00_topic_master_index.md           # Topic-to-note mapping
├── 01_technique_library.md            # All normalized techniques
│
├── modules/
│   ├── 00-pre-engagement.md           # Scope, RoE, setup, tool checklist
│   ├── 01-info-gathering.md           # OSINT, DNS, passive recon
│   ├── 02-enumeration.md              # Nmap, service fingerprinting, footprinting
│   ├── 03-vuln-assessment.md          # Nessus, OpenVAS, CVE research
│   ├── 04-web-application.md          # Full web app testing (LFI, SQLi, XSS, etc.)
│   ├── 05-initial-access.md           # Shells, payloads, exploits
│   ├── 06-password-attacks.md         # Cracking, spraying, hashcat, john
│   ├── 07-common-services.md          # FTP, SMB, MSSQL, MySQL, RDP, etc.
│   ├── 08-common-apps.md              # CMS, Tomcat, Jenkins, Splunk, etc.
│   ├── 09-linux-privesc.md            # Linux privilege escalation
│   ├── 10-windows-privesc.md          # Windows privilege escalation
│   ├── 11-active-directory.md         # Full AD attack chain
│   ├── 12-lateral-pivot.md            # Lateral movement, pivoting, tunneling
│   ├── 13-post-exploitation.md        # Credential harvesting, data collection
│   ├── 14-reporting.md                # Documentation, reporting templates
│   ├── 15-exam-strategy.md            # CPTS exam-specific guidance
│   └── _template.md                   # Empty module template
│
├── decision-trees/
│   ├── ad-attack-flow.md              # Visual AD attack path map
│   ├── web-attack-flow.md             # Web app decision flow
│   ├── privesc-flow.md                # OS privilege escalation flow
│   └── pivot-flow.md                  # Pivoting decision flow
│
└── assets/
    ├── cheatsheets/
    │   ├── nmap-cheatsheet.md
    │   ├── hashcat-cheatsheet.md
    │   ├── netexec-cheatsheet.md
    │   └── msfvenom-cheatsheet.md
    ├── templates/
    │   ├── finding-template.md
    │   └── report-template.md
    └── exam/
        ├── time-budget.md
        └── common-attack-chains.md
```

---

## 4. Module Template

```markdown
# Module N: [Phase Name]

## When to Use This Module
One paragraph explaining: what triggers this phase, what input you need, what you expect to get.

## Prerequisites
- What must already be true before entering this phase
- Previous phase outputs required (e.g., "valid credentials from Phase 6")

## Tools Required
- Tool list with one-line purpose (not full documentation)

## Decision Flow

### Entry Check
```
Trigger condition?
├── Yes → What to do
│   ├── Result A → next action (→ see subsection below)
│   │   ├── Succeeds → where to pivot (→ Phase X)
│   │   └── Fails → fallback (→ alternative subsection)
│   └── Result B → different path
└── No → skip (→ Phase Y)
```

### [Technique Group 1]: [Name]

**When to use:** One-line decision trigger.

**Why this technique:** What it accomplishes and what it reveals.

```
Decision tree for this technique
├── Branch → action
│   ├── Sub-branch → tool/command
│   └── Alternative → tool/command
└── Dead end → where to go next
```

**Commands:**
```bash
# Purpose of command
command_here
```

**What to look for:**
- Finding — what it means, next step

## Cross-References
- When you obtain credentials → [Phase 6: Password Attacks](../modules/06-password-attacks.md)
- When you find a domain-joined host → [Phase 11: Active Directory](../modules/11-active-directory.md)

## Output Summary
What you should have when this phase is complete:
- [ ] List of findings
- [ ] Credentials obtained
- [ ] Access level achieved
- [ ] Next phase to execute
```

---

## 5. Decision Tree Design Principles

### 5.1 Entry-Exit Contract
Every decision tree must have:
- **Entry condition**: What fact or finding triggers this decision branch
- **Exit condition**: What the operator has when the branch resolves

### 5.2 Branch Types

| Branch Type | Syntax | Meaning |
|---|---|---|
| Yes/No | `├── Yes →` / `└── No →` | Binary check |
| Value | `├── Port 445 →` | Specific value match |
| Action | `├── Crack hash →` | Do this, then branch on result |
| Reference | `├── → [Phase 9](...)` | Go to another phase |

### 5.3 Decision Tree Rules
1. Every branch must lead to an action or a dead-end reference
2. Dead-ends must explicitly state "move to Phase X" — never leave the operator stuck
3. At most 4-5 levels deep per tree; deeper logic gets a subsection
4. Tool choices must be justified by the branch condition (not listed arbitrarily)
5. Parallel branches (e.g., "crack hash AND SMB enum simultaneously") must be marked

### 5.4 Cross-Reference Rules
- Every module must reference at least 2 other modules
- Cross-references are placed at the bottom AND inline where triggered
- Format: `→ [Phase N: Name](path)` — clickable in file tree

---

## 6. Consistency Strategy

| Aspect | Rule |
|---|---|
| Naming | Pascal case for modules (`01-Info-Gathering.md`), lowercase for assets |
| Tool references | First mention: full tool name. Subsequent: short name |
| Commands | Always include explanation comment line above |
| Decision trees | ASCII box-drawing characters (`├── └── │`) |
| Severity levels | Critical/High/Medium/Low (CVSS 3.1) |
| Cross-file refs | Relative path from `modules/` directory |
| Heading levels | H1 = module title, H2 = technique groups, H3 = techniques |
| Code blocks | `bash` for Linux, `powershell` for Windows, `shell` for generic |

---

## 7. Quality Assurance Process

### 7.1 Per-Module QA Checklist
- [ ] Every technique has an entry trigger (what finding activates it)
- [ ] Every decision branch ends in an action or reference
- [ ] All tools mentioned are justified (no "try this because reasons")
- [ ] All commands include purpose-comment lines
- [ ] Cross-references to at least 2 other modules
- [ ] "Output Summary" checklist is populated
- [ ] Decision tree is <= 5 levels deep

### 7.2 Cross-Module QA
- [ ] No duplicate technique entries across modules
- [ ] References between modules are bidirectional
- [ ] Phase ordering is consistent (no "go to Phase X" where X doesn't exist)
- [ ] Terminology is consistent (e.g., "lateral movement" vs "pivoting" usage)

### 7.3 Coverage Verification
Against `modules.txt` (28 HTB Academy URLs):
- [ ] Every module's key topics appear in the technique library
- [ ] Every major attack type (SQLi, XSS, Kerberoast, etc.) has a decision tree
- [ ] Missing techniques flagged for manual addition

### 7.4 Gap Detection
When building from notes, track anything that doesn't fit a decision tree shape:
- **Theoretical content** → move to "Background" section of module
- **Generic advice** → move to "Strategy" section
- **Too tool-specific** → attach as cheatsheet in `assets/cheatsheets/`
- **Outdated** → flag with `⚠️ Legacy (pre-2023)`

---

## 8. Generation Order

Process notes in 14 iterations, each producing one or more module files:

| It | Notes | Produces |
|---|---|---|
| 1 | Getting Started, Pen Testing Process | 00-pre-engagement, 15-exam-strategy |
| 2 | Nmap, Footprinting, Info Gathering (Web) | 01-info-gathering, 02-enumeration |
| 3 | Vuln Assessment, Documentation & Reporting | 03-vuln-assessment, 14-reporting |
| 4 | Ffuf, Web Proxies, Login Brute Forcing | Web proxy section (04) |
| 5 | SQLi Fundamentals, SQLMap Essentials | SQLi section (04) |
| 6 | XSS, File Inclusion, Command Injections | Injection sections (04) |
| 7 | File Upload Attacks, Web Attacks | Attack sections (04) |
| 8 | Shells & Payloads, File Transfers, MSF | 05-initial-access |
| 9 | Password Attacks | 06-password-attacks |
| 10 | Common Services, Common Apps | 07-common-services, 08-common-apps |
| 11 | Linux PrivEsc, Windows PrivEsc | 09-linux-privesc, 10-windows-privesc |
| 12 | Active Directory | 11-active-directory |
| 13 | Pivoting, Tunneling, Port Forwarding | 12-lateral-pivot, 13-post-exploitation |
| 14 | Attacking Enterprise Networks | Full integration + master assembly |

After iteration 14, merge all into the master methodology with cross-references.

---

## 9. Relationship to `mimo_methodology.md`

The existing `mimo_methodology.md` serves three roles:
1. **Reference model** — demonstrates the decision-tree style and depth to match
2. **Consistency check** — compare module output against existing content for completeness
3. **Not the source** — raw notes contain primary details; the methodology may have simplified

Use it to validate, not to generate. Each module should be built from the raw notes first, then cross-checked against `mimo_methodology.md` for anything missed.
