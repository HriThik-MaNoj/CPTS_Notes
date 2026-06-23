# Module 14: Documentation & Reporting

## When to Use This Module
Use this module from Phase 0 through the entire engagement. Documentation is NOT a phase you start at the end — it's a continuous process from the first Nmap scan to the final deliverable. This module covers note-taking structure, evidence collection, report components, and the findings format.

## Prerequisites
- All testing completed (this module synthesizes everything)
- Folder structure created (from Module 00)
- Tmux/logging configured before testing began

## Entry Check

```
Testing complete?
├── Yes → Begin report assembly
│   ├── Notes organized? → Map notes to finding templates
│   └── Screenshots collected? → Organize by finding
└── No → Continue testing, document as you go
     Never try to reconstruct evidence after testing
```

## Continuous Documentation (During Testing)

### Folder Structure

Create this structure BEFORE testing begins:

```
Client_Name/
├── Admin/                          # Scope docs, contracts, meeting notes
├── Deliverables/                   # Draft reports, final reports
└── Evidence/
    ├── Findings/                   # One folder per finding
    ├── Logging output/             # Tmux logs, tool logs
    ├── Misc Files/                 # Shells, payloads, custom scripts
    ├── Notes/                      # Daily activity, research notes
    ├── OSINT/                      # Passive recon output
    └── Scans/
        ├── AD Enumeration/        # BloodHound JSON, LDAP dumps
        ├── Service/               # Nmap, Masscan, Rumble exports
        ├── Vuln/                  # Nessus/OpenVAS exports
        └── Web/                   # Burp state files, Eyewitness, Aquatone
```

### Note Sections (per engagement)

```
1. Administrative Information  — POCs, objectives, to-do list
2. Scoping Information         — In-scope IPs, URLs, provided creds
3. Activity Log                — High-level daily tracking
4. Payload Log                 — File hashes, upload paths, cleanup status
5. OSINT Data                  — External recon findings
6. Credentials                 — Centralized credential store
7. Web Application Research    — Interesting endpoints, tested paths
8. Vulnerability Scan Research — Triage notes
9. Service Enumeration Research — Failed attempts, promising leads
10. AD Enumeration Research    — Step-by-step enumeration tracking
11. Attack Path                — Full chain from foothold to DA
12. Findings                   — Drafts of each finding
```

### Tmux Logging

```bash
# Install tmux logging plugin
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm

# Configure .tmux.conf
cat ~/.tmux.conf
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'
set -g history-limit 50000
run '~/.tmux/plugins/tpm/tpm'

# Start logging: prefix + Shift+P
# Stop logging: prefix + Shift+P (toggles)
# Retroactive capture: prefix + Alt+Shift+P
# Pane screenshot: prefix + Alt+P
```

### What to Screenshot

```
For EVERY significant step:
├── The command you ran
├── The output you received
├── Both in one screenshot frame (cmd + output)
├── Including IP, hostname, user context
└── Save to: Evidence/Findings/<finding-name>/
```

## Report Structure

### Executive Summary
- 1-2 pages, non-technical audience
- Engagement scope (what was tested, dates)
- Highest-impact findings (3-5 bullets, business risk language)
- Risk distribution chart (Critical/High/Medium/Low counts)
- Strategic recommendations (3-5 bullets)

### Scope & Testing Overview
- In-scope assets (IPs, domains, applications)
- Out-of-scope (explicit exclusions)
- Testing window (start/end timestamps)
- Methodology framework (PTES, OWASP)
- Limitations / constraints

### Attack Chain
A narrative walkthrough of the full exploitation path:
```
Initial foothold → Privilege escalation → Lateral movement → DA/crown jewel
```

Write this as a story with supporting command output and screenshots. Show how individual findings combine to create risk.

Example structure:
```
Step 1: Responder captures NTLMv2 hash for domain user  
Step 2: Hashcat cracks hash → cleartext password  
Step 3: BloodHound reveals Kerberoastable accounts  
Step 4: GetUserSPNs retrieves TGS ticket  
Step 5: Crack TGS → SQL admin credentials  
Step 6: Authenticate to SQL server, extract LSA secrets  
Step 7: Found creds have DCSync rights → domain compromise
```

### Findings Detail

```
Each finding follows this template:

Title: [Descriptive name, e.g., "Unauthenticated SQL Injection in /search"]
Severity: [CVSS 3.1 score + vector string]  
CWE: [CWE classification]
Affected Asset(s): [IP/hostname/URL]
Description: [Technical explanation of the issue]
Impact: [What an attacker gains — business + technical terms]
Evidence: [Commands + screenshots, numbered]
Reproduction Steps: [1, 2, 3 — runnable by client]
Remediation: [Specific, not "patch the software"]
References: [CVE, CWE, vendor advisory, OWASP]
```

### Findings Evidence Guidelines

```
Terminal evidence:
├── Use TEXT output (copy/paste) over screenshots when possible
├── Redact credentials with <REDACTED> or black bars (NOT blurring)
├── Shorten output with <SNIP> where appropriate
├── Highlight commands in blue, interesting output in red
└── Never alter actual output — strip formatting before pasting

Screenshot evidence:
├── Use solid black bars for redaction (NOT pixelation/blur)
├── Add arrows/boxes to highlight relevant content
├── Show address bar in browser screenshots
├── Crop to relevant content only
└── Add minimal border around image
```

### Appendices

```
A: Host Inventory (IP/hostname/OS/services/access level)
B: Credential Inventory (user, cleartext/hash, source, where reused)
C: Exploitation Timeline (timestamped chronology)
D: Tools Used (with versions)
E: Raw Scan Data (nmap, BloodHound exports)
F: References + Further Reading
```

## Post-Engagement Cleanup

```
Testing concluded?
├── Remove ALL uploaded files from target systems
│   ├── Web shells
│   ├── Payloads
│   ├── Custom scripts
│   └── Accounts created
├── Document any changes made that couldn't be reverted
├── Note file paths and cleanup status for client
└── Verify nothing persists that could be exploited
```

## Deliverable Types

### Draft Report
- Submit to client for feedback
- Allow time for client review
- Schedule readout meeting

### Final Report
- Incorporate client feedback
- Issue formal final version
- This is what compliance auditors accept

### Post-Remediation Report
- Retest ONLY the findings from the original report
- Do NOT rescan the entire environment
- Tag each finding: Resolved / Unresolved / Partially Resolved
- Set time limit on how long after original assessment retesting occurs

### Attestation Letter
- 1-2 page summary suitable for third parties
- Number of findings, approach taken, general comments
- NO technical details, credentials, or sensitive information

### Spreadsheet of Findings
- Tabular layout for client ticketing systems
- All finding fields, sortable by severity/category
- Use pivot tables for analytics

## Quality Assurance

```
Before submitting any deliverable:
├── Spelling and grammar check (entire document)
├── Verify all screenshots are legible and properly cropped
├── Redact ALL credentials and PII
├── Verify reproduction steps work when followed exactly
├── Check CVSS scores are accurate
├── Confirm findings match evidence provided
├── Remove any placeholder text
└── Have a second reviewer (if available)
```

## Cross-References
- Pre-engagement documentation → [Module 00: Pre-Engagement](00-pre-engagement.md)
- Finding generation from scanner data → [Module 03: Vulnerability Assessment](03-vuln-assessment.md)
- Evidence screenshots from attacks → [Module 05-13 as applicable]
- Report templates → [assets/templates/](../assets/templates/)

## Output Summary
- [ ] Continuous notes maintained throughout testing
- [ ] Tmux logging enabled from day one
- [ ] All evidence organized in structured folders
- [ ] Attack chain documented step-by-step
- [ ] All findings formatted with CVSS scores
- [ ] Screenshots taken, cropped, and redacted
- [ ] Draft report submitted to client
- [ ] Final report issued after feedback
- [ ] Cleanup performed on all target systems
