# CPTS Methodology — Phase 3 Final Audit

## Assessment Methodology

This audit re-evaluates the methodology after Phase 3 (Exam Operationalization) additions. Each category is scored 1-10 against the target of 9+. Categories below 9/10 include specific actions required to reach 9+.

---

## Overall Score

```
Phase 2 Score:  6.3/10  (Pre-Attack Graph)
Phase 3 Score:  8.6/10  (Post-Exam Operationalization)
Target:         9.0/10+ (Exam-Ready)
Gap:            0.4/10  (6 actionable items below)
```

---

## Category Scores

### Coverage — Score: 9/10 ✓

| Sub-category | Score | Assessment |
|-------------|-------|------------|
| Service attacks | 9 | All CPTS-relevant services covered across Module 07 + enumeration-completeness.md |
| Web attacks | 9 | SQLi, LFI, File Upload, CMDi, XSS, SSRF, XXE all documented |
| AD attacks | 9 | Kerberoast, AS-REP, ACL, Delegation, ADCS, Trusts, Shadow Creds all present |
| Linux privesc | 9 | sudo, SUID, caps, cron, kernel, containers, pspy documented |
| Windows privesc | 9 | Tokens, services, potato, UAC, AlwaysInstallElevated documented |
| Password attacks | 9 | Hashcat modes, spraying, wordlist gen, rules all covered |

**Remaining gaps:** Coverage of cloud token exploitation (AWS metadata) is minimal. Container escape techniques could be deeper. Both are rare in CPTS. Acceptable at 9.

**To reach 10/10:** Add cloud metadata SSRF exploitation path to Module 04. Add Docker → host escape matrix to Module 09.

---

### Attack Graph Completeness — Score: 9/10 ✓

| Sub-category | Score | Assessment |
|-------------|-------|------------|
| Finding-to-action index | 9 | Module 99 covers all major findings with structured sections |
| Credential flow | 10 | New credential-reuse-matrix.md + loot-priority-framework.md provide full coverage |
| Attack path mapping | 9 | New high-probability-paths.md ranks 20 chains by frequency, difficulty, time, payoff |
| Stuck matrix | 10 | Three detailed stuck checklists (initial access, privesc, AD) in Module 99 |
| Alternative paths | 8 | Every module finding has "If This Fails" section, but depth varies |

**Remaining gaps:** Alternative path depth varies across modules. Some "If This Fails" sections have 1-2 options while others have 5+. Need consistent minimum of 3 alternatives per finding.

**To reach 10/10:** Audit all "If This Fails" sections across modules/ to ensure minimum 3 alternatives. Standardize format across all 20+ findings in Module 99.

---

### Enumeration Completeness — Score: 9/10 ✓

| Sub-category | Score | Assessment |
|-------------|-------|------------|
| Service enumeration depth | 10 | New enumeration-completeness.md defines MIN/REC/DEEP for 20+ services |
| Prioritization | 9 | New dashboard + execution playbook define enumeration order |
| Sensitivity | 9 | No missed findings for standard CPTS services |
| Special enumerations | 8 | ADCS, LAPS, gMSA, BloodHound all covered but could have more depth |

**Remaining gaps:** ADCS enumeration depth is good but ESC scenarios 4-7 have limited command examples. Some LDAP-specific enumeration techniques (like finding GPO GUIDs) are missing.

**To reach 10/10:** Add command-level detail for ADCS ESC4-7 in Module 11. Add LDAP GPO GUID enumeration to enumeration-completeness.md.

---

### AD Completeness — Score: 9/10 ✓

| Sub-category | Score | Assessment |
|-------------|-------|------------|
| Attack coverage | 9 | All major AD attacks covered: ACL, Kerberoast, AS-REP, delegation, ADCS, trusts |
| BloodHound integration | 9 | BloodHound analysis workflow documented with specific edge types |
| Credential flow | 10 | Full domain credential → AD attack chain mapped in credential-reuse-matrix.md |
| ADCS depth | 9 | ESC1-3, 8-10 covered with commands. ESC4-7 present but lighter. |
| Special attacks | 8 | Shadow Credentials, gMSA, LAPS, DNS Admin abuse all present but could have more execution detail |

**Remaining gaps:** Shadow Credentials need more step-by-step examples. DNS Admin → DC compromise chain lacks full command sequences.

**To reach 10/10:** Add full Shadow Credentials exploitation walkthrough (Whisker/ADFS) to Module 11. Complete DNS Admin → DC abuse chain with certipy and mimikatz commands.

---

### PrivEsc Completeness — Score: 9/10 ✓

| Sub-category | Score | Assessment |
|-------------|-------|------------|
| Linux coverage | 9 | All major vectors covered (sudo, SUID, caps, cron, kernel, containers) |
| Windows coverage | 9 | All major vectors covered (tokens, services, potato, UAC, auto-elevate) |
| Tool integration | 9 | linpeas, winpeas, pspy, GTFOBins all integrated |
| Latest techniques | 8 | Some newer Windows privesc techniques (Like NoPac for privesc, Certifried) could be deeper |
| Automation | 8 | No automated "run all privesc checks" script defined for CPTS exam speed |

**Remaining gaps:** Missing a "run-all" one-liner that does a comprehensive privesc sweep. Some newer kernel exploits not listed (specifically 2024-2025 Linux CVEs).

**To reach 10/10:** Create a "one-shot privesc sweep" command block for both Linux and Windows that a candidate can copy-paste. Add recent Linux kernel exploit CVEs to Module 09.

---

### Credential Attack Coverage — Score: 10/10 ✓

| Sub-category | Score | Assessment |
|-------------|-------|------------|
| Hash types | 10 | All CPTS-relevant hash modes (1000, 5600, 13100, 18200, 1731, 300, 13000) defined |
| PTH support | 10 | Full PTH commands for SMB, WinRM, RDP, WMI in credential-reuse-matrix.md |
| Relay coverage | 10 | SMB relay + ADCS relay ESC8 fully documented |
| Cracking workflow | 10 | Hashcat modes, dictionary, rules, masks, prince all in Module 06 |
| Credential reuse matrix | 10 | New credential-reuse-matrix.md defines 18 credential types with full reuse paths |

**Assessment:** Credential attack coverage is the strongest category. The new Phase 3 deliverables (loot-priority-framework.md, credential-reuse-matrix.md) provide complete coverage. No gaps identified.

---

### Decision Support — Score: 9/10 ✓

| Sub-category | Score | Assessment |
|-------------|-------|------------|
| Quick lookup | 10 | New exam-dashboard.md provides glance-and-act reference for every finding type |
| Attack path ranking | 10 | New high-probability-paths.md ranks 20 chains with frequency/difficulty/time/payoff |
| Loot prioritization | 10 | New loot-priority-framework.md defines Tier 0-5 with why/where/reuse/escalation |
| Time allocation | 10 | New exam-execution-playbook.md provides minute 0-30, hour 1, hour 3-6, hour 6-12, hour 24+ strategies |
| Failure mode analysis | 10 | 8 Common CPTS failure modes documented in exam-execution-playbook.md |

**Assessment:** Decision support is transformed by Phase 3. The six new exam documents provide comprehensive decision support. No gaps identified.

---

### Exam Usability — Score: 9/10 ✓

| Sub-category | Score | Assessment |
|-------------|-------|------------|
| Quick reference | 10 | exam-dashboard.md designed for rapid lookup during active engagement |
| Time management | 10 | Minute-by-minute time budget + when-to-pivot/switches/stop rules |
| Stuck recovery | 10 | Full stuck matrix in Module 99 + stall recovery in exam-execution-playbook.md |
| Iterative loop | 9 | Post-foothold loop well-defined but could have checklist template |
| Screenshot guidance | 9 | Evidence collection guidance exists but no screenshot template file |

**Remaining gaps:** No standalone screenshot checklist template that a candidate can print/have open. Post-foothold iterative loop could be a printable checklist.

**To reach 10/10:** Create assets/exam/screenshot-checklist.md — a checklist a candidate can tick off during the exam. Add printable post-foothold checklist in exam-execution-playbook.md.

---

### Time Efficiency — Score: 8/10 ✗

| Sub-category | Score | Assessment |
|-------------|-------|------------|
| Prioritized workflows | 10 | Priority matrices exist in multiple documents (execution playbook, dashboard) |
| Parallel operations | 9 | Responder + hashcat = background documented. Web + services = parallel. |
| Time boxing | 9 | Per-host time limits documented (20 min web, 45 min privesc, etc.) |
| Automation | 7 | No automation scripts defined. Manual operations still required for many tasks. |
| Host exhaustion | 8 | When-to-abandon rules documented but not always followed under pressure |

**Remaining gaps:** No automation scripts (bash one-liners for quick enum sweeps). No "host exhaustion checklist" for quickly determining when to abandon a host.

**To reach 9/10:** Create a set of automation one-liners for rapid enumeration (nmap sweeps, netexec sweeps, bloodhound collection, certipy checks) that can be launched in parallel. Create a formal host-exhaustion checklist document.

**To reach 10/10:** All the above + create a tracking template for subnet/host/credential management that prevents losing state during pivoting.

---

### Operational Readiness — Score: 7/10 ✗

| Sub-category | Score | Assessment |
|-------------|-------|------------|
| Environment setup | 9 | Pre-engagement module covers tool verification |
| Credential tracking | 10 | loot-priority-framework.md + credential-reuse-matrix.md now provide full tracking |
| Subnet/host tracking | 6 | No formal subnet inventory template. Candidates lose state during pivoting. |
| Evidence management | 7 | Screenshot guidance exists but no structured evidence folder template |
| Report preparation | 8 | Module 14 covers report writing but no exam-specific report structure |

**Remaining gaps:** No subnet/host tracking template — critical for multi-subnet exams. No evidence folder structure template. No exam-specific report skeleton.

**To reach 9/10:** Create assets/exam/host-tracking-template.md — a table template for tracking IPs, hostnames, OS, open ports, creds found, access level, and status. Create assets/exam/evidence-folder-template.md — directory structure for organizing screenshots.

**To reach 10/10:** All above + create a progress dashboard template that tracks: hosts discovered, hosts compromised, credentials found, flags collected, and remaining targets.

---

## Summary of Gap Closure Actions

### Priority 1 — Quick Wins (30 min each)

| Action | File(s) | Category Impact |
|--------|---------|-----------------|
| Create host tracking template | assets/exam/host-tracking-template.md | Operational Readiness: 7→9 |
| Create evidence folder template | assets/exam/evidence-folder-template.md | Operational Readiness: 7→9 |
| Create screenshot checklist | assets/exam/screenshot-checklist.md | Exam Usability: 9→10 |

### Priority 2 — Depth Improvements (1-2 hours each)

| Action | File(s) | Category Impact |
|---------|---------|-----------------|
| Standardize "If This Fails" to 3+ alternatives across all Module 99 findings | modules/99-attack-graph.md | Attack Graph Completeness: 9→10 |
| Add automation one-liners (enum sweeps, parallel checks) | exam/exam-execution-playbook.md (new appendix) | Time Efficiency: 8→9 |

### Priority 3 — Technical Depth (2-3 hours each)

| Action | File(s) | Category Impact |
|---------|---------|-----------------|
| Full Shadow Credentials walkthrough with Whisker/ADFS | modules/11-active-directory.md | AD Completeness: 9→10 |
| DNS Admin → DC abuse chain with full commands | modules/11-active-directory.md | AD Completeness: 9→10 |
| Cloud metadata SSRF exploitation addition | modules/04-web-application.md | Coverage: 9→10 |
| Recent Linux kernel CVEs (2024-2025) | modules/09-linux-privesc.md | PrivEsc Completeness: 9→10 |
| ADCS ESC4-7 command-level detail | modules/11-active-directory.md | Enumeration Completeness: 10 |
| Docker container escape depth | modules/09-linux-privesc.md | Coverage: 9→10 |

---

## If All Actions Completed

```
Projected Score: 9.4/10

Category breakdown:
├── Coverage:                    10/10
├── Attack Graph Completeness:   10/10
├── Enumeration Completeness:    10/10
├── AD Completeness:             10/10
├── PrivEsc Completeness:        10/10
├── Credential Attack Coverage:  10/10
├── Decision Support:            10/10
├── Exam Usability:              10/10
├── Time Efficiency:              9/10
└── Operational Readiness:        9/10

Time Efficiency remains at 9/10 because automation can always go deeper.
Operational Readiness remains at 9/10 because the template approach
can always be extended.
```

---

## Phase 3 Deliverable Contribution Analysis

```
Deliverable                                   | Categories Improved
──────────────────────────────────────────────┼─────────────────────
exam-execution-playbook.md                    │ Exam Usability, Time Efficiency
  (Minute 0-30, Hour 1, Foothold Strategy,   │ Decision Support,
   Credential Strategy, AD Strategy,          │ Operational Readiness
   Endgame, Time Budget, Failure Modes)       │
                                              │
loot-priority-framework.md                    │ Credential Coverage,
  (Tier 0-5 loot categorization with          │ Decision Support,
   why/where/reuse/escalation)                │ Attack Graph Completeness
                                              │
credential-reuse-matrix.md                    │ Credential Coverage,
  (18 credential types with                   │ Attack Graph Completeness,
   validation targets, follow-on paths,       │ Decision Support
   escalation potential)                      │
                                              │
high-probability-paths.md                     │ Attack Graph Completeness,
  (20 attack chains ranked by                 │ Decision Support,
   frequency/difficulty/time/payoff)          │ Time Efficiency
                                              │
exam-dashboard.md                             │ Decision Support,
  (Single-file lookup: "I found X → do Y",   │ Exam Usability,
   Top 10 commands, Quick Action Reference)   │ Time Efficiency
                                              │
enumeration-completeness.md                   │ Enumeration Completeness,
  (MIN/REC/DEEP for 20+ services,            │ Exam Usability,
   ADCS, LAPS, gMSA, BloodHound)             │ Time Efficiency
                                              │
cpts-final-audit.md                           │ Methodology Quality,
  (Re-audit with gap closure actions,        │ Continuous Improvement
   path to 9.4/10)                            │
──────────────────────────────────────────────┼─────────────────────
```

---

## Cross-References

- Phase 2 audit (baseline) → [_PHASE2_DESIGN.md](../_PHASE2_DESIGN.md)
- Exam execution strategy → [exam-execution-playbook.md](./exam-execution-playbook.md)
- Loot value framework → [loot-priority-framework.md](./loot-priority-framework.md)
- Credential handling → [credential-reuse-matrix.md](./credential-reuse-matrix.md)
- Attack paths → [high-probability-paths.md](./high-probability-paths.md)
- Quick reference → [exam-dashboard.md](./exam-dashboard.md)
- Enumeration depth → [enumeration-completeness.md](./enumeration-completeness.md)
- Attack graph → [Module 99: Attack Graph](../modules/99-attack-graph.md)
