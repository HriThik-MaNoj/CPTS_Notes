# Module 15: Exam Strategy

## When to Use This Module
Use this module throughout the entire CPTS exam. It provides the high-level strategic view that ties all other modules together — when to prioritize, when to pivot, and how to manage time. Read it BEFORE starting the exam and revisit it whenever you feel stuck.

## Prerequisites
- All other modules completed (this is the synthesis layer)
- Familiarity with all tools and attack types

## Exam Flow Reality

The CPTS exam is NOT a linear process. The flow reality is:

```
Phases 1→2→3 (recon, web) = mostly linear
Phases 4→6→7→8→9 = ITERATIVE — each new foothold restarts the loop
Phase 5 (cracking) = runs in PARALLEL once hashes are captured
Phase 10/10B (pivot/transfer) = runs as needed throughout
Phase 12 (notes/screenshots) = CONTINUOUS — start at Phase 0

Typical exam path:
Phase 0 → 1 (nmap) → 2 (web enum) → 3 (web attack) → 6 (shell)
→ 7 (creds on host) → 5 (crack if needed) → 8 (privesc)
→ 9 (AD if joined) → 10 (pivot) → restart at 1 for new subnet
```

## Time Budget Framework

```
Total exam time: ~10 days (varies, check exam brief)

Suggested time allocation:
├── Day 1: Full network scan + web enumeration (all hosts)
├── Day 2-3: Deep enumeration + initial footholds
├── Day 4-5: Privilege escalation + AD enumeration
├── Day 6-7: Lateral movement + pivoting + full AD compromise
├── Day 8: Data collection + flag hunting
├── Day 9-10: Buffer days + report writing + evidence review
└── Note: Screenshots EVERY step, starting from Day 1
```

## Decision Flow

```
Stuck on current host?
├── No → Continue current attack chain
└── Yes → Diagnosis:
    ├── Service found but can't exploit?
    │   ├── Check for other ports / services missed
    │   ├── Run deeper nmap (all ports, all scripts)
    │   ├── Search for version-specific exploits
    │   └── Move to next host, come back later
    │
    ├── Have shell but can't privesc?
    │   ├── Run linpeas/winpeas
    │   ├── Check all privesc vectors (see Module 09/10)
    │   ├── Check for other users on the system
    │   └── Check if host is domain-joined → Module 11
    │
    ├── Have creds but nowhere to use them?
    │   ├── Spray against all hosts (careful with lockouts)
    │   ├── Check password reuse
    │   ├── Try against other services (RDP, WinRM, SSH)
    │   └── Use for pivoting if multi-homed
    │
    └── Network segmented and can't reach?
        ├── Check routing (netstat -rn on compromised host)
        ├── Deploy pivot (ligolo-ng / chisel) → Module 12
        └── Scan new subnet from pivot host
```

## Prioritization Matrix

```
What to attack first?
├── Web applications (most common initial access)
│   ├── Look for: login pages, file upload, LFI/RFI, SQLi
│   └── If found → exploit immediately (high success rate)
├── Open services (SMB, FTP, RDP, MSSQL)
│   ├── Look for: anonymous access, default creds, known vulns
│   └── If no auth → enumerate first, exploit second
├── Password attacks
│   ├── Start in parallel once you have usernames
│   └── Run password spraying FIRST, then brute force
└── Active Directory
    └── Start enumeration as soon as you have domain creds
```

## The Iterative Loop

After EVERY successful foothold:

```
New host compromised?
├── Step 1: Check privileges (whoami / id)
├── Step 2: Check network (ipconfig / netstat / route)
├── Step 3: Enumerate host for creds → Module 13
├── Step 4: Crack any hashes found → Module 06
├── Step 5: Check privesc paths → Module 09/10
├── Step 6: Check if domain-joined → Module 11
├── Step 7: Check for pivoting opportunities → Module 12
│   ├── Multi-homed? → Deploy pivot tool
│   └── New subnet reachable? → Scan from pivot
└── Step 8: RESTART from Module 02 on new hosts
     DO NOT skip back to Module 01 (already scanned)
```

## Common Attack Chains

### Chain 1: Web → Shell → Root → AD → DA
```
Port 80/443 open → Web enum → Vuln found → Webshell
→ Reverse shell → LinPEAS → Root via SUID/kernel exploit
→ Check domain: is host AD-joined?
├── Yes → Dump creds, BloodHound, Kerberoast, DCSync
└── No → Check for pivot routes → scan internal network
```

### Chain 2: SMB → Creds → RDP → Windows PrivEsc → DA
```
Port 445 open → SMB enum → Null/password auth → Shares readable
→ Find creds in config files → Use for RDP/WinRM
→ WinPEAS → Admin via service misconfig
→ Dump LSASS → Domain creds → AD attack chain
```

### Chain 3: Responder → Hash → Crack → Spray → DA
```
No credentials yet → Run Responder → Capture NetNTLMv2
→ Crack with hashcat (-m 5600) → Cleartext password
→ Spray against domain → More accounts
→ BloodHound → Find privesc path → DA
```

### Chain 4: Pivot → Pivot → Pivot
```
Compromised host has 2+ NICs → Deploy ligolo-ng
→ New subnet accessible → Nmap from pivot
→ Find new hosts → Exploit from pivot
→ Repeat until all subnets compromised
```

## When to Pivot vs. When to Dig Deeper

```
Current host exhausted all attack paths?
├── Host has domain access? → Move to AD attacks (Module 11)
├── Host is multi-homed? → Deploy pivot (Module 12)
├── Still on initial host with no way forward?
│   ├── Re-check: Did you scan ALL ports? (65535 TCP + top UDP)
│   ├── Re-check: Did you try ALL services?
│   ├── Re-check: Did you run full privesc enumeration?
│   ├── Re-check: Are there other subnets you haven't seen?
│   └── Only give up after ALL checks pass → move to next host
└── Never abandon a host that still has unexplored attack surface
```

## Evidence Collection During Exam

```
For EVERY finding:
├── Screenshot the command AND output (in one frame)
├── Save to: Client_Folder/evidence/screenshots/
├── Note: IP, hostname, user context, date/time
└── Don't clean up screenshots — you'll need them for the report
```

## What to Do When Completely Stuck

```
Nothing working after 2+ hours?
├── Take a break (walk, coffee, 15 min)
├── Re-read the scope document — did you miss something?
├── Review your notes from the start — was there a finding you didn't follow up?
├── Check the exam forum/discord (carefully, no spoilers)
├── Try a completely different attack path
│   ├── Had web? Try services
│   ├── Had services? Try password attacks
│   └── Had password attacks? Try AD enumeration
└── Last resort: restart the environment and begin fresh
     (sometimes you've broken something without realizing it)
```

## Output Summary
You should have by exam end:
- [ ] All flags/submitted findings
- [ ] Full screenshot evidence for every step
- [ ] Documented attack chain from initial foothold to DA
- [ ] List of all compromised hosts
- [ ] All credentials discovered
- [ ] Clear report-ready findings

## Cross-References
- Target scanning methodology → [Module 02: Enumeration](../modules/02-enumeration.md)
- Web attack decision trees → [Module 04: Web Application](../modules/04-web-application.md)
- Privilege escalation → [Module 09: Linux PrivEsc](../modules/09-linux-privesc.md) and [Module 10: Windows PrivEsc](../modules/10-windows-privesc.md)
- AD attack chains → [Module 11: Active Directory](../modules/11-active-directory.md)
- Pivoting → [Module 12: Lateral Movement & Pivoting](../modules/12-lateral-pivot.md)
- Password attacks → [Module 06: Password Attacks](../modules/06-password-attacks.md)
- Reporting → [Module 14: Reporting](../modules/14-reporting.md)
