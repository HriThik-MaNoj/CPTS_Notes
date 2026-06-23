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

## Progress Checkpoints

Don't measure by days elapsed. Measure by checkpoints completed.

```
CHECKPOINT A — Recon Complete
  [ ] All hosts identified (nmap -sn)
  [ ] All services enumerated (top 1000 TCP + web ports)
  [ ] SMB null session checked on all hosts
  [ ] LDAP anonymous bind checked
  [ ] Responder/coercion running in background
  [ ] Web applications identified and technology fingerprinted
  → GOAL: Know what you're working with

CHECKPOINT B — Access Obtained
  [ ] At least one shell, credential, or service access
  [ ] OR: All TRY FIRST paths exhausted and you're working TRY NEXT
  → GOAL: First foothold established

CHECKPOINT C — Credential Expansion
  [ ] All harvested credentials tested across all hosts
  [ ] Password spraying completed (top patterns)
  [ ] AS-REP roasting attempted
  [ ] All hashes sent to cracking (background)
  → GOAL: Maximize credential surface area

CHECKPOINT D — AD Enumeration
  [ ] BloodHound collected and analyzed
  [ ] Kerberoasting attempted
  [ ] ADCS enumerated (certipy)
  [ ] Delegation checked
  [ ] LAPS checked
  → GOAL: DA path identified OR verified no path exists from current position

CHECKPOINT E — Full Compromise
  [ ] Domain Admin achieved OR all escalation paths exhausted
  [ ] All hosts compromised OR enumerated fully
  [ ] All flags collected
  [ ] Screenshots taken for every finding
  → GOAL: Exam objectives complete

CHECKPOINT F — Report Ready
  [ ] Attack chain documented from start to finish
  [ ] All credentials logged with sources
  [ ] Evidence folder organized
  → GOAL: Deliverable ready for submission
```

### Progress Rules

- Each checkpoint depends on the previous one. Don't jump from A to D.
- If stuck at a checkpoint for extended time, take a break and re-triage.
- It's normal to loop back: new credentials (C) may enable new AD paths (D).
- Document screenshots continuously — don't defer to "later."

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
- Target scanning methodology → [Module 02: Enumeration](02-enumeration.md)
- Web attack decision trees → [Module 04: Web Application](04-web-application.md)
- Privilege escalation → [Module 09: Linux PrivEsc](09-linux-privesc.md) and [Module 10: Windows PrivEsc](10-windows-privesc.md)
- AD attack chains → [Module 11: Active Directory](11-active-directory.md)
- Pivoting → [Module 12: Lateral Movement & Pivoting](12-lateral-pivot.md)
- Password attacks → [Module 06: Password Attacks](06-password-attacks.md)
- Reporting → [Module 14: Reporting](14-reporting.md)
