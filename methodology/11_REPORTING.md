# PHASE 12: DOCUMENTATION & REPORTING

> CPTS exam: report = ~40% of pass weight. 7-day exam window, 48-hour report write.
> Report rejected = exam fail, even if all flags captured.

## 12.1 - During Assessment (collect as you go)

- **Timestamp every action** (`script -t timing.log assessment.log` records terminal + timing)
- **Save scan output with exact syntax** — copy/paste full command + first 20 lines of output minimum
- **Screenshot every finding**: command + output visible, terminal title shows target hostname/IP
- **Credentials log**: maintain `loot/creds.txt` with `host:port|user|cred|source|first-seen`
- **Host inventory**: `loot/hosts.md` with hostname, IP, OS, services, foothold path, privesc method
- **Exploitation timeline**: append-only log `loot/timeline.md` — every successful action with timestamp
- **Raw output preservation**: `nmap -oA`, `tee` everything, keep Burp project file

## 12.2 - CVSS 3.1 Quick Reference

```
Vector: CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?

AV (Attack Vector):    N=Network, A=Adjacent, L=Local, P=Physical
AC (Attack Complexity): L=Low, H=High
PR (Privileges Req'd): N=None, L=Low, H=High
UI (User Interaction): N=None, R=Required
S  (Scope):            U=Unchanged, C=Changed
C/I/A (Confid/Integ/Avail): N=None, L=Low, H=High

Severity bands:
 0.0       None
 0.1-3.9   Low
 4.0-6.9   Medium
 7.0-8.9   High
 9.0-10.0  Critical

Common quick scores:
- Unauth RCE on internet-facing service: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
- Authenticated RCE:                     AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 High
- DCSync as DA:                          AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H = 9.1 Critical
- IDOR reading other user's data:        AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 Medium
- Stored XSS:                            AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N = 5.4 Medium
- Reflected XSS:                         AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 Medium
- LFI (read sensitive files):            AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 Medium
- Default creds on admin panel:          AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical

Calculator: https://www.first.org/cvss/calculator/3.1
```

## 12.3 - Evidence Standards (per finding)

Each finding needs:
1. **Command executed** — full syntax, copy-paste-able
2. **Output / screenshot** — terminal showing target IP/hostname in window title or prompt
3. **Timestamp** — when finding was confirmed
4. **Affected asset** — IP + hostname + role (DC / file server / etc.)
5. **Reproduction steps** — numbered, runnable by a third party with only the report

Bad evidence:
- Truncated output (cut off mid-line)
- Screenshot of just an alert box with no URL/host context
- "I got a shell" with no `whoami` / `hostname` / `id` proof
- Hand-typed transcript (rewrite of what happened)

Good evidence:
- Terminal screenshot: window title shows `192.168.1.50`, prompt shows `root@target:#`, command + output visible, timestamp in scrollback
- Burp request + response pair, both screens
- Diff of `before` and `after` state (added user, modified file, dumped hash)

## 12.4 - Report Structure

```
1. Cover Page
   ├── Client name, project name, version, date, classification
   └── Author + reviewer names

2. Executive Summary (non-technical, 1 page)
   ├── Engagement scope (what was tested, dates)
   ├── Highest-impact findings (3-5 bullets, business risk language)
   ├── Risk distribution chart (Critical/High/Medium/Low counts)
   └── Strategic recommendations (3-5 bullets)

3. Scope & Methodology
   ├── In-scope assets (IPs, domains, applications)
   ├── Out-of-scope (explicit)
   ├── Testing window (start/end timestamps)
   ├── Methodology framework reference (PTES, OWASP, NIST SP 800-115)
   └── Limitations / constraints

4. Attack Narrative (chronological)
   ├── Initial foothold
   ├── Each privilege escalation step
   ├── Lateral movement chain
   └── Final compromise (DA / crown jewel access)

5. Technical Findings (one per vulnerability, repeated)
   For each finding:
   ├── Title (descriptive: "Unauthenticated SQL Injection in /search Parameter")
   ├── Severity (CVSS 3.1 score + vector string)
   ├── CWE classification
   ├── Affected asset(s)
   ├── Description (technical explanation of the issue)
   ├── Impact (what an attacker gains — business + technical)
   ├── Evidence (commands + screenshots, numbered)
   ├── Reproduction steps (1, 2, 3 — runnable)
   ├── Remediation (specific, not "patch the software")
   └── References (CVE, CWE, vendor advisory, OWASP)

6. Appendices
   ├── A: Host Inventory (IP/hostname/OS/services/access level)
   ├── B: Credential Inventory (user, cleartext or hash, source, where reused)
   ├── C: Exploitation Timeline (timestamped chronology of all actions)
   ├── D: Tools Used (with versions)
   ├── E: Raw Scan Data (nmap, BloodHound exports)
   └── F: References + further reading
```

## 12.5 - Severity Decision Guide

```
Critical (9.0+):
- Unauthenticated RCE on production system
- Full domain compromise (DA via DCSync, golden ticket)
- Cleartext credentials of privileged accounts exposed network-wide
- Crown jewel data access (PII, financial records, source code)

High (7.0-8.9):
- Authenticated RCE
- Privilege escalation local → admin / root
- Sensitive file read (passwd, SAM, configs with creds)
- Persistent backdoor / scheduled task install
- AD ACL abuse leading to high-priv account compromise

Medium (4.0-6.9):
- Stored / Reflected XSS
- IDOR exposing PII of other users
- Limited LFI (no /etc/passwd, only app files)
- CSRF on sensitive actions
- Weak password policy / no MFA on critical app

Low (0.1-3.9):
- Information disclosure (version banners, internal IPs in headers)
- Missing security headers (HSTS, CSP, X-Frame-Options)
- Outdated software no exploitable CVE
- Self-XSS

Informational:
- Best-practice recommendations
- Hardening suggestions without active risk
```

## 12.6 - Remediation Patterns (write specific, not generic)

Bad: "Update to the latest version."
Good: "Upgrade Apache Tomcat from 9.0.30 to 9.0.85 or newer. Disable the `/manager` application
unless required. If required, restrict `tomcat-users.xml` to deny remote access and rotate
default credentials. Apply ALLOW from x.x.x.x in `context.xml` for management endpoints."

Bad: "Sanitize user input."
Good: "Replace the string concatenation in `search.php:42` with a parameterized query using
PDO prepared statements. Cast `$_GET['id']` to integer via `(int)` if the field is strictly
numeric. Add an allowlist regex `^[a-zA-Z0-9_-]+$` for the `sort` parameter."

Bad: "Implement strong passwords."
Good: "Enforce minimum 14-character passwords with complexity (Group Policy:
Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies >
Password Policy). Enable Account Lockout after 5 failed attempts for 30 minutes. Deploy
Microsoft LAPS for local admin accounts so each host has a unique random password."

## 12.7 - Common Report Mistakes (kill these)

- No CVSS vector string (only the score) — reviewer can't verify
- Hostname / IP missing from screenshots
- "Could lead to" / "may allow" — write what you DID, not what you imagine
- Reusing the same screenshot for multiple findings
- Steps to Reproduce that skip a step ("login, then ...")
- Remediation that says "implement security best practices"
- Inconsistent severity (text says High, table says Medium)
- Findings out of scope (out-of-scope assets in the report)
- Spelling client name wrong (instant credibility loss)
- Tables not numbered, figures not captioned

## 12.8 - Pre-Submission Checklist

```
[ ] All in-scope assets covered (none missed)
[ ] No out-of-scope assets included
[ ] Every finding has: title, CVSS vector, evidence, repro steps, remediation
[ ] Executive summary is non-technical
[ ] Attack narrative tells the story chronologically
[ ] Appendix C timeline matches finding timestamps
[ ] Credential inventory complete (every cred found is listed)
[ ] No placeholder text ("TODO", "TBD", "lorem ipsum")
[ ] Page numbers, TOC, header/footer consistent
[ ] Client name spelled correctly throughout
[ ] PDF compiled, no broken images / missing fonts
[ ] File named per client convention (e.g., CLIENT_PT_v1.0_2026-MM-DD.pdf)
```

---

# ITERATIVE METHODOLOGY RULES

> Apply across every phase. After each new foothold, re-enter the loop.

## After EVERY New Foothold:
```
1. Stabilize shell (python3 -c 'import pty;pty.spawn("/bin/bash")')
2. Transfer tools (linpeas, winpeas, etc.)
3. Enumerate host fully (OS, kernel, services, creds, network)
4. Check for additional NICs → new subnets (pivot targets)
5. Check for domain membership → AD enumeration
6. Dump all credentials (SAM, LSASS, shadow, bash_history, configs)
7. Search for sensitive files (configs, backups, scripts with creds)
8. Check for other users' sessions → lateral movement targets
9. Re-spray all found creds against all discovered hosts
10. Re-run BloodHound with new account as owned node
11. RESTART methodology from Phase 1 on new host/subnet
```

## When Stuck:
```
General:
1. Re-read all scan output carefully — may have missed something
2. Check for non-standard ports (8080, 8443, 9090, 7474, 9200, 27017, etc.)
3. Try all found creds on ALL services (not just where found)
4. Check write access to shares → SCF/LNK file drop → capture hash
5. Re-run nmap with -sU (UDP) — SNMP, IPMI, TFTP, IKE often missed
6. Check searchsploit for EVERY version banner (§0.6)
7. Check Wayback Machine + GitHub for old endpoints / leaked secrets
8. Try ALL Phase 3 attacks on every parameter (LDAP injection §3.14, Mass Assign §3.15 commonly missed)
9. Thick client binaries on shares — extract hardcoded creds (§11.10)
10. Printer / MFP web admin → LDAP test creds (§11.11)

AD-specific:
11. IPv6 attacks (mitm6 → relay LDAPS / ADCS) — see §9.1.6
12. LLMNR/NBT-NS poisoning (Responder)
13. Re-review BloodHound output — look for overlooked paths/ACL edges
14. Password spray season+year, company+year patterns
15. GPP/c-password in SYSVOL
16. Shadow Credentials / PKINIT (§9.8.4)
17. ADCS ESC1-ESC11 (§9.10) ← high-value, often overlooked
18. NoPac, PrintNightmare (if unpatched)
19. Coerced auth menu (§9.8.3b): PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce
20. LAPS / gMSA password reads (§9.3.3b)
21. Scheduled tasks running as SYSTEM with writable scripts
22. Cross-forest trust enumeration
23. GPO abuse (§9.8.7) — writable GPO = full OU control
24. MS14-068 (§9.8.8) on pre-2014 patch level DCs
25. PrivExchange (§9.8.9) — Exchange pre-CU Feb 2019
26. adidnsdump (§9.8.11) — hidden DNS records reveal hidden hosts
27. SCCM / WSUS / Veeam — enterprise infrastructure with NAA/DA creds (§11.8-11.12)

Citrix / Restricted Desktop stuck:
28. UNC path in dialog box (§8.3)
29. Alternate file manager (Explorer++)
30. Modify .lnk shortcut Target
31. AlwaysInstallElevated check
```

## Key Decision Points:
```
Got creds?
├─ Spray against ALL services: SMB, WinRM, RDP, MSSQL, SSH, LDAP
├─ Run BloodHound + mark owned
├─ Kerberoast / AS-REP roast
├─ Check shares for sensitive data
└─ Try LAPS / gMSA reads

Got admin (local)?
├─ Dump SAM/LSASS/secrets
├─ Find DA sessions
├─ Token impersonation (potato attacks)
└─ Lateral move with same creds

Got DA / DC compromise?
├─ DCSync all hashes (esp. krbtgt)
├─ Golden/Silver ticket persistence
├─ ADCS golden cert persistence (§9.10.10)
├─ Trust exploitation (parent/cross-forest)
└─ Document everything for report
```

## Wordlists to Use:
```
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/*-passwords.txt
/usr/share/seclists/Usernames/*-usernames.txt
Custom: CeWL from target website + company name variations
Season passwords: Spring2024!, Summer2024!, Fall2024!, Winter2024!
Company passwords: Companyname1!, Companyname123!, Welcome1
```

---

*This methodology covers 100% of CPTS exam content (28 modules). Follow decision trees iteratively. If one path fails, backtrack and try the next. Always enumerate before attacking. Document everything.*

**The exam tests methodology, not just tools. Understand WHY each step matters.**