# 00 - MASTER Decision Tree

This folder is the CPTS exam methodology: this router plus 8 phase files. Open this file first, find your stage, follow the branch — every node below lives in full detail in its phase file.

**Marker convention:** `⚠️` = NOT from my own notes (external) — always followed by a source URL; `TYPO:` = my note has a typo (correction given); `GAP:` = my notes contain no command here; `STUB:` = the source note is a stub. Unmarked items are from my own notes. Loop-back sections are linkage-only (no source note). Verify any `⚠️` before trusting it.

One rule runs the whole exam: **enumerate → act → loot → re-enumerate.** Never stop at "act" — loot, then re-enumerate.

## THE MAIN FLOW

```
START
└─ read the LOE / scope / RoE; scaffold the evidence tree; start terminal logging ...... [[01 - Exam Ops & Reporting]]
   └─ enumerate the surface: host discovery → port scan → per-service nodes ............ [[02 - External Recon & Enumeration]]
      ├─ web ports 80/443/8080/8000/8180 (+8500) → fingerprint the stack → attack the app [[03 - Web Exploitation & Foothold]]
      │  ├─ reachable CMS / app (WordPress, Joomla, Drupal, Tomcat, Jenkins, PRTG, GitLab ...) → app node
      │  ├─ login portal / SSO / API → default creds, then stuffing / brute ............. [[04 - Credentials & Common Services]]
      │  ├─ injectable input (SQLi, LFI/RFI, cmdi, XXE, IDOR, file upload, XSS) → the matching vuln node
      │  └─ code exec / uploaded shell / SQLi-to-webshell → stabilise the shell ...... [[05 - Shells, Transfers & Metasploit]]
      ├─ other services (21 FTP · 139/445 SMB · 111+2049 NFS · 22 SSH · 1433/3306 SQL
      │  · 3389 RDP · 5985 WinRM · 25/110/143 mail · 161 SNMP · 623 IPMI)
      │  ├─ per-service footprint node → its "next action" .............................. [[02 - External Recon & Enumeration]]
      │  ├─ database port (1433 / 3306 / 1521) + creds → OS cmd / webshell → FOOTHOLD ... [[02 - External Recon & Enumeration]]
      │  └─ service attack: anon / defaults / brute / public exploit .................... [[04 - Credentials & Common Services]]
      └─ credentials or hashes obtained (anon, leak, spray, AS-REP) → validate everywhere [[04 - Credentials & Common Services]]
         ├─ no creds yet, internal foothold only → poison / spray → get the first cred .. [[08 - Active Directory & Lateral Movement]]
         ├─ external usernames enumerated, no password yet → spray → first cred ........ [[04 - Credentials & Common Services]] / [[08 - Active Directory & Lateral Movement]]
         └─ FOOTHOLD ACHIEVED → stabilize the shell / pick a payload ................... [[05 - Shells, Transfers & Metasploit]]
            └─ escalate → Linux root / Windows SYSTEM .................................. [[06 - Privilege Escalation]]
               ├─ looted creds / configs / hashes → back into the cred loop ............. [[04 - Credentials & Common Services]]
               ├─ second NIC or a reachable new subnet → build a tunnel ................. [[07 - Pivoting & Tunneling]]
               │  └─ route up → re-run host discovery + port scan on the new subnet ..... [[02 - External Recon & Enumeration]]
               └─ domain creds (or a domain-joined host) → AD enumeration ............... [[08 - Active Directory & Lateral Movement]]
                  ├─ child → parent trust → ExtraSids ticket → parent DA ................ [[08 - Active Directory & Lateral Movement]]
                  ├─ cross-forest trust → cross-forest kerberoast → forest B admin ...... [[08 - Active Directory & Lateral Movement]]
                  └─ DOMAIN ADMIN → DCSync / NTDS loot → re-run the loot loop → write the report → [[01 - Exam Ops & Reporting]]
```

The expected chain is segment-dependent: **external web → foothold → internal host → pivot → AD segment → DC.** Each segment's creds come from the previous segment's loot — you cannot skip a segment without its material.

### Where am I? — symptom → entry point

| What you're looking at                                  | Stage            | Go to                                        |
| ------------------------------------------------------- | ---------------- | -------------------------------------------- |
| a scope list / IP range, nothing scanned yet            | pre-exploit      | [[02 - External Recon & Enumeration]]        |
| open ports + version banners, still no access           | enumeration done | [[02 - External Recon & Enumeration]]        |
| a login page or CMS fingerprint                         | web target       | [[03 - Web Exploitation & Foothold]]         |
| a found credential/hash but no shell                    | cred stage       | [[04 - Credentials & Common Services]]       |
| a valid username but no password yet                    | spraying         | [[08 - Active Directory & Lateral Movement]] |
| a PCAP or mountable shares, no host access              | cred harvest     | [[04 - Credentials & Common Services]]       |
| code exec but a dumb, non-interactive shell             | foothold         | [[05 - Shells, Transfers & Metasploit]]      |
| a low-priv shell as a normal user                       | local privesc    | [[06 - Privilege Escalation]]                |
| a Windows service account set with a token privilege    | Windows privesc  | [[06 - Privilege Escalation]]                |
| a host with two NICs or a reachable new subnet          | pivot            | [[07 - Pivoting & Tunneling]]                |
| an internal-only service you can reach through a tunnel | deeper pivot     | [[07 - Pivoting & Tunneling]]                |
| a domain user, or a domain-joined box                   | AD               | [[08 - Active Directory & Lateral Movement]] |
| flags captured, time left in the window                 | wrap-up          | [[01 - Exam Ops & Reporting]]                |

## THE ITERATION LOOP (the backbone — do not skip the re-run)

The exam chains vulns across segments; nothing is one-and-done. Every artifact you collect re-enters the flow at a defined point. Four triggers, each with the exact sections to re-run.

**Trigger 1 — new credential (user:pass or hash)**
- validate it on every protocol: SMB / WinRM / RDP / SSH / MSSQL / MySQL / LDAP — "Got a valid user:pass" + full service sweep → [[04 - Credentials & Common Services]]
- re-test every service that earlier refused auth (the loop-back node in [[02 - External Recon & Enumeration]]: SMB, MSSQL, MySQL, IMAP/POP3, Windows RM, Linux RM)
- cracked from a hash → resolve to plaintext: "Have a hash — identify the type, then crack it" → [[04 - Credentials & Common Services]]
- if it is still a hash, try it raw before cracking: Pass-the-Hash / Pass-the-Ticket → [[04 - Credentials & Common Services]]
- enumerate AS that user: users, groups, logged-on users, shares → [[08 - Active Directory & Lateral Movement]] then [[02 - External Recon & Enumeration]]
- if it is domain context, re-run ACL + BloodHound analysis for the new principal: "The loop — every new credential re-runs validation + BloodHound/ACL analysis" → [[08 - Active Directory & Lateral Movement]]
- new cred on a Windows foothold → re-hunt creds with it (shares, services, WinRM/RDP) → [[04 - Credentials & Common Services]]
- new username list (no password yet) → password spray → [[04 - Credentials & Common Services]] §spray / [[08 - Active Directory & Lateral Movement]] §Spraying
- ⏱ 15 min per trigger re-run; if the credential authenticates nowhere new → log it and return to the segment that produced it.

**Trigger 2 — new host / new subnet / new vhost**
- new host → host discovery → Nmap scan → per-service nodes → [[02 - External Recon & Enumeration]]
- new subnet behind a pivot → ligolo-ng (or SSH / chisel fallback) → add the route → re-enumerate → [[07 - Pivoting & Tunneling]] then [[02 - External Recon & Enumeration]]
- new vhost or subdomain → dir brute + vhost fuzz + app discovery → [[03 - Web Exploitation & Foothold]] then [[02 - External Recon & Enumeration]]
- any new host you hold access to → hunt creds on it and spider its shares → [[04 - Credentials & Common Services]]
- look for the next hop: a dual-homed host on the new subnet is the next pivot → [[07 - Pivoting & Tunneling]]
- prove reachability before moving in: `-sT` over proxychains, one TCP probe per host → [[07 - Pivoting & Tunneling]]
- new subdomain → also retry vhost/DNS brute against every previously found host → [[02 - External Recon & Enumeration]]
- ⏱ 15 min per trigger re-run; if the new host/subnet yields no new port → widen the sweep, else return to the current segment.

**Trigger 3 — new access level (foothold → root/SYSTEM; SYSTEM → DA)**
- Linux root → read /etc/shadow, SSH keys, app configs, histories → reuse: "Loop-back (got root / SYSTEM → loot and move)" → [[06 - Privilege Escalation]] + [[04 - Credentials & Common Services]]
- Windows SYSTEM → dump SAM / SECURITY / SYSTEM, then LSASS: "Local admin on Windows" / "dump LSASS memory" → [[04 - Credentials & Common Services]]
- local admin or SYSTEM on a DC → NTDS.dit → [[04 - Credentials & Common Services]] then [[08 - Active Directory & Lateral Movement]]
- replication rights held → DCSync for DA-equivalent hashes → [[08 - Active Directory & Lateral Movement]]
- new level as a domain principal → re-run BloodHound + ACL analysis → [[08 - Active Directory & Lateral Movement]]
- read-only access to a domain controller → look for a writable GPO / ACL path → [[08 - Active Directory & Lateral Movement]]
- DA context → re-run 04 (cred hunt), 02 (re-enumerate), 08 (BloodHound re-run) → [[04 - Credentials & Common Services]] + [[02 - External Recon & Enumeration]] + [[08 - Active Directory & Lateral Movement]]
- escalate BEFORE you pivot; a root box with no new creds is not a flag → [[06 - Privilege Escalation]]
- ⏱ 15 min per trigger re-run; if the new access level unlocks nothing new → re-read §STUCK PROTOCOL.

**Trigger 4 — every flag (and every loot item)**
- log the flag numerically and write the report entry, then re-loot the host you just owned → [[01 - Exam Ops & Reporting]]
- a captured host almost always yields creds or a config → re-enters Trigger 1 → [[04 - Credentials & Common Services]]
- screenshot + colour-code the command; keep the walkthrough human-written → [[01 - Exam Ops & Reporting]]
- track against the ≥12/14 bar; stop hunting NEW flags at ~day 7–8 and switch to the report → [[01 - Exam Ops & Reporting]] ⚠️ [src: https://radiantsec.io/blog/htb-cpts-review/]
- a flag you cannot reproduce from your notes is a flag you cannot defend in the report → [[01 - Exam Ops & Reporting]]
- ⏱ 5 min per flag write-up; if a capture yields no new creds → re-loot that host before moving on.

**Loop mechanics**
- a new credential makes you re-validate; a new host makes you re-enumerate; a new access level makes you re-loot; a flag makes you re-document.
- expect 2–3 pivots to the DC: `WEB → pivot → MS → DC`. Each segment depends on the prior segment's creds.
- when a value lands in two phases, follow the phase that owns the *action* (domain cred → [[08 - Active Directory & Lateral Movement]]; local hash → [[04 - Credentials & Common Services]]; moving files → [[05 - Shells, Transfers & Metasploit]]).
- an empty result is data: a refused auth, a filtered port, or a missing share all shrink the unknown — record it and move.
- finish the current segment before jumping ahead: early flags are external, and a later segment usually needs the prior segment's creds → [[01 - Exam Ops & Reporting]]
- time-box each re-run tightly; the loop is fast, the one exploit inside it is slow → [[01 - Exam Ops & Reporting]]

**Universal re-enumeration checklist — run it after ANY change**
- [ ] re-scan the affected host/subnet for new ports and services → [[02 - External Recon & Enumeration]]
- [ ] re-fingerprint any new web app / CMS / version → [[03 - Web Exploitation & Foothold]]
- [ ] retry every credential against every service — old failures and newly found ports → [[04 - Credentials & Common Services]]
- [ ] re-check shares / configs / histories on every host you now own → [[04 - Credentials & Common Services]]
- [ ] re-collect BloodHound and re-read ACLs if a domain principal changed → [[08 - Active Directory & Lateral Movement]]
- [ ] confirm the tunnel/route still reaches the new segment before scanning → [[07 - Pivoting & Tunneling]]
- [ ] log the change and any new flag before you move on → [[01 - Exam Ops & Reporting]]
- ⏱ cap the whole checklist at 10 min; a check that yields nothing is a result — record it and move on.

## STUCK PROTOCOL

Pre-commit your numbers before the exam; obey them without debate. Full detail + sources: [[01 - Exam Ops & Reporting]].
- 3 consecutive failures on the SAME technique → force a pivot; stop retrying it. ⚠️ [src: https://radiantsec.io/blog/htb-cpts-review/]
- 2 hours max on an already-compromised host → move on. ⚠️ [src: https://radiantsec.io/blog/htb-cpts-review/]
- stuck 1–2h with no progress → stop, re-enumerate, re-read the relevant phase file. ⚠️ [src: https://radiantsec.io/blog/htb-cpts-review/]
Jump order (cheapest first):
1. re-run enumeration — enumeration wins exams; check the folder/parent folder you landed in and the "weird" artifact → [[02 - External Recon & Enumeration]]
2. swap wordlists / add rules / change the extension list → [[03 - Web Exploitation & Foothold]] FFUF nodes
3. attack the simplest service you skipped (defaults / anon / credential reuse) → [[04 - Credentials & Common Services]]
4. only then escalate complexity to a CVE/exploit → [[06 - Privilege Escalation]] kernel CVEs · [[03 - Web Exploitation & Foothold]] public exploits
5. step away; sleep 7–8h. Fatigue causes missed clues; do NOT reach for AI as an un-stick tool → [[01 - Exam Ops & Reporting]] ⚠️ [src: https://fernale.blogspot.com/2025/06/my-experience-with-hack-box-cpts.html]
6. nudge etiquette is a PREP skill only — the exam has no hint system → [[01 - Exam Ops & Reporting]] ⚠️ [src: https://www.brunorochamoura.com/posts/cpts-tips/]
If you are still blocked after the jump order, the blocker is usually a missed clue from the previous segment, not a novel exploit → [[02 - External Recon & Enumeration]].
- if you cannot name your next action, you are missing enumeration, not a trick → [[02 - External Recon & Enumeration]]
- re-read the phase file's loop-back section — it lists exactly what a new artifact unlocks.

## INDEX

| File | Covers |
|---|---|
| [[01 - Exam Ops & Reporting]] | exam format/rules, 10-day plan, report setup + components, terminal logging, stuck protocol, readiness |
| [[02 - External Recon & Enumeration]] | host discovery, Nmap + evasion, per-service footprint nodes (FTP/SMB/NFS/DNS/SMTP/IMAP/SNMP/MySQL/MSSQL/Oracle/IPMI/Linux & Windows RM), web recon, subdomains/vhosts/CT logs |
| [[03 - Web Exploitation & Foothold]] | app discovery, ffuf, CMS/app attacks, SQLi/sqlmap, XSS, LFI/RFI, file upload, command injection, IDOR, XXE, verb tampering |
| [[04 - Credentials & Common Services]] | cred hunting, cracking (John/Hashcat), spray/stuff/defaults, PtH/PtT/PtC, SAM/LSASS/NTDS, brute (Hydra/Medusa), service attacks |
| [[05 - Shells, Transfers & Metasploit]] | reverse/bind shells, msfvenom, web shells, TTY upgrade, the transfer decision table, Metasploit workflow + evasion |
| [[06 - Privilege Escalation]] | Linux + Windows local privesc: enum checklists, sudo/SUID, groups/privileges, services, kernel CVEs, the loot loop-back |
| [[07 - Pivoting & Tunneling]] | ligolo-ng, SSH family, chisel, socat, netsh/plink/SocksOverRDP, DNS/ICMP tunnels, the re-enumeration loop |
| [[08 - Active Directory & Lateral Movement]] | AD enum, Responder/spray, Kerberoast/AS-REP, ACL/DCSync, BloodHound, trusts, PtH/PtT/PtC, child→parent, cross-forest |

## DOCUMENTATION TRIGGERS

Write as you go — by day 10 the report should be ~90% done. Full detail + sources: [[01 - Exam Ops & Reporting]].
- exam start → meta/scope sections; screenshot + log from minute one.
- each host + service discovered → add a host/service appendix row.
- each finding confirmed → a Finding entry (Title, CWE, CVSS, impact, recommendations).
- each foothold / flag → the exploited-host walkthrough + the flags table.
- root / SYSTEM → the host-cleanup appendix (artifacts you left) + the compromised-users appendix.
