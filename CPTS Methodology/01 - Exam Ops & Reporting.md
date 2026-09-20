# 01 - Exam Ops & Reporting

> **Marker convention:** `⚠️` = NOT from my own notes (external) — always followed by a source URL; `TYPO:` = my note has a typo (correction given); `GAP:` = my notes contain no command here; `STUB:` = the source note is a stub. Unmarked items are from my own notes (`24. Documentation and Reporting/`, `0. Prep.md`, `templates/`). Loop-back sections are linkage-only.

## Exam format & rules (external research)
| Fact | Value | Source |
|---|---|---|
| Window | 10 consecutive calendar days; hacking AND report share the window | ⚠️ [src: https://help.hackthebox.com/en/articles/12741732-academy-certifications] |
| Environment | black-box, VPN, multi-subnet AD enterprise (~8 machines, mixed Linux/Windows) | ⚠️ [src: https://blog.deephacking.tech/en/posts/htb-cpts-review/] |
| Flags | 14 total; pass needs ≥12/14 (~85%), or the official points threshold | ⚠️ [src: https://blog.deephacking.tech/en/posts/htb-cpts-review/] |
| Two gates | BOTH the flag threshold AND a commercial-grade English report must pass (people fail at 13–14/14 on the report) | ⚠️ [src: https://www.brunorochamoura.com/posts/cpts-report/] |
| Attempts | 2 attempts/voucher; start the 2nd within 14 days or lose it; results ≤20 business days; no 2nd attempt without a submitted report | ⚠️ [src: https://help.hackthebox.com/en/articles/12741732-academy-certifications] |
| Tooling | local VPN config OR in-browser Pwnbox (not both at once); Pwnbox max 4 days continuous, then wiped | ⚠️ [src: https://help.hackthebox.com/en/articles/12741732-academy-certifications] |
| Deliverable | unencrypted PDF or ZIP, max 20MB, English; submit via dashboard (irreversible, closes the lab) | ⚠️ [src: https://help.hackthebox.com/en/articles/12741732-academy-certifications] |
| June 2025 update | exam changed, details NOT published; pre-update flag lore is stale — rely on methodology, not flag order | ⚠️ [src: https://radiantsec.io/blog/htb-cpts-review/] |

## 10-day time plan (day-by-day buckets) — external research
⚠️ The day-bucket framing is external research; each bucket's rule is cited inline. [src: https://radiantsec.io/blog/htb-cpts-review/]
| Day(s) | Bucket | Rule |
|---|---|---|
| 1–2 | Recon → first foothold (external web/foothold) | ⚠️ early flags = external; don't jump segments before you have the prior segment's creds [src: https://www.brunorochamoura.com/posts/cpts-tips/] |
| 3–6 | Exploitation + lateral into the internal network (Windows svc/priv-esc, AD) | ⚠️ each segment depends on material from the previous one [src: https://morimori-dev.github.io/en/posts/cpts-passed/] |
| 7–8 | Mop-up / finish flags; start polishing the report | ⚠️ stop hacking for NEW flags once you cross 12 (or by ~day 7–8) [src: https://radiantsec.io/blog/htb-cpts-review/] |
| 8–10 | Report (sacrosanct) | ⚠️ keep the last ~2–3 days for the report; passers: flags done by day 7, submit day 9 [src: https://morimori-dev.github.io/en/posts/cpts-passed/] |

- ⚠️ Track flags numerically; ~2 flags of slack max — you cannot skip a whole network segment and pass. [src: https://blog.deephacking.tech/en/posts/htb-cpts-review/]
- ⚠️ Time-to-first-flag is contested (Discord says 2–3 days; passers report ~4h–1 day); don't panic over day 1–2, but a multi-day stall = re-enumerate the basics. [src: https://www.brunorochamoura.com/posts/cpts-tips/]
- ⚠️ Difficulty "filters" exist (pre-update flag 1 & 9; post-update accounts say flag 8 is the longest); sources disagree — slow down and track every link of a long chain. [src: https://archwarden.com/posts/cpts-exam-what-nobody-tells-you/]

Day-by-day operational checklist:
- [ ] Day 1 — scope review, evidence folder, tmux logging, host discovery, nmap, public-exploit match on any open port
- [ ] Day 2 — finish external recon (subdomains, vhosts, web recon on every name), per-service nodes (FTP/SMB/NFS/SQL/SSH/RDP/WinRM), first foothold OR first spray
- [ ] Day 3 — stabilise the first foothold, Windows/Linux enum, first privesc attempt (sudo/SeImpersonate/Potato), internal host discovery
- [ ] Day 4 — pivot (ligolo-ng or chisel), re-enumerate the internal subnet, dump SAM/LSASS or /etc/shadow, first internal creds
- [ ] Day 5 — first domain cred → BloodHound + netexec full sweep, Kerberoast/AS-REP, ACL analysis, spray with harvested context
- [ ] Day 6 — exploit the BloodHound path (ACL abuse, child→parent, misc misconfigs), lateral movement across AD, second pivot if needed
- [ ] Day 7 — finish flags 12+; **stop hunting NEW flags once you cross 12**
- [ ] Day 7–8 — start polishing the report (write-as-you-go should leave ~80% done already)
- [ ] Day 8–9 — finalise the report (SysReptor export, exec summary, remediation table, appendices), compress under 20MB
- [ ] Day 9–10 — submit (irreversible)

## Documentation triggers — stop and write the report NOW
Write-as-you-go; by day 10 the report should be ~90% done. ⚠️ [src: https://www.brunorochamoura.com/posts/cpts-report/]
⏱ write within ~15 min of each trigger — never batch it to the end.

| Moment (trigger) | Stop and write | Source |
|---|---|---|
| exam start | meta/scope sections (screenshot + log commands from minute one) | ⚠️ [src: https://www.brunorochamoura.com/posts/cpts-report/] |
| host + service discovered | a host/service appendix row — every host, every service | ⚠️ [src: https://0xm4ix.com/posts/cpts-exam-experience/] |
| finding confirmed | a Finding entry (Title, CWE, CVSS, Overview, Impact, Affected Components, Recommendations, References, Details) | ⚠️ [src: https://github.com/ProfessorAnkush/CPTS-Exam-/blob/main/HTB-CPTS-Preparation-and-Reporting-Guide] |
| foothold taken | exploited host + walkthrough (the graded chain; keep it human-written) | ⚠️ [src: https://0xikon.github.io/posts/cpts-review-2025/] |
| root / SYSTEM | host cleanup appendix (artifacts you left, so the client can revert) | ⚠️ [src: https://www.brunorochamoura.com/posts/cpts-report/] |
| user compromised | compromised-users appendix (if ALL domain accounts were taken, just say so) | ⚠️ [src: https://www.brunorochamoura.com/posts/cpts-report/] |
| flag captured | the flags table (track numerically against the ≥12/14 bar) | ⚠️ [src: https://radiantsec.io/blog/htb-cpts-review/] |

Every foothold / flag / host triggers a write — never batch it to the end.

Pre-flight checklist (do once at exam start):
- [ ] evidence folder tree scaffolded (`Report setup` below)
- [ ] tmux-logging plugin installed and active (`Terminal logging` below)
- [ ] SysReptor + HTB CPTS template installed and a dry-run export completed

## Report setup — folder tree & file layout (own notes)
**IF** assessment kickoff, before any tooling output →
- [ ] create the full per-target directory tree under the target-IP folder.
```bash
mkdir -p $TARGET_IP/{Admin,Deliverables,Evidence/{Findings,Scans/{Vuln,Service,Web,'AD Enumeration'},Notes,OSINT,Wireless,'Logging output','Misc Files'},Retest}
```
WHY: keep evidence organized → avoid missed work, duplicate work, and RoE violations.
- [ ] works → allocate every artifact per the table below; the tree is the single evidence index.
- [ ] fails → preserve the quoted space-names exactly (`'AD Enumeration'`, `'Logging output'`, `'Misc Files'`).
- [ ] ⏱ scaffold at kickoff, before anything is collected.
→ [[24. Documentation and Reporting/3. Folder structure command|src]]

| Path | Contents |
|---|---|
| `Admin/` | SoW, kickoff notes, status, vuln notifications |
| `Deliverables/` | Reports, spreadsheets, slides |
| `Evidence/Findings/` | Evidence per finding |
| `Evidence/Scans/` | Vuln scans, Nmap, Masscan, web, AD enumeration |
| `Evidence/Notes/` | Assessment notes |
| `Evidence/OSINT/` | OSINT output |
| `Evidence/Wireless/` | Wireless testing data |
| `Evidence/Logging/` | Tmux, Metasploit, other logs |
| `Evidence/Misc/` | Payloads, web shells, scripts |
| `Retest/` | Separate evidence for retesting |

## Terminal logging — capture every command (own notes)
**IF** you set up the attacker box before/at exam start →
- [ ] install the tmux-logging plugin and start logging the active session.
```bash
touch .tmux.conf
tmux source ~/.tmux.conf
tmux new -s setup
```
Append to `.tmux.conf` (the `run '~/.tmux/plugins/tpm/tpm'` line MUST stay at the bottom):
```bash
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'
run '~/.tmux/plugins/tpm/tpm'
```
Then `[Ctrl]+[B]` then `[Shift]+[I]` (install plugins) → `[Ctrl]+[B]` then `[Shift]+[P]` (begin logging the session/pane).
WHY: tmux-logging gives a persistent transcript so evidence isn't lost to scrollback.
- [ ] works → install plugins inside a session (Shift+I), then toggle logging (Shift+P) per pane.
- [ ] fails → non-default prefix: use your configured `prefix` key instead of `Ctrl+B`.
- [ ] ⏱ do this on day 1; a lost transcript costs hours of rework.
→ [[24. Documentation and Reporting/1. Terminal logging|src]]

## Report requirements checklist
Per finding (the graded unit):
- [ ] Description + platforms affected
- [ ] Impact if unresolved
- [ ] Affected systems/networks/apps
- [ ] Recommendations
- [ ] Reference links (vendor-agnostic, no paywalls/ads)
- [ ] Steps to reproduce + evidence (one figure per step, narrative between figures)

→ [[24. Documentation and Reporting/7. How to Write Up a Finding|src]]

Formatting & redaction (every screenshot/figure):
- [ ] prefer terminal output over screenshots
- [ ] color-code the command + interesting output
- [ ] cut noise with `<SNIP`
- [ ] strip formatting
- [ ] redact creds/hashes (keep first AND last 3–4 chars of a hash); cleartext → `<Redacted>`
- [ ] annotate/border/crop; include the URL bar
- [ ] black bars (not blur), edited INTO the image
- [ ] don't archive sensitive-share file contents — screenshot the directory listing only

→ [[24. Documentation and Reporting/4. Formatting and Redaction|src]]

Report components:
- [ ] focus effort on high-impact findings, consolidate minor ones, disclose everything
- [ ] Exec summary: non-technical, 1.5–2 pages, no acronyms/vendor names, specific numbers, root causes
- [ ] Recommendations: short/medium/long-term, each mapped to a finding
- [ ] Static appendices: Scope, Methodology, Severity Ratings, Biographies
- [ ] Dynamic appendices: Exploitation Attempts & Payloads, Compromised Credentials, Configuration Changes (written approval first), Additional Affected Scope, Information Gathering, Domain Password Analysis
- [ ] Internal pentest / external ending in compromise → full layout with an attack chain

→ [[24. Documentation and Reporting/6. Components of a Report|src]]

- [ ] ⏱ write each finding within ~15 min of confirming it; the steps-to-reproduce narrative is written while the command is still on screen.

Grading rules (external research):
- ⚠️ The report is the #1 cause of failure-with-flags; graders pass you on the report, not the pentest. [src: https://blog.deephacking.tech/en/posts/htb-cpts-review/]
- ⚠️ Tooling: SysReptor (free, self-hostable) + the official HTB CPTS template, markdown → PDF; install and rehearse a full export BEFORE exam day. [src: https://www.brunorochamoura.com/posts/cpts-report/]
- ⚠️ Length is all over the map (no minimum; ~50–230 pages observed); quality beats page count, but bloat risks the 20MB cap — compress/crop images. [src: https://rezydev.com/writeups/hackthebox/ultimate-htb-cpts-guide]
- ⚠️ Common rejection reasons: no exec summary; findings not written individually; missing business impact; tiny/unlabelled screenshots; poor/missing CVSS; thin remediation; CTF-style wall-of-text; typos/bad structure. [src: https://medium.com/@piyushbusiness29/ultimate-cpts-reporting-guide-piyush-sh-57cb584bb38e]
- ⚠️ AI allowed for language/grammar polish + CWE/CVSS lookup; generating the report with AI violates HTB ToS; pasting exam targets into public AI violates the NDA. Keep the walkthrough human-written. [src: https://help.hackthebox.com/en/articles/12741732-academy-certifications]
- ⚠️ SysReptor HTB template sections: candidate/engagement meta, doc control, exec summary, scope, assessment overview, network summary, internal compromise walkthrough, remediation summary, appendices (host/service, subdomain, exploited hosts, compromised users, host cleanup, flags, domain password review), per-finding fields. [src: https://www.brunorochamoura.com/posts/cpts-report/]

## Stuck protocol (external research)
### Time-boxes
**IF** a technique fails 3 times in a row or you burn 1–2h with no progress →
- [ ] force a pivot; obey the numeric rule without debate.
- ⚠️ "3 consecutive failures on the same technique → force a pivot"; "max 2 hours on an already-compromised host"; "if stuck 1–2h, stop and get a nudge". [src: https://radiantsec.io/blog/htb-cpts-review/]
- [ ] fails → unbounded grinding on one technique is the classic time sink.
- [ ] ⏱ pre-commit your numbers before the exam; never renegotiate mid-panic.
→ [src: https://radiantsec.io/blog/htb-cpts-review/]

### Think dumber / re-enumerate
**IF** stuck →
- [ ] rank solutions simplest→most complex and try them in that order; re-run enumeration first.
- ⚠️ "Enumeration wins exams"; try alternate wordlists/rules, check the folder/parent folder where you landed, look for the "weird" artifact. [src: https://www.brunorochamoura.com/posts/cpts-tips/]
- [ ] fails → escalate complexity only after simple options are exhausted.
- [ ] ⏱ the answer is usually a missed clue from re-enumeration, not a novel exploit.
→ [src: https://www.brunorochamoura.com/posts/cpts-tips/]

### Break / sleep (don't reach for AI)
**IF** you're fatigued or have been at the desk for hours →
- [ ] step away; sleep 7–8h, hydrate, walk.
- ⚠️ "A path invisible at 2 AM becomes obvious after 8 hours of sleep"; a failed attempt #1 came partly from too little sleep; AI is a *poor* un-stick tool (hallucinates). [src: https://fernale.blogspot.com/2025/06/my-experience-with-hack-box-cpts.html]
- [ ] fails → fatigue directly causes missed clues and rabbit holes over a 10-day run.
- [ ] ⏱ schedule daily sleep + a walk/Pomodoro; leave the desk before reaching for AI.
→ [src: https://archwarden.com/posts/cpts-exam-what-nobody-tells-you/]

### Nudge etiquette
**IF** stuck during PREP →
- [ ] ask for the smallest possible hint, then re-derive the step yourself.
- ⚠️ A nudge (IppSec/0xdf video, related writeup, HTB Discord) is fine during prep; during the EXAM there is no hint system and support will NOT give hints. [src: https://www.brunorochamoura.com/posts/cpts-tips/]
- [ ] fails → replace "ask for help" with "re-read the relevant module / apply methodology".
- [ ] ⏱ build the nudge muscle on boxes (AEN) so the exam is solo-with-methodology.
→ [src: https://www.brunorochamoura.com/posts/cpts-tips/]

## Readiness validation
### AEN blind (primary gate)
**IF** you're deciding whether you're ready →
- [ ] run Attacking Enterprise Networks (AEN) completely blind: no walkthrough, no reading the questions. ⚠️ [src: https://www.brunorochamoura.com/posts/cpts-tips/]
- ⚠️ clear AEN blind in ~5 days or less → likely ready; heavy help needed = refine methodology first; AEN walks one flag at a time, the exam chains vulns to a single flag (a sim, not the exam). [src: https://www.brunorochamoura.com/posts/cpts-tips/]
- [ ] fails → re-do AEN with hints to fill gaps, then run it blind again under a time limit.
- [ ] ⏱ treat AEN + a full practice report as the readiness gate.
→ [src: https://www.brunorochamoura.com/posts/cpts-tips/]

### Other validation paths
**IF** AEN is done →
- [ ] validate via hardened methods: fresh-eyes skill assessments, the IppSec CPTS playlist as a stress test, optional Pro Labs. ⚠️ [src: https://github.com/ProfessorAnkush/CPTS-Exam-/blob/main/HTB-CPTS-Preparation-and-Reporting-Guide]
- ⚠️ IppSec playlist: at each step ask "what would I do next?"; optional Pro Labs (Dante = pivoting, Zephyr = AD); sources disagree on Pro Labs' necessity. [src: https://github.com/ProfessorAnkush/CPTS-Exam-/blob/main/HTB-CPTS-Preparation-and-Reporting-Guide]
- [ ] fails → boxes (Forest, Tombwatcher) + Ligolo drills are a fine substitute.
- [ ] ⏱ drill the core toolset (NetExec, Ligolo-ng, BloodHound CE, Impacket, PowerView, evil-winrm, Rubeus, Certipy, Responder/Kerbrute).
→ [src: https://github.com/ProfessorAnkush/CPTS-Exam-/blob/main/HTB-CPTS-Preparation-and-Reporting-Guide]

### Prep tracking (own notes)
**IF** planning/measuring exam prep →
- [ ] complete the Penetration Tester path (HTB Academy)
- [ ] the IppSec unofficial CPTS prep playlist
- [ ] the HTB official CPTS prep track (16 machines)
- [ ] the Intro to Dante track (14 machines)
- [ ] Pro Labs P.O.O.
- [ ] Pro Labs Dante
- [ ] TryHackMe "Attacking Enterprises" room (own methodology, no hints).
→ [[0. Prep|src]]

### Retake mechanics
**IF** you must use a second attempt →
- [ ] resume, don't restart: the lab environment does NOT change between attempts.
- ⚠️ retake preserved within the 14-day post-feedback window; feedback focuses on the report; submit attempt-1's report to be eligible; keep an organized folder so attempt 2 resumes. [src: https://help.hackthebox.com/en/articles/12741732-academy-certifications]
- [ ] fails → feedback is report-centric and won't hand you flag hints.
- [ ] ⏱ aim to pass in a single attempt; the 14-day window can be tight.
→ [src: https://help.hackthebox.com/en/articles/12741732-academy-certifications]

## Evidence-capture honesty marker
- `GAP:` `24. Documentation and Reporting/2. Evidence Capturing.md` contains only the heading `##### What to capture` with an empty body — no capture rules, screenshot list, or timing. Minimal capture checklist: prefer terminal output over screenshots, annotate/crop, redact creds/hashes, one figure per step, black bars edited into the image. Full rules → §Report requirements checklist above.
→ [[24. Documentation and Reporting/2. Evidence Capturing|src]]
