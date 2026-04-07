# Master Gap Analysis: Academy OG vs Both Methodologies

> **Date:** April 7, 2026
> **Source:** 31 markdown files in `/home/hri7hik/CPTS_Notes/academy_og/`
> **Analyzers:** 8 parallel agents, one per domain
> **Target Documents:** Comprehensive Methodology + Decision Tree Methodology

---

## Summary Statistics

| Domain | Academy Files Analyzed | Gaps Found |
|--------|----------------------|------------|
| Footprinting / Nmap / Info Gathering | 3 files | ~30 |
| Web Applications (Ffuf, XSS, SQLi, LFI, Upload, CmdInj, Proxies) | 10 files | ~45 |
| Common Services & Applications | 2 files | ~25 |
| Active Directory + Password Attacks | 2 files | ~40 |
| Shells & Payloads + File Transfers + Metasploit | 3 files | ~121 |
| Pivoting, Tunneling & Port Forwarding | 1 file | ~90 |
| Linux + Windows Privilege Escalation | 2 files | ~50 |
| Enterprise / Process / Exam / Reporting / Getting Started | 6 files | ~20 |
| **TOTAL** | **31 files** | **~421 gaps** |

---

## Gap Priority Classification

### 🔴 CRITICAL — Must Add (Blocks Exam Success)

| # | Gap | Domain | Target Doc |
|---|-----|--------|-----------|
| C1 | Metasploit database integration (msfdb, db_nmap, db_import, workspaces, hosts, services, creds, loot) | MSF | Both |
| C2 | Pass-the-Hash comprehensive (Mimikatz, evil-WinRM /pth, xfreerdp /pth, Restricted Admin Mode, UAC bypass via LocalAccountTokenFilterPolicy) | AD/LatMove | Both |
| C3 | Pass-the-Ticket (Windows: Mimikatz/Rubeus ticket harvesting, OverPass-the-Hash; Linux: ccache abuse, keytab extraction, ticket conversion) | AD/LatMove | Both |
| C4 | SAM/SYSTEM/SECURITY hive extraction (reg save, secretsdump, DCC2 cracking, hashcat mode 2100) | CredDump | Both |
| C5 | NTDS.dit extraction (VSS shadow copy, ntdsutil, secretsdump -just-dc, DCC2 explanation) | AD | Both |
| C6 | NTLM Relay chains (Responder SMB disable, impacket-ntlmrelayx -c, MSSQL xp_dirtree forced auth, ADCS ESC8) | AD | Both |
| C7 | AD CS Attacks (ESC8, Shadow Credentials, PassTheCert) | AD | Both |
| C8 | LSASS memory dump CLI (rundll32 comsvcs.dll MiniDump, Mimikatz sekurlsa::logonpasswords, pypykatz) | CredDump | Both |
| C9 | Linux credential hunting (Mimipenguin, LaZagne, KeyTab files, ccache files, Linikatz, Firefox Decrypt) | CredDump | Both |
| C10 | Windows Credential Manager (cmdkey /list, runas /savecred, Mimikatz sekurlsa::credman) | CredDump | Both |
| C11 | DPAPI credential extraction (Chrome/Edge passwords, RDP files) | CredDump | Both |
| C12 | TTY stabilization alternatives when Python absent (Perl, Ruby, Lua, AWK, find, VIM, /bin/sh -i) | Shells | Both |
| C13 | Non-TTY shell concept + why sudo -l fails in non-TTY | Shells | Both |
| C14 | CMD vs PowerShell decision framework (when to use each, technical differences) | Shells | Decision Tree |
| C15 | File transfer: BITS, WebDAV, RDP drive mounting, WinRM PS remoting, JS/VBS download cradles, certutil, /dev/tcp | Transfers | Both |
| C16 | File transfer: FTP command files for non-interactive shells, SMB guest auth blocking, SSL/TLS bypass, user agent evasion | Transfers | Both |
| C17 | Hashcat comprehensive (modes, rule-based attacks, custom rules, combinator attacks) | Cracking | Both |
| C18 | John the Ripper (usage patterns, rules, incremental modes) | Cracking | Both |
| C19 | Custom wordlist generation (cupp, CeWL, username-anarchy, password pattern analysis) | Cracking | Both |
| C20 | Protected file cracking (ZIP, PDF, SSH keys, KeePass, 7z) | Cracking | Both |

### 🟠 HIGH — Should Add (Significant Impact)

| # | Gap | Domain | Target Doc |
|---|-----|--------|-----------|
| H1 | Meterpreter full command catalog (filesystem, networking, system, UI, webcam, audio, priv esc, password dump) | MSF | Comprehensive |
| H2 | Metasploit plugin system (installation, catalog, usage examples like Nessus) | MSF | Comprehensive |
| H3 | Metasploit advanced search (-o, -S, -u, -s, -r flags; all columns) | MSF | Comprehensive |
| H4 | Metasploit encoder architecture (SGN limitations, iterations, VirusTotal analysis, available encoders by arch) | MSF | Comprehensive |
| H5 | Metasploit session/job management (background, sessions -i, jobs -l/-K, exploit -j) | MSF | Both |
| H6 | Meterpreter payload architecture (DLL injection, in-memory only, AES encryption, initialization sequence) | Shells | Comprehensive |
| H7 | Staged vs Stageless decision framework (bandwidth vs reliability vs evasion) | Shells | Decision Tree |
| H8 | Windows NX vs NO-NX stagers, middle stagers concept | Shells | Comprehensive |
| H9 | Windows Defender AV real-time disable (Set-MpPreference -DisableRealtimeMonitoring $true) | Shells | Both |
| H10 | WSL as attack vector (firewall/Defender blind spot) | Shells | Comprehensive |
| H11 | PowerShell Core on Linux (avoids Windows AV/EDR) | Shells | Comprehensive |
| H12 | Laudanum web shell toolkit, Antak Webshell, WhiteWinterWolf shell | Shells | Comprehensive |
| H13 | Web shell considerations (auto-delete, limited interactivity, browser instability) | Shells | Comprehensive |
| H14 | Burp Suite content-type bypass for file upload | Web | Both |
| H15 | DNS cache poisoning (Ettercap/Bettercap MITM DNS spoofing) | Services | Both |
| H16 | Subdomain takeover (dangling CNAME, AWS S3 bucket claiming) | Recon | Both |
| H17 | FTP bounce attacks (PORT command abuse) | Services | Comprehensive |
| H18 | RDP session hijacking (tscon abuse, service-based hijacking) | Services | Both |
| H19 | MSSQL linked server abuse + impersonation chains + xp_dirtree hash stealing | Services | Both |
| H20 | O365spray for cloud email enumeration/spraying | Services | Both |
| H21 | Open relay abuse (smtp-open-relay detection, swaks) | Services | Both |
| H22 | Network traffic credential capture (tcpdump/Wireshark for cleartext protocols) | CredHunt | Both |
| H23 | Network share credential pillaging (Snaffler, config file searches, SSH key hunting) | CredHunt | Both |
| H24 | File encryption (OpenSSL enc on Linux, Invoke-AESEncryption.ps1 on Windows) | Transfers | Both |
| H25 | User Agent detection/evasion (PowerShell, WinHttpRequest, Certutil, BITS UA strings; changing UA) | Transfers | Both |
| H26 | LOLBAS project specifics (CertReq.exe -Post/-config, GfxDownloadWrapper.exe) | Transfers | Comprehensive |
| H27 | GTFOBins search syntax (+file download, +file upload) | Transfers | Comprehensive |
| H28 | Nmap firewall/IDS evasion (fragment, decoy, timing, script evasion) | Nmap | Both |
| H29 | SOCKS4 vs SOCKS5 differences, NAT traversal capabilities | Pivoting | Both |
| H30 | Pivoting: Lateral Movement vs Pivoting vs Tunneling comparison table | Pivoting | Decision Tree |
| H31 | Pivoting: Detection & Prevention (baseline establishment, MITRE mapping, beaconing detection) | Pivoting | Comprehensive |
| H32 | Pivoting: dnscat2 full commands (server help, window -i, direct connection mode, auto_attach) | Pivoting | Both |
| H33 | Pivoting: rpivot full commands (server, client, NTLM proxy auth) | Pivoting | Comprehensive |
| H34 | Pivoting: ptunnel-ng full commands (server, client, stats, privilege dropping, Wireshark analysis) | Pivoting | Comprehensive |
| H35 | Pivoting: SocksOverRDP details (DLL registration, netstat verification, DVC explanation) | Pivoting | Comprehensive |
| H36 | Pivoting: sshuttle limitations (UDP off, DNS forwarding, iptables rules, autossh) | Pivoting | Comprehensive |
| H37 | Pivoting: Windows firewall blocks ICMP by default (affects host discovery through proxychains) | Pivoting | Decision Tree |
| H38 | PrivEsc: Linux — capabilities abuse (getcap), wildcard injection, PATH hijacking, NFS root squashing | PrivEsc | Both |
| H39 | PrivEsc: Windows — token impersonation, AlwaysInstallElevated, SeBackupOperator, SeRestoreOperator | PrivEsc | Both |
| H40 | PrivEsc: Automated tools (linpeas.sh, winPEAS, PowerUp, SharpUp, PrivescCheck) | PrivEsc | Both |

### 🟡 MEDIUM — Should Add (Completeness)

| # | Gap | Domain | Target Doc |
|---|-----|--------|-----------|
| M1 | Metasploit file system layout (Data, Documentation, Lib, Modules, Plugins, Scripts, Tools) | MSF | Comprehensive |
| M2 | Metasploit module naming convention breakdown | MSF | Comprehensive |
| M3 | Metasploit interactable vs non-interactable modules | MSF | Comprehensive |
| M4 | Metasploit mixins concept | MSF | Comprehensive |
| M5 | Metasploit banner info interpretation | MSF | Comprehensive |
| M6 | Metasploit msf-virustotal tool integration | MSF | Comprehensive |
| M7 | Metasploit target types and return addresses (jmp esp, pop/pop/ret) | MSF | Comprehensive |
| M8 | Metasploit singles vs stagers vs stages detailed explanation | MSF | Comprehensive |
| M9 | GNU Netcat vs Ncat distinction (SSL, IPv6, SOCKS/HTTP proxy, --send-only, --recv-only) | Shells | Comprehensive |
| M10 | Bind shell challenges (pre-existing listener, firewall rules, NAT/PAT, OS firewalls) | Shells | Comprehensive |
| M11 | PowerShell reverse shell one-liner full dissection | Shells | Comprehensive |
| M12 | PowerShell script version (Nishang Invoke-PowerShellTcp with -Reverse/-Bind) | Shells | Comprehensive |
| M13 | Why port 443 for reverse shells (rationale, DPI caveat) | Shells | Comprehensive |
| M14 | Payload naming convention by OS (linux/, windows/, osx/, etc.) | Shells | Comprehensive |
| M15 | MSFVenom flags deep breakdown (-p, -f, >, LHOST, LPORT) | Shells | Comprehensive |
| M16 | Terminal emulator catalog per OS | Shells | Comprehensive |
| M17 | Command language interpreter identification techniques (ps, $SHELL, prompt character) | Shells | Comprehensive |
| M18 | Web shell perspectives framework (Computing, Exploitation, Web) | Shells | Comprehensive |
| M19 | TTL-based OS fingerprinting (Windows=32/128, Linux=64) | Nmap | Comprehensive |
| M20 | Windows-specific prominent exploits catalog (MS08-067, EternalBlue, PrintNightmare, BlueKeep, Zerologon, etc.) | Exploits | Comprehensive |
| M21 | Social engineering payload delivery vectors (email attachments, download links, USB dead drops) | Shells | Comprehensive |
| M22 | Ncat as default nc on Pwnbox | Shells | Comprehensive |
| M23 | File transfer: HTTPS upload server with self-signed certs | Transfers | Comprehensive |
| M24 | File transfer: Python requests module upload one-liner | Transfers | Comprehensive |
| M25 | File transfer: temporary SSH user accounts for transfers | Transfers | Comprehensive |
| M26 | File transfer: MD5 hash verification workflow (md5sum vs Get-FileHash) | Transfers | Both |
| M27 | File transfer: data exfiltration professional guidance (don't exfil PII) | Transfers | Comprehensive |
| M28 | File transfer: OpenSSL file transfer "nc style" (s_server/s_client) | Transfers | Comprehensive |
| M29 | File transfer: Nginx PUT upload server | Transfers | Comprehensive |
| M30 | Web: XSS subtypes (reflected, stored, DOM-based, CSP bypass, etc.) | Web | Both |
| M31 | Web: SQLi subtypes (UNION, boolean-based, time-based, error-based, out-of-band) | Web | Both |
| M32 | Web: File upload bypasses (MIME type, extension, magic bytes, double extension, null byte) | Web | Both |
| M33 | Web: Command injection bypasses (space bypass, slash bypass, blacklist bypass) | Web | Comprehensive |
| M34 | Web: Login brute forcing tools and techniques (hydra, ffuf, Burp Intruder) | Web | Both |
| M35 | Web: Web proxy usage (Burp Suite, OWASP ZAP, interception, modification, repeater) | Web | Comprehensive |
| M36 | Web: ffuf advanced usage (recursion, auto-tuning, filtering, rate limiting, headers) | Web | Both |
| M37 | DNS: Subdomain brute force with specific tools and wordlists | DNS | Both |
| M38 | Kerberos: pre-auth enumeration nuances (why Kerbrute doesn't trigger Event ID 4625) | AD | Comprehensive |
| M39 | AD: BloodHound usage patterns (SharpHound, AzureHound, Cypher queries) | AD | Both |
| M40 | AD: LDAP enumeration (anonymous bind, windapsearch, PowerView) | AD | Both |
| M41 | Exam: CPTS-specific strategies, time management, documentation requirements | Exam | Decision Tree |
| M42 | Reporting: documentation standards, evidence collection, business impact focus | Reporting | Both |
| M43 | Process: Rules of engagement, scoping, legal considerations | Process | Comprehensive |
| M44 | Vuln Assessment: vulnerability scoring (CVSS), prioritization, validation | VulnAssess | Comprehensive |
| M45 | Getting Started: VPN setup, Pwnbox usage, lab access | GettingStarted | Decision Tree |

### 🟢 LOW — Nice to Have

| # | Gap | Domain | Target Doc |
|---|-----|--------|-----------|
| L1 | Palo Alto Networks and MITRE references for Lateral Movement | Pivoting | Comprehensive |
| L2 | Network diagramming recommendation (Draw.io, diagrams.net) | Pivoting | Comprehensive |
| L3 | BYOD risk scenario | Pivoting | Comprehensive |
| L4 | Multi-factor authentication factors (have, know, are, location) | Process | Comprehensive |
| L5 | SOC team / SOC as a Service recommendation | Process | Comprehensive |
| L6 | Incident response planning guidance | Process | Comprehensive |
| L7 | Gold images and baseline security hardening guidelines | Process | Comprehensive |
| L8 | Change management processes | Process | Comprehensive |
| L9 | Perimeter security mental exercise (firewall capabilities, NGF, OOB, DR) | Process | Comprehensive |
| L10 | Internal defense considerations (DMZ, IDS/IPS, segmentation, SIEM) | Process | Comprehensive |
| L11 | HTB box recommendations for practice (Enterprise, Inception, Reddish) | Learning | Comprehensive |
| L12 | Pro Lab recommendations (RastaLabs, Dante, Offshore) | Learning | Comprehensive |
| L13 | Recommended creators/blogs (0xdf, RastaMouse, SpecterOps, Ippsec) | Learning | Comprehensive |
| L14 | 3-5 minute lab spawn wait time warning | Pivoting | Decision Tree |
| L15 | GLIBC version matching between target and workstation | Pivoting | Both |
| L16 | Meterpreter scripts deprecation warning (autoroute) | Pivoting | Comprehensive |
| L17 | Metasploit Pro vs Framework feature comparison table | MSF | Comprehensive |
| L18 -| Metasploit msfupdate deprecated in favor of apt | MSF | Comprehensive |
| L19 | Metasploit grep within msfconsole | MSF | Comprehensive |
| L20 | Empire and Cobalt Strike mention (professional tools) | MSF | Comprehensive |

---

## Execution Plan

### Phase 1: Add CRITICAL gaps (C1-C20)
### Phase 2: Add HIGH gaps (H1-H40)
### Phase 3: Add MEDIUM gaps (M1-M45)
### Phase 4: Add LOW gaps (L1-L20)
### Phase 5: Final review — verify zero gaps remain

---

*Total gaps: ~421*
- Critical: 20
- High: 40
- Medium: 45
- Low: 20
- Already covered (verified): ~296
