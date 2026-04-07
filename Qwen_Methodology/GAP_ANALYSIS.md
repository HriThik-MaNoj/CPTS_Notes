# Gap Analysis: Comprehensive Penetration Testing Methodology v1.0

> **Analyst:** Professional Penetration Tester (20+ years experience perspective)
> **Date:** April 7, 2026
> **Source Document:** `Comprehensive_Penetration_Testing_Methodology.md` (2575 lines, 12 phases)
> **Reference Material:** CPTS Notes repository (~180 markdown files across 11 modules)

---

## Executive Summary

The existing methodology document is **well-structured** and covers the fundamental phases of a penetration test. However, after cross-referencing against the CPTS Notes repository, I identified **37 significant gaps** across the attack lifecycle. These range from missing entire attack categories (AD CS attacks, Pass-the-Certificate) to incomplete treatment of critical techniques (credential dumping, NTLM relay chains). Below is the categorized gap inventory with severity ratings.

---

## Gap Inventory by Severity

### CRITICAL — Missing Entire Attack Categories

| # | Gap | Phase Affected | Severity | Source |
|---|-----|---------------|----------|--------|
| C1 | **AD CS Attacks (ESC8, Shadow Credentials, PassTheCert)** — No coverage of Active Directory Certificate Services attacks, which are among the most impactful modern AD attack chains | Phase 8 / 11 | Critical | `8. Password Attacks/20. Pass the Certificate.md`, `20.1 Passs the certificate Claude.md` |
| C2 | **Pass-the-Hash (PtH) comprehensive techniques** — Only mentioned in passing; missing Mimikatz, Invoke-TheHash, evil-WinRM, xfreerdp /pth, Restricted Admin Mode enablement | Phase 11 | Critical | `8. Password Attacks/17. Pass the Hash.md`, `9. Attacking Common Services/3. Attacking SMB.md`, `5. Attacking RDP.md` |
| C3 | **Pass-the-Ticket (PtT) — Windows AND Linux** — Missing ticket harvesting, OverPass-the-Hash, cross-platform ticket conversion, ccache abuse, keytab extraction | Phase 11 | Critical | `8. Password Attacks/18. Pass the Ticket (PtT) from Windows.md`, `19. Pass the Ticket (PtT) from Linux.md`, `19. Pass the Ticket (PtT) from Linux - Comprehensive.md` |
| C4 | **SAM/SYSTEM/SECURITY hive extraction & parsing** — Not covered at all; missing reg save, secretsdump, DCC2 cracking | Phase 10 | Critical | `8. Password Attacks/8. Attacking SAM, SYSTEM, and SECURITY.md` |
| C5 | **NTDS.dit extraction methods** — Mentioned briefly but missing VSS shadow copy extraction, ntdsutil, secretsdump with -just-dc | Phase 11 | Critical | `8. Password Attacks/11. Attacking Active Directory and NTDS.dit.md` |
| C6 | **NTLM Relay attack chains** — Not covered; missing responder SMB disable, impacket-ntlmrelayx with -c command execution, MSSQL xp_dirtree hash stealing | Phase 8 | Critical | `9. Attacking Common Services/3. Attacking SMB.md` |

### HIGH — Missing Credential Hunting & Post-Exploitation

| # | Gap | Phase Affected | Severity | Source |
|---|-----|---------------|----------|--------|
| H1 | **Linux credential hunting** — Missing Mimipenguin, LaZagne, KeyTab file abuse, ccache file abuse, Linikatz, Firefox Decrypt | Phase 10 | High | `8. Password Attacks/14. Credential Hunting in Linux.md`, `13. Linux Authentication Process.md` |
| H2 | **LSASS memory dump (CLI methods)** — Only Task Manager GUI method mentioned; missing rundll32 comsvcs.dll MiniDump, Mimikatz sekurlsa::logonpasswords | Phase 10 | High | `8. Password Attacks/9. Attacking LSASS.md` |
| H3 | **Windows Credential Manager attacks** — Missing cmdkey /list, runas /savecred, Mimikatz sekurlsa::credman | Phase 10 | High | `8. Password Attacks/10. Attacking Windows Credential Manager.md` |
| H4 | **DPAPI credential extraction** — Not mentioned; critical for extracting Chrome/Edge saved passwords, RDP files, etc. | Phase 10 | High | `8. Password Attacks/12. Credential Hunting in Windows.md` |
| H5 | **Network traffic credential capture** — Missing tcpdump/Wireshark for credential extraction from cleartext protocols | Phase 8 | High | `8. Password Attacks/15. Credential Hunting in Network Traffic.md` |
| H6 | **Network share credential pillaging** — Missing Snaffler usage patterns, config file searches, SSH key hunting across shares | Phase 8 | High | `8. Password Attacks/16. Credential Hunting in Network Shares.md` |
| H7 | **OverPass-the-Hash / Pass-the-Key** — Converting NTLM/AES hashes to TGTs via Mimikatz or Rubeus; missing encryption downgrade detection | Phase 11 | High | `8. Password Attacks/18. Pass the Ticket (PtT) from Windows.md` |

### HIGH — Missing Service-Specific Attacks

| # | Gap | Phase Affected | Severity | Source |
|---|-----|---------------|----------|--------|
| H8 | **DNS cache poisoning (Ettercap/Bettercap)** — Missing MITM DNS spoofing for traffic redirection | Phase 4 | High | `9. Attacking Common Services/6. Attacking DNS.md` |
| H9 | **Subdomain takeover** — Missing dangling CNAME detection and AWS S3 bucket claiming | Phase 2 | High | `9. Attacking Common Services/6. AttackingDNS.md` |
| H10 | **FTP bounce attacks** — Missing PORT command abuse for indirect scanning/access | Phase 4 | High | `9. Attacking Common Services/2. Attacking FTP.md` |
| H11 | **RDP session hijacking** — Missing tscon abuse, service-based hijacking | Phase 4 | High | `9. Attacking Common Services/5. Attacking RDP.md` |
| H12 | **MSSQL linked server abuse + impersonation chains** — Missing EXECUTE AS LOGIN, cross-server xp_cmdshell, full AD compromise chain | Phase 4 | High | `9. Attacking Common Services/4. Attacking SQL Databases..md`, `10. Lab Hard.md` |
| H13 | **O365spray for cloud email enumeration/spraying** — Missing cloud-specific authentication attacks | Phase 2/8 | High | `9. Attacking Common Services/7. Attacking Email Services.md` |
| H14 | **Open relay abuse for phishing** — Missing smtp-open-relay detection and swaks usage | Phase 4 | High | `9. Attacking Common Services/7. Attacking Email Services.md` |

### MEDIUM — Missing Metasploit & Evasion

| # | Gap | Phase Affected | Severity | Source |
|---|-----|---------------|----------|--------|
| M1 | **Metasploit database integration** — Missing msfdb init, db_import, db_nmap, db_export, workspaces | Phase 6 | Medium | `7. Metasploit/1. Metasploit.md` |
| M2 | **Local exploit suggester** — Missing post-exploitation priv escalation via MSF modules | Phase 10 | Medium | `7. Metasploit/1. Metasploit.md` |
| M3 | **AV evasion — binary embedding** — Missing msfvenom -k -x for injecting into legitimate executables | Phase 6 | Medium | `7. Metasploit/2. Firewall and IDS or IPS Evation.md` |
| M4 | **AV evasion — password-protected double archiving** — Missing RAR nesting technique to bypass AV archive scanning | Phase 6/7 | Medium | `7. Metasploit/2. Firewall and IDS or IPS Evation.md` |
| M5 | **Metasploit encoder understanding** — Missing knowledge that SGN single-iteration is detected by modern AV; encoder limitations | Phase 6 | Medium | `7. Metasploit/1. Metasploit.md` |
| M6 | **Meterpreter DLL injection for persistence** — Missing understanding of stable, persistent connections across reboots | Phase 7 | Medium | `7. Metasploit/1. Metasploit.md` |
| M7 | **setg (global set) for persistent targeting** — Missing workflow optimization for multi-target engagements | Phase 1 | Medium | `7. Metasploit/1. Metasploit.md` |

### MEDIUM — Missing Password Cracking Depth

| # | Gap | Phase Affected | Severity | Source |
|---|-----|---------------|----------|--------|
| M8 | **John the Ripper techniques** — Missing entirely; no usage patterns, rules, or incremental modes | Phase 8 | Medium | `8. Password Attacks/1. John The Ripper.md` |
| M9 | **Hashcat comprehensive usage** — Missing mode reference, rule-based attacks, custom rules, combinator attacks | Phase 8 | Medium | `8. Password Attacks/2. Hashcat.md` |
| M10 | **Custom wordlist generation** — Missing cupp, CeWL, username-anarchy, password pattern analysis from breached creds | Phase 8 | Medium | `8. Password Attacks/3. Custom wordlists.md` |
| M11 | **Protected file cracking** — Missing John/Hashcat for ZIP, PDF, SSH keys, KeePass, 7z | Phase 8 | Medium | `8. Password Attacks/4. Protected files cracking.md` |
| M12 | **DCC2 (Domain Cached Credentials v2)** — Missing understanding that DCC2 hashes (mode 2100) cannot be used for Pass-the-Hash | Phase 11 | Medium | `8. Password Attacks/8. Attacking SAM, SYSTEM, and SECURITY.md` |

### LOW — Missing Methodology Refinements

| # | Gap | Phase Affected | Severity | Source |
|---|-----|---------------|----------|--------|
| L1 | **Nmap firewall/IDS evasion** — Missing fragment, decoy, timing, and script evasion techniques | Phase 3 | Low | `3. Footprinting/Network Enumeration with Nmap/` |
| L2 | **Kerberos pre-auth enumeration nuances** — Missing understanding of why Kerbrute doesn't trigger Event ID 4625 | Phase 8 | Low | `11. Active Directory Enumeration & Attacks/` |
| L3 | **MSSQL xp_dirtree forced authentication** — Missing technique to steal SQL service account hashes | Phase 4 | Low | `9. Attacking Common Services/3. Attacking SMB.md` |
| L4 | **Web shell persistence detection** — Missing systematic checks for previously planted shells | Phase 7 | Low | `11. Active Directory Enumeration & Attacks/` (post-compromise checks section) |
| L5 | **UAC bypass for local accounts** — Missing LocalAccountTokenFilterPolicy registry key impact on PtH | Phase 10 | Low | `8. Password Attacks/17. Pass the Hash.md` |

---

## Gaps by Phase Coverage Heatmap

```
Phase 1:  Preparation          ██░░░░░░░░  (1 gap — setg usage)
Phase 2:  External Recon       ███░░░░░░░  (3 gaps — subdomain takeover, O365spray, username-anarchy)
Phase 3:  Network Enum         █░░░░░░░░░  (1 gap — Nmap IDS evasion)
Phase 4:  Service Attacks      ██████░░░░  (6 gaps — DNS poison, FTP bounce, RDP hijack, MSSQL chain, open relay, xp_dirtree)
Phase 5:  Web Apps             █░░░░░░░░░  (1 gap — CoreFTP CVE coverage)
Phase 6:  Initial Access       ████░░░░░░  (4 gaps — binary embedding, double archive, encoders, MSF db)
Phase 7:  Post-Exploitation    ███░░░░░░░  (3 gaps — DLL injection, web shell checks, network traffic creds)
Phase 8:  AD Attacks           ████████░░  (8 gaps — NTLM relay, ESC8, Shadow Creds, share pillaging, etc.)
Phase 9:  Pivoting             ██░░░░░░░░  (2 gaps — already well covered)
Phase 10: Priv Escalation     ██████░░░░  (6 gaps — SAM/NTDS, LSASS CLI, Win Cred Manager, DPAPI, Linux creds)
Phase 11: Lateral Movement    ███████░░░  (7 gaps — PtH, PtT, OverPass-the-Hash, DCC2, ACL abuse)
Phase 12: Reporting            ░░░░░░░░░░  (0 gaps — already well covered)
```

---

## Recommendations Priority Order

1. **First:** Add AD CS attacks (ESC8 → DCSync chain) — highest impact in modern AD environments
2. **Second:** Add comprehensive Pass-the-Hash/Pass-the-Ticket/Pass-the-Certificate sections
3. **Third:** Add credential dumping methods (SAM, NTDS.dit, LSASS CLI, Credential Manager, DPAPI)
4. **Fourth:** Add NTLM Relay attack chains (Responder + ntlmrelayx + MSSQL xp_dirtree)
5. **Fifth:** Add Linux credential hunting (Mimipenguin, LaZagne, KeyTab, ccache, Linikatz)
6. **Sixth:** Add Metasploit database, evasion, and local exploit suggester
7. **Seventh:** Add password cracking depth (John, Hashcat rules, custom wordlists, protected files)
8. **Eighth:** Add service-specific attacks (DNS poisoning, subdomain takeover, RDP hijack, MSSQL chains)
9. **Ninth:** Add methodology refinements (Nmap evasion, UAC bypass, Kerbrute stealth)

---

*Total gaps identified: **37***
- Critical: 6
- High: 14
- Medium: 12
- Low: 5
