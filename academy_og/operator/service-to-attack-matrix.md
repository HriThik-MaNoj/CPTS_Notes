# Service-to-Attack Mapping Matrix

## Purpose
Rapid lookup: Given a service, what can I get from it at every stage of the attack lifecycle?

---

## SMB (139, 445)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | smbclient -N -L, rpcclient enumdomusers, enum4linux -a, smbmap -u "" |
| **Credential Opportunities** | Shares → configs/web.config/backups, GPP cpassword, registry hives |
| **Exploitation** | MS17-010, PrintNightmare, SMBGhost (CVE-2020-0796), pass-the-hash |
| **PrivEsc Opportunities** | PSExec → SYSTEM, WMIexec, schtask execution |
| **AD Opportunities** | Null session → user list → spray, signing disabled → relay → ADCS → DA |
| **Lateral Movement** | PTH with psexec/wmiexec/smbexec, sessions check, share pivot |

---

## LDAP (389, 636)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | ldapsearch -x -b, netexec ldap -M users, bloodhound-python |
| **Credential Opportunities** | Description fields, service accounts, LAPS ms-Mcs-AdmPwd |
| **Exploitation** | ADCS ESC1-8 via LDAP, delegation abuse, RBCD, shadow credentials |
| **PrivEsc Opportunities** | AD access → domain admin path identification |
| **AD Opportunities** | AS-REP roastable user discovery, Kerberoastable SPNs, delegation flags |
| **Lateral Movement** | LDAP queries for high-value targets, admin SD holder info |

---

## Kerberos (88)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | kerbrute userenum, nmap --script krb5-enum-users |
| **Credential Opportunities** | AS-REP roast (GetNPUsers), Kerberoast (GetUserSPNs) |
| **Exploitation** | Pass-the-Ticket, Golden Ticket, Silver Ticket, DC-Sync |
| **PrivEsc Opportunities** | Cracked TGT → domain user, cracked service hash → lateral |
| **AD Opportunities** | Delegation abuse, constrained delegation abuse, RBCD |
| **Lateral Movement** | Kerberos auth via ticket, PTH via krb5, service ticket reuse |

---

## WinRM (5985, 5986)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | netexec winrm target -u users.txt -p passwords.txt |
| **Credential Opportunities** | Password spray results, hash reuse |
| **Exploitation** | evil-winrm -i target -u user -p pass, evil-winrm -i target -u user -H hash |
| **PrivEsc Opportunities** | SeImpersonate → PrintSpoofer → SYSTEM, whoami /priv check |
| **AD Opportunities** | Domain user → BloodHound, domain admin → full compromise |
| **Lateral Movement** | WinRM to other hosts, upload/download with evil-winrm |

---

## MSSQL (1433)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | nmap --script ms-sql-info, netexec mssql -u sa -p '', mssqlclient.py |
| **Credential Opportunities** | Default SA creds, linked servers, DB contents |
| **Exploitation** | xp_cmdshell → RCE, xp_dirtree → hash capture linked server abuse |
| **PrivEsc Opportunities** | SA → xp_cmdshell → SYSTEM, linked server → jump |
| **AD Opportunities** | Windows auth MSSQL → domain user context, AD enumeration via SQL |
| **Lateral Movement** | Linked servers, hash capture → relay → new host |

---

## MySQL (3306)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | mysql -h target -u root, netexec mysql target -u root -p '' |
| **Credential Opportunities** | DB contents (users, passwords), config files via LOAD_FILE |
| **Exploitation** | INTO OUTFILE → webshell, UDF injection → RCE, SQLi |
| **PrivEsc Opportunities** | MySQL as root → UDF → OS command as root |
| **AD Opportunities** | Rare (MySQL typically Linux-based) |
| **Lateral Movement** | Credential reuse from DB contents (same password elsewhere) |

---

## FTP (21)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | ftp target (anon login), nc -nv target 21, netexec ftp -u anon |
| **Credential Opportunities** | Configs, SSH keys, backups, hidden files, .my.cnf |
| **Exploitation** | vsFTPd 2.3.4 backdoor, writable upload → trigger → RCE |
| **PrivEsc Opportunities** | Found SSH key → SSH access, found creds → reuse |
| **AD Opportunities** | None directly (FTP is typically standalone) |
| **Lateral Movement** | Credential reuse from found files across other services |

---

## NFS (2049)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | showmount -e target, mount -t nfs target:/share /mnt/nfs |
| **Credential Opportunities** | SSH keys, configs, backups, .bash_history |
| **Exploitation** | no_root_squash → SUID upload → root, writable → authorized_keys |
| **PrivEsc Opportunities** | Root on NFS client via no_root_squash |
| **AD Opportunities** | Rare; NFS typically Linux-based |
| **Lateral Movement** | SSH keys found → SSH to other hosts |

---

## DNS (53)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | dig axfr @target domain.local, dig ANY, gobuster dns |
| **Credential Opportunities** | None directly (recon only) |
| **Exploitation** | Zone transfer → full host map, DNS poisoning via Responder |
| **PrivEsc Opportunities** | None directly |
| **AD Opportunities** | SRV records → DC/LDAP/Kerberos discovery, subdomain → AD env mapping |
| **Lateral Movement** | Host discovery → targeted enumeration |

---

## SNMP (161, 162)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | snmpwalk -v2c -c public, onesixtyone -c dict.txt target |
| **Credential Opportunities** | User lists (Windows), processes (software versions) |
| **Exploitation** | SNMP set (write) → config changes (rare) |
| **PrivEsc Opportunities** | Software version → known exploit → RCE |
| **AD Opportunities** | Domain name, DC info, network topology |
| **Lateral Movement** | Network topology → pivot path identification |

---

## HTTP/HTTPS (80, 443, 8080, 8443)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | whatweb, gobuster dir, ffuf, nikto, nmap --script http-* |
| **Credential Opportunities** | Admin creds in configs, DB connection strings, .env, .git |
| **Exploitation** | LFI → RFEI → RCE, SQLi → DB dump, file upload → shell, command injection |
| **PrivEsc Opportunities** | Web shell → OS user → sudo/SUID/cron check |
| **AD Opportunities** | Web app as domain service account, form auth → AD creds |
| **Lateral Movement** | DB creds → database access, admin creds → other apps |

---

## SSH (22)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | nmap -sV -p 22, netexec ssh -u users -p passwords |
| **Credential Opportunities** | SSH keys found elsewhere, password reuse, default creds |
| **Exploitation** | Weak creds → SSH shell, key-based auth with found key |
| **PrivEsc Opportunities** | SSH as user → sudo -l → root, SUID check |
| **AD Opportunities** | None directly (SSH on Linux, rarely domain-jointed) |
| **Lateral Movement** | Key reuse across hosts, tunnel setup via SSH proxy |

---

## POP3/IMAP (110, 143, 995, 993)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | nmap -sV, telnet target 110 to grab banner |
| **Credential Opportunities** | Plaintext creds in email, password reset emails |
| **Exploitation** | Weak creds → read email → sensitive data |
| **PrivEsc Opportunities** | None directly |
| **AD Opportunities** | AD user emails, internal app notifications |
| **Lateral Movement** | Creds found in email → reuse |

---

## RDP (3389)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | nmap -sV -p 3389, ncrack/ hydra for brute force |
| **Credential Opportunities** | Password spray high-value target |
| **Exploitation** | BlueKeep (CVE-2019-0708), RDP relay, credential theft |
| **PrivEsc Opportunities** | RDP session → GUI access → UAC bypass → admin |
| **AD Opportunities** | RDP to DC → full GUI control if DA |
| **Lateral Movement** | RDP to multiple hosts with same creds |

---

## SMTP (25, 587)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | nmap --script smtp-commands, smtp-user-enum, VRFY/EXPN |
| **Credential Opportunities** | User enumeration via VRFY/EXPN/RCPT TO |
| **Exploitation** | Relaying (open relay → spam), phishing |
| **PrivEsc Opportunities** | None directly |
| **AD Opportunities** | User list via email, internal email discovery |
| **Lateral Movement** | Internal email access → credential phishing |

---

## Redis (6379)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | redis-cli -h target, INFO command, CONFIG GET dir |
| **Credential Opportunities** | Keys with sensitive data, SSH keys in memory |
| **Exploitation** | CONFIG SET dir → write SSH key → SSH, CONFIG SET dir → write crontab → RCE |
| **PrivEsc Opportunities** | Writable SSH/cron → root level execution |
| **AD Opportunities** | None directly (typically Linux) |
| **Lateral Movement** | SSH key write → host access, credential reuse |

---

## RPC (135)

| Phase | What To Do |
|-------|------------|
| **Enumeration** | rpcclient -U "" -N, impacket-rpcdump |
| **Credential Opportunities** | User enumeration via rpcclient, password policy |
| **Exploitation** | Rare direct exploitation |
| **PrivEsc Opportunities** | None directly |
| **AD Opportunities** | User list → spray, domain info, DC identification |
| **Lateral Movement** | Target identification for lateral paths |

---

## Global Credential Flow

```
Every credential found → Test on ALL protocols (SMB, WinRM, SSH, MSSQL, RDP)
Every hash found → PTH before cracking
Every password found → Password reuse sweep on all hosts
Every SSH key found → Check all hosts in subnet
```
