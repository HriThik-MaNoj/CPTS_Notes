# FTP Battle Card

## What to Check First
```
1. PORT 21? → nmap -sV -p 21 target
2. ANONYMOUS? → ftp target (user: anonymous, pass: anonymous)
3. BANNER GRAB → nc -nv target 21
4. ANON CHECK → netexec ftp target -u anonymous -p anonymous
```

## High-Value Findings
- **Anonymous login enabled** → Free file access
- **Readable files** → Configs, SSH keys, backups, creds
- **Writable directory** → File upload potential
- **Banner reveals version** → Exploit search (ProFTPD, vsFTPD)
- **FTP backdoor (vsFTPD 2.3.4)** → Immediate shell
- **.txt/.md/.cfg files** → Notes, instructions, creds

## Immediate Commands
```
# Anonymous login
ftp target
  anonymous@target.com
  ls -la  # Check for interesting files
  passive  # Toggle passive mode if needed
  bin    # Binary mode for downloads

# Recursive download with wget
wget -m --no-passive-ftp ftp://anonymous:anonymous@target/

# Download all files (non-interactive)
wget -r ftp://anonymous:anonymous@target/

# Check banner for version
nc -nv target 21 | tee ftp-banner.txt

# Search for interesting files
grep -r 'password\|cred\|key\|\.ssh\|backup' ftp-downloads/

# If creds found
ftp user:pass@target

# vsFTPd 2.3.4 backdoor check
nmap --script ftp-vsftpd-backdoor -p 21 target
```

## Common Attack Paths
```
ANONYMOUS → Browse → Creds/Configs → Password Reuse → Shell
ANONYMOUS → SSH Key Found → SSH Access → Shell
ANONYMOUS → Backup File → Enumerate DB/App Creds → Lateral
vsFTPD 2.3.4 BACKDOOR → Root Shell → Full Compromise
FTP WRITABLE → Upload Malicious File → Trigger → RCE
CRED REUSE → FTP creds = same as SSH/RDP → Direct Shell
```

## Escalation Paths
- **SSH key from FTP** → Direct SSH access (check all hosts)
- **Config file creds** → Reuse across services (web, DB, SSH)
- **Backup files** → Application source code → Hardcoded creds
- **Database backup** → Hashes → Crack → DB/App access

## When to Stop
- Anonymous rejected and no banner exploits → Move on
- Downloaded everything → Analyze before time investment
- FTP is rarely the main path (cheap information gather)

## Common Mistakes
- Not trying anonymous login (both username and password)
- Not recursively downloading all files (wget -m)
- Interactive browsing instead of bulk download
- Ignoring hidden files (.bash_history, .ssh, .my.cnf)
- Not checking if FTP creds work on other protocols
- Forgetting to check writable directories for upload
