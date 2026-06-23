# Privilege Escalation Attack Flow

## Linux Privesc Flow

```
Non-root shell obtained on Linux
│
├── Initial enumeration
│   ├── id / whoami → Current user & groups
│   ├── sudo -l → Sudo privileges
│   ├── uname -a → Kernel version
│   ├── find / -perm -4000 -type f 2>/dev/null → SUID binaries
│   ├── getcap -r / 2>/dev/null → Capabilities
│   ├── cat /etc/crontab → Cron jobs
│   ├── ps aux → Running processes
│   ├── netstat -tlnp → Listening ports
│   └── ls -la /home/ → Other users' dirs
│
├── Check SUDO (sudo -l)
│   ├── (ALL) ALL → sudo su / sudo -i → ROOT
│   ├── Specific commands → GTFOBins for each
│   └── env_keep+=LD_PRELOAD → LD_PRELOAD exploit
│
├── Check SUID binaries
│   ├── Common: vim, nmap, less, find, bash, python
│   └── Each → GTFOBins
│
├── Check capabilities
│   ├── cap_setuid → Escalate via binary
│   ├── cap_dac_override → Overwrite protected files
│   ├── cap_sys_admin → Namespace escape
│   └── cap_net_raw → Packet capture
│
├── Check cron jobs
│   ├── Writable script? → Inject reverse shell
│   ├── Wildcard in cron? → tar checkpoint injection
│   └── pspy64 → Monitor for hidden jobs
│
├── Check kernel version
│   ├── searchsploit linux kernel <version>
│   ├── Dirty Pipe (5.8-5.17), PwnKit (CVE-2021-4034)
│   └── WARNING: Kernel exploits may crash system
│
├── Check writable files / PATH
│   ├── Writable /etc/passwd? → Add root user
│   ├── Writable dir in PATH? → Create fake command
│   └── Writable .so in RUNPATH? → DLL hijack
│
└── Still not root?
    ├── Check for other users logged in
    ├── Check for SSH keys in other users' dirs
    ├── Run LinPEAS
    ├── Check for Docker/LXD membership
    └── Check NFS exports (root_squash?)

## Windows Privesc Flow

```
Non-admin shell obtained on Windows
│
├── Initial enumeration
│   ├── whoami → Current user
│   ├── whoami /priv → Token privileges
│   ├── whoami /groups → Group memberships
│   ├── systeminfo → OS version, patch level
│   ├── net localgroup Administrators → Local admins
│   ├── netstat -ano → Listening ports
│   ├── tasklist /SVC → Running services
│   └── wmic service get name,pathname,startname → Services
│
├── Check token privileges (whoami /priv)
│   ├── SeImpersonatePrivilege?
│   │   ├── Win ≤ 2016 → JuicyPotato
│   │   └── Win ≥ 2019 → PrintSpoofer / GodPotato
│   ├── SeDebugPrivilege?
│   │   ├── ProcDump LSASS.exe → Extract creds
│   │   └── psgetsystem → SYSTEM shell
│   ├── SeBackupPrivilege?
│   │   └── robocopy /B SAM/SYSTEM → Extract hashes offline
│   ├── SeTakeOwnershipPrivilege?
│   │   └── takeown + icacls on protected files
│   ├── SeLoadDriverPrivilege?
│   │   └── Capcom.sys → Kernel driver → SYSTEM
│   └── SeRestorePrivilege?
│       └── Write to protected locations
│
├── Check service misconfigurations
│   ├── Unquoted service path?
│   │   └── Insert malicious exe in writable path
│   ├── Writable service binary?
│   │   └── Replace with reverse shell binary
│   ├── Writable service config?
│   │   └── sc config binpath= "cmd /c revshell"
│   └── AlwaysInstallElevated?
│       └── Build malicious MSI → Install as admin
│
├── Check for stored credentials
│   ├── cmdkey /list → Stored creds
│   ├── findstr /si password *.txt *.ini *.config
│   ├── Unattend.xml, web.config, .env files
│   ├── PowerShell history
│   └── GPP cpassword → gpp-decrypt
│
├── Check scheduled tasks
│   ├── schtasks /query /fo LIST /v
│   └── Writable script running as SYSTEM?
│
├── Check UAC bypass (if admin but filtered)
│   ├── fodhelper.exe hijack
│   ├── computerdefaults.exe hijack
│   └── sdclt.exe hijack
│
├── Check kernel exploits
│   ├── systeminfo → Windows Exploit Suggester
│   ├── PrintNightmare (CVE-2021-34527)
│   ├── HiveNightmare (CVE-2021-36934)
│   └── MS17-010 (EternalBlue)
│
└── Still not admin?
    ├── Run WinPEAS
    ├── Check mounted VHDX/VMDK files
    ├── Check registry autoruns
    ├── Check for DLL hijacking opportunities
    └── Check named pipes
```
