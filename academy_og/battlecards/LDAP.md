# LDAP Battle Card

## What to Check First
```
1. ANONYMOUS BIND → ldapsearch -H ldap://target -x -b "" -s base namingcontexts
2. ENUM DOMAIN → ldapsearch -H ldap://target -x -b "DC=domain,DC=local"
3. NULL CREDENTIALS → netexec ldap target -u "" -p "" -M users
```

## High-Value Findings
- **Anonymous bind enabled** → Full domain user/machine enumeration
- **Password in description** → Users with creds in description field
- **AS-REP roastable users** → No Kerberos pre-auth required
- **Domain admins group** → Identify DA targets
- **Service accounts** → Potential Kerberoast targets
- **LAPS ms-Mcs-AdmPwd** → Read local admin passwords
- **Delegation (unconstrained)** → Ticket theft possible

## Immediate Commands
```
# Check anonymous bind
ldapsearch -H ldap://target -x -b "DC=exam,DC=local" -s base

# Dump all users
ldapsearch -H ldap://target -x -b "DC=exam,DC=local" "(objectClass=user)" samaccountname | grep sAMAccountName

# Dump all computers
ldapsearch -H ldap://target -x -b "DC=exam,DC=local" "(objectClass=computer)" name

# Dump domain admins
ldapsearch -H ldap://target -x -b "DC=exam,DC=local" "(memberOf=CN=Domain Admins,CN=Users,DC=exam,DC=local)" samaccountname

# BloodHound via LDAP
bloodhound-python -d exam.local -u "" -p "" -ns target -c all

# With creds
netexec ldap target -u user -p pass --bloodhound -c all
netexec ldap target -u user -p pass --gmsa   # Read gMSA passwords
netexec ldap target -u user -p pass -M ldap-checker
ldapdomaindump ldap://target -u 'domain\user' -p 'pass'
```

## Common Attack Paths
```
ANONYMOUS BIND → Users → Password Spray → First Shell
ANONYMOUS BIND → AS-REP Users → Crack Hash → Access
ANONYMOUS BIND → Domain Admins List → Targeted Attacks
LDAP w/ CREDS → Delegation → Unconstrained → Ticket Theft
LDAP w/ CREDS → LAPS → Local Admin Passwords → Lateral
```

## Escalation Paths
- **User list from LDAP** → Password spray → Domain user → AD enumeration
- **LAPS read** → Local admin on any LAPS-managed machine
- **Unconstrained delegation** → Compromise server → Ticket capture → DA
- **AS-REP users** → Crack hash → Domain user access

## When to Stop
- Anonymous bind fully blocked (no data returned)
- Move to Kerberos attacks or SMB enum

## Common Mistakes
- Not checking anonymous bind before trying SMB null session
- Only using `netexec` when raw `ldapsearch` gives more control
- Missing AS-REP roastable users in anonymous dump
- Not dumping ALL objects (groups, computers, service accounts)
- Forgetting BloodHound ingestion from LDAP dump
