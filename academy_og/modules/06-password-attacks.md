# Module 06: Password Attacks

## When to Use This Module
Use this module when you obtain password hashes (from post-exploitation, network captures, or database dumps) that need cracking, or when you need to perform online password spraying/brute-forcing against authentication services.

## Prerequisites
- Hashes or encrypted credentials to crack, OR
- Target authentication service (SSH, RDP, SMB, web form) with usernames
- Hashcat/John installed + GPU support for fast cracking
- Wordlists (rockyou, SecLists)

## Entry Check

```
Hash obtained?
├── Yes → Identify hash type → Choose cracking mode
│   ├── Offline (hashcat/john) → GPU optimized
│   └── Online (hydra/medusa) → Service-level auth
└── No → Password spraying against known services
    ├── Usernames known? → Spray common passwords
    └── No usernames? → Enumerate users first (Module 02)
```

## Hash Identification

```bash
# Automatic identification
hashid <hash>
hash-identifier <hash>

# Common hash types for hashcat mode (-m)
# NTLM: 1000
# NetNTLMv2: 5600
# Kerberos TGS-REP: 13100
# Kerberos AS-REP: 18200
# SHA-512 (Unix): 1800
# SHA-256 (Unix): 7400
# MD5 (Unix): 500
# bcrypt: 3200
# PBKDF2: 10900 (macOS), 2100 (MS Office)
```

## Offline Cracking with Hashcat

```bash
# Benchmark your GPU
hashcat -b

# Dictionary attack (fastest, try first)
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules (next, catches mutations)
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack (brute force pattern)
hashcat -m <mode> hash.txt -a 3 ?u?l?l?l?l?l?d?d?d

# Rules location: /usr/share/hashcat/rules/
# Popular: best64.rule, d3ad0ne.rule, OneRuleToRuleThemAll.rule

# Show cracked passwords
hashcat -m <mode> hash.txt --show
```

## Password Attack Decision Flow

```
Password attack needed?
├── OFFLINE (I have hashes):
│   ├── Quick wins: rockyou.txt dictionary
│   ├── Medium: dictionary + best64.rule
│   ├── Heavy: mask attack on known pattern
│   └── Time-based: Leave hashcat running overnight
│
├── ONLINE (I have usernames + service):
│   ├── Password policy known?
│   │   ├── Strict lockout → Spray: 1 password, many users
│   │   ├── Lenient policy → Brute force with wordlist
│   │   ├── Unknown → Start spraying conservatively
│   │   └── No policy → Full brute force
│   │
│   ├── Services to attack:
│   │   ├── SSH → hydra -L users.txt -P pass.txt ssh://target
│   │   ├── RDP → hydra -L users.txt -P pass.txt rdp://target
│   │   ├── SMB → netexec smb target -u users.txt -p pass.txt
│   │   ├── WinRM → netexec winrm target -u users.txt -p pass.txt
│   │   └── Web form → hydra target http-post-form "..."
│   │
│   └── Credential stuffing:
│       └── Use known breaches (HaveIBeenPwned, Dehashed)
│
└── I need usernames:
    ├── Web scraping (LinkedIn, company website)
    ├── Kerbrute user enumeration (AD environments)
    ├── SMTP VRFY/EXPN
    └── Common patterns: firstname.lastname, f.lastname
```

## Spraying vs Brute Force

```
Lockout policy:
├── Known: Spray at threshold-1 attempts, wait lockout_duration
├── Unknown: 1-2 sprays with common passwords, wait 1+ hour
└── No lockout: Full brute force

Spraying strategy:
├── Password: <CompanyName>1, <Season><Year>, Welcome1, Password1
├── Target: ALL domain users (100+ accounts)
└── Frequency: 1 attempt per account, wait 30-60 min, next password
```

## Password Mutations (Rules)

```bash
# Common mutation patterns to try:
# Capitalize: password → Password
# Append number: password → password1 → password123
# Append year: password → password2024
# Leet speak: password → p@ssw0rd
# Prepend special: password → !password
# Common combos: CompanyName2024!, Spring2024

# Hashcat rule example
# Use d3ad0ne.rule for comprehensive mutations
hashcat -m 5600 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule
```

## Stolen Credential Reuse

```
Credential found?
├── What service did it come from?
├── Try against other services on same host
├── Try against other hosts in network
├── Spray against AD domain (if applicable)
└── Check for password reuse across different privilege levels
```

## Default Credentials Reference

Always try on first encounter:
- Tomcat: tomcat:tomcat, admin:admin
- Jenkins: admin:admin, admin:password
- WordPress: admin:admin
- MySQL: root:root, root:(empty)
- MSSQL: sa:sa, sa:(empty)
- PostgreSQL: postgres:postgres
- VNC: (no password), password:password
- SNMP: public, private
- phpMyAdmin: root:(empty)
- Splunk: admin:changeme
- PRTG: prtgadmin:prtg

## Cross-References
- For AD-specific password attacks → [Module 11: Active Directory](../modules/11-active-directory.md)
- For web login forms → [Module 04: Web Application](../modules/04-web-application.md)
- For hash dumping techniques → [Module 13: Post-Exploitation](../modules/13-post-exploitation.md)
- Hashcat cheat sheet → [assets/cheatsheets/hashcat.md](../assets/cheatsheets/hashcat.md)

## Output Summary
- [ ] Hash type identified
- [ ] Dictionary attack attempted
- [ ] Rule-based attack attempted
- [ ] Online spraying/brute force completed (within lockout limits)
- [ ] Cracked passwords saved to credentials/ folder
- [ ] Passwords tested for reuse across services
