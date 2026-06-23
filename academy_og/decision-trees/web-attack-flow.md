# Web Application Attack Flow

```
Web server found on port 80/443/8080/8443?
│
├── Fingerprint technology stack
│   ├── WhatWeb, Wappalyzer, HTTP headers
│   ├── CMS? → Wordpress/Joomla/Drupal checklist (Module 08)
│   └── Custom app? → Full test suite below
│
├── Content discovery
│   ├── ffuf directories → Found admin panels, dev portals?
│   ├── ffuf files → .bak, .old, .txt, config files?
│   ├── ffuf vhosts → Different apps on same IP?
│   └── Found interesting endpoint?
│       ├── Login page → Auth testing
│       ├── File upload → Upload attack
│       ├── File viewer/reader → LFI test
│       ├── Search/news/ID parameter → SQLi test
│       └── API endpoint → Parameter fuzzing, injection
│
├── Authentication testing
│   ├── Default credentials? → Try admin:admin, etc.
│   ├── Username enumeration? → Different error messages
│   ├── Password reset? → Token prediction, user enum
│   ├── Registration? → Open registration, user escalation
│   ├── JWT tokens? → alg:none, HS256 confusion, weak secret
│   └── MFA? → Check for bypass, exhausion
│
├── Injection testing
│   ├── Parameter fuzzed with special chars?
│   │   ├── ' or " → SQLi
│   │   ├── <script> → XSS
│   │   ├── ../../../etc/passwd → LFI
│   │   ├── ;id → Command injection
│   │   └── ../..\\ → Path traversal
│   │
│   └── Successful injection?
│       ├── SQLi → Data extraction → File read/write → RCE
│       ├── XSS → Session theft → Admin access → RCE
│       ├── LFI → Config disclosure → Log poisoning → RCE
│       └── CMDi → Reverse shell → Full host access
│
├── File upload testing
│   ├── Can upload PHP/ASP/JSP? → Immediate RCE
│   ├── Filter bypass possible?
│   │   ├── Double extension: shell.php.jpg
│   │   ├── Alternate extension: .phtml, .php5
│   │   ├── Content type: image/jpeg
│   │   └── Magic bytes: GIF89a
│   └── Success? → Upload webshell → RCE
│
├── Business logic testing
│   ├── IDOR? → Change IDs to access others' data
│   ├── HTTP verb tampering? → Try different methods
│   ├── Mass assignment? → Add extra parameters
│   ├── XXE? → XML input → File read/SSRF
│   ├── SSRF? → URL parameter → Internal access
│   └── Open redirect? → Phishing vector
│
└── No success?
    ├── Use Burp scanner (Pro only)
    ├── Re-check with different user roles
    ├── Spider/ajax crawl for hidden endpoints
    └── Check for WebSocket endpoints, API docs
```
