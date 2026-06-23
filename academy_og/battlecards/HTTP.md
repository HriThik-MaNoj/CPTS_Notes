# HTTP/HTTPS Battle Card

## What to Check First
```
1. PORTS 80/443/8080/8443? → nmap -sV -p 80,443,8080,8443 target
2. WHATS RUNNING → WhatWeb, Wappalyzer, CMS detection
3. DIR BUST → dirsearch/gobuster/ffuf
4. TECH DETECT → whatweb target -v | tee whatweb.log
```

## High-Value Findings
- **Known CMS** (WordPress/Joomla/Drupal) → Version-specific exploits
- **Admin panels** (/admin, /wp-admin, /manager) → Login brute force
- **File upload** → Upload web shell → RCE
- **LFI/RFI** → File read → Config extraction → RCE
- **SQL injection** → Database dump → Admin creds → Login
- **Command injection** → Immediate RCE
- **Directory listing** → Information disclosure
- **Backup files** (.bak, ~, .old, .sql) → Source/db creds
- **Default credentials** → admin:admin, tomcat:tomcat
- **API endpoints** → /api, /v1, /swagger → API attack surface
- **Source code disclosure** → .git/ HEAD exposed, .env exposed

## Immediate Commands
```
# Tech detection
whatweb target -v
wappalyzer (browser extension - manual)

# Directory brute force
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,asp,aspx,jsp,txt,html,zip -o gobuster.txt
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Extension and file search
gobuster dir -u http://target -w /wordlist.txt -x .php,.asp,.aspx,.jsp,.txt,.old,.bak,.inc,.sql,.zip,.tar.gz

# SQL injection check
sqlmap -u "http://target/page?id=1" --batch --banner
# Manual: ' " ) ' -- # /* in all params

# LFI check
http://target/index.php?page=../../../etc/passwd
ffuf -u http://target/index.php?page=FUZZ -w lfi-wordlist.txt

# Default credentials
# Check /manager/html (Tomcat), /admin, /phpmyadmin, /administrator

# Source code disclosure
curl http://target/.git/config
curl http://target/.env
curl http://target/robots.txt
curl http://target/sitemap.xml

# CMS specific
# WordPress: wpscan --url http://target --enumerate u,vp,vt
# Joomla: joomscan -u http://target
# Drupal: droopescan scan drupal -u http://target
```

## Common Attack Paths
```
DIR BUST → Hidden Admin → Default Creds → Admin Access → RCE
LFI → /etc/passwd → Config Read → DB Creds → More Access
SQLi → DB Dump → Admin Hash → Crack → Admin → RCE
FILE UPLOAD → Web Shell → www-data → Privesc → Root
CMS ENUM → Version Exploit → Known CVE → RCE
.git DISCLOSURE → Source Code → Hardcoded Creds → Shell
API ENDPOINT → Injection → Data Access → More Attack Surface
```

## Escalation Paths
- **Web shell (www-data)** → Check sudo, SUID, cron, capabilities
- **CMS admin** → Upload plugin/theme → RCE via file write
- **DB Admin creds from SQLi** → Reuse on SSH, other services
- **Config file creds** → Password reuse across services
- **SSRF from LFI** → Internal service scanning, cloud metadata

## When to Stop
- Full directory brute complete, no obvious vulns
- All common CMS exploits tried
- Can invest 30-60 mins per web app before diminishing returns
- If stuck, move to other services and return later

## Common Mistakes
- Not running directory brute early (parallelize with other enum)
- Only using common wordlist (need tech-specific lists too)
- Missing LFI because didn't try ../ traversal
- Not checking for .git disclosure (fast and high value)
- Forgetting to check POST parameters for injection
- Not checking robots.txt and sitemap.xml early (free info)
- Only one directory brute wordlist (try small, medium, large)
