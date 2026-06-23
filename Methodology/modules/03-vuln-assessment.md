# Module 03: Vulnerability Assessment

## When to Use This Module
Use this module after you have a list of targets with identified services and versions (from Module 02). This phase covers automated vulnerability scanning with Nessus/OpenVAS, manual CVE research via searchsploit, and triaging results to prioritize exploitation. It also provides the risk-scoring framework (CVSS) used to classify findings in the final report.

## Prerequisites
- Live hosts with identified open ports and service versions (from Module 02)
- Network connectivity to targets (may need VPN/pivot)
- Nessus/OpenVAS installed if running authenticated scans

## Entry Check

```
Service versions identified?
├── Yes → Search for known vulnerabilities
│   ├── Automated scanning allowed by scope?
│   │   ├── Yes → Start Nessus/OpenVAS scan in parallel
│   │   │   ├── Non-evasive test → Full scan with all plugins
│   │   │   └── Evasive test → Skip automated scanning, manual only
│   │   └── No → Manual CVE research only
│   └── → searchsploit for each service version
│
├── Credentials available for target?
│   ├── Yes → Configure authenticated scan (deeper results)
│   │   └── SSH keys (Linux), NTLM/plaintext (Windows)
│   └── No → Unauthenticated scan only
│
└── No version info? → Return to Module 02 for deeper enumeration
```

## Automated Vulnerability Scanning

### Nessus

```bash
# Start Nessus
sudo systemctl start nessusd
sudo systemctl enable nessusd

# Access web UI at https://localhost:8834

# Scan types by scenario:
# Basic Network Scan → Quick unauthenticated scan
# Advanced Scan → Custom plugin selection, credentialed
# Credentialed Scan → Deepest results (requires creds)

# SSH credential config: Credentials → SSH → Password or Private Key
# Windows credential config: Credentials → Windows → LM/NTLM or Password
```

### OpenVAS / GVM

```bash
# Initial setup
sudo gvm-setup
sudo gvm-start

# Access web UI at https://localhost:9392
# Tasks → New Task → Full and Fast Scan
```

### Scan Triage Decision Flow

```
Scanner results received?
├── Prioritize by severity:
│   ├── Critical (9.0-10.0) → Validate immediately
│   │   ├── RCE? → Manual PoC validation
│   │   └── Data exposure? → Verify with manual request
│   ├── High (7.0-8.9) → Validate next 24 hours
│   │   ├── Check exploit-db for public PoC
│   │   └── Test in non-production if possible
│   ├── Medium (4.0-6.9) → Validate during assessment if time permits
│   └── Low (0.1-3.9) → Note and consolidate
│
├── Verify false positives:
│   ├── For EACH finding: attempt manual reproduction
│   ├── If scanner says "Apache 2.4.49" → verify with banner grab
│   └── If scanner says "SQLi" → confirm with manual payload
│
└── Validated findings → Add to exploit priority list
```

## Manual CVE Research

For every service version discovered, run the following in parallel:

### searchsploit

```bash
# Update database first
searchsploit -u

# Search by product + version (drop minor version where possible)
searchsploit apache 2.4.49
searchsploit "wordpress 5.7"
searchsploit tomcat 9
searchsploit openssh 8.2

# Exclude DOS/denial-of-service modules
searchsploit apache 2.4 --exclude="(DoS|/dos/)"

# View exploit details
searchsploit -x <EDB-ID>

# Mirror exploit to local directory
searchsploit -m exploits/linux/remote/47297.py

# JSON output for reporting
searchsploit --json tomcat 9 | jq
```

### CVE Lookup Chain

```
Finding has a CVE?
├── Check NVD: https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNN
├── Check exploit-db: https://www.exploit-db.com/search?cve=YYYY-NNNN
├── Check GitHub for PoC: https://github.com/search?q=CVE-YYYY-NNNN
├── Check Metasploit: msfconsole -q -x "search cve:YYYY-NNNN; exit"
└── Check PoCsInGitHub: https://github.com/nomi-sec/PoC-in-GitHub
```

### Quick Service-Version Research

```bash
# Get exact version from nmap output
nmap -sV -p<port> <target>

# Or banner grab manually
banner=$(nc -nv <target> <port> 2>&1 | head -1)
searchsploit "$(echo $banner | awk '{print $1, $2}')"
```

### Vetting a PoC Before Running

```
Found a PoC exploit?
├── Read the full source code
│   ├── Check for backdoors in the exploit itself
│   ├── Verify it matches your target version
│   └── Check author reputation
├── Test in lab environment first (if available)
├── Verify it won't cause DoS / crash the service
│   └── Avoid "BSOD" level exploits unless RoE allows
└── Only proceed if:
    ├── Exploit is reliable
    ├── Target is non-production
    └── Emergency contact notified for critical systems
```

## CVSS Scoring Reference

### Severity Levels
| Score | Severity | Response |
|---|---|---|
| 9.0-10.0 | Critical | Drop everything, validate now |
| 7.0-8.9 | High | Validate within 24 hours |
| 4.0-6.9 | Medium | Validate during assessment |
| 0.1-3.9 | Low | Note, consolidate, report |

### Risk Assessment Framework

```
Risk = Likelihood × Impact

Likelihood:
├── High: Public exploit exists, unauthenticated, low complexity
├── Medium: Exploit exists but requires auth or high complexity
└── Low: No public exploit, requires physical access

Impact:
├── High: RCE, privilege escalation, data exfiltration
├── Medium: Information disclosure, limited access
└── Low: DoS, minor information leak
```

## Decision Flow: What to Exploit First

```
Validated findings list ready?
├── Prioritize exploitation:
│   1. RCE (unauthenticated) → Immediate exploitation → Module 05
│   2. SQL injection → Data extraction → possible RCE
│   3. LFI/RFI → File read → possible RCE via log poisoning
│   4. Command injection → Immediate RCE
│   5. Weak credentials → Authentication → Module 06
│   6. Privilege escalation (local) → Module 09/10
│   7. Information disclosure → Use to enable higher-priority attacks
│
├── Credentialed scan results available?
│   ├── Compare unauthenticated vs authenticated results
│   ├── Authenticated = deeper patch-level findings
│   └── Use for prioritization with client
│
└── Prioritization completed → Begin exploitation chain
```

## Cross-References
- For exploitation of validated vulns → [Module 05: Initial Access](05-initial-access.md)
- For service-specific attacks → [Module 07: Common Services](07-common-services.md)
- For web application vulnerabilities → [Module 04: Web Application](04-web-application.md)
- For password cracking found hashes → [Module 06: Password Attacks](06-password-attacks.md)
- For reporting findings → [Module 14: Reporting](14-reporting.md)

## Output Summary
- [ ] Nessus/OpenVAS scan completed or waived
- [ ] searchsploit run against every unique service version
- [ ] CVE lookups completed for all interesting findings
- [ ] False positives identified and documented
- [ ] Exploitation priority list created (RCE first)
- [ ] All findings documented with CVSS scores
- [ ] PoC exploits vetted and ready
