# Recon & OSINT Flow

## Entry Conditions
- In-scope domains or IP ranges provided from scope document
- No active scanning yet (passive phase before Nmap)

## Decision Tree

```
Scope received: domains, IP ranges, or organization name
│
├── [DOMAINS PROVIDED] → Passive domain recon
│   │
│   ├── STEP 1: Certificate Transparency (crt.sh)
│   │   ├── curl -s "https://crt.sh/?q=<domain>&output=json" | jq -r '.[].name_value' | sort -u
│   │   └── [SUCCESS] Subdomain list → Resolve to IPs → Target list
│   │
│   ├── STEP 2: SSL Certificate analysis
│   │   ├── openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -text | grep DNS
│   │   └── [SUCCESS] SAN entries → More subdomains
│   │
│   ├── STEP 3: DNS record enumeration
│   │   ├── dig A <domain> → IPv4 addresses
│   │   ├── dig AAAA <domain> → IPv6 addresses
│   │   ├── dig MX <domain> → Mail servers
│   │   ├── dig NS <domain> → Name servers (zone transfer attempt)
│   │   ├── dig TXT <domain> → SPF/DKIM/DMARC records
│   │   ├── dig CNAME <domain> → Third-party service mapping
│   │   └── dig axfr @ns <domain> → Zone transfer (rare success)
│   │
│   ├── STEP 4: Subdomain brute force
│   │   ├── DNS-based: for sub in $(cat dns-wordlist.txt); do host $sub.<domain>; done
│   │   ├── API-based: dnsrecon -d <domain> -D wordlist.txt -t brt
│   │   └── Start small wordlist, escalate to larger
│   │
│   ├── STEP 5: WHOIS lookup
│   │   ├── whois <domain> → Registrant, org, name servers
│   │   └── whois <org IP> → Netblocks, ASN
│   │
│   └── [OUTPUT] Subdomain list + resolved IPs + target list
│       └── [→ Module 02 - Active Enumeration]
│
├── [IP RANGES PROVIDED] → IP-based passive recon
│   │
│   ├── STEP 1: Shodan lookups
│   │   ├── shodan host <ip> → Open ports, banners, org
│   │   ├── shodan search "org:<Organization>" → All exposed hosts
│   │   └── [SUCCESS] Open ports hint → Prioritize scanning
│   │
│   ├── STEP 2: Reverse DNS
│   │   ├── dig -x <ip> → Hostname
│   │   └── [SUCCESS] Domain names → Web testing targets
│   │
│   ├── STEP 3: ASN organization
│   │   ├── whois <ip> → Organization, netblock
│   │   └── BGP lookup → Additional netblocks
│   │
│   └── [OUTPUT] Hostname list + service hints + target IPs
│       └── [→ Module 02 - Active Enumeration]
│
├── [ORGANIZATION NAME ONLY] → Company recon
│   │
│   ├── STEP 1: Website analysis
│   │   ├── Browse main website → Technology stack recognition
│   │   ├── Check careers page → Tech stack from job postings
│   │   ├── Check partner logos → Third-party integrations
│   │   └── Search engine dorking: site:<company>.com
│   │
│   ├── STEP 2: Google dorking
│   │   ├── site:<domain> filetype:pdf
│   │   ├── site:<domain> intitle:"index of"
│   │   ├── site:<domain> inurl:admin
│   │   └── site:<domain> ext:sql ext:bak ext:swp ext:log
│   │
│   ├── STEP 3: Wayback Machine
│   │   └── web.archive.org/web/*/<domain> → Historical endpoints
│   │
│   ╰── [OUTPUT] Initial domain list → Feed into domain recon above
│
└── [OUTPUT SUMMARY]
    ├── Target IP list → [Module 02: Enumeration]
    ├── Subdomain list → [Module 04: Web Application]
    ├── Mail server IPs → [Module 07: Common Services]
    ├── DNS server IPs → [Module 07: Common Services]
    └── Company tech stack intel → All relevant modules

## What Passive Recon Reveals

| Source | Data Gained | Attack Relevance |
|--------|-------------|------------------|
| crt.sh | Subdomains | More web targets = more attack surface |
| SSL certs | SAN subdomains | Hidden dev/staging sites |
| WHOIS | Org, netblocks, tech contacts | Social engineering, scope expansion |
| DNS records | Infrastructure mapping | Mail, DNS, web server targets |
| Shodan | Open ports, banners | Prioritize scanning targets |
| Google dorking | Exposed files, admin panels | Direct access vectors |
| Wayback Machine | Historical endpoints | Hidden endpoints, old vulns |

## Failure Paths

| Situation | Alternative |
|-----------|-------------|
| No subdomains from crt.sh | Try subdomain brute force with bigger wordlist |
| No DNS records found | Domain may not resolve publicly; check VPN |
| Zone transfer denied | Expected 99% of the time; move to brute force |
| Shodan no results | No API key or host not indexed; skip to active scan |
| No useful OSINT | Move to active scanning immediately |
| Too much data | Prioritize: web servers first, then mail, then services |

## Cross-References
- Active scanning with results → [Module 02](../modules/02-enumeration.md)
- Web targets discovered → [Module 04](../modules/04-web-application.md)
- Service targets → [Module 07](../modules/07-common-services.md)
- Nmap cheatsheet → [assets/cheatsheets/nmap-cheatsheet.md](../assets/cheatsheets/nmap-cheatsheet.md)
- Attack Graph navigation → [Module 99](../modules/99-attack-graph.md)
