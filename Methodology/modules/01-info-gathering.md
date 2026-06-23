# Module 01: Information Gathering (Passive Recon & OSINT)

## When to Use This Module
Use this module before any active scanning touches the target. Everything here is passive — you gather intel without sending a single packet to the target infrastructure. Run this against scope domains/IPs to build the initial target map before Nmap ever fires a probe.

## Prerequisites
- Scope document from Pre-Engagement (at minimum: domains, root IP ranges)
- Internet connection (no special VPN required)

## Entry Check

```
Scope includes domain names?
├── Yes → Begin passive recon pipeline below
│   ├── Public company info available?
│   │   ├── Yes → Extract technologies, employees, services offered
│   │   └── No → Move directly to infrastructure recon
└── No (IPs only) → Skip domain recon, start with Shodan/IP recon
```

## Techniques

### 1. Company Online Presence Analysis

First, study the main website. Read the company's service offerings to understand their technology stack. Ask: what infrastructure is needed to deliver what they offer?

**What to look for:**
- Technologies mentioned (AWS, Azure, custom apps, IoT)
- Careers/jobs pages (reveal tech stack in job descriptions)
- Partner logos (reveal third-party integrations)
- Office locations (physical security context)

### 2. SSL Certificate Analysis

SSL certificates often include multiple subdomains in their Subject Alternative Names (SANs).

```bash
# Extract certificate info via openssl
openssl s_client -connect <target>:443 2>/dev/null | openssl x509 -noout -text | grep DNS
```

### 3. Certificate Transparency Logs (crt.sh)

Certificate Transparency logs are one of the best sources for discovering subdomains.

```bash
# List all certificates, extract unique subdomains
curl -s "https://crt.sh/?q=<domain>&output=json" | jq -r '.[].name_value' | sort -u

# Parse newlines within entries
curl -s "https://crt.sh/?q=<domain>&output=json" | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

### 4. WHOIS Lookups

Query domain registration records for ownership, registrar, and name servers.

```bash
whois <domain>
```

**Key data points:**
- Registrant organization and contact
- Creation and expiry dates (recent registration = potential phishing)
- Name servers (self-hosted vs third-party)
- Registrar identity

### 5. DNS Enumeration

```
DNS records available?
├── A/AAAA records → Map domain to IP addresses
├── MX records → Identify mail servers
├── NS records → Identify name servers
├── TXT records → Check for SPF, DKIM, DMARC (security posture)
├── CNAME records → Reveal third-party services (AWS, Cloudflare)
└── SOA record → Primary name server, admin contact
```

```bash
# Basic DNS queries
dig A <domain> @<dns-server>
dig AAAA <domain> @<dns-server>
dig MX <domain> @<dns-server>
dig NS <domain> @<dns-server>
dig TXT <domain> @<dns-server>

# Zone transfer attempt (rarely works but always try)
dig axfr <domain> @<dns-server>

# Reverse DNS lookup
dig -x <ip-address>

# Subdomain brute force (uses local wordlist)
for sub in $(cat subdomains.txt); do
  host $sub.<domain> | grep "has address"
done
```

### 6. Identifying Infrastructure

```
Subdomain resolves to IP?
├── Company-owned IP range → Added to target list
└── Third-party (AWS, Cloudflare, etc.) →
    ├── Must verify scope allows testing
    └── May be out of scope
```

Resolve all discovered subdomains to IPs:

```bash
for i in $(cat subdomains.txt); do
  host $i | grep "has address" | cut -d" " -f1,4 >> resolved.txt
done
```

### 7. Shodan Recon

Query Shodan for open ports, services, and organization info on discovered IPs.

```bash
# Requires Shodan API key
shodan host <ip>
```

**Shodan reveals:**
- Open ports and service banners
- Organization name (verify against scope)
- Geographic location
- SSL/TLS configuration details

### 8. Wayback Machine

Historical snapshots may reveal old versions of the site with exposed endpoints, backup files, or commented-out credentials.

```
https://web.archive.org/web/*/<domain>
```

### 9. Search Engine Discovery

Use Google dorking to find exposed files and directories:

```
site:<domain> filetype:pdf
site:<domain> intitle:"index of"
site:<domain> inurl:admin
site:<domain> ext:sql ext:bak ext:swp
```

## Decision Flow

```
Subdomains discovered?
├── Yes → What services do they host?
│   ├── Web applications → Note URLs for web testing (→ Module 04)
│   ├── API endpoints → Note for API testing
│   └── Dev/staging → Often less hardened, high-value targets
│
├── IPs identified?
│   ├── Company-owned → Add to nmap target list (→ Module 02)
│   └── CDN/Third-party → Verify scope, may need alternate approach
│
└── Nothing useful found?
    ├── Try additional wordlists (bigger = more noise)
    ├── Check passive DNS databases (SecurityTrails, VirusTotal)
    └── Move to active scanning (→ Module 02)
```

## Cross-References
- When you have target IPs → [Module 02: Enumeration](02-enumeration.md)
- When you find web endpoints → [Module 04: Web Application](04-web-application.md)
- When you need deeper OSINT → [assets/cheatsheets/osint.md](../assets/cheatsheets/osint.md)
- Pre-engagement setup → [Module 00: Pre-Engagement](00-pre-engagement.md)

## Output Summary
- [ ] All in-scope domains enumerated for subdomains
- [ ] DNS records collected for each domain
- [ ] IP addresses mapped to subdomains
- [ ] Third-party infrastructure identified
- [ ] SSL certificates examined for hidden subdomains
- [ ] All findings saved to workspace evidence folder
- [ ] Target list ready for active scanning
