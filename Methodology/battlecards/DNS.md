# DNS Battle Card

## What to Check First
```
1. PORT 53? → nmap -sU -sT -p 53 target
2. ZONE TRANSFER → dig axfr @target domain.local
3. DNS ENUM → nslookup, host, dig
4. SUBDOMAIN → gobuster dns -d domain.local -r target -w wordlist.txt
```

## High-Value Findings
- **Zone transfer allowed** → All DNS records (subdomains, hosts, SRV)
- **Subdomain enumeration** → Hidden services, admin panels, dev sites
- **SRV records** → Domain controllers, LDAP, Kerberos servers
- **DNS poisoning opportunity** → Responder auto-detection
- **DynDNS registration** → Host enumeration
- **CNAME records** → Cloud service mapping

## Immediate Commands
```
# Zone transfer (primary check)
dig axfr @target domain.local
host -l domain.local target
nslookup -type=any domain.local target

# Basic DNS queries
dig @target domain.local ANY
dig @target domain.local A
dig @target domain.local AAAA
dig @target domain.local MX
dig @target domain.local NS
dig @target domain.local CNAME

# Reverse DNS lookup
dig @target -x <ip_address>

# SRV record enumeration (AD environment)
dig @target _ldap._tcp.domain.local SRV
dig @target _kerberos._tcp.domain.local SRV
dig @target _gc._tcp.domain.local SRV

# Subdomain brute force
gobuster dns -d domain.local -r target -w /usr/share/wordlists/subdomains.txt -o dns-subs.txt

# DNSRecon
dnsrecon -d domain.local -n target -t axfr
dnsrecon -d domain.local -n target -t brt -D /wordlist.txt

# Nmap NSE
nmap --script dns-zone-transfer -p 53 target
nmap --script dns-brute -p 53 target --dns-brute.domain domain.local
nmap --script dns-srv-enum -p 53 target
```

## Common Attack Paths
```
ZONE TRANSFER → All Hosts → Mapping → Targeted Enumeration
SUBDOMAIN → Hidden Web App → Web Attack → Foothold
SRV RECORDS → DC Discovery → AD Attack Path ID'd
DNS ENUM → Host + IP Map → Network Layout → Pivot Planning
DNS → Responder → Hash Capture → Crack → Access
```

## Escalation Paths
- **Zone transfer** → Full network map → Identify DCs, SQL servers, etc.
- **Hidden subdomain** → Web admin panel → Potential RCE
- **SRV records** → Find GC, LDAP, Kerberos for targeted attacks
- **DNS info** → Host naming convention → OS/role identification

## When to Stop
- Zone transfer rejected (expected, but always check)
- After comprehensive subdomain brute force with common lists
- DNS is recon, not exploitation. Don't over-invest

## Common Mistakes
- Forgetting to check zone transfer (takes 2 seconds)
- Not enumerating SRV records in AD environments
- Using only TCP when UDP may be required
- Not doing reverse DNS lookups (identifies hostnames)
- Under-investing in subdomain brute force
- Not running gobuster DNS brute in parallel with other recon
