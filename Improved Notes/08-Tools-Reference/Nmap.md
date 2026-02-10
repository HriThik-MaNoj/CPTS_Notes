# Nmap - Network Mapper

## 📋 Overview

Nmap is the industry-standard network scanning tool for port discovery, service enumeration, and vulnerability detection.

**Default Behavior**: TCP SYN scan on top 1000 ports (requires root)

---

## 🎯 When to Use

- **Initial reconnaissance** - Discover open ports and services
- **Service fingerprinting** - Identify versions and configurations
- **Vulnerability scanning** - Check for known vulnerabilities
- **Network mapping** - Understand network topology
- **Firewall testing** - Identify filtering rules

---

## 🔄 Nmap Methodology Workflow

```
┌─────────────────────────────────────────┐
│ 1. Host Discovery                       │
│    └─ Is the host alive?                │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 2. Port Scanning                        │
│    └─ What ports are open?              │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 3. Service Detection                    │
│    └─ What services are running?        │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 4. OS Detection                         │
│    └─ What operating system?            │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 5. Vulnerability Scanning               │
│    └─ Any known vulnerabilities?        │
└─────────────────────────────────────────┘
```

---

## 🚀 Quick Start Commands

### Basic Scan
```bash
# Simple scan (top 1000 ports)
nmap $IP

# Scan specific ports
nmap -p 80,443,8080 $IP

# Scan all ports
nmap -p- $IP

# Scan port range
nmap -p 1-1000 $IP
```

### Common Scan Combinations
```bash
# Standard enumeration scan
nmap -sC -sV -oA nmap/initial $IP

# Fast full port scan
sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $IP -oA nmap/allports

# Detailed scan on specific ports
sudo nmap -sC -sV -p 22,80,443,445 $IP -oA nmap/detailed

# UDP scan (top 100 ports)
sudo nmap -sU -F --top-ports 100 $IP -oA nmap/udp
```

---

## 📚 Essential Flags Reference

### Scan Types

| Flag | Description | Use Case | Requires Root |
|------|-------------|----------|---------------|
| `-sS` | TCP SYN scan (stealth) | Default, fast, stealthy | Yes |
| `-sT` | TCP Connect scan | When no root access | No |
| `-sU` | UDP scan | Find UDP services (DNS, SNMP) | Yes |
| `-sV` | Version detection | Identify service versions | No |
| `-sC` | Default NSE scripts | Safe enumeration scripts | No |
| `-sA` | ACK scan | Firewall rule detection | Yes |
| `-sN` | NULL scan | Firewall evasion | Yes |
| `-sF` | FIN scan | Firewall evasion | Yes |
| `-sX` | Xmas scan | Firewall evasion | Yes |

### Port Specification

| Flag | Description | Example |
|------|-------------|---------|
| `-p 22` | Single port | `nmap -p 22 $IP` |
| `-p 22,80,443` | Multiple ports | `nmap -p 22,80,443 $IP` |
| `-p 1-1000` | Port range | `nmap -p 1-1000 $IP` |
| `-p-` | All ports (1-65535) | `nmap -p- $IP` |
| `-F` | Fast scan (top 100) | `nmap -F $IP` |
| `--top-ports 1000` | Top N ports | `nmap --top-ports 1000 $IP` |

### Host Discovery

| Flag | Description | Use Case |
|------|-------------|----------|
| `-sn` | Ping scan only (no port scan) | Host discovery |
| `-Pn` | Skip ping (assume host is up) | Bypass ICMP filtering |
| `-PS22,80,443` | TCP SYN ping on specific ports | Alternative host discovery |
| `-PA22,80,443` | TCP ACK ping | Bypass stateful firewalls |
| `-PU53,161` | UDP ping | Detect UDP-only hosts |

### Output Options

| Flag | Description | File Extension |
|------|-------------|----------------|
| `-oN` | Normal output | `.nmap` |
| `-oX` | XML output | `.xml` |
| `-oG` | Grepable output | `.gnmap` |
| `-oA` | All formats | `.nmap`, `.xml`, `.gnmap` |
| `-v` | Verbose | N/A |
| `-vv` | Very verbose | N/A |

### Timing and Performance

| Flag | Description | Speed | Stealth |
|------|-------------|-------|---------|
| `-T0` | Paranoid | Extremely slow | Maximum |
| `-T1` | Sneaky | Very slow | High |
| `-T2` | Polite | Slow | Medium |
| `-T3` | Normal (default) | Normal | Low |
| `-T4` | Aggressive | Fast | Very Low |
| `-T5` | Insane | Very fast | None |

**Custom Timing**:
```bash
--min-rate 5000        # Minimum packets per second
--max-rate 10000       # Maximum packets per second
--min-parallelism 100  # Minimum parallel probes
--max-retries 1        # Reduce retries for speed
```

### Advanced Options

| Flag | Description |
|------|-------------|
| `-O` | OS detection |
| `-A` | Aggressive scan (OS, version, scripts, traceroute) |
| `-n` | No DNS resolution (faster) |
| `-R` | Always resolve DNS |
| `--reason` | Show reason for port state |
| `--packet-trace` | Show all packets sent/received |
| `--open` | Show only open ports |

---

## 🎯 Practical Scanning Strategies

### Strategy 1: Fast Initial Scan (Recommended for CPTS)

**Goal**: Quickly identify all open ports

```bash
# Step 1: Fast full TCP scan (5-10 minutes)
sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $IP -oA nmap/allports

# Step 2: Extract open ports
ports=$(grep open nmap/allports.nmap | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')
echo $ports

# Step 3: Detailed scan on open ports only
sudo nmap -sC -sV -p $ports $IP -oA nmap/detailed

# Step 4: UDP scan (top 100 ports)
sudo nmap -sU -F --top-ports 100 $IP -oA nmap/udp
```

**Time**: ~15-20 minutes for full enumeration

### Strategy 2: Thorough Scan (When time permits)

```bash
# Full TCP + UDP + Scripts
sudo nmap -p- -sS -sU -sC -sV -O -A --min-rate 1000 $IP -oA nmap/full
```

**Time**: 30-60 minutes

### Strategy 3: Stealth Scan (IDS/IPS evasion)

```bash
# Slow, fragmented scan
sudo nmap -p- -sS -T2 -f --data-length 200 -D RND:10 $IP -oA nmap/stealth
```

**Time**: Several hours

---

## 🔍 Nmap Scripting Engine (NSE)

### Script Categories

| Category | Description | Example |
|----------|-------------|---------|
| `auth` | Authentication bypass | `http-auth` |
| `broadcast` | Network discovery | `broadcast-dhcp-discover` |
| `brute` | Brute force attacks | `ssh-brute` |
| `default` | Safe, common scripts | Enabled with `-sC` |
| `discovery` | Service discovery | `dns-brute` |
| `dos` | Denial of service | `http-slowloris` |
| `exploit` | Exploit vulnerabilities | `smb-vuln-ms17-010` |
| `fuzzer` | Fuzzing | `http-form-fuzzer` |
| `intrusive` | Aggressive scripts | May crash services |
| `malware` | Malware detection | `http-malware-host` |
| `safe` | Won't crash services | Most discovery scripts |
| `version` | Version detection | Enabled with `-sV` |
| `vuln` | Vulnerability detection | `vuln` category |

### Common NSE Scripts

#### Default Scripts (`-sC`)
```bash
# Equivalent to --script=default
nmap -sC $IP
```

#### Vulnerability Scanning
```bash
# All vulnerability scripts
nmap -p $ports --script vuln $IP

# Specific vulnerability
nmap -p 445 --script smb-vuln-ms17-010 $IP
nmap -p 80 --script http-vuln-cve2021-41773 $IP
```

#### Service Enumeration
```bash
# SMB enumeration
nmap -p 445 --script smb-enum-shares,smb-enum-users $IP

# HTTP enumeration
nmap -p 80 --script http-enum,http-headers,http-methods $IP

# DNS enumeration
nmap -p 53 --script dns-zone-transfer,dns-brute $IP

# SMTP enumeration
nmap -p 25 --script smtp-enum-users,smtp-commands $IP
```

#### Brute Force
```bash
# SSH brute force
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt $IP

# FTP brute force
nmap -p 21 --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt $IP
```

### Script Arguments

```bash
# Pass arguments to scripts
nmap --script <script> --script-args <arg1>=<value1>,<arg2>=<value2> $IP

# Example: HTTP form brute force
nmap -p 80 --script http-form-brute --script-args 'http-form-brute.path=/login,uservar=username,passvar=password' $IP
```

### Finding Scripts

```bash
# List all scripts
ls /usr/share/nmap/scripts/

# Search for scripts
ls /usr/share/nmap/scripts/ | grep smb

# Get script help
nmap --script-help <script-name>
nmap --script-help smb-enum-shares
```

---

## 🛡️ Firewall and IDS Evasion

### Fragmentation
```bash
# Fragment packets
nmap -f $IP

# Set custom MTU
nmap --mtu 24 $IP
```

### Decoys
```bash
# Use decoy IPs
nmap -D RND:10 $IP

# Specific decoys
nmap -D 192.168.1.1,192.168.1.2,ME $IP
```

### Source Port Manipulation
```bash
# Use specific source port (often allowed through firewalls)
nmap --source-port 53 $IP
nmap -g 53 $IP
```

### Timing Adjustments
```bash
# Slow scan to avoid detection
nmap -T1 $IP

# Add random delays
nmap --scan-delay 1s $IP
nmap --max-scan-delay 10s $IP
```

### Data Length
```bash
# Append random data to packets
nmap --data-length 200 $IP
```

### Spoofing
```bash
# Spoof MAC address
nmap --spoof-mac 0 $IP  # Random MAC
nmap --spoof-mac Apple $IP  # Vendor-specific
nmap --spoof-mac 00:11:22:33:44:55 $IP  # Specific MAC
```

---

## 📊 Output Parsing

### Extract Open Ports
```bash
# From normal output
grep open nmap/scan.nmap | awk -F/ '{print $1}'

# Create comma-separated list
grep open nmap/scan.nmap | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//'

# Save to variable
ports=$(grep open nmap/scan.nmap | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')
```

### Extract Service Versions
```bash
# Get services and versions
grep open nmap/scan.nmap | awk '{print $3, $4, $5, $6}'
```

### Parse XML Output
```bash
# Convert XML to HTML
xsltproc nmap/scan.xml -o nmap/scan.html

# Extract hosts with open ports
grep -oP '(?<=<address addr=")[^"]*' nmap/scan.xml
```

### Parse Grepable Output
```bash
# Find hosts with specific port open
grep "80/open" nmap/scan.gnmap | awk '{print $2}'

# Find all open ports across all hosts
grep "open" nmap/scan.gnmap | awk '{print $2, $3}'
```

---

## 🎯 Service-Specific Scanning

### Web Services (80, 443, 8080, 8443)
```bash
nmap -p 80,443,8080,8443 --script http-enum,http-headers,http-methods,http-title $IP
```

### SMB (139, 445)
```bash
nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln* $IP
```

### DNS (53)
```bash
nmap -p 53 --script dns-zone-transfer,dns-brute --script-args dns-brute.domain=$DOMAIN $IP
```

### SMTP (25, 465, 587)
```bash
nmap -p 25,465,587 --script smtp-enum-users,smtp-commands,smtp-open-relay $IP
```

### FTP (21)
```bash
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst $IP
```

### SSH (22)
```bash
nmap -p 22 --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos $IP
```

### SNMP (161 UDP)
```bash
sudo nmap -sU -p 161 --script snmp-brute,snmp-info,snmp-interfaces $IP
```

### Database Services
```bash
# MySQL (3306)
nmap -p 3306 --script mysql-enum,mysql-info,mysql-databases $IP

# MSSQL (1433)
nmap -p 1433 --script ms-sql-info,ms-sql-config,ms-sql-dump-hashes $IP

# PostgreSQL (5432)
nmap -p 5432 --script pgsql-brute $IP
```

---

## ⚠️ Common Errors and Solutions

### Error: "You requested a scan type which requires root privileges"
**Solution**: Use `sudo` or switch to TCP connect scan
```bash
sudo nmap -sS $IP
# OR
nmap -sT $IP  # No root required
```

### Error: "Failed to resolve hostname"
**Solution**: Use `-n` to skip DNS resolution or check DNS settings
```bash
nmap -n $IP
```

### Error: "No route to host"
**Solution**: Check VPN connection and routing
```bash
ip route
ping $IP
```

### Slow Scans
**Solution**: Increase speed with timing options
```bash
nmap -T4 --min-rate 1000 $IP
```

### Incomplete Results
**Solution**: Use `-Pn` to skip host discovery
```bash
nmap -Pn $IP
```

---

## 💡 Pro Tips

1. **Always save output**: Use `-oA` to save all formats
   ```bash
   nmap -oA nmap/scan $IP
   ```

2. **Use variables**: Set IP as environment variable
   ```bash
   export IP=10.10.10.10
   nmap $IP
   ```

3. **Scan in stages**: Fast scan first, then detailed
   ```bash
   # Fast
   nmap -p- --min-rate 5000 $IP
   # Detailed
   nmap -sC -sV -p <ports> $IP
   ```

4. **Don't skip UDP**: Many services run on UDP
   ```bash
   sudo nmap -sU -F $IP
   ```

5. **Check for virtual hosts**: Scan with Host header
   ```bash
   nmap -p 80 --script http-vhosts $IP
   ```

6. **Use verbose mode**: See results in real-time
   ```bash
   nmap -vv $IP
   ```

7. **Combine with other tools**: Use nmap for initial scan, then specialized tools
   ```bash
   nmap -p- $IP  # Find ports
   nikto -h $IP  # Web vulnerability scan
   ```

---

## 📚 Related Resources

- [Network Enumeration Workflow](../02-Enumeration/Network-Enumeration.md)
- [Service-Specific Enumeration](../02-Enumeration/Service-Specific/)
- [Firewall Evasion Techniques](../02-Enumeration/Firewall-Evasion.md)
- [Quick Reference Cheat Sheet](../09-Quick-Reference/Nmap-Cheatsheet.md)

---

## 🔗 External Resources

- [Official Nmap Documentation](https://nmap.org/book/man.html)
- [NSE Script Documentation](https://nmap.org/nsedoc/)
- [Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/)

---

**Remember**: Nmap is just the beginning. Always follow up with service-specific enumeration tools!
