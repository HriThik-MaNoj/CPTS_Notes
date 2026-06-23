# Nmap Cheat Sheet

```bash
# Host discovery
nmap -sn <target>                                         # Ping sweep
nmap -sn -PS22,80,443,445 <target>                        # TCP discovery (ICMP blocked)

# Port scanning
nmap -p- <target>                                         # All 65535 TCP ports
nmap --top-ports=1000 <target>                            # Top 1000 TCP ports
nmap -p 22,80,443 <target>                                # Specific ports
nmap -sU --top-ports=100 <target>                         # UDP scan (slow)

# Service/version detection
nmap -sV <target>                                         # Version detection
nmap -sV --version-intensity 9 <target>                   # Aggressive version

# OS detection
nmap -O <target>                                          # OS detection
nmap -A <target>                                          # Aggressive (OS + version + scripts + traceroute)

# NSE scripts
nmap -sC <target>                                         # Default scripts
nmap --script vuln <target>                               # Vulnerability scripts
nmap --script safe <target>                               # Safe scripts
nmap --script smb-vuln-ms17-010 -p 445 <target>           # Specific script

# Output formats
nmap -oN scan.nmap <target>                               # Normal output
nmap -oX scan.xml <target>                                # XML output
nmap -oG scan.gnmap <target>                              # Grepable output
nmap -oA scan <target>                                    # All formats

# Evasion
nmap -f <target>                                          # Fragment packets
nmap -D RND:5 <target>                                    # Decoy scan
nmap --source-port 53 <target>                            # Source port spoof
nmap -sA <target>                                         # ACK scan (firewall rules)
nmap -T1 <target>                                         # Slow scan (IDS evasion)
nmap -T5 <target>                                         # Insane speed (noisy)
nmap -Pn <target>                                         # Skip host discovery
```
