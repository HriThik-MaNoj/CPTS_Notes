# SNMP Battle Card

## What to Check First
```
1. PORTS 161 (UDP), 162 (TCP)? → nmap -sU -p 161 target
2. COMMUNITY STRING → snmpwalk -v2c -c public target
3. BRUTE STRING → onesixtyone target -c /usr/share/seclists/Discovery/SNMP/snmp.txt
4. MIB WALK → snmpwalk -v2c -c public target 1.3.6.1.2.1.1
```

## High-Value Findings
- **Default community string (public)** → Full SNMP read access
- **Running processes** → Identify software versions, AV
- **Network interfaces** → IP/subnet mapping, additional networks
- **User accounts** → Enumeration for password attacks
- **Services/Software** → Installed versions for exploit search
- **Windows services** → Installed patches, hotfixes (patch level)
- **Routing tables** → Network topology, pivot paths
- **Domain info (AD)** → Domain name, DC info

## Immediate Commands
```
# Check community string
snmpwalk -v2c -c public target -On

# System info
snmpwalk -v2c -c public target 1.3.6.1.2.1.1

# Running processes (Windows)
snmpwalk -v2c -c public target 1.3.6.1.2.1.25.4.2.1.2

# Installed software
snmpwalk -v2c -c public target 1.3.6.1.2.1.25.6.3.1.2

# Network interfaces
snmpwalk -v2c -c public target 1.3.6.1.2.1.2.2.1.2

# IP routing table
snmpwalk -v2c -c public target 1.3.6.1.2.1.4.24

# Windows users
snmpwalk -v2c -c public target 1.3.6.1.4.1.77.1.2.25

# Windows services
snmpwalk -v2c -c public target 1.3.6.1.4.1.77.1.2.3.1.1

# TCP listening ports
snmpwalk -v2c -c public target 1.3.6.1.2.1.6.13.1.3

# Brute force community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt target -o snmp-found.txt

# Automate dump (braa)
braa public@target:.1.3.6.1.2.1.1.*

# Nmap NSE
nmap -sU -p 161 --script snmp-* target
```

## Common Attack Paths
```
SNMP PUBLIC → Processes → Identify Vulnerable Software → Exploit
SNMP PUBLIC → Windows Users → Password Spray Targets
SNMP PUBLIC → Network Topology → Pivot Paths → Lateral Movement
SNMP PUBLIC → Windows → Installed Patches → Missing KBs → Privesc
SNMP PUBLIC → Services → Find Accessible Services → Direct Access
```

## Escalation Paths
- **User list from SNMP** → Password spray → Initial access
- **Software versions** → Known exploit → RCE
- **Missing patches** → Windows exploit → SYSTEM
- **Network info** → Pivot to P1 target
- **Domain controller info** → Identify primary attack surface

## When to Stop
- public fails, onesixtyone finds no community strings → Move on
- SNMP rarely primary attack vector (secondary intelligence)

## Common Mistakes
- Only trying "public" community string (try "private", "manager", "default")
- Forgetting UDP scan (default nmap TCP scan misses it)
- Not extracting running processes (high-value info)
- Missing Windows-specific MIBs for users/services
- Not running ongoing SNMP brute force in background
- Ignoring SNMP on Linux (also valuable)
