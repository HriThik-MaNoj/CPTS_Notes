# CPTS Exam Screenshot Checklist

> Use this checklist during the exam to ensure you capture all required evidence. Every screenshot must show the command AND its output in one frame. Include hostname, IP, and user context where possible.

---

## Initial Reconnaissance

- [ ] Nmap scan results (full TCP scan: `nmap -p- <target>`)
- [ ] Nmap service/version scan results (`nmap -sV -sC <target>`)
- [ ] Host inventory (all discovered hosts with open ports)
- [ ] UDP scan results (if performed: `nmap -sU --top-ports <target>`)
- [ ] SMB signing check (`nmap --script smb2-security-mode -p 445 <target>`)

## Initial Access

- [ ] Web vulnerability discovery (SQLi, LFI, file upload, CMDi)
- [ ] Exploitation command + proof of shell (whoami, hostname, ip addr)
- [ ] SMB null session enumeration (if used)
- [ ] Password spray success (if used)
- [ ] Responder hash capture (if applicable)
- [ ] Default credential login (if applicable)

## Privilege Escalation

- [ ] Before: `whoami` / `id` showing low-priv user
- [ ] Privilege escalation technique (sudo -l, SeImpersonate, SUID, etc.)
- [ ] After: `whoami` / `id` showing root/SYSTEM
- [ ] Proof of elevated access (e.g., reading /etc/shadow or SAM dump)

## Credential Harvesting

- [ ] LSASS dump command + output (Windows)
- [ ] SAM dump command + output
- [ ] /etc/shadow contents (Linux root)
- [ ] SSH keys discovered
- [ ] Configuration file credentials
- [ ] Browser saved passwords
- [ ] Bash/PowerShell history with credentials

## Lateral Movement

- [ ] Credential sweep results (netexec output)
- [ ] Lateral movement command (psexec, evil-winrm, ssh, etc.)
- [ ] Proof of access on new host (whoami, hostname on new host)
- [ ] Pivot deployment (if multi-subnet)
- [ ] New subnet discovery (ip addr, route print showing new subnet)

## Active Directory

- [ ] BloodHound data collection command
- [ ] BloodHound path to DA (screenshot from GUI)
- [ ] AS-REP roasting command + hash output
- [ ] Kerberoasting command + hash output
- [ ] ADCS enumeration (certipy find output)
- [ ] ADCS exploitation (certipy req/auth output)
- [ ] ACL abuse command + output
- [ ] NTLM relay setup + captured output
- [ ] DCSync command + hash output (proof of DA)
- [ ] Domain Admin proof (`net group "Domain Admins" /domain` with your user)

## Domain Compromise

- [ ] DCSync output (KRBTGT hash + all user hashes)
- [ ] Golden Ticket creation (if performed)
- [ ] Full domain hash dump
- [ ] Proof of Domain Admin access on DC
- [ ] All hosts compromised summary

## Flags / Proof of Completion

- [ ] Each flag with context (whoami, hostname, ip addr in same screenshot)
- [ ] All compromised hosts listed with access level
- [ ] Full attack chain summary (start to DA)

## Report Evidence

- [ ] All screenshots organized by finding
- [ ] Screenshots cropped to relevant content
- [ ] Credentials redacted with black bars
- [ ] Each screenshot labeled with finding number
- [ ] Terminal output copied as text (not just screenshots)

---

## Screenshot Best Practices

```
DO:
├── Show command AND output in one frame
├── Include hostname/IP/user context
├── Use solid black bars for redaction (not blur/pixelation)
├── Crop to relevant content only
├── Label each screenshot with finding number
├── Copy terminal output as text for the report (cleaner than screenshots)

DON'T:
├── Screenshot only the output without the command
├── Use blur or pixelation for redaction
├── Leave credentials visible in screenshots
├── Take full-screen screenshots (crop to terminal)
├── Forget to screenshot failed attempts (shows methodology)
└── Rely on memory — screenshot everything as you go
```
