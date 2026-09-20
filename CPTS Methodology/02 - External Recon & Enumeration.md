# 02 - External Recon & Enumeration

## At a glance — nmap result → next action

| Port | Service | Next action |
|---|---|---|
| 20/21 | FTP | anon login, pull/put → §FTP |
| 22 | SSH | ssh-audit, then cred/key login → §Linux RM |
| 25 | SMTP | VRFY user enum → §SMTP |
| 53 | DNS | records + AXFR + subdomain brute → §DNS |
| 80/443/8080/8000/8180/8888 | HTTP(S) | dir brute + fingerprint → §Web recon |
| 111/2049 | rpcbind/NFS | showmount + mount → §NFS |
| 135 | WMI/RPC | wmiexec with creds → §Windows RM |
| 139/445 | SMB | null session, RID cycle, shares → §SMB |
| 143/993 · 110/995 | IMAP/POP3 | openssl s_client + LIST/FETCH → §IMAP/POP3 |
| 512-514 / 873 | r-services / rsync | rlogin/rusers, list share → §Linux RM |
| 1433 | MSSQL | ms-sql NSE + impacket → §MSSQL |
| 1521 | Oracle TNS | SID brute + ODAT → §Oracle |
| 3306 | MySQL | mysql login + dump → §MySQL |
| 3389 / 5985-5986 | RDP / WinRM | xfreerdp / evil-winrm → §Windows RM |
| 623/udp | IPMI | ipmi-version + dumphashes → §IPMI |
| 161/162/udp | SNMP | onesixtyone + snmpwalk → §SNMP |
| 8500/8000/8080 | ColdFusion/Jenkins/Tomcat | → `03 - Web Exploitation & Foothold` |

**IF** the initial nmap sweep returned open ports →
- [ ] **DO** read the port's "Next action" and jump straight to that §node
WHY: every open port maps to one starting node. → [[3. Footprinting/2. Network Enumeration with Nmap/1. Enumeration|Nmap src]]

## Host Discovery (network / IP list)
**IF** internal network or `-iL` IP list, no live-host picture →
- [ ] **DO** sweep, then extract live IPs.
```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```
WHY: most effective host discovery = ICMP echo requests; `-sn` disables port scanning.
- [ ] works → feed live IPs into §Nmap scan | fails → force ICMP with `-PE`, confirm with `--packet-trace`
- [ ] ⏱ cap a /24 sweep at a few min → move to §Nmap scan (TTL tell: Linux 64, Windows 128, net devices 255)
→ [[3. Footprinting/2. Network Enumeration with Nmap/2. Host Discovery|Host Discovery src]]

## Nmap — scan, scripts, perf & saved output
**IF** host alive, need ports/versions/scripts or a saved report →
- [ ] **DO** quick `-sC -sV`, then all-ports; banner grab, `-A`, RTT tuning, XML→HTML.
```bash
nmap -sC -sV -oN nmap_initial.txt $TARGET
nmap -p- -sV --min-rate 2000 -oN nmap_allports.txt $TARGET
nmap -sV --script=banner $TARGET
sudo nmap -A 10.129.2.28
sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
xsltproc target.xml -o target.html
```
WHY: default is top-1000 TCP only; `-sC -sV` adds default scripts + version detection; `-A` adds OS+traceroute.
- [ ] works → feed each open port into its per-service node | fails/slow → `-sU` UDP, `-O`, or a timing template `-T0`…`-T5`; `--script <category>` for one NSE category
- [ ] ⏱ don't idle on `-p-`; keep it running and work known ports → §Web recon
- save formats: `-oN`/`-oG`/`-oX`; `-oA` saves all → convert with the xsltproc line
→ [[3. Footprinting/2. Network Enumeration with Nmap/1. Enumeration|Nmap src]]

## Nmap — firewall / IDS-IPS evasion
**IF** subnets or ports are filtered / nothing responds →
- [ ] **DO** decoy scan, spoof a trusted source port, or source-IP spoof.
```bash
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```
WHY: a firewall may trust traffic FROM port 53 ("just a DNS reply"); decoys randomise source IP.
- [ ] works → pivot the trick to other filtered ports | fails → ensure decoys are alive (else SYN-flood block) → DNS proxying via `--dns-server`
- [ ] ⏱ cap evasion experiments; if still dark → §Web recon / other footholds
→ [[3. Footprinting/2. Network Enumeration with Nmap/7. Firewall and IDS or IPS Evasion|Evasion src]]

## FTP (21 / 20 / 2121)
**IF** port 21 (or alt 2121) open →
- [ ] **DO** try anonymous login, mirror the tree, test upload, confirm banner.
```bash
wget -m --no-passive ftp://anonymous:anonymous@$TARGET:2121
nc -nv $TARGET 21
openssl s_client -connect $TARGET:21 -starttls ftp
```
WHY: anonymous login needs no credentials; control channel on 21, data on 20.
- [ ] works → download all files, look for creds/keys/config → §SMB / §SSH | fails → active vs passive (`--no-passive` forces active), or TFTP (UDP, no auth)
- [ ] ⏱ 2 min → else next open service
→ [[3. Footprinting/5. FTP|FTP src]]

## SMB (445 / 139)
**IF** TCP 139/445 open →
- [ ] **DO** version scan, list & connect shares, RPC/cross-tool enumeration.
```bash
sudo nmap $TARGET -sV -sC -p139,445
smbclient -N -L //$TARGET
smbclient //$TARGET/sambashare -N
smbclient //$TARGET/Users -U '$USER%$PASS'
rpcclient -U "" $TARGET
smbmap -H $TARGET
./enum4linux-ng.py $TARGET -A
```
WHY: anonymous/null sessions and RID cycling enumerate users/shares before you have creds.
- [ ] works → download files, find creds → §MSSQL / §Windows RM, re-run with `$USER%$PASS` | fails → rpcclient one-offs (`enumdomusers`, `netshareenumall`, `queryuser <RID>`), smbmap/crackmapexec/enum4linux-ng
- usernames collected (RID cycle / `enum4linux-ng` / `rpcclient`) → password spray → [[04 - Credentials & Common Services]] §spray
- [ ] ⏱ 3–5 min → if SMB gives little, actively send specific requests, else next service
→ [[3. Footprinting/6. SMB|SMB src]]

## NFS (111 rpcbind / 2049)
**IF** 111 + 2049 open →
- [ ] **DO** scan NFS, list exports, mount, enumerate perms.
```bash
showmount -e $TARGET
sudo mount -t nfs $TARGET:/ ./target-NFS/ -o nolock
ls -n mnt/nfs/
```
WHY: NFS has no auth of its own — trust is delegated to RPC / Unix UID-GID & group perms.
- [ ] works → read/write files; recreate matching UID/GID locally; upload a SUID shell for privesc | fails → match local usernames/UIDs, `-o nolock` if it hangs
- [ ] ⏱ 3 min → unmount (`sudo umount ./target-NFS`) and move on
→ [[3. Footprinting/7. NFS|NFS src]]

## DNS (53)
**IF** DNS reachable on 53 →
- [ ] **DO** NS lookup, version probe, AXFR attempt, subdomain brute.
```bash
dig ns $DOMAIN @$TARGET
dig CH TXT version.bind $TARGET
dig axfr $DOMAIN @$TARGET
dnsenum --dnsserver $TARGET --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt $DOMAIN
```
WHY: AXFR copies an entire zone (domain + subdomains); version.bind leaks the server build.
- [ ] works → harvest hostnames → enumerate each → §Web recon | fails → brute loop with `dig` per wordlist entry, `host` for simple resolution
- [ ] ⏱ 3 min → if AXFR refused, brute briefly then go to §Subdomains
→ [[3. Footprinting/8. DNS|DNS src]]

## SMTP (25)
**IF** TCP 25 open →
- [ ] **DO** interactive VRFY enum + nmap scripts + smtp-user-enum.
```bash
telnet $TARGET 25
sudo nmap $TARGET -p25 --script smtp-open-relay -v
smtp-user-enum -M VRFY -U footprinting-wordlist.txt -t $TARGET -w 15 -v
```
WHY: VRFY can enumerate existing users; open-relay/user-enum scripts find mail abuse and accounts.
- [ ] works → collect usernames → reuse for §SMB/§RDP/§WinRM | fails → manual `VRFY <user>` (look for `252 2.0.0 <user>`), try EXPN
- [ ] ⏱ 2 min → next service
→ [[3. Footprinting/9. SMTP|SMTP src]]

## IMAP / POP3 (143/993, 110/995)
**IF** mail ports open and you have creds →
- [ ] **DO** TLS interactive session, then enumerate mailboxes/messages.
```bash
curl -k 'imaps://$TARGET' --user $USER:$PASS
openssl s_client -connect $TARGET:993 -crlf -quiet
a1 LOGIN $USER $PASS
a10 FETCH 1 RFC822
```
WHY: with creds you can read (and send) mail; mailboxes often hold keys/credentials/admin emails.
- [ ] works → grep messages for creds/SSH keys → reuse (Hard lab chain) | fails → POP3 USER/PASS/STAT/LIST/RETR, IMAP CREATE/DELETE/RENAME/LSUB/CLOSE/LOGOUT
- [ ] ⏱ 3 min → move on; creds may still work for SSH
→ [[3. Footprinting/10. IMAP  POP3|IMAP/POP3 src]]

## SNMP (161 / 162 udp)
**IF** UDP 161/162 open →
- [ ] **DO** brute the community string, then walk OIDs.
```bash
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt $TARGET
snmpwalk -v2c -c public $TARGET
```
WHY: SNMP handles remote config; the MIB stores device info, an OID is a node in the hierarchy.
- [ ] works → walk for processes/users/routing/versions → creds often leak (Hard lab) | fails → after onesixtyone finds a string, walk with it, then `braa public@$TARGET:.1.3.6.*`
- [ ] ⏱ 2 min → next service
- TYPO: source note lists port `61`; SNMP is UDP/161
→ [[3. Footprinting/11.SNMP|SNMP src]]

## MySQL (3306)
**IF** TCP 3306 open →
- [ ] **DO** nmap mysql scripts, then interactive SQL.
```bash
sudo nmap $TARGET -sV -sC -p3306 --script mysql*
mysql -u $USER -p<password> -h <IP address>
```
WHY: enumerate databases/tables/columns and dump data.
- [ ] works → `show databases;` → `use <db>;` → `show tables;` → `select * from <table>;` | fails → filter `select * from <table> where <column> = "<string>";`, try empty/`root`
- [ ] ⏱ 3 min → no creds? hunt them via §SMB / web LFI (no space between `-p` and password)
→ [[3. Footprinting/12. MySQL|MySQL src]]

## MSSQL (1433)
**IF** TCP 1433 open →
- [ ] **DO** NSE ms-sql scripts, Metasploit ping, impacket login.
```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
impacket-mssqlclient ILF-SQL-01/$USER@$TARGET -windows-auth
```
WHY: enumerate the DB via NSE; log in with impacket (`-windows-auth` for Windows integrated auth).
- [ ] works → `xp_cmdshell` RCE if enabled → reuse creds for §Windows RM | fails → drop `-windows-auth` (mixed auth), try empty `sa` via the NSE args
- [ ] ⏱ 3 min → hunt `sa` creds on §SMB (Medium lab chain)
→ [[3. Footprinting/13. MSSQL|MSSQL src]]

## Oracle TNS (1521)
**IF** TCP 1521 open (Oracle listener) →
- [ ] **DO** version scan, SID brute, ODAT, sqlplus, hash extraction, file upload.
```bash
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
./odat.py all -s 10.129.204.235
sqlplus scott/tiger@10.129.204.235/XE as sysdba
select name, password from sys.user$;
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```
WHY: ODAT enumerates/exploits Oracle; `sys.user$` holds password hashes to crack offline.
- [ ] works → crack hashes, reuse; upload a web shell to a webroot and `curl -X GET http://10.129.204.235/testing.txt` | fails → try sysdba `scott/tiger`, upload to `/var/www/html` (Linux)
- [ ] ⏱ 4 min → no known webroot? pivot to §Web recon (default TCP/1521; Oracle 9 default `CHANGE_ON_INSTALL`)
→ [[3. Footprinting/14. Oracle TNS|Oracle TNS src]]

## IPMI (623 udp)
**IF** UDP 623 open (BMC: HP iLO, Dell iDRAC, Supermicro) →
- [ ] **DO** version scan, then dump hashes.
```bash
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
use auxiliary/scanner/ipmi/ipmi_dumphashes
set rhosts 10.129.42.195
```
WHY: IPMI manages hardware out-of-band (even powered off) — BMC access = full host control.
- [ ] works → crack the dumped rakhash offline → log into the BMC | fails → try defaults: Dell `root:calvin`, Supermicro `ADMIN:ADMIN`, HP `Administrator:<random>`
- [ ] ⏱ 2 min → next service
→ [[3. Footprinting/15. IPMI|IPMI src]]

## Linux Remote Management (SSH 22 / rsync 873 / r-services 512-514)
**IF** SSH, rsync, or r-services open →
- [ ] **DO** audit SSH, enumerate/sync rsync, list r-service users.
```bash
./ssh-audit.py $TARGET
rsync -av --list-only rsync://$TARGET/dev
sudo nmap -sV -p 512,513,514 $TARGET
rusers -al $TARGET
```
WHY: rsync shares are often world-readable; r-services trust `/etc/hosts.equiv` and `.rhosts`.
- [ ] works → pull rsync contents; `rwho`/`rusers` give logged-in users → reuse | fails → rsync over SSH (`-e ssh`), host-based/key-only SSH if password refused
- [ ] ⏱ 3 min → if SSH refuses password, get a key elsewhere (mail/NFS) and retry
→ [[3. Footprinting/16. Linux Remote Management Protocols|Linux RM src]]

## Windows Remote Management (RDP 3389 / WinRM 5985-5986 / WMI 135)
**IF** RDP, WinRM, or WMI open →
- [ ] **DO** RDP security check/connect, WinRM scan + evil-winrm, WMI exec.
```bash
./rdp-sec-check.pl 10.129.201.248
xfreerdp /v:$TARGET /u:$USER /d:. /p:'$PASS' /cert:ignore
evil-winrm -i $TARGET -u $USER -p $PASS
/usr/share/doc/python3-impacket/examples/wmiexec.py $USER:"$PASS"@$TARGET "hostname"
```
WHY: the three main Windows footholds — RDP (GUI), WinRM (CLI 5985/5986), WMI (via 135, impacket wmiexec).
- [ ] works → GUI/CLI/remote-exec shell → hunt creds for privesc/lateral | fails → `/d:.` for explicit local auth, heavy-flag xfreerdp for low bandwidth
- [ ] ⏱ 3 min → no creds? pivot to §SMB / §MSSQL to find them
→ [[3. Footprinting/17. Windows Remote Management Protocols|Windows RM src]]

## Public Exploits (version → known CVE)
**IF** you have an exact vulnerable service/version →
- [ ] **DO** search Exploit-DB, then drive Metasploit.
```bash
searchsploit openssh 7.2
msfconsole
use exploit/<exploit_name>
set RHOSTS <target>
run
```
WHY: match a discovered version against known public exploits before reinventing.
- [ ] works → shell → [[06 - Privilege Escalation]] | fails → run the raw Exploit-DB PoC manually; set every required MSF option before `run`
- [ ] ⏱ 3 min per CVE → no match? return to §Web recon / service nodes
→ [[1. Getting Started/4. Public Exploits/1.Public Exploits|Public Exploits src]]

## Web recon (HTTP/HTTPS → structure, tech, hidden paths, WAF)
**IF** HTTP/HTTPS service found →
- [ ] **DO** dir brute, header/banner grab, WAF detect, tech fingerprint; or one-shot broad recon.
```bash
gobuster dir -u http://$TARGET/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
curl -IL https://www.inlanefreight.com
whatweb $TARGET
wafw00f inlanefreight.com
nikto -h inlanefreight.com -Tuning b
./finalrecon.py --help
```
WHY: Gobuster enumerates dirs/vhosts/DNS/S3; `curl -IL` shows server headers; whatweb extracts versions; wafw00f IDs the WAF; FinalRecon automates the sweep.
- [ ] works → inspect `robots.txt`, page source (cred leaks/hidden paths), TLS certs (emails/orgs → OSINT) → `03 - Web Exploitation & Foothold` (authoritative app-discovery home: `03` §Application Discovery) | fails → swap wordlist (`directory-list-2.3-small`), add `-e .php,.html`
- [ ] ⏱ 5 min → once you have a stack/attack surface, jump to `03 - Web Exploitation & Foothold`
- FinalRecon setup: `git clone https://github.com/thewhiteh4t/FinalRecon.git` → `cd FinalRecon` → `pip3 install -r requirements.txt` → `chmod +x ./finalrecon.py`
→ [[1. Getting Started/3. Web Enumeration/1. Web Enumeration|Web Enum src]]

## Web DNS records (domain mapping)
**IF** starting external recon on a domain →
- [ ] **DO** pull records with dig.
```bash
dig $DOMAIN
dig $DOMAIN MX
dig $DOMAIN NS
dig $DOMAIN TXT
dig $DOMAIN SOA
dig +trace $DOMAIN
```
WHY: dig is the versatile lookup (A/MX/NS/TXT/zone transfers/deep analysis).
- [ ] works → feed records into §Subdomains / §vhosts / §CT logs | fails → `nslookup` / `host`, then `dnsenum`/`fierce`/`dnsrecon`/`theHarvester`
- [ ] ⏱ 2 min → note MX/SPF/DMARC for later phishing/email angles
→ [[4. Information Gathering - Web Edition/2. DNS|DNS src]]

## Subdomains & DNS Zone Transfer
**IF** you need subdomains, or an authoritative NS may allow AXFR →
- [ ] **DO** brute with dnsenum / vhost-fuzz, and attempt a zone copy.
```bash
dnsenum --enum $DOMAIN -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
ffuf -u http://$DOMAIN:35684 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mc 200,403 -t 60 -H "Host: FUZZ.$DOMAIN" -ac
dig axfr @$TARGET $DOMAIN
```
WHY: brute-force tests candidate names; AXFR copies the whole zone (domain + subdomains) if misconfigured.
- [ ] works → add to `/etc/hosts` or vhost-fuzz each → §vhosts / §Web recon | fails → `fierce` (wildcard detect) / `dnsrecon` / `amass` / `assetfinder` / `puredns`
- [ ] ⏱ 3 min → if DNS-only fails, switch to Host-header fuzzing (§vhosts); AXFR is almost always refused today
→ [[4. Information Gathering - Web Edition/3. Subdomains|Subdomains src]]

## Virtual Hosts (vhost discovery)
**IF** one IP hosts multiple sites but DNS has no record →
- [ ] **DO** brute-force the Host header and map names in `/etc/hosts`.
```bash
gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
gobuster vhost -u http://83.136.249.164:52488 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --domain $DOMAIN --append-domain -t 50
```
WHY: the server differentiates sites by the Host header; visiting the raw IP shows the default page.
- [ ] works → add entries to `/etc/hosts`, re-run §Web recon per vhost (dup of `03` §FFUF vhost — pick one home) | fails → ffuf (`-H 'Host: FUZZ.$DOMAIN'`), Feroxbuster host-header fuzzing
- [ ] ⏱ 3 min → internal/`.local` names need no DNS, so don't chase resolution
→ [[4. Information Gathering - Web Edition/5. Virtual Hosts|vhosts src]]

## Domain & OSINT footprint (whole internet presence)
**IF** mapping a company's entire internet presence →
- [ ] **DO** CT logs, company-hosted hosts, Shodan, then WHOIS/cloud/staff OSINT.
```bash
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
dig any inlanefreight.com
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```
WHY: separates company-hosted (directly accessible) hosts from third-party ones; WHOIS/cloud/staff add contacts, cloud assets, and tech stack.
- [ ] works → enumerate each company-hosted host → §Web recon | fails → Shodan needs an API key; correlate subdomains→IPs→Shodan
- [ ] ⏱ 5 min → don't test third-party-hosted hosts without provider permission
- CT logs (crt.sh `contains("dev")` filter → dedupe subdomains): [[4. Information Gathering - Web Edition/6. Certificate Transparency Logs|CT logs src]]
- `GAP:` WHOIS / Cloud Resources / Staff are notes-only (no commands) and out-of-scope for this router — sources: [[4. Information Gathering - Web Edition/1.WHOIS|WHOIS src]], [[3. Footprinting/3. Cloud Resources|Cloud src]], [[3. Footprinting/4. Staff|Staff src]]
→ [[3. Footprinting/2. Domain Information|Domain Info src]]

## Loop-back
New credential / host / subnet discovered → re-run these:
- [ ] new credential → §SMB, §MSSQL, §MySQL, §IMAP/POP3, §Windows RM, §Linux RM (retry every service that previously failed auth)
- [ ] new host → §Host Discovery, §Nmap scan, then the per-service nodes
- [ ] new subnet → §Host Discovery sweep → §Nmap scan → §Nmap evasion if filtered
- [ ] new domain/hostname → §Web DNS, §Subdomains, §vhosts, §Domain & OSINT footprint (CT logs) → §Web recon
- [ ] new web stack/fingerprint → hand off to `03 - Web Exploitation & Foothold`
