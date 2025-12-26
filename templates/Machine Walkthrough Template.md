# {{machine_name}} Walkthrough

| Info | Value |
|------|-------|
| Platform | HackTheBox / TryHackMe |
| Difficulty | Easy / Medium / Hard |
| OS | Linux / Windows |
| IP | `{{ip_address}}` |

---

## Enumeration

### Nmap Scan

```bash
nmap -sC -sV -oN nmap_initial.txt {{ip_address}}
```

<!-- Paste nmap output screenshot here -->

**Open Ports:**
- Port X - Service
- Port Y - Service

### Web Enumeration

<!-- If web service is running -->

```bash
gobuster dir -u http://{{ip_address}}/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

<!-- Paste screenshots of interesting findings -->

### Other Enumeration

<!-- Add any other enumeration steps -->

## Initial Foothold

### Vulnerability Found

- Description of the vulnerability
- CVE number if applicable

### Exploitation

```bash
# Commands used for exploitation
```

<!-- Paste screenshot of shell access -->

### Upgrading Shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### User Flag

```bash
cat /home/user/user.txt
```

**Flag:** `{{user_flag}}`

---

## Privilege Escalation

### Enumeration

```bash
sudo -l
```

<!-- Paste screenshot of sudo privileges -->

### Exploitation Method

- What was exploited
- How it was exploited

```bash
# Commands for privilege escalation
```

<!-- Paste screenshot of root shell -->

### Root Flag

```bash
cat /root/root.txt
```

**Flag:** `{{root_flag}}`

---

## Lessons Learned

- Key takeaway 1
- Key takeaway 2
- What I would do differently next time

---

See also: [[2. Upgrading TTY]], [[1. Privilege Escalation]]
