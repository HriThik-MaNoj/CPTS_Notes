# Complete CPTS Notes Index

## 📚 Navigation Guide

This index provides quick access to all topics organized by category, phase, and use case.

---

## 🎯 By Penetration Testing Phase

### Phase 0: Preparation
- [Penetration Testing Workflow](./Penetration-Testing-Workflow.md)
- [Environment Setup](../09-Quick-Reference/Environment-Setup.md)
- [Tool Installation](../08-Tools-Reference/Tool-Installation.md)

### Phase 1: Reconnaissance
- [External Reconnaissance](../01-Reconnaissance/External-Recon.md)
- [WHOIS Enumeration](../01-Reconnaissance/WHOIS.md)
- [DNS Enumeration](../01-Reconnaissance/DNS-Enumeration.md)
- [Subdomain Discovery](../01-Reconnaissance/Subdomain-Discovery.md)

### Phase 2: Enumeration
- [Network Enumeration](../02-Enumeration/Network-Enumeration.md)
- [Nmap Reference](../08-Tools-Reference/Nmap.md)
- [Service-Specific Enumeration](../02-Enumeration/Service-Specific/)
  - [SMB Enumeration](../02-Enumeration/Service-Specific/SMB-Enumeration.md)
  - [FTP Enumeration](../02-Enumeration/Service-Specific/FTP-Enumeration.md)
  - [DNS Enumeration](../02-Enumeration/Service-Specific/DNS-Enumeration.md)
  - [SMTP Enumeration](../02-Enumeration/Service-Specific/SMTP-Enumeration.md)
  - [SNMP Enumeration](../02-Enumeration/Service-Specific/SNMP-Enumeration.md)
  - [Database Enumeration](../02-Enumeration/Service-Specific/Database-Enumeration.md)
- [Web Enumeration](../02-Enumeration/Web-Enumeration/)
  - [Web Recon Workflow](../02-Enumeration/Web-Enumeration/Web-Recon-Workflow.md)
  - [Directory Fuzzing](../02-Enumeration/Web-Enumeration/Directory-Fuzzing.md)
  - [Virtual Host Discovery](../02-Enumeration/Web-Enumeration/VHost-Discovery.md)

### Phase 3: Initial Access
- [Exploitation Workflow](../03-Initial-Access/Exploitation-Workflow.md)
- [Payload Generation](../03-Initial-Access/Payload-Generation.md)
- [Reverse Shells](../03-Initial-Access/Reverse-Shells.md)
- [Bind Shells](../03-Initial-Access/Bind-Shells.md)
- [Web Shells](../03-Initial-Access/Web-Shells.md)
- [Shell Stabilization](../03-Initial-Access/Shell-Stabilization.md)

### Phase 4: Post-Exploitation
- [Situational Awareness](../04-Post-Exploitation/Situational-Awareness.md)
- [Credential Harvesting](../04-Post-Exploitation/Credential-Harvesting.md)
- [Lateral Movement](../04-Post-Exploitation/Lateral-Movement.md)
- [Pivoting and Tunneling](../04-Post-Exploitation/Pivoting-Tunneling.md)
- [Persistence](../04-Post-Exploitation/Persistence.md)

### Phase 5: Privilege Escalation
- [Linux Privilege Escalation](../05-Privilege-Escalation/Linux-PrivEsc.md)
- [Windows Privilege Escalation](../05-Privilege-Escalation/Windows-PrivEsc.md)
- [PrivEsc Checklist](../05-Privilege-Escalation/PrivEsc-Checklist.md)

### Phase 6: Active Directory
- [AD Enumeration Workflow](../06-Active-Directory/Enumeration-Workflow.md)
- [Attack Paths](../06-Active-Directory/Attack-Paths.md)
- [Kerberoasting](../06-Active-Directory/Kerberoasting.md)
- [AS-REP Roasting](../06-Active-Directory/ASREP-Roasting.md)
- [Pass-the-Hash](../06-Active-Directory/Pass-the-Hash.md)
- [DCSync](../06-Active-Directory/DCSync.md)
- [Bloodhound Analysis](../06-Active-Directory/Bloodhound.md)

### Phase 7: File Transfers
- [File Transfer Methods](../07-File-Transfers/File-Transfer-Methods.md)
- [Living Off The Land](../07-File-Transfers/Living-Off-The-Land.md)
- [Evasion Techniques](../07-File-Transfers/Evasion-Techniques.md)

---

## 🔧 By Tool

### Network Scanning
- [Nmap](../08-Tools-Reference/Nmap.md)
- [Masscan](../08-Tools-Reference/Masscan.md)
- [Rustscan](../08-Tools-Reference/Rustscan.md)

### Web Enumeration
- [Gobuster](../08-Tools-Reference/Gobuster.md)
- [Ffuf](../08-Tools-Reference/Ffuf.md)
- [Feroxbuster](../08-Tools-Reference/Feroxbuster.md)
- [Nikto](../08-Tools-Reference/Nikto.md)
- [WhatWeb](../08-Tools-Reference/WhatWeb.md)

### Exploitation Frameworks
- [Metasploit](../08-Tools-Reference/Metasploit.md)
- [MSFVenom](../08-Tools-Reference/MSFVenom.md)

### Active Directory
- [Bloodhound](../08-Tools-Reference/Bloodhound.md)
- [Impacket Suite](../08-Tools-Reference/Impacket.md)
- [CrackMapExec](../08-Tools-Reference/CrackMapExec.md)
- [Kerbrute](../08-Tools-Reference/Kerbrute.md)
- [Rubeus](../08-Tools-Reference/Rubeus.md)

### Password Attacks
- [John the Ripper](../08-Tools-Reference/John.md)
- [Hashcat](../08-Tools-Reference/Hashcat.md)
- [Hydra](../08-Tools-Reference/Hydra.md)

### Privilege Escalation
- [LinPEAS](../08-Tools-Reference/LinPEAS.md)
- [WinPEAS](../08-Tools-Reference/WinPEAS.md)
- [GTFOBins](../08-Tools-Reference/GTFOBins.md)
- [LOLBAS](../08-Tools-Reference/LOLBAS.md)

### Pivoting
- [Chisel](../08-Tools-Reference/Chisel.md)
- [Ligolo-ng](../08-Tools-Reference/Ligolo-ng.md)
- [Proxychains](../08-Tools-Reference/Proxychains.md)
- [SSH Tunneling](../08-Tools-Reference/SSH-Tunneling.md)

---

## 🎯 By Service/Protocol

### Port 21 - FTP
- [FTP Enumeration](../02-Enumeration/Service-Specific/FTP-Enumeration.md)
- Anonymous login
- File download/upload
- Brute force attacks

### Port 22 - SSH
- [SSH Enumeration](../02-Enumeration/Service-Specific/SSH-Enumeration.md)
- [SSH Tunneling](../08-Tools-Reference/SSH-Tunneling.md)
- Key-based authentication
- Port forwarding

### Port 25 - SMTP
- [SMTP Enumeration](../02-Enumeration/Service-Specific/SMTP-Enumeration.md)
- User enumeration (VRFY, EXPN, RCPT)
- Open relay testing

### Port 53 - DNS
- [DNS Enumeration](../02-Enumeration/Service-Specific/DNS-Enumeration.md)
- Zone transfers
- Subdomain brute forcing
- DNS tunneling

### Port 80/443 - HTTP/HTTPS
- [Web Recon Workflow](../02-Enumeration/Web-Enumeration/Web-Recon-Workflow.md)
- [Directory Fuzzing](../02-Enumeration/Web-Enumeration/Directory-Fuzzing.md)
- [VHost Discovery](../02-Enumeration/Web-Enumeration/VHost-Discovery.md)
- [SQL Injection](../02-Enumeration/Web-Enumeration/SQLi.md)
- [LFI/RFI](../02-Enumeration/Web-Enumeration/LFI-RFI.md)
- [Command Injection](../02-Enumeration/Web-Enumeration/Command-Injection.md)

### Port 139/445 - SMB
- [SMB Enumeration](../02-Enumeration/Service-Specific/SMB-Enumeration.md)
- Null session attacks
- Share enumeration
- RID cycling
- SMB relay attacks

### Port 161 - SNMP
- [SNMP Enumeration](../02-Enumeration/Service-Specific/SNMP-Enumeration.md)
- Community string brute force
- SNMP walking
- Information disclosure

### Port 389/636 - LDAP
- [LDAP Enumeration](../02-Enumeration/Service-Specific/LDAP-Enumeration.md)
- Anonymous bind
- User/group enumeration
- Password policy discovery

### Port 1433 - MSSQL
- [MSSQL Enumeration](../02-Enumeration/Service-Specific/Database-Enumeration.md)
- xp_cmdshell exploitation
- Linked servers
- Impersonation attacks

### Port 3306 - MySQL
- [MySQL Enumeration](../02-Enumeration/Service-Specific/Database-Enumeration.md)
- UDF exploitation
- File read/write
- Privilege escalation

### Port 3389 - RDP
- [RDP Enumeration](../02-Enumeration/Service-Specific/RDP-Enumeration.md)
- NLA bypass
- BlueKeep (CVE-2019-0708)
- Credential attacks

### Port 5985/5986 - WinRM
- [WinRM Enumeration](../02-Enumeration/Service-Specific/WinRM-Enumeration.md)
- Evil-WinRM usage
- PowerShell remoting

---

## 🎯 By Attack Type

### Web Application Attacks
- [SQL Injection](../02-Enumeration/Web-Enumeration/SQLi.md)
- [Cross-Site Scripting (XSS)](../02-Enumeration/Web-Enumeration/XSS.md)
- [Local File Inclusion (LFI)](../02-Enumeration/Web-Enumeration/LFI-RFI.md)
- [Remote File Inclusion (RFI)](../02-Enumeration/Web-Enumeration/LFI-RFI.md)
- [Command Injection](../02-Enumeration/Web-Enumeration/Command-Injection.md)
- [File Upload Vulnerabilities](../02-Enumeration/Web-Enumeration/File-Upload.md)
- [Server-Side Request Forgery (SSRF)](../02-Enumeration/Web-Enumeration/SSRF.md)

### Password Attacks
- [Brute Force](../08-Tools-Reference/Hydra.md)
- [Password Spraying](../06-Active-Directory/Password-Spraying.md)
- [Hash Cracking](../08-Tools-Reference/Hashcat.md)
- [Credential Stuffing](../04-Post-Exploitation/Credential-Harvesting.md)

### Active Directory Attacks
- [Kerberoasting](../06-Active-Directory/Kerberoasting.md)
- [AS-REP Roasting](../06-Active-Directory/ASREP-Roasting.md)
- [Pass-the-Hash](../06-Active-Directory/Pass-the-Hash.md)
- [Pass-the-Ticket](../06-Active-Directory/Pass-the-Ticket.md)
- [DCSync](../06-Active-Directory/DCSync.md)
- [Golden Ticket](../06-Active-Directory/Golden-Ticket.md)
- [Silver Ticket](../06-Active-Directory/Silver-Ticket.md)
- [LLMNR/NBT-NS Poisoning](../06-Active-Directory/LLMNR-Poisoning.md)

### Privilege Escalation
- [SUID Binaries](../05-Privilege-Escalation/Linux-PrivEsc.md#suid)
- [Sudo Misconfigurations](../05-Privilege-Escalation/Linux-PrivEsc.md#sudo)
- [Kernel Exploits](../05-Privilege-Escalation/Kernel-Exploits.md)
- [Unquoted Service Paths](../05-Privilege-Escalation/Windows-PrivEsc.md#unquoted)
- [Token Impersonation](../05-Privilege-Escalation/Windows-PrivEsc.md#tokens)
- [AlwaysInstallElevated](../05-Privilege-Escalation/Windows-PrivEsc.md#alwaysinstall)

---

## 🎯 By Operating System

### Linux
- [Linux Enumeration](../04-Post-Exploitation/Situational-Awareness.md#linux)
- [Linux Privilege Escalation](../05-Privilege-Escalation/Linux-PrivEsc.md)
- [Linux File Transfers](../07-File-Transfers/File-Transfer-Methods.md#linux)
- [Linux Persistence](../04-Post-Exploitation/Persistence.md#linux)

### Windows
- [Windows Enumeration](../04-Post-Exploitation/Situational-Awareness.md#windows)
- [Windows Privilege Escalation](../05-Privilege-Escalation/Windows-PrivEsc.md)
- [Windows File Transfers](../07-File-Transfers/File-Transfer-Methods.md#windows)
- [Windows Persistence](../04-Post-Exploitation/Persistence.md#windows)

---

## 🎯 By Scenario

### Black Box Assessment
1. [External Reconnaissance](../01-Reconnaissance/External-Recon.md)
2. [Network Enumeration](../02-Enumeration/Network-Enumeration.md)
3. [Service Enumeration](../02-Enumeration/Service-Specific/)
4. [Exploitation](../03-Initial-Access/Exploitation-Workflow.md)

### Gray Box Assessment (Credentials Provided)
1. [Authenticated Enumeration](../02-Enumeration/Authenticated-Enumeration.md)
2. [Credential Validation](../08-Tools-Reference/CrackMapExec.md)
3. [Lateral Movement](../04-Post-Exploitation/Lateral-Movement.md)

### Internal Network Assessment
1. [Network Discovery](../04-Post-Exploitation/Network-Discovery.md)
2. [Pivoting](../04-Post-Exploitation/Pivoting-Tunneling.md)
3. [Lateral Movement](../04-Post-Exploitation/Lateral-Movement.md)

### Active Directory Assessment
1. [AD Enumeration](../06-Active-Directory/Enumeration-Workflow.md)
2. [Bloodhound Analysis](../06-Active-Directory/Bloodhound.md)
3. [Attack Paths](../06-Active-Directory/Attack-Paths.md)
4. [Domain Dominance](../06-Active-Directory/DCSync.md)

---

## 📚 Quick Reference Sheets

### Exam Preparation
- [Exam Checklist](../09-Quick-Reference/Exam-Checklist.md)
- [Environment Setup](../09-Quick-Reference/Environment-Setup.md)
- [Common Commands](../09-Quick-Reference/Common-Commands.md)

### Cheat Sheets
- [Nmap Cheatsheet](../09-Quick-Reference/Nmap-Cheatsheet.md)
- [Reverse Shell Cheatsheet](../09-Quick-Reference/Reverse-Shell-Cheatsheet.md)
- [Privilege Escalation Cheatsheet](../09-Quick-Reference/PrivEsc-Cheatsheet.md)
- [Active Directory Cheatsheet](../09-Quick-Reference/AD-Cheatsheet.md)
- [File Transfer Cheatsheet](../09-Quick-Reference/File-Transfer-Cheatsheet.md)

### Command Templates
- [Nmap Commands](../09-Quick-Reference/Nmap-Commands.md)
- [Web Enumeration Commands](../09-Quick-Reference/Web-Enum-Commands.md)
- [SMB Commands](../09-Quick-Reference/SMB-Commands.md)
- [PowerShell Commands](../09-Quick-Reference/PowerShell-Commands.md)

---

## 🔍 Search by Keyword

### A
- Active Directory → [AD Section](../06-Active-Directory/)
- AS-REP Roasting → [AS-REP Roasting](../06-Active-Directory/ASREP-Roasting.md)
- AlwaysInstallElevated → [Windows PrivEsc](../05-Privilege-Escalation/Windows-PrivEsc.md)

### B
- Bind Shells → [Bind Shells](../03-Initial-Access/Bind-Shells.md)
- Bloodhound → [Bloodhound](../08-Tools-Reference/Bloodhound.md)
- Brute Force → [Hydra](../08-Tools-Reference/Hydra.md)

### C
- Command Injection → [Command Injection](../02-Enumeration/Web-Enumeration/Command-Injection.md)
- CrackMapExec → [CrackMapExec](../08-Tools-Reference/CrackMapExec.md)
- Credential Harvesting → [Credential Harvesting](../04-Post-Exploitation/Credential-Harvesting.md)

### D
- DCSync → [DCSync](../06-Active-Directory/DCSync.md)
- DNS Enumeration → [DNS Enumeration](../02-Enumeration/Service-Specific/DNS-Enumeration.md)
- Directory Fuzzing → [Directory Fuzzing](../02-Enumeration/Web-Enumeration/Directory-Fuzzing.md)

### E
- Enumeration → [Enumeration Section](../02-Enumeration/)
- Evil-WinRM → [WinRM](../02-Enumeration/Service-Specific/WinRM-Enumeration.md)
- Exploitation → [Initial Access](../03-Initial-Access/)

### F
- File Transfers → [File Transfers](../07-File-Transfers/)
- FTP → [FTP Enumeration](../02-Enumeration/Service-Specific/FTP-Enumeration.md)
- Ffuf → [Ffuf](../08-Tools-Reference/Ffuf.md)

### G
- Gobuster → [Gobuster](../08-Tools-Reference/Gobuster.md)
- Golden Ticket → [Golden Ticket](../06-Active-Directory/Golden-Ticket.md)
- GTFOBins → [GTFOBins](../08-Tools-Reference/GTFOBins.md)

### H
- Hashcat → [Hashcat](../08-Tools-Reference/Hashcat.md)
- Hydra → [Hydra](../08-Tools-Reference/Hydra.md)
- HTTP Enumeration → [Web Enumeration](../02-Enumeration/Web-Enumeration/)

### I
- Impacket → [Impacket](../08-Tools-Reference/Impacket.md)
- Initial Access → [Initial Access](../03-Initial-Access/)

### J
- John the Ripper → [John](../08-Tools-Reference/John.md)

### K
- Kerberoasting → [Kerberoasting](../06-Active-Directory/Kerberoasting.md)
- Kernel Exploits → [Kernel Exploits](../05-Privilege-Escalation/Kernel-Exploits.md)

### L
- Lateral Movement → [Lateral Movement](../04-Post-Exploitation/Lateral-Movement.md)
- LDAP → [LDAP Enumeration](../02-Enumeration/Service-Specific/LDAP-Enumeration.md)
- LFI → [LFI/RFI](../02-Enumeration/Web-Enumeration/LFI-RFI.md)
- LinPEAS → [LinPEAS](../08-Tools-Reference/LinPEAS.md)
- LLMNR Poisoning → [LLMNR Poisoning](../06-Active-Directory/LLMNR-Poisoning.md)

### M
- Metasploit → [Metasploit](../08-Tools-Reference/Metasploit.md)
- MSFVenom → [MSFVenom](../08-Tools-Reference/MSFVenom.md)
- MSSQL → [Database Enumeration](../02-Enumeration/Service-Specific/Database-Enumeration.md)
- MySQL → [Database Enumeration](../02-Enumeration/Service-Specific/Database-Enumeration.md)

### N
- Netcat → [Reverse Shells](../03-Initial-Access/Reverse-Shells.md)
- Nmap → [Nmap](../08-Tools-Reference/Nmap.md)

### P
- Pass-the-Hash → [Pass-the-Hash](../06-Active-Directory/Pass-the-Hash.md)
- Password Attacks → [Password Attacks](../08-Tools-Reference/)
- Persistence → [Persistence](../04-Post-Exploitation/Persistence.md)
- Pivoting → [Pivoting](../04-Post-Exploitation/Pivoting-Tunneling.md)
- PowerShell → [PowerShell Commands](../09-Quick-Reference/PowerShell-Commands.md)
- Privilege Escalation → [PrivEsc Section](../05-Privilege-Escalation/)

### R
- RDP → [RDP Enumeration](../02-Enumeration/Service-Specific/RDP-Enumeration.md)
- Reconnaissance → [Reconnaissance](../01-Reconnaissance/)
- Reverse Shells → [Reverse Shells](../03-Initial-Access/Reverse-Shells.md)

### S
- Shell Stabilization → [Shell Stabilization](../03-Initial-Access/Shell-Stabilization.md)
- SMB → [SMB Enumeration](../02-Enumeration/Service-Specific/SMB-Enumeration.md)
- SMTP → [SMTP Enumeration](../02-Enumeration/Service-Specific/SMTP-Enumeration.md)
- SNMP → [SNMP Enumeration](../02-Enumeration/Service-Specific/SNMP-Enumeration.md)
- SQL Injection → [SQLi](../02-Enumeration/Web-Enumeration/SQLi.md)
- SSH → [SSH Enumeration](../02-Enumeration/Service-Specific/SSH-Enumeration.md)
- SUID → [Linux PrivEsc](../05-Privilege-Escalation/Linux-PrivEsc.md)

### T
- Token Impersonation → [Windows PrivEsc](../05-Privilege-Escalation/Windows-PrivEsc.md)
- Tunneling → [Pivoting](../04-Post-Exploitation/Pivoting-Tunneling.md)

### W
- Web Enumeration → [Web Enumeration](../02-Enumeration/Web-Enumeration/)
- Web Shells → [Web Shells](../03-Initial-Access/Web-Shells.md)
- WinPEAS → [WinPEAS](../08-Tools-Reference/WinPEAS.md)
- WinRM → [WinRM Enumeration](../02-Enumeration/Service-Specific/WinRM-Enumeration.md)

### X
- XSS → [XSS](../02-Enumeration/Web-Enumeration/XSS.md)

---

## 📖 Study Path

### Beginner Path (Weeks 1-4)
1. [Penetration Testing Workflow](./Penetration-Testing-Workflow.md)
2. [Nmap](../08-Tools-Reference/Nmap.md)
3. [Web Enumeration](../02-Enumeration/Web-Enumeration/)
4. [Shell Stabilization](../03-Initial-Access/Shell-Stabilization.md)
5. [File Transfers](../07-File-Transfers/)

### Intermediate Path (Weeks 5-8)
1. [Service Enumeration](../02-Enumeration/Service-Specific/)
2. [Privilege Escalation](../05-Privilege-Escalation/)
3. [Post-Exploitation](../04-Post-Exploitation/)
4. [Pivoting](../04-Post-Exploitation/Pivoting-Tunneling.md)

### Advanced Path (Weeks 9-12)
1. [Active Directory](../06-Active-Directory/)
2. [Bloodhound Analysis](../06-Active-Directory/Bloodhound.md)
3. [Advanced Exploitation](../03-Initial-Access/)
4. [Evasion Techniques](../07-File-Transfers/Evasion-Techniques.md)

---

## 🎯 Exam-Specific Resources

### Before the Exam
- [ ] Review [Exam Checklist](../09-Quick-Reference/Exam-Checklist.md)
- [ ] Setup [Environment](../09-Quick-Reference/Environment-Setup.md)
- [ ] Practice [Common Commands](../09-Quick-Reference/Common-Commands.md)

### During the Exam
- Keep [Exam Checklist](../09-Quick-Reference/Exam-Checklist.md) open
- Follow [Methodology](./Penetration-Testing-Workflow.md)
- Use [Quick Reference](../09-Quick-Reference/) sheets

### After Each Machine
- Document findings
- Screenshot flags
- Review methodology gaps

---

**Last Updated**: 2026-02-05
**Version**: 2.0 - Methodology-Focused Edition

---

**Navigation Tip**: Use Ctrl+F (or Cmd+F) to search for specific topics in this index!
