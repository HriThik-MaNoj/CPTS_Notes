# CPTS Exam Notes - Methodology-Focused Edition

## 📋 Overview

This is a **methodology-driven** reorganization of CPTS exam preparation notes. Every section is structured around **practical workflows** and **decision trees** to help you systematically approach penetration testing scenarios.

## 🎯 Core Philosophy

> **"Distinguish between what we see and what we do not see. There are always ways to gain more information."**

The notes follow a **layered enumeration approach**:
1. **Internet Presence** → Identify external footprint
2. **Gateway** → Understand security measures
3. **Accessible Services** → Map attack surface
4. **Processes** → Understand data flow
5. **Privileges** → Identify permission boundaries
6. **OS Setup** → Gather system intelligence

## 📚 Structure

### Phase-Based Organization

```
Improved Notes/
├── 00-Methodology/              # Core methodology and workflows
├── 01-Reconnaissance/           # Information gathering techniques
├── 02-Enumeration/              # Service-specific enumeration
├── 03-Initial-Access/           # Exploitation and shell techniques
├── 04-Post-Exploitation/        # Lateral movement and pivoting
├── 05-Privilege-Escalation/     # Linux and Windows privesc
├── 06-Active-Directory/         # AD-specific attacks
├── 07-File-Transfers/           # Data exfiltration methods
├── 08-Tools-Reference/          # Tool-specific guides
└── 09-Quick-Reference/          # Cheat sheets and quick lookups
```

## 🔄 How to Use These Notes

### For Exam Preparation
1. Start with [`00-Methodology/Penetration-Testing-Workflow.md`](00-Methodology/Penetration-Testing-Workflow.md)
2. Follow the phase-based structure sequentially
3. Use Quick Reference sheets during practice labs
4. Review decision trees before tackling machines

### During Practice Labs
1. Open the relevant phase guide
2. Follow the checklist systematically
3. Reference tool-specific guides as needed
4. Document your methodology gaps

### During the Exam
1. Keep [`09-Quick-Reference/Exam-Checklist.md`](09-Quick-Reference/Exam-Checklist.md) open
2. Follow the systematic enumeration workflow
3. Use command templates from Quick Reference
4. Don't skip enumeration steps

## 🎓 Key Improvements Over Original Notes

### ✅ Methodology-First Approach
- Every section starts with "When to use" and "Workflow"
- Decision trees for choosing techniques
- Systematic checklists to prevent missing steps

### ✅ Practical Command Templates
- All commands verified and tested
- Variables clearly marked (e.g., `$IP`, `$PORT`)
- Common errors and solutions included

### ✅ Cross-Referenced Content
- Links between related techniques
- "See also" sections for context
- Prerequisite knowledge clearly marked

### ✅ Exam-Focused Organization
- Quick reference sheets for time-sensitive scenarios
- Common pitfalls highlighted
- Time-saving tips included

## 📖 Navigation Guide

### By Scenario Type

**Black Box Assessment**
1. [`01-Reconnaissance/External-Recon.md`](01-Reconnaissance/External-Recon.md)
2. [`02-Enumeration/Network-Enumeration.md`](02-Enumeration/Network-Enumeration.md)
3. Follow service-specific enumeration guides

**Gray Box Assessment (Credentials Provided)**
1. [`02-Enumeration/Authenticated-Enumeration.md`](02-Enumeration/Authenticated-Enumeration.md)
2. [`06-Active-Directory/Initial-Enumeration.md`](06-Active-Directory/Initial-Enumeration.md)

**Post-Exploitation**
1. [`04-Post-Exploitation/Situational-Awareness.md`](04-Post-Exploitation/Situational-Awareness.md)
2. [`05-Privilege-Escalation/`](05-Privilege-Escalation/) (OS-specific)

### By Service/Protocol

- **Web Applications**: [`02-Enumeration/Web-Enumeration/`](02-Enumeration/Web-Enumeration/)
- **SMB/CIFS**: [`02-Enumeration/SMB-Enumeration.md`](02-Enumeration/SMB-Enumeration.md)
- **Active Directory**: [`06-Active-Directory/`](06-Active-Directory/)
- **Databases**: [`02-Enumeration/Database-Enumeration.md`](02-Enumeration/Database-Enumeration.md)

### By Tool

- **Nmap**: [`08-Tools-Reference/Nmap.md`](08-Tools-Reference/Nmap.md)
- **Metasploit**: [`08-Tools-Reference/Metasploit.md`](08-Tools-Reference/Metasploit.md)
- **Impacket**: [`08-Tools-Reference/Impacket.md`](08-Tools-Reference/Impacket.md)
- **Bloodhound**: [`08-Tools-Reference/Bloodhound.md`](08-Tools-Reference/Bloodhound.md)

## 🔥 Quick Start for Common Scenarios

### New Target - Full Enumeration
```bash
# 1. Set up environment
export IP=10.10.10.10
mkdir -p {nmap,scans,exploits,loot,notes}

# 2. Initial scan
sudo nmap -p- -sS --min-rate 5000 -oA nmap/allports $IP

# 3. Detailed scan
ports=$(grep open nmap/allports.nmap | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')
sudo nmap -sC -sV -p $ports -oA nmap/detailed $IP

# 4. Follow service-specific enumeration guides
```

### Web Application Found
1. [`02-Enumeration/Web-Enumeration/Web-Recon-Workflow.md`](02-Enumeration/Web-Enumeration/Web-Recon-Workflow.md)
2. Check for common vulnerabilities (SQLi, LFI, RCE)
3. Directory/VHost fuzzing

### Got Initial Shell
1. [`03-Initial-Access/Shell-Stabilization.md`](03-Initial-Access/Shell-Stabilization.md)
2. [`04-Post-Exploitation/Situational-Awareness.md`](04-Post-Exploitation/Situational-Awareness.md)
3. [`05-Privilege-Escalation/`](05-Privilege-Escalation/) (OS-specific)

### Active Directory Environment
1. [`06-Active-Directory/Enumeration-Workflow.md`](06-Active-Directory/Enumeration-Workflow.md)
2. [`06-Active-Directory/Attack-Paths.md`](06-Active-Directory/Attack-Paths.md)

## 📝 Study Recommendations

### Week 1-2: Foundation
- [ ] Master the core methodology workflow
- [ ] Practice Nmap enumeration on HTB machines
- [ ] Learn shell stabilization techniques
- [ ] Understand file transfer methods

### Week 3-4: Service Enumeration
- [ ] Deep dive into SMB, FTP, NFS enumeration
- [ ] Practice web enumeration workflows
- [ ] Learn database interaction techniques
- [ ] Master DNS enumeration

### Week 5-6: Exploitation
- [ ] Practice public exploit modification
- [ ] Master MSFvenom payload creation
- [ ] Learn web vulnerability exploitation
- [ ] Practice privilege escalation

### Week 7-8: Active Directory
- [ ] Master Bloodhound analysis
- [ ] Practice Kerberoasting and AS-REP roasting
- [ ] Learn lateral movement techniques
- [ ] Practice DCSync and credential dumping

### Week 9-10: Integration
- [ ] Complete full machine walkthroughs
- [ ] Practice pivoting and tunneling
- [ ] Time yourself on practice exams
- [ ] Review and fill knowledge gaps

## 🛠️ Essential Tools Setup

See [`08-Tools-Reference/Tool-Installation.md`](08-Tools-Reference/Tool-Installation.md) for complete setup guide.

**Core Tools:**
- Nmap, Masscan
- Gobuster, Ffuf, Feroxbuster
- Impacket suite
- Bloodhound + SharpHound
- Chisel, Ligolo-ng
- LinPEAS, WinPEAS

## 🎯 Exam Tips

1. **Time Management**: Spend max 2 hours on initial enumeration per target
2. **Documentation**: Screenshot everything, take detailed notes
3. **Methodology**: Don't skip steps, even if you think you found something
4. **Breaks**: Take regular breaks to maintain focus
5. **Backup Plans**: Always have alternative attack vectors identified

## 📚 Additional Resources

- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS](https://lolbas-project.github.io/)
- [WADComs](https://wadcoms.github.io/)

## 🔄 Updates and Maintenance

These notes are continuously improved based on:
- New techniques discovered
- Exam feedback and experiences
- Tool updates and new features
- Community contributions

---

**Last Updated**: 2026-02-05
**Version**: 2.0 - Methodology-Focused Edition
**Maintainer**: CPTS Exam Preparation

---

## 🚀 Getting Started

**Ready to begin?** Start with:
1. [`00-Methodology/Penetration-Testing-Workflow.md`](00-Methodology/Penetration-Testing-Workflow.md)
2. [`09-Quick-Reference/Environment-Setup.md`](09-Quick-Reference/Environment-Setup.md)
3. Pick a practice machine and follow the methodology!

**Good luck with your CPTS preparation! 🎯**
