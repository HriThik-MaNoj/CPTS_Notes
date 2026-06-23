# CPTS Penetration Test Report Template

> Copy this template for your exam report. Replace all `[BRACKETED]` text with your content. Delete sections that don't apply. The report is 50% of your grade — be thorough, professional, and clear.

---

# [Client Name] Penetration Test Report

**Prepared by:** [Your Name]
**Date:** [Date]
**Classification:** Confidential

---

## 1. Executive Summary

[1-2 pages. Non-technical audience. Business risk language.]

[Client Name] engaged [Your Name/Company] to conduct a penetration test of their network infrastructure. The assessment was performed between [start date] and [end date] and covered [X] in-scope systems.

### Key Findings Summary

| Severity | Count |
|----------|-------|
| Critical | [N] |
| High | [N] |
| Medium | [N] |
| Low | [N] |
| **Total** | **[N]** |

### Highest-Impact Findings

1. **[Finding 1 title]** — [1-2 sentence business impact]
2. **[Finding 2 title]** — [1-2 sentence business impact]
3. **[Finding 3 title]** — [1-2 sentence business impact]

### Strategic Recommendations

1. [Recommendation 1]
2. [Recommendation 2]
3. [Recommendation 3]

---

## 2. Scope & Testing Overview

### In-Scope Assets

| IP Address | Hostname | OS | Services |
|------------|----------|----|----------|
| [IP] | [hostname] | [OS] | [ports/services] |

### Out-of-Scope Assets

- [List any exclusions]

### Testing Window

- **Start:** [Date/Time]
- **End:** [Date/Time]

### Methodology

Testing was conducted following the PTES (Penetration Testing Execution Standard) and OWASP testing methodologies. The assessment included network enumeration, web application testing, Active Directory assessment, and post-exploitation analysis.

### Limitations

- [Any limitations encountered during testing]

---

## 3. Attack Chain Narrative

[A detailed walkthrough of the full exploitation path from initial access to domain compromise. Write this as a story with supporting command output and screenshots.]

### Step 1: Initial Reconnaissance

[Description of initial scanning and enumeration]

```
[Command output showing discovery]
```

![Screenshot: Initial scan results](screenshots/01-initial-scan.png)

### Step 2: [Attack Step Name]

[Description of what was found and how it was exploited]

```
[Command output]
```

![Screenshot: Exploitation](screenshots/02-exploitation.png)

### Step 3: Privilege Escalation

[Description of privesc technique used]

```
[Command output showing before/after privilege]
```

![Screenshot: Privilege escalation proof](screenshots/03-privesc.png)

### Step 4: Lateral Movement

[Description of lateral movement to additional hosts]

```
[Command output]
```

![Screenshot: Lateral movement](screenshots/04-lateral.png)

### Step 5: Domain Compromise

[Description of DA achievement]

```
[Command output proving DA]
```

![Screenshot: Domain Admin proof](screenshots/05-da-proof.png)

### Step 6: Full Domain Control (DCSync)

[Description of DCSync and full hash dump]

```
[Command output]
```

![Screenshot: DCSync output](screenshots/06-dcsync.png)

---

## 4. Findings Detail

### Finding 1: [Finding Title]

**Severity:** [Critical/High/Medium/Low]
**CVSS 3.1 Score:** [X.X] ([Vector String])
**CWE:** [CWE-XXX: Name]
**Affected Asset(s):** [IP/hostname/URL]

#### Description

[Technical explanation of the vulnerability. What is it? Why does it exist?]

#### Impact

[What an attacker can do with this. Business + technical impact.]

#### Evidence

```
[Command output proving the vulnerability]
```

![Screenshot: Vulnerability evidence](screenshots/finding-01.png)

#### Reproduction Steps

1. [Step 1 — exact command or action]
2. [Step 2]
3. [Step 3]

#### Remediation

[Specific, actionable fix. Not "patch the software" — give exact steps.]

#### References

- [CVE number if applicable]
- [Vendor advisory URL]
- [OWASP reference]

---

### Finding 2: [Finding Title]

[Repeat the finding template above for each finding]

---

## 5. Additional Findings

### [Lower-severity findings can be grouped here]

| # | Finding | Severity | Host | Status |
|---|---------|----------|------|--------|
| 1 | [Finding] | [Sev] | [Host] | [Open] |
| 2 | [Finding] | [Sev] | [Host] | [Open] |

---

## 6. Appendices

### Appendix A: Host Inventory

| IP | Hostname | OS | Open Ports | Access Level | Method |
|----|----------|----|------------|--------------|--------|
| [IP] | [name] | [OS] | [ports] | [user/SYSTEM/DA] | [how] |

### Appendix B: Credential Inventory

| Username | Type | Source | Where Reused |
|----------|------|--------|--------------|
| [user] | [password/hash] | [where found] | [where tested] |

> **Note:** All credentials in this report are redacted with `<REDACTED>`.

### Appendix C: Exploitation Timeline

| Timestamp | Action | Result |
|-----------|--------|--------|
| [time] | [command/action] | [outcome] |

### Appendix D: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| nmap | [version] | Network scanning |
| netexec | [version] | AD enumeration |
| impacket | [version] | AD exploitation |
| BloodHound | [version] | AD path analysis |
| hashcat | [version] | Hash cracking |
| [other] | [version] | [purpose] |

### Appendix E: Raw Scan Data

[Reference to attached scan files — nmap XML, BloodHound JSON, etc.]

---

## Report Quality Checklist

- [ ] Executive summary is non-technical and business-focused
- [ ] Attack chain tells a complete story from start to DA
- [ ] Every finding has: description, impact, evidence, reproduction, remediation
- [ ] All screenshots show command AND output in one frame
- [ ] All credentials redacted with black bars (not blur)
- [ ] CVSS scores are accurate
- [ ] Reproduction steps are runnable by the client
- [ ] No placeholder text remains
- [ ] Spelling and grammar checked
- [ ] All compromised hosts documented
- [ ] Remediation is specific and actionable
