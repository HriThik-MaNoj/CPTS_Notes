#!/usr/bin/env python3
"""
Restructure CPTS_Exam_Master_Methodology.md.

KEY FIX: renumber main_body FIRST, THEN inject with final target numbers.
This prevents double-shifting of injected section headers.
"""

import re
import shutil

SRC = "/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md.bak"  # read from backup
DST = "/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md"

# ──────────────────────────────────────────────────────────
# 1. Load the backup (original)
# ──────────────────────────────────────────────────────────
with open(SRC, "r") as f:
    raw = f.read()
print(f"Loaded {SRC} ({raw.count(chr(10))} lines)")

# ──────────────────────────────────────────────────────────
# 2. Helper: extract a section by unique header prefix
# ──────────────────────────────────────────────────────────
def get_sec(header_prefix):
    start = raw.find(header_prefix)
    if start == -1:
        raise ValueError(f"Not found: {repr(header_prefix)}")
    # Find next top-level ## section (not ###)
    nxt = re.search(r'\n(?=## (?!#))', raw[start+1:])
    end = start + 1 + nxt.start() if nxt else len(raw)
    return raw[start:end].strip()

sec19 = get_sec("## 19. Pentest Process Stages")
sec17 = get_sec("## 17. Web Information Gathering")
sec15 = get_sec("## 15. Burp Suite / ZAP Workflow")
sec14 = get_sec("## 14. Vulnerability Assessment Workflow")
sec13 = get_sec("## 13. Common Application Attacks")
sec16 = get_sec("## 16. Metasploit Framework Workflow")
sec23 = get_sec("## 23. Quick AD attack ordering")
sec22 = get_sec("## 22. File Transfer Code Library")
sec21 = get_sec("## 21. Web Shell Library")
sec20 = get_sec("## 20. Bind vs. Reverse Shell")
sec18 = get_sec("## 18. Documentation & Reporting")
sec24 = get_sec("## 24. Final Service-Port Quick Reference")
appA  = get_sec("## Appendix A")
appB  = get_sec("## Appendix B")
appC  = get_sec("## Appendix C")
appD  = get_sec("## Appendix D")
final = get_sec("## Final Pre-Submit Checklist")
print("Sections extracted.")

# ──────────────────────────────────────────────────────────
# 3. Carve out main body (§0 through §12, no §13+ and no Appendices)
# ──────────────────────────────────────────────────────────
app_start = raw.find("\n## Appendix A")
sec13_start = raw.find("\n## 13. Common Application Attacks")
main_end = min(x for x in [app_start, sec13_start] if x != -1)
main_body = raw[:main_end].rstrip()
print(f"Main body carved (chars 0–{main_end})")

# ──────────────────────────────────────────────────────────
# 4. Renumber ALL section/subsection headers in main_body FIRST
#    Old §1→§2, §2→§3, …, §12→§13
# ──────────────────────────────────────────────────────────

def renumber_headers(text):
    # ## N.  → ## (N+1).   for N in 1..12
    def h2(m):
        n = int(m.group(1))
        return f"## {n+1}." if 1 <= n <= 12 else m.group(0)
    text = re.sub(r'^## (\d+)\.', h2, text, flags=re.MULTILINE)

    # ### N.M  → ### (N+1).M   for N in 1..12
    def h3(m):
        n = int(m.group(1))
        return f"### {n+1}.{m.group(2)}" if 1 <= n <= 12 else m.group(0)
    text = re.sub(r'^### (\d+)\.(\d+)', h3, text, flags=re.MULTILINE)

    return text

main_body = renumber_headers(main_body)
print("Headers renumbered (§1-§12 → §2-§13).")

# ──────────────────────────────────────────────────────────
# 5. Update inline §X cross-references (single-pass via regex)
# ──────────────────────────────────────────────────────────
# Simple shifts: §1→§2 through §12→§13 (§N.M also shifts first component)
# Special: §18.7 → §11.7 (§18 absorbed into new §11 Reporting)

def replace_refs(text):
    def _sub(m):
        parts = tuple(int(x) for x in m.group(1).split('.'))
        n = parts[0]
        if n == 18 and len(parts) >= 2 and parts[1] == 7:
            rest = parts[2:] if len(parts) > 2 else ()
            new = (11, 7) + rest
            return '§' + '.'.join(str(x) for x in new)
        if 1 <= n <= 12:
            new = (n+1,) + parts[1:]
            return '§' + '.'.join(str(x) for x in new)
        return m.group(0)
    return re.sub(r'§(\d+(?:\.\d+)*)', _sub, text)

main_body = replace_refs(main_body)
print("Cross-references updated.")

# ──────────────────────────────────────────────────────────
# 6. Fix Track A-E references in §0.2 (use plain text not §-refs)
# ──────────────────────────────────────────────────────────
track_fixes = [
    ("Sections 1.2 SMB/LDAP/Kerberos → 6 → 7",
     "Sections 2.2 SMB/LDAP/Kerberos → 7 → 8"),
    ("Sections 1 → 2 → 3.1 → 4",
     "Sections 2 → 3 → 4.1 → 5"),
    ("Sections 1 → 3.2 → 5",
     "Sections 2 → 4.2 → 6"),
    ("Sections 1.3 → 2 → 3.1",
     "Sections 2.3 → 3 → 4.1"),
    ("External recon → web foothold → pivot (8) → AD (6)",
     "External recon → web foothold → pivot (9) → AD (7)"),
]
for old, new in track_fixes:
    main_body = main_body.replace(old, new)
print("Track references fixed.")

# ──────────────────────────────────────────────────────────
# 7. Prepare injected section content with FINAL target numbers
#    (These are injected AFTER renumbering so they won't be shifted)
# ──────────────────────────────────────────────────────────

# §19 → new §1 (top-level, goes between §0 and §2)
sec1_new = sec19.replace("## 19. Pentest Process Stages", "## 1. Pentest Process Stages")
sec1_new = re.sub(r'^### 19\.', '### 1.', sec1_new, flags=re.MULTILINE)

# §17 → ### 2.0 inside §2 Recon (before ### 2.1 Network Enum)
# Demote the top-level header, promote sub-headers
sec17_body = "### 2.0 Web OSINT / External Recon\n"
# Strip the old ## header line
sec17_content = re.sub(r'^## 17\. Web Information Gathering.*\n', '', sec17, flags=re.MULTILINE)
# Demote ### 17.X → #### 2.0.X
sec17_content = re.sub(r'^### 17\.(\d+)', lambda m: f"#### 2.0.{m.group(1)}", sec17_content, flags=re.MULTILINE)
sec17_body += sec17_content

# §15 → ### 2.4 inside §2.3 Web App Enum
sec15_body = "### 2.4 Burp Suite / ZAP (Proxy Workflow)\n"
sec15_content = re.sub(r'^## 15\. Burp Suite.*\n', '', sec15, flags=re.MULTILINE)
sec15_content = re.sub(r'^### 15\.(\d+)', lambda m: f"#### 2.4.{m.group(1)}", sec15_content, flags=re.MULTILINE)
sec15_body += sec15_content

# §14 → ### 3.5 inside §3 Vuln ID
sec14_body = "### 3.5 Vulnerability Assessment Workflow\n"
sec14_content = re.sub(r'^## 14\. Vulnerability.*\n', '', sec14, flags=re.MULTILINE)
sec14_content = re.sub(r'^### 14\.(\d+)', lambda m: f"#### 3.5.{m.group(1)}", sec14_content, flags=re.MULTILINE)
sec14_body += sec14_content

# §13 → #### 4.1.A inside §4.1 Web App Attacks (detailed CMS trees)
sec13_body = "#### 4.1.A Application-Specific Attack Trees\n"
sec13_content = re.sub(r'^## 13\. Common Application.*\n', '', sec13, flags=re.MULTILINE)
sec13_content = re.sub(r'^### 13\.(\d+)', lambda m: f"##### 13.{m.group(1)}", sec13_content, flags=re.MULTILINE)
sec13_body += sec13_content

# §16 → ### 4.4 inside §4 Exploitation
sec16_body = "### 4.4 Metasploit Framework\n"
sec16_content = re.sub(r'^## 16\. Metasploit.*\n', '', sec16, flags=re.MULTILINE)
sec16_content = re.sub(r'^### 16\.(\d+)', lambda m: f"#### 4.4.{m.group(1)}", sec16_content, flags=re.MULTILINE)
sec16_body += sec16_content

# §23 → appended to §7.2 AD Attack Decision Tree (before ### 7.3)
sec23_body = "#### 7.2.1 Quick AD Attack Ordering Cheat-Sheet\n"
sec23_content = re.sub(r'^## 23\. Quick AD.*\n', '', sec23, flags=re.MULTILINE)
sec23_body += sec23_content

# §21 → #### 10.6.1 inside ### 10.6 Web Shells (before ### 10.7)
sec21_body = "#### 10.6.1 Extended Web Shell Library\n"
sec21_content = re.sub(r'^## 21\. Web Shell.*\n', '', sec21, flags=re.MULTILINE)
sec21_body += sec21_content

# §20 → #### 10.7.1 inside ### 10.7 Reverse-Shell Payloads (before ### 10.8)
sec20_body = "#### 10.7.1 Bind vs. Reverse Shell Decision\n"
sec20_content = re.sub(r'^## 20\. Bind.*\n', '', sec20, flags=re.MULTILINE)
sec20_body += sec20_content

# §22 → ### 10.9 after ### 10.8 Persistence (before ## 11.)
sec22_body = "### 10.9 Extended File Transfer Code Library\n"
sec22_content = re.sub(r'^## 22\. File Transfer.*\n', '', sec22, flags=re.MULTILINE)
sec22_content = re.sub(r'^### 22\.(\d+)', lambda m: f"#### 10.9.{m.group(1)}", sec22_content, flags=re.MULTILINE)
sec22_body += sec22_content

# §18 → ### 11.5 inside §11 Reporting (after ### 11.4)
sec18_body = "### 11.5 Documentation & Reporting (Full Structure)\n"
sec18_content = re.sub(r'^## 18\. Documentation.*\n', '', sec18, flags=re.MULTILINE)
sec18_content = re.sub(r'^### 18\.(\d+)', lambda m: f"#### 11.5.{m.group(1)}", sec18_content, flags=re.MULTILINE)
# Fix nested ## header in the finding template
sec18_content = sec18_content.replace("## [F-001]", "##### [F-001]")
sec18_body += sec18_content

# §24 → Appendix E
sec24_body = sec24.replace("## 24. Final Service-Port Quick Reference",
                           "## Appendix E — Service-Port Quick Reference")

print("Injection content prepared with final target numbers.")

# ──────────────────────────────────────────────────────────
# 8. Inject content into main_body
#    The markers now use RENUMBERED text (§2 for old §1, etc.)
# ──────────────────────────────────────────────────────────

# 8a. §17 → before ### 2.1 Network Enumeration
if "### 2.1 Network Enumeration" not in main_body:
    raise RuntimeError("Marker '### 2.1 Network Enumeration' not found after renumbering!")
main_body = main_body.replace(
    "\n### 2.1 Network Enumeration",
    "\n\n" + sec17_body + "\n\n### 2.1 Network Enumeration"
)
print("  Injected §17 (Web OSINT) before §2.1")

# 8b. §15 → append to §2.3, before ## 3. Vulnerability
main_body = main_body.replace(
    "\n---\n\n## 3. Vulnerability Identification",
    "\n\n" + sec15_body + "\n\n---\n\n## 3. Vulnerability Identification"
)
print("  Injected §15 (Burp/ZAP) before §3")

# 8c. §14 → append to §3, before ## 4. Initial Access
main_body = main_body.replace(
    "\n---\n\n## 4. Initial Access / Exploitation",
    "\n\n" + sec14_body + "\n\n---\n\n## 4. Initial Access / Exploitation"
)
print("  Injected §14 (Vuln Assessment) before §4")

# 8d. §13 CMS trees → inside §4.1, before ### 4.2 Service Exploitation
main_body = main_body.replace(
    "\n### 4.2 Service Exploitation",
    "\n\n" + sec13_body + "\n\n### 4.2 Service Exploitation"
)
print("  Injected §13 (App Attacks) before §4.2")

# 8e. §16 Metasploit → before ## 5. Post-Exploitation Linux
main_body = main_body.replace(
    "\n---\n\n## 5. Post-Exploitation — Linux",
    "\n\n" + sec16_body + "\n\n---\n\n## 5. Post-Exploitation — Linux"
)
print("  Injected §16 (Metasploit) before §5")

# 8f. §23 → inside §7.2 before ### 7.3 Specific AD Attack Flows
main_body = main_body.replace(
    "\n### 7.3 Specific AD Attack Flows",
    "\n\n" + sec23_body + "\n\n### 7.3 Specific AD Attack Flows"
)
print("  Injected §23 (AD Cheat-Sheet) before §7.3")

# 8g. §21 → inside §10.6 before ### 10.7 Reverse-shell
main_body = main_body.replace(
    "\n### 10.7 Reverse-shell payload templates",
    "\n\n" + sec21_body + "\n\n### 10.7 Reverse-shell payload templates"
)
print("  Injected §21 (Web Shell Library) into §10.6")

# 8h. §20 → inside §10.7 before ### 10.8 Persistence
main_body = main_body.replace(
    "\n### 10.8 Persistence",
    "\n\n" + sec20_body + "\n\n### 10.8 Persistence"
)
print("  Injected §20 (Bind/Reverse) into §10.7")

# 8i. §22 → after §10.8, before ## 11. Reporting
main_body = main_body.replace(
    "\n---\n\n## 11. Reporting Mindset",
    "\n\n" + sec22_body + "\n\n---\n\n## 11. Reporting Mindset"
)
print("  Injected §22 (File Transfer Library) before §11")

# 8j. §18 → inside §11, before ## 12. Stuck
main_body = main_body.replace(
    "\n---\n\n## 12. When You're Stuck",
    "\n\n" + sec18_body + "\n\n---\n\n## 12. When You're Stuck"
)
print("  Injected §18 (Documentation) before §12")

# ──────────────────────────────────────────────────────────
# 9. Insert §1 (from §19) between §0 and §2
# ──────────────────────────────────────────────────────────
marker = "\n## 2. Reconnaissance"
pos = main_body.find(marker)
if pos == -1:
    raise RuntimeError("'## 2. Reconnaissance' not found!")

before_recon = main_body[:pos].rstrip()
recon_onward = main_body[pos:]

doc_body = (
    before_recon
    + "\n\n---\n\n"
    + sec1_new
    + "\n\n---\n\n"
    + recon_onward.lstrip()
)
print("§1 (Pentest Process Stages) inserted between §0 and §2.")

# ──────────────────────────────────────────────────────────
# 10. Assemble final document
# ──────────────────────────────────────────────────────────
final_doc = (
    doc_body.rstrip()
    + "\n\n---\n\n"
    + sec24_body
    + "\n\n---\n\n"
    + appA
    + "\n\n---\n\n"
    + appB
    + "\n\n---\n\n"
    + appC
    + "\n\n---\n\n"
    + appD
    + "\n\n---\n\n"
    + final
    + "\n"
)

# ──────────────────────────────────────────────────────────
# 11. Write
# ──────────────────────────────────────────────────────────
with open(DST, "w") as f:
    f.write(final_doc)

lines = final_doc.count('\n')
print(f"\nWritten to {DST} ({lines} lines).")
print("Done. Run: grep -n '^## ' <file>")
