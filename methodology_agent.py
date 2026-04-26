#!/usr/bin/env python3
"""
CPTS Methodology Multi-Agent Improvement Pipeline

Architecture:
  Phase 1: 5 Reader agents (parallel)  — analyze 28 modules vs current methodology
  Phase 2: 3 Improver agents (parallel) — rewrite phases using gap feedback
  Phase 3: 1 Auditor agent             — validate structure, enforce recursion, finalize

Usage:
  export ANTHROPIC_API_KEY="sk-ant-..."
  python3 methodology_agent.py

Output:
  agent_workspace/   — intermediate results from each agent
  CPTS_Improved_Methodology.md — final audited methodology
"""

import asyncio
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime
import anthropic

# ── Configuration ───────────────────────────────────────────────────────────────
MODULES_DIR      = Path("/home/hri7hik/CPTS_Notes/academy_og")
METHODOLOGY_FILE = Path("/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md")
WORKSPACE        = Path("/home/hri7hik/CPTS_Notes/agent_workspace")
OUTPUT_FILE      = Path("/home/hri7hik/CPTS_Notes/CPTS_Improved_Methodology.md")

READER_MODEL   = "claude-sonnet-4-6"
IMPROVER_MODEL = "claude-sonnet-4-6"
AUDITOR_MODEL  = "claude-sonnet-4-6"  # swap to "claude-opus-4-7" for best reasoning

MAX_CHARS_PER_MODULE = 70_000   # smart-extract cap per module (~17K tokens)
MAX_CHARS_PER_AGENT  = 220_000  # total module budget per reader agent (~55K tokens)

# ── Module Groups for 5 Reader Agents ──────────────────────────────────────────
MODULE_GROUPS = [
    {
        "id": "reader_1",
        "name": "Reader-1 [Recon & Process]",
        "focus": "overall pentest lifecycle, network scanning methodology, vulnerability assessment, and documentation",
        "modules": [
            "Penetration Testing Process.md",
            "Getting Started.md",
            "Network Enumeration with Nmap.md",
            "Vulnerability Assessment.md",
            "Documentation & Reporting.md",
        ],
    },
    {
        "id": "reader_2",
        "name": "Reader-2 [Footprinting & Web Intel]",
        "focus": "external footprinting, OSINT, web information gathering, directory fuzzing, and proxy-based enumeration",
        "modules": [
            "Footprinting.md",
            "Information Gathering - Web Edition.md",
            "Attacking Web Applications with Ffuf.md",
            "Using Web Proxies.md",
        ],
    },
    {
        "id": "reader_3",
        "name": "Reader-3 [Web Exploitation]",
        "focus": "web attack techniques: command injection, XSS, LFI/RFI, file uploads, SQL injection, web-specific attacks",
        "modules": [
            "Command Injections.md",
            "Cross-Site Scripting (XSS).md",
            "File Inclusion.md",
            "File Upload Attacks.md",
            "SQL Injection Fundamentals.md",
            "SQLMap Essentials.md",
            "Web Attacks.md",
        ],
    },
    {
        "id": "reader_4",
        "name": "Reader-4 [Exploitation & Credentials]",
        "focus": "shells and payloads, file transfers, brute forcing, password attacks, Metasploit, and common service attacks",
        "modules": [
            "Shells & Payloads.md",
            "File Transfers.md",
            "Login Brute Forcing.md",
            "Password Attacks.md",
            "Using the Metasploit Framework.md",
            "Attacking Common Services.md",
        ],
    },
    {
        "id": "reader_5",
        "name": "Reader-5 [Post-Exploitation & AD]",
        "focus": "Linux/Windows privilege escalation, Active Directory enumeration and attacks, pivoting, and enterprise network attacks",
        "modules": [
            "Linux Privilege Escalation.md",
            "Windows Privilege Escalation.md",
            "Pivoting, Tunneling, and Port Forwarding.md",
            "Active Directory Enumeration & Attacks.md",
            "Attacking Common Applications.md",
            "Attacking Enterprise Networks.md",
        ],
    },
]

# ── Phase Assignments for 3 Improver Agents ─────────────────────────────────────
IMPROVER_ASSIGNMENTS = [
    {
        "id": "improver_a",
        "name": "Improver-A [Pre-Engagement, Recon, Enumeration, Vuln Assessment]",
        "section_prefixes": ["## 0.", "## 1.", "## 2.", "## 14.", "## 17."],
        "phase_names": [
            "Pre-Engagement Checklist",
            "Reconnaissance & Enumeration",
            "Vulnerability Identification",
            "Vulnerability Assessment Workflow",
            "Web Information Gathering",
        ],
    },
    {
        "id": "improver_b",
        "name": "Improver-B [Exploitation, Web Attacks, Application Attacks]",
        "section_prefixes": [
            "## 3.", "## 13.", "## 15.", "## 16.",
            "## 20.", "## 21.", "## 22.", "## 24.",
            "## Appendix A", "## Appendix B",
        ],
        "phase_names": [
            "Initial Access / Exploitation",
            "Common Application Attacks",
            "Burp Suite / ZAP Workflow",
            "Metasploit Framework Workflow",
            "Bind vs Reverse Shell Decision",
            "Web Shell Library",
            "File Transfer Code Library",
            "Final Service-Port Quick Reference",
            "Appendix A (Default Credentials)",
            "Appendix B (One-liner Triage)",
        ],
    },
    {
        "id": "improver_c",
        "name": "Improver-C [Post-Exploitation, AD, Pivoting, Reporting]",
        "section_prefixes": [
            "## 4.", "## 5.", "## 6.", "## 7.", "## 8.", "## 9.",
            "## 10.", "## 11.", "## 12.", "## 18.", "## 19.",
            "## 23.", "## Appendix C", "## Appendix D", "## Final",
        ],
        "phase_names": [
            "Post-Exploitation Linux",
            "Post-Exploitation Windows",
            "Active Directory",
            "Lateral Movement",
            "Pivoting & Tunneling",
            "File Transfers & Persistence",
            "Reporting Mindset",
            "When Stuck Checklist",
            "Tool Quick Reference",
            "Documentation & Reporting",
            "Pentest Process Stages",
            "Quick AD Attack Ordering",
            "Appendix C (Kerberos)",
            "Appendix D (Hash Formats)",
            "Final Pre-Submit Checklist",
        ],
    },
]


# ── Helper: Smart Module Extraction ────────────────────────────────────────────
def smart_extract(content: str, max_chars: int = MAX_CHARS_PER_MODULE) -> str:
    """
    Extract the most valuable content from a large module.
    Keeps: all headers, all code blocks, all bullet points, first line after headers.
    Drops: dense prose paragraphs (retains structure + commands).
    """
    if len(content) <= max_chars:
        return content

    lines = content.split('\n')
    result = []
    in_code_block = False
    after_header = False
    chars_used = 0

    for line in lines:
        if chars_used >= max_chars:
            result.append(
                f"\n\n... [TRUNCATED — {len(content):,} chars total, "
                f"{max_chars:,} chars shown. Remaining content omitted.]"
            )
            break

        stripped = line.strip()

        if line.startswith('```'):
            in_code_block = not in_code_block
            result.append(line)
            chars_used += len(line) + 1
            continue

        if in_code_block:
            result.append(line)
            chars_used += len(line) + 1
            continue

        if line.startswith('#'):
            result.append(line)
            chars_used += len(line) + 1
            after_header = True
            continue

        if after_header and stripped:
            result.append(line)
            chars_used += len(line) + 1
            after_header = False
            continue

        if stripped.startswith(('-', '*', '+', '|')) or re.match(r'^\d+\.', stripped):
            result.append(line)
            chars_used += len(line) + 1
            after_header = False
            continue

        if stripped.startswith('>'):
            result.append(line)
            chars_used += len(line) + 1
            continue

        after_header = False

    return '\n'.join(result)


# ── Helper: Extract Methodology Sections ───────────────────────────────────────
def extract_sections(methodology: str, section_prefixes: list[str]) -> str:
    """Extract specific sections from the methodology by their header prefixes."""
    sections_text = []
    lines = methodology.split('\n')
    in_target = False
    current_section = []

    for line in lines:
        is_target_header = any(line.startswith(p) for p in section_prefixes)
        is_any_top_header = line.startswith('## ')

        if is_target_header:
            if current_section:
                sections_text.append('\n'.join(current_section))
            current_section = [line]
            in_target = True
        elif is_any_top_header and in_target and not is_target_header:
            if current_section:
                sections_text.append('\n'.join(current_section))
            current_section = []
            in_target = False
        elif in_target:
            current_section.append(line)

    if current_section:
        sections_text.append('\n'.join(current_section))

    return '\n\n'.join(sections_text)


# ── Prompt Builders ─────────────────────────────────────────────────────────────

READER_SYSTEM = """\
You are a Senior Penetration Testing Curriculum Analyst specializing in the CPTS \
(Certified Penetration Testing Specialist) exam. You have completed all 28 HTB Academy \
CPTS path modules and passed the exam. You review module content to find actionable gaps \
in an exam methodology playbook.

Your analysis principles:
- A gap is only worth reporting if a CPTS candidate would be STUCK without it during the exam
- HIGH priority: techniques completely missing that are exam-critical
- MEDIUM priority: commands that are wrong/outdated, or important decision trees missing
- LOW priority: nice-to-have additions, minor completeness improvements
- You always output valid JSON with no prose before or after
"""

def reader_user_prompt(agent: dict, module_contents: str, methodology: str) -> str:
    module_list = "\n".join(f"  - {m}" for m in agent["modules"])
    return f"""\
## Your Identity
{agent["name"]}
Focus area: {agent["focus"]}

## Modules Assigned to You
{module_list}

---
## MODULE CONTENT (extracted from your assigned modules)
{module_contents}

---
## CURRENT CPTS EXAM METHODOLOGY (find gaps in this)
{methodology}

---
## YOUR TASK
Find every gap between what the modules teach and what the methodology covers.
Think like this: "A CPTS candidate reads this module and learns technique X — but the \
methodology doesn't mention X, so during a live 10-day exam they'd be stuck."

Output a JSON array. Output ONLY the JSON — no prose before or after.

```json
[
  {{
    "phase": "pre-engagement|recon|enumeration|scanning|exploitation|post-exploitation|lateral-movement|ad|pivoting|reporting",
    "gap_type": "missing_technique|missing_tool|missing_command|missing_decision_tree|missing_recursive_loop|missing_checklist|incorrect_command|underrepresented_phase",
    "priority": "HIGH|MEDIUM|LOW",
    "title": "Short descriptive title (max 70 chars)",
    "description": "What is missing and why it matters for the exam (2-4 sentences)",
    "module_source": "Exact module filename",
    "suggested_content": "Exact markdown to add — include commands, decision trees, loop markers"
  }}
]
```

Aim for 30-60 gap entries. Be thorough. Especially look for:
1. Entire attack categories from a module that have NO presence in the methodology
2. Missing recursive loop triggers: "new creds found → re-enumerate all services with them"
3. Missing IF/ELSE decision branches for common port/service scenarios
4. Commands from the module that are absent or wrong in the methodology
5. Places where the methodology says "enumerate" but doesn't say HOW
"""


IMPROVER_SYSTEM = """\
You are a Master Penetration Testing Methodology Author. You write clear, decisive, \
exam-ready penetration testing playbooks used by candidates in live 10-day exams.

Your methodology style rules:
- SEQUENTIAL: phases always flow recon → enumeration → exploitation → post-exploitation → reporting
- RECURSIVE: every foothold/credential/new-host discovery has an explicit LOOP BACK marker
- DECISION-TREE: every section uses IF/ELSE/THEN branching so candidates never get stuck
- COMMAND-COMPLETE: every technique has at least one copy-paste ready command
- EXAM-FOCUSED: written for someone under pressure with no time to think — be direct
"""

def improver_user_prompt(improver: dict, current_sections: str, all_feedback: str) -> str:
    phase_list = "\n".join(f"  - {p}" for p in improver["phase_names"])
    return f"""\
## Your Assignment
{improver["name"]}

You are rewriting these methodology phases:
{phase_list}

---
## CURRENT METHODOLOGY SECTIONS (your starting content — improve this)
{current_sections}

---
## GAP ANALYSIS FROM ALL 5 READER AGENTS (incorporate ALL relevant gaps)
{all_feedback}

---
## MANDATORY STRUCTURAL REQUIREMENTS

### 1. Recursive Loop Markers — use this EXACT format:
```
> 🔄 **LOOP**: [trigger condition]
> → Return to [Section Name] with: [what you now have]
```

Required loops you MUST include in appropriate sections:
- New credentials discovered → return to enumeration (SMB, SSH, RDP, WinRM, etc.) with new creds
- New internal host/IP found → return to Section 1 recon for that host
- Linux PrivEsc success → return to post-exploitation enum as root
- Windows PrivEsc success → return to post-exploitation enum as SYSTEM
- Domain user creds obtained → return to AD enumeration section
- Domain Admin obtained → dump all hashes, enumerate trust relationships, loop AD
- Pivot/tunnel established → return to recon + enumeration on new network segment from scratch
- Web shell / RCE obtained → establish persistence, then enumerate as www-data/SYSTEM

### 2. Decision Tree Format — use for service branching:
```
PORT/SERVICE DECISION:
├── 21 FTP    → [specific action]
├── 22 SSH    → [specific action]
├── 80/443    → [specific action]
├── 445 SMB   → [specific action]
└── 3389 RDP  → [specific action]
```

### 3. Section Template — every subsection must have:
```
### N.X Title

**Trigger**: [what condition activates this subsection]

[Decision tree or IF/ELSE branches]

[Copy-paste commands]

> 🔄 **LOOP**: [condition] → Return to [section] with [context]

**→ Next**: [where to go when done]
```

### 4. Phase Sequence Rule
Your sections must internally follow: recon → enumeration → exploitation → post-exploitation.
Never suggest jumping to exploitation before enumeration is complete.

---
## OUTPUT INSTRUCTIONS
- Output ONLY the improved markdown for your assigned sections
- Keep ALL existing good content; ADD the improvements from gap analysis
- Start directly with the first section header (e.g. `## 0. Pre-Engagement...`)
- No preamble, no explanation — just clean exam-ready markdown
- This output is inserted directly into the final methodology document
"""


AUDITOR_SYSTEM = """\
You are the Chief Methodology Auditor for the CPTS exam preparation system. You perform \
the final structural validation of penetration testing methodologies before candidates \
use them in live exams. You are precise, rigorous, and do not accept structural gaps.

Your audit philosophy:
- A methodology with missing recursive loops fails candidates at the pivot/privesc stage
- A methodology without decision trees causes "what do I do now?" paralysis under pressure
- Phase ordering errors teach bad habits and cause missed findings
- You always produce a corrected, complete output — not just a list of problems
"""

def auditor_user_prompt(assembled: str) -> str:
    return f"""\
## ASSEMBLED METHODOLOGY FOR FINAL AUDIT
{assembled}

---
## AUDIT CRITERIA

### A. Phase Sequence Compliance (10 pts)
Verify this EXACT order is present and complete:
A1. Pre-Engagement / Setup
A2. External Reconnaissance (OSINT + passive)
A3. Active Enumeration (port scan → service enum)
A4. Vulnerability Identification
A5. Initial Access / Exploitation
A6. Post-Exploitation local enumeration
A7. Privilege Escalation (Linux AND Windows paths)
A8. Lateral Movement / Credential Reuse
A9. Active Directory Attacks
A10. Pivoting & Tunneling
A11. Reporting & Documentation

### B. Recursive Loop Coverage (10 pts)
Every one of these MUST exist as an explicit marked loop:
B1. New credentials found → re-enumerate ALL services
B2. New host discovered → return to A2 recon for that host
B3. Linux root obtained → re-enumerate as root
B4. Windows SYSTEM obtained → re-enumerate as SYSTEM
B5. Domain user obtained → full AD enum loop
B6. Domain Admin obtained → hash dump + trust relationship enum
B7. Pivot established → full recon + enum on new segment
B8. Web shell / RCE → persistence + enum as web user
B9. Hash cracked → spray across all discovered services
B10. New vhost/subdomain → full web enumeration loop

### C. Decision Tree Coverage (10 pts)
Must have explicit IF/ELSE trees for:
C1. Nmap result → service-specific attack path selection
C2. HTTP status codes → enumeration decisions
C3. SMB access level → attack path (anonymous / guest / creds)
C4. Domain vs workgroup → attack path split
C5. Linux vs Windows → post-exploitation path split
C6. Service version → CVE/exploit check trigger
C7. Hash type → cracking vs relay decision
C8. Credentials found → spray vs targeted vs relay decision
C9. No results → fallback path selection
C10. Port 443 vs 80 vs 8080/8443/other → enumeration approach

### D. Command Completeness (10 pts)
Verify complete commands exist for:
D1. Full nmap scan sequence (fast → targeted → UDP)
D2. SMB enumeration (enum4linux-ng, nxc, smbmap, smbclient)
D3. Web fuzzing (ffuf/feroxbuster with wordlists)
D4. Password spraying (nxc/kerbrute)
D5. Kerberoasting (impacket-GetUserSPNs or Rubeus)
D6. AS-REP roasting (impacket-GetNPUsers or Rubeus)
D7. Pass-the-Hash (nxc/evil-winrm/impacket)
D8. Linux privesc enum (linpeas + manual checks)
D9. Windows privesc enum (winpeas + manual checks)
D10. Chisel/ligolo-ng tunnel setup

---
## YOUR OUTPUT — three sections in this exact order:

### SECTION 1: AUDIT FINDINGS
List every issue found using this format:
```
[CRITERION-ID] SEVERITY(HIGH/MEDIUM/LOW): Brief description
Location: approximate section in methodology
Fix: what to add/change
```

### SECTION 2: CORRECTED FINAL METHODOLOGY
Output the COMPLETE corrected methodology with every issue fixed.
This is what the candidate uses in their exam. Make it perfect.
Maintain all original markdown structure and add improvements inline.
Start with: `# CPTS Exam — Final Methodology`

### SECTION 3: AUDIT SCORECARD
```
A. Phase Sequence:    X/10 — brief note
B. Recursive Loops:   X/10 — brief note
C. Decision Trees:    X/10 — brief note
D. Command Complete:  X/10 — brief note
─────────────────────────────
Overall:             XX/40
Exam Readiness:      READY | NEEDS_REVIEW | NOT_READY
```
"""


# ── Core Agent Runner ───────────────────────────────────────────────────────────
async def run_agent(
    client: anthropic.AsyncAnthropic,
    agent_id: str,
    model: str,
    system: str,
    user: str,
    log_prefix: str,
) -> str:
    print(f"  [{log_prefix}] Starting... ({len(user):,} chars in prompt)")

    message = await client.messages.create(
        model=model,
        max_tokens=8192,
        system=system,
        messages=[{"role": "user", "content": user}],
    )

    response = message.content[0].text
    print(f"  [{log_prefix}] Done — {len(response):,} chars output "
          f"(in:{message.usage.input_tokens} out:{message.usage.output_tokens} tokens)")

    save_path = WORKSPACE / f"{agent_id}_output.txt"
    save_path.write_text(response, encoding="utf-8")
    return response


# ── Phase 1: Readers ────────────────────────────────────────────────────────────
async def run_reader(
    client: anthropic.AsyncAnthropic,
    agent: dict,
    methodology: str,
) -> list[dict]:
    module_parts = []
    total_chars = 0
    # Reserve space for the methodology itself so module budget is accurate
    module_budget = MAX_CHARS_PER_AGENT - len(methodology)

    for module_name in agent["modules"]:
        module_path = MODULES_DIR / module_name
        if not module_path.exists():
            print(f"  [WARN] Module not found: {module_name}")
            continue

        raw = module_path.read_text(encoding="utf-8", errors="ignore")
        extracted = smart_extract(raw, max_chars=MAX_CHARS_PER_MODULE)

        remaining_budget = module_budget - total_chars
        if remaining_budget <= 0:
            print(f"  [{agent['id']}] Budget exhausted, skipping: {module_name}")
            continue

        if len(extracted) > remaining_budget:
            extracted = extracted[:remaining_budget] + "\n\n... [agent budget exhausted]"

        module_parts.append(f"### MODULE: {module_name}\n\n{extracted}")
        total_chars += len(extracted)

    module_contents = "\n\n{'='*80}\n\n".join(module_parts)
    prompt = reader_user_prompt(agent, module_contents, methodology)
    raw_output = await run_agent(
        client, agent["id"], READER_MODEL,
        READER_SYSTEM, prompt, agent["name"],
    )

    try:
        json_match = re.search(r'\[\s*\{.*\}\s*\]', raw_output, re.DOTALL)
        if json_match:
            gaps = json.loads(json_match.group())
        else:
            gaps = json.loads(raw_output.strip())
        print(f"  [{agent['id']}] Parsed {len(gaps)} gaps from feedback")
        return gaps
    except json.JSONDecodeError as e:
        print(f"  [{agent['id']}] JSON parse error: {e} — saving raw output")
        return [{"raw_output": raw_output, "parse_error": str(e)}]


# ── Phase 2: Improvers ──────────────────────────────────────────────────────────
async def run_improver(
    client: anthropic.AsyncAnthropic,
    improver: dict,
    methodology: str,
    all_feedback: str,
) -> str:
    current_sections = extract_sections(methodology, improver["section_prefixes"])
    if not current_sections.strip():
        current_sections = f"[No existing sections found for prefixes: {improver['section_prefixes']}]"

    prompt = improver_user_prompt(improver, current_sections, all_feedback)
    return await run_agent(
        client, improver["id"], IMPROVER_MODEL,
        IMPROVER_SYSTEM, prompt, improver["name"],
    )


# ── Phase 3: Auditor ────────────────────────────────────────────────────────────
async def run_auditor(
    client: anthropic.AsyncAnthropic,
    assembled_methodology: str,
) -> str:
    prompt = auditor_user_prompt(assembled_methodology)
    return await run_agent(
        client, "auditor", AUDITOR_MODEL,
        AUDITOR_SYSTEM, prompt, "Auditor",
    )


# ── Pipeline Orchestrator ───────────────────────────────────────────────────────
async def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: Set ANTHROPIC_API_KEY environment variable first.")
        print("  export ANTHROPIC_API_KEY='sk-ant-...'")
        sys.exit(1)

    WORKSPACE.mkdir(parents=True, exist_ok=True)
    print(f"\n{'='*60}")
    print("  CPTS METHODOLOGY MULTI-AGENT PIPELINE")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Workspace: {WORKSPACE}")
    print(f"{'='*60}\n")

    methodology = METHODOLOGY_FILE.read_text(encoding="utf-8")
    print(f"Loaded methodology: {len(methodology):,} chars from {METHODOLOGY_FILE.name}\n")

    client = anthropic.AsyncAnthropic(api_key=api_key)

    # ── Phase 1: 5 Reader Agents (parallel) ────────────────────────────────────
    print("PHASE 1: Running 5 Reader Agents in parallel...")
    print("-" * 40)
    reader_tasks = [run_reader(client, agent, methodology) for agent in MODULE_GROUPS]
    reader_results = await asyncio.gather(*reader_tasks, return_exceptions=True)

    all_gaps = []
    for i, result in enumerate(reader_results):
        if isinstance(result, Exception):
            print(f"  [Reader-{i+1}] FAILED: {result}")
        else:
            all_gaps.extend(result)

    print(f"\n  Total gaps collected: {len(all_gaps)}")
    gaps_file = WORKSPACE / "all_gaps.json"
    gaps_file.write_text(json.dumps(all_gaps, indent=2), encoding="utf-8")
    print(f"  Gaps saved to: {gaps_file}\n")

    # Format feedback for improvers
    feedback_by_phase: dict[str, list] = {}
    for gap in all_gaps:
        if isinstance(gap, dict) and "phase" in gap:
            phase = gap.get("phase", "general")
            feedback_by_phase.setdefault(phase, []).append(gap)

    all_feedback_text = json.dumps(all_gaps, indent=2)

    # ── Phase 2: 3 Improver Agents (parallel) ──────────────────────────────────
    print("PHASE 2: Running 3 Improver Agents in parallel...")
    print("-" * 40)
    improver_tasks = [
        run_improver(client, imp, methodology, all_feedback_text)
        for imp in IMPROVER_ASSIGNMENTS
    ]
    improver_results = await asyncio.gather(*improver_tasks, return_exceptions=True)

    improved_sections = {}
    for i, (imp, result) in enumerate(zip(IMPROVER_ASSIGNMENTS, improver_results)):
        if isinstance(result, Exception):
            print(f"  [{imp['name']}] FAILED: {result}")
            improved_sections[imp["id"]] = f"[ERROR: {result}]"
        else:
            improved_sections[imp["id"]] = result

    # Assemble in order: A → B → C
    assembled = "\n\n".join([
        improved_sections.get("improver_a", ""),
        improved_sections.get("improver_b", ""),
        improved_sections.get("improver_c", ""),
    ])
    assembled_file = WORKSPACE / "assembled_methodology.md"
    assembled_file.write_text(assembled, encoding="utf-8")
    print(f"\n  Assembled methodology: {len(assembled):,} chars")
    print(f"  Saved to: {assembled_file}\n")

    # ── Phase 3: Auditor Agent ──────────────────────────────────────────────────
    print("PHASE 3: Running Auditor Agent...")
    print("-" * 40)
    auditor_result = await run_auditor(client, assembled)

    # Extract just the corrected methodology (Section 2 of auditor output)
    final_methodology = auditor_result
    section2_match = re.search(
        r'###\s*SECTION\s*2[:\s]+CORRECTED.*?\n(.*?)(?=###\s*SECTION\s*3|$)',
        auditor_result, re.DOTALL | re.IGNORECASE
    )
    if section2_match:
        final_methodology = section2_match.group(1).strip()
        print("  Extracted corrected methodology from auditor output")

    OUTPUT_FILE.write_text(final_methodology, encoding="utf-8")
    audit_raw_file = WORKSPACE / "auditor_full_output.md"
    audit_raw_file.write_text(auditor_result, encoding="utf-8")

    print(f"\n{'='*60}")
    print("  PIPELINE COMPLETE")
    print(f"  Final methodology: {OUTPUT_FILE}")
    print(f"  Full audit report: {audit_raw_file}")
    print(f"  Intermediate files: {WORKSPACE}/")
    print(f"{'='*60}\n")

    # Print scorecard if we can find it
    scorecard_match = re.search(
        r'###\s*SECTION\s*3[:\s]+AUDIT SCORECARD.*?\n(.*?)$',
        auditor_result, re.DOTALL | re.IGNORECASE
    )
    if scorecard_match:
        print("AUDIT SCORECARD:")
        print(scorecard_match.group(1)[:500])


if __name__ == "__main__":
    asyncio.run(main())
