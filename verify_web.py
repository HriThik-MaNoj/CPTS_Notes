import os
import glob
import re

source_dir = '/home/hri7hik/CPTS_Notes/academy_og'
methodology_file = '/home/hri7hik/CPTS_Notes/methodology/02_WEB_ATTACKS.md'

ignore_files = ['CPTS_MEMORY.md', 'WORKFLOW_GUIDE.md', 'm3_ad_methodology.md', 'mimo_methodology.md', 'Comprehensive_Methodology.md']

web_keywords = ['xss', 'sqli', 'sql injection', 'ssrf', 'xxe', 'lfi', 'rfi', 'file inclusion', 'file upload', 'command injection', 'verb tampering', 'shellshock', 'mass assignment', 'idor', 'insecure direct object', 'api', 'directory traversal']

def extract_methods(filepath):
    results = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        
    # Split content by markdown headers
    sections = re.split(r'\n(#+ .*)', '\n' + content)
    
    current_header = ""
    for i in range(1, len(sections), 2):
        header = sections[i].strip()
        text = sections[i+1]
        
        # Check if header or text contains web keywords
        header_lower = header.lower()
        if any(kw in header_lower for kw in web_keywords):
            # Extract key tools or commands
            commands = re.findall(r'```[a-z]*\n(.*?)```', text, re.DOTALL)
            inline = re.findall(r'`([^`]+)`', text)
            
            # Condense the text to just the first 100 characters and the commands
            cmds = []
            for c in commands:
                cmds.extend(c.split('\n'))
            cmds = [c.strip() for c in cmds if c.strip() and not c.startswith('#')]
            
            # Unique commands and inline code
            all_code = list(set(cmds + inline))
            
            if all_code or len(text.strip()) > 0:
                results.append({
                    'header': header,
                    'code': all_code[:10] # limit to top 10 code snippets
                })
    return results

all_methods = {}
source_files = glob.glob(os.path.join(source_dir, '*.md'))

for f in source_files:
    if any(ign in f for ign in ignore_files): continue
    methods = extract_methods(f)
    if methods:
        basename = os.path.basename(f)
        all_methods[basename] = methods

with open('web_audit_checklist.txt', 'w') as out:
    for f, methods in all_methods.items():
        out.write(f"=== {f} ===\n")
        for m in methods:
            out.write(f"{m['header']}\n")
            if m['code']:
                out.write(f"  Code/Tools: {', '.join(m['code'])}\n")
        out.write("\n")
