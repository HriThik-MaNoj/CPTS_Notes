import os
import glob
import re
from collections import Counter

source_dir = '/home/hri7hik/CPTS_Notes/academy_og'
methodology_dir = '/home/hri7hik/CPTS_Notes/methodology'

# Files to ignore
ignore_files = ['CPTS_MEMORY.md', 'WORKFLOW_GUIDE.md', 'm3_ad_methodology.md', 'mimo_methodology.md', 'Comprehensive_Methodology.md']

def extract_scripts(filepath):
    terms = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read().lower()
        # Find all words ending in known script/binary extensions
        matches = re.findall(r'\b[\w-]+\.(?:py|ps1|exe|sh|php|asp|aspx|jsp|jspx)\b', content)
        terms.extend(matches)
    return terms

# 1. Gather source terms
source_terms = []
source_files = glob.glob(os.path.join(source_dir, '*.md'))
for f in source_files:
    if any(ign in f for ign in ignore_files): continue
    source_terms.extend(extract_scripts(f))

source_counter = Counter(source_terms)

# 2. Gather methodology terms
method_terms = set()
method_files = glob.glob(os.path.join(methodology_dir, '*.md'))
for f in method_files:
    with open(f, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read().lower()
        method_terms.update(re.findall(r'\b[\w-]+\.(?:py|ps1|exe|sh|php|asp|aspx|jsp|jspx)\b', content))

# 3. Find gaps
gaps = []
for term, count in source_counter.most_common():
    if count > 0: # Check all scripts mentioned
        if term not in method_terms:
            gaps.append((term, count))

with open('audit_scripts_gaps.txt', 'w') as out:
    for term, count in gaps:
        out.write(f"{term}: {count}\n")
