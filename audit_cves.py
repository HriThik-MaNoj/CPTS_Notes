import os
import glob
import re
from collections import Counter

source_dir = '/home/hri7hik/CPTS_Notes/academy_og'
methodology_dir = '/home/hri7hik/CPTS_Notes/methodology'

ignore_files = ['CPTS_MEMORY.md', 'WORKFLOW_GUIDE.md', 'm3_ad_methodology.md', 'mimo_methodology.md', 'Comprehensive_Methodology.md']

def extract_cves(filepath):
    cves = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read().upper()
        # Find all CVEs and MS bulletins
        matches = re.findall(r'CVE-\d{4}-\d{4,7}', content)
        matches += re.findall(r'MS\d{2}-\d{3}', content)
        cves.extend(matches)
    return cves

# 1. Gather source CVEs
source_cves = []
source_files = glob.glob(os.path.join(source_dir, '*.md'))
for f in source_files:
    if any(ign in f for ign in ignore_files): continue
    source_cves.extend(extract_cves(f))

source_counter = Counter(source_cves)

# 2. Gather methodology CVEs
method_cves = set()
method_files = glob.glob(os.path.join(methodology_dir, '*.md'))
for f in method_files:
    with open(f, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read().upper()
        method_cves.update(re.findall(r'CVE-\d{4}-\d{4,7}', content))
        method_cves.update(re.findall(r'MS\d{2}-\d{3}', content))

# 3. Find gaps
gaps = []
for cve, count in source_counter.most_common():
    if cve not in method_cves:
        gaps.append((cve, count))

with open('audit_cves_gaps.txt', 'w') as out:
    for cve, count in gaps:
        out.write(f"{cve}: {count}\n")
