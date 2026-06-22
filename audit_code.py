import os
import glob
import re
from collections import Counter

source_dir = '/home/hri7hik/CPTS_Notes/academy_og'
methodology_dir = '/home/hri7hik/CPTS_Notes/methodology'

# Files to ignore
ignore_files = ['CPTS_MEMORY.md', 'WORKFLOW_GUIDE.md', 'm3_ad_methodology.md', 'mimo_methodology.md', 'Comprehensive_Methodology.md']

def extract_technical_terms(filepath):
    terms = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        
        # Extract inline code
        inline_code = re.findall(r'`([^`]+)`', content)
        for code in inline_code:
            # split by space to get individual words/commands
            for word in code.split():
                word = word.strip().lower()
                if len(word) > 2 and word.isalnum() or '.' in word or '-' in word:
                    terms.append(word)
                    
        # Extract code blocks
        code_blocks = re.findall(r'```[a-z]*\n(.*?)```', content, re.DOTALL)
        for block in code_blocks:
            for word in block.split():
                word = word.strip().lower()
                if len(word) > 2:
                    terms.append(word)
    return terms

# 1. Gather source terms
source_terms = []
source_files = glob.glob(os.path.join(source_dir, '*.md'))
for f in source_files:
    if any(ign in f for ign in ignore_files): continue
    source_terms.extend(extract_technical_terms(f))

source_counter = Counter(source_terms)

# 2. Gather methodology terms
method_terms = set()
method_files = glob.glob(os.path.join(methodology_dir, '*.md'))
for f in method_files:
    with open(f, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read().lower()
        words = set(content.split())
        method_terms.update(words)

# 3. Find gaps
gaps = []
for term, count in source_counter.most_common():
    if count > 5: # Only care about terms that appear somewhat frequently
        # Check if the exact term is not in methodology
        # Because we split by space, some punctuation might be attached in method_terms
        found = False
        for m_term in method_terms:
            if term in m_term:
                found = True
                break
        if not found:
            gaps.append((term, count))

with open('audit_gaps.txt', 'w') as out:
    for term, count in gaps:
        out.write(f"{term}: {count}\n")
