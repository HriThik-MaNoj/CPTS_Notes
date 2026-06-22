import os
import glob

source_dir = '/home/hri7hik/CPTS_Notes/academy_og'
md_files = glob.glob(os.path.join(source_dir, '*.md'))
md_files = [f for f in md_files if 'CPTS_MEMORY.md' not in f and 'WORKFLOW_GUIDE.md' not in f and 'm3_ad_methodology.md' not in f and 'mimo_methodology.md' not in f and 'Comprehensive_Methodology.md' not in f]
md_files.sort()

with open('audit_report.txt', 'w') as out:
    for f in md_files:
        basename = os.path.basename(f)
        out.write(f"=== {basename} ===\n")
        with open(f, 'r', encoding='utf-8', errors='ignore') as infile:
            for line in infile:
                if line.startswith('#') and not line.startswith('######'):
                    out.write(line.strip() + '\n')
        out.write("\n")
