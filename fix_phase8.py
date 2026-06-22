with open('academy_og/mimo_methodology.md', 'r') as f:
    content = f.read()

p8_idx = content.find("# PHASE 8: PRIVILEGE ESCALATION")
p9_idx = content.find("# PHASE 9: ACTIVE DIRECTORY ATTACKS")

phase8 = content[p8_idx:p9_idx].strip()

win_idx = phase8.find("## 8.2 - Windows PrivEsc")
citrix_idx = phase8.find("## 8.3 - Citrix")

linux_part = phase8[:win_idx].strip()
win_part = phase8[win_idx:].strip()

with open('methodology/06_LINUX_PRIVESC.md', 'w') as f:
    f.write(linux_part)
with open('methodology/07_WINDOWS_PRIVESC.md', 'w') as f:
    f.write(win_part)
