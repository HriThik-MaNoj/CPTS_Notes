#!/usr/bin/env python3
"""Build CPTS methodology website from markdown source."""

import re
import sys
from pathlib import Path
from markdown_it import MarkdownIt

SRC = Path("/home/hri7hik/CPTS_Notes/CPTS_Exam_Master_Methodology.md")
OUT = Path("/home/hri7hik/CPTS_Notes/academy_og/CPTS_Methodology_Site.html")


def slugify(text):
    """Convert heading text to a URL-safe anchor id."""
    text = re.sub(r'<[^>]+>', '', text)          # strip HTML tags
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)          # remove punctuation
    text = re.sub(r'[\s_]+', '-', text)           # spaces → hyphens
    text = re.sub(r'-+', '-', text)               # collapse hyphens
    text = text.strip('-')
    return text


def add_heading_ids(html):
    """
    Add id attributes and permalink anchors to h1-h4 headings.
    Returns (modified_html, list of (level, id, clean_title) for h2/h3).
    """
    nav_items = []
    seen_ids = {}

    def replace_heading(m):
        level = int(m.group(1))
        inner = m.group(2)
        clean = re.sub(r'<[^>]+>', '', inner).strip()
        base_id = slugify(clean)
        # Ensure unique ids
        if base_id in seen_ids:
            seen_ids[base_id] += 1
            uid = f"{base_id}-{seen_ids[base_id]}"
        else:
            seen_ids[base_id] = 0
            uid = base_id
        if level in (2, 3):
            nav_items.append((level, uid, clean))
        permalink = f'<a class="headerlink" href="#{uid}" title="Permanent link">¶</a>'
        return f'<h{level} id="{uid}">{inner}{permalink}</h{level}>'

    html = re.sub(r'<h([1-4])>(.*?)</h\1>', replace_heading, html, flags=re.DOTALL)
    return html, nav_items


def fix_unclosed_markdown_fence(raw):
    """
    The markdown source has a ```markdown fence at section 11.5.4 that
    is never closed, swallowing sections 12, 13, and the appendices.
    Find that fence and close it before the next top-level ## heading.
    """
    # Find the ```markdown fence that starts the finding write-up template
    pattern = re.compile(
        r'(#### 11\.5\.4.*?```markdown\n)',
        re.DOTALL
    )
    m = pattern.search(raw)
    if not m:
        return raw

    fence_end = m.end()
    # Find the next top-level ## heading after the fence
    next_h2 = re.search(r'\n## ', raw[fence_end:])
    if not next_h2:
        return raw

    insert_pos = fence_end + next_h2.start()
    # Insert closing fence + blank line before the next ## heading
    raw = raw[:insert_pos] + '\n```\n' + raw[insert_pos:]
    return raw


print(f"Reading {SRC}...")
raw = SRC.read_text(encoding="utf-8")

# Strip escaped heading marker used in Obsidian
raw = re.sub(r'^/#\s', '# ', raw, flags=re.MULTILINE)

# Fix unclosed ```markdown fence that swallows sections 12+
raw = fix_unclosed_markdown_fence(raw)

print("Converting markdown...")
md = MarkdownIt('commonmark', {'html': True}).enable(['table', 'strikethrough'])
body_html = md.render(raw)

# Fix task-list checkboxes
body_html = re.sub(r'<li>\[ \]\s*', '<li><input type="checkbox"> ', body_html)
body_html = re.sub(r'<li>\[x\]\s*', '<li><input type="checkbox" checked> ', body_html, flags=re.IGNORECASE)

# Escape any raw <script> tags that leaked out of fenced code blocks
body_html = re.sub(r'<(/?script\b)', r'&lt;\1', body_html)

# Add heading ids and collect nav items
body_html, nav_items = add_heading_ids(body_html)

# Remove duplicate <hr> tags (--- in markdown produces <hr>, double --- = double <hr>)
body_html = re.sub(r'(<hr\s*/?>\s*){2,}', '<hr>', body_html)

# Add copy buttons to code blocks
body_html = re.sub(
    r'(<pre>)',
    r'<div class="code-wrapper"><button class="copy-btn" onclick="copyCode(this)">Copy</button>\1',
    body_html
)
body_html = re.sub(r'(</pre>)', r'\1</div>', body_html)

# Build sidebar nav
nav_parts = ['<ul id="nav-list">']
for level, anchor, title in nav_items:
    cls = 'nav-h2' if level == 2 else 'nav-h3'
    nav_parts.append(f'<li class="{cls}"><a href="#{anchor}">{title}</a></li>')
nav_parts.append('</ul>')
nav_html = '\n'.join(nav_parts)

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CPTS Exam — Master Methodology</title>
<link rel="stylesheet"
  href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js" defer></script>
<style>
:root {{
  --bg:       #0d1117;
  --bg2:      #161b22;
  --bg3:      #21262d;
  --border:   #30363d;
  --accent:   #58a6ff;
  --green:    #3fb950;
  --red:      #f85149;
  --yellow:   #d29922;
  --text:     #c9d1d9;
  --muted:    #8b949e;
  --sidebar-w: 280px;
}}
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ scroll-behavior: smooth; font-size: 15px; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  line-height: 1.6;
  display: flex;
  min-height: 100vh;
}}

/* ── Sidebar ─────────────────────────────────────────────── */
#sidebar {{
  width: var(--sidebar-w);
  min-width: var(--sidebar-w);
  background: var(--bg2);
  border-right: 1px solid var(--border);
  position: fixed;
  top: 0; left: 0; bottom: 0;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  z-index: 100;
}}
#sidebar-header {{
  padding: 16px 16px 8px;
  border-bottom: 1px solid var(--border);
  background: var(--bg2);
  position: sticky;
  top: 0;
  z-index: 1;
}}
#sidebar-header h1 {{
  font-size: 0.85rem;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: 0.05em;
  text-transform: uppercase;
  margin-bottom: 8px;
}}
#search {{
  width: 100%;
  padding: 6px 10px;
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  font-size: 0.82rem;
  outline: none;
}}
#search:focus {{ border-color: var(--accent); }}
#search::placeholder {{ color: var(--muted); }}

#nav-list {{
  list-style: none;
  padding: 8px 0 24px;
  flex: 1;
}}
#nav-list li a {{
  display: block;
  padding: 4px 16px;
  color: var(--muted);
  text-decoration: none;
  font-size: 0.8rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  transition: color 0.15s, background 0.15s;
}}
#nav-list li a:hover {{ color: var(--text); background: var(--bg3); }}
#nav-list li a.active {{ color: var(--accent); border-right: 2px solid var(--accent); }}
.nav-h2 > a {{ color: var(--text); font-weight: 600; font-size: 0.82rem; padding-top: 8px; }}
.nav-h3 > a {{ padding-left: 28px; font-size: 0.78rem; }}

/* ── Main content ────────────────────────────────────────── */
#main {{
  margin-left: var(--sidebar-w);
  flex: 1;
  max-width: 960px;
  padding: 40px 48px;
}}

/* Typography */
h1, h2, h3, h4, h5, h6 {{
  line-height: 1.3;
  font-weight: 600;
  margin-top: 2rem;
  margin-bottom: 0.6rem;
  color: #e6edf3;
}}
h1 {{ font-size: 2rem; color: var(--accent); border-bottom: 2px solid var(--border); padding-bottom: 12px; }}
h2 {{ font-size: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 3rem; }}
h3 {{ font-size: 1.15rem; color: var(--green); }}
h4 {{ font-size: 1rem; color: var(--yellow); }}

p {{ margin-bottom: 0.8rem; }}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}

ul, ol {{ padding-left: 1.5rem; margin-bottom: 0.8rem; }}
li {{ margin-bottom: 0.3rem; }}
li > ul, li > ol {{ margin-top: 0.2rem; margin-bottom: 0.2rem; }}
li > p {{ margin-bottom: 0.3rem; }}

/* Checkboxes */
li input[type="checkbox"] {{
  margin-right: 6px;
  accent-color: var(--green);
  cursor: pointer;
}}

/* Blockquote */
blockquote {{
  border-left: 3px solid var(--accent);
  padding: 8px 16px;
  margin: 1rem 0;
  background: var(--bg2);
  border-radius: 0 6px 6px 0;
  color: var(--muted);
}}
blockquote p {{ margin-bottom: 0.2rem; }}

/* Tables */
table {{
  width: 100%;
  border-collapse: collapse;
  margin: 1rem 0;
  font-size: 0.88rem;
}}
th {{
  background: var(--bg3);
  color: var(--accent);
  text-align: left;
  padding: 8px 12px;
  border: 1px solid var(--border);
  font-weight: 600;
}}
td {{
  padding: 6px 12px;
  border: 1px solid var(--border);
  vertical-align: top;
}}
tr:nth-child(even) {{ background: var(--bg2); }}
tr:hover {{ background: var(--bg3); }}

/* Inline code */
code {{
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 1px 5px;
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 0.85em;
  color: #e6edf3;
}}

/* Code blocks */
.code-wrapper {{
  position: relative;
  margin: 1rem 0;
}}
pre {{
  background: #161b22 !important;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 16px 16px 16px;
  overflow-x: auto;
  font-size: 0.82rem;
  line-height: 1.5;
}}
pre code {{
  background: none;
  border: none;
  padding: 0;
  font-size: inherit;
  color: #e6edf3;
}}
.copy-btn {{
  position: absolute;
  top: 8px; right: 8px;
  background: var(--bg3);
  border: 1px solid var(--border);
  color: var(--muted);
  border-radius: 5px;
  padding: 3px 10px;
  font-size: 0.75rem;
  cursor: pointer;
  transition: all 0.15s;
  z-index: 1;
  opacity: 0;
}}
.code-wrapper:hover .copy-btn {{ opacity: 1; }}
.copy-btn:hover {{ background: var(--border); color: var(--text); }}
.copy-btn.copied {{ color: var(--green); border-color: var(--green); opacity: 1; }}

/* Horizontal rule */
hr {{ border: none; border-top: 1px solid var(--border); margin: 2rem 0; }}

/* Permalink anchors */
.headerlink {{ opacity: 0; margin-left: 6px; font-size: 0.8em; color: var(--muted); }}
h1:hover .headerlink, h2:hover .headerlink,
h3:hover .headerlink, h4:hover .headerlink {{ opacity: 1; }}

/* ── Search highlight ────────────────────────────────────── */
mark {{ background: #d29922; color: #0d1117; border-radius: 2px; padding: 0 2px; }}

/* ── Scrollbar ───────────────────────────────────────────── */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: var(--bg); }}
::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--muted); }}

/* ── Top progress bar ────────────────────────────────────── */
#progress {{
  position: fixed;
  top: 0; left: var(--sidebar-w); right: 0;
  height: 3px;
  background: linear-gradient(to right, var(--accent), var(--green));
  transform-origin: left;
  transform: scaleX(0);
  z-index: 200;
  transition: transform 0.1s;
}}

/* ── Responsive ──────────────────────────────────────────── */
@media (max-width: 768px) {{
  :root {{ --sidebar-w: 0px; }}
  #sidebar {{ transform: translateX(-280px); width: 280px; transition: transform 0.25s; }}
  #sidebar.open {{ transform: translateX(0); --sidebar-w: 280px; }}
  #main {{ margin-left: 0; padding: 24px 20px; }}
  #progress {{ left: 0; }}
  #menu-btn {{
    display: flex;
    position: fixed; top: 12px; left: 12px;
    z-index: 300;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 10px;
    cursor: pointer;
    color: var(--text);
    font-size: 1.2rem;
    align-items: center;
  }}
}}
@media (min-width: 769px) {{
  #menu-btn {{ display: none; }}
}}
</style>
</head>
<body>

<div id="progress"></div>
<button id="menu-btn" onclick="document.getElementById('sidebar').classList.toggle('open')">&#9776;</button>

<nav id="sidebar">
  <div id="sidebar-header">
    <h1>CPTS Methodology</h1>
    <input id="search" type="search" placeholder="Search sections..." autocomplete="off">
  </div>
  {nav_html}
</nav>

<main id="main">
{body_html}
</main>

<script>
document.addEventListener('DOMContentLoaded', function() {{
  if (typeof hljs !== 'undefined') hljs.highlightAll();
}});

// ── Progress bar ──────────────────────────────────────────
const prog = document.getElementById('progress');
window.addEventListener('scroll', () => {{
  const el = document.documentElement;
  const pct = el.scrollTop / (el.scrollHeight - el.clientHeight);
  prog.style.transform = `scaleX(${{pct}})`;
}});

// ── Active nav on scroll ──────────────────────────────────
const headings = Array.from(document.querySelectorAll('h2[id], h3[id]'));
const navLinks = document.querySelectorAll('#nav-list a');
const observer = new IntersectionObserver(entries => {{
  entries.forEach(e => {{
    if (e.isIntersecting) {{
      navLinks.forEach(l => l.classList.remove('active'));
      const link = document.querySelector(`#nav-list a[href="#${{e.target.id}}"]`);
      if (link) {{
        link.classList.add('active');
        link.scrollIntoView({{block: 'nearest'}});
      }}
    }}
  }});
}}, {{rootMargin: '-10% 0px -80% 0px'}});
headings.forEach(h => observer.observe(h));

// ── Copy button ───────────────────────────────────────────
function copyCode(btn) {{
  const pre = btn.nextElementSibling;
  const code = pre.innerText;
  navigator.clipboard.writeText(code).then(() => {{
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {{ btn.textContent = 'Copy'; btn.classList.remove('copied'); }}, 2000);
  }});
}}

// ── Search / filter nav ───────────────────────────────────
document.getElementById('search').addEventListener('input', function() {{
  const q = this.value.trim().toLowerCase();
  navLinks.forEach(link => {{
    const li = link.parentElement;
    li.style.display = (!q || link.textContent.toLowerCase().includes(q)) ? '' : 'none';
  }});
}});

// ── Checkbox persistence ──────────────────────────────────
document.querySelectorAll('input[type=checkbox]').forEach((cb, i) => {{
  const key = 'cb_' + i;
  if (localStorage.getItem(key) === '1') cb.checked = true;
  cb.addEventListener('change', () => localStorage.setItem(key, cb.checked ? '1' : '0'));
}});
</script>
</body>
</html>
"""

print(f"Writing {OUT}...")
OUT.write_text(HTML, encoding="utf-8")
size_kb = OUT.stat().st_size / 1024
print(f"Done. {OUT.name} ({size_kb:.0f} KB)")
