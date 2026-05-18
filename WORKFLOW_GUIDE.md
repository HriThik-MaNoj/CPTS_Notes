# Hri7hik H4cks — Complete Beginner's Workflow Guide

> **Who this guide is for:** Anyone who wants to write blog posts for this site without needing to understand Hugo, static site generators, or web development. If you can write in Obsidian, you can publish here.

---

## Table of Contents

1. [How This System Works](#1-how-this-system-works)
2. [One-Time Setup](#2-one-time-setup)
3. [Your First Blog Post — Step by Step](#3-your-first-blog-post--step-by-step)
4. [Choosing the Right Template](#4-choosing-the-right-template)
5. [Writing Your Post in Obsidian](#5-writing-your-post-in-obsidian)
6. [Special Obsidian Features That Work Automatically](#6-special-obsidian-features-that-work-automatically)
7. [Previewing Your Post Live](#7-previewing-your-post-live)
8. [Publishing Your Post](#8-publishing-your-post)
9. [Building and Deploying the Site](#9-building-and-deploying-the-site)
10. [All Commands at a Glance](#10-all-commands-at-a-glance)
11. [Troubleshooting Common Problems](#11-troubleshooting-common-problems)
12. [Frequently Asked Questions](#12-frequently-asked-questions)

---

## 1. How This System Works

Before you do anything, it helps to understand the big picture. There are three stages your blog post goes through:

```
Stage 1: You write       →   Stage 2: Auto-convert   →   Stage 3: Live on site
obsidian-vault/posts/        content/posts/               public/
(your Obsidian files)        (Hugo-ready files)           (the actual website)
```

### What each stage means

**Stage 1 — Your writing zone:**
This is where you work. You write `.md` (Markdown) files inside the `obsidian-vault/posts/` folder. You can open this folder directly in Obsidian. Write like you normally would.

**Stage 2 — The automatic conversion:**
A Python script reads your Obsidian files and converts them into a format that Hugo (the website engine) understands. It handles things like callout boxes, image optimisation, and link formatting. **You never need to touch this folder.**

**Stage 3 — The website:**
Hugo takes the converted files and builds the final website into the `public/` folder. This is what gets deployed online. **You never need to touch this folder either.**

> **The golden rule:** Only ever write inside `obsidian-vault/posts/`. Everything else is automatic.

---

## 2. One-Time Setup

You only need to do this once. After this, everything is ready to go.

### Step 1 — Open a terminal in the project folder

```bash
cd /home/hri7hik/Hri7hik_H4cks
```

### Step 2 — Create a Python virtual environment

A virtual environment is an isolated space for the Python tools this workflow needs. This is required on Kali Linux because the system blocks installing packages globally.

```bash
python3 -m venv scripts/venv
```

### Step 3 — Activate the virtual environment

```bash
source scripts/venv/bin/activate
```

You will see `(venv)` appear at the start of your terminal prompt. This means it's active. **You need to do this activation step every time you open a new terminal session before running any workflow commands.**

### Step 4 — Install the required tools

```bash
pip install -r requirements.txt
```

This installs two things:
- `pyyaml` — reads configuration files
- `Pillow` — resizes and optimises your images automatically

### Step 5 — Install optional but recommended extras

```bash
sudo apt install fzf inotify-tools
```

- `fzf` — gives you a nice interactive fuzzy search menu when choosing templates or picking a draft to publish
- `inotify-tools` — watches your Obsidian files for changes so the preview updates instantly when you save

### Step 6 — Create the folder structure

```bash
./scripts/workflow.sh setup
```

### Step 7 — Verify everything is working

```bash
./scripts/workflow.sh check
```

You should see green `[ OK ]` messages for Python, Hugo, and the required packages. If anything shows red, follow the instructions it prints.

---

## 3. Your First Blog Post — Step by Step

Here is the complete flow from start to published post. Follow these steps in order.

### Step 1 — Activate the virtual environment (every session)

Every time you open a new terminal, run this first:

```bash
source scripts/venv/bin/activate
```

You will see `(venv)` in your prompt. If you forget this step, commands will fail.

### Step 2 — Create a new post

```bash
./scripts/workflow.sh new
```

The script will ask you two questions interactively:

**Question 1 — Post title:**
```
Post title: Hack The Box — Blue Walkthrough
```

Type your title and press Enter. The script automatically converts this into a filename. For example, `Hack The Box — Blue Walkthrough` becomes `hack-the-box-blue-walkthrough.md`.

**Question 2 — Template selection:**

If you have `fzf` installed, you will see a fuzzy picker:
```
Template ▶
  ctf-walkthrough
  quick-reference
  security-analysis
  tutorial
```

Use the arrow keys to select and press Enter.

If you do not have `fzf`, you will see a numbered list:
```
Templates:
  1) ctf-walkthrough
  2) quick-reference
  3) security-analysis
  4) tutorial
Choose [1-4] (default 1):
```

Type the number and press Enter.

**Result:** A new file is created at `obsidian-vault/posts/hack-the-box-blue-walkthrough.md`. You will see:
```
[ OK ] Created: obsidian-vault/posts/hack-the-box-blue-walkthrough.md
[INFO] Template: ctf-walkthrough
[INFO] Edit in Obsidian, then: ./scripts/workflow.sh serve
```

### Step 3 — Open the file in Obsidian

Open Obsidian and navigate to `obsidian-vault/posts/` inside your vault. Open the new file. You will see it pre-filled with the template structure and placeholder text like `{{Machine Name}}` and `{{Target IP}}`.

Replace the placeholders with your actual content.

### Step 4 — Start the live preview

In your terminal (with venv active), run:

```bash
./scripts/workflow.sh serve
```

This command does four things at once:
1. Converts your Obsidian files to Hugo format
2. Starts watching your files for changes
3. Starts the Hugo web server
4. Opens a preview at `http://localhost:1313`

Open `http://localhost:1313` in your browser. Every time you save your file in Obsidian, the browser preview updates automatically — no manual refresh needed.

### Step 5 — Write your post

Write in Obsidian normally. Save frequently. Watch the browser update in real time.

Your post starts as a draft, so it is visible in the preview (the server shows drafts) but not yet published on the live site.

### Step 6 — Publish when ready

When you are happy with your post, stop the server with `Ctrl+C` and run:

```bash
./scripts/workflow.sh publish
```

If you have `fzf`, you will see a picker showing all your current drafts. Select your post and press Enter. If you do not have `fzf`, the script will list your drafts and prompt you to type the slug (filename without `.md`).

The script changes `draft: true` to `draft: false` in your file and reconverts it automatically.

### Step 7 — Build the final site

```bash
./scripts/workflow.sh build
```

This creates the production-ready website in the `public/` folder. Deploy that folder to your hosting service (Netlify, Cloudflare Pages, GitHub Pages, etc.).

---

## 4. Choosing the Right Template

There are four templates available. Here is when to use each one.

---

### `ctf-walkthrough` — For Capture the Flag writeups

Use this for any CTF box or challenge — HackTheBox, TryHackMe, PicoCTF, VulnHub, etc.

**Pre-built sections:**
- Information box (platform, difficulty, target IP, objective)
- Table of contents
- Introduction and target information
- Reconnaissance (port scans, service enumeration, web directory bruteforce)
- Initial access and exploitation
- Privilege escalation
- Flag finding
- Summary and tools used

**Example post titles:**
- "HackTheBox — Lame Walkthrough"
- "TryHackMe — Mr Robot Room"
- "PicoCTF 2024 — Buffer Overflow Challenge"

---

### `tutorial` — For educational how-to content

Use this when you are teaching something — explaining a concept, showing how a tool works, or walking someone through a process step by step.

**Pre-built sections:**
- Tutorial information box (category, difficulty, prerequisites, estimated time)
- Table of contents
- Introduction and learning objectives
- Prerequisites
- Step-by-step guide
- Best practices
- Common mistakes
- Troubleshooting
- Conclusion

**Example post titles:**
- "How to Set Up a Burp Suite Proxy"
- "Understanding SQL Injection from Scratch"
- "Setting Up a Home Penetration Testing Lab"

---

### `security-analysis` — For CVEs, vulnerability research, and deep dives

Use this when you are analysing a specific vulnerability, malware, or security incident in technical depth.

**Pre-built sections:**
- Abstract
- Executive summary and key findings
- Impact assessment (severity, affected systems)
- Background and methodology
- Technical analysis
- Proof of concept
- Remediation recommendations
- Timeline

**Example post titles:**
- "Log4Shell (CVE-2021-44228) Deep Dive"
- "Analysing the WannaCry Ransomware"
- "BlueKeep RDP Vulnerability — Technical Analysis"

---

### `quick-reference` — For cheat sheets and command references

Use this for content that people will come back to repeatedly for quick lookups — command tables, flag references, payload lists, tool syntax guides.

**Pre-built sections:**
- Common commands (organised by category with code blocks)
- Syntax reference
- Quick tips callout
- Common pitfalls
- Cheat sheet table (Command | Description | Example)
- Useful resources

**Example post titles:**
- "Nmap Complete Command Reference"
- "SQL Injection Payloads Cheat Sheet"
- "Linux Privilege Escalation Quick Reference"

---

## 5. Writing Your Post in Obsidian

### Understanding the front matter

At the very top of every post file, between the two `---` lines, is the **front matter**. This is metadata about your post — think of it like the properties or settings for that specific post.

Here is what it looks like after the `new` command creates it:

```yaml
---
title: "Hack The Box — Blue Walkthrough"
date: 2026-05-04T15:30:00Z
draft: true
categories: []
tags: []
description: ""
---
```

**Fields you should fill in manually:**

| Field | What it does | Example |
|---|---|---|
| `title` | The displayed title of your post | `"HackTheBox — Blue Walkthrough"` |
| `categories` | Broad groupings shown in the site menu | `["CTF", "HackTheBox"]` |
| `tags` | More specific keywords for filtering | `["samba", "eternal-blue", "windows"]` |
| `description` | Short summary shown in post listings | `"A walkthrough of the Blue box..."` |
| `draft` | Controls visibility on live site | `true` = hidden, `false` = published |

**Fields that are filled automatically** (you can leave these blank or override them):

| Field | How it is detected |
|---|---|
| `platforms` | Script scans your post for words like `hackthebox`, `tryhackme`, `picoctf`, `vulnhub` |
| `tools` | Script scans your code blocks for tool names like `nmap`, `gobuster`, `sqlmap`, `metasploit` |
| `difficulties` | Script looks for the phrase `difficulty: easy/medium/hard` anywhere in your post |
| `description` | If you leave it blank, the first paragraph of your post becomes the description |

> **Tip:** Fill in `categories` and `tags` manually — the auto-detection is helpful but your manual choices are always more accurate.

### A complete front matter example

```yaml
---
title: "HackTheBox — Blue Walkthrough"
date: 2026-05-04
draft: false
categories: ["CTF", "HackTheBox"]
tags: ["eternal-blue", "ms17-010", "windows", "smb"]
difficulties: ["easy"]
platforms: ["hackthebox"]
tools: ["nmap", "metasploit"]
description: "Walkthrough of HTB Blue — exploiting EternalBlue (MS17-010) on a Windows 7 target."
---
```

---

## 6. Special Obsidian Features That Work Automatically

The converter handles several Obsidian-specific features so that they render properly on the website. You write them in Obsidian's normal way and they just work.

---

### Callout Boxes

Callouts are highlighted boxes that draw attention to important information. You write them like this in Obsidian:

```
> [!info] Machine Information
> **Platform:** HackTheBox
> **Difficulty:** Easy
> **Target IP:** 10.10.10.40
```

On the website this becomes a styled highlighted box with a coloured border. There are several types:

| What you write | Colour on site | Best used for |
|---|---|---|
| `[!info]` | Blue | General information, box details, notes |
| `[!tip]` | Green | Helpful hints, pro tips |
| `[!warning]` | Yellow | Cautions, things to be aware of |
| `[!danger]` | Red | Critical warnings, destructive actions |
| `[!success]` | Green | Completed steps, achievements, flags found |
| `[!note]` | Blue | Side notes, additional context |
| `[!question]` | Blue | Discussion points, things to investigate |
| `[!example]` | Green | Examples, demonstrations |
| `[!abstract]` | Blue | Summaries, abstracts |

**The title after the type is optional.** If you leave it out, the callout type name is used automatically:

```
> [!warning]
> This payload may trigger antivirus detection on the target.
```

---

### Wikilinks (Internal Links Between Posts)

In Obsidian you can link to other notes using double brackets. The converter turns these into proper website links automatically.

| What you write in Obsidian | What appears on the website |
|---|---|
| `[[Nmap Cheat Sheet]]` | `[Nmap Cheat Sheet](/posts/nmap-cheat-sheet/)` |
| `[[Nmap Cheat Sheet\|Click here for commands]]` | `[Click here for commands](/posts/nmap-cheat-sheet/)` |

This means you can cross-reference your posts using standard Obsidian linking and they will work correctly on the live site.

---

### Images

Drop your image files into the `obsidian-vault/attachments/` folder. Then reference them in your post like this:

```markdown
![Nmap scan results showing open ports](attachments/nmap-output.png)
```

The converter automatically:
1. Finds the image in the attachments folder
2. Resizes it if it is wider than 1200 pixels
3. Optimises it to reduce file size (JPEG images get compressed to 85% quality; PNG images keep full quality and transparency)
4. Copies it to the correct location for the website
5. Updates the link in your post to point to the new location

You never need to manually copy or resize images.

---

### Code Blocks

Write code blocks in standard Markdown format with a language tag:

````markdown
```bash
nmap -sC -sV -oA initial_scan 10.10.10.40
```

```python
import socket
s = socket.socket()
s.connect(("10.10.10.40", 9001))
```
````

The converter adds a **copy button** to every code block on the website. Readers can click the button to copy the code to their clipboard. This works with the keyboard too (Tab to focus, Enter or Space to copy).

---

## 7. Previewing Your Post Live

The `serve` command is your main working command. It starts a local version of your website that updates in real time as you write.

```bash
./scripts/workflow.sh serve
```

Open `http://localhost:1313` in your browser.

### What you see in the preview

- **All posts are visible**, including drafts. This is intentional — the preview shows everything so you can see exactly how your draft will look when published.
- The site looks exactly like the live version.
- When you save a file in Obsidian, the browser updates within about a second.

### What happens behind the scenes when you save

1. The file watcher detects your save
2. It waits 400 milliseconds to collect any rapid consecutive saves (Obsidian saves multiple times in quick succession)
3. The converter runs on only the changed file — unchanged files are skipped
4. Hugo detects the updated converted file and refreshes the browser

### If port 1313 is already in use

```bash
# Use a different port
HUGO_PORT=4000 ./scripts/workflow.sh serve

# Or forcefully take port 1313 from whatever is using it
KILL_PORT=1 ./scripts/workflow.sh serve
```

### Stopping the server

Press `Ctrl+C` in the terminal. The file watcher and server both stop cleanly.

---

## 8. Publishing Your Post

A post with `draft: true` is never included in the live site build, even if you run `build`. To make a post live, you need to publish it.

### Interactive publish (recommended)

```bash
./scripts/workflow.sh publish
```

If `fzf` is installed, you see a searchable list of all your current drafts. Arrow keys to navigate, Enter to select. If `fzf` is not installed, the script lists your drafts and asks you to type the slug.

### Direct publish (if you know the slug)

```bash
./scripts/workflow.sh publish hack-the-box-blue-walkthrough
```

The slug is the filename without the `.md` extension.

### What happens when you publish

1. The script opens your source file in `obsidian-vault/posts/`
2. Changes `draft: true` to `draft: false`
3. Runs the converter automatically to update `content/posts/`
4. Your post is now ready to be built into the live site

> **Note:** Publishing does not automatically build or deploy the site. After publishing, you still need to run `./scripts/workflow.sh build` and deploy the `public/` folder.

---

## 9. Building and Deploying the Site

When you are ready to put your changes live:

```bash
./scripts/workflow.sh build
```

This runs the full production build. After it finishes, you will see something like:

```
[ OK ] Built in 3s
[INFO] Output: 2.7M | HTML pages: 47
```

The `public/` folder now contains your complete website. Deploy this folder to your hosting service.

**Important:** The build command always forces a fresh conversion of all Obsidian files before building, to make sure nothing is missed.

---

## 10. All Commands at a Glance

Here is every command you might need, with a plain-English explanation.

### Writing commands

| Command | What it does |
|---|---|
| `./scripts/workflow.sh new` | Creates a new post interactively (prompts for title and template) |
| `./scripts/workflow.sh new "My Title"` | Creates a post with that title, then prompts for template |
| `./scripts/workflow.sh new "My Title" ctf-walkthrough` | Creates a post with that title using the ctf-walkthrough template — no prompts |
| `./scripts/workflow.sh serve` | Starts live preview at localhost:1313 (your main writing command) |
| `./scripts/workflow.sh publish` | Interactive draft picker — flips the selected post from draft to published |
| `./scripts/workflow.sh publish my-post-slug` | Publishes a specific post directly |

### Build and maintenance commands

| Command | What it does |
|---|---|
| `./scripts/workflow.sh build` | Builds the final website into `public/` (ready to deploy) |
| `./scripts/workflow.sh convert` | Converts Obsidian files to Hugo format without starting a server |
| `./scripts/workflow.sh watch` | Watches for file changes and converts automatically — no server |
| `./scripts/workflow.sh stats` | Shows post count, word count, site size |
| `./scripts/workflow.sh clean` | Deletes all generated files (asks for confirmation first) |
| `./scripts/workflow.sh clean-cache` | Clears the conversion cache so everything reconverts fresh next time |
| `./scripts/workflow.sh setup` | Creates all required folders (safe to run multiple times) |
| `./scripts/workflow.sh check` | Verifies all dependencies are installed and working |

### Environment variable overrides

These are optional settings you can put in front of any command:

| Variable | Default | Example use |
|---|---|---|
| `HUGO_PORT` | `1313` | `HUGO_PORT=4000 ./scripts/workflow.sh serve` |
| `KILL_PORT=1` | off | `KILL_PORT=1 ./scripts/workflow.sh serve` — kills what's on port 1313 |
| `FORCE_CONVERT=1` | off | `FORCE_CONVERT=1 ./scripts/workflow.sh convert` — ignores cache, reconverts everything |
| `VERBOSE=1` | off | `VERBOSE=1 ./scripts/workflow.sh convert` — shows detailed debug output |
| `FORCE=1` | off | `FORCE=1 ./scripts/workflow.sh clean` — skips the "are you sure?" prompt |
| `DEBOUNCE_MS` | `400` | `DEBOUNCE_MS=200 ./scripts/workflow.sh serve` — faster watcher response |

---

## 11. Troubleshooting Common Problems

### "command not found: python3" or packages fail to import

You forgot to activate the virtual environment. Run:

```bash
source scripts/venv/bin/activate
```

You should see `(venv)` at the start of your terminal prompt. Then try again.

---

### "Port 1313 is already in use"

Something else is running on port 1313 (probably a previous Hugo server that did not close cleanly).

**Option A:** Use a different port:
```bash
HUGO_PORT=4000 ./scripts/workflow.sh serve
```

**Option B:** Kill whatever is using 1313 and take it:
```bash
KILL_PORT=1 ./scripts/workflow.sh serve
```

---

### My changes are not showing up in the preview

First check that the file watcher is running — you should see a `[ OK ] Watcher running` message when you start `serve`. If `inotify-tools` is not installed, the watcher cannot run.

```bash
sudo apt install inotify-tools
```

Then restart `serve`.

If the watcher is running but changes still do not appear:

```bash
# Stop the server with Ctrl+C, then force a fresh reconvert
FORCE_CONVERT=1 ./scripts/workflow.sh convert
./scripts/workflow.sh serve
```

---

### My image is not showing up on the site

1. Make sure the image file is inside `obsidian-vault/attachments/`
2. Make sure your reference in the post uses the correct format:
   ```markdown
   ![Description](attachments/your-image-filename.png)
   ```
3. Run the converter with verbose mode to see if there is an error:
   ```bash
   VERBOSE=1 FORCE_CONVERT=1 ./scripts/workflow.sh convert
   ```
   Look for a `[WARN] Image not found` message — it will tell you exactly what path it was looking for.
4. Check that the image appears in `static/images/` after conversion.

---

### My post is published but it is not appearing on the live site

Check two things:

1. **Is it still a draft?** Open the source file in `obsidian-vault/posts/` and check that the front matter says `draft: false`, not `draft: true`.

2. **Did you build after publishing?** Run:
   ```bash
   ./scripts/workflow.sh build
   ```
   Then redeploy the `public/` folder.

---

### The conversion is failing with a YAML error

The front matter has invalid formatting. Common causes:

- A quotation mark inside a quoted title without escaping:
  ```yaml
  # Wrong:
  title: "Hack "The Box" Walkthrough"
  
  # Right:
  title: "Hack The Box Walkthrough"
  # or escape the inner quotes:
  title: "Hack \"The Box\" Walkthrough"
  ```

Open the file, fix the front matter, and run:
```bash
FORCE_CONVERT=1 ./scripts/workflow.sh convert
```

---

### I want to start completely fresh

**Warning:** This deletes all generated content. Your source files in `obsidian-vault/posts/` are NOT deleted.

```bash
FORCE=1 ./scripts/workflow.sh clean
./scripts/workflow.sh setup
FORCE_CONVERT=1 ./scripts/workflow.sh convert
./scripts/workflow.sh serve
```

---

## 12. Frequently Asked Questions

**Q: Do I need to know how Hugo works?**
No. The workflow hides all of Hugo's complexity. You write Markdown in Obsidian, run a couple of commands, and your post appears on the website.

---

**Q: Can I edit files in `content/posts/` directly?**
Technically yes, but you should not. Every time the converter runs, it overwrites `content/posts/` with fresh output from your Obsidian vault. Any manual edits you made there will be lost. Always edit in `obsidian-vault/posts/`.

---

**Q: Why do I need to activate the venv every session?**
The virtual environment contains the Python packages (pyyaml, Pillow) the converter needs. When you open a new terminal, those packages are not in scope until you activate the venv. It is a one-command step: `source scripts/venv/bin/activate`.

---

**Q: My post has `draft: false` in the source but it still shows on the preview. Is that a problem?**
No. The preview server (`serve`) shows all posts including drafts. This is intentional so you can see your work-in-progress. Only the production `build` command respects `draft: true` and hides drafts. If you want to hide a post from preview, that is not supported by design — the preview is your private workspace.

---

**Q: What is the `.cache/o2h/` folder and can I delete it?**
That folder stores a small file that remembers which of your posts have already been converted and have not changed. It makes subsequent conversions very fast (skipping unchanged files). You can delete it at any time — the next conversion will just rebuild it from scratch. The command `./scripts/workflow.sh clean-cache` does this for you.

---

**Q: How do I add a new template?**
Create a `.md` file inside `obsidian-templates/`. Give it a descriptive name like `pentest-report.md`. The next time you run `./scripts/workflow.sh new`, it will appear in the template picker automatically. You can use any Obsidian Markdown in the template — callouts, code blocks, headings, etc.

---

**Q: Can I write posts without Obsidian?**
Yes. The converter works on any standard Markdown file. You can create and edit files in `obsidian-vault/posts/` using any text editor (VS Code, Nano, Vim, etc.). Obsidian-specific features like callouts and wikilinks will still be converted automatically.

---

**Q: I ran `publish` but nothing happened. What went wrong?**
Make sure the source file actually contains `draft: true`. Run:
```bash
grep "draft:" obsidian-vault/posts/your-post-slug.md
```
If it already says `draft: false`, the post is already published and the command will tell you so.

---

*Last updated: May 2026*
