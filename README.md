# zeropwn — Security Research & 0day Disclosures Blog

Personal security research portfolio for **Tong Hoang Gia** ([@uziii2208](https://github.com/uziii2208) / `zeropwn`).
Features authentic CVE vulnerability write-ups, CTF challenge solutions, and HackTheBox walkthroughs.

Live at: **[https://uziii2208.github.io](https://uziii2208.github.io)**

---

## 🚀 Clean Static Architecture & URL Routing

The blog compiles markdown files in `posts/` into static standalone HTML pages with clean, canonical URLs:

```
uziii2208.github.io/
├── .github/
│   └── workflows/
│       └── build.yml             # GitHub Actions CI auto-builder
├── css/
│   └── style.css                 # Cyber-Aesthetic stylesheet (Red #e8192c / Base #050508)
├── js/
│   ├── app.js                    # Core logic: Web Audio SFX, canvas, search, lightbox, TOC
│   └── posts-data.js             # Pre-compiled manifest & search index
├── photos/
│   └── hercules/                 # Exploit screenshots & diagrams
├── post/                         # Generated Static Post Pages (Clean URL Routing)
│   ├── hackthebox-hercules/
│   │   └── index.html            # Served at: /post/hackthebox-hercules
│   ├── cve-2026-88899/
│   │   └── index.html            # Served at: /post/cve-2026-88899
│   ├── cve-2026-86259/
│   │   └── index.html            # Served at: /post/cve-2026-86259
│   ├── hackthebox-hercules.html  # Direct slash-less fallback
│   ├── cve-2026-88899.html
│   └── cve-2026-86259.html
├── posts/                        # Raw Markdown sources (.md)
│   ├── CVEs/
│   │   ├── CVE-2026-88899.md
│   │   └── CVE-2026-86259.md
│   └── HackTheBox/
│       └── HackTheBox-Hercules.md
├── build.py                      # SSG generator & real-time watcher
├── index.html                    # Homepage (< 220 lines)
├── posts.json                    # Lightweight metadata manifest
├── 404.html                      # Custom cyber terminal 404 page
└── README.md
```

### Active Catalog & URL Mapping
| Post | Tags | Author | Live URL |
| :--- | :--- | :--- | :--- |
| **HackTheBox - Sandcastle** | `htb`, `ctf`, `challenges` | `@uziii2208` | `https://uziii2208.github.io/post/hackthebox-sandcastle` |
| **HackTheBox - ZaZamarin** | `htb`, `ctf`, `challenges` | `@uziii2208` | `https://uziii2208.github.io/post/hackthebox-zazamarin` |
| **CVE-2026-88899** | `cve`, `research` | `@uziii2208` | `https://uziii2208.github.io/post/cve-2026-88899` |
| **CVE-2026-86543** | `cve`, `research` | `@uziii2208` | `https://uziii2208.github.io/post/cve-2026-86543` |
| **CVE-2026-86259** | `cve`, `research` | `@uziii2208` | `https://uziii2208.github.io/post/cve-2026-86259` |
| **HackTheBox - Sorcery** | `htb`, `ctf`, `linux` | `@0xdf` | `https://uziii2208.github.io/post/hackthebox-sorcery` |
| **HackTheBox - Hercules** | `htb`, `ctf`, `windows` | `@uziii2208` | `https://uziii2208.github.io/post/hackthebox-hercules` |

---

## ⚡ Adding a New Write-Up & Updating `build.py`

Adding a new write-up consists of **3 straightforward steps**: creating the Markdown file, optionally customizing the hero banner in `build.py`, and executing the build generator.

### Step 1: Create Markdown File with Frontmatter
Add your `.md` file anywhere inside the `posts/` directory (e.g. `posts/HackTheBox/HackTheBox-MyTarget.md` or `posts/CVEs/CVE-2026-XXXXX.md`):

```markdown
---
title: "HackTheBox - Target: Exploit Vector, Chained Vulnerabilities & Root PrivEsc"
date: 2026-09-18
tags: [htb, ctf, linux]
author: "@uziii2208"
# password: "optional-secret-passphrase"   # Uncomment for AES-256-GCM client-side encryption
---

## Overview
Executive summary and vulnerability disclosure statement...

## Foothold
Analysis and initial exploitation steps...
```

#### Frontmatter Field Specifications:
- `title` *(required)*: Full descriptive title of the advisory or walkthrough.
- `date` *(required)*: ISO date `YYYY-MM-DD` for chronological sorting.
- `tags` *(required)*: Array of relevant category tags (e.g. `[htb, ctf, linux]`, `[cve, research]`).
- `author` *(optional, defaults to `@uziii2208`)*: Set author handle (e.g. `@0xdf`, `@uziii2208`) for accurate research attribution in the hero banner and metadata.
- `password` *(optional)*: If specified, the post content will be cryptographically encrypted with **AES-256-GCM** (PBKDF2-HMAC-SHA256 with 600,000 rounds) at compile time. Visitors must provide the key to decrypt in-browser.

---

### Step 2: (Optional) Customize Hero Banner in `build.py`
The generator renders a 1200×630 OpenGraph / Post Hero banner image (`post/<slug>/hero.png`) for each post. 

By default, `build.py` dynamically infers badges (`0-DAY ADVISORY`, `HTB // ROOT PWNED`, `CTF // CHALLENGE SOLVED`) and extracts the first sentence of the write-up as the summary. If you want **custom editorial text and custom badges**, add an entry in `build_hero_html_template()` inside `build.py`:

```python
    # Locate build_hero_html_template() in build.py (around line 1510):
    elif "mytarget" in slug_lower:
        badge = "MEDIUM // ROOT PWNED"          # e.g. "CRITICAL // CVSS 9.8", "INSANE // ROOT PWNED"
        repro_label = "ROOT ACCESS // VERIFIED"    # e.g. "100% DETERMINISTIC TRIGGER", "FLAG CAPTURED // VERIFIED"
        summary_desc = "Exploiting blind SQL injection to bypass auth, chained with SSRF to internal Docker daemon for root RCE."
```

> [!NOTE]
> **Hero Banner 3-Column Layout**:
> The bottom spec strip automatically renders 3 clean columns:
> 1. `// PUBLISHED`: `YYYY-MM-DD` (Crimson accent)
> 2. `// AUDIT RIGOR`: Verification proof status (`#22c55e` Green)
> 3. `// RESEARCHER / AUTHOR`: Author handle with glowing dot indicator
>
> *(Target System & Vulnerability Class were intentionally deprecated for a cleaner, high-contrast editorial look).*

---

### Step 3: Run the Build Compiler
Compile your write-up into static assets and generate hero banners:

```bash
python build.py
```

What `build.py` does automatically:
1. **Compiles Markdown**: Converts markdown to semantic HTML with syntax highlighting, TOC generation, and copy-buttons.
2. **Generates Hero Images**: Uses Playwright to render high-res 1200×630 hero PNGs (`post/<slug>/hero.png` and `og-hero.png`) with embedded pixel font `uziii2208-pixel.ttf`.
3. **Creates Clean Static URLs**: Writes `post/<slug>/index.html` (no `.html` extension needed in URLs).
4. **Updates Global Manifests**: Synchronizes `posts.json` and `js/posts-data.js` for instant command palette search (<kbd>Ctrl+K</kbd> / <kbd>/</kbd>).
5. **Pre-renders Index & Archive**: Updates homepage `index.html` and dedicated archive `post/index.html`.

---

### 🛠️ Development & Live Preview Modes

#### Auto-Watch Mode (Instant Recompilation)
```bash
python build.py --watch
```
Watches the `posts/` folder for any modified, added, or deleted `.md` files and recompiles in real time.

#### Local Development Server
```bash
python build.py --serve
# Or combined with real-time watch:
python build.py --watch --serve
```
View locally at: `http://localhost:8000`

---

> [!IMPORTANT]
> **Font Integrity Constraint**:
> Never rename or overwrite `fonts/uziii2208-pixel.ttf`. `build.py` base64-embeds this file directly into the Playwright headless renderer to guarantee 100% pixel-perfect headings without FOUT or system font fallback errors.

---

## 🔮 Cyber Effects & Trendy UI Innovations (Thinking Out of the Box)

1. **Interactive Cyber Constellation Canvas (`#cyber-canvas`)**:
   - Dynamic 2D mesh of red nodes with connecting laser lines in the hero section.
   - Mouse proximity interaction: tracks your cursor, pulling and connecting nearby nodes with glowing laser lines.
2. **Hacker Text Scrambler / Decoder**:
   - Authentic cyberpunk character-scramble decoding effect on page load and logo hover.
3. **Synthesized Web Audio Cyber SFX (Pure Web Audio API)**:
   - High-tech, futuristic sound design synthesized purely in code (no external MP3 files, 0ms latency).
   - Audio feedback on button clicks, code copies, and modal triggers.
   - Includes a sleek **`[SFX: ON/OFF]`** toggle in the navbar that persists preferences.
4. **Spotlight Command Palette HUD (<kbd>Ctrl+K</kbd> or <kbd>/</kbd>)**:
   - Floating hacker modal with blurred backdrop, red glowing border, real-time fuzzy search, and keyboard arrow navigation.
5. **Live Hacker Telemetry HUD Bar**:
   - Real-time animated ticker: `[NODE: ZERO_PWN // ONLINE] • [INTEL: CONFIRMED WRITE-UPS] • [CIPHER: TLS_AES_256_GCM]`.
6. **Exploit Screenshot Lightbox**:
   - Click any proof-of-concept screenshot (e.g. the 26 Hercules images) to open a full-resolution zoom overlay.
7. **Laser Reading Progress Bar**:
   - Glowing red laser along the top of the viewport tracking your reading percentage smoothly.
8. **Cyber Code Chrome & One-Click Copy**:
   - Terminal window headers with terminal dots, language badges (`BASH`, `PYTHON`, `HTTP`), and animated copy buttons.
