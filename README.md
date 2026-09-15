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

### URL Mapping
| Post | Live URL |
| :--- | :--- |
| **HackTheBox Hercules** | `http://uziii2208.github.io/post/hackthebox-hercules` |
| **CVE-2026-88899** | `http://uziii2208.github.io/post/cve-2026-88899` |
| **CVE-2026-86259** | `http://uziii2208.github.io/post/cve-2026-86259` |

---

## ⚡ Adding a New Write-Up

Create a `.md` file anywhere inside `posts/` (e.g. `posts/CVEs/CVE-2026-XXXXX.md`):

```markdown
---
title: "CVE-2026-XXXXX: Remote Code Execution in TargetApp"
date: 2026-09-15
tags: [cve, research]
author: "@uziii2208"
---

## Overview
Your markdown write-up here...
```

Then run:
```bash
python build.py
```
This automatically generates:
1. `post/cve-2026-xxxxx/index.html`
2. `post/cve-2026-xxxxx.html`
3. Updates `posts.json` and `js/posts-data.js`

### Auto-Watch Mode (Real-Time Generation)
```bash
python build.py --watch
```
Watches `posts/` for any changes or new files, instantly compiling HTML pages in milliseconds.

### Local Development Server
```bash
python build.py --serve
# Or combined with watch:
python build.py --watch --serve
```
View locally at: `http://localhost:8000`

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
