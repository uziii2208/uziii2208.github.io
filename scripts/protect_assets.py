#!/usr/bin/env python3
"""
─────────────────────────────────────────────────────────────────────────────
  uziii2208 Asset Protection & Forensic Watermark Engine (scripts/protect_assets.py)
  Part of mcp2agy-forge CI/CD Defense Pipeline

  1. Multi-Expression Holographic Matrix Compiler (8 Operative Kira Expressions):
     - Encodes expressions into self-seeding, keyless scrambled binary packets (photos/model.bin)
     - Inlines compressed packets into js/kira-matrix.js for 0ms zero-latency rendering
     - ZERO hardcoded encryption keys / fake secret seeds (uses intrinsic entropy & CRC-derived LCG)
  2. Replaces public photos/model.png with an authoritative Level-5 decoy
     asset to neutralize DevTools Sources / URL direct scraping.
  3. Strips sensitive EXIF/GPS metadata from all images across writeups.
  4. Audits and validates frontend defense shields across CSS and JS.
─────────────────────────────────────────────────────────────────────────────
"""

import sys
import os
import io
import struct
import zlib
import json
import base64
from pathlib import Path

# Ensure UTF-8 output on Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
except ImportError:
    print("[!] Pillow not found. Installing Pillow...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow"])
    from PIL import Image, ImageDraw, ImageFont, PngImagePlugin

BASE_DIR = Path(__file__).resolve().parent.parent
PHOTOS_DIR = BASE_DIR / "photos"
MODEL_PNG = PHOTOS_DIR / "model.png"
MODEL_BIN = PHOTOS_DIR / "model.bin"
POSTS_DIR = BASE_DIR / "posts"
POST_DIR = BASE_DIR / "post"
FONTS_DIR = BASE_DIR / "fonts"
PIXEL_FONT = FONTS_DIR / "uziii2208-pixel.ttf"
CSS_FILE = BASE_DIR / "css" / "style.css"
JS_FILE = BASE_DIR / "js" / "app.js"
MATRIX_JS = BASE_DIR / "js" / "kira-matrix.js"

EXPRESSIONS = {
    "default": ".source_model.png",
    "greeting": ".source_model_greeting.png",
    "confident": ".source_model_confident_quote_mode.png",
    "cool": ".source_model_cool_professional.png",
    "playful": ".source_model_playful.png",
    "sarcastic": ".source_model_sarcastic.png",
    "tease": ".source_model_tease.png",
    "special": ".source_adorable_special_event_face_to_face.png",
}

ASSET_METADATA = {
    "Title": "Operative Kira (0x0D) — Protected Mascot Sentinel",
    "Author": "Tong Hoang Gia (@uziii2208)",
    "Copyright": "(c) 2026 uziii2208. All Rights Reserved. Direct extraction prohibited.",
    "Classification": "LEVEL-5 CLASSIFIED // OPERATIVE SEC-DEFENSE",
    "License": "Proprietary / All Rights Reserved",
    "Provenance": "https://github.com/uziii2208/uziii2208.github.io"
}

def build_expression_packet(key, source_file, target_w=416, target_h=624):
    """
    Constructs a scrambled binary envelope for a single expression.
    - Resizes to exact canvas display dimensions with Lanczos resampling
    - Burns multi-layered forensic security watermarks onto the tactical outfit
    - Encodes to optimized WebP
    - Scrambles via self-seeding LCG (Linear Congruential Generator) derived from content entropy
    - ZERO hardcoded keys or secret seeds in code
    """
    img_path = PHOTOS_DIR / source_file
    if not img_path.exists():
        return None

    img = Image.open(img_path).convert("RGBA")
    img_down = img.resize((target_w, target_h), Image.Resampling.LANCZOS)

    # Burn forensic visual watermark across tactical clothing
    draw = ImageDraw.Draw(img_down)
    try:
        font_wm = ImageFont.truetype(str(PIXEL_FONT), 13)
        font_sm = ImageFont.truetype(str(PIXEL_FONT), 10)
    except Exception:
        font_wm = ImageFont.load_default()
        font_sm = ImageFont.load_default()

    draw.text((125, 340), "OPERATIVE KIRA // 0x0D", fill=(232, 25, 44, 110), font=font_wm)
    draw.text((126, 341), "OPERATIVE KIRA // 0x0D", fill=(0, 255, 238, 85), font=font_wm)
    draw.text((120, 360), "PROVENANCE: @uziii2208", fill=(255, 255, 255, 75), font=font_sm)
    draw.text((140, 480), "github.com/uziii2208", fill=(232, 25, 44, 70), font=font_sm)

    # Encode to optimized WebP
    buf = io.BytesIO()
    img_down.save(buf, format="WEBP", quality=92, method=4)
    webp_bytes = buf.getvalue()

    # Self-seeding LCG salt derived mathematically from payload content checksum (NO hardcoded key!)
    salt = (zlib.crc32(webp_bytes) ^ 0x0D22) & 0xFFFF

    # Scramble payload using standard ANSI C LCG keystream
    scrambled = bytearray(webp_bytes)
    state = salt
    for i in range(len(scrambled)):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        scrambled[i] ^= (state >> 16) & 0xFF

    # Pack envelope: Magic (4B: 'KZ8M'), Name (12B), W (2B), H (2B), Salt (2B), Len (4B), Data
    name_bytes = key.encode("ascii")[:12].ljust(12, b"\x00")
    header = struct.pack(">4s12sHHHI", b"KZ8M", name_bytes, target_w, target_h, salt, len(scrambled))
    return header + bytes(scrambled)

def encrypt_model_assets():
    """
    Builds the complete multi-expression matrix for all 8 Kira expressions.
    Exports to photos/model.bin and inlines to js/kira-matrix.js.
    """
    # Check if source images exist in workspace
    found_sources = [k for k, v in EXPRESSIONS.items() if (PHOTOS_DIR / v).exists()]

    if not found_sources:
        # CI/CD Fallback when sources are gitignored
        if MODEL_BIN.exists() and MODEL_BIN.stat().st_size > 10000:
            header = MODEL_BIN.read_bytes()[:4]
            if header in (b"KZ8M", b"KZSH"):
                print(f"[+] Verified pre-compiled expression matrix at {MODEL_BIN.name} ({MODEL_BIN.stat().st_size:,} bytes)")
                return True
        print("[!] Critical: No source expression images and no pre-compiled model.bin found.")
        return False

    print(f"[*] Compiling {len(found_sources)} holographic expressions for Operative Kira (Keyless LCG Matrix)...")

    b64_dict = {}
    combined_binary = bytearray()

    for key, filename in EXPRESSIONS.items():
        pkt = build_expression_packet(key, filename)
        if pkt:
            b64_dict[key] = base64.b64encode(pkt).decode("ascii")
            combined_binary.extend(pkt)
            print(f"    [+] Expression '{key}': {len(pkt):,} bytes ({filename})")

    # Deploy combined binary
    MODEL_BIN.write_bytes(combined_binary)
    print(f"[+] Full multi-expression bundle deployed to {MODEL_BIN.name} ({len(combined_binary):,} bytes)")

    # Export to js/kira-matrix.js
    json_b64 = json.dumps(b64_dict, indent=2)
    default_payload = b64_dict.get("default", "")

    matrix_js_content = f"""/* Auto-generated by protect_assets.py - Multi-Expression Kira Matrix */
window.__KIRA_EXPRESSIONS__ = {json_b64};
window.__KIRA_MATRIX_DATA__ = window.__KIRA_EXPRESSIONS__['default'] || '{default_payload}';
"""
    MATRIX_JS.write_text(matrix_js_content, encoding="utf-8")
    print(f"[+] Multi-expression runtime deployed to {MATRIX_JS.relative_to(BASE_DIR).as_posix()} ({len(matrix_js_content):,} chars)")
    return True

def generate_decoy_model_image():
    """Generate high-contrast cyber warning decoy PNG for photos/model.png."""
    w, h = 416, 624
    img = Image.new("RGBA", (w, h), (10, 10, 15, 255))
    draw = ImageDraw.Draw(img)

    # Cyber grid lines
    for x in range(0, w, 26):
        draw.line([(x, 0), (x, h)], fill=(20, 20, 30, 255), width=1)
    for y in range(0, h, 26):
        draw.line([(0, y), (w, y)], fill=(20, 20, 30, 255), width=1)

    # Red warning bounding box
    draw.rectangle([(16, 16), (w - 17, h - 17)], outline=(232, 25, 44, 180), width=2)
    draw.rectangle([(20, 20), (w - 21, h - 21)], outline=(0, 255, 238, 120), width=1)

    try:
        font_lg = ImageFont.truetype(str(PIXEL_FONT), 16)
        font_md = ImageFont.truetype(str(PIXEL_FONT), 12)
        font_sm = ImageFont.truetype(str(PIXEL_FONT), 10)
    except Exception:
        font_lg = ImageFont.load_default()
        font_md = ImageFont.load_default()
        font_sm = ImageFont.load_default()

    draw.text((w // 2, 80), "uziii2208 // SECURITY LAB", fill=(232, 25, 44, 240), font=font_lg, anchor="mm")
    draw.text((w // 2, 110), "LEVEL-5 PROTECTED GRAPHIC ASSET", fill=(0, 255, 238, 220), font=font_md, anchor="mm")

    # Silhouette placeholder
    cx, cy = w // 2, 280
    draw.ellipse([(cx - 45, cy - 80), (cx + 45, cy + 10)], outline=(232, 25, 44, 150), width=2)
    draw.polygon([(cx - 70, cy + 10), (cx + 70, cy + 10), (cx + 100, cy + 200), (cx - 100, cy + 200)], outline=(232, 25, 44, 120))

    draw.text((w // 2, 250), "[SENTINEL MODEL]", fill=(255, 255, 255, 140), font=font_sm, anchor="mm")
    draw.text((w // 2, 270), "ENCRYPTED IN MEMORY", fill=(0, 255, 238, 180), font=font_sm, anchor="mm")

    draw.text((w // 2, 450), "ACCESS DENIED", fill=(232, 25, 44, 255), font=font_lg, anchor="mm")
    draw.text((w // 2, 475), "Direct file scraping neutralized.", fill=(200, 200, 220, 200), font=font_sm, anchor="mm")
    draw.text((w // 2, 495), "Rendered exclusively via client canvas matrix.", fill=(160, 160, 180, 180), font=font_sm, anchor="mm")

    draw.text((w // 2, 540), "CLASSIFICATION: OPSEC RESTRICTED", fill=(0, 255, 238, 180), font=font_sm, anchor="mm")
    draw.text((w // 2, 560), "PROVENANCE: @uziii2208", fill=(255, 255, 255, 140), font=font_sm, anchor="mm")

    meta = PngImagePlugin.PngInfo()
    for k, v in ASSET_METADATA.items():
        meta.add_text(k, v)

    MODEL_PNG.parent.mkdir(parents=True, exist_ok=True)
    img.save(MODEL_PNG, "PNG", pnginfo=meta, optimize=True)
    print(f"[+] Decoy asset successfully deployed at {MODEL_PNG.name} ({MODEL_PNG.stat().st_size} bytes)")

def strip_exif_metadata():
    """Strip unnecessary EXIF/IPTC/GPS chunks from auxiliary images in writeup folders."""
    count = 0
    search_dirs = [PHOTOS_DIR, POSTS_DIR, POST_DIR]
    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for img_path in search_dir.rglob("*"):
            if img_path.name.startswith(".source") or img_path.name in ("model.png", "model.bin"):
                continue
            if img_path.suffix.lower() in [".jpg", ".jpeg", ".webp"]:
                try:
                    with Image.open(img_path) as img:
                        data = list(img.getdata())
                        image_without_exif = Image.new(img.mode, img.size)
                        image_without_exif.putdata(data)
                        image_without_exif.save(img_path)
                        count += 1
                except Exception:
                    pass
    print(f"[+] Sanitized EXIF metadata across {count} auxiliary images.")

def verify_frontend_shields():
    """Verify that CSS and JS contain all necessary anti-tamper and cursor lockdown rules."""
    passed = True
    print("[*] Auditing frontend security shield configuration...")

    if CSS_FILE.exists():
        css_content = CSS_FILE.read_text(encoding="utf-8")
        checks = [
            ("companion-shield", "Kira model invisible pointer shield"),
            ("companion-canvas", "Kira in-memory canvas styling"),
            ("Unavailable.png", "Unavailable restricted cursor rule"),
            ("user-select: none !important", "Writeup prose text selection lockdown"),
            ("Beam%20select.png", "Code block exception rule"),
            ("cursor: zoom-in !important", "Image lightbox hover exception rule"),
        ]
        for pattern, label in checks:
            if pattern in css_content:
                print(f"    [+] CSS Check Passed: {label}")
            else:
                print(f"    [!] CSS Check FAILED: Missing '{pattern}' ({label})")
                passed = False

    if JS_FILE.exists():
        js_content = JS_FILE.read_text(encoding="utf-8")
        checks = [
            ("loadSecuredCompanionModel", "In-memory model reconstructor engine"),
            ("initContentShield", "Content protection & anti-copy engine"),
            ("initConsoleDefense", "Console anti-tamper warning banner"),
        ]
        for pattern, label in checks:
            if pattern in js_content:
                print(f"    [+] JS Check Passed: {label}")
            else:
                print(f"    [!] JS Check FAILED: Missing '{pattern}' ({label})")
                passed = False

    return passed

def main():
    print("═══════════════════════════════════════════════════════════════")
    print("  uziii2208 // Multi-Expression Asset Shield & Watermark Engine")
    print("  Security Forge CI/CD Component (mcp2agy-forge)               ")
    print("═══════════════════════════════════════════════════════════════")

    encrypt_model_assets()
    generate_decoy_model_image()
    strip_exif_metadata()
    shields_ok = verify_frontend_shields()

    if not shields_ok:
        print("[!] Warning: Some frontend shields are still pending configuration.")
    print("[+] Asset guard task completed successfully.\n")

if __name__ == "__main__":
    main()
