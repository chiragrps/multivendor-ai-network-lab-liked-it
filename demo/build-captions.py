#!/usr/bin/env python3.13
"""
Caption-burner for source-recording.mov

Approach:
1. Pre-render each unique caption (top badge + bottom subtitle) as a transparent
   PNG card sized to the final 1920x1080 frame.
2. Use ffmpeg's overlay filter (built into stock Homebrew ffmpeg, unlike drawtext)
   with enable='between(t,start,end)' to composite each card over the source.
3. Encode H.264 + faststart for LinkedIn delivery.
"""
import subprocess, sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).parent
SRC = HERE / "source-recording.mov"
DST = HERE / "source-recording-captioned.mp4"
CARDS = HERE / "caption-cards"
CARDS.mkdir(exist_ok=True)

W, H = 1920, 1080

# Fonts — Helvetica.ttc on macOS has multiple weights
FONT_BOLD = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"
FONT_REG = "/System/Library/Fonts/Supplemental/Arial.ttf"
if not Path(FONT_BOLD).exists():
    FONT_BOLD = "/System/Library/Fonts/Helvetica.ttc"
if not Path(FONT_REG).exists():
    FONT_REG = "/System/Library/Fonts/Helvetica.ttc"

# ─── Timeline: (start, end, top_badge, bottom_caption) ─────────────
# v3 — re-anchored against verified frames at 56s, 85s, 95s.
# User navigates fast in 50-100s window — 2-4s per panel.
TIMELINE = [
    (0, 6,    "INTENT VERIFY",
     "Config-claimed BGP sessions vs observed · 100% score · 0 drift across 10 sessions"),
    (6, 10,   "DEVICE HEALTH CARDS",
     "Live CPU / MEM / BGP / OSPF · 26 devices · 5 sites · auto-fetch on landing"),
    (10, 22,  "BGP TOPOLOGY",
     "26 devices · 5 sites · 36 BGP sessions · live up/down · click any node to drill in"),
    (22, 28,  "AUTO-REMEDIATION",
     "Right-side panel scans all 10 FRR devices via HTTP proxy — no SSH needed"),
    (28, 34,  "STREAMING TELEMETRY",
     "gNMI subscribe over OpenConfig paths · sub-second metric stream from FRR"),
    (34, 42,  "SYSLOG RECEIVER",
     "UDP :5140 ring buffer · severity tiles click-to-filter · 7 CRIT · 7 WARN · 11 INFO"),
    (42, 48,  "AGENT CHAT · AI COORDINATOR",
     "Natural-language routing to 10 specialist agents · diagnosis · remediation · forecast"),
    (48, 54,  "AI INSIGHTS · DEEP ANALYSIS",
     "Per-device health score + grade · LLM narrative · drift · log intelligence · security"),
    (54, 55.5,  "PATH TRACE",
     "Hop-by-hop BFS across multi-vendor graph · eBGP / iBGP / LAN edge types"),
    (55.5, 57,  "CHANGE APPROVAL",
     "Describe intent → AI proposes CLI commands → human approves → pyATS diff captured"),
    (57, 64,  "CLI / TERMINAL",
     "Direct SSH to lab · BGP / Interfaces / Routes / Alarms quick-action chips"),
    (64, 72,  "NORNIR ENGINE",
     "Parallel fleet tasks across sites · ~10× faster than sequential Netmiko"),
    (72, 80,  "CHANGE VALIDATION · STATE DIFF",
     "Pre / post snapshot · BGP + interface deltas · pyATS-backed reconciliation"),
    (80, 82,  "EVAL HARNESS",
     "10 incident scenarios · keyword + LLM-as-judge dual scoring · Run All with progress"),
    (82, 86,  "CHAOS MONKEY",
     "Break BGP sessions in live lab · Observer-Actor self-heal · stress-tests remediation"),
    (86, 88,  "GAIT AUDIT",
     "Immutable AI audit trail · clickable target hostnames · tokens-in / tokens-out · JSONL export"),
    (88, 94,  "COMPLIANCE SCANNER",
     "BGP MD5 auth · prefix-limits · OSPF fast timers · router-ID · backbone area"),
    (94, 98,  "INVENTORY",
     "26 devices · free-text filter (hostname / site / vendor / model) · WCAG grid"),
    (98, 115, "EVAL HARNESS · RESULTS",
     "LLM judge 9.5/10 · keyword 8.67/10 · 3650 ms latency on OSPF area-mismatch scenario"),
]

REPO_URL = "github.com/gesh75/multivendor-ai-network-lab"

# ─── Build one card per timeline entry ─────────────────────────────
def build_card(idx: int, top: str, bottom: str) -> Path:
    out = CARDS / f"card_{idx:02d}.png"
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Top badge
    top_font = ImageFont.truetype(FONT_BOLD, 38)
    bbox = d.textbbox((0, 0), top, font=top_font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    pad_x, pad_y = 36, 14
    bx0 = (W - tw - 2 * pad_x) // 2
    by0 = 28
    bx1 = bx0 + tw + 2 * pad_x
    by1 = by0 + th + 2 * pad_y
    # Translucent dark fill + accent border
    d.rounded_rectangle((bx0, by0, bx1, by1),
                        radius=10,
                        fill=(22, 27, 34, 235),
                        outline=(88, 166, 255, 230), width=2)
    d.text((bx0 + pad_x - bbox[0], by0 + pad_y - bbox[1]),
           top, font=top_font, fill=(88, 166, 255, 255))

    # Bottom caption bar
    bot_font = ImageFont.truetype(FONT_REG, 30)
    bbox2 = d.textbbox((0, 0), bottom, font=bot_font)
    bw, bh = bbox2[2] - bbox2[0], bbox2[3] - bbox2[1]
    bar_pad_x, bar_pad_y = 32, 18
    bar_w = bw + 2 * bar_pad_x
    bar_h = bh + 2 * bar_pad_y
    bar_x0 = (W - bar_w) // 2
    bar_y0 = H - bar_h - 64
    bar_x1 = bar_x0 + bar_w
    bar_y1 = bar_y0 + bar_h
    d.rounded_rectangle((bar_x0, bar_y0, bar_x1, bar_y1),
                        radius=12,
                        fill=(0, 0, 0, 215))
    d.text((bar_x0 + bar_pad_x - bbox2[0], bar_y0 + bar_pad_y - bbox2[1]),
           bottom, font=bot_font, fill=(255, 255, 255, 255))

    img.save(out)
    return out


def build_watermark() -> Path:
    out = CARDS / "watermark.png"
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    f = ImageFont.truetype(FONT_REG, 22)
    bb = d.textbbox((0, 0), REPO_URL, font=f)
    tw = bb[2] - bb[0]
    th = bb[3] - bb[1]
    x = W - tw - 32
    y = H - th - 24
    # subtle drop-shadow box
    pad = 8
    d.rounded_rectangle(
        (x - pad, y - pad, x + tw + pad, y + th + pad),
        radius=6,
        fill=(0, 0, 0, 160),
    )
    d.text((x - bb[0], y - bb[1]), REPO_URL, font=f, fill=(255, 255, 255, 200))
    img.save(out)
    return out


print("Generating caption cards...")
cards = []
for i, (s, e, top, bot) in enumerate(TIMELINE):
    p = build_card(i, top, bot)
    cards.append((p, s, e))
    print(f"  ✓ card_{i:02d}.png  [{s:>4}s–{e:<4}s]  {top}")
wm = build_watermark()
print(f"  ✓ watermark.png")

# ─── Build ffmpeg filter chain ─────────────────────────────────────
# Inputs: 0 = source video; 1..N = caption cards; last = watermark
inputs = ["-i", str(SRC)]
for p, _, _ in cards:
    inputs += ["-i", str(p)]
inputs += ["-i", str(wm)]

# Filter graph: scale source → 1920×1080, then chain overlays gated by enable=
filters = []
filters.append("[0:v]scale=1920:1080:flags=lanczos[base]")
prev = "base"
for i, (_, s, e) in enumerate(cards):
    in_label = f"[{i + 1}:v]"
    out_label = f"v{i + 1}"
    enable = f"between(t,{s},{e})"
    filters.append(f"[{prev}]{in_label}overlay=x=0:y=0:enable='{enable}'[{out_label}]")
    prev = out_label
# Watermark on top, always visible
wm_in = f"[{len(cards) + 1}:v]"
filters.append(f"[{prev}]{wm_in}overlay=x=0:y=0[outv]")

filter_complex = ";".join(filters)

cmd = ["ffmpeg", "-y", *inputs,
       "-filter_complex", filter_complex,
       "-map", "[outv]",
       "-c:v", "libx264", "-preset", "slow", "-crf", "20",
       "-profile:v", "high", "-pix_fmt", "yuv420p",
       "-r", "30", "-movflags", "+faststart", "-an",
       str(DST)]

print("\nFilter graph length:", len(filter_complex), "chars")
print("Running ffmpeg...")
res = subprocess.run(cmd, capture_output=True, text=True)
print(res.stderr.strip().split("\n")[-4:][0] if res.stderr else "")
for line in res.stderr.splitlines()[-6:]:
    print(line)

if res.returncode != 0:
    print(f"\nffmpeg failed (exit {res.returncode})")
    sys.exit(1)

size = DST.stat().st_size / 1024 / 1024
print(f"\n✓ Done. {DST} ({size:.1f} MB)")
