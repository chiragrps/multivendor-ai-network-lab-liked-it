"""
Markdown → CLI corpus ingester.

Parses Cisco/Juniper/Arista command-reference Markdown files and appends
structured entries to cli-export.json.

Usage:
    cd 04_Scripts_Tools/DCN_Network_Tool
    venv/bin/python cli_corpus/ingest_md.py \
        ../../06_Documentation/Cisco_IOS_OSPF_Command_Reference.md \
        ../../06_Documentation/ENCOR_ENARSI_Command_Reference.md \
        --vendor Cisco --os ios

Each ```code block``` becomes one corpus entry. The title is taken from the
nearest preceding bold section heading; the description from any following
quote block (`> ...`).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# Heuristics: chapter title → category
# ──────────────────────────────────────────────────────────────────────────────


_CHAPTER_TO_CAT = [
    (r"vlan",            "VLAN"),
    (r"spanning.*tree",  "STP"),
    (r"inter.*vlan",     "Routing"),
    (r"eigrp",           "EIGRP"),
    (r"ospf",            "OSPF"),
    (r"redistribut",     "Redistribution"),
    (r"path.*control",   "Routing"),
    (r"\bbgp\b",         "BGP"),
    (r"\bip services\b", "IPServices"),
    (r"device manag",    "DeviceMgmt"),
    (r"infrastructure security", "Security"),
    (r"network assurance", "Assurance"),
    (r"wireless",        "Wireless"),
    (r"overlay|vrf",     "Overlay"),
]


def _cat_from_chapter(title: str) -> str:
    t = (title or "").lower()
    for pat, cat in _CHAPTER_TO_CAT:
        if re.search(pat, t):
            return cat
    return "Misc"


# ──────────────────────────────────────────────────────────────────────────────
# Parser
# ──────────────────────────────────────────────────────────────────────────────


_HEADER_RE  = re.compile(r"^##\s+Chapter\s+\d+:\s*(.+?)\s*$", re.MULTILINE)
_SUBHEAD_RE = re.compile(r"^###\s+(.+?)\s*$",                 re.MULTILINE)
_BOLD_RE    = re.compile(r"^\*\*`([^`]+)`\*\*",               re.MULTILINE)
_CODE_RE    = re.compile(r"```[a-z]*\n([\s\S]*?)```",         re.MULTILINE)
_QUOTE_RE   = re.compile(r"^>\s+(.+)$",                       re.MULTILINE)


def parse_markdown(path: Path, *, vendor: str, os_: str, role: str) -> list[dict]:
    """Walk the document linearly. For each fenced code block, attach the
    nearest preceding heading + bold-command + following quote block."""
    text = path.read_text(encoding="utf-8")
    out: list[dict] = []

    # Split into chapter-bounded windows so categories are tight.
    chapters: list[tuple[str, str]] = []
    prev_end = 0
    prev_title = ""
    for m in _HEADER_RE.finditer(text):
        chapters.append((prev_title, text[prev_end:m.start()]))
        prev_title = m.group(1).strip()
        prev_end = m.end()
    chapters.append((prev_title, text[prev_end:]))

    for chapter_title, body in chapters:
        if not body.strip():
            continue
        cat = _cat_from_chapter(chapter_title) if chapter_title else "Misc"
        # Identify section spans inside this chapter
        section_positions: list[tuple[int, str]] = [(0, chapter_title or "")]
        for sm in _SUBHEAD_RE.finditer(body):
            section_positions.append((sm.start(), sm.group(1).strip()))
        section_positions.sort()
        # Identify all code blocks with their start offsets
        for code_match in _CODE_RE.finditer(body):
            code = code_match.group(1).strip()
            if not code:
                continue
            # Find which section contains this offset
            offset = code_match.start()
            section = chapter_title
            for pos, name in section_positions:
                if pos <= offset:
                    section = name
                else:
                    break
            # Find the most recent **`...`** bold title before this code
            title = ""
            for bm in _BOLD_RE.finditer(body, 0, offset):
                title = bm.group(1).strip()
            if not title:
                # Use first non-empty line of the code as the title
                title = (code.splitlines() or [""])[0].strip()
            # Pull following quote-block description (within ~6 lines after code end)
            tail = body[code_match.end():code_match.end() + 600]
            quote_lines = _QUOTE_RE.findall(tail)
            desc_parts: list[str] = []
            if section and section != chapter_title:
                desc_parts.append(f"{cat} > {section}")
            elif chapter_title:
                desc_parts.append(f"{cat} > {chapter_title}")
            if quote_lines:
                desc_parts.append(" ".join(quote_lines).strip())
            desc = " — ".join([p for p in desc_parts if p]).strip()
            out.append({
                "os": os_,
                "vendor": vendor,
                "role": role,
                "cat": cat,
                "title": title[:120],
                "cmd": code,
                "desc": desc[:280] or (chapter_title or "Command reference"),
            })
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", help="Markdown reference files")
    ap.add_argument("--vendor", default="Cisco")
    ap.add_argument("--os",     default="ios", dest="os_")
    ap.add_argument("--role",   default="router")
    ap.add_argument("--corpus", default=str(Path(__file__).parent / "cli-export.json"))
    ap.add_argument("--dry-run", action="store_true", help="Just print stats, don't write")
    args = ap.parse_args()

    corpus_path = Path(args.corpus)
    existing: list[dict] = []
    if corpus_path.exists():
        try:
            existing = json.loads(corpus_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = []

    # Dedupe key: (vendor, os, cmd) — same command from same vendor/os shouldn't appear twice
    seen = {(e.get("vendor"), e.get("os"), (e.get("cmd") or "").strip()) for e in existing}
    new_entries: list[dict] = []
    for p in args.paths:
        path = Path(p)
        if not path.exists():
            print(f"skip (missing): {p}", file=sys.stderr); continue
        parsed = parse_markdown(path, vendor=args.vendor, os_=args.os_, role=args.role)
        added = 0
        for entry in parsed:
            key = (entry["vendor"], entry["os"], entry["cmd"].strip())
            if key in seen:
                continue
            seen.add(key)
            new_entries.append(entry)
            added += 1
        print(f"  {path.name}: {len(parsed)} parsed · {added} new")

    print(f"total existing: {len(existing)} · adding: {len(new_entries)}")
    if args.dry_run:
        return 0
    if new_entries:
        merged = existing + new_entries
        corpus_path.write_text(json.dumps(merged, indent=1, ensure_ascii=False), encoding="utf-8")
        print(f"wrote {corpus_path} — {len(merged)} total entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
