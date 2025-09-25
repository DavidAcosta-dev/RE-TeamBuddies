#!/usr/bin/env python3
"""
Scan one or more binary files for occurrences of strings from a text dump (e.g., eng_ascii_l1.txt).

Usage:
  python scripts/xref_strings_in_binaries.py exports/eng_ascii_l1.txt assets/TeamBuddiesGameFiles --ext .EXE .BIN

Writes:
  exports/xref_bin_strings_<stem>.md
"""
import os, sys, re
from pathlib import Path

OFFSET_RE = re.compile(r'^===== OFFSET', re.I)

def load_strings(txt_path: Path, min_len: int = 4):
    lines = []
    for raw in txt_path.read_text(encoding='utf-8', errors='ignore').splitlines():
        s = raw.strip()
        if not s or OFFSET_RE.match(s):
            continue
        if len(s) >= min_len and re.search(r'[A-Za-z]', s):
            lines.append(s)
    # de-dup while preserving order
    seen = set(); out = []
    for s in lines:
        if s not in seen:
            seen.add(s); out.append(s)
    return out

def iter_target_files(root: Path, exts):
    if root.is_file():
        yield root
        return
    for p in root.rglob('*'):
        if p.is_file() and (not exts or p.suffix.upper() in exts):
            yield p

def scan_file_for_strings(bin_path: Path, strings):
    try:
        data = bin_path.read_bytes()
    except Exception:
        return {}
    hits = {}
    for s in strings:
        try:
            needle = s.encode('latin-1', errors='ignore')
        except Exception:
            continue
        if not needle:
            continue
        pos = 0
        locs = []
        while True:
            i = data.find(needle, pos)
            if i < 0:
                break
            locs.append(i)
            pos = i + 1
            if len(locs) >= 64:
                break
        if locs:
            hits[s] = locs
    return hits

def main():
    if len(sys.argv) < 3:
        print('usage: python scripts/xref_strings_in_binaries.py <strings.txt> <file-or-dir> [--ext .EXE .BIN .OVL]')
        sys.exit(1)
    root = Path(__file__).resolve().parent.parent
    exports = root / 'exports'
    strings_path = Path(sys.argv[1])
    target = Path(sys.argv[2])
    exts = set()
    if '--ext' in sys.argv:
        i = sys.argv.index('--ext')
        exts = {e.upper() for e in sys.argv[i+1:]}
    strings = load_strings(strings_path)
    targets = list(iter_target_files(target, exts))
    out_md = exports / f"xref_bin_strings_{strings_path.stem}.md"
    total_hits = 0
    with out_md.open('w', encoding='utf-8') as f:
        f.write(f"# Binary String XRef for {strings_path.stem}\n\n")
        f.write(f"Scanned {len(targets)} files under {target}\n\n")
        for p in targets:
            hits = scan_file_for_strings(p, strings)
            if not hits:
                continue
            try:
                rel = p.resolve().relative_to(root)
            except Exception:
                rel = p.name
            f.write(f"## {rel}\n\n")
            for s, locs in hits.items():
                total_hits += 1
                if len(locs) > 10:
                    locs = locs[:10] + ['...']
                locs_fmt = ', '.join(str(x) for x in locs)
                f.write(f"- '{s}' @ [{locs_fmt}]\n")
            f.write("\n")
    print('Wrote', out_md, 'with', total_hits, 'distinct string hits')

if __name__ == '__main__':
    main()
