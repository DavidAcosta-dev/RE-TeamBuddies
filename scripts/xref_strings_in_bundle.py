#!/usr/bin/env python3
"""
Cross-reference strings from a text dump (e.g., eng_ascii_l1.txt) against bundle_ghidra.jsonl.

Usage:
  python scripts/xref_strings_in_bundle.py exports/eng_ascii_l1.txt [min_len=6]

Writes:
  exports/xref_strings_<stem>.md
"""
import os, sys, json, re
from pathlib import Path

# Resolve repo root relative to this script to avoid relying on user home layout
ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
ALL_BUNDLES = sorted(EXPORTS.glob('bundle_*.jsonl'))

OFFSET_RE = re.compile(r'^===== OFFSET', re.I)

def load_strings(txt_path: Path, min_len: int = 6):
    lines = []
    for raw in txt_path.read_text(encoding='utf-8', errors='ignore').splitlines():
        s = raw.strip()
        if not s or OFFSET_RE.match(s):
            continue
        # keep original line; also collect alnum-ish tokens split by whitespace
        if len(s) >= min_len and re.search(r'[A-Za-z]', s):
            lines.append(s)
    # de-dup while preserving order
    seen = set(); out = []
    for s in lines:
        if s not in seen:
            seen.add(s); out.append(s)
    return out

def scan_bundle(strings):
    """Scan all bundle_*.jsonl files for occurrences of the given strings.
    Matches are case-insensitive and check both decompilation text and strings_used if present.
    """
    results = {s: [] for s in strings}
    if not ALL_BUNDLES:
        return results
    # Pre-lower strings for faster comparisons
    lower_map = {s: s.lower() for s in strings}
    for bundle_path in ALL_BUNDLES:
        try:
            with bundle_path.open('r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except Exception:
                        continue
                    b = (r.get('binary') or '').strip()
                    fn = r.get('function') or {}
                    name = fn.get('name') or ''
                    ea = fn.get('ea') or 0
                    dec = (r.get('decompilation') or '')
                    dec_l = dec.lower() if dec else ''
                    sused = r.get('strings_used') or []
                    # Consolidate strings_used entries to a single lower string for quick checks
                    sused_l = [str(x).lower() for x in sused if x]
                    for s, sl in lower_map.items():
                        hit = False
                        if dec_l and sl in dec_l:
                            hit = True
                        elif sused_l and any(sl in x for x in sused_l):
                            hit = True
                        if hit:
                            results[s].append((b, name, ea))
        except FileNotFoundError:
            continue
    return results

def write_md(strings, matches, out_path: Path):
    with out_path.open('w', encoding='utf-8') as f:
        f.write(f"# String XRef for {out_path.stem}\n\n")
        total = 0
        for s in strings:
            hits = matches.get(s) or []
            if not hits:
                continue
            total += 1
            f.write(f"## {s}\n\n")
            for (b, name, ea) in hits[:40]:
                f.write(f"- {b}: {name} @ 0x{ea:08x}\n")
            f.write("\n")
    return out_path

def main():
    if len(sys.argv) < 2:
        print('usage: python scripts/xref_strings_in_bundle.py <strings.txt> [min_len=6]')
        sys.exit(1)
    spath = Path(sys.argv[1])
    min_len = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    strings = load_strings(spath, min_len=min_len)
    matches = scan_bundle(strings)
    outp = EXPORTS / f"xref_strings_{spath.stem}.md"
    write_md(strings, matches, outp)
    print('Wrote', outp)

if __name__ == '__main__':
    main()
