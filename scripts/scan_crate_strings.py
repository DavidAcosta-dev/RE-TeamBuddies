#!/usr/bin/env python3
"""
Scan MAIN.EXE functions for crate-related strings and surface candidates.

Inputs:
- exports/bundle_ghidra.jsonl
- exports/curated_overlays.json

Output:
- exports/crate_string_hits.md
"""
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'
BUNDLE = EXPORTS / 'bundle_ghidra.jsonl'
OUT = EXPORTS / 'crate_string_hits.md'

TOKENS = [r'crate', r'throw', r'pickup', r'pick up', r'drop', r'carry', r'pad']
RX = [re.compile(t, re.IGNORECASE) for t in TOKENS]


def load_overlay():
    overlay = defaultdict(dict)
    ov = EXPORTS / 'curated_overlays.json'
    if ov.exists():
        try:
            data = json.loads(ov.read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            return overlay
        for b, entries in (data or {}).items():
            for e in (entries or []):
                if isinstance(e, dict) and e.get('name') and e.get('new_name'):
                    overlay[b][e['name']] = e['new_name']
    return overlay


def main():
    overlay = load_overlay()
    perfn = {}
    with open(BUNDLE, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get('binary') != 'MAIN.EXE':
                continue
            fn = r.get('function') or {}
            name = fn.get('name') or ''
            if not name:
                continue
            ent = perfn.setdefault(name, {'s': set(), 'ea': fn.get('ea') or 0})
            for s in (r.get('strings_used') or []):
                if isinstance(s, dict):
                    sv = s.get('s') or s.get('str') or s.get('string') or s.get('value') or s.get('text') or ''
                else:
                    sv = s or ''
                if not isinstance(sv, str):
                    try:
                        sv = str(sv)
                    except Exception:
                        sv = ''
                for rx in RX:
                    if rx.search(sv):
                        ent['s'].add(sv)
    rows = []
    for name, ent in perfn.items():
        if ent['s']:
            rows.append((len(ent['s']), name, ent))
    rows.sort(key=lambda x: x[0], reverse=True)
    with OUT.open('w', encoding='utf-8') as f:
        f.write('# Crate-related string hits (MAIN.EXE)\n\n')
        for cnt, name, ent in rows[:120]:
            pretty = overlay['MAIN.EXE'].get(name, name)
            f.write(f"- 0x{ent['ea']:08x} {pretty} ({name}) | strings={cnt}\n")
            for s in list(sorted(ent['s']))[:10]:
                f.write(f"  - \"{s}\"\n")
            f.write('\n')
    print('Wrote', OUT)


if __name__ == '__main__':
    main()
