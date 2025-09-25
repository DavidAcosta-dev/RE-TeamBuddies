#!/usr/bin/env python3
"""
Emit callers/callees for the top crate candidates to help triage their neighborhood.

Inputs:
- exports/crate_system_candidates.csv
- exports/bundle_ghidra.jsonl
- exports/curated_overlays.json (pretty names)

Output:
- exports/crate_candidate_edges.md
"""
import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'
BUNDLE = EXPORTS / 'bundle_ghidra.jsonl'
CAND = EXPORTS / 'crate_system_candidates.csv'
OUT = EXPORTS / 'crate_candidate_edges.md'


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


def load_bundle():
    bybin = defaultdict(dict)
    with open(BUNDLE, 'r', encoding='utf-8', errors='ignore') as f:
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
            name = fn.get('name')
            if not b or not name:
                continue
            ent = bybin[b].setdefault(name, {
                'name': name,
                'ea': fn.get('ea') or 0,
                'size': fn.get('size') or 0,
                'decompilation': r.get('decompilation') or '',
                'callers': list(r.get('callers') or []),
                'callees': list(r.get('callees') or []),
            })
            # prefer longer decomp
            dec = r.get('decompilation') or ''
            if dec and len(dec) > len(ent['decompilation']):
                ent['decompilation'] = dec
    return bybin


def main():
    if not CAND.exists():
        print('No crate_system_candidates.csv found; run the scanner first')
        return
    overlay = load_overlay()
    bundle = load_bundle()
    fnmap = bundle.get('MAIN.EXE', {})

    rows = []
    with open(CAND, 'r', encoding='utf-8', newline='') as f:
        rd = csv.DictReader(f)
        for r in rd:
            if r.get('bin') != 'MAIN.EXE':
                continue
            rows.append(r)
    # sort by score desc then distance asc
    rows.sort(key=lambda r: (int(r.get('score') or 0), -(int(r.get('distance') or 99))), reverse=True)
    top = rows[:20]

    with OUT.open('w', encoding='utf-8') as f:
        f.write('# Crate candidate callers/callees (MAIN.EXE)\n\n')
        for r in top:
            name = r.get('name') or ''
            ent = fnmap.get(name)
            if not ent:
                continue
            pretty = overlay['MAIN.EXE'].get(name, name)
            f.write(f"## {pretty} ({name}) @ 0x{ent['ea']:08x} | score={r.get('score')} | d={r.get('distance')}\n\n")
            # callers
            f.write('### callers\n\n')
            callers = ent.get('callers') or []
            if callers:
                for c in callers[:40]:
                    f.write(f"- {overlay['MAIN.EXE'].get(c, c)} ({c})\n")
            else:
                f.write('(none)\n')
            f.write('\n')
            # callees
            f.write('### callees\n\n')
            callees = ent.get('callees') or []
            if callees:
                for c in callees[:40]:
                    f.write(f"- {overlay['MAIN.EXE'].get(c, c)} ({c})\n")
            else:
                f.write('(none)\n')
            f.write('\n')
    print('Wrote', OUT)


if __name__ == '__main__':
    main()
