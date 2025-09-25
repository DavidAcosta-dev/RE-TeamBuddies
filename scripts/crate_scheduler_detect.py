#!/usr/bin/env python3
from __future__ import annotations
"""
Detect scheduler call sites and extract slot offsets and callback pair.

Looks for lines calling FUN_00035324(context, *(actor+slot), cb1, cb2)
and records caller function, slot (0x38/0x3c/0x40), cb1, cb2, and binary.

Outputs:
  exports/crate_scheduler_map.csv
  exports/crate_scheduler_map.md
"""
import csv, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
OUT_CSV = EXPORTS / 'crate_scheduler_map.csv'
OUT_MD = EXPORTS / 'crate_scheduler_map.md'
LABELS = EXPORTS / 'crate_labels.json'

bundles = sorted(EXPORTS.glob('bundle_*.jsonl'))

CALL_RE = re.compile(r'FUN_00035324\s*\(')
FUN_RE = re.compile(r'FUN_[0-9a-fA-F]{6,}')
HEX_RE = re.compile(r'0x[0-9a-fA-F]{6,8}')
SLOT_TOKENS = ['+ 0x38', '+ 0x3c', '+ 0x40']

rows = []
seen = set()
labels = {}
if LABELS.exists():
    try:
        labels = json.loads(LABELS.read_text(encoding='utf-8', errors='ignore'))
    except Exception:
        labels = {}

def extract_args(line: str, m: re.Match) -> str | None:
    # Start right after the opening '('
    start = m.end()
    depth = 1
    i = start
    while i < len(line):
        ch = line[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return line[start:i]
        i += 1
    return None

for b in bundles:
    try:
        fh = b.open('r', encoding='utf-8', errors='ignore')
    except Exception:
        continue
    with fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            fn = obj.get('function', {}).get('name')
            if not fn:
                continue
            body = obj.get('decompilation') or ''
            text = body.replace('\r', ' ').replace('\n', ' ')
            for m in CALL_RE.finditer(text):
                args = extract_args(text, m) or ''
                funs = FUN_RE.findall(args)
                # Also accept hex addresses like 0x800240a0 and map to FUN_000240a0
                hexes = HEX_RE.findall(args)
                mapped = []
                for h in hexes:
                    try:
                        v = int(h, 16)
                        # Normalize KSEG0 0x8000_0000 base if present
                        if v >= 0x80000000:
                            v -= 0x80000000
                        mapped.append(f'FUN_{v:08x}')
                    except Exception:
                        continue
                # Merge keeping order preference: explicit FUN_ tokens first then mapped
                cb_list = funs + mapped
                cb1, cb2 = (cb_list[-2], cb_list[-1]) if len(cb_list) >= 2 else ('','')
                slot = ''
                for tok in SLOT_TOKENS:
                    if tok in args:
                        slot = tok.replace('+ ','')
                        break
                snippet = text[m.start():m.end()+64]
                key = (b.name, fn, slot, cb1, cb2, snippet)
                if key in seen:
                    continue
                seen.add(key)
                def lab(name: str) -> str:
                    return f"{labels.get(name, name)}"
                rows.append({
                    'binary': b.name,
                    'caller': labels.get(fn, fn),
                    'slot': slot,
                    'cb1': labels.get(cb1, cb1),
                    'cb2': labels.get(cb2, cb2),
                    'line': snippet.strip(),
                })

OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
with OUT_CSV.open('w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=['binary','caller','slot','cb1','cb2','line'])
    w.writeheader()
    for r in rows:
        w.writerow(r)

md = ['# Crate Scheduler Call Sites','','| Binary | Caller | Slot | CB1 | CB2 |','|--------|--------|------|-----|-----|']
for r in rows[:200]:
    md.append(f"| {r['binary']} | {r['caller']} | {r['slot']} | {r['cb1']} | {r['cb2']} |")
OUT_MD.write_text('\n'.join(md), encoding='utf-8')
print(f'Wrote {OUT_MD} ({len(rows)} sites)')
