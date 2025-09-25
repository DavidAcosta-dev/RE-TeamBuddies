#!/usr/bin/env python3
from __future__ import annotations
"""
Parse exports/crate_system_candidates.md into a normalized CSV.

Output:
  exports/crate_system_candidates.csv
Columns:
  binary, function, fun_addr_hex, score, masks, size, raw
"""
import csv, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
SRC = EXPORTS / 'crate_system_candidates.md'
OUT = EXPORTS / 'crate_system_candidates.csv'

line_re = re.compile(r'^-\s+([^.]+\.EXE):([^\s]+)\s+\((FUN_[0-9a-fA-F]+)\)\s+@\s+0x([0-9a-fA-F]+)\s*\|\s*.*?score=(\d+)\s*\|\s*masks=(\d+).*?size=(\d+)', re.I)

rows = []
if SRC.exists():
    for ln in SRC.read_text(encoding='utf-8', errors='ignore').splitlines():
        m = line_re.match(ln.strip())
        if m:
            binary, label, fun, addr, score, masks, size = m.groups()
            rows.append({
                'binary': binary,
                'function': fun,
                'label': label,
                'fun_addr_hex': f'0x{addr.lower()}',
                'score': int(score),
                'masks': int(masks),
                'size': int(size),
                'raw': ln.strip(),
            })

OUT.parent.mkdir(parents=True, exist_ok=True)
with OUT.open('w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=['binary','function','label','fun_addr_hex','score','masks','size','raw'])
    w.writeheader()
    for r in rows:
        w.writerow(r)

print(f'Wrote {OUT} ({len(rows)} rows)')
