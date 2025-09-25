#!/usr/bin/env python3
"""
Scan all exported decompilations for scheduler installs targeting base slot (+0x38),
and extract a nearby predicate if present.

Outputs:
- exports/crate_slot38_installs.csv
- exports/crate_slot38_installs.md
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / 'exports'

def iter_jsonls():
    return sorted(EXP.glob('bundle_*.jsonl'))

SCHED_CALL = re.compile(r"(FUN_00035324|FUN_00032278)\s*\(")
COND = re.compile(r"if\s*\((?P<cond>[^)]+)\)\s*{", re.IGNORECASE)

def load_jsonl() -> List[Dict[str, str]]:
    out = []
    for p in iter_jsonls():
        if not p.exists():
            continue
        with p.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                func = obj.get('function') or {}
                name = func.get('name') or obj.get('name')
                decomp = obj.get('decompilation') or obj.get('code') or ''
                if name and decomp:
                    out.append({'name': name, 'code': decomp})
    return out

def find_slot38_installs() -> List[Dict[str, str]]:
    funcs = load_jsonl()
    results: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for f in funcs:
        code = f['code']
        if 'FUN_00035324' not in code:
            continue
        lines = code.splitlines()
        for i, ln in enumerate(lines):
            if 'FUN_00035324' not in ln:
                continue
            # Look around the call to catch argument snippets and prior slot-ptr assignments
            window = '\n'.join(lines[i:i+4])
            prev_next = '\n'.join(lines[max(0, i-6):i+4])
            if ('+ 0x38' not in window and ' 0x38,' not in window and '(0x38' not in window
                and '+ 0x38' not in prev_next and ' 0x38,' not in prev_next and '(0x38' not in prev_next):
                continue
            # Backtrack up to 10 lines to find a predicate
            predicate = ''
            for j in range(max(0, i-10), i+1):
                m = COND.search(lines[j])
                if m:
                    predicate = m.group('cond').strip()
            key = (f['name'], ln.strip())
            if key in seen:
                continue
            seen.add(key)
            results.append({'function': f['name'], 'predicate': predicate, 'line': ln.strip()})
    return results

def write_outputs(rows: List[Dict[str, str]]):
    EXP.mkdir(parents=True, exist_ok=True)
    # Stable ordering by function then line
    rows = sorted(rows, key=lambda r: (r['function'], r['line']))
    # CSV
    with (EXP / 'crate_slot38_installs.csv').open('w', encoding='utf-8', newline='') as f:
        wr = csv.DictWriter(f, fieldnames=['function','predicate','line'])
        wr.writeheader()
        wr.writerows(rows)
    # MD
    with (EXP / 'crate_slot38_installs.md').open('w', encoding='utf-8') as f:
        f.write('# Slot 0x38 Scheduler Installs (Predicates)\n\n')
        for r in rows:
            f.write(f"## {r['function']}\n\n")
            f.write(f"- Predicate: {r['predicate'] or '(none found)'}\n\n")
            f.write('```c\n')
            f.write(r['line'] + '\n')
            f.write('```\n\n')

def main():
    rows = find_slot38_installs()
    write_outputs(rows)
    print(f"Wrote {len(rows)} slot 0x38 installs")

if __name__ == '__main__':
    main()
