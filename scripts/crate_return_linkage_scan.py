#!/usr/bin/env python3
from __future__ import annotations
"""
Link base-slot installers back to callback functions via a caller graph scan:
- Build function->callees and callee->callers maps by parsing exported JSONL decompilations.
- Seed from known base-slot installer callsites (from crate_slot38_installs.csv and crate_scheduler_map.csv slot==0x38 callers).
- Traverse callers up to a small depth to see if we reach any callback (cb1 or cb2) known to the scheduler.

Outputs:
- exports/crate_return_linkage.csv (cb, driver, depth, predicates, path)
- exports/crate_return_linkage.md
"""
import csv
import json
import re
from collections import deque
from pathlib import Path
from typing import Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / 'exports'

def iter_jsonls():
    return sorted(EXP.glob('bundle_*.jsonl'))

SCHED = EXP / 'crate_scheduler_map.csv'
SLOT38 = EXP / 'crate_slot38_installs.csv'

CALL_PAT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*|FUN_[0-9a-fA-F]{5,})\s*\(")


def load_code() -> Dict[str, str]:
    code: Dict[str, str] = {}
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
                if name and decomp and name not in code:
                    code[name] = decomp
    return code


def build_callmaps(code: Dict[str, str]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    f2c: Dict[str, Set[str]] = {}
    c2f: Dict[str, Set[str]] = {}
    for name, text in code.items():
        callees: Set[str] = set()
        for m in CALL_PAT.finditer(text):
            cal = m.group(1)
            if cal in ('if', 'for', 'while', 'switch'):
                continue
            if cal == name:
                continue
            callees.add(cal)
        if callees:
            f2c[name] = callees
            for cal in callees:
                c2f.setdefault(cal, set()).add(name)
    return f2c, c2f


def load_scheduler() -> Tuple[Set[str], Set[str], Set[str]]:
    cb1s: Set[str] = set()
    cb2s: Set[str] = set()
    callers: Set[str] = set()
    if not SCHED.exists():
        return cb1s, cb2s, callers
    with SCHED.open('r', encoding='utf-8', newline='') as f:
        rd = csv.DictReader(f)
        for r in rd:
            cb1 = (r.get('cb1') or '').strip()
            cb2 = (r.get('cb2') or '').strip()
            if cb1:
                cb1s.add(cb1)
            if cb2:
                cb2s.add(cb2)
            if (r.get('slot') == '0x38') and r.get('caller'):
                callers.add(r['caller'])
    return cb1s, cb2s, callers


def load_slot38_preds() -> Dict[str, Set[str]]:
    preds: Dict[str, Set[str]] = {}
    if not SLOT38.exists():
        return preds
    with SLOT38.open('r', encoding='utf-8', newline='') as f:
        rd = csv.DictReader(f)
        for r in rd:
            fn = r.get('function') or ''
            pred = (r.get('predicate') or '').strip() or '(none found)'
            if fn:
                preds.setdefault(fn, set()).add(pred)
    return preds


def bfs_link(cbset: Set[str], drivers: Set[str], callers_map: Dict[str, Set[str]], max_depth: int = 4):
    links: List[Tuple[str, str, int, List[str]]] = []
    for drv in drivers:
        dq = deque([(drv, 0, [drv])])
        seen = {drv}
        while dq:
            cur, depth, path = dq.popleft()
            if depth > max_depth:
                continue
            cset = callers_map.get(cur, set())
            for caller in cset:
                if caller in seen:
                    continue
                seen.add(caller)
                npath = path + [caller]
                if caller in cbset:
                    links.append((caller, drv, depth + 1, list(reversed(npath))))
                dq.append((caller, depth + 1, npath))
    return links


def main():
    code = load_code()
    f2c, c2f = build_callmaps(code)
    cb1s, cb2s, base_callers = load_scheduler()
    slot38_preds = load_slot38_preds()

    # Load labels to canonicalize to FUN_* where possible
    labels_path = EXP / 'crate_labels.json'
    labels: Dict[str, str] = {}
    if labels_path.exists():
        try:
            labels = json.loads(labels_path.read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            labels = {}
    # Build reverse labels: label -> FUN_*
    rev_labels: Dict[str, str] = {}
    for fun, lab in labels.items():
        if isinstance(lab, str) and fun.startswith('FUN_'):
            rev_labels[lab] = fun

    def to_fun(name: str) -> str:
        # Already FUN_* or unknown label; prefer FUN_* if mapping exists
        if name.startswith('FUN_'):
            return name
        return rev_labels.get(name, name)

    # Canonicalize driver set
    drivers_raw = set(base_callers) | set(slot38_preds.keys())
    drivers = {to_fun(d) for d in drivers_raw}
    drivers = {d for d in drivers if d in c2f or d in code}  # keep only known to code map
    if not drivers:
        print('No drivers found; aborting.')
        return

    # Canonicalize callbacks to FUN_*
    cbset_raw = cb1s | cb2s
    cbset = {to_fun(c) for c in cbset_raw}
    links = bfs_link(cbset, drivers, c2f, max_depth=4)

    # Also derive direct links from scheduler rows: any base-slot install links cb1/cb2 to caller
    direct: List[Tuple[str, str, int, List[str]]] = []
    if SCHED.exists():
        with SCHED.open('r', encoding='utf-8', newline='') as f:
            rd = csv.DictReader(f)
            for r in rd:
                if r.get('slot') != '0x38':
                    continue
                caller = r.get('caller') or ''
                if not caller:
                    continue
                for cbk in (r.get('cb1') or '', r.get('cb2') or ''):
                    if not cbk:
                        continue
                    # Canonicalize callback and caller to FUN_* when possible
                    cb_fun = to_fun(cbk)
                    drv_fun = to_fun(caller)
                    # Compose a simple path label
                    path = [drv_fun, 'SCHED_INSTALL', cb_fun]
                    direct.append((cb_fun, drv_fun, 0, path))

    # Merge direct links with BFS links
    links.extend(direct)

    uniq = {}
    for cb, drv, depth, path in links:
        key = (cb, drv)
        if key not in uniq or depth < uniq[key][0]:
            uniq[key] = (depth, path)

    rows = []
    for (cb, drv), (depth, path) in sorted(uniq.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        # Predicates are keyed by raw driver names; include both if necessary
        preds_set = set()
        if drv in slot38_preds:
            preds_set |= slot38_preds.get(drv, set())
        # also check label form
        label = labels.get(drv, '') if labels else ''
        if label and label in slot38_preds:
            preds_set |= slot38_preds.get(label, set())
        preds = '; '.join(sorted(preds_set)) if preds_set else ''
        rows.append({
            'cb': cb,
            'driver': drv,
            'depth': depth,
            'predicates': preds,
            'path': ' -> '.join(path),
        })

    EXP.mkdir(parents=True, exist_ok=True)
    with (EXP / 'crate_return_linkage.csv').open('w', encoding='utf-8', newline='') as f:
        wr = csv.DictWriter(f, fieldnames=['cb','driver','depth','predicates','path'])
        wr.writeheader()
        wr.writerows(rows)

    with (EXP / 'crate_return_linkage.md').open('w', encoding='utf-8') as f:
        f.write('# Crate: Return Linkage (cb → base)\n\n')
        if not rows:
            f.write('_No cb → base linkages found._\n')
        for r in rows:
            f.write(f"## {r['cb']}\n\n")
            f.write(f"- Driver: {r['driver']} (depth {r['depth']})\n")
            if r['predicates']:
                f.write(f"- Predicates: {r['predicates']}\n")
            f.write(f"- Path: {r['path']}\n\n")
    print(f"Wrote {len(rows)} linkage rows")


if __name__ == '__main__':
    main()
