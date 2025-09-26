#!/usr/bin/env python3
"""
apply_suggestions_threshold.py

Aggressively apply suggested names to bookmarks when functions meet strong
evidence thresholds. Uses Q12 candidates, integrator map, and the rename
checklist for suggested_name text. Applies only when new_name is empty.

Criteria:
    - GAME.BIN:
            (integrator && direct_pos && axes=='Z') OR
            pos_hits >= 16 OR
            (basis_dest_hits + basis_src_hits) >= 40
    - MAIN.EXE (stricter):
            (integrator && direct_pos && axes=='Z') OR
            pos_hits >= 24 OR
            (basis_dest_hits + basis_src_hits) >= 60

Output: updates exports/suspects_bookmarks.json in-place.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"
BOOK = EXPORTS / "suspects_bookmarks.json"
Q12_JSON = EXPORTS / "q12_math_candidates.json"
INTEGRATOR_CSV = EXPORTS / "physics_integrator_map.csv"
CHECKLIST = EXPORTS / "rename_checklist.csv"


def load_q12(path: Path) -> dict[str, dict]:
    data = json.loads(path.read_text(encoding='utf-8'))
    out: dict[str, dict] = {}
    for e in data.get('candidates', []):
        out[e.get('name')] = e
    return out


def load_integrators(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    import csv as _csv
    out: dict[str, dict] = {}
    with path.open('r', encoding='utf-8', newline='') as fh:
        reader = _csv.DictReader(fh)
        for row in reader:
            nm = row.get('function')
            if nm:
                out[nm] = row
    return out


def load_checklist(path: Path) -> dict[tuple[str,str], dict]:
    out: dict[tuple[str,str], dict] = {}
    with path.open('r', encoding='utf-8', newline='') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            out[(row.get('binary'), row.get('function'))] = row
    return out


def pick_suggested(row: dict | None, q: dict | None, integ: dict | None) -> str:
    if row:
        s = row.get('suggested_name') or row.get('suggested')
        if s:
            return s
    # fallback heuristic
    pos = (q or {}).get('pos_hits', 0)
    bd = (q or {}).get('basis_dest_hits', 0)
    bs = (q or {}).get('basis_src_hits', 0)
    if integ and integ.get('direct_pos_write','0')=='1' and integ.get('axes')=='Z' and pos:
        return 'phys_integrate_pos_z_auto'
    if (bd + bs) >= 60:
        return 'orient_basis_update_auto'
    if pos >= 24:
        return 'phys_pos_update_auto'
    return 'q12_candidate'


def main() -> None:
    if not (BOOK.exists() and Q12_JSON.exists()):
        raise SystemExit('Missing exports; run the generators first.')
    qmap = load_q12(Q12_JSON)
    imap = load_integrators(INTEGRATOR_CSV)
    clmap = load_checklist(CHECKLIST) if CHECKLIST.exists() else {}
    data = json.loads(BOOK.read_text(encoding='utf-8'))

    changed = 0
    scanned = 0
    for bin_name, items in list(data.items()):
        if not isinstance(items, list):
            continue
        for it in items:
            nm = it.get('name')
            if not nm:
                continue
            scanned += 1
            if it.get('new_name'):
                continue
            q = qmap.get(nm)
            if not q:
                continue
            pos = q.get('pos_hits', 0)
            bd = q.get('basis_dest_hits', 0)
            bs = q.get('basis_src_hits', 0)
            integ = imap.get(nm)
            is_z = bool(integ and integ.get('direct_pos_write','0')=='1' and integ.get('axes')=='Z')
            # thresholds by binary
            if bin_name == 'GAME.BIN':
                cond = is_z or pos >= 16 or (bd + bs) >= 40
            elif bin_name == 'MAIN.EXE':
                cond = is_z or pos >= 24 or (bd + bs) >= 60
            else:
                cond = False
            if cond:
                sugg = pick_suggested(clmap.get((bin_name, nm)), q, integ)
                it['new_name'] = sugg
                if not it.get('category'):
                    it['category'] = 'naming'
                changed += 1

    if changed:
        BOOK.write_text(json.dumps(data, indent=2), encoding='utf-8')
        print(f"Applied {changed} aggressive suggestions (scanned {scanned} entries across binaries).")
    else:
        print(f"No changes (scanned {scanned} entries; none met thresholds or already named).")


if __name__ == '__main__':
    main()
