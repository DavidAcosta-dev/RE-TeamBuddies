#!/usr/bin/env python3
"""
Promote likely crate handlers by combining signals across:
- crate_system_candidates.csv (scored neighborhood + masks + cases + strings)
- crate_string_hits.md (string presence)
- action_button_ids.json (to anchor pickup/drop = button 2)

Writes updated entries into curated_overlays.json as suspect_crate_{pickup|drop|throw|pad}_NN
and refreshes action-curated names when applicable.
"""
import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EX = ROOT / 'exports'
CAND = EX / 'crate_system_candidates.csv'
STRH = EX / 'crate_string_hits.md'
CURR = EX / 'curated_overlays.json'
BTN = EX / 'action_button_ids.json'

ROLE_KEYWORDS = {
    'pickup': ['pickup', 'pick up', 'lift', 'grab'],
    'drop': ['drop', 'release', 'put down'],
    'throw': ['throw', 'lob'],
    'pad': ['pad'],
}

ROLE_ORDER = ['pickup', 'drop', 'throw', 'pad']

def load_buttons():
    if not BTN.exists():
        return {}
    try:
        return json.loads(BTN.read_text(encoding='utf-8'))
    except Exception:
        return {}


def parse_string_hits():
    # Returns set of names that have any crate-related string
    names = set()
    if not STRH.exists():
        return names
    try:
        text = STRH.read_text(encoding='utf-8')
    except Exception:
        return names
    # Lines like: - 0xXXXXXXXX pretty (NAME) | strings=K
    rx = re.compile(r'\(([^)]+)\)\s*\|\s*strings=')
    for line in text.splitlines():
        m = rx.search(line)
        if m:
            names.add(m.group(1))
    return names


def pick_role(row, string_names):
    # prefer explicit string hints
    pretty = (row.get('pretty') or '').lower()
    old = (row.get('name') or '').lower()
    combined = pretty + ' ' + old
    for role in ROLE_ORDER:
        for w in ROLE_KEYWORDS[role]:
            if w in combined:
                return role
    # fallbacks using features
    try:
        pm = int(row.get('pickup_mask_hit') or 0)
        pc = int(row.get('pickup_case_hit') or 0)
        dm = int(row.get('distinct_masks') or 0)
        sg = int(row.get('str_hits') or 0)
        pad = int(row.get('pad_hits') or 0)
    except Exception:
        pm = pc = dm = sg = pad = 0
    if pad > 0:
        return 'pad'
    if (pm + pc) >= 1:
        return 'pickup'
    if dm >= 2 and sg > 0:
        return 'throw'
    # string-only functions are still interesting; bias as 'crate'
    return 'crate'


def main():
    if not CAND.exists():
        print('No candidates CSV; aborting')
        return
    rows = []
    with CAND.open('r', encoding='utf-8', newline='') as f:
        rd = csv.DictReader(f)
        for r in rd:
            if r.get('bin') != 'MAIN.EXE':
                continue
            try:
                score = int(r.get('score') or 0)
                dist = int(r.get('distance') or 99)
            except Exception:
                score = 0; dist = 99
            rows.append((score, -dist, r))
    rows.sort(key=lambda x: (x[0], x[1]), reverse=True)

    string_names = parse_string_hits()

    # load curated overlays
    curated = {}
    if CURR.exists():
        try:
            curated = json.loads(CURR.read_text(encoding='utf-8'))
        except Exception:
            curated = {}
    if not isinstance(curated, dict):
        curated = {}
    arr = curated.get('MAIN.EXE') or []
    by_name = {e.get('name'): e for e in arr if isinstance(e, dict) and e.get('name')}

    updates = 0
    limit = 8
    for idx, (_s, _d, r) in enumerate(rows[:40], start=1):
        name = r.get('name') or ''
        if not name:
            continue
        # don’t override curated definitive names
        cur = by_name.get(name)
        if cur and cur.get('new_name', '').startswith('suspect_') is False:
            continue
        role = pick_role(r, string_names)
        new_name = f"suspect_crate_{role}_{idx:02d}"
        entry = dict(cur or {})
        tags = set((entry.get('tags') or [])) | {'crate', 'suspect'}
        entry.update({'name': name, 'new_name': new_name, 'tags': sorted(tags)})
        by_name[name] = entry
        updates += 1
        if updates >= limit:
            break

    curated['MAIN.EXE'] = list(by_name.values())
    CURR.write_text(json.dumps(curated, indent=2), encoding='utf-8')
    print('Updated', CURR, 'with', updates, 'crate suspects')


if __name__ == '__main__':
    main()
