#!/usr/bin/env python3
"""
Auto-curate safe function renames from name_suggestions_*.csv into exports/suspects_bookmarks.json.

Policy (conservative):
- Only rename functions suggested as ReturnZero with high confidence (>= 0.9).
- Use a unique, descriptive pattern: stub_ret0_<orig_name> (e.g., stub_ret0_FUN_00008528)
- Optionally honor a small allowlist of specific suggestions (like Sync_Wait) if present.

For entries not already present in suspects_bookmarks.json, inject a minimal bookmark
record so the Ghidra script can set the name (category=naming-auto, tags=[auto,ret0]).

By default this script operates on MAIN.EXE only to minimize risk.
You can pass --all to process all binaries with name_suggestions_*.csv available.
"""
import csv
import json
import os
import sys
from glob import glob

ROOT = os.path.join(os.path.expanduser('~'), 'tb-re')
EXPORTS = os.path.join(ROOT, 'exports')
BOOK = os.path.join(EXPORTS, 'suspects_bookmarks.json')

ALLOW_SPECIFIC = {
    # If suggestions reference these specifically, normalize to our curated naming.
    'Sync_Wait': 'sync_wait',
}

def load_book():
    if not os.path.exists(BOOK):
        return {}
    with open(BOOK, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_book(data):
    with open(BOOK, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def parse_csv(p):
    out = []
    with open(p, 'r', encoding='utf-8', newline='') as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            try:
                row['confidence'] = float(row.get('confidence') or 0)
            except Exception:
                row['confidence'] = 0.0
            out.append(row)
    return out

def ensure_item(arr, name, ea_int):
    # Find existing item by name or ea
    for it in arr:
        if it.get('name') == name or it.get('ea') == ea_int:
            return it
    # Create a new one
    it = {
        'name': name,
        'ea': ea_int,
        'category': 'naming-auto',
        'tags': ['auto']
    }
    arr.append(it)
    return it

def curate_for_bin(bin_name, data):
    # Load suggestions CSV
    csv_path = os.path.join(EXPORTS, f'name_suggestions_{bin_name}.csv')
    if not os.path.exists(csv_path):
        return 0
    suggestions = parse_csv(csv_path)

    # Bookmarks bucket for this bin
    items = data.get(bin_name) or []
    changed = 0

    for row in suggestions:
        name = row.get('name')
        ea = row.get('ea') or ''
        proposed = (row.get('proposed') or '').strip()
        conf = row.get('confidence') or 0.0
        if not name or not ea:
            continue
        try:
            ea_int = int(ea, 16)
        except Exception:
            # ea might be decimal already
            try:
                ea_int = int(ea)
            except Exception:
                continue

        # Only accept ReturnZero high-confidence renames automatically
        if proposed == 'ReturnZero' and conf >= 0.9:
            new_name = f'stub_ret0_{name}'
            it = ensure_item(items, name, ea_int)
            # annotate and set new_name if different
            tags = set(it.get('tags') or [])
            tags.update(['auto', 'ret0'])
            it['tags'] = sorted(tags)
            if it.get('category') is None:
                it['category'] = 'naming-auto'
            if it.get('new_name') != new_name:
                it['new_name'] = new_name
                changed += 1
            continue

        # Normalize a tiny set of known labels (if ever suggested)
        if proposed in ALLOW_SPECIFIC:
            new_name = ALLOW_SPECIFIC[proposed]
            it = ensure_item(items, name, ea_int)
            tags = set(it.get('tags') or [])
            tags.update(['auto'])
            it['tags'] = sorted(tags)
            if it.get('category') is None:
                it['category'] = 'naming-auto'
            if it.get('new_name') != new_name:
                it['new_name'] = new_name
                changed += 1

    data[bin_name] = items
    return changed

def main():
    only = None
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        pass
    else:
        # default MAIN.EXE only
        only = 'MAIN.EXE'

    # Discover binaries from available CSVs
    bins = []
    for p in glob(os.path.join(EXPORTS, 'name_suggestions_*.csv')):
        b = os.path.splitext(os.path.basename(p))[0].replace('name_suggestions_', '')
        bins.append(b)
    if only:
        bins = [b for b in bins if b == only]
    if not bins:
        print('No name_suggestions CSVs found to process.')
        return

    data = load_book()
    total = 0
    for b in bins:
        total += curate_for_bin(b, data)

    if total:
        save_book(data)
        print(f'Updated {total} rename entries across {len(bins)} binaries.')
    else:
        print('No changes made (nothing new to curate).')

if __name__ == '__main__':
    main()
