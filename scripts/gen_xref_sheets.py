#!/usr/bin/env python3
"""
Generate concise cross-reference sheets for selected functions:
- Inputs: exports/bundle_<BIN>.jsonl, exports/callgraph_hubs_<BIN>.csv
- Output: exports/xref_<BIN>.md with sections per function (by name or EA)

For convenience, the default seed list focuses on core loop suspects around MAIN.EXE:
- main_update (or FUN_000090e0), sync_wait (or FUN_0001cc38), FUN_000211ac,
  FUN_00021c64, FUN_00021ff4, FUN_00023d74, FUN_00023f50, FUN_000240a0.

Usage:
  python scripts/gen_xref_sheets.py MAIN.EXE [name_or_ea ...]
If no function names are provided, the default seeds are used.
"""
import argparse
import csv
import json
import os
from collections import defaultdict

ROOT = os.path.join(os.path.expanduser('~'), 'tb-re')
EXPORTS = os.path.join(ROOT, 'exports')

DEFAULT_SEEDS = [
    'main_update', 'FUN_000090e0', 'sync_wait', 'FUN_0001cc38',
    'FUN_000211ac', 'FUN_00021c64', 'FUN_00021ff4', 'FUN_00023d74',
    'FUN_00023f50', 'FUN_000240a0'
]

def load_hubs(bin_name):
    hubs = {}
    p = os.path.join(EXPORTS, f'callgraph_hubs_{bin_name}.csv')
    if not os.path.exists(p):
        return hubs
    with open(p, 'r', encoding='utf-8', newline='') as f:
        rdr = csv.reader(f)
        # name,ea,size,in,out,degree,BIN
        for row in rdr:
            # Skip empty/malformed rows
            if not row or len(row) < 6:
                continue
            # Skip header if present
            if row[0].strip().lower() == 'name':
                continue
            try:
                name, ea, size, inn, out, degree, *_ = row
            except ValueError:
                # Row not matching expected columns
                continue
            def as_int(x):
                try:
                    return int(x)
                except Exception:
                    return 0
            hubs[name] = {
                'ea': ea,
                'size': as_int(size),
                'in': as_int(inn),
                'out': as_int(out),
                'degree': as_int(degree),
            }
    return hubs

def load_bundle(bin_name):
    bundle = []
    p = os.path.join(EXPORTS, f'bundle_{bin_name}.jsonl')
    if not os.path.exists(p):
        return bundle
    with open(p, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                bundle.append(json.loads(line))
            except Exception:
                pass
    return bundle

def load_bookmarks(bin_name):
    bm_path = os.path.join(EXPORTS, 'suspects_bookmarks.json')
    if not os.path.exists(bm_path):
        return []
    try:
        with open(bm_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data.get(bin_name, []) or []
    except Exception:
        return []

def _bm_weight(entry):
    # Prefer curated over suspect_* over auto-ret0
    tags = entry.get('tags') or []
    new_name = (entry.get('new_name') or '').strip()
    if 'auto' in tags:
        return 0
    if new_name.startswith('suspect_'):
        return 1
    return 2

def build_rename_maps(bookmarks):
    by_ea = {}
    by_name = {}
    for e in bookmarks:
        new_name = (e.get('new_name') or '').strip()
        if not new_name:
            continue
        ea = e.get('ea')
        name = e.get('name')
        w = _bm_weight(e)
        if isinstance(ea, int):
            cur = by_ea.get(ea)
            # Prefer later entries on equal weight (so curated overlays appended later can win)
            if (cur is None) or (w >= cur[0]):
                by_ea[ea] = (w, new_name)
        if name:
            cur = by_name.get(name)
            # Prefer later entries on equal weight
            if (cur is None) or (w >= cur[0]):
                by_name[name] = (w, new_name)
    # Strip weights
    by_ea = {ea: nm for ea, (w, nm) in by_ea.items()}
    by_name = {nm: new for nm, (w, new) in by_name.items()}
    return by_ea, by_name

def index_bundle(bundle):
    by_name = {}
    by_ea = {}
    for rec in bundle:
        fn = rec.get('function') or {}
        name = fn.get('name')
        ea = fn.get('ea')
        if name:
            by_name[name] = rec
        if ea is not None:
            by_ea[ea] = rec
    return by_name, by_ea

def resolve_targets(seed_tokens, by_name, by_ea, rename_by_name):
    targets = []
    if not seed_tokens:
        # Default seeds
        seed_tokens = DEFAULT_SEEDS
    # Build reverse map: curated/new_name -> original name (first win)
    # rename_by_name maps original -> new; invert it
    reverse_name = {}
    for orig, new in rename_by_name.items():
        if new and new not in reverse_name:
            reverse_name[new] = orig
    for tok in seed_tokens:
        if isinstance(tok, str) and tok.startswith('0x'):
            try:
                ea = int(tok, 16)
            except Exception:
                continue
            rec = by_ea.get(ea)
            if rec:
                targets.append(rec)
            continue
        # try by name first
        rec = by_name.get(tok)
        if rec:
            targets.append(rec)
            continue
        # try curated name -> original name mapping
        orig = reverse_name.get(tok)
        if orig:
            rec = by_name.get(orig)
            if rec:
                targets.append(rec)
                continue
        # accept FUN_ prefix fallbacks
        if tok.startswith('FUN_'):
            rec = by_name.get(tok)
            if rec:
                targets.append(rec)
    return targets

def md_section(rec, hubs, rename_by_ea, rename_by_name, index_by_name):
    fn = rec.get('function') or {}
    nm = fn.get('name')
    ea = fn.get('ea')
    size = fn.get('size')
    callers = rec.get('callers') or []
    callees = rec.get('callees') or []
    hub = hubs.get(nm) or {}
    h_ea = hub.get('ea')
    deg = hub.get('degree', 0)
    inn = hub.get('in', 0)
    out = hub.get('out', 0)

    def disp_name(name, ea_val=None):
        if ea_val is None:
            # Try to resolve EA via bundle index for better mapping
            rec2 = index_by_name.get(name)
            if rec2:
                ea2 = (rec2.get('function') or {}).get('ea')
                if isinstance(ea2, int) and ea2 in rename_by_ea:
                    return rename_by_ea[ea2]
        if isinstance(ea_val, int) and ea_val in rename_by_ea:
            return rename_by_ea[ea_val]
        # Fallback by name
        return rename_by_name.get(name, name)

    header_name = disp_name(nm, ea)
    lines = []
    lines.append(f"### {header_name} @ 0x{ea:08x} | size={size} | in={inn} out={out} deg={deg}")
    # Top callers/callees (first 10)
    if callers:
        renamed_callers = [disp_name(c) for c in callers[:10]]
        lines.append(f"- callers ({len(callers)}): " + ", ".join(renamed_callers))
    if callees:
        renamed_callees = [disp_name(c) for c in callees[:20]]
        lines.append(f"- callees ({len(callees)}): " + ", ".join(renamed_callees))
    return "\n".join(lines) + "\n"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('bin', help='Binary name e.g. MAIN.EXE or GAME.BIN')
    ap.add_argument('symbols', nargs='*', help='Function names or EAs (0x...)')
    args = ap.parse_args()

    hubs = load_hubs(args.bin)
    bundle = load_bundle(args.bin)
    if not bundle:
        print('No bundle found')
        return
    by_name, by_ea = index_bundle(bundle)
    bookmarks = load_bookmarks(args.bin)
    rename_by_ea, rename_by_name = build_rename_maps(bookmarks)
    targets = resolve_targets(args.symbols, by_name, by_ea, rename_by_name)
    if not targets:
        print('No targets resolved; nothing to do.')
        return

    outp = os.path.join(EXPORTS, f'xref_{args.bin}.md')
    with open(outp, 'w', encoding='utf-8') as f:
        f.write(f"# XRef sheet for {args.bin}\n\n")
        for rec in targets:
            f.write(md_section(rec, hubs, rename_by_ea, rename_by_name, by_name))
            f.write("\n")
    print(f'Wrote {outp} with {len(targets)} sections.')

if __name__ == '__main__':
    main()
