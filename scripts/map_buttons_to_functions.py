#!/usr/bin/env python3
"""
Map tutorial button IDs (from action_button_ids.json) to engine functions by scanning
decompilation for matching bitmasks (1<<id) and switch/case constants.

Inputs:
- exports/action_button_ids.json
- exports/bundle_ghidra.jsonl
- exports/suspects_bookmarks.json (for display names)
- exports/action_candidates_MAIN.EXE.csv (levels near dispatcher)

Outputs:
- exports/button_to_action_map.md (top 3 per action)
- updates exports/curated_overlays.json with curated action_* names for top matches
"""
import os, json, csv, re, collections
from pathlib import Path

ROOT = Path(os.path.expanduser('~'))/ 'tb-re'
EX = ROOT / 'exports'

BTN_JSON = EX / 'action_button_ids.json'
BUNDLE = EX / 'bundle_ghidra.jsonl'
BOOK = EX / 'suspects_bookmarks.json'
CANDS = EX / 'action_candidates_MAIN.EXE.csv'
CURR = EX / 'curated_overlays.json'

HEX_MASK_RE = re.compile(r'&\s*0x([0-9a-fA-F]+)\b')
CASE_RE = re.compile(r'\bcase\s+(\d+)\s*:')

def load_buttons():
    mp = json.loads(BTN_JSON.read_text(encoding='utf-8'))
    # normalize to int keys
    out = {}
    for k,v in mp.items():
        out[int(k)] = v
    return out

def load_bundle():
    bybin = collections.defaultdict(dict)
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
                'decompilation': '',
                'callers': set(),
                'callees': set(),
            })
            dec = r.get('decompilation') or ''
            if dec and len(dec) > len(ent['decompilation']):
                ent['decompilation'] = dec
            ent['callers'] |= set(r.get('callers') or [])
            ent['callees'] |= set(r.get('callees') or [])
    return bybin

def load_bookmarks():
    try:
        data = json.loads(BOOK.read_text(encoding='utf-8'))
    except Exception:
        return {}
    perbin = collections.defaultdict(dict)
    if isinstance(data, dict):
        for b, entries in (data.items() or []):
            best = {}
            for e in entries or []:
                orig = e.get('name') or e.get('fn')
                new = (e.get('new_name') or '').strip()
                if not orig or not new:
                    continue
                tags = set(e.get('tags') or [])
                if new.startswith('stub_ret0_') or ('auto' in tags or 'ret0' in tags):
                    w = 1
                elif new.startswith('suspect_'):
                    w = 2
                else:
                    w = 3
                if (orig not in best) or (w >= best[orig][0]):
                    best[orig] = (w, new)
            for k, (_w, n) in best.items():
                perbin[b][k] = n
    return perbin

def load_candidates_levels():
    lv = {}
    if not CANDS.exists():
        return lv
    with open(CANDS, 'r', encoding='utf-8', newline='') as f:
        rd = csv.DictReader(f)
        for row in rd:
            lv[row['name']] = int(row.get('lvl') or 99)
    return lv

def disp_name(bmarks, name: str) -> str:
    nn = bmarks.get('MAIN.EXE', {}).get(name)
    return nn or name

def score_matches(dec: str, btn_id: int):
    if not dec:
        return 0, {'mask_hits': 0, 'case_hits': 0}
    mask = 1 << btn_id
    mask_hits = sum(1 for m in HEX_MASK_RE.finditer(dec) if int(m.group(1), 16) == mask)
    case_hits = sum(1 for m in CASE_RE.finditer(dec) if int(m.group(1)) == btn_id)
    s = mask_hits * 2 + case_hits * 3
    return s, {'mask_hits': mask_hits, 'case_hits': case_hits}

def normalize_action_name(label: str) -> str:
    t = label.lower()
    t = t.replace(' ', '_').replace('/', '_or_').replace('-', '_')
    t = re.sub(r'[^a-z0-9_]', '', t)
    t = re.sub(r'_+', '_', t).strip('_')
    return t

def main():
    buttons = load_buttons()
    bundle = load_bundle()
    bmarks = load_bookmarks()
    levels = load_candidates_levels()
    fnmap = bundle.get('MAIN.EXE', {})

    # Limit search to a reasonable pool: near dispatcher per prior candidates or top degree
    pool = sorted(fnmap.values(), key=lambda e: (-(e['name'] in levels), levels.get(e['name'], 99), -len(e['callees']), e['name']))
    pool = pool[:600]

    results = {}
    for bid, label in buttons.items():
        ranked = []
        for ent in pool:
            s, meta = score_matches(ent.get('decompilation') or '', bid)
            if s <= 0:
                continue
            # Proximity bump if we have a level from candidates
            lvl = levels.get(ent['name'])
            if lvl == 1:
                s += 3
            elif lvl == 2:
                s += 1
            ranked.append((s, ent, meta, lvl if lvl is not None else -1))
        ranked.sort(key=lambda x: (-x[0], x[1]['name']))
        results[bid] = {'label': label, 'ranked': ranked[:5]}

    # Write markdown report
    out_md = EX / 'button_to_action_map.md'
    with out_md.open('w', encoding='utf-8') as f:
        f.write('# Button → Function mapping (heuristic)\n\n')
        for bid in sorted(results.keys()):
            label = results[bid]['label']
            f.write(f"## {bid} — {label}\n\n")
            rows = results[bid]['ranked']
            if not rows:
                f.write('(no matches found)\n\n')
                continue
            for i, (s, ent, meta, lvl) in enumerate(rows, start=1):
                f.write(f"- {i:02d}. {disp_name(bmarks, ent['name'])} ({ent['name']}) @ 0x{ent['ea']:08x} | score={s} | lvl={lvl} | mask_hits={meta['mask_hits']} | case_hits={meta['case_hits']}\n")
            f.write('\n')
    print('Wrote', out_md)

    # Update curated overlays with the top match per button (if score >= threshold)
    cur = {}
    if CURR.exists():
        try:
            cur = json.loads(CURR.read_text(encoding='utf-8'))
        except Exception:
            cur = {}
    if not isinstance(cur, dict):
        cur = {}
    arr = cur.get('MAIN.EXE') or []
    by_name = {e.get('name'): e for e in arr if isinstance(e, dict) and e.get('name')}
    updates = 0
    for bid, obj in results.items():
        rows = obj['ranked']
        if not rows:
            continue
        s, ent, meta, lvl = rows[0]
        if s < 3:
            continue
        base = normalize_action_name(obj['label'])
        new_name = f'action_{base}'
        # Only assign a curated name if not already curated to a non-suspect name
        cur_entry = by_name.get(ent['name'])
        if cur_entry and cur_entry.get('new_name', '').startswith('suspect_'):
            cur_entry['new_name'] = new_name
            updates += 1
        elif cur_entry is None:
            by_name[ent['name']] = {'name': ent['name'], 'new_name': new_name, 'tags': ['action','curated']}
            updates += 1
    cur['MAIN.EXE'] = list(by_name.values())
    CURR.write_text(json.dumps(cur, indent=2), encoding='utf-8')
    print('Updated', CURR, 'with', updates, 'curated action names')

if __name__ == '__main__':
    main()
