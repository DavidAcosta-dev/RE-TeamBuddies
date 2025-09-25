#!/usr/bin/env python3
"""
Identify action-mapping functions downstream of update_state_dispatch and propose suspect_action_* renames.

Outputs:
- exports/action_candidates_MAIN.EXE.{csv,md}
- updates/creates exports/curated_overlays.json entries with suspect_action_* names for MAIN.EXE

Heuristics:
- Seed at bookmark rename 'update_state_dispatch' within MAIN.EXE.
- Consider callees within depth<=2 of the seed.
- Score by: switch presence, struct access ("->"), bitmasks, input keywords, callsite proximity.
"""
import os, re, json, csv, collections
from pathlib import Path

ROOT = Path(os.path.expanduser('~'))/ 'tb-re'
EXPORTS = ROOT / 'exports'
BUNDLE_ALL = EXPORTS / 'bundle_ghidra.jsonl'
BOOKMARKS = EXPORTS / 'suspects_bookmarks.json'
CURATED = EXPORTS / 'curated_overlays.json'

BIT_RE = re.compile(r'&\s*0x[0-9a-fA-F]+')
EDGE_RE = re.compile(r'&\s*~')
KW_RE = re.compile(r'input|pad|button|joy|control', re.I)

def load_bundle(path: Path):
    bybin = collections.defaultdict(dict)
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
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

def load_bookmarks(path: Path = BOOKMARKS):
    perbin = collections.defaultdict(dict)
    if not path.exists():
        return perbin
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return perbin
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
                if (orig not in best) or (w > best[orig][0]):
                    best[orig] = (w, new)
            for k, (_w, n) in best.items():
                perbin[b][k] = n
    return perbin

def disp_name(bmarks, name: str) -> str:
    nn = bmarks.get('MAIN.EXE', {}).get(name)
    return nn or name

def neighborhood(fnmap:dict, seed:str, depth:int=2):
    if not seed or seed not in fnmap:
        return {}
    lvls = {seed:0}
    q = [seed]
    while q:
        cur = q.pop(0)
        lvl = lvls[cur]
        if lvl >= depth:
            continue
        for cal in fnmap[cur]['callees']:
            if cal in fnmap and cal not in lvls:
                lvls[cal] = lvl+1
                q.append(cal)
    return lvls

def find_update_state_dispatch_name(bmarks, fnmap):
    for orig, new in bmarks.get('MAIN.EXE', {}).items():
        if new == 'update_state_dispatch' and orig in fnmap:
            return orig
    # fallback: try to find a high-fanout function called by main_update
    # heuristic if rename not present
    # pick max outdegree among callees of main_update
    main = None
    for orig, new in bmarks.get('MAIN.EXE', {}).items():
        if new == 'main_update' and orig in fnmap:
            main = orig
            break
    if main:
        cals = list(fnmap[main]['callees'])
        if cals:
            return max(cals, key=lambda n: len(fnmap.get(n,{}).get('callees') or []), default=None)
    return None

def score_action_candidate(ent):
    dec = ent.get('decompilation') or ''
    # Ignore decomp stubs with bad-instruction warnings
    if 'Bad instruction' in dec or 'Truncating control flow' in dec:
        return 0, {'arrow': 0, 'masks': 0, 'edge': 0, 'size': ent.get('size') or 0}
    s = 0
    if 'switch' in dec:
        s += 6
    arrow = dec.count('->')
    s += min(arrow, 5)  # struct accesses
    masks = len(BIT_RE.findall(dec))
    s += min(masks, 4)
    if EDGE_RE.search(dec):
        s += 2
    if KW_RE.search(dec):
        s += 2
    # size heuristic: medium functions likely
    sz = ent.get('size') or 0
    if 32 <= sz <= 2000:
        s += 1
    return s, {'arrow': arrow, 'masks': masks, 'edge': 1 if EDGE_RE.search(dec) else 0, 'size': sz}

def propose_name(ent, idx, lvl):
    dec = ent.get('decompilation') or ''
    base = 'suspect_action'
    if 'switch' in dec:
        base += '_dispatch'
    elif re.search(r'move|walk|turn|rot|axis', dec, re.I):
        base += '_move'
    elif re.search(r'fire|shoot|attack|throw', dec, re.I):
        base += '_attack'
    elif re.search(r'jump', dec, re.I):
        base += '_jump'
    else:
        base += '_handler'
    return f"{base}_{idx:02d}_lvl{lvl}"

def main():
    bybin = load_bundle(BUNDLE_ALL)
    bmarks = load_bookmarks()
    fnmap = bybin.get('MAIN.EXE', {})
    if not fnmap:
        print('No MAIN.EXE in bundle')
        return
    usd = find_update_state_dispatch_name(bmarks, fnmap)
    if not usd:
        print('update_state_dispatch seed not found')
        return
    depth = 2
    lvls = neighborhood(fnmap, usd, depth=depth)
    def collect(levels: dict):
        out = []
        for n, lvl in levels.items():
            if n == usd:
                continue
            ent = fnmap[n]
            # Skip tiny functions (likely thunks/alignment)
            if (ent.get('size') or 0) <= 8:
                continue
            s, meta = score_action_candidate(ent)
            if s > 0:
                # Proximity weight
                if lvl == 1:
                    s += 5
                elif lvl == 2:
                    s += 2
                elif lvl >= 3:
                    s += 1
                out.append((s, n, ent, lvl, meta))
        return out
    cand = collect(lvls)
    if len(cand) < 5:
        depth = 3
        lvls = neighborhood(fnmap, usd, depth=depth)
        cand = collect(lvls)
    # Fallback: try input handler seeds if still too sparse
    if len(cand) < 3:
        alt_seeds = []
        for orig, new in bmarks.get('MAIN.EXE', {}).items():
            if new in ('suspect_input_mode_handler','suspect_input_update_gate') and orig in fnmap:
                alt_seeds.append(orig)
        for seed in alt_seeds:
            lv = neighborhood(fnmap, seed, depth=3)
            cand += collect(lv)
    # Broaden depth one more if still empty
    if not cand:
        lvls = neighborhood(fnmap, usd, depth=4)
        cand = collect(lvls)
    cand.sort(key=lambda x: (-x[0], x[1]))
    # Write candidates
    csv_p = EXPORTS / 'action_candidates_MAIN.EXE.csv'
    md_p = EXPORTS / 'action_candidates_MAIN.EXE.md'
    edges_p = EXPORTS / 'action_edges_MAIN.EXE.md'
    with open(csv_p, 'w', encoding='utf-8', newline='') as f:
        wr = csv.writer(f)
        wr.writerow(['score','name','ea','size','lvl','arrow','masks','edge','outdeg','indeg'])
        for s, n, ent, lvl, meta in cand:
            wr.writerow([s, n, f"0x{ent.get('ea',0):08x}", ent.get('size',0), lvl, meta['arrow'], meta['masks'], meta['edge'], len(ent.get('callees') or []), len(ent.get('callers') or [])])
    with open(md_p, 'w', encoding='utf-8') as f:
        f.write('# Action candidates near update_state_dispatch (MAIN.EXE)\n\n')
        f.write(f'Seed: {disp_name(bmarks, usd)} ({usd})\n\n')
        for i, (s, n, ent, lvl, meta) in enumerate(cand[:30], start=1):
            f.write(f"- {i:02d}. {disp_name(bmarks, n)} @ 0x{ent.get('ea',0):08x} | score={s} | lvl={lvl} | size={meta['size']} | ->={meta['arrow']} | masks={meta['masks']} | edge={meta['edge']} | out={len(ent.get('callees') or [])} in={len(ent.get('callers') or [])} [{n}]\n")
    # Action-edge inspector: show lines with switch/case/struct/bit-test/edge patterns
    with open(edges_p, 'w', encoding='utf-8') as f:
        f.write('# Action edge inspector (MAIN.EXE)\n\n')
        f.write(f'Seed: {disp_name(bmarks, usd)} ({usd})\n\n')
        top = cand[:16]
        for s, n, ent, lvl, meta in top:
            f.write(f"## {disp_name(bmarks, n)} ({n}) @ 0x{ent.get('ea',0):08x} | score={s} | lvl={lvl} | ->={meta['arrow']} | masks={meta['masks']} | edge={meta['edge']}\n\n")
            dec = ent.get('decompilation') or ''
            lines = []
            for line in dec.splitlines():
                t = line.strip()
                if not t:
                    continue
                if ('switch' in t) or t.startswith('case ') or ('->' in t) or ('& 0x' in t) or ('& ~' in t) or re.search(r'Pad|input|button|joy|control', t, re.I):
                    lines.append(t)
            if lines:
                for ln in lines[:60]:
                    f.write(f"- {ln}\n")
            else:
                f.write('(no indicative lines captured)\n')
            f.write('\n')
    print('Wrote', csv_p)
    print('Wrote', md_p)
    print('Wrote', edges_p)

    # Update curated overlays with proposed suspect_action_* names for top 8
    proposals = []
    for idx, (_s, n, ent, lvl, _m) in enumerate(cand[:8], start=1):
        proposals.append({'name': n, 'new_name': propose_name(ent, idx, lvl), 'tags': ['suspect','action']})
    # Merge into CURATED file under MAIN.EXE
    cur = {}
    if CURATED.exists():
        try:
            cur = json.loads(CURATED.read_text(encoding='utf-8'))
        except Exception:
            cur = {}
    if not isinstance(cur, dict):
        cur = {}
    arr = cur.get('MAIN.EXE') or []
    # Avoid duplicating existing names; replace entries for same original name
    by_name = {e.get('name'): e for e in arr if isinstance(e, dict) and e.get('name')}
    for p in proposals:
        name = p['name']
        existing = by_name.get(name)
        if existing:
            # Do NOT overwrite curated or non-suspect names
            existing_new = (existing.get('new_name') or '').strip()
            if existing_new and not existing_new.startswith('suspect_'):
                # Keep curated/definitive name; just ensure tags include 'action'
                tags = set(existing.get('tags') or []) | set(p.get('tags') or [])
                existing['tags'] = sorted(tags)
                by_name[name] = existing
                continue
            # Existing is suspect_*: update proposal but merge tags
            tags = set(existing.get('tags') or []) | set(p.get('tags') or [])
            upd = dict(existing)
            upd['new_name'] = p.get('new_name') or existing_new
            upd['tags'] = sorted(tags)
            by_name[name] = upd
        else:
            by_name[name] = p
    cur['MAIN.EXE'] = list(by_name.values())
    CURATED.write_text(json.dumps(cur, indent=2), encoding='utf-8')
    print('Updated', CURATED)

if __name__ == '__main__':
    main()
