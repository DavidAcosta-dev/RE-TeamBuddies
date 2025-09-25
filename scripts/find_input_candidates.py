#!/usr/bin/env python3
"""
Rank likely input/controller functions by:
- Proximity to the main_update seed (direct callees and their callees)
- Bitmask usage typical of PS1 pad buttons (& 0x10, 0x20, 0x40, 0x80, 0x100, ... , 0x8000)
- Edge-detection idioms (curr & ~prev)
- Light keyword hints (press, button, input)

Outputs CSV and a compact Markdown summary under exports/ for MAIN.EXE and GAME.BIN.
"""
import os, re, json, csv, collections
from pathlib import Path

ROOT = Path(os.path.expanduser('~'))/ 'tb-re'
EXPORTS = ROOT / 'exports'
BUNDLE_ALL = EXPORTS / 'bundle_ghidra.jsonl'
BOOKMARKS = EXPORTS / 'suspects_bookmarks.json'

BIT_MASKS = {0x10,0x20,0x40,0x80, 0x100,0x200,0x400,0x800, 0x1000,0x2000,0x4000,0x8000}
BIT_RE = re.compile(r'&\s*0x([0-9a-fA-F]+)\b')
EDGE_RE = re.compile(r'&\s*~\s*([A-Za-z_][A-Za-z0-9_]*)')
KW_RE = re.compile(r'press|button|input|pad|joy', re.I)

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

def disp_name(bmarks: dict, binary: str, name: str) -> str:
    return bmarks.get(binary, {}).get(name) or name

def pick_main(fnmap:dict):
    # prefer exact rename if it exists
    if 'main_update' in fnmap:
        return 'main_update'
    # heuristic: highest outdegree with vsync-like tokens near it
    best = None; best_score = -1
    for n, r in fnmap.items():
        dec = r.get('decompilation') or ''
        s = len(r.get('callees') or [])
        if re.search(r'VSync|WaitVSync|DrawSync|sync', dec, re.I):
            s += 10
        if re.search(r'update|main|loop', n, re.I):
            s += 5
        if s > best_score:
            best = n; best_score = s
    return best

def neighborhood(fnmap:dict, seed:str, depth:int=2):
    if not seed or seed not in fnmap:
        return {seed:0} if seed else {}
    levels = {seed:0}
    q = [seed]
    while q:
        cur = q.pop(0)
        lvl = levels[cur]
        if lvl >= depth:
            continue
        for cal in fnmap[cur]['callees']:
            if cal in fnmap and cal not in levels:
                levels[cal] = lvl+1
                q.append(cal)
    return levels

def score_fn(name:str, ent:dict, lvl:int|None):
    dec = ent.get('decompilation') or ''
    masks = 0
    for m in BIT_RE.finditer(dec):
        try:
            val = int(m.group(1), 16)
        except Exception:
            continue
        if val in BIT_MASKS:
            masks += 1
    edges = len(EDGE_RE.findall(dec))
    kws = 1 if KW_RE.search(dec) else 0
    # base score
    s = masks*3 + edges*4 + kws*2
    # proximity weight: lvl 1 highest, then 2
    if lvl == 1:
        s += 6
    elif lvl == 2:
        s += 3
    # small helper functions that just check input often are smallish
    sz = ent.get('size') or 0
    if 8 <= sz <= 256:
        s += 1
    return s, {'masks': masks, 'edges': edges, 'kws': kws, 'lvl': (lvl if lvl is not None else -1), 'size': sz}

def analyze(bin_name:str, fnmap:dict):
    seed = pick_main(fnmap)
    lvls = neighborhood(fnmap, seed, depth=2)
    rows = []
    for n, ent in fnmap.items():
        lvl = lvls.get(n)
        sc, meta = score_fn(n, ent, lvl)
        if sc > 0:
            rows.append((sc, n, ent, meta))
    rows.sort(key=lambda x: (-x[0], x[1]))
    return seed, rows

def write_outputs(bin_name:str, seed:str, rows:list, bmarks:dict):
    csv_p = EXPORTS / f'input_candidates_{bin_name}.csv'
    md_p = EXPORTS / f'input_candidates_{bin_name}.md'
    edges_p = EXPORTS / f'input_edges_{bin_name}.md'
    with open(csv_p, 'w', encoding='utf-8', newline='') as f:
        wr = csv.writer(f)
        wr.writerow(['score','name','disp','ea','size','lvl','masks','edges','kws','outdeg','indeg'])
        for sc, n, ent, meta in rows:
            wr.writerow([sc, n, disp_name(bmarks, bin_name, n), f"0x{ent.get('ea',0):08x}", ent.get('size',0), meta['lvl'], meta['masks'], meta['edges'], meta['kws'], len(ent.get('callees') or []), len(ent.get('callers') or [])])
    with open(md_p, 'w', encoding='utf-8') as f:
        f.write(f"# Input candidates for {bin_name}\n\n")
        f.write(f"Seed: {disp_name(bmarks, bin_name, seed)} ({seed})\n\n")
        for sc, n, ent, meta in rows[:30]:
            dn = disp_name(bmarks, bin_name, n)
            f.write(f"- {dn} @ 0x{ent.get('ea',0):08x} | score={sc} | lvl={meta['lvl']} | size={meta['size']} | masks={meta['masks']} | edges={meta['edges']} | kws={meta['kws']} | out={len(ent.get('callees') or [])} in={len(ent.get('callers') or [])} [{n}]\n")
    # Input-edge inspector: show code lines with bit tests and edge patterns for top edge-heavy functions
    top_edges = [row for row in rows if row[3]['edges'] > 0][:12]
    with open(edges_p, 'w', encoding='utf-8') as f:
        f.write(f"# Input edge inspector for {bin_name}\n\n")
        if not top_edges:
            f.write("(No edge-detection patterns found.)\n")
        for sc, n, ent, meta in top_edges:
            dn = disp_name(bmarks, bin_name, n)
            f.write(f"## {dn} ({n}) @ 0x{ent.get('ea',0):08x} | score={sc} | lvl={meta['lvl']} | masks={meta['masks']} | edges={meta['edges']}\n\n")
            dec = ent.get('decompilation') or ''
            # Filter decomp lines that likely indicate input tests
            lines = []
            for line in dec.splitlines():
                s = line.strip()
                if not s:
                    continue
                if ('& 0x' in s) or ('& ~' in s) or re.search(r'Pad|button|input|joy', s, re.I):
                    lines.append(s)
            if lines:
                for ln in lines[:40]:
                    f.write(f"- {ln}\n")
            else:
                f.write("(no indicative lines captured)\n")
            f.write("\n")
    return csv_p, md_p, edges_p

def main():
    bybin = load_bundle(BUNDLE_ALL)
    bmarks = load_bookmarks()
    targets = [b for b in ['MAIN.EXE','GAME.BIN'] if b in bybin]
    written = []
    for b in targets:
        seed, rows = analyze(b, bybin[b])
        csv_p, md_p, edges_p = write_outputs(b, seed, rows, bmarks)
        print('Wrote', csv_p)
        print('Wrote', md_p)
        print('Wrote', edges_p)
        written.append((csv_p, md_p, edges_p))
    if not written:
        print('No targets found in bundle.')

if __name__ == '__main__':
    main()
