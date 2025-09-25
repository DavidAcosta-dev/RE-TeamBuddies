#!/usr/bin/env python3
"""
Build a high-level logic map for PS1 binaries using exported bundle JSONL and bookmark-based renames.
Outputs per-binary markdown describing the per-frame pipeline and key functions around the main loop.
"""
import os, sys, json, csv, re, collections
from pathlib import Path

ROOT = Path(os.path.expanduser('~'))/ 'tb-re'
EXPORTS = ROOT / 'exports'
BUNDLE_ALL = EXPORTS / 'bundle_ghidra.jsonl'
BOOKMARKS = EXPORTS / 'suspects_bookmarks.json'
OUT_DIR = EXPORTS

PSYQ_MARKERS = {
    'vsync': re.compile(r'\b(VSync|WaitVSync|DrawSync)\b', re.I),
    'pad': re.compile(r'\b(Pad(Read|Init|Open|Close|Info)|/pad|controller|joy)\b', re.I),
    'gpu': re.compile(r'\b(ResetGraph|ClearOTag|DrawPrim|AddPrim|GsSort|SetDrawEnv|ClearImage)\b', re.I),
    'spu': re.compile(r'\b(Spu|Ss|Se\b|XA|CDPlay|CdPlay|CdControl|CdRead)\b'),
    'dma': re.compile(r'\b(DMA|Dma)\b'),
    'gte': re.compile(r'\b(GTE|Rt|MulMat)\b'),
}

NAME_HINTS = {
    'vsync': re.compile(r'sync|vsync|wait', re.I),
    'pad': re.compile(r'pad|ctrl|input|button', re.I),
    'gpu': re.compile(r'(gs|gpu|draw|ot|prim)', re.I),
    'spu': re.compile(r'(spu|sound|audio|sfx|music)', re.I),
    'physics': re.compile(r'phys', re.I),
}

class Bundle:
    def __init__(self, jsonl_path: str | os.PathLike[str] | Path):
        self.bybin = collections.defaultdict(dict)
        with open(jsonl_path, 'r', encoding='utf-8', errors='ignore') as f:
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
                if name in self.bybin[b]:
                    # merge callers/callees, keep larger size/dec
                    m = self.bybin[b][name]
                    m['callers'] |= set(r.get('callers') or [])
                    m['callees'] |= set(r.get('callees') or [])
                    if (fn.get('size') or 0) > (m.get('size') or 0):
                        m['size'] = fn.get('size') or m.get('size')
                        m['ea'] = fn.get('ea') or m.get('ea')
                    if (r.get('decompilation') or '') and len(r.get('decompilation') or '') > len(m.get('decompilation') or ''):
                        m['decompilation'] = r.get('decompilation')
                else:
                    self.bybin[b][name] = {
                        'name': name,
                        'ea': fn.get('ea') or 0,
                        'size': fn.get('size') or 0,
                        'callers': set(r.get('callers') or []),
                        'callees': set(r.get('callees') or []),
                        'decompilation': r.get('decompilation') or '',
                    }

    def get(self, b):
        return self.bybin.get(b, {})


def load_bookmarks(path=BOOKMARKS):
    """Load rename overlays from suspects_bookmarks.json.
    Structure is { "BINARY": [ {"name": original, "new_name": rename, "tags": [...]}, ... ], ... }
    Apply precedence: curated/phys/spu/etc > suspect_* > stub_ret0_ (auto).
    """
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
    except Exception:
        return {}
    perbin = collections.defaultdict(dict)
    if isinstance(data, dict):
        for b, entries in data.items():
            best_for = {}
            for ent in entries or []:
                fn = ent.get('name') or ent.get('fn')
                new = ent.get('new_name')
                if not fn or not new:
                    continue
                tags = set(ent.get('tags') or [])
                # precedence weighting
                if new.startswith('stub_ret0_') or ('auto' in tags or 'ret0' in tags):
                    w = 1
                elif new.startswith('suspect_'):
                    w = 2
                else:
                    w = 3
                prev = best_for.get(fn)
                if not prev or w > prev[0]:
                    best_for[fn] = (w, new)
            for fn, (_w, new) in best_for.items():
                perbin[b][fn] = new
    else:
        # fallback if file is a flat list (older format)
        for ent in data or []:
            b = (ent.get('binary') or '').strip()
            fn = ent.get('name') or ent.get('fn')
            new = ent.get('new_name')
            if b and fn and new:
                perbin[b][fn] = new
    return perbin


def disp_name(bmarks, binary, name):
    nn = bmarks.get(binary, {}).get(name)
    if nn:
        return nn
    # auto-ret0 overlay handling
    if name.startswith('FUN_'):
        return name
    return name


def tag_function(name, dec):
    tags = set()
    lower = name.lower()
    for k, rx in PSYQ_MARKERS.items():
        if rx.search(dec):
            tags.add(k)
    for k, rx in NAME_HINTS.items():
        if rx.search(name):
            tags.add(k)
    # special overlays
    if name.startswith('phys_'):
        tags.add('physics')
    if 'sync' in lower:
        tags.add('vsync')
    return tags


def pick_main_function(binary, funcs, bmarks):
    # 1) bookmark exact name
    for n, r in funcs.items():
        dn = disp_name(bmarks, binary, n)
        if dn == 'main_update':
            return n
    # 2) token search and degree heuristic
    best = None; best_score = -1
    for n, r in funcs.items():
        dec = r.get('decompilation') or ''
        outdeg = len(r.get('callees') or [])
        s = 0
        if re.search(r'update|main', n, re.I) or re.search(r'update|main', dec, re.I):
            s += 10
        if PSYQ_MARKERS['vsync'].search(dec):
            s += 15
        if PSYQ_MARKERS['pad'].search(dec):
            s += 8
        s += min(outdeg, 40)
        if s > best_score:
            best_score = s; best = n
    if best:
        return best
    # 3) fallback to CSV loop candidates if present
    lc = OUT_DIR / f"loop_candidates_{re.sub(r'[^A-Za-z0-9._-]','_',binary)}.csv"
    if lc.exists():
        try:
            with lc.open('r', encoding='utf-8') as f:
                rd = csv.DictReader(f)
                row = next(iter(rd))
                if row:
                    return row['name']
        except Exception:
            pass
    # 4) highest outdegree
    return max(funcs.keys(), key=lambda n: len(funcs[n].get('callees') or []), default=None)


def build_logic(binary, bundle:Bundle, bmarks, depth=2):
    funcs = bundle.get(binary)
    if not funcs:
        return None
    seed = pick_main_function(binary, funcs, bmarks)
    if not seed:
        return None
    seen = {seed}
    levels = {seed:0}
    order = [seed]
    edges = []
    q = [seed]
    while q:
        cur = q.pop(0)
        lvl = levels[cur]
        if lvl >= depth:
            continue
        for cal in sorted(funcs.get(cur, {}).get('callees') or []):
            edges.append((cur, cal))
            if cal not in seen and cal in funcs:
                seen.add(cal)
                levels[cal] = lvl+1
                order.append(cal)
                q.append(cal)
    # build nodes with tags
    nodes = []
    for n in order:
        r = funcs[n]
        dn = disp_name(bmarks, binary, n)
        tags = tag_function(dn, r.get('decompilation') or '')
        nodes.append({
            'name': n, 'disp': dn, 'ea': r.get('ea') or 0, 'size': r.get('size') or 0,
            'in': len(r.get('callers') or []), 'out': len(r.get('callees') or []),
            'tags': sorted(tags), 'level': levels.get(n, 0)
        })
    return {'binary': binary, 'seed': seed, 'nodes': nodes, 'edges': edges}


def write_markdown(result):
    binary = result['binary']
    seed = result['seed']
    nodes = result['nodes']
    edges = result['edges']
    outp = OUT_DIR / f"logic_{binary}.md"
    with outp.open('w', encoding='utf-8', newline='') as f:
        f.write(f"# Logic map for {binary}\n\n")
        # Find display seed name
        disp_seed = None
        for n in nodes:
            if n['name'] == seed:
                disp_seed = n['disp']
                break
        f.write(f"Seed: {disp_seed or seed} ({seed})\n\n")
        # Per-frame summary
        cats = collections.Counter()
        for n in nodes:
            for t in n['tags']:
                cats[t] += 1
        pipeline = [
            ('input', cats.get('pad',0)),
            ('update', len(nodes)),
            ('physics', cats.get('physics',0)),
            ('render', cats.get('gpu',0)),
            ('audio', cats.get('spu',0)),
            ('vsync', cats.get('vsync',0)),
        ]
        f.write("## Per-frame pipeline\n\n")
        f.write("- input: ~%d nodes\n" % pipeline[0][1])
        f.write("- update: ~%d nodes (depth<=2)\n" % pipeline[1][1])
        f.write("- physics: ~%d nodes\n" % pipeline[2][1])
        f.write("- render: ~%d nodes\n" % pipeline[3][1])
        f.write("- audio: ~%d nodes\n" % pipeline[4][1])
        f.write("- vsync: ~%d nodes\n\n" % pipeline[5][1])
        f.write("## Key nodes\n\n")
        for n in nodes:
            f.write("- %s @ 0x%08x | size=%d | in=%d out=%d | tags=[%s] | lvl=%d\n" % (
                n['disp'], n['ea'], n['size'], n['in'], n['out'], ','.join(n['tags']), n['level']))
        f.write("\n## Edges (level<2)\n\n")
        disp = {n['name']: n['disp'] for n in nodes}
        for a,b in edges:
            f.write(f"- {disp.get(a,a)} -> {disp.get(b,b)} [{a} -> {b}]\n")
    return outp


def main():
    # bins: default to MAIN.EXE and GAME.BIN if present in bundle
    bundle = Bundle(BUNDLE_ALL)
    bmarks = load_bookmarks()
    targets = sorted(bundle.bybin.keys())
    # prioritize MAIN.EXE and GAME.BIN
    ordered = [b for b in ['MAIN.EXE','GAME.BIN'] if b in targets]
    ordered += [b for b in targets if b not in ordered]
    written = []
    for b in ordered:
        if b not in ('MAIN.EXE','GAME.BIN'):
            continue
        res = build_logic(b, bundle, bmarks, depth=2)
        if res:
            outp = write_markdown(res)
            print('Wrote', outp)
            written.append(str(outp))
    if not written:
        print('No logic maps written; check bundle and bookmarks.')

if __name__ == '__main__':
    main()
