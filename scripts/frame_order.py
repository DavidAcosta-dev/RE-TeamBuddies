#!/usr/bin/env python3
"""
Extract a sequential call order from a selected function's decompilation and map it to known functions.
Outputs a markdown "frame order" sheet that approximates the per-frame pipeline order.
"""
import os, sys, json, re, collections
from pathlib import Path

ROOT = Path(os.path.expanduser('~'))/ 'tb-re'
EXPORTS = ROOT / 'exports'
BUNDLE_ALL = EXPORTS / 'bundle_ghidra.jsonl'
BOOKMARKS = EXPORTS / 'suspects_bookmarks.json'

CALL_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_\.]+)\s*\(')

class Bundle:
    def __init__(self, path: Path):
        self.records = []
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    self.records.append(json.loads(line))
                except Exception:
                    continue
        self.bybin = collections.defaultdict(dict)
        for r in self.records:
            b = (r.get('binary') or '').strip()
            fn = r.get('function') or {}
            name = fn.get('name')
            if not b or not name:
                continue
            ent = self.bybin[b].setdefault(name, {
                'name': name,
                'ea': fn.get('ea') or 0,
                'size': fn.get('size') or 0,
                'decompilation': '',
                'callers': set(), 'callees': set(),
            })
            dec = r.get('decompilation') or ''
            if dec and len(dec) > len(ent['decompilation']):
                ent['decompilation'] = dec
            ent['callers'] |= set(r.get('callers') or [])
            ent['callees'] |= set(r.get('callees') or [])

    def get_funcs(self, b):
        return self.bybin.get(b, {})


def load_bmarks(path=BOOKMARKS):
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
    except Exception:
        return {}
    perbin = collections.defaultdict(dict)
    if isinstance(data, dict):
        for b, entries in data.items():
            best = {}
            for ent in entries or []:
                fn = ent.get('name') or ent.get('fn')
                new = ent.get('new_name')
                if not fn or not new:
                    continue
                tags = set(ent.get('tags') or [])
                if new.startswith('stub_ret0_') or ('auto' in tags or 'ret0' in tags):
                    w = 1
                elif new.startswith('suspect_'):
                    w = 2
                else:
                    w = 3
                if fn not in best or w > best[fn][0]:
                    best[fn] = (w, new)
            for k,(w,n) in best.items():
                perbin[b][k] = n
    return perbin


def pick_main(binary, funcs, bmarks):
    # prefer known rename
    for n in funcs:
        if bmarks.get(binary, {}).get(n) == 'main_update':
            return n
    # fallback heuristics
    for n, r in sorted(funcs.items(), key=lambda kv: len(kv[1]['callees']), reverse=True):
        dec = r.get('decompilation') or ''
        if re.search(r'update|main|loop', n, re.I) or re.search(r'VSync|Pad', dec):
            return n
    # last fallback: highest out-degree
    return max(funcs.keys(), key=lambda k: len(funcs[k]['callees']), default=None)


def disp_name(binary, name, bmarks):
    return bmarks.get(binary, {}).get(name) or name


def extract_call_order(dec:str, funcs:set[str]):
    order = []
    seen_at = {}
    for m in CALL_RE.finditer(dec):
        cal = m.group(1)
        if cal in funcs and cal not in seen_at:
            seen_at[cal] = m.start()
            order.append(cal)
    return order


def write_md(binary, seed, order, funcs, bmarks):
    outp = EXPORTS / f"frame_{binary}.md"
    with outp.open('w', encoding='utf-8') as f:
        f.write(f"# Frame order for {binary}\n\n")
        f.write(f"Seed: {disp_name(binary, seed, bmarks)} ({seed})\n\n")
        idx = 1
        for name in order:
            r = funcs.get(name) or {}
            dn = disp_name(binary, name, bmarks)
            f.write(f"{idx:02d}. {dn} @ 0x{r.get('ea',0):08x} | out={len(r.get('callees') or [])} | in={len(r.get('callers') or [])} [{name}]\n")
            idx += 1
    return outp


def main():
    # args: BINARY [SEED]
    binary = sys.argv[1] if len(sys.argv)>1 else 'MAIN.EXE'
    override_seed = sys.argv[2] if len(sys.argv)>2 else None
    bundle = Bundle(BUNDLE_ALL)
    bmarks = load_bmarks()
    funcs = bundle.get_funcs(binary)
    if not funcs:
        print('No funcs for', binary)
        return
    seed = override_seed if override_seed in funcs else pick_main(binary, funcs, bmarks)
    if not seed:
        print('No seed found for', binary)
        return
    dec = funcs[seed].get('decompilation') or ''
    order = extract_call_order(dec, set(funcs.keys()))
    outp = write_md(binary, seed, order, funcs, bmarks)
    print('Wrote', outp)

if __name__ == '__main__':
    main()
