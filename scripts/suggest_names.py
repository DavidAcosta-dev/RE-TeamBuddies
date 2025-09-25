#!/usr/bin/env python3
import os, sys, json, csv, collections, re

IN = sys.argv[1] if len(sys.argv)>1 else os.path.join(os.path.expanduser('~'),'tb-re','exports','bundle_ghidra.jsonl')
OUT_DIR = os.path.join(os.path.expanduser('~'),'tb-re','exports')
os.makedirs(OUT_DIR, exist_ok=True)

def load_jsonl(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue

records = list(load_jsonl(IN))

perbin = collections.defaultdict(list)
for r in records:
    b = (r.get('binary') or '').strip()
    fn = r.get('function') or {}
    name = fn.get('name')
    if b and name:
        perbin[b].append(r)

def propose_for_bin(recs):
    # Index by name
    nodes = {}
    for r in recs:
        fn = r['function']; name = fn['name']
        n = nodes.setdefault(name, {
            'name': name,
            'ea': fn.get('ea') or 0,
            'size': fn.get('size') or 0,
            'callers': set(),
            'callees': set(),
            'dec': r.get('decompilation') or ''
        })
        n['callers'] |= set(r.get('callers') or [])
        n['callees'] |= set(r.get('callees') or [])
        if (fn.get('size') or 0) > n['size']:
            n['size'] = fn.get('size') or 0
            n['ea'] = fn.get('ea') or n['ea']
            if r.get('decompilation'):
                n['dec'] = r['decompilation']

    # Reverse edges to count popular callees
    callee_counts = collections.Counter()
    for n in nodes.values():
        for c in n['callees']:
            callee_counts[c] += 1

    suggestions = []

    # Rule: return-zero stubs (exact decomp "return 0;")
    for n in nodes.values():
        if re.search(r'\breturn\s+0\s*;', n['dec']):
            suggestions.append((n['name'], 'ReturnZero', 0.9, 'decomp returns constant 0; many callers=%d' % len(n['callers'])))

    # Rule: thunk with many callers -> Alloc/Free
    for n in nodes.values():
        if n['name'].startswith('thunk_') and len(n['callers']) >= 10:
            # Check if called with immediate small sizes in other decomp blobs
            called_with_sizes = 0
            for m in nodes.values():
                if n['name'] in m['callees'] and re.search(n['name'] + r'\s*\(0x?[0-9a-fA-F]{1,3}\)', m['dec']):
                    called_with_sizes += 1
            if called_with_sizes >= 1:
                suggestions.append((n['name'], 'Alloc_Mem', 0.85, f'thunk with {len(n["callers"])} callers; invoked with small constant sizes'))
            else:
                suggestions.append((n['name'], 'Lib_Thunk', 0.6, f'thunk with {len(n["callers"])} callers'))

    # Rule: Big out-degree + VSync/WaitVSync -> Main_Update
    for n in nodes.values():
        if len(n['callees']) >= 20 and re.search(r'VSync|WaitVSync|DrawSync', n['dec']):
            suggestions.append((n['name'], 'Main_Update', 0.7, f'large out-degree={len(n["callees"])} and vsync tokens present'))

    # Rule: small function that only calls one vsync/drawsync -> Sync_Wait
    for n in nodes.values():
        if n['size'] <= 64 and re.search(r'\b(FUN_00034460|VSync|WaitVSync|DrawSync)\b', n['dec']):
            suggestions.append((n['name'], 'Sync_Wait', 0.65, 'tiny wrapper around sync'))

    # Rule: tables/bitmask param updates to global array -> ChannelParam_Apply (low confidence)
    for n in nodes.values():
        if re.search(r'\[(?:int\))?param_1', n['dec']) and re.search(r'\b<<\s*3\b|\*\s*0x10', n['dec']) and re.search(r'_DAT_|DAT_', n['dec']):
            suggestions.append((n['name'], 'ChannelParam_Apply', 0.5, 'bitmask-driven table updates detected'))

    # Deduplicate by name keeping highest confidence
    best = {}
    for name, prop, conf, reason in suggestions:
        if name not in best or conf > best[name][1]:
            best[name] = (prop, conf, reason)
    # Return sorted list
    out = []
    for name, (prop, conf, reason) in best.items():
        n = nodes[name]
        out.append({
            'name': name,
            'ea': f"0x{n['ea']:08x}",
            'size': n['size'],
            'in': len(n['callers']),
            'out': len(n['callees']),
            'proposed': prop,
            'confidence': conf,
            'reason': reason
        })
    out.sort(key=lambda r: (-r['confidence'], -r['out'], -r['in']))
    return out

for b, recs in perbin.items():
    out = propose_for_bin(recs)
    if not out:
        continue
    out_csv = os.path.join(OUT_DIR, f'name_suggestions_{re.sub(r"[^A-Za-z0-9._-]","_",b)}.csv')
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['name','ea','size','in','out','proposed','confidence','reason'])
        w.writeheader(); w.writerows(out)
    print('Wrote', out_csv, f'({len(out)} suggestions)')
