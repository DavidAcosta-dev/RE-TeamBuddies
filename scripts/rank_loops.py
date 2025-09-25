#!/usr/bin/env python3
import os, sys, json, csv, re, collections

IN = sys.argv[1] if len(sys.argv)>1 else os.path.join(os.path.expanduser('~'),'tb-re','exports','bundle_ghidra.jsonl')
OUT_DIR = os.path.join(os.path.expanduser('~'),'tb-re','exports')
os.makedirs(OUT_DIR, exist_ok=True)

def load_jsonl(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line=line.strip()
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
    if not b or not name:
        continue
    rec = {
        'name': name,
        'ea': fn.get('ea') or 0,
        'size': fn.get('size') or 0,
        'callers': set(r.get('callers') or []),
        'callees': set(r.get('callees') or []),
        'dec': r.get('decompilation') or ''
    }
    perbin[b].append(rec)

# tokens for main loop/update/render/tick
TOKENS = [
    ('main', re.compile(r'\b(main|Main|_main)\b')),
    ('loop', re.compile(r'\b(loop|while\s*\(|for\s*\(|do\s*\{)')),
    ('tick', re.compile(r'\b(update|tick|step|frame|game\s*loop|game\s*main)\b', re.I)),
    ('vsync', re.compile(r'\b(VSync|WaitVSync|DrawSync)\b')),
    ('pad', re.compile(r'\b(Pad(Read|Init|Open|Close|Info)|button)\b', re.I)),
]

def score(rec):
    dec = rec['dec']
    name = rec['name']
    s = 0
    # degree
    indeg = len(rec['callers']); outdeg = len(rec['callees'])
    s += min(indeg, 20) * 2 + min(outdeg, 40)
    # size sweet spot (loop bodies are mid-to-large but not massive init blobs)
    if 200 < rec['size'] < 8000:
        s += 5
    # tokens
    for label, rx in TOKENS:
        if rx.search(name) or rx.search(dec):
            s += 8
    # evidence of fixed-step pattern: VSync + pad + update-like token
    if re.search(r'VSync|WaitVSync', dec) and re.search(r'Pad(Read|Init)', dec):
        s += 10
    return s

for b, lst in perbin.items():
    # merge duplicates by name
    merged = {}
    for r in lst:
        m = merged.setdefault(r['name'], r)
        if r['size'] > m['size']:
            m['size'] = r['size']; m['ea'] = r['ea']; m['dec'] = r['dec'] or m['dec']
        m['callers'] |= r['callers']; m['callees'] |= r['callees']
    ranked = sorted(merged.values(), key=score, reverse=True)
    out_csv = os.path.join(OUT_DIR, f'loop_candidates_{re.sub(r"[^A-Za-z0-9._-]","_",b)}.csv')
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['name','ea','size','in','out','score'])
        for r in ranked[:100]:
            w.writerow([r['name'], f"0x{r['ea']:08x}", r['size'], len(r['callers']), len(r['callees']), score(r)])
    print('Wrote', out_csv)
