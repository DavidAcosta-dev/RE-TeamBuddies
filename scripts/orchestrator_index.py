import json, re
from pathlib import Path
from collections import defaultdict, Counter

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'
OUT = EXPORTS / 'orchestrator_index.md'

CATEGORY_PATTERNS = {
    'input': [r'input_candidates_.*\.md', r'input_edges_.*\.md', r'action_candidates_.*\.md'],
    'crate': [r'crate_system_candidates\.md', r'crate_candidate_edges\.md'],
    'cdstream': [r'cdstream_.*\.md'],
    'pickup_drop':[r'pickup_drop_.*\.md'],
    'vertical':[r'vertical_core_functions\.md','vertical_writer_functions\.md','vertical_struct_layout\.md'],
    'gravity':[r'gravity_.*\.md'],
}

FUNC_RE = re.compile(r'\bFUN_[0-9a-fA-F]{8}\b')

def load_categories():
    mapping=defaultdict(set)
    for cat, pats in CATEGORY_PATTERNS.items():
        regexes=[re.compile(p) for p in pats]
        for f in EXPORTS.iterdir():
            if not f.is_file(): continue
            if not any(rx.fullmatch(f.name) for rx in regexes):
                continue
            try: text=f.read_text(encoding='utf-8',errors='ignore')
            except: continue
            for fn in set(FUNC_RE.findall(text)):
                mapping[fn].add(cat)
    return mapping

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except: continue
                if 'function' in obj: yield obj

def main():
    cat_map = load_categories()
    # Hub threshold: belongs to >=3 categories
    hub_funcs = {fn for fn,cats in cat_map.items() if len(cats)>=3}
    if not hub_funcs:
        print('No hubs found'); return
    # Build call graph subset
    decomp_index={}
    for fn in iter_funcs():
        func=fn['function']; name=func['name']
        if name in hub_funcs:
            decomp_index[name]=fn.get('decompilation') or ''
    hub_rows=[]; detail={}
    for hub, dec in decomp_index.items():
        callees=set(FUNC_RE.findall(dec)) - {hub}
        cat_counts=Counter()
        for c in callees:
            for cat in cat_map.get(c, []):
                cat_counts[cat]+=1
        hub_rows.append((hub, len(callees), len(cat_map.get(hub,[])), dict(cat_counts)))
        detail[hub]={'callees':sorted(callees),'cat_counts':dict(cat_counts),'hub_categories':sorted(cat_map.get(hub,[]))}
    hub_rows.sort(key=lambda r:(-r[1], -r[2], r[0]))
    with OUT.open('w',encoding='utf-8') as f:
        f.write('# Orchestrator Hub Index\n\n')
        f.write('| Function | CalleeCount | OwnCategories | TopCats |\n|----------|------------:|--------------:|---------|\n')
        for hub, ccount, ownc, cats in hub_rows:
            top = ','.join(f"{k}:{v}" for k,v in sorted(cats.items(), key=lambda kv:-kv[1])[:4])
            f.write(f"| {hub} | {ccount} | {ownc} | {top} |\n")
        f.write('\n## Details\n\n')
        for hub in [h[0] for h in hub_rows]:
            info=detail[hub]
            f.write(f"### {hub} ({'/'.join(info['hub_categories'])})\n\n")
            f.write('Category Callee Counts:\n\n')
            for k,v in sorted(info['cat_counts'].items(), key=lambda kv:-kv[1]):
                f.write(f"- {k}: {v}\n")
            f.write('\nCallees (subset):\n\n')
            for c in info['callees'][:120]:
                f.write(f"- {c} {'/'.join(sorted(cat_map.get(c, [])))}\n")
            f.write('\n')
    print('Wrote orchestrator_index.md with', len(hub_rows), 'hubs')

if __name__=='__main__':
    main()
