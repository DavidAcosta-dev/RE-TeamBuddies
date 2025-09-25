import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'

OUT_CORE = EXPORTS / 'vertical_core_functions.md'
OUT_CONS = EXPORTS / 'vertical_consumer_functions.md'
OUT_JSON = EXPORTS / 'vertical_vertical_refined.json'

CORE_OFFSETS = {
    'progress': [' + 0x5c', ' + 0x5e'],
    'step_scale': [' + 0x60', ' + 0x62'],
    'toggles': [' + 0x38', ' + 0x3c'],
}
AMPLITUDE_OFFSETS = [' + 0x50', ' + 0x54', ' + 0x56', ' + 0x58', ' + 0x5a']

KNOWN_CORE_NAMES = set([
    'FUN_0001a320','FUN_0001abfc','FUN_0001a528','FUN_0001a558','FUN_0001a614',
    'FUN_0001a3b0','FUN_0001a348','FUN_0001a440'
])

FUNC_NAME_RE = re.compile(r"\bFUN_[0-9a-fA-F]{8}\b")

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except: continue
                if 'function' in obj: yield obj

def classify(dec: str, name: str):
    # Count presence of core offset families
    families_present = {fam: any(tok in dec for tok in toks) for fam,toks in CORE_OFFSETS.items()}
    fam_count = sum(families_present.values())
    raw_hits = []
    for fam,toks in CORE_OFFSETS.items():
        for t in toks:
            if t in dec: raw_hits.append(t.strip())
    amplitude_refs = any(a in dec for a in AMPLITUDE_OFFSETS)
    # Heuristics:
    # 1. Known writer functions -> core
    # 2. If references at least two core families -> core
    # 3. If references >=3 distinct core offsets (even within families) -> core
    # 4. Else if only amplitude or single family -> consumer
    if name in KNOWN_CORE_NAMES:
        role='core'
    elif fam_count >=2:
        role='core'
    elif len(set(raw_hits)) >=3:
        role='core'
    else:
        if amplitude_refs or fam_count==1:
            role='consumer'
        else:
            role=None
    return role, families_present, raw_hits, amplitude_refs

def main():
    # Use dicts keyed by function name to collapse duplicate appearances across bundles
    core_map={}; cons_map={}; mapping={}
    for fn in iter_funcs():
        func=fn['function']; name=func['name']
        if not name.startswith('FUN_'): continue
        dec = fn.get('decompilation') or ''
        # Skip if no relevant offsets at all
        if not any(tok in dec for tok in (AMPLITUDE_OFFSETS + [t for toks in CORE_OFFSETS.values() for t in toks])):
            continue
        role, fams, hits, amp = classify(dec, name)
        if not role: continue
        families_list = [k for k,v in fams.items() if v]
        core_hits = len(set(hits))
        amplitude_flag = int(amp)
        target_map = core_map if role=='core' else cons_map
        existing = target_map.get(name)
        if existing:
            # Merge: union families, max core_hits, OR amplitude
            existing_fams = set(existing['families'].split(',')) if existing['families'] else set()
            existing_fams.update(families_list)
            existing['families'] = ','.join(sorted(f for f in existing_fams if f))
            if core_hits > existing['core_hits']:
                existing['core_hits'] = core_hits
            if amplitude_flag and not existing['amplitude']:
                existing['amplitude'] = 1
        else:
            target_map[name]={
                'name': name,
                'ea': f"0x{func['ea']:x}",
                'families': ','.join(families_list),
                'core_hits': core_hits,
                'amplitude': amplitude_flag
            }
        mapping[name]=role
    core_rows = sorted(core_map.values(), key=lambda r:(-r['core_hits'], r['name']))
    cons_rows = sorted(cons_map.values(), key=lambda r:r['name'])
    with OUT_CORE.open('w',encoding='utf-8') as f:
        f.write('# Vertical Core Functions (refined)\n\n')
        f.write(f'Total core: {len(core_rows)}\n\n')
        f.write('| Function | EA | Families | CoreHits | AmpRefs |\n|----------|----|----------|---------:|--------:|\n')
        for r in core_rows:
            f.write(f"| {r['name']} | {r['ea']} | {r['families']} | {r['core_hits']} | {r['amplitude']} |\n")
    with OUT_CONS.open('w',encoding='utf-8') as f:
        f.write('# Vertical Consumer Functions (refined)\n\n')
        f.write(f'Total consumers: {len(cons_rows)}\n\n')
        f.write('| Function | EA | Families | CoreHits | AmpRefs |\n|----------|----|----------|---------:|--------:|\n')
        for r in cons_rows:
            f.write(f"| {r['name']} | {r['ea']} | {r['families']} | {r['core_hits']} | {r['amplitude']} |\n")
    with OUT_JSON.open('w',encoding='utf-8') as f:
        json.dump(mapping,f,indent=2)
    print('Refinement complete: core', len(core_rows), 'consumer', len(cons_rows))

if __name__=='__main__':
    main()
