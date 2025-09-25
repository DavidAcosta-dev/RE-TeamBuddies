import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_amplitude_vertical_intersection.md'
# Goal: isolate functions that touch amplitude offsets (0x50/0x54/0x58) AND vertical core offsets (0x60/0x62 or 0x5c) to reduce false positives from generic object layout reuse.
AMP_OFFS = ['+ 0x50','+ 0x54','+ 0x58']
VERT_OFFS = ['+ 0x60','+ 0x62','+ 0x5c']


def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except: continue
                if 'function' in obj: yield obj


def main():
    hits=[]
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if not any(o in dec for o in AMP_OFFS): continue
        if not any(o in dec for o in VERT_OFFS): continue
        name=fn['function']['name']; ea=fn['function']['ea']
        # Gather context lines containing any of the offsets
        lines=dec.splitlines()
        rel=[l for l in lines if any(o.strip('+ ') in l for o in AMP_OFFS+VERT_OFFS)]
        snippet='\n'.join(rel[:40])
        hits.append({'name':name,'ea':f'0x{ea:x}','snippet':snippet[:800].replace('`','\'')})
    hits.sort(key=lambda r:r['name'])
    with OUT.open('w',encoding='utf-8') as f:
        f.write('# Functions touching both amplitude and vertical core fields\n\n')
        if not hits:
            f.write('No intersections found.\n'); return
        f.write('| Function | EA |\n|----------|----|\n')
        for h in hits:
            f.write(f"| {h['name']} | {h['ea']} |\n")
        f.write('\n## Snippets (truncated)\n\n')
        for h in hits[:80]:
            f.write(f"### {h['name']} {h['ea']}\n\n````\n{h['snippet']}\n````\n\n")
    print('Wrote', OUT.name, 'with', len(hits), 'intersections')

if __name__=='__main__':
    main()
