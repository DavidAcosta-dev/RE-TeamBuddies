import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_updater_callers.md'
UPDATERS = ['FUN_0001abfc','FUN_0001a528','FUN_0001a558']
CALL_RES = {u: re.compile(rf'\b{u}\s*\(') for u in UPDATERS}
FLAG_PAT = re.compile(r'\(param_1 \+ 0x(24|8c)\)')
ACT_GATE_PAT = re.compile(r'\(param_1 \+ 0x88\)')
SEC_PTR_PAT = re.compile(r'\+ 0x11c')
STEP_PAT = re.compile(r'\+ 0x60')
SCALE_PAT = re.compile(r'\+ 0x62')
TOGGLE_PAT = re.compile(r'\+ 0x3c|\+ 0x38')


def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except: continue
                if 'function' in obj: yield obj

def main():
    rows=[]
    for fn in iter_funcs():
        dec = fn.get('decompilation') or ''
        name = fn['function']['name']; ea = fn['function']['ea']
        # skip the updater functions themselves
        if name in UPDATERS: continue
        if not any(cre.search(dec) for cre in CALL_RES.values()):
            continue
        lines = dec.splitlines()
        for idx,l in enumerate(lines):
            called = [u for u,cre in CALL_RES.items() if cre.search(l)]
            if not called: continue
            window_lines = lines[max(0,idx-10): idx+11]
            window = '\n'.join(window_lines)
            score = 0
            score += 2 if SEC_PTR_PAT.search(window) else 0
            score += 1 if FLAG_PAT.search(window) else 0
            score += 1 if ACT_GATE_PAT.search(window) else 0
            score += 1 if STEP_PAT.search(window) else 0
            score += 1 if SCALE_PAT.search(window) else 0
            score += 1 if TOGGLE_PAT.search(window) else 0
            rows.append({
                'caller': name,
                'ea': f'0x{ea:x}',
                'called': ','.join(called),
                'line': idx+1,
                'score': score,
                'flags': 'F' if FLAG_PAT.search(window) else '',
                'gate': 'G' if ACT_GATE_PAT.search(window) else '',
                'sec': 'S' if SEC_PTR_PAT.search(window) else '',
                'st': 'T' if STEP_PAT.search(window) else '',
                'sc': 'C' if SCALE_PAT.search(window) else '',
                'tog': 'X' if TOGGLE_PAT.search(window) else '',
                'snippet': window.replace('`','\'')[:800]
            })
    with OUT.open('w',encoding='utf-8') as f:
        f.write('# Vertical updater caller candidates\n\n')
        if not rows:
            f.write('No callers detected.\n')
            return
        # sort by score desc
        rows.sort(key=lambda r:r['score'], reverse=True)
        f.write('| Caller | EA | Calls | Line | Score | Marks (S=sec,F=flag,G=gate,T=step,C=scale,X=toggle) |\n')
        f.write('|--------|----|-------|------|-------|-----------------------------------------------|\n')
        for r in rows:
            marks = ''.join([r['sec'],r['flags'],r['gate'],r['st'],r['sc'],r['tog']])
            f.write(f"| {r['caller']} | {r['ea']} | {r['called']} | {r['line']} | {r['score']} | {marks} |\n")
        f.write('\n## Snippets\n\n')
        for r in rows[:80]:  # limit snippet dump
            f.write(f"### {r['caller']} {r['ea']} line {r['line']} score={r['score']}\n\n````\n{r['snippet']}\n````\n\n")
    print('Wrote', OUT.name, 'with', len(rows), 'rows')

if __name__=='__main__':
    main()
