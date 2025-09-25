#!/usr/bin/env python3
import json, os, collections
from pathlib import Path

ROOT = Path(os.path.expanduser('~'))/ 'tb-re'
OUT = ROOT / 'exports'

def main():
    data_p = OUT / 'buddies_script.json'
    if not data_p.exists():
        print('No parsed script found at', data_p)
        return
    lessons = json.loads(data_p.read_text(encoding='utf-8'))
    wait_counts = collections.Counter()
    if_counts = collections.Counter()
    buttonset_freq = collections.Counter()
    buttonon_freq = collections.Counter()
    buttonoff_freq = collections.Counter()
    combos = collections.Counter()
    for blk in lessons:
        curset = tuple()
        for op in blk.get('ops', []):
            if op['op'] == 'wait':
                wait_counts[op['cond']] += 1
            elif op['op'] == 'if':
                tag = ('NOT_' if op.get('neg') else '') + op.get('cond','')
                if_counts[tag] += 1
            elif op['op'] == 'buttonSET':
                vals = tuple(op.get('values') or [])
                buttonset_freq[vals] += 1
                curset = vals
            elif op['op'] == 'buttonON':
                for v in (op.get('values') or []):
                    buttonon_freq[v] += 1
            elif op['op'] == 'buttonOFF':
                for v in (op.get('values') or []):
                    buttonoff_freq[v] += 1
        if curset:
            combos[curset] += 1
    outp = OUT / 'buddies_script_summary.md'
    with outp.open('w', encoding='utf-8') as f:
        f.write('# Tutorial DSL summary\n\n')
        f.write('## Most common waits\n\n')
        for k,c in wait_counts.most_common(40):
            f.write(f'- wait_{k}: {c}\n')
        f.write('\n## Most common if-conditions\n\n')
        for k,c in if_counts.most_common(40):
            f.write(f'- if_{k}: {c}\n')
        f.write('\n## buttonSET combos (top)\n\n')
        for k,c in combos.most_common(30):
            f.write(f'- {", ".join(k)}: {c}\n')
        f.write('\n## buttonON (individual)\n\n')
        for k,c in buttonon_freq.most_common(30):
            f.write(f'- {k}: {c}\n')
        f.write('\n## buttonOFF (individual)\n\n')
        for k,c in buttonoff_freq.most_common(30):
            f.write(f'- {k}: {c}\n')
    print('Wrote', outp)

if __name__ == '__main__':
    main()
