import re, json
from pathlib import Path

SRC = Path('exports/vertical_amplitude_vertical_intersection.md')
OUT = Path('exports/vertical_amplitude_vertical_intersection_summary.md')

def main():
    if not SRC.exists():
        print('source missing'); return
    counts = {}
    with SRC.open('r',encoding='utf-8') as f:
        for line in f:
            if line.startswith('| FUN_'):
                parts = [p.strip() for p in line.strip().split('|') if p.strip()]
                if len(parts)>=2:
                    fn = parts[0]
                    counts[fn] = counts.get(fn,0)+1
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Summary: amplitude+vertical intersection unique functions\n\n')
        if not counts:
            out.write('No entries.\n'); return
        out.write('| Function | OccurrenceLines |\n|----------|----------------:|\n')
        for fn,c in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
            out.write(f'| {fn} | {c} |\n')
    print('Wrote summary with', len(counts), 'unique functions')

if __name__=='__main__':
    main()
