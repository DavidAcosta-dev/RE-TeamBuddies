from pathlib import Path
SRC = Path('exports/vertical_offset_0x88_write_classes.md')
OUT = Path('exports/vertical_offset_0x88_write_classes_summary.md')

def main():
    if not SRC.exists():
        print('missing source'); return
    counts = {}
    dedup=set()
    with SRC.open('r',encoding='utf-8') as f:
        for line in f:
            if line.startswith('| FUN_'):
                # | Function | EA | Line | Class | Code |
                cols=[c.strip() for c in line.split('|')]
                if len(cols)<6: continue
                fn=cols[1]; cls=cols[4]
                key=(fn,cls,cols[3])  # function,class,EA pair basis
                if key in dedup: continue
                dedup.add(key)
                counts[(fn,cls)] = counts.get((fn,cls),0)+1
    agg={}
    for (fn,cls),n in counts.items():
        agg.setdefault(fn,{})[cls]=agg.setdefault(fn,{}).get(cls,0)+n
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Summary +0x88 write classes per function (dedup by EA/class)\n\n')
        out.write('| Function | zero | one | neg1 | gp_rel | other_func_call | other |\n|----------|-----:|----:|-----:|-------:|-----------------:|------:|\n')
        for fn in sorted(agg):
            cl=agg[fn]
            out.write(f"| {fn} | {cl.get('zero',0)} | {cl.get('one',0)} | {cl.get('neg1',0)} | {cl.get('gp_rel',0)} | {cl.get('other_func_call',0)} | {cl.get('other',0)} |\n")
    print('Wrote summary for', len(agg), 'functions')

if __name__=='__main__':
    main()
