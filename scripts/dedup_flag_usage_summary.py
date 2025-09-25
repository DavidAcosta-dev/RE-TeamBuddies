import pathlib, re, collections

SRC = pathlib.Path('exports/vertical_flag_usage.md')
DST = pathlib.Path('exports/vertical_flag_usage_summary.md')
ROW_RE = re.compile(r'^\| (?P<fn>FUN_[0-9a-f]+) \| (?P<ea>0x[0-9a-f]+) \| (?P<line>\d+) \| (?P<kind>read|write) \| `(?P<src>.+)` \|')

def main():
    if not SRC.exists():
        print('Source flag usage file missing')
        return
    per_fn = {}
    with SRC.open('r',encoding='utf-8') as f:
        for line in f:
            m = ROW_RE.match(line)
            if not m: continue
            fn = m.group('fn'); kind = m.group('kind'); src = m.group('src')
            rec = per_fn.setdefault(fn, {'reads':0,'writes':0,'off24':0,'off8c':0})
            if kind == 'read': rec['reads'] += 1
            else: rec['writes'] += 1
            if '+ 0x24' in src or '(param_1 + 0x24)' in src: rec['off24'] += 1
            if '+ 0x8c' in src or '(param_1 + 0x8c)' in src: rec['off8c'] += 1
    with DST.open('w',encoding='utf-8') as out:
        out.write('# Deduplicated flag usage summary (+0x24 / +0x8c)\n\n')
        if not per_fn:
            out.write('No data parsed.\n'); return
        out.write('| Function | Reads | Writes | +0x24 refs | +0x8c refs |\n|----------|------:|-------:|-----------:|-----------:|\n')
        for fn in sorted(per_fn):
            r=per_fn[fn]
            out.write(f"| {fn} | {r['reads']} | {r['writes']} | {r['off24']} | {r['off8c']} |\n")
    print(f'Wrote summary for {len(per_fn)} functions')

if __name__=='__main__':
    main()
