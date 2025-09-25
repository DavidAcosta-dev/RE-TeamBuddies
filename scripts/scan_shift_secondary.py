#!/usr/bin/env python3
"""
scan_shift_secondary.py

Locate lines performing >> 0xC shifts whose source operands come from secondary struct
fields ( *(int *)(param + 0x11c) + off ) or *(short *) variants. This aims to catch the
vertical integrator application if Y position = Y position + (velY >> 0xC) pattern resides
in secondary structure.

Outputs: shift_secondary_candidates.md
"""
from __future__ import annotations
import re,json
from pathlib import Path

BUNDLE_GLOB='exports/bundle_*.jsonl'
SHIFT_ANY=re.compile(r'>>\s*0x([0-9a-fA-F]+)|>>\s*(\d+)')
SRA_HINT=re.compile(r'sra\s')  # if raw MIPS disassembly lines appear in decompilation blobs
SEC_PAT_INT=re.compile(r'\(\*\(int \*\)\(param_\d+ \+ 0x11c\) \+ 0x([0-9a-fA-F]{2,3})\)')
SEC_DEREF_SHORT=re.compile(r'\*(?:short|undefined2) \*\)\(\*\(int \*\)\(param_\d+ \+ 0x11c\) \+ 0x([0-9a-fA-F]{2,3})\)')
# Array index form: (*(type **)(param_X + 0x11c))[index]
SEC_ARRAY_INDEX=re.compile(r'\(\*\([^)]*\*\)\(param_\d+ \+ 0x11c\)\)\[(0x[0-9a-fA-F]+|\d+)\]')

WINDOW=6

def iter_funcs():
    for p in Path('.').glob(BUNDLE_GLOB):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip();
                if not line: continue
                try:
                    obj=json.loads(line)
                except json.JSONDecodeError:
                    continue
                if 'function' in obj:
                    yield obj

def main():
    out=['# Secondary Shift (>>0xC) Candidates','']
    total=0
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if '+ 0x11c)' not in dec:
            continue
        lines=dec.splitlines()
        hit_blocks=[]
        for i,l in enumerate(lines):
            if not (SHIFT_ANY.search(l) or SRA_HINT.search(l)):
                continue
            # look back within WINDOW for a secondary struct field load
            window_lines=lines[max(0,i-WINDOW):i+1]
            secs=[]
            for wl in window_lines:
                for pat in (SEC_PAT_INT, SEC_DEREF_SHORT):
                    for m in pat.finditer(wl):
                        secs.append(int(m.group(1),16))
                for am in SEC_ARRAY_INDEX.finditer(wl):
                    # index-based usage; tag with high bit to separate from fixed offset, or just store as pseudo offset
                    idx_token=am.group(1)
                    try:
                        idx_val=int(idx_token,16) if idx_token.startswith('0x') else int(idx_token)
                        # encode as 0x800000 | idx
                        secs.append(0x800000 | idx_val)
                    except ValueError:
                        pass
            if secs:
                # capture shift amount if present
                m=SHIFT_ANY.search(l)
                if m:
                    amt = m.group(1) or m.group(2)
                elif SRA_HINT.search(l):
                    amt = 'sra?'
                else:
                    amt = '?'
                hit_blocks.append((i,sorted(set(secs)),l.strip(),window_lines,amt))
        if hit_blocks:
            total+=1
            fname=fn['function']['name']; ea=fn['function']['ea']
            out.append(f"## {fname} (ea=0x{ea:x})")
            for (idx,offs,line,ctx,amt) in hit_blocks[:6]:
                pretty=[]
                for o in offs:
                    if o & 0x800000:
                        pretty.append(f"idx[{hex(o & 0xFFFF)}]")
                    else:
                        pretty.append(hex(o))
                out.append(f"- L{idx} shift(amt={amt}) secondary refs={','.join(pretty)}")
                out.append(f"  line: {line}")
                for cl in ctx:
                    out.append(f"    {cl.strip()}")
            out.append('')
    if total==0:
        out.append('_No secondary shift candidates found._')
    with open('shift_secondary_candidates.md','w',encoding='utf-8') as f:
        f.write('\n'.join(out))
    print('Wrote shift_secondary_candidates.md; functions with hits:', total)

if __name__=='__main__':
    main()
