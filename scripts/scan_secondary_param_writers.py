#!/usr/bin/env python3
"""
scan_secondary_param_writers.py

Two-pass scan to find callees that likely receive the secondary struct pointer
(*(int *)(X + 0x11c)) and then perform writes to +0x60 (index 0x30 as short) inside.

Pass 1: Find callsites that pass a deref of (+0x11c) as an argument to a direct function call
         of the form func_0xXXXXXXXX(...).
Pass 2: For the set of callee addresses collected in Pass 1, scan their bodies for direct writes:
         - *(<type> *)(param_k + 0x60) = ...
         - ((<type> *)param_k)[0x30] = ...

Limitations:
- Does not (yet) resolve indirect function pointers / virtual dispatch.
- Alias-based writes inside callee are not fully handled; we focus on direct param_k writes.

Output: secondary_param_writers.md
"""
from __future__ import annotations
import re, json
from pathlib import Path
from typing import Dict, Set, List, Tuple

BUNDLE_GLOB = 'exports/bundle_*.jsonl'

# Identify call lines that pass a deref of (+0x11c) as an argument
# Rough pattern: func_0xXXXXXXXX( ..., *(<cast>)(<expr> + 0x11c), ... )
CALL_WITH_11C_ARG = re.compile(r'func_0x([0-9a-fA-F]{6,8})\s*\([^\)]*\*\([^)]*\)\([^)]*\+\s*0x11c\)')

# Direct write patterns inside callee bodies
WRITE_PARAM_PLUS_60 = re.compile(
    r'\*\s*\((?:short|ushort|undefined2|int|uint|undefined4)\s*\*\)\s*\(param_\d+\s*\+\s*0x60\)\s*='
)
WRITE_PARAM_IDX_30 = re.compile(
    r'\(\s*\([^)]*\*\)\s*param_\d+\s*\)\s*\[\s*0x30\s*\]\s*='
)

# Optional: detect copy helpers where dest appears to be (param_k + off)
COPY_CALL = re.compile(r'func_0x([0-9a-fA-F]{6,8})\s*\(([^)]*)\)')
DEST_PARAM_PLUS = re.compile(r'\(param_\d+\s*\+\s*0x([0-9a-fA-F]{2,3})\)')
SIZE_ARG = re.compile(r'(?:0x[0-9a-fA-F]+|\d+)')


def iter_functions():
    for p in Path('.').glob(BUNDLE_GLOB):
        with p.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if 'function' in obj:
                    yield obj


def pass1_collect_callees() -> Set[int]:
    callees: Set[int] = set()
    for fn in iter_functions():
        dec = fn.get('decompilation') or ''
        if '+ 0x11c)' not in dec:
            continue
        for m in CALL_WITH_11C_ARG.finditer(dec):
            addr_hex = m.group(1)
            try:
                callees.add(int(addr_hex, 16))
            except ValueError:
                pass
    return callees


def pass2_scan_callees(callee_addrs: Set[int]) -> List[Tuple[str, int, str]]:
    rows: List[Tuple[str, int, str]] = []
    if not callee_addrs:
        return rows
    for fn in iter_functions():
        f_addr = int(fn['function']['ea'])
        if f_addr not in callee_addrs:
            continue
        dec = fn.get('decompilation') or ''
        # direct writes
        for l in dec.splitlines():
            if WRITE_PARAM_PLUS_60.search(l) or WRITE_PARAM_IDX_30.search(l):
                rows.append((fn['function']['name'], f_addr, l.strip()))
        # heuristic: look for copy calls where destination is (param_k + off) and size covers >= 0x62
        for m in COPY_CALL.finditer(dec):
            args = m.group(2)
            # quick parse: first arg as dest
            parts = [a.strip() for a in args.split(',')]
            if not parts:
                continue
            dest = parts[0]
            dm = DEST_PARAM_PLUS.search(dest)
            if not dm:
                continue
            try:
                off = int(dm.group(1), 16)
            except ValueError:
                continue
            if len(parts) >= 3:
                size = parts[2]
                sm = SIZE_ARG.fullmatch(size)
                if sm:
                    try:
                        size_val = int(size, 16) if size.lower().startswith('0x') else int(size)
                    except ValueError:
                        size_val = 0
                else:
                    size_val = 0
            else:
                size_val = 0
            if off <= 0x60 and size_val >= 0x62:
                rows.append((fn['function']['name'], f_addr, f"copy-like into param +0x{off:x}, size={size_val}"))
    return rows


def main():
    callees = pass1_collect_callees()
    rows = pass2_scan_callees(callees)
    with open('secondary_param_writers.md', 'w', encoding='utf-8') as f:
        f.write('# Secondary Param Writers (callees receiving *(..+0x11c))\n\n')
        f.write(f'- candidate callees from pass1: {len(callees)}\n')
        if not rows:
            f.write('\n_No direct param+0x60 or [0x30] writes found in candidate callees._\n')
        else:
            f.write('\n| Callee | EA | Evidence |\n|--------|----|----------|\n')
            for name, ea, line in rows:
                esc = line.replace('|', '\\|')
                f.write(f"| {name} | 0x{ea:x} | `{esc}` |\n")
    print('Wrote secondary_param_writers.md with', len(rows), 'rows; pass1 candidates:', len(callees))


if __name__ == '__main__':
    main()
