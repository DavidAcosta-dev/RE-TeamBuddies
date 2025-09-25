#!/usr/bin/env python3
"""
Extract printable ASCII text blocks from a binary file (e.g., BUDDIES.DAT).
Writes a combined text dump and marks offsets for each block.
"""
import sys, os, string
from pathlib import Path

ROOT = Path(os.path.expanduser('~'))/ 'tb-re'
ASSETS = ROOT / 'assets' / 'TeamBuddiesGameFiles'
OUT = ROOT / 'exports'

PRINTABLE = set(bytes(string.printable, 'ascii')) - set(b"\x0b\x0c")

def is_printable_byte(b: int) -> bool:
    return b in PRINTABLE and b not in (0x00,)

def is_printable_byte_ext(b: int) -> bool:
    # Latin-1-ish: allow tabs/newlines/CR and any byte >= 0x20
    return b in (0x09, 0x0a, 0x0d) or (b >= 0x20)

def extract_blocks(data: bytes, min_len: int = 64, latin1: bool = False):
    blocks = []
    i = 0
    n = len(data)
    is_ok = is_printable_byte_ext if latin1 else is_printable_byte
    while i < n:
        # skip non-printable
        while i < n and not is_ok(data[i]):
            i += 1
        start = i
        while i < n and is_ok(data[i]):
            i += 1
        end = i
        if end - start >= min_len:
            blk = data[start:end]
            # normalize newlines
            txt = blk.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            enc = 'latin-1' if latin1 else 'ascii'
            blocks.append((start, txt.decode(enc, errors='ignore')))
    return blocks

def main():
    in_path = ASSETS / 'BUDDIES.DAT'
    if len(sys.argv) > 1:
        in_path = Path(sys.argv[1])
    # Optional second arg: output path; default to exports/<stem>_ascii.txt
    if len(sys.argv) > 2:
        out_path = Path(sys.argv[2])
    else:
        out_path = OUT / f"{in_path.stem.lower()}_ascii.txt"
    # Optional third arg: min length for a block
    min_len = 40
    if len(sys.argv) > 3:
        try:
            min_len = int(sys.argv[3])
        except Exception:
            pass
    # Optional fourth arg: mode ('latin1' to broaden printable set)
    latin1 = False
    if len(sys.argv) > 4:
        latin1 = (str(sys.argv[4]).lower().strip() == 'latin1')
    out_path.parent.mkdir(parents=True, exist_ok=True)
    data = in_path.read_bytes()
    blocks = extract_blocks(data, min_len=min_len, latin1=latin1)
    with out_path.open('w', encoding='utf-8') as f:
        for off, txt in blocks:
            f.write(f"===== OFFSET 0x{off:08x} =====\n")
            f.write(txt)
            if not txt.endswith('\n'):
                f.write('\n')
            f.write('\n')
    print(f"Wrote {out_path} with {len(blocks)} blocks")

if __name__ == '__main__':
    main()
