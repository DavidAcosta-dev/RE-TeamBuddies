#!/usr/bin/env python3
"""
dump_trig_table_scaffold.py

Scaffold to extract the 4096-entry directional trig table (pairs of 16-bit values) once the
base file offset is known. You must supply:
  --bin  Path to MAIN.EXE (or relevant binary containing table)
  --base Hex file offset where the table begins (e.g. 0x123456)
  --count Number of entries (default 4096)
  --stride Bytes per logical entry (default 4: two signed 16-bit shorts)
  --out Output text file (default direction_table_dump.txt)

The script will:
  - Seek to base
  - Read count * stride bytes
  - Interpret each entry as (short, short)
  - Output lines: idx,shortX,shortY,hexRaw

You can then load this file in Unity via the existing external injection path.

Note: You still have to discover the base offset. Common approach: locate function using &0xFFF
mask with index multiply. Use disassembly or earlier integrator/orientation function cross refs.
"""
from __future__ import annotations
import argparse
import struct
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bin', required=True, help='Path to MAIN.EXE or binary containing table')
    ap.add_argument('--base', required=True, help='Hex file offset (e.g., 0x123456)')
    ap.add_argument('--count', type=int, default=4096)
    ap.add_argument('--stride', type=int, default=4)
    ap.add_argument('--out', default='direction_table_dump.txt')
    args = ap.parse_args()

    base = int(args.base, 16)
    size = args.count * args.stride
    path = Path(args.bin)
    data = path.read_bytes()
    if base + size > len(data):
        raise SystemExit(f"Requested range exceeds file size: base=0x{base:x} size=0x{size:x} file=0x{len(data):x}")

    with open(args.out, 'w', encoding='utf-8') as f:
        f.write('# idx,sinLike,cosLike,rawHex\n')
        for i in range(args.count):
            off = base + i * args.stride
            chunk = data[off: off + args.stride]
            if len(chunk) < args.stride:
                break
            if args.stride >= 4:
                a, b = struct.unpack('<hh', chunk[:4])
            elif args.stride == 2:
                a, = struct.unpack('<h', chunk)
                b = 0
            else:
                # Fallback: treat first two bytes as signed, rest ignored
                a, = struct.unpack('<h', chunk[:2])
                b = 0
            f.write(f"{i},{a},{b},{chunk.hex()}\n")
    print(f"Dumped {args.count} entries to {args.out}")

if __name__ == '__main__':
    main()
