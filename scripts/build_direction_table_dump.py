#!/usr/bin/env python3
"""
build_direction_table_dump.py

Extracts separate sin/cos 4096-entry short arrays from discovered bases and emits an interleaved
dump suitable for Unity `DirectionTable` external injection (supports idx,a,b,hex format).

Defaults use candidate bases from multi-segment probe:
  sin_base=0x26800  cos_base=0x27800 (order assumed; will also output radius stats)

Usage:
  python build_direction_table_dump.py --bin ".../MAIN.EXE" --sin 0x26800 --cos 0x27800 --out direction_table_dump.txt
"""
from __future__ import annotations
import argparse, struct, math
from pathlib import Path

COUNT=4096

def load_shorts(data, base):
    size=COUNT*2
    seg=data[base:base+size]
    if len(seg)<size:
        raise SystemExit(f"Segment truncated at 0x{base:x}")
    return struct.unpack('<'+'h'*COUNT, seg)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--bin', required=True)
    ap.add_argument('--sin', required=True, help='hex base of sin array')
    ap.add_argument('--cos', required=True, help='hex base of cos array')
    ap.add_argument('--out', default='direction_table_dump.txt')
    args=ap.parse_args()
    sin_base=int(args.sin,16); cos_base=int(args.cos,16)
    data=Path(args.bin).read_bytes()
    sin_vals=load_shorts(data,sin_base)
    cos_vals=load_shorts(data,cos_base)
    # radius stats
    radii=[math.hypot(cos_vals[i], sin_vals[i]) for i in range(COUNT)]
    mean_r=sum(radii)/COUNT
    max_r=max(radii)
    min_r=min(radii)
    var_r=sum((r-mean_r)**2 for r in radii)/COUNT
    with open(args.out,'w',encoding='utf-8') as f:
        f.write(f"# idx,cos,sin,hexPair  meanR={mean_r:.2f} varR={var_r:.2f} minR={min_r:.2f} maxR={max_r:.2f}\n")
        for i in range(COUNT):
            c=cos_vals[i]; s=sin_vals[i]
            raw=(c & 0xffff) | ((s & 0xffff)<<16)
            f.write(f"{i},{c},{s},0x{raw:08x}\n")
    print(f"Wrote {args.out} (meanR={mean_r:.2f} varR={var_r:.2f})")

if __name__=='__main__':
    main()
