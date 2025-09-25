#!/usr/bin/env python3
"""
trig_table_probe.py

Attempt to automatically guess trig table base candidates from a binary by scanning for a
16K region (default 4096 entries * 4 bytes) whose 16-bit signed pairs approximate a circle.

Heuristic:
  - Slide over binary in stride of 2 bytes.
  - For each candidate block of size count*stride (default 4096*4), sample N evenly spaced entries.
  - Compute mean radius R = mean(sqrt(x^2 + y^2)), and variance of R; require low variance and
    value range near expected scale (we expect magnitudes around FixedPoint 1.0 ~= 0x1000 scale).
  - Additionally, monotonic angle progression: atan2(y,x) differences mostly positive (mod 2pi).

Outputs: trig_table_probe_candidates.csv and first plausible dump (preview) to trig_table_probe_preview.txt

This is an expensive heuristic; keep sample rate modest.
"""
from __future__ import annotations
import argparse, struct, math, statistics
from pathlib import Path

def score_region(data: bytes, base: int, count=4096, stride=4, samples=128):
    step = max(1, count // samples)
    radii=[]; angles=[]
    for i in range(0, count, step):
        off = base + i*stride
        chunk = data[off:off+stride]
        if len(chunk) < 4:
            return None
        x,y = struct.unpack('<hh', chunk[:4])
        # filter zero or absurd values
        r = math.hypot(x,y)
        if r == 0: return None
        radii.append(r)
        ang = math.atan2(y,x)
        angles.append(ang)
    if len(radii) < samples//4: # not enough
        return None
    mean_r = statistics.mean(radii)
    var_r = statistics.pvariance(radii)
    # Expect radius roughly constant; allow some scale range 500..7000 (tunable)
    if not (500 <= mean_r <= 7000):
        return None
    # variance threshold (empirical)
    if var_r > (mean_r * 0.2)**2:
        return None
    # angle progression check
    inc_count=0; last=angles[0]
    for a in angles[1:]:
        d=a-last
        # allow wrap
        if d < -math.pi: d += 2*math.pi
        if d > 0: inc_count+=1
        last=a
    inc_ratio = inc_count / max(1,len(angles)-1)
    if inc_ratio < 0.7:
        return None
    return {'mean_r':mean_r,'var_r':var_r,'inc_ratio':inc_ratio}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--bin', required=True)
    ap.add_argument('--count', type=int, default=4096)
    ap.add_argument('--stride', type=int, default=4)
    ap.add_argument('--limit', type=int, default=2000000, help='scan at most first N bytes')
    ap.add_argument('--step', type=int, default=64, help='coarse base increment in bytes')
    ap.add_argument('--samples', type=int, default=128)
    ap.add_argument('--out', default='trig_table_probe_candidates.csv')
    args=ap.parse_args()
    data = Path(args.bin).read_bytes()[:args.limit]
    size = args.count * args.stride
    results=[]
    for base in range(0, len(data)-size, args.step):
        sc = score_region(data, base, args.count, args.stride, args.samples)
        if sc:
            results.append((base, sc['mean_r'], sc['var_r'], sc['inc_ratio']))
    if not results:
        print('No circular pattern regions found.')
        return
    results.sort(key=lambda x: (abs(x[1]-2048), x[2]))
    with open(args.out,'w',encoding='utf-8') as f:
        f.write('base,mean_r,var_r,inc_ratio\n')
        for b,mr,vr,ir in results[:200]:
            f.write(f"0x{b:x},{mr:.2f},{vr:.2f},{ir:.3f}\n")
    # Dump preview of best candidate first 32 entries
    best = results[0][0]
    with open('trig_table_probe_preview.txt','w',encoding='utf-8') as f:
        for i in range(32):
            off = best + i*args.stride
            x,y = struct.unpack('<hh', data[off:off+4])
            f.write(f"{i},{x},{y}\n")
    print(f"Wrote {args.out} with {len(results)} candidates; best base=0x{best:x} -> preview trig_table_probe_preview.txt")

if __name__=='__main__':
    main()
