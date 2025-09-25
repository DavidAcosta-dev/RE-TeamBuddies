#!/usr/bin/env python3
"""
trig_table_split_probe.py

Detect trig table stored as two contiguous 4096-entry signed short arrays:
  sin[4096] followed by cos[4096] (or vice versa).

Heuristic:
  - Slide candidate base over binary (step configurable).
  - For each base, take 4096 shorts (A) and next 4096 shorts (B).
  - Compute amplitude stats: max(|A|), max(|B|), mean(|A|), mean(|B|) expecting ~ similar scale.
  - Correlate A and B phase shift: For a few sample indices i, check approximate Pythagorean identity A[i]^2 + B[i]^2 ~= R^2 with low variance.
  - Accept candidates with:
      * amplitude bounds within [300, 6000]
      * radius variance below threshold.

Outputs: trig_table_split_candidates.csv (top 200) and preview dump (interleaved pairs) at trig_table_split_preview.txt
"""
from __future__ import annotations
import argparse, struct, math, statistics
from pathlib import Path

def analyze_block(data, base, count=4096):
    need = (count*2)*2  # two arrays * shorts (2 bytes)
    if base+need > len(data):
        return None
    A = struct.unpack_from('<' + 'h'*count, data, base)
    B = struct.unpack_from('<' + 'h'*count, data, base + count*2)
    absA=[abs(x) for x in A]; absB=[abs(x) for x in B]
    maxA=max(absA); maxB=max(absB)
    meanA=sum(absA)/count; meanB=sum(absB)/count
    if not (300 <= meanA <= 6000 and 300 <= meanB <= 6000):
        return None
    if maxA < 500 or maxB < 500: return None
    # Sample radii at stride
    stride = max(1, count//256)
    radii=[]
    for i in range(0, count, stride):
        r2 = A[i]*A[i] + B[i]*B[i]
        r = math.sqrt(r2)
        radii.append(r)
    meanR = sum(radii)/len(radii)
    varR = sum((r-meanR)**2 for r in radii)/len(radii)
    if varR > (meanR*0.25)**2: # loose threshold
        return None
    return {'base':base,'meanA':meanA,'meanB':meanB,'maxA':maxA,'maxB':maxB,'meanR':meanR,'varR':varR}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--bin', required=True)
    ap.add_argument('--count', type=int, default=4096)
    ap.add_argument('--limit', type=int, default=3000000)
    ap.add_argument('--step', type=int, default=256)
    ap.add_argument('--out', default='trig_table_split_candidates.csv')
    args=ap.parse_args()
    data=Path(args.bin).read_bytes()[:args.limit]
    results=[]
    for base in range(0, len(data)-(args.count*4), args.step):
        res=analyze_block(data, base, args.count)
        if res:
            results.append(res)
    if not results:
        print('No split sin/cos table candidates found.')
        return
    results.sort(key=lambda r: (abs(r['meanA']-r['meanB']), r['varR']))
    with open(args.out,'w',encoding='utf-8') as f:
        f.write('base,meanA,meanB,maxA,maxB,meanR,varR\n')
        for r in results[:200]:
            f.write(f"0x{r['base']:x},{r['meanA']:.1f},{r['meanB']:.1f},{r['maxA']},{r['maxB']},{r['meanR']:.1f},{r['varR']:.1f}\n")
    # preview best
    best=results[0]
    A = struct.unpack_from('<' + 'h'*args.count, data, best['base'])
    B = struct.unpack_from('<' + 'h'*args.count, data, best['base'] + args.count*2)
    with open('trig_table_split_preview.txt','w',encoding='utf-8') as f:
        for i in range(64):
            f.write(f"{i},{A[i]},{B[i]}\n")
    print(f"Wrote {args.out} with {len(results)} candidates; best base=0x{best['base']:x} preview trig_table_split_preview.txt")

if __name__=='__main__':
    main()
