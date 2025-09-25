#!/usr/bin/env python3
"""
trig_multi_segment_probe.py

Attempt to locate two separate 8KB (4096 * short) regions that together form sin/cos tables.
Strategy:
 1. Scan binary for candidate sine-like blocks: mean(abs(values)) within range, low variance of radius when hypot with some shifted version.
 2. For each candidate A, attempt pairing with other candidate B by computing combined radii R[i] = sqrt(A[i]^2 + B[i]^2) for sample indices.
 3. Score pairs by variance of R and closeness of mean(R) across sample.

Outputs: trig_multi_segment_pairs.csv (top scoring pairs) and preview best pair -> trig_multi_segments_preview.txt
"""
from __future__ import annotations
import argparse, struct, math, statistics
from pathlib import Path

def load_shorts(data, base, count):
    return struct.unpack_from('<' + 'h'*count, data, base)

def candidate_blocks(data, count=4096, step=512, limit=None):
    lim = len(data) if limit is None else min(limit,len(data))
    size = count*2
    cands=[]
    for base in range(0, lim-size, step):
        block = load_shorts(data, base, count)
        absvals=[abs(x) for x in block]
        meanA=sum(absvals)/count
        if not (300 <= meanA <= 6000):
            continue
        # Rough energy check: not all zeros, not saturated
        if max(absvals) < 400: continue
        cands.append((base,meanA))
    return cands

def score_pair(data, a_base, b_base, count=4096, samples=256):
    A=load_shorts(data,a_base,count)
    B=load_shorts(data,b_base,count)
    step=max(1,count//samples)
    radii=[]
    for i in range(0,count,step):
        r=math.hypot(A[i],B[i])
        radii.append(r)
    meanR=sum(radii)/len(radii)
    varR=sum((r-meanR)**2 for r in radii)/len(radii)
    return meanR,varR

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--bin', required=True)
    ap.add_argument('--count', type=int, default=4096)
    ap.add_argument('--step', type=int, default=512)
    ap.add_argument('--limit', type=int, default=4000000)
    ap.add_argument('--pairs', type=int, default=2000, help='max pairs to score (sample)')
    ap.add_argument('--out', default='trig_multi_segment_pairs.csv')
    args=ap.parse_args()
    data=Path(args.bin).read_bytes()[:args.limit]
    cands=candidate_blocks(data, args.count, args.step, args.limit)
    if len(cands)<2:
        print('Not enough candidate blocks.')
        return
    # Simple sampling of pairs (first N^2 naive but cap by pairs argument)
    pairs=[]
    for i in range(min(len(cands),100)):
        for j in range(i+1,min(len(cands),100)):
            if len(pairs) >= args.pairs: break
            a_base=cands[i][0]; b_base=cands[j][0]
            meanR,varR=score_pair(data,a_base,b_base,args.count)
            if varR < (meanR*0.3)**2: # loose acceptance
                pairs.append((varR,meanR,a_base,b_base))
        if len(pairs) >= args.pairs: break
    if not pairs:
        print('No viable sin/cos pairings found.')
        return
    pairs.sort(key=lambda x:(x[0],abs(x[1]-2048)))
    with open(args.out,'w',encoding='utf-8') as f:
        f.write('varR,meanR,a_base,b_base\n')
        for varR,meanR,a,b in pairs[:200]:
            f.write(f"{varR:.2f},{meanR:.2f},0x{a:x},0x{b:x}\n")
    # preview best 32 lines interleaved
    best=pairs[0]
    A=load_shorts(data,best[2],args.count)
    B=load_shorts(data,best[3],args.count)
    with open('trig_multi_segments_preview.txt','w',encoding='utf-8') as f:
        for i in range(32):
            f.write(f"{i},{A[i]},{B[i]}\n")
    print(f"Wrote {args.out}; best pair bases=0x{best[2]:x},0x{best[3]:x}")

if __name__=='__main__':
    main()
