#!/usr/bin/env python3
import os, glob, json, sys, time

ROOT = os.path.join(os.path.expanduser('~'), 'tb-re')
EX = os.path.join(ROOT, 'exports')
OUT = os.path.join(EX, 'bundle_ghidra.jsonl')  # output
CHUNK_PRINT = 10000  # print every N records

bundles = sorted(glob.glob(os.path.join(EX, 'bundle_*.jsonl')))

if not bundles:
    print('No bundle_*.jsonl files found in', EX, flush=True)
    sys.exit(1)

# Exclude OUT if it exists so we never try to read what we're writing
bundles = [p for p in bundles if os.path.abspath(p) != os.path.abspath(OUT)]

print(f'Found {len(bundles)} input bundles under {EX}', flush=True)

total = 0
t0 = time.time()
with open(OUT, 'w', encoding='utf-8') as out:
    for i, path in enumerate(bundles, 1):
        start = time.time()
        wrote_this_file = 0
        print(f'[{i}/{len(bundles)}] Merging: {os.path.basename(path)}', flush=True)

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                out.write(json.dumps(rec, ensure_ascii=False) + '\n')
                wrote_this_file += 1
                total += 1
                if (total % CHUNK_PRINT) == 0:
                    dt = time.time() - t0
                    rate = int(total / dt) if dt > 0 else 0
                    print(f'  … {total:,} records total ({rate:,}/s)', flush=True)

        dt_file = time.time() - start
        print(f'  Done {os.path.basename(path)}: {wrote_this_file:,} records in {dt_file:.1f}s', flush=True)

dt = time.time() - t0
rate = int(total / dt) if dt > 0 else 0
print(f'✅ Merged {len(bundles)} bundles, wrote {total:,} records to {OUT} in {dt:.1f}s ({rate:,}/s)', flush=True)
