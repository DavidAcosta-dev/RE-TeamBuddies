#!/usr/bin/env python3
import os, json, sys, collections

ROOT = os.path.join(os.path.expanduser('~'), 'tb-re')
EX = os.path.join(ROOT, 'exports')
MERGED = os.path.join(EX, 'bundle_ghidra.jsonl')
BOOK = os.path.join(EX, 'suspects_bookmarks.json')

limit = int(sys.argv[1]) if len(sys.argv) > 1 else 12

# Load merged bundle as lookup: (binary,name)->rec and by EA
by_key = {}
by_ea = collections.defaultdict(dict)
with open(MERGED, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        b = (rec.get('binary') or '').strip()
        fn = rec.get('function') or {}
        name = fn.get('name')
        ea = fn.get('ea')
        if not name:
            continue
        by_key[(b, name)] = rec
        if ea is not None:
            by_ea[b][ea] = rec

with open(BOOK, 'r', encoding='utf-8') as f:
    bookmarks = json.load(f)

def write_markdown_for_binary(bin_name, items):
    safe = ''.join(ch if ch.isalnum() or ch in '._-' else '_' for ch in (bin_name or 'unknown'))
    outp = os.path.join(EX, f'snippets_{safe}.md')
    with open(outp, 'w', encoding='utf-8') as out:
        out.write(f'# Snippets for {bin_name}\n\n')
        for i, it in enumerate(items, 1):
            ea = it.get('ea')
            nm = it.get('name')
            new_name = it.get('new_name')
            tags = it.get('tags') or []
            score = it.get('score')
            rec = by_ea.get(bin_name, {}).get(ea) or by_key.get((bin_name, nm))
            dec = (rec or {}).get('decompilation') or ''
            strings = (rec or {}).get('strings_used') or []
            out.write(f'## {i}. {new_name or nm} @ 0x{ea:08x}  tags:{",".join(tags)}  score:{score}\n\n')
            if strings:
                out.write('Strings:\n')
                for s in strings[:8]:
                    try:
                        out.write(f'- 0x{s.get("offset"):08x}: {s.get("text","")[:120]}\n')
                    except Exception:
                        pass
                out.write('\n')
            if dec:
                out.write('```c\n')
                out.write(dec)
                out.write('\n```\n\n')
            else:
                out.write('(no decompilation available)\n\n')
    return outp

generated = []
for bname, items in bookmarks.items():
    # Take physics first, then controller
    phys = [it for it in items if (it.get('category') == 'physics')]
    ctrl = [it for it in items if (it.get('category') == 'controller')]
    chosen = (phys[:limit] + ctrl[: max(0, limit - len(phys))])[:limit]
    if not chosen:
        continue
    path = write_markdown_for_binary(bname, chosen)
    generated.append(path)

print('Wrote:', *generated, sep='\n - ')
