#!/usr/bin/env python3
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
bookmarks = root / 'exports' / 'suspects_bookmarks.json'
out = root / 'js-sim' / 'findings.json'

with open(bookmarks, 'r', encoding='utf-8') as f:
    data = json.load(f)

# Extract a compact list of physics suspects per binary, keep top-N by score
TOP_N = 10
result = {}
for binary, items in data.items():
    phys = [it for it in items if it.get('category') == 'physics']
    phys.sort(key=lambda x: x.get('score', 0), reverse=True)
    result[binary] = [
        {
            'ea': it['ea'],
            'name': it['name'],
            'alias': it.get('new_name', it['name']),
            'score': it.get('score', 0)
        }
        for it in phys[:TOP_N]
    ]

with open(out, 'w', encoding='utf-8') as f:
    json.dump(result, f, indent=2)

print(f'Wrote findings to {out}')
