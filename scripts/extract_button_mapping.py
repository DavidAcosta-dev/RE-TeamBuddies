#!/usr/bin/env python3
"""
Extract action button id -> name mapping from comment lines in buddies_ascii.txt.
Looks for lines like:
  buttonON 0 ; jump
  buttonON 12 ; kicking/entering vehicle
Writes exports/action_button_ids.json
"""
import re, os
from pathlib import Path
import json

ROOT = Path(os.path.expanduser('~'))/ 'tb-re'
OUT = ROOT / 'exports'
ASCII = OUT / 'buddies_ascii.txt'

RE_MAP = re.compile(r'^\s*buttonON\s+(-?\d+)(?:\s*,\s*(-?\d+))?(?:\s*,\s*(-?\d+))?(?:\s*,\s*(-?\d+))?\s*;\s*(.+?)\s*$')

def main():
    if not ASCII.exists():
        print('No buddies_ascii.txt found at', ASCII)
        return
    mapping = {}
    lines = ASCII.read_text(encoding='utf-8', errors='ignore').splitlines()
    for ln in lines:
        m = RE_MAP.match(ln)
        if not m:
            continue
        name = m.group(5).strip()
        for i in range(1,5):
            g = m.group(i)
            if g is None or g == '':
                continue
            try:
                idx = int(g)
            except ValueError:
                continue
            mapping[idx] = name
    outp = OUT / 'action_button_ids.json'
    outp.write_text(json.dumps(mapping, indent=2), encoding='utf-8')
    print('Wrote', outp, 'with', len(mapping), 'entries')

if __name__ == '__main__':
    main()
