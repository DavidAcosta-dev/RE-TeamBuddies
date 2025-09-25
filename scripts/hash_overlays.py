#!/usr/bin/env python3
"""Compute hashes for overlay / core binary files.

Targets: TeamBuddiesGameFiles/*.BIN (and SCES* executable) plus SYSTEM.CNF.

Outputs:
  exports/overlay_hashes.md
  exports/overlay_hashes.json
"""
from __future__ import annotations
from pathlib import Path
import hashlib, json

ROOT = Path(__file__).resolve().parent.parent
GAME = ROOT / 'assets' / 'TeamBuddiesGameFiles'
EXPORTS = ROOT / 'exports'
EXPORTS.mkdir(exist_ok=True)
targets = []
if GAME.exists():
    for p in GAME.iterdir():
        if not p.is_file():
            continue
        ext_up = p.suffix.upper()
        if ext_up in {'.BIN','.DAT','.XA'} or p.name.startswith('SCES') or p.name == 'SYSTEM.CNF':
            targets.append(p)

def sha1(path: Path):
    h = hashlib.sha1()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

entries = []
def classify(name: str) -> str:
    if name.endswith('.BIN'):
        if name in {'GAME.BIN','SYS.BIN'}:
            return 'core'
        return 'overlay'
    if name.endswith('.DAT'):
        return 'container'
    if name.endswith('.XA'):
        return 'audio_xa'
    if name.startswith('SCES'):
        return 'boot'
    if name == 'SYSTEM.CNF':
        return 'config'
    return 'other'
for t in sorted(targets):
    size = t.stat().st_size
    digest = sha1(t)
    entries.append({'file': t.name, 'size': size, 'sha1': digest, 'class': classify(t.name)})

md = ['# Overlay / Core Binary Hashes','', f'Total files: {len(entries)}','', '| File | Class | Size (bytes) | SHA1 |','|------|-------|-------------:|------|']
for e in entries:
    md.append(f"| {e['file']} | {e['class']} | {e['size']} | {e['sha1']} |")

(EXPORTS / 'overlay_hashes.md').write_text('\n'.join(md), encoding='utf-8')
(EXPORTS / 'overlay_hashes.json').write_text(json.dumps(entries, indent=2), encoding='utf-8')
print(f'Wrote overlay hash listing for {len(entries)} files')
