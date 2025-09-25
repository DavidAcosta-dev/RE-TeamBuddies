#!/usr/bin/env python3
"""
Search all game binaries for crate-related tokens in ASCII blocks.

This complements bundle-embedded strings_used by scanning raw EXE/BIN files.

Outputs: exports/crate_tokens_binary_scan.md
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'
GAME_DIR = ROOT / 'TeamBuddiesGameFiles'

TOKENS = [r'crate', r'throw', r'pickup', r'pick up', r'drop', r'carry', r'hold', r'place']
TOK_RX = [re.compile(t, re.IGNORECASE) for t in TOKENS]


def scan_bytes(data: bytes, rx):
    try:
        s = data.decode('latin-1', errors='ignore')
    except Exception:
        return []
    hits = []
    for r in rx:
        for m in r.finditer(s):
            hits.append((r.pattern, m.start()))
    return hits


def main():
    targets = []
    for p in GAME_DIR.glob('*.EXE'):
        targets.append(p)
    for p in GAME_DIR.glob('*.BIN'):
        targets.append(p)
    targets.sort()
    out = EXPORTS / 'crate_tokens_binary_scan.md'
    total = 0
    with out.open('w', encoding='utf-8') as f:
        f.write('# Crate-related tokens in raw binaries\n\n')
        f.write(f'Scanned {len(targets)} files under {GAME_DIR.name}\n\n')
        for p in targets:
            try:
                data = p.read_bytes()
            except Exception:
                continue
            hits = scan_bytes(data, TOK_RX)
            if not hits:
                continue
            total += len(hits)
            f.write(f'## {p.name}\n\n')
            # show up to 30 hits per file, grouped by token
            per_tok = {}
            for pat, off in hits:
                per_tok.setdefault(pat, []).append(off)
            for pat, offs in per_tok.items():
                offs = sorted(offs)
                if len(offs) > 20:
                    offs = offs[:20] + ['...']
                offs_s = ', '.join(str(o) for o in offs)
                f.write(f"- '{pat}' @ [{offs_s}]\n")
            f.write('\n')
    print('Wrote', out, 'total hits', total)


if __name__ == '__main__':
    main()
