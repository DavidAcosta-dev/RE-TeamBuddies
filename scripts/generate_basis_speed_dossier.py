#!/usr/bin/env python3
"""
generate_basis_speed_dossier.py

Cluster top functions by basis (dest/src) + speed evidence from Q12 scanner
and extract short sample lines for rapid tagging of orientation update paths.

Output: exports/basis_speed_dossier.md
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"
Q12_JSON = EXPORTS / "q12_math_candidates.json"
OUT_MD = EXPORTS / "basis_speed_dossier.md"


def main() -> None:
    data = json.loads(Q12_JSON.read_text(encoding='utf-8'))
    cands = data.get('candidates', [])

    # Rank by (basis_dest + basis_src) then speed, then weighted score
    def key(e: dict):
        return (
            -(e.get('basis_dest_hits', 0) + e.get('basis_src_hits', 0)),
            -e.get('speed_hits', 0),
            -(
                3 * e.get('right_shifts', 0)
                + 2 * e.get('q12_products', 0)
                + 2 * e.get('sar_calls', 0)
                + 2 * e.get('angle_masks', 0)
                + 1 * e.get('left_shifts', 0)
                + 1 * e.get('pos_shifts', 0)
                + 1 * e.get('q12_one_consts', 0)
                + 1 * e.get('q12_half_consts', 0)
            ),
            e.get('name', '')
        )

    ranked = sorted(cands, key=key)

    lines: List[str] = []
    lines.append('# Basis + Speed Dossier')
    lines.append('')
    lines.append('| Rank | Function | Bin | BD | BS | Spd | Pxyz | Ang | WScore |')
    lines.append('| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |')
    for i, e in enumerate(ranked[:40], start=1):
        wscore = (
            3 * e.get('right_shifts', 0)
            + 2 * e.get('q12_products', 0)
            + 2 * e.get('sar_calls', 0)
            + 2 * e.get('angle_masks', 0)
            + 1 * e.get('left_shifts', 0)
            + 1 * e.get('pos_shifts', 0)
            + 1 * e.get('q12_one_consts', 0)
            + 1 * e.get('q12_half_consts', 0)
        ) or e.get('total_hits', 0)
        lines.append(
            f"| {i} | {e.get('name')} | {e.get('binary','')} | {e.get('basis_dest_hits',0)} | {e.get('basis_src_hits',0)} | {e.get('speed_hits',0)} | {e.get('pos_hits',0)} | {e.get('angle_hits',0)} | {wscore} |"
        )
    lines.append('')
    lines.append('Top 40 by basis+speed evidence. Prioritize for tagging orientation update paths.')

    OUT_MD.write_text('\n'.join(lines), encoding='utf-8')
    print(f"Wrote {OUT_MD}")


if __name__ == '__main__':
    main()
