#!/usr/bin/env python3
"""
generate_ghidra_comments.py

Aggregate annotations and generate a simple CSV (binary,ea,comment) to import
into Ghidra as plate/end-of-line comments via a small helper script.

Sources:
 - decomp_integrator_orientation.md (inline tags)
 - q12_overlay_report.md (prefix evidence counts)

Output: exports/ghidra_comments.csv
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"
DECOMP = EXPORTS / "decomp_integrator_orientation.md"
OVERLAY = EXPORTS / "q12_overlay_report.md"
OUT_CSV = EXPORTS / "ghidra_comments.csv"

FUNC_LINE_RE = re.compile(r"^##\s+(FUN_[0-9a-fA-F]{6,8})\s*\(([^)]*)\)\s*@\s*0x([0-9a-fA-F]+)")
TAG_RE = re.compile(r"//\s+(.*)$")


def parse_decomp(path: Path):
    comments = []
    cur = None
    if not path.exists():
        return comments
    for line in path.read_text(encoding='utf-8').splitlines():
        m = FUNC_LINE_RE.match(line)
        if m:
            name, bin_name, ea_hex = m.groups()
            cur = (bin_name.strip(), int(ea_hex, 16), name)
            continue
        if cur is None:
            continue
        t = TAG_RE.search(line)
        if t:
            comments.append((cur[0], cur[1], f"{cur[2]}: {t.group(1)}"))
    return comments


def parse_overlay(path: Path):
    comments = []
    if not path.exists():
        return comments
    for line in path.read_text(encoding='utf-8').splitlines():
        # crude parse of table rows containing function name and counts
        if line.startswith('|') and 'FUN_' in line:
            cols = [c.strip() for c in line.strip('|').split('|')]
            try:
                name = cols[1]
                ea = int(cols[2], 16)
                bin_name = cols[4]
                pxyz = cols[9]
                ang = cols[10]
                bd = cols[11]
                bs = cols[12]
                spd = cols[13]
            except Exception:
                continue
            cmt = f"Q12 evidence: Pxyz={pxyz}, Ang={ang}, BD={bd}, BS={bs}, Spd={spd}"
            comments.append((bin_name, ea, f"{name}: {cmt}"))
    return comments


def main() -> None:
    rows = []
    rows.extend(parse_decomp(DECOMP))
    rows.extend(parse_overlay(OVERLAY))
    # de-dup by (bin,ea,comment)
    seen = set()
    uniq = []
    for r in rows:
        if r in seen:
            continue
        seen.add(r)
        uniq.append(r)
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open('w', encoding='utf-8', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['binary','ea','comment'])
        for bin_name, ea, cmt in uniq:
            w.writerow([bin_name, f"0x{ea:06x}", cmt])
    print(f"Wrote {OUT_CSV} ({len(uniq)} comments)")


if __name__ == '__main__':
    main()
