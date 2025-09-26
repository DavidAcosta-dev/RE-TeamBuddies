#!/usr/bin/env python3
"""
extract_basis_caller_snippets.py

Extract small caller snippets for basis functions (normalize/recompute) to show
how callsites prepare/consume TbActorPrefix fields. Useful for confirming axes
and speed linkage.

Output: exports/basis_caller_snippets.md
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, List

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"
BUNDLE = EXPORTS / "bundle_ghidra.jsonl"
OUT_MD = EXPORTS / "basis_caller_snippets.md"

TARGETS = {"FUN_00044f80", "FUN_00044a14"}


def iter_jsonl(path: Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def main() -> None:
    if not BUNDLE.exists():
        raise SystemExit(f"Missing {BUNDLE}; export with scripts/export_bundles.ps1")
    lines: List[str] = []
    lines.append('# Basis Caller Snippets')
    lines.append('')
    for entry in iter_jsonl(BUNDLE):
        fn = entry.get('function') or {}
        name = fn.get('name')
        if not name or name in TARGETS:
            continue
        callees = set(entry.get('callees') or [])
        if not (callees & TARGETS):
            continue
        bin_name = entry.get('binary') or ''
        ea = fn.get('ea')
        lines.append(f"## {name} ({bin_name}) @ 0x{ea:06x}")
        lines.append('')
        decomp = entry.get('decompilation') or ''
        snippet = '\n'.join(decomp.splitlines()[:15])
        lines.append('```c')
        lines.append(snippet)
        lines.append('```')
        lines.append('')
    OUT_MD.write_text('\n'.join(lines), encoding='utf-8')
    print(f"Wrote {OUT_MD}")


if __name__ == '__main__':
    main()
