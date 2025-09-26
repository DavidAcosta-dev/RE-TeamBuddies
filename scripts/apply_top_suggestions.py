#!/usr/bin/env python3
"""
apply_top_suggestions.py

Apply top-N suggestions from exports/rename_checklist.csv into
exports/suspects_bookmarks.json by copying `suggested_name` → `new_name` for
matching function names. Safe: skips entries that already have a `new_name`.

Usage: python scripts/apply_top_suggestions.py [N]
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOK = ROOT / "exports" / "suspects_bookmarks.json"
CHECK = ROOT / "exports" / "rename_checklist.csv"


def load_checklist(path: Path, limit: int) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append(row)
    return rows[:limit]


def main(argv: list[str]) -> None:
    limit = int(argv[1]) if len(argv) > 1 else 25
    if not BOOK.exists() or not CHECK.exists():
        raise SystemExit("Missing exports files; run generators first.")
    todo = load_checklist(CHECK, limit)
    data = json.loads(BOOK.read_text(encoding="utf-8"))
    # index by (binary, function)
    index = {(row.get("binary"), row.get("function")): row for row in todo}

    changed = 0
    for bin_name, items in list(data.items()):
        if not isinstance(items, list):
            continue
        for it in items:
            nm = it.get('name')
            if not nm:
                continue
            if it.get('new_name'):
                continue
            row = index.get((bin_name, nm))
            if not row:
                continue
            sugg = row.get('suggested_name') or row.get('suggested') or 'q12_candidate'
            it['new_name'] = sugg
            if not it.get('category'):
                it['category'] = 'naming'
            changed += 1

    if changed:
        BOOK.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"Applied {changed} top suggestions to new_name (limit={limit}).")
    else:
        print("No changes (entries already named or no matches in top-N).")


if __name__ == "__main__":
    main(sys.argv)
