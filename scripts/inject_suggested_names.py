#!/usr/bin/env python3
"""
inject_suggested_names.py

Read exports/rename_checklist.csv and add a non-destructive `suggested_name`
field to exports/suspects_bookmarks.json entries for quick UI tagging. Does not
overwrite `new_name` if already present.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOK = ROOT / "exports" / "suspects_bookmarks.json"
CHECK = ROOT / "exports" / "rename_checklist.csv"


def load_checklist(path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            nm = row.get("function")
            if nm:
                out[nm] = row
    return out


def main() -> None:
    if not BOOK.exists():
        raise SystemExit(f"Not found: {BOOK}")
    if not CHECK.exists():
        raise SystemExit(f"Not found: {CHECK}")
    checklist = load_checklist(CHECK)
    data = json.loads(BOOK.read_text(encoding="utf-8"))

    changed = 0
    for bin_name, items in list(data.items()):
        if not isinstance(items, list):
            continue
        for it in items:
            nm = it.get('name')
            if not nm:
                continue
            rec = checklist.get(nm)
            if not rec:
                continue
            sugg = rec.get('suggested_name') or rec.get('suggested') or None
            if not sugg:
                sugg = rec.get('reason') and rec['reason'].split(';')[0].split(',')[0]
            if sugg and it.get('suggested_name') != sugg:
                it['suggested_name'] = sugg
                # do not overwrite an existing curated new_name
                changed += 1
    if changed:
        BOOK.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"Updated {changed} bookmark entries with suggested_name.")
    else:
        print("No changes (suggestions already present or no matching functions).")


if __name__ == "__main__":
    main()
