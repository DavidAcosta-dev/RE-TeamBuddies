#!/usr/bin/env python3
"""Utility helpers for slicing the BUDDIES.DAT index file.

Examples
--------
# Find crate related assets (case-insensitive substring match)
python scripts/filter_bind_index.py --pattern crate

# Use a regex to locate anything with XPLO_* in the filename and show 10 rows
python scripts/filter_bind_index.py --regex "XPLO_.*" --limit 10

# Summarise counts per container for files containing TIM
python scripts/filter_bind_index.py --pattern tim --summarise
"""
import argparse
import csv
import pathlib
import re
from collections import Counter, defaultdict

DEFAULT_INDEX = pathlib.Path("exports/bind_index_BUDDIES.DAT.csv")

def load_rows(path: pathlib.Path):
    with path.open(newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield row

def matches(row_name: str, sub: str = None, regex: re.Pattern = None, case_sensitive: bool = False) -> bool:
    if regex is not None:
        return bool(regex.search(row_name))
    if sub is None:
        return True
    if case_sensitive:
        return sub in row_name
    return sub.lower() in row_name.lower()

def main():
    ap = argparse.ArgumentParser(description="Filter entries in the BUDDIES.DAT index CSV")
    ap.add_argument("index", nargs="?", default=str(DEFAULT_INDEX), help="Path to the CSV index (default: exports/bind_index_BUDDIES.DAT.csv)")
    ap.add_argument("--pattern", help="Substring to search for (case-insensitive unless --case-sensitive)" )
    ap.add_argument("--regex", help="Regular expression to apply to filenames")
    ap.add_argument("--case-sensitive", action="store_true", help="Use case-sensitive matching for --pattern")
    ap.add_argument("--limit", type=int, default=50, help="Maximum number of rows to print (default 50; 0 = no cap)")
    ap.add_argument("--summarise", action="store_true", help="Summarise matches per container instead of printing rows")
    ap.add_argument("--output", help="Optional path to write the matched rows as CSV")
    args = ap.parse_args()

    index_path = pathlib.Path(args.index)
    if not index_path.exists():
        ap.error(f"Index file not found: {index_path}")

    regex = re.compile(args.regex, re.IGNORECASE) if args.regex else None

    selected = []
    per_container = Counter()
    size_by_container = defaultdict(int)

    for row in load_rows(index_path):
        name = row.get("name", "")
        if matches(name, args.pattern, regex, args.case_sensitive):
            selected.append(row)
            cidx = int(row.get("container_i", 0))
            per_container[cidx] += 1
            try:
                size_by_container[cidx] += int(row.get("size", 0))
            except ValueError:
                pass

    if args.output:
        out_path = pathlib.Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=selected[0].keys() if selected else ["container_i","name"])
            writer.writeheader()
            for row in selected:
                writer.writerow(row)
        print(f"Wrote {len(selected)} rows to {out_path}")

    if args.summarise:
        print(f"Matches: {len(selected)} rows")
        print("Top containers:")
        for container, count in per_container.most_common(20):
            total_bytes = size_by_container.get(container, 0)
            print(f"  container_{container:04d}: {count} files, {total_bytes} bytes")
    else:
        limit = args.limit if args.limit is not None else 0
        if limit == 0 or limit > len(selected):
            limit = len(selected)
        print(f"Matches: {len(selected)} rows (showing {limit})")
        for row in selected[:limit]:
            print(f"container_{int(row['container_i']):04d} | {row['name']} | size={row['size']} | rel_off={row['rel_off']}" )

if __name__ == "__main__":
    main()
