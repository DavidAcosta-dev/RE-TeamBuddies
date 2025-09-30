#!/usr/bin/env python3
"""Produce overall cross-reference statistics and top offenders per table."""
from __future__ import annotations

import argparse
import csv
import pathlib
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

CRATE_SUMMARY_CSV = pathlib.Path("exports/crate_contents_summary.csv")
CROSSREF_CSV = pathlib.Path("exports/crate_value_crossrefs.csv")
OUTPUT_TOTALS = pathlib.Path("exports/crossref_table_totals.csv")
OUTPUT_TOP = pathlib.Path("exports/crossref_table_top_crates.csv")


def load_crate_summary(path: pathlib.Path) -> Dict[int, Dict[str, List[Tuple[int, int]]]]:
    crates: Dict[int, Dict[str, List[Tuple[int, int]]]] = defaultdict(lambda: {"value_a": [], "value_b": []})
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                crate_index = int(row["index"])
                value_a = int(row["value_a"])
                value_b = int(row["value_b"])
            except (KeyError, TypeError, ValueError):
                continue
            slot = int(row.get("slot", "0") or 0)
            crates[crate_index]["value_a"].append((slot, value_a))
            crates[crate_index]["value_b"].append((slot, value_b))
    return crates


def load_crossrefs(path: pathlib.Path) -> Dict[int, List[Tuple[str, int]]]:
    hits: Dict[int, List[Tuple[str, int]]] = defaultdict(list)
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                value = int(row["value"])
                table = row["table"]
                record_idx = int(row.get("record_idx", "0") or 0)
            except (KeyError, TypeError, ValueError):
                continue
            hits[value].append((table, record_idx))
    return hits


def build_totals(crates: Dict[int, Dict[str, List[Tuple[int, int]]]], hits: Dict[int, List[Tuple[str, int]]]):
    table_totals: Counter[str] = Counter()
    table_counts_by_crate: Dict[str, Counter[int]] = defaultdict(Counter)

    for crate_index, bucket in crates.items():
        involved_tables = set()
        for value_type in ("value_a", "value_b"):
            for _, value in bucket[value_type]:
                for table, _ in hits.get(value, []):
                    table_totals[table] += 1
                    table_counts_by_crate[table][crate_index] += 1
                    involved_tables.add(table)
        # we may want to note crates with no crossrefs, but crossref scan already covers all values

    return table_totals, table_counts_by_crate


def write_totals(table_totals: Counter[str], out_path: pathlib.Path) -> None:
    rows = sorted(table_totals.items(), key=lambda kv: (-kv[1], kv[0]))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["table", "total_hits"])
        writer.writerows(rows)
    print(f"Wrote totals for {len(rows)} tables -> {out_path}")


def write_top_crates(table_counts_by_crate: Dict[str, Counter[int]], out_path: pathlib.Path, top_n: int = 5) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["table", "crate_index", "crate_hit_count"])
        for table in sorted(table_counts_by_crate):
            for crate_index, count in table_counts_by_crate[table].most_common(top_n):
                writer.writerow([table, crate_index, count])
    print(f"Wrote top crate involvement per table -> {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize overall crossref coverage")
    parser.add_argument("--crate-summary", default=str(CRATE_SUMMARY_CSV))
    parser.add_argument("--crossref", default=str(CROSSREF_CSV))
    parser.add_argument("--totals-output", default=str(OUTPUT_TOTALS))
    parser.add_argument("--top-output", default=str(OUTPUT_TOP))
    parser.add_argument("--top-n", type=int, default=5)
    args = parser.parse_args()

    crate_summary_path = pathlib.Path(args.crate_summary)
    crossref_path = pathlib.Path(args.crossref)

    crates = load_crate_summary(crate_summary_path)
    hits = load_crossrefs(crossref_path)
    table_totals, table_counts_by_crate = build_totals(crates, hits)
    write_totals(table_totals, pathlib.Path(args.totals_output))
    write_top_crates(table_counts_by_crate, pathlib.Path(args.top_output), top_n=args.top_n)


if __name__ == "__main__":
    main()
