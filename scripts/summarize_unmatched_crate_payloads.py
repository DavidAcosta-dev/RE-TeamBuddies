#!/usr/bin/env python3
"""Summarize crate slots whose value_b lacks a weapon match.

Inputs:
    - exports/crate_weapon_projectile_matrix.csv (produced by join_crate_weapon_projectile.py)
    - exports/crate_value_crossrefs.csv (produced by crossref_crate_values.py)

Output:
    - exports/crate_unmatched_payloads.csv
"""
from __future__ import annotations

import argparse
import csv
import pathlib
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Set

MATRIX_CSV = pathlib.Path("exports/crate_weapon_projectile_matrix.csv")
CROSSREF_CSV = pathlib.Path("exports/crate_value_crossrefs.csv")
OUTPUT_CSV = pathlib.Path("exports/crate_unmatched_payloads.csv")


def load_unmatched_values(matrix_path: pathlib.Path) -> Dict[int, Set[str]]:
    contexts: Dict[int, Set[str]] = defaultdict(set)
    with matrix_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            weapon_index = row.get("weapon_index", "").strip()
            if weapon_index:
                continue
            try:
                value_b = int(row["value_b"])
            except (KeyError, TypeError, ValueError):
                continue
            label = row.get("crate_label", "?")
            slot = row.get("slot", "?")
            contexts[value_b].add(f"{label}:{slot}")
    return contexts


def load_crossrefs(crossref_path: pathlib.Path, target_values: Iterable[int]) -> Dict[int, Counter]:
    target_set = set(target_values)
    hits: Dict[int, Counter] = {value: Counter() for value in target_set}
    with crossref_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                value = int(row["value"])
            except (KeyError, TypeError, ValueError):
                continue
            if value not in target_set:
                continue
            table = row.get("table", "unknown")
            hits[value][table] += 1
    return hits


def write_summary(out_path: pathlib.Path, contexts: Dict[int, Set[str]], crossrefs: Dict[int, Counter]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "value_b",
            "crate_slot_count",
            "crate_slots",
            "table_hits",
        ])
        for value in sorted(contexts):
            slots = sorted(contexts[value])
            table_counter = crossrefs.get(value, Counter())
            table_summary = "; ".join(f"{table}:{count}" for table, count in table_counter.most_common())
            writer.writerow([
                value,
                len(slots),
                " | ".join(slots),
                table_summary,
            ])


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize unmatched crate payloads")
    parser.add_argument("--matrix", default=str(MATRIX_CSV), help="Joined crate/weapon matrix CSV")
    parser.add_argument("--crossref", default=str(CROSSREF_CSV), help="Cross-reference CSV")
    parser.add_argument("--output", default=str(OUTPUT_CSV), help="Summary CSV output path")
    args = parser.parse_args()

    matrix_path = pathlib.Path(args.matrix)
    crossref_path = pathlib.Path(args.crossref)
    output_path = pathlib.Path(args.output)

    contexts = load_unmatched_values(matrix_path)
    crossrefs = load_crossrefs(crossref_path, contexts.keys())
    write_summary(output_path, contexts, crossrefs)

    print(f"Wrote {output_path} for {len(contexts)} unmatched value_b codes")


if __name__ == "__main__":
    main()
