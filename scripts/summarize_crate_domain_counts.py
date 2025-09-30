#!/usr/bin/env python3
"""Aggregate crate domain counts from the joined matrix."""
from __future__ import annotations

import argparse
import csv
import pathlib
from collections import Counter, defaultdict
from typing import Dict, Iterable

MATRIX_CSV = pathlib.Path("exports/crate_weapon_projectile_matrix.csv")
OUTPUT_CSV = pathlib.Path("exports/crate_domain_pivot.csv")


def load_matrix(path: pathlib.Path) -> Iterable[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            yield row


def aggregate_domains(rows: Iterable[Dict[str, str]]):
    crates: Dict[int, Dict[str, Counter[str]]] = defaultdict(lambda: {"value_a": Counter(), "value_b": Counter(), "both": Counter()})
    labels: Dict[int, str] = {}

    for row in rows:
        try:
            crate_index = int(row.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        labels.setdefault(crate_index, row.get("crate_label", ""))

        a_domain = row.get("value_a_domain", "").strip()
        a_kind = row.get("value_a_kind", "").strip()
        b_domain = row.get("value_b_domain", "").strip()
        b_kind = row.get("value_b_kind", "").strip()

        if a_domain:
            crates[crate_index]["value_a"][a_domain] += 1
            crates[crate_index]["both"][a_domain] += 1
            if a_kind == "value_a+value_b":
                crates[crate_index]["value_b"][a_domain] += 0
        if b_domain:
            crates[crate_index]["value_b"][b_domain] += 1
            crates[crate_index]["both"][b_domain] += 1

    rows_out = []
    for crate_index in sorted(crates):
        label = labels.get(crate_index, "")
        counters = crates[crate_index]
        row = {
            "crate_index": crate_index,
            "crate_label": label,
        }
        for prefix, counter in counters.items():
            total = sum(counter.values())
            row[f"{prefix}_total"] = total
            for domain, count in counter.items():
                key = f"{prefix}_domain_{domain or 'unknown'}"
                row[key] = row.get(key, 0) + count
        rows_out.append(row)
    return rows_out


def write_rows(rows, out_path: pathlib.Path) -> None:
    if not rows:
        print("No domain data to write; skipping.")
        return
    headers = sorted({key for row in rows for key in row})
    headers.remove("crate_index")
    headers = ["crate_index"] + headers

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"Wrote {len(rows)} crate domain pivot rows -> {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize crate domain counts from the matrix")
    parser.add_argument("--matrix", default=str(MATRIX_CSV), help="Joined crate matrix CSV path")
    parser.add_argument("--output", default=str(OUTPUT_CSV), help="Output CSV path")
    args = parser.parse_args()

    matrix_path = pathlib.Path(args.matrix)
    output_path = pathlib.Path(args.output)

    rows = list(load_matrix(matrix_path))
    summary_rows = aggregate_domains(rows)
    write_rows(summary_rows, output_path)


if __name__ == "__main__":
    main()
