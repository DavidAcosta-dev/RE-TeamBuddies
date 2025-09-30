#!/usr/bin/env python3
"""Aggregate crate rows that resolve to TOYS.BIN payloads."""
from __future__ import annotations

import argparse
import csv
import pathlib
from collections import defaultdict
from typing import Dict, Iterable, List, Sequence

MATRIX_CSV = pathlib.Path("exports/crate_weapon_projectile_matrix.csv")
OUTPUT_CSV = pathlib.Path("exports/crate_toy_payloads.csv")


def load_matrix(path: pathlib.Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(
            f"Crate/weapon matrix not found: {path}. Run join_crate_weapon_projectile.py first."
        )
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def collect_toy_rows(rows: Iterable[Dict[str, str]], word_count: int = 6) -> Sequence[Dict[str, object]]:
    buckets: Dict[int, Dict[str, object]] = {}
    contexts: Dict[int, set[str]] = defaultdict(set)
    for row in rows:
        try:
            value_a = int(row.get("value_a", "0"))
        except (TypeError, ValueError):
            continue

        toy_present = int(row.get("toy_present", "0") or 0)
        if not toy_present:
            continue

        label = row.get("crate_label", "")
        slot = row.get("slot", "?")
        contexts[value_a].add(f"{label}:{slot}")

        toy_words: List[int | str] = []
        for idx in range(word_count):
            key = f"toy_w{idx:02d}"
            value = row.get(key, "")
            if value == "":
                toy_words.append("")
            else:
                try:
                    toy_words.append(int(value))
                except ValueError:
                    toy_words.append(value)

        buckets.setdefault(
            value_a,
            {
                "toy_index": value_a,
                "toy_words": toy_words,
                "weapon_match_count": 0,
            },
        )

        try:
            weapon_matches = int(row.get("weapon_matches", "0") or 0)
        except ValueError:
            weapon_matches = 0

        buckets[value_a]["weapon_match_count"] = max(
            weapon_matches, buckets[value_a]["weapon_match_count"]
        )

    summary_rows: List[Dict[str, object]] = []
    for toy_index in sorted(buckets):
        bucket = buckets[toy_index]
        toy_words = bucket["toy_words"]
        summary: Dict[str, object] = {
            "toy_index": toy_index,
            "crate_slot_count": len(contexts[toy_index]),
            "crate_slots": " | ".join(sorted(contexts[toy_index])),
            "weapon_match_count": bucket["weapon_match_count"],
        }
        for idx, value in enumerate(toy_words):
            summary[f"toy_w{idx:02d}"] = value
        summary_rows.append(summary)
    return summary_rows


def write_summary(rows: Sequence[Dict[str, object]], out_path: pathlib.Path) -> None:
    if not rows:
        print("No toy-backed crate rows detected; skipping write.")
        return

    headers = list(rows[0].keys())
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"Wrote {len(rows)} toy payload rows -> {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize crate payloads that map to toy slots")
    parser.add_argument("--matrix", default=str(MATRIX_CSV), help="Crate/weapon matrix CSV path")
    parser.add_argument("--output", default=str(OUTPUT_CSV), help="Toy payload summary CSV path")
    parser.add_argument("--word-count", type=int, default=6, help="Number of toy halfwords to emit per row")
    args = parser.parse_args()

    matrix_path = pathlib.Path(args.matrix)
    output_path = pathlib.Path(args.output)

    rows = load_matrix(matrix_path)
    summary = collect_toy_rows(rows, word_count=args.word_count)
    write_summary(summary, output_path)


if __name__ == "__main__":
    main()
