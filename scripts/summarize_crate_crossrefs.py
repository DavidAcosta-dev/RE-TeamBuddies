#!/usr/bin/env python3
"""Summarize crate cross-reference coverage by gameplay table and PSYQ domain."""
from __future__ import annotations

import argparse
import csv
import pathlib
from collections import Counter, defaultdict
from typing import Dict, Iterable, List

CRATE_SUMMARY_CSV = pathlib.Path("exports/crate_contents_summary.csv")
CROSSREF_CSV = pathlib.Path("exports/crate_value_crossrefs.csv")
OUTPUT_CSV = pathlib.Path("exports/crate_crossref_summary.csv")

TABLES = [
    "ACTION.BIN",
    "ATTITUDE.BIN",
    "BUDDIES.BIN",
    "PERCEPT.BIN",
    "POWERUP.BIN",
    "PROJECTILES.BIN",
    "STATICS.BIN",
    "TOYS.BIN",
    "VEHICLES.BIN",
    "WEAPONS.BIN",
]

TABLE_TO_DOMAIN = {
    "ACTION.BIN": "engine",
    "ATTITUDE.BIN": "ai",
    "BUDDIES.BIN": "ai",
    "PERCEPT.BIN": "ai",
    "POWERUP.BIN": "support",
    "PROJECTILES.BIN": "render",
    "STATICS.BIN": "render",
    "TOYS.BIN": "support",
    "VEHICLES.BIN": "render",
    "WEAPONS.BIN": "combat",
}

DOMAIN_HINT = {
    "ai": "AI behaviour (libgte-assisted decision data)",
    "combat": "Combat runtime (libgte/libgpu coupling)",
    "engine": "Core scheduler/state machines",
    "render": "Rendering & geometry (libgpu/libgte)",
    "support": "Support systems (libspu/libpad)",
    "other": "Unmapped",
}


def load_crossrefs(path: pathlib.Path) -> Dict[int, Counter[str]]:
    if not path.exists():
        raise FileNotFoundError(
            f"Cross-reference CSV not found: {path}. Run crossref_crate_values.py first."
        )
    hits: Dict[int, Counter[str]] = defaultdict(Counter)
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                value = int(row["value"])
            except (KeyError, TypeError, ValueError):
                continue
            table = row.get("table", "unknown")
            hits[value][table] += 1
    return hits


def load_crate_summary(path: pathlib.Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(
            f"Crate summary CSV not found: {path}. Run analyse_crate_contents.py first."
        )
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def aggregate(rows: Iterable[Dict[str, str]], crossrefs: Dict[int, Counter[str]]):
    crates: Dict[int, Dict[str, object]] = {}
    for row in rows:
        try:
            crate_index = int(row["index"])
            value_a = int(row["value_a"])
            value_b = int(row["value_b"])
        except (KeyError, TypeError, ValueError):
            continue
        label = row.get("label", "")

        crate = crates.setdefault(
            crate_index,
            {
                "label": label,
                "slot_count": 0,
                "value_a_counter": Counter(),
                "value_b_counter": Counter(),
            },
        )
        crate["slot_count"] += 1

        crate["value_a_counter"].update(crossrefs.get(value_a, Counter()))
        crate["value_b_counter"].update(crossrefs.get(value_b, Counter()))

    return crates


def build_output_rows(crates: Dict[int, Dict[str, object]]):
    domain_keys = sorted(DOMAIN_HINT)
    rows: List[Dict[str, object]] = []
    for crate_index in sorted(crates):
        crate = crates[crate_index]
        value_a_counter: Counter[str] = crate["value_a_counter"]
        value_b_counter: Counter[str] = crate["value_b_counter"]
        combined = value_a_counter + value_b_counter

        total_a = sum(value_a_counter.values())
        total_b = sum(value_b_counter.values())
        total = sum(combined.values())

        domain_counter: Counter[str] = Counter()
        for table, count in combined.items():
            domain = TABLE_TO_DOMAIN.get(table, "other")
            domain_counter[domain] += count

        dominant_domain = ""
        domain_hint = ""
        if domain_counter:
            dominant_domain, _ = domain_counter.most_common(1)[0]
            domain_hint = DOMAIN_HINT.get(dominant_domain, "")

        row: Dict[str, object] = {
            "crate_index": crate_index,
            "crate_label": crate["label"],
            "slot_count": crate["slot_count"],
            "value_a_total": total_a,
            "value_b_total": total_b,
            "combined_total": total,
            "dominant_domain": dominant_domain,
            "dominant_domain_hint": domain_hint,
        }

        for table in TABLES:
            row[f"table_{table}"] = combined.get(table, 0)

        for domain in domain_keys:
            row[f"domain_{domain}"] = domain_counter.get(domain, 0)

        rows.append(row)

    return rows


def write_rows(rows: List[Dict[str, object]], out_path: pathlib.Path) -> None:
    if not rows:
        print("No crate data to summarize; skipping write.")
        return
    headers = list(rows[0].keys())
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"Wrote {len(rows)} crate crossref summaries -> {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize crate cross-reference coverage")
    parser.add_argument("--crate-summary", default=str(CRATE_SUMMARY_CSV), help="Crate summary CSV path")
    parser.add_argument("--crossref", default=str(CROSSREF_CSV), help="Cross-reference CSV path")
    parser.add_argument("--output", default=str(OUTPUT_CSV), help="Output CSV path")
    args = parser.parse_args()

    crate_rows = load_crate_summary(pathlib.Path(args.crate_summary))
    crossrefs = load_crossrefs(pathlib.Path(args.crossref))
    crates = aggregate(crate_rows, crossrefs)
    rows = build_output_rows(crates)
    write_rows(rows, pathlib.Path(args.output))


if __name__ == "__main__":
    main()
