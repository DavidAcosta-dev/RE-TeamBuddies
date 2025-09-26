#!/usr/bin/env python3
"""Emit per-category symbol dossiers to guide subsystem RE work."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Iterable, List, Sequence


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    repo_root = _default_repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--labels",
        type=Path,
        default=repo_root / "exports" / "symbols" / "sdk_symbol_labels.json",
        help="Path to the enriched label JSON (with categories)",
    )
    parser.add_argument(
        "--category",
        action="append",
        required=True,
        help="Category name to emit (can be provided multiple times)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=repo_root / "notes" / "symbol_dossiers",
        help="Directory to place generated markdown reports",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=30,
        help="Number of top entries per category",
    )
    return parser.parse_args()


def _load_labels(path: Path) -> List[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _filter_by_category(records: Iterable[dict], category: str) -> List[dict]:
    cat_lc = category.lower()
    selected: List[dict] = []
    for record in records:
        cats = [c.lower() for c in record.get("categories", []) if c]
        if cat_lc in cats:
            selected.append(record)
    selected.sort(
        key=lambda r: (-int(r.get("observations", 0)), -len(r.get("map_files", [])), r.get("symbol", ""))
    )
    return selected


def _get_map_stats(records: Sequence[dict]) -> Counter:
    counter: Counter = Counter()
    for record in records:
        for map_path in record.get("map_files", []):
            counter[map_path] += 1
    return counter


def _write_markdown(category: str, records: Sequence[dict], limit: int, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    outfile = output_dir / f"{category.lower()}_dossier.md"
    top_records = records[:limit]
    map_stats = _get_map_stats(top_records)

    lower_category = category.lower()
    with outfile.open("w", encoding="utf-8") as handle:
        handle.write(f"# {category.title()} Symbol Dossier\n\n")
        handle.write(
            f"Auto-generated summary from `sdk_symbol_labels.json`. Focused on high-confidence symbols "
            f"within the \"{category}\" category to guide subsystem reverse engineering.\n\n"
        )
        handle.write("## Top Symbols\n\n")
        handle.write("| Symbol | Address | Observations | Distinct Addrs | Map Samples |\n")
        handle.write("|---|---|---:|---:|---|\n")
        for record in top_records:
            samples = "<br/>".join(record.get("map_files", [])[:3])
            handle.write(
                f"| `{record['symbol']}` | {record['address_hex']} | {record['observations']} | {record['distinct_addresses']} | {samples} |\n"
            )
        handle.write("\n")

        handle.write("## Frequent MAP Sources\n\n")
        handle.write("| MAP Path | Count |\n")
        handle.write("|---|---:|\n")
        for map_path, count in map_stats.most_common(20):
            handle.write(f"| `{map_path}` | {count} |\n")
        handle.write("\n")

        handle.write("## Next Steps\n\n")
        handle.write("- Cross-check these addresses against Team Buddies binaries to confirm function parity.\n")
        handle.write("- Capture calling conventions in shared headers (e.g., `include/graphics.h`).\n")
        handle.write(
            f"- Use `ApplySdkSymbols.py include_categories={lower_category}` during Ghidra sessions for targeted labelling.\n"
        )

    print(f"Wrote dossier for {category} -> {outfile}")


def main() -> None:
    args = _parse_args()
    records = _load_labels(args.labels)
    for category in args.category:
        filtered = _filter_by_category(records, category)
        if not filtered:
            print(f"Warning: no symbols found for category '{category}'.")
            continue
        _write_markdown(category, filtered, args.limit, args.output_dir)


if __name__ == "__main__":
    main()
