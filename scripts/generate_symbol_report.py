#!/usr/bin/env python3
"""Produce a Markdown snapshot of PSYQ symbol reconnaissance findings."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence


@dataclass
class CategoryStat:
    name: str
    count: int
    percentage: float


@dataclass
class SymbolEntry:
    symbol: str
    address: str
    observations: int
    distinct_addresses: int
    map_count: int
    example_map: str


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    repo_root = _default_repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--group-counts",
        type=Path,
        default=repo_root / "exports" / "symbols" / "sdk_symbol_group_counts.csv",
    )
    parser.add_argument(
        "--symbol-groups",
        type=Path,
        default=repo_root / "exports" / "symbols" / "sdk_symbol_groups.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "notes" / "symbol_recon_report.md",
    )
    parser.add_argument(
        "--top-per-category",
        type=int,
        default=10,
        help="Number of exemplar symbols to list for each category",
    )
    parser.add_argument(
        "--min-address",
        type=lambda value: int(value, 0),
        default=0x80010000,
        help="Ignore symbols below this canonical address (default: 0x80010000)",
    )
    parser.add_argument(
        "--max-address",
        type=lambda value: int(value, 0),
        default=0x8FFFFFFF,
        help="Ignore symbols above this canonical address (default: 0x8FFFFFFF)",
    )
    parser.add_argument(
        "--skip-prefix",
        action="append",
        default=["__", "_text", "_rdata"],
        help="Exclude symbols whose names start with any of these prefixes",
    )
    return parser.parse_args()


def _load_category_counts(path: Path) -> List[CategoryStat]:
    stats: List[CategoryStat] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            stats.append(
                CategoryStat(
                    name=row["category"],
                    count=int(row["symbol_count"]),
                    percentage=float(row["percentage"]),
                )
            )
    return stats


def _load_symbol_groups(
    path: Path,
    *,
    min_address: int,
    max_address: int,
    skip_prefixes: Sequence[str],
) -> Dict[str, List[SymbolEntry]]:
    categories: Dict[str, List[SymbolEntry]] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            cats = [c.strip() for c in row["category_list"].split(";") if c.strip()]
            entry = SymbolEntry(
                symbol=row["symbol"],
                address=row["canonical_address_hex"],
                observations=int(row["observations"]),
                distinct_addresses=int(row["distinct_addresses"]),
                map_count=int(row["map_file_count"]),
                example_map=row["example_map_file"],
            )
            addr_int = int(entry.address, 16)
            if addr_int < min_address or addr_int > max_address:
                continue
            if any(entry.symbol.startswith(prefix) for prefix in skip_prefixes):
                continue
            for cat in cats or ["unknown"]:
                categories.setdefault(cat, []).append(entry)
    for entries in categories.values():
        entries.sort(
            key=lambda e: (-(e.observations), -(e.map_count), e.symbol.lower())
        )
    return categories


def _write_report(
    output_path: Path,
    category_counts: Sequence[CategoryStat],
    category_entries: Dict[str, List[SymbolEntry]],
    top_n: int,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write("# PSYQ Symbol Recon Report\n\n")
        handle.write(
            "Automated snapshot derived from the PSYQ SDK MAP exports. Use it to prioritise\n"
            "interface work and bulk rename passes inside Ghidra.\n\n"
        )
        handle.write("## Category Overview\n\n")
        handle.write("| Category | Symbols | Share (%) |\n")
        handle.write("|---|---:|---:|\n")
        for stat in category_counts:
            handle.write(f"| {stat.name} | {stat.count} | {stat.percentage:.2f} |\n")
        handle.write("\n")

        handle.write("## Category Highlights\n\n")
        for stat in category_counts:
            entries = category_entries.get(stat.name, [])
            handle.write(f"### {stat.name.title()} ({stat.count} symbols, {stat.percentage:.2f}% share)\n\n")
            if not entries:
                handle.write("No exemplar symbols recorded yet.\n\n")
                continue
            subset = entries[:top_n]
            for entry in subset:
                handle.write(
                    f"- `{entry.symbol}` @ {entry.address} — obs={entry.observations}, distinct_addrs={entry.distinct_addresses}, "
                    f"maps={entry.map_count}; e.g. `{entry.example_map}`\n"
                )
            if len(entries) > top_n:
                handle.write(f"- … {len(entries) - top_n} more entries.\n")
            handle.write("\n")

        handle.write("## Suggested Next Steps\n\n")
        handle.write("- Feed category-specific labels into subsystem headers (graphics, audio, etc.).\n")
        handle.write("- Run `ghidra_scripts/ApplySdkSymbols.py` to splash the 864 canonical labels across the game binary.\n")
        handle.write(
            "- Start with the dominant categories when carving interface contracts (graphics + UI together represent ~40% of the dataset).\n"
        )


def main() -> None:
    args = _parse_args()
    category_counts = _load_category_counts(args.group_counts)
    category_entries = _load_symbol_groups(
        args.symbol_groups,
        min_address=args.min_address,
        max_address=args.max_address,
        skip_prefixes=args.skip_prefix,
    )
    _write_report(args.output, category_counts, category_entries, args.top_per_category)
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
