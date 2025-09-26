#!/usr/bin/env python3
"""Export PSYQ MAP symbol tables to CSV for downstream analysis.

This utility scans the PSYQ SDK tree (or a user-specified directory) for linker
``.MAP`` files, extracts address/name pairs, and consolidates them into a single
CSV that lives under ``exports/symbols``. The resulting dataset accelerates
cross-referencing between SDK samples and the Team Buddies binaries.
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Tuple

_ADDRESS_LINE = re.compile(r"^\s*([0-9A-Fa-f]{8})\s+([^\s]+)")


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    repo_root = _default_repo_root()
    default_sdk = repo_root / "assets" / "PSYQ_SDK"
    default_output = repo_root / "exports" / "symbols" / "sdk_map_symbols.csv"
    default_summary = repo_root / "exports" / "symbols" / "sdk_symbol_summary.csv"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sdk-root",
        type=Path,
        default=default_sdk,
        help="Directory to search for .MAP files (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=default_output,
        help="CSV destination path (default: %(default)s)",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=default_summary,
        help="Optional summary CSV (symbol -> canonical address) (default: %(default)s)",
    )
    parser.add_argument(
        "--relative-to",
        type=Path,
        default=repo_root,
        help="Base path used when writing the map_file column (default: repo root)",
    )
    parser.add_argument(
        "--glob",
        action="append",
        default=[],
        help="Optional additional glob(s) relative to --sdk-root to limit search scope.",
    )
    return parser.parse_args()


def _iter_map_files(sdk_root: Path, globs: Iterable[str]) -> Iterator[Path]:
    if globs:
        for pattern in globs:
            for path in sdk_root.glob(pattern):
                if path.is_file() and path.suffix.lower() == ".map":
                    yield path.resolve()
    else:
        for path in sdk_root.rglob("*"):
            if path.is_file() and path.suffix.lower() == ".map":
                yield path.resolve()


def _extract_symbols(map_path: Path) -> List[Tuple[str, int, str]]:
    symbols: List[Tuple[str, int, str]] = []
    with map_path.open("r", encoding="latin-1", errors="replace") as handle:
        for line in handle:
            match = _ADDRESS_LINE.match(line)
            if not match:
                continue
            addr_hex, name = match.groups()
            if re.fullmatch(r"[0-9A-Fa-f]{8}", name):
                # Skip section table rows where both columns are addresses.
                continue
            try:
                address = int(addr_hex, 16)
            except ValueError:
                continue
            remainder = line[match.end():].strip()
            symbols.append((name, address, remainder))
    return symbols


def _write_csv(
    output_path: Path,
    rows: Iterable[Tuple[str, str, int, str]],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["map_file", "symbol", "address_hex", "annotation"])
        for map_file, symbol, address, annotation in rows:
            writer.writerow([map_file, symbol, f"0x{address:08X}", annotation])


def main() -> None:
    args = _parse_args()
    sdk_root = args.sdk_root
    if not sdk_root.exists():
        raise SystemExit(f"SDK root not found: {sdk_root}")

    files = sorted(_iter_map_files(sdk_root, args.glob))
    if not files:
        raise SystemExit("No .MAP files discovered with supplied parameters.")

    repo_root = args.relative_to
    rows: List[Tuple[str, str, int, str]] = []
    for map_path in files:
        rel_path = map_path.relative_to(repo_root)
        rel_str = rel_path.as_posix()
        for symbol, address, annotation in _extract_symbols(map_path):
            rows.append((rel_str, symbol, address, annotation))

    _write_csv(args.output, rows)
    print(f"Exported {len(rows)} symbols from {len(files)} MAP files -> {args.output}")

    if args.summary_output:
        _write_summary(args.summary_output, rows)


def _write_summary(
    summary_path: Path, rows: Iterable[Tuple[str, str, int, str]]
) -> None:
    symbol_counts: Dict[str, Counter] = defaultdict(Counter)
    symbol_maps: Dict[str, set] = defaultdict(set)
    for map_file, symbol, address, _ in rows:
        symbol_counts[symbol][address] += 1
        symbol_maps[symbol].add(map_file)

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", encoding="utf-8", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            [
                "symbol",
                "canonical_address_hex",
                "observations",
                "distinct_addresses",
                "map_files",
                "address_histogram",
            ]
        )

        for symbol in sorted(symbol_counts.keys()):
            counter = symbol_counts[symbol]
            canonical_addr, canonical_count = max(
                counter.items(), key=lambda item: (item[1], -item[0])
            )
            histogram = ";".join(
                f"0x{addr:08X}({count})"
                for addr, count in sorted(
                    counter.items(), key=lambda item: (-item[1], item[0])
                )
            )
            writer.writerow(
                [
                    symbol,
                    f"0x{canonical_addr:08X}",
                    canonical_count,
                    len(counter),
                    len(symbol_maps[symbol]),
                    histogram,
                ]
            )

        print(
            f"Summary written to {summary_path} (symbols={len(symbol_counts)})"
        )


if __name__ == "__main__":
    main()
