#!/usr/bin/env python3
"""Export enriched label data as simple address/name maps."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    repo_root = _default_repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--labels",
        type=Path,
        default=repo_root / "exports" / "symbols" / "sdk_symbol_labels.json",
        help="Path to label JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "exports" / "symbols" / "sdk_symbol_labels.map",
        help="Output text map (address symbol [categories])",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if not args.labels.exists():
        raise SystemExit(f"Label JSON not found: {args.labels}")

    records = json.loads(args.labels.read_text(encoding="utf-8"))
    with args.output.open("w", encoding="utf-8") as handle:
        for record in records:
            address = record["address_hex"].lower()
            name = record["symbol"]
            categories = ",".join(record.get("categories", []))
            handle.write(f"{address} {name} {categories}\n")

    print(f"Wrote label map -> {args.output}")


if __name__ == "__main__":
    main()
