#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pattern")
    parser.add_argument("--file", default="exports/bundle_GAME.BIN.jsonl")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    bundle = root / args.file
    if not bundle.exists():
        raise SystemExit(f"bundle not found: {bundle}")

    patt = args.pattern.lower()
    with bundle.open("r", encoding="utf-8") as fh:
        for line in fh:
            if patt in line.lower():
                print(line.strip())


if __name__ == "__main__":
    main()
