#!/usr/bin/env python3
"""Dump TOYS.BIN records as 16-bit fields."""
from __future__ import annotations

import csv
import pathlib
import struct

TOYS_BIN = pathlib.Path("assets/extracted/BUDDIES.DAT/container_0288/TOYS.BIN")
OUTPUT = pathlib.Path("exports/toys_table.csv")


def main() -> None:
    data = TOYS_BIN.read_bytes()
    count = struct.unpack_from("<I", data, 0)[0]
    body = data[4:]
    record_size = len(body) // count if count else 0
    if record_size != 12:
        print(f"Warning: expected 12-byte toy records, got {record_size}")
    records = []
    for idx in range(count):
        start = idx * record_size
        blob = body[start : start + record_size]
        words = struct.unpack_from("<" + "H" * (record_size // 2), blob)
        records.append((idx, words))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    headers = ["index"] + [f"w{i:02d}" for i in range(len(records[0][1]))]
    with OUTPUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for idx, words in records:
            writer.writerow([idx, *words])
    print(f"Wrote {len(records)} toy records to {OUTPUT}")


if __name__ == "__main__":
    main()
