#!/usr/bin/env python3
"""Dump VEHICLES.BIN records as 16-bit fields for inspection."""
from __future__ import annotations

import csv
import pathlib
import struct

VEHICLES_BIN = pathlib.Path("assets/extracted/BUDDIES.DAT/container_0288/VEHICLES.BIN")
OUTPUT = pathlib.Path("exports/vehicles_table.csv")


def main() -> None:
    data = VEHICLES_BIN.read_bytes()
    count = struct.unpack_from("<I", data, 0)[0]
    body = data[4:]
    record_size = len(body) // count if count else 0
    if record_size == 0:
        raise RuntimeError("VEHICLES.BIN appears to have zero records")
    records = []
    for idx in range(count):
        start = idx * record_size
        blob = body[start : start + record_size]
        words = struct.unpack_from("<" + "H" * (record_size // 2), blob)
        records.append((idx, words))

    headers = ["index"] + [f"w{i:02d}" for i in range(record_size // 2)]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for idx, words in records:
            writer.writerow([idx, *words])
    print(f"Wrote {len(records)} vehicle records to {OUTPUT}")


if __name__ == "__main__":
    main()
