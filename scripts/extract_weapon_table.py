#!/usr/bin/env python3
"""Dump WEAPONS.BIN records as 16-bit fields for inspection."""
import csv
import pathlib
import struct

WEAPONS_BIN = pathlib.Path("assets/extracted/BUDDIES.DAT/container_0288/WEAPONS.BIN")
OUTPUT = pathlib.Path("exports/weapons_table.csv")


def main():
    data = WEAPONS_BIN.read_bytes()
    count = struct.unpack_from("<I", data, 0)[0]
    body = data[4:]
    record_size = len(body) // count
    if record_size != 100:
        print(f"Warning: expected 100-byte weapons records, got {record_size}")
    records = []
    for idx in range(count):
        start = idx * record_size
        blob = body[start : start + record_size]
        fields = struct.unpack_from("<" + "H" * (record_size // 2), blob)
        records.append((idx, fields))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    headers = ["index"] + [f"f{i:02d}" for i in range(len(records[0][1]))]
    with OUTPUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for idx, fields in records:
            writer.writerow([idx, *fields])
    print(f"Wrote {len(records)} weapon records to {OUTPUT}")


if __name__ == "__main__":
    main()
