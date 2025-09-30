#!/usr/bin/env python3
"""Cross-reference crate value IDs against core gameplay tables."""
import csv
import struct
import argparse
import pathlib
from collections import defaultdict

CONTAINER_DIR = pathlib.Path("assets/extracted/BUDDIES.DAT/container_0288")
CRATE_SUMMARY = pathlib.Path("exports/crate_contents_summary.csv")

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


def read_crate_values(path: pathlib.Path):
    ids_a = set()
    ids_b = set()
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ids_a.add(int(row["value_a"]))
            ids_b.add(int(row["value_b"]))
    return ids_a, ids_b


def scan_file(root: pathlib.Path, filename: str):
    data = (root / filename).read_bytes()
    count = struct.unpack_from("<I", data, 0)[0]
    body = data[4:]
    if count == 0:
        return []
    rec_size = len(body) // count
    records = []
    for i in range(count):
        start = i * rec_size
        records.append(body[start:start + rec_size])
    return records


def main():
    ap = argparse.ArgumentParser(description="Cross-reference crate value IDs")
    ap.add_argument("--root", default=str(CONTAINER_DIR))
    ap.add_argument("--crate-summary", default=str(CRATE_SUMMARY))
    ap.add_argument("--output", default="exports/crate_value_crossrefs.csv")
    args = ap.parse_args()

    ids_a, ids_b = read_crate_values(pathlib.Path(args.crate_summary))
    root = pathlib.Path(args.root)

    refs = defaultdict(list)

    visited = set()
    for filename in TABLES:
        if filename in visited:
            continue
        visited.add(filename)
        records = scan_file(root, filename)
        for idx, blob in enumerate(records):
            for offset in range(0, len(blob) - 1, 2):
                value = struct.unpack_from('<H', blob, offset)[0]
                if value in ids_a or value in ids_b:
                    refs[value].append((filename, idx, offset))

    out_path = pathlib.Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["value", "table", "record_idx", "field_pos"])
        for value in sorted(refs):
            for table_name, record_idx, field_pos in refs[value]:
                writer.writerow([value, table_name, record_idx, field_pos])
    print(f"Wrote {sum(len(v) for v in refs.values())} references for {len(refs)} values -> {out_path}")

if __name__ == "__main__":
    main()
