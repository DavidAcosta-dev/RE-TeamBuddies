#!/usr/bin/env python3
"""Parse *_CRATECONTENTS.BIN payloads from container_0288 and dump a friendly CSV."""
import csv
import struct
import argparse
import pathlib
from collections import Counter

CONTAINER_DIR = pathlib.Path("assets/extracted/BUDDIES.DAT/container_0288")


def find_label(root: pathlib.Path, prefix: str) -> str:
    for candidate in root.glob(f"{prefix}_BT*.BIN"):
        stem = candidate.stem
        parts = stem.split("_", 1)
        if len(parts) == 2:
            # remove BT_ prefix for readability
            label = parts[1]
            if label.upper().startswith("BT_"):
                label = label[3:]
            return label
    return ""


def parse_file(path: pathlib.Path):
    data = path.read_bytes()
    if len(data) < 4:
        raise ValueError(f"Unexpected short file: {path} ({len(data)} bytes)")
    count, reserved = struct.unpack_from("<HH", data, 0)
    values_expected = count * 2
    values = struct.unpack_from(f"<{values_expected}H", data, 4)
    pairs = list(zip(values[0::2], values[1::2]))
    return count, reserved, pairs


def main():
    ap = argparse.ArgumentParser(description="Analyse container_0288 crate content tables")
    ap.add_argument("--root", default=str(CONTAINER_DIR), help="Path to container_0288 (default assets/extracted/BUDDIES.DAT/container_0288)")
    ap.add_argument("--output", default="exports/crate_contents_summary.csv", help="CSV file for per-slot breakdown")
    ap.add_argument("--dict-output", default="exports/crate_value_dictionary.csv", help="CSV for unique value mapping")
    args = ap.parse_args()

    root = pathlib.Path(args.root)
    if not root.exists():
        ap.error(f"Container directory not found: {root}")

    rows = []
    value_counts_a = Counter()
    value_counts_b = Counter()

    for file_path in sorted(root.glob('*_CRATECONTENTS.BIN'), key=lambda p: int(p.stem.split('_')[0])):
        prefix = file_path.stem.split('_')[0]
        label = find_label(root, prefix)
        count, reserved, pairs = parse_file(file_path)
        if reserved != 0:
            print(f"Warning: {file_path.name} reserved!=0 -> {reserved}")
        for idx, (val_a, val_b) in enumerate(pairs):
            rows.append({
                "index": int(prefix),
                "label": label,
                "slot": idx,
                "value_a": val_a,
                "value_b": val_b,
                "count": count
            })
            value_counts_a[val_a] += 1
            value_counts_b[val_b] += 1

    out_path = pathlib.Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["index", "label", "count", "slot", "value_a", "value_b"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"Wrote {len(rows)} rows to {out_path}")

    dict_path = pathlib.Path(args.dict_output)
    dict_path.parent.mkdir(parents=True, exist_ok=True)
    with dict_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["value", "type", "occurrences"])
        for value, occ in sorted(value_counts_a.items()):
            writer.writerow([value, "value_a", occ])
        for value, occ in sorted(value_counts_b.items()):
            writer.writerow([value, "value_b", occ])
    print(f"Wrote dictionary counts to {dict_path}")

if __name__ == "__main__":
    main()
