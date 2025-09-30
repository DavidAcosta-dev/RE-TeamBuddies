#!/usr/bin/env python3
"""Produce a joined view of crate slots, toy/vehicle payloads, weapon records, projectiles, and cross-table hits."""
from __future__ import annotations

import argparse
import csv
import pathlib
import struct
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

CONTAINER_ROOT = pathlib.Path("assets/extracted/BUDDIES.DAT/container_0288")
DEFAULT_CRATE_CSV = pathlib.Path("exports/crate_contents_summary.csv")
DEFAULT_CROSSREF_CSV = pathlib.Path("exports/crate_value_crossrefs.csv")
DEFAULT_VALUE_DOMAIN_CSV = pathlib.Path("exports/crate_value_domain_summary.csv")
OUTPUT_CSV = pathlib.Path("exports/crate_weapon_projectile_matrix.csv")


@dataclass
class WeaponRecord:
    index: int
    weapon_id: int
    upgrade_id: int
    projectile_index: int
    range_a: int
    range_b: int
    cooldown: int
    camera_kick: int
    resource0: int
    resource1: int
    resource2: int
    resource3: int
    resource4: int


@dataclass
class ProjectileRecord:
    index: int
    archetype_id: int
    damage: int
    burst_count: int
    collision_mask: int
    velocity_x: int
    velocity_y: int
    velocity_z: int
    fuse_frames: int
    spawn_interval: int
    resource_a: int
    resource_b: int
    resource_c: int


@dataclass
class ToyRecord:
    index: int
    words: Sequence[int]


@dataclass
class VehicleRecord:
    index: int
    words: Sequence[int]


def _read_file(path: pathlib.Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(f"Expected file not found: {path}")
    return path.read_bytes()


def _extract_records(data: bytes) -> Sequence[bytes]:
    count = struct.unpack_from("<I", data, 0)[0]
    body = data[4:]
    if count == 0:
        return []
    record_size = len(body) // count
    return [body[i * record_size : (i + 1) * record_size] for i in range(count)]


def _u16(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<H", blob, offset)[0]


def _s16(blob: bytes, offset: int) -> int:
    value = _u16(blob, offset)
    return value if value < 0x8000 else value - 0x10000


def _u32(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<I", blob, offset)[0]


def _record_word_count(records: Sequence[bytes]) -> int:
    return len(records[0]) // 2 if records else 0


def load_weapons(path: pathlib.Path) -> List[WeaponRecord]:
    raw = _read_file(path)
    records = _extract_records(raw)
    result: List[WeaponRecord] = []
    for idx, blob in enumerate(records):
        result.append(
            WeaponRecord(
                index=idx,
                weapon_id=_u32(blob, 0x30),
                upgrade_id=_u32(blob, 0x34),
                projectile_index=_u32(blob, 0x2C),
                range_a=_u16(blob, 0x4C),
                range_b=_u16(blob, 0x50),
                cooldown=_u16(blob, 0x5C),
                camera_kick=_u16(blob, 0x58),
                resource0=_u32(blob, 0x38),
                resource1=_u32(blob, 0x3C),
                resource2=_u32(blob, 0x40),
                resource3=_u32(blob, 0x44),
                resource4=_u32(blob, 0x48),
            )
        )
    return result


def load_toys(path: pathlib.Path) -> List[ToyRecord]:
    raw = _read_file(path)
    records = _extract_records(raw)
    word_count = _record_word_count(records)
    result: List[ToyRecord] = []
    for idx, blob in enumerate(records):
        words = struct.unpack_from("<" + "H" * word_count, blob)
        result.append(ToyRecord(index=idx, words=words))
    return result


def load_vehicles(path: pathlib.Path) -> List[VehicleRecord]:
    raw = _read_file(path)
    records = _extract_records(raw)
    word_count = _record_word_count(records)
    result: List[VehicleRecord] = []
    for idx, blob in enumerate(records):
        words = struct.unpack_from("<" + "H" * word_count, blob)
        result.append(VehicleRecord(index=idx, words=words))
    return result


def load_projectiles(path: pathlib.Path) -> List[ProjectileRecord]:
    raw = _read_file(path)
    records = _extract_records(raw)
    result: List[ProjectileRecord] = []
    for idx, blob in enumerate(records):
        result.append(
            ProjectileRecord(
                index=idx,
                archetype_id=_u16(blob, 0x00),
                damage=_u16(blob, 0x1C),
                burst_count=_u16(blob, 0x18),
                collision_mask=_u16(blob, 0x20),
                velocity_x=_s16(blob, 0x4C),
                velocity_y=_s16(blob, 0x50),
                velocity_z=_s16(blob, 0x54),
                fuse_frames=_u16(blob, 0x58),
                spawn_interval=_u16(blob, 0x5C),
                resource_a=_u16(blob, 0x64),
                resource_b=_u16(blob, 0x68),
                resource_c=_u16(blob, 0x6C),
            )
        )
    return result


def read_crate_summary(path: pathlib.Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(
            f"Crate summary CSV not found: {path}. Did you run analyse_crate_contents.py?"
        )
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_crossrefs(path: pathlib.Path) -> Dict[int, Counter[str]]:
    if not path.exists():
        return {}
    hits: Dict[int, Counter[str]] = {}
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                value = int(row["value"])
            except (KeyError, TypeError, ValueError):
                continue
            table = row.get("table", "unknown")
            hits.setdefault(value, Counter())[table] += 1
    return hits


def load_value_domains(path: pathlib.Path) -> Dict[int, Dict[str, str]]:
    if not path.exists():
        return {}
    result: Dict[int, Dict[str, str]] = {}
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                value = int(row.get("value", ""))
            except (TypeError, ValueError):
                continue
            result[value] = {
                "kind": row.get("kind", ""),
                "domain": row.get("dominant_domain", ""),
                "domain_hint": row.get("dominant_domain_hint", ""),
                "slot_count": row.get("crate_slot_count", ""),
                "slot_context": row.get("crate_slots", ""),
            }
    return result


def _format_counter(counter: Counter[str], limit: int = 6) -> str:
    pairs = counter.most_common(limit)
    return "; ".join(f"{name}:{count}" for name, count in pairs)


def build_weapon_index(weapons: Iterable[WeaponRecord]) -> Dict[int, List[Tuple[WeaponRecord, str]]]:
    index: Dict[int, List[Tuple[WeaponRecord, str]]] = {}
    for record in weapons:
        index.setdefault(record.weapon_id, []).append((record, "primary"))
        if record.upgrade_id:
            index.setdefault(record.upgrade_id, []).append((record, "upgrade"))
    return index


def main() -> None:
    parser = argparse.ArgumentParser(description="Join crate, weapon, and projectile data")
    parser.add_argument("--crate-summary", default=str(DEFAULT_CRATE_CSV), help="Path to crate summary CSV")
    parser.add_argument(
        "--root",
        default=str(CONTAINER_ROOT),
        help="Root directory containing WEAPONS.BIN and PROJECTILES.BIN",
    )
    parser.add_argument(
        "--crossref",
        default=str(DEFAULT_CROSSREF_CSV),
        help="Optional cross-reference CSV (from crossref_crate_values.py)",
    )
    parser.add_argument(
        "--value-domain",
        default=str(DEFAULT_VALUE_DOMAIN_CSV),
        help="Optional value domain summary CSV",
    )
    parser.add_argument("--output", default=str(OUTPUT_CSV), help="Destination CSV path")
    args = parser.parse_args()

    root = pathlib.Path(args.root)
    weapons = load_weapons(root / "WEAPONS.BIN")
    projectiles = load_projectiles(root / "PROJECTILES.BIN")
    toys = load_toys(root / "TOYS.BIN")
    vehicles = load_vehicles(root / "VEHICLES.BIN")
    crate_rows = read_crate_summary(pathlib.Path(args.crate_summary))
    crossrefs = load_crossrefs(pathlib.Path(args.crossref))
    value_domains = load_value_domains(pathlib.Path(args.value_domain))

    weapon_lookup = build_weapon_index(weapons)
    projectile_lookup = {record.index: record for record in projectiles}
    toy_lookup = {record.index: record for record in toys}
    vehicle_lookup = {record.index: record for record in vehicles}

    toy_word_count = len(toys[0].words) if toys else 0
    vehicle_word_count = len(vehicles[0].words) if vehicles else 0
    vehicle_word_limit = min(vehicle_word_count, 12)

    out_path = pathlib.Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    headers = [
        "crate_index",
        "crate_label",
        "slot",
        "value_a",
        "value_b",
        "toy_present",
        *[f"toy_w{i:02d}" for i in range(toy_word_count)],
        "vehicle_present",
        *[f"vehicle_w{i:02d}" for i in range(vehicle_word_limit)],
    "value_a_crossref_total",
    "value_a_crossref_tables",
    "value_a_domain",
    "value_a_domain_hint",
    "value_a_kind",
    "value_a_slot_context",
    "value_b_crossref_total",
    "value_b_crossref_tables",
    "value_b_domain",
    "value_b_domain_hint",
    "value_b_kind",
    "value_b_slot_context",
        "weapon_matches",
        "weapon_index",
        "weapon_match_kind",
        "weapon_upgrade_id",
        "weapon_projectile_index",
        "weapon_range_a",
        "weapon_range_b",
        "weapon_cooldown",
        "weapon_camera_kick",
        "weapon_resource0",
        "weapon_resource1",
        "weapon_resource2",
        "weapon_resource3",
        "weapon_resource4",
        "projectile_index",
        "projectile_archetype_id",
        "projectile_damage",
        "projectile_burst_count",
        "projectile_collision_mask",
        "projectile_velocity_x",
        "projectile_velocity_y",
        "projectile_velocity_z",
        "projectile_fuse_frames",
        "projectile_spawn_interval",
        "projectile_resource_a",
        "projectile_resource_b",
        "projectile_resource_c",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for row in crate_rows:
            crate_index = int(row.get("index", "0"))
            crate_label = row.get("label", "")
            slot = int(row.get("slot", "0"))
            value_a = int(row.get("value_a", "0"))
            value_b = int(row.get("value_b", "0"))

            toy = toy_lookup.get(value_a)
            toy_present = 1 if toy else 0
            toy_columns: List[object] = []
            if toy:
                toy_columns.extend(toy.words)
            else:
                toy_columns.extend([""] * toy_word_count)

            vehicle = vehicle_lookup.get(value_b)
            vehicle_present = 1 if vehicle else 0
            vehicle_columns: List[object] = []
            if vehicle:
                vehicle_columns.extend(vehicle.words[:vehicle_word_limit])
            else:
                vehicle_columns.extend([""] * vehicle_word_limit)

            a_counter = crossrefs.get(value_a)
            a_total = sum(a_counter.values()) if a_counter else ""
            a_summary = _format_counter(a_counter) if a_counter else ""
            a_domain_info = value_domains.get(value_a, {})

            b_counter = crossrefs.get(value_b)
            b_total = sum(b_counter.values()) if b_counter else ""
            b_summary = _format_counter(b_counter) if b_counter else ""
            b_domain_info = value_domains.get(value_b, {})

            matches = weapon_lookup.get(value_b, [])
            prefix = [
                crate_index,
                crate_label,
                slot,
                value_a,
                value_b,
                toy_present,
                *toy_columns,
                vehicle_present,
                *vehicle_columns,
                a_total,
                a_summary,
                a_domain_info.get("domain", ""),
                a_domain_info.get("domain_hint", ""),
                a_domain_info.get("kind", ""),
                a_domain_info.get("slot_context", ""),
                b_total,
                b_summary,
                b_domain_info.get("domain", ""),
                b_domain_info.get("domain_hint", ""),
                b_domain_info.get("kind", ""),
                b_domain_info.get("slot_context", ""),
                len(matches),
            ]

            if not matches:
                writer.writerow(prefix + [""] * (len(headers) - len(prefix)))
                continue

            for weapon, match_kind in matches:
                projectile = projectile_lookup.get(weapon.projectile_index)
                weapon_part = [
                    weapon.index,
                    match_kind,
                    weapon.upgrade_id,
                    weapon.projectile_index,
                    weapon.range_a,
                    weapon.range_b,
                    weapon.cooldown,
                    weapon.camera_kick,
                    weapon.resource0,
                    weapon.resource1,
                    weapon.resource2,
                    weapon.resource3,
                    weapon.resource4,
                ]
                projectile_part = [
                    projectile.index if projectile else "",
                    projectile.archetype_id if projectile else "",
                    projectile.damage if projectile else "",
                    projectile.burst_count if projectile else "",
                    projectile.collision_mask if projectile else "",
                    projectile.velocity_x if projectile else "",
                    projectile.velocity_y if projectile else "",
                    projectile.velocity_z if projectile else "",
                    projectile.fuse_frames if projectile else "",
                    projectile.spawn_interval if projectile else "",
                    projectile.resource_a if projectile else "",
                    projectile.resource_b if projectile else "",
                    projectile.resource_c if projectile else "",
                ]
                writer.writerow(prefix + weapon_part + projectile_part)

    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
