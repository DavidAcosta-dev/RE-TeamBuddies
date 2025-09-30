#!/usr/bin/env python3
"""Extract weapon and projectile data into a Unity-friendly JSON catalog."""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = REPO_ROOT / "exports" / "crate_weapon_projectile_matrix.csv"
DEFAULT_OUTPUT = REPO_ROOT / "exports" / "weapon_definitions.json"


_NUMERIC_FIELDS = {
    "weaponIndex",
    "weaponMatches",
    "weaponProjectileIndex",
    "weaponUpgradeId",
    "weaponRangeA",
    "weaponRangeB",
    "weaponCooldown",
    "weaponCameraKick",
    "weaponResource0",
    "weaponResource1",
    "weaponResource2",
    "weaponResource3",
    "weaponResource4",
    "projectileIndex",
    "projectileArchetypeId",
    "projectileDamage",
    "projectileBurstCount",
    "projectileCollisionMask",
    "projectileVelocityX",
    "projectileVelocityY",
    "projectileVelocityZ",
    "projectileFuseFrames",
    "projectileSpawnInterval",
    "projectileResourceA",
    "projectileResourceB",
    "projectileResourceC",
}


def _normalise_key(name: str) -> str:
    parts = name.strip().split("_")
    if not parts:
        return name
    first, *rest = parts
    rest_cap = [seg.capitalize() for seg in rest]
    return first + "".join(rest_cap)


def _coerce(value: str | None) -> Any:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return text


def _merge_field(target: Dict[str, Any], key: str, value: Any) -> None:
    if value is None:
        return
    existing = target.get(key)
    if existing is None:
        target[key] = value
    elif isinstance(existing, list):
        if value not in existing:
            existing.append(value)
    elif existing != value:
        target[key] = [existing, value]


def build_weapon_catalog(source: Path) -> Dict[str, Any]:
    if not source.exists():
        raise FileNotFoundError(f"Missing source CSV: {source}")

    with source.open(encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp)
        weapons: Dict[str, Dict[str, Any]] = {}
        projectile_sources: Dict[str, set[str]] = defaultdict(set)

        for row in reader:
            weapon_projectile_index = row.get("weapon_projectile_index", "").strip()
            if not weapon_projectile_index:
                continue

            key = weapon_projectile_index
            weapon = weapons.setdefault(
                key,
                {
                    "weaponId": f"weapon-{weapon_projectile_index}",
                    "weaponProjectileIndex": None,
                    "weaponIndex": None,
                    "weaponRoles": [],
                    "weaponMatches": None,
                    "weaponUpgradeId": None,
                    "weaponRangeA": None,
                    "weaponRangeB": None,
                    "weaponCooldown": None,
                    "weaponCameraKick": None,
                    "weaponResource0": None,
                    "weaponResource1": None,
                    "weaponResource2": None,
                    "weaponResource3": None,
                    "weaponResource4": None,
                    "projectileIndex": None,
                    "projectileArchetypeId": None,
                    "projectileDamage": None,
                    "projectileBurstCount": None,
                    "projectileCollisionMask": None,
                    "projectileVelocityX": None,
                    "projectileVelocityY": None,
                    "projectileVelocityZ": None,
                    "projectileFuseFrames": None,
                    "projectileSpawnInterval": None,
                    "projectileResourceA": None,
                    "projectileResourceB": None,
                    "projectileResourceC": None,
                    "sources": [],
                },
            )

            for csv_key, raw_value in row.items():
                if not csv_key:
                    continue
                norm_key = _normalise_key(csv_key)
                if norm_key not in weapon:
                    continue
                coerced = _coerce(raw_value)
                if norm_key in _NUMERIC_FIELDS and isinstance(coerced, float):
                    # Normalise floats that are effectively ints
                    if coerced.is_integer():
                        coerced = int(coerced)
                _merge_field(weapon, norm_key, coerced)

            source_entry = {
                "crateIndex": _coerce(row.get("crate_index")),
                "crateLabel": row.get("crate_label", ""),
                "slot": _coerce(row.get("slot")),
                "priority": row.get("priority", ""),
                "matchKind": row.get("weapon_match_kind", "") or row.get("weapon_match_type", ""),
                "weaponIndex": _coerce(row.get("weapon_index")),
            }
            weapon["sources"].append(source_entry)

            match_kind = source_entry["matchKind"].strip()
            if match_kind:
                roles = weapon.setdefault("weaponRoles", [])
                if match_kind not in roles:
                    roles.append(match_kind)

            proj_idx = weapon.get("projectileIndex")
            if proj_idx is not None:
                projectile_sources[str(proj_idx)].add(key)

    for weapon in weapons.values():
        field_conflicts = []
        for field_name, field_value in list(weapon.items()):
            if field_name in {"sources", "weaponRoles"}:
                continue
            if isinstance(field_value, list):
                filtered = [value for value in field_value if value is not None]
                if not filtered:
                    weapon[field_name] = None
                else:
                    weapon[field_name] = filtered[0]
                if filtered and len(filtered) > 1:
                    field_conflicts.append({"field": field_name, "values": filtered})
        if field_conflicts:
            weapon["conflictingValues"] = field_conflicts

    weapons_sorted = [weapons[key] for key in sorted(weapons.keys(), key=int)]
    for weapon in weapons_sorted:
        roles = weapon.get("weaponRoles")
        if roles:
            weapon["weaponRoles"] = sorted(roles)

    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "sourceCsv": str(source.relative_to(REPO_ROOT)),
        "weaponCount": len(weapons_sorted),
        "weapons": weapons_sorted,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build weapon catalog JSON from crate matrix CSV")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE, help="Path to crate_weapon_projectile_matrix.csv")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Destination JSON path")
    args = parser.parse_args()

    catalog = build_weapon_catalog(args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fp:
        json.dump(catalog, fp, indent=2)
        fp.write("\n")

    print(f"Wrote {args.output} ({catalog['weaponCount']} weapons)")


if __name__ == "__main__":
    main()
