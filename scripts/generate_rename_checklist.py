#!/usr/bin/env python3
"""
generate_rename_checklist.py

Produce a CSV checklist of high-priority functions with suggested names based on
Q12 traits and TbActorPrefix evidence, merged with integrator/orientation info.

Output: exports/rename_checklist.csv
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"
Q12_JSON = EXPORTS / "q12_math_candidates.json"
INTEGRATOR_CSV = EXPORTS / "physics_integrator_map.csv"
OUT_CSV = EXPORTS / "rename_checklist.csv"


def load_q12(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("candidates", [])


def load_integrators(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    out: dict[str, dict[str, str]] = {}
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            name = row.get("function")
            if name:
                out[name] = row
    return out


def weighted_score(entry: dict) -> int:
    return (
        3 * entry.get("right_shifts", 0)
        + 2 * entry.get("q12_products", 0)
        + 2 * entry.get("sar_calls", 0)
        + 2 * entry.get("angle_masks", 0)
        + 1 * entry.get("left_shifts", 0)
        + 1 * entry.get("pos_shifts", 0)
        + 1 * entry.get("q12_one_consts", 0)
        + 1 * entry.get("q12_half_consts", 0)
    ) or entry.get("total_hits", 0)


def suggest_name(entry: dict, integ: dict | None) -> tuple[str, str]:
    name = entry.get("name", "UNKNOWN")
    rs = weighted_score(entry)
    pos = entry.get("pos_hits", 0)
    ang = entry.get("angle_hits", 0)
    bd = entry.get("basis_dest_hits", 0)
    bs = entry.get("basis_src_hits", 0)
    spd = entry.get("speed_hits", 0)
    trig = entry.get("rsin_calls", 0) + entry.get("rcos_calls", 0)
    if integ:
        axes = integ.get("axes", "-")
        direct = integ.get("direct_pos_write", "0") == "1"
    else:
        axes, direct = "-", False

    # Heuristics
    if integ and direct and axes in ("Z", "z") and pos > 0 and bd > 0:
        sugg = "phys_integrate_pos_z_candidate"
        why = f"integrator+direct Z; Pxyz={pos}, BD={bd}"
        return sugg, why
    if bd + bs + spd >= 40:
        # basis-heavy: prefer recompute when BS dominates, else normalize
        if bs >= bd:
            sugg = "orient_recompute_basis_candidate"
            why = f"basis-src heavy; BS={bs}, BD={bd}, Spd={spd}"
        else:
            sugg = "orient_normalize_basis_candidate"
            why = f"basis-dest heavy; BD={bd}, BS={bs}, Spd={spd}"
        return sugg, why
    if trig > 0 and ang > 0:
        sugg = "orientation_trig_update_candidate"
        why = f"trig={trig}, angles={ang}"
        return sugg, why
    if ang > 0 and rs >= 40:
        sugg = "orientation_update_candidate"
        why = f"angles+Q12 heavy; WScore={rs}, Ang={ang}"
        return sugg, why
    return "q12_candidate", f"WScore={rs}, Pxyz={pos}, Ang={ang}, BD={bd}, BS={bs}, Spd={spd}"


def main(limit: int = 150) -> None:
    q12 = load_q12(Q12_JSON)
    integrators = load_integrators(INTEGRATOR_CSV)
    # stable sort like overlay
    q12.sort(
        key=lambda e: (
            -weighted_score(e),
            -(e.get("rsin_calls", 0) + e.get("rcos_calls", 0)),
            e.get("name", "")
        )
    )

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "function","ea","binary","score","integrator","direct_pos","axes",
            "pos_hits","angle_hits","basis_dest_hits","basis_src_hits","speed_hits","trig_hits",
            "suggested_name","reason"
        ])
        for entry in q12[:limit]:
            name = entry.get("name")
            integ = integrators.get(name)
            trig = entry.get("rsin_calls", 0) + entry.get("rcos_calls", 0)
            sugg, why = suggest_name(entry, integ)
            writer.writerow([
                name,
                entry.get("ea_hex","?"),
                entry.get("binary",""),
                weighted_score(entry),
                1 if integ else 0,
                1 if (integ and integ.get("direct_pos_write","0")=="1") else 0,
                (integ.get("axes") if integ else "-"),
                entry.get("pos_hits",0),
                entry.get("angle_hits",0),
                entry.get("basis_dest_hits",0),
                entry.get("basis_src_hits",0),
                entry.get("speed_hits",0),
                trig,
                sugg,
                why
            ])
    print(f"Wrote {OUT_CSV}")


if __name__ == "__main__":
    main()
