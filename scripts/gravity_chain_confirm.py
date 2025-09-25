#!/usr/bin/env python3
"""
Correlate detected Q12 integrators with composed gravity chains/callers.

Inputs:
- exports/physics_integrator_map.csv (from gravity_integrator_detect.py)
- exports/gravity_composed_integrators_extended.csv (if present)
- exports/gravity_chain_intersections.json (fallback metadata)

Output:
- exports/physics_integrator_chains.md: For each integrator, list known callers and any scores.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / "exports"


def read_integrators() -> List[Dict[str, str]]:
    path = EXP / "physics_integrator_map.csv"
    rows: List[Dict[str, str]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        for r in rd:
            rows.append(r)
    return rows


def read_composed() -> List[Dict[str, str]]:
    path = EXP / "gravity_composed_integrators_extended.csv"
    rows: List[Dict[str, str]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        for r in rd:
            rows.append(r)
    return rows


def read_intersections() -> List[Dict[str, str]]:
    path = EXP / "gravity_chain_intersections.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    # Normalize to a list of dicts with at least caller/integrator keys when possible
    out: List[Dict[str, str]] = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        out.append(item)
    return out


def build_map():
    integrators = read_integrators()
    comp = read_composed()
    inter = read_intersections()

    # Index composed by integrator name
    composed_by_int: Dict[str, List[Dict[str, str]]] = {}
    for r in comp:
        integ = r.get("Integrator") or r.get("integrator") or r.get("callee") or ""
        caller = r.get("Caller") or r.get("caller") or r.get("caller_name") or ""
        if not integ:
            continue
        lst = composed_by_int.setdefault(integ, [])
        lst.append(r)

    # Intersections fallback: try to infer pairs if labeled
    inter_by_int: Dict[str, List[Dict[str, str]]] = {}
    for r in inter:
        integ = r.get("integrator") or r.get("callee") or r.get("nodeB") or ""
        caller = r.get("caller") or r.get("nodeA") or ""
        if integ:
            inter_by_int.setdefault(integ, []).append(r)

    # Write markdown
    outp = EXP / "physics_integrator_chains.md"
    with outp.open("w", encoding="utf-8") as f:
        f.write("# Physics Integrator Chains\n\n")
        f.write("Correlates Q12 integrators with known composed chains and intersections.\n\n")
        for r in sorted(integrators, key=lambda x: (x.get("function",""))):
            fn = r.get("function", "")
            ea = r.get("ea", "")
            axes = r.get("axes", "")
            f.write(f"## {fn} {ea}\n\n")
            f.write(f"- Axes: {axes}\n\n")
            rows = composed_by_int.get(fn, [])
            if rows:
                f.write("### Composed Chains\n\n")
                f.write("| Caller | Score | Notes |\n|---|---:|---|\n")
                for rr in rows:
                    caller = rr.get("Caller") or rr.get("caller") or rr.get("nodeA") or ""
                    score = rr.get("Score") or rr.get("score") or rr.get("weight") or ""
                    notes = rr.get("Notes") or rr.get("notes") or ""
                    f.write(f"| {caller} | {score} | {notes} |\n")
                f.write("\n")
            rows2 = inter_by_int.get(fn, [])
            if rows2:
                f.write("### Intersections (fallback)\n\n")
                for rr in rows2[:10]:
                    caller = rr.get("caller") or rr.get("nodeA") or ""
                    f.write(f"- {caller}\n")
                if len(rows2) > 10:
                    f.write(f"- ... and {len(rows2)-10} more\n")
                f.write("\n")


if __name__ == "__main__":
    build_map()
