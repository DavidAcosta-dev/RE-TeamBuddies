#!/usr/bin/env python3
"""
generate_z_writer_dossier.py

Create a focused dossier for direct-Z position writers found in integrator map
and top Q12 candidates. Extract 3-5 decomp lines around Pxyz hits and summarize
axes and direct-pos flags for rapid manual verification.

Output: exports/z_writer_dossier.md
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"
Q12_JSON = EXPORTS / "q12_math_candidates.json"
INTEGRATOR_CSV = EXPORTS / "physics_integrator_map.csv"
BUNDLE_GLOB = "exports/bundle_*.jsonl"
OUT_MD = EXPORTS / "z_writer_dossier.md"

POS_OFFS = {0x08, 0x0C, 0x10}
OFF_RE = re.compile(r"\+\s*0x(?:8|c|10)\b", re.IGNORECASE)


def load_q12(path: Path) -> List[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("candidates", [])


def load_integrators(path: Path) -> Dict[str, dict]:
    import csv
    if not path.exists():
        return {}
    out: Dict[str, dict] = {}
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            nm = row.get("function")
            if nm:
                out[nm] = row
    return out


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            import json as _j
            try:
                yield _j.loads(line)
            except _j.JSONDecodeError:
                continue


def collect_snippets(names: List[str], bundles: List[Path]) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {n: [] for n in names}
    for path in bundles:
        for entry in iter_jsonl(path):
            fn = entry.get("function") or {}
            name = fn.get("name")
            if name not in result:
                continue
            decomp = entry.get("decompilation") or ""
            if not decomp:
                continue
            lines = decomp.splitlines()
            for i, ln in enumerate(lines):
                if OFF_RE.search(ln):
                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    snippet = " ".join(l.strip() for l in lines[start:end])
                    if snippet not in result[name]:
                        result[name].append(snippet)
                    if len(result[name]) >= 5:
                        break
    return result


def main() -> None:
    q12 = load_q12(Q12_JSON)
    integ = load_integrators(INTEGRATOR_CSV)
    # choose top Z-writers from integrator map and Q12 pos evidence
    z_funcs: List[str] = []
    for nm, row in integ.items():
        if row.get("axes") == "Z" and row.get("direct_pos_write", "0") == "1":
            z_funcs.append(nm)
    # Include top Q12 with high Pxyz + some basis evidence
    q12_sorted = sorted(q12, key=lambda e: (-(e.get("pos_hits", 0)), -e.get("basis_dest_hits", 0), e.get("name", "")))
    for e in q12_sorted[:10]:
        if e.get("pos_hits", 0) >= 20:
            z_funcs.append(e.get("name"))
    # de-dup
    z_funcs = sorted(set(z_funcs))

    bundles = sorted(ROOT.glob(BUNDLE_GLOB))
    snippets = collect_snippets(z_funcs, bundles)

    lines: List[str] = []
    lines.append("# Direct-Z Writer Dossier")
    lines.append("")
    for nm in z_funcs:
        meta = integ.get(nm, {})
        lines.append(f"## {nm}")
        lines.append("")
        lines.append(f"- Integrator: {'yes' if nm in integ else 'no'}; axes={meta.get('axes','-')}; directPos={meta.get('direct_pos_write','0')}")
        lines.append("")
        for sn in snippets.get(nm, [])[:5]:
            lines.append(f"> {sn}")
        lines.append("")
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUT_MD}")


if __name__ == "__main__":
    main()
