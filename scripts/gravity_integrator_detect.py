#!/usr/bin/env python3
"""
Scan exported decompilations for fixed-point physics integrator patterns:
- Identify functions that update position fields using velocity components with >> 0xC (Q12)
- Heuristic-based detection focusing on common offsets:
  - Position (candidate): +0x8 (X), +0xA (Y), +0xC (Z)
  - Velocity (candidate): +0x34 (VX), +0x36 (VY), +0x38 (VZ)

Inputs:
- exports/bundle_all_plus_demo.jsonl (preferred)
- exports/bundle_ghidra.jsonl (fallback/also scanned)

Outputs:
- exports/physics_integrator_map.csv
- exports/physics_integrator_map.md
- exports/physics_integrator_candidates.md (contextual snippets)

Notes:
- This is heuristic and robust to noisy decompilation. It looks for the same base pointer
  accessing both pos and vel offsets in the same function, plus evidence of >> 0xC in
  arithmetic near pos writes.
- It emits per-function findings, listing which axes (X/Y/Z) were observed and a short snippet.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
EXPORTS = WORKSPACE_ROOT / "exports"
INPUT_FILES = [
    EXPORTS / "bundle_all_plus_demo.jsonl",
    EXPORTS / "bundle_ghidra.jsonl",
]

POS_OFFSETS = {0x8: "X", 0xA: "Y", 0xC: "Z"}
VEL_OFFSETS = {0x34: "VX", 0x36: "VY", 0x38: "VZ"}


@dataclass
class FunctionRecord:
    tool: str
    binary: str
    name: str
    ea: int
    decompilation: str


@dataclass
class BaseAccessInfo:
    base: str
    pos_hits: Dict[int, List[str]] = field(default_factory=lambda: {k: [] for k in POS_OFFSETS})
    vel_hits: Dict[int, List[str]] = field(default_factory=lambda: {k: [] for k in VEL_OFFSETS})
    shift_hits: List[str] = field(default_factory=list)
    pos_write_lines: List[str] = field(default_factory=list)


@dataclass
class IntegratorFinding:
    func_name: str
    ea: int
    base: str
    axes: List[str]
    direct_pos_write: bool
    lines: List[str]


BASE_ACCESS_RE = re.compile(r"\*\((?:u?short|short|undefined2) \*\)\((?P<base>[^)]+)\s*\+\s*0x(?P<off>[0-9a-fA-F]+)\)")
SHIFT_RE = re.compile(r">>\s*0x?c\b", re.IGNORECASE)

# Approximate detection of a write to a position field using same base and containing a shift
POS_WRITE_RE = re.compile(
    r"^\s*(?:\*\s*)?\(?(?:u?short|short|undefined2)\s*\*\)?\s*\((?P<base>[^)]+)\s*\+\s*0x(?P<off>[0-9a-fA-F]+)\)\s*=.*>>\s*0x?c",
    re.IGNORECASE,
)


def iter_functions(paths: List[Path]) -> List[FunctionRecord]:
    out: List[FunctionRecord] = []
    seen_keys = set()
    for p in paths:
        if not p.exists():
            continue
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                func = obj.get("function") or {}
                name = func.get("name") or obj.get("name")
                ea = int(func.get("ea")) if func.get("ea") is not None else -1
                decomp = obj.get("decompilation") or obj.get("code") or ""
                tool = obj.get("tool") or ""
                binary = obj.get("binary") or ""
                key = (name, ea)
                if not name or not decomp:
                    continue
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                out.append(FunctionRecord(tool=tool, binary=binary, name=name, ea=ea, decompilation=decomp))
    return out


def analyze_function(fr: FunctionRecord) -> List[IntegratorFinding]:
    text = fr.decompilation
    lines = text.splitlines()

    # Track base-wise accesses
    base_map: Dict[str, BaseAccessInfo] = {}

    # First pass: collect all memory access sites and shift evidence
    for ln in lines:
        for m in BASE_ACCESS_RE.finditer(ln):
            base = m.group("base").strip()
            try:
                off = int(m.group("off"), 16)
            except ValueError:
                continue
            info = base_map.setdefault(base, BaseAccessInfo(base=base))
            if off in POS_OFFSETS:
                info.pos_hits[off].append(ln.strip())
            if off in VEL_OFFSETS:
                info.vel_hits[off].append(ln.strip())
        if SHIFT_RE.search(ln):
            # Record generic shift usage
            for info in base_map.values():
                info.shift_hits.append(ln.strip())

    # Second pass: try to pick out explicit pos writes
    for ln in lines:
        m = POS_WRITE_RE.search(ln)
        if not m:
            continue
        base = m.group("base").strip()
        try:
            off = int(m.group("off"), 16)
        except ValueError:
            continue
        if base not in base_map:
            base_map[base] = BaseAccessInfo(base=base)
        if off in POS_OFFSETS:
            base_map[base].pos_write_lines.append(ln.strip())

    findings: List[IntegratorFinding] = []
    for base, info in base_map.items():
        # Must reference at least one pos and one vel and have some >> 0xc evidence
        pos_axes = [POS_OFFSETS[o] for o, hits in info.pos_hits.items() if hits]
        vel_axes = [VEL_OFFSETS[o] for o, hits in info.vel_hits.items() if hits]
        if not pos_axes or not vel_axes:
            continue
        # Check that we have shift usage and ideally a pos write with shift
        has_shift = len(info.shift_hits) > 0
        has_direct_write = len(info.pos_write_lines) > 0
        if not has_shift and not has_direct_write:
            continue

        # Form a compact snippet: up to 3 pos writes + 3 nearby shift lines
        snippet: List[str] = []
        snippet.extend(info.pos_write_lines[:3])
        for ln in info.shift_hits[:3]:
            if ln not in snippet:
                snippet.append(ln)

        axes = sorted(set(pos_axes))
        findings.append(
            IntegratorFinding(
                func_name=fr.name,
                ea=fr.ea,
                base=base,
                axes=axes,
                direct_pos_write=has_direct_write,
                lines=snippet,
            )
        )

    return findings


def write_reports(findings: List[IntegratorFinding]) -> None:
    EXPORTS.mkdir(parents=True, exist_ok=True)

    # CSV
    csv_path = EXPORTS / "physics_integrator_map.csv"
    with csv_path.open("w", encoding="utf-8") as f:
        f.write("function,ea,base,axes,direct_pos_write\n")
        for fi in findings:
            axes = ";".join(fi.axes)
            f.write(f"{fi.func_name},{hex(fi.ea) if fi.ea>=0 else ''},{fi.base},{axes},{int(fi.direct_pos_write)}\n")

    # MD summary table
    md_path = EXPORTS / "physics_integrator_map.md"
    findings_sorted = sorted(findings, key=lambda x: (x.func_name, x.ea))
    with md_path.open("w", encoding="utf-8") as f:
        f.write("# Physics Integrator Map\n\n")
        f.write("This report lists functions that likely implement position updates from velocity using Q12 (>> 0xC).\n\n")
        f.write("| Function | EA | Base | Axes | Direct pos write |\n")
        f.write("|---|---:|---|---|:---:|\n")
        for fi in findings_sorted:
            f.write(
                f"| {fi.func_name} | {hex(fi.ea) if fi.ea>=0 else ''} | `{fi.base}` | {','.join(fi.axes)} | {'yes' if fi.direct_pos_write else 'no'} |\n"
            )

    # Candidates with snippets
    cand_path = EXPORTS / "physics_integrator_candidates.md"
    with cand_path.open("w", encoding="utf-8") as f:
        f.write("# Physics Integrator Candidates\n\n")
        for fi in findings_sorted:
            f.write(f"## {fi.func_name} @ {hex(fi.ea) if fi.ea>=0 else ''}\n\n")
            f.write(f"- Base: `{fi.base}`\n")
            f.write(f"- Axes: {', '.join(fi.axes)}\n")
            f.write(f"- Direct pos write: {'yes' if fi.direct_pos_write else 'no'}\n\n")
            if fi.lines:
                f.write("```c\n")
                for ln in fi.lines:
                    f.write(ln + "\n")
                f.write("```\n\n")


def main() -> None:
    funcs = iter_functions(INPUT_FILES)
    all_findings: List[IntegratorFinding] = []
    for fr in funcs:
        try:
            fnds = analyze_function(fr)
        except Exception:
            # Be resilient to parsing issues
            continue
        if fnds:
            all_findings.extend(fnds)

    # Deduplicate by (func_name, ea, base)
    uniq: Dict[Tuple[str, int, str], IntegratorFinding] = {}
    for fi in all_findings:
        key = (fi.func_name, fi.ea, fi.base)
        if key in uniq:
            # Merge axes and lines
            old = uniq[key]
            old.axes = sorted(set(old.axes) | set(fi.axes))
            if fi.direct_pos_write:
                old.direct_pos_write = True
            # Extend lines but cap at 6
            for ln in fi.lines:
                if ln not in old.lines and len(old.lines) < 6:
                    old.lines.append(ln)
        else:
            uniq[key] = fi

    write_reports(list(uniq.values()))


if __name__ == "__main__":
    main()
