#!/usr/bin/env python3
"""Aggregate function categories from existing export artifacts.

Scans the exports directory for known category listing files and produces:
  exports/inventory/function_category_index.json

Currently parses:
  - vertical_core_functions.md
  - vertical_consumer_functions.md
  - vertical_legacy_consumer_diff.md (tag: vertical_legacy_only)
  - crate_system_candidates.md (tag: crate)
  - pickup_drop_candidates.md (tag: pickup_drop)
  - input_candidates_MAIN.EXE.md / input_candidates_GAME.BIN.md (tag: input)
  - cdstream_consumer_candidates.md (tag: cdstream)
  - gravity_candidates.md (tag: gravity)
  - mapping_coverage_report.md (multi-category hubs list)

Merges all into a dict: { function_name: {categories:[...], sources:[...]} }
"""
from __future__ import annotations
import re, json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
OUT_DIR = EXPORTS / 'inventory'
OUT_DIR.mkdir(parents=True, exist_ok=True)

def parse_fun_names_from_lines(lines, pattern):
    rx = re.compile(pattern)
    for ln in lines:
        m = rx.search(ln)
        if m:
            yield m.group(1)

index = {}

def add(fn, cat, source):
    entry = index.setdefault(fn, {'categories': set(), 'sources': set()})
    entry['categories'].add(cat)
    entry['sources'].add(source)

def load_file(rel):
    p = EXPORTS / rel
    if not p.exists():
        return []
    return p.read_text(encoding='utf-8', errors='ignore').splitlines()

def extract_simple_list(rel, cat):
    lines = load_file(rel)
    for fn in parse_fun_names_from_lines(lines, r'(FUN_0[0-9a-fA-F]{5,})'):
        add(fn, cat, rel)

# Specific parsers
extract_simple_list('vertical_core_functions.md', 'vertical_core')
extract_simple_list('vertical_consumer_functions.md', 'vertical_consumer')
extract_simple_list('vertical_legacy_consumer_diff.md', 'vertical_legacy_only')
extract_simple_list('crate_system_candidates.md', 'crate')
extract_simple_list('pickup_drop_candidates.md', 'pickup_drop')
extract_simple_list('input_candidates_MAIN.EXE.md', 'input')
extract_simple_list('input_candidates_GAME.BIN.md', 'input')
extract_simple_list('cdstream_consumer_candidates.md', 'cdstream')
extract_simple_list('gravity_candidates.md', 'gravity')

# Parse multi-category hub list from mapping_coverage_report
hub_lines = load_file('mapping_coverage_report.md')
hub_section = False
for ln in hub_lines:
    if 'Multi-Category Function Candidates' in ln:
        hub_section = True
        continue
    if hub_section and ln.startswith('## '):
        break
    if hub_section and ln.startswith('- FUN_'):
        # Format: - FUN_xxxxxx: cat1/cat2/...
        parts = ln[2:].split(':',1)
        if len(parts) == 2:
            fn = parts[0].strip()
            cats = [c.strip() for c in parts[1].split('/') if c.strip()]
            for c in cats:
                add(fn, c, 'mapping_coverage_report.md')

# Finalize
serializable = {
    fn: {
        'categories': sorted(v['categories']),
        'sources': sorted(v['sources'])
    } for fn, v in sorted(index.items())
}

out_path = OUT_DIR / 'function_category_index.json'
out_path.write_text(json.dumps(serializable, indent=2))
print(f"Wrote {out_path} with {len(serializable)} functions")
