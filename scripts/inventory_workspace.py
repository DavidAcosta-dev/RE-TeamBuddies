#!/usr/bin/env python3
"""Workspace inventory generator.

Walks the entire repository tree and produces:
 1. exports/inventory/workspace_inventory.json  (exhaustive list with size + category)
 2. exports/inventory/workspace_inventory.md    (human friendly summary + category tables)

Categories are heuristic based on path prefixes:
  - exports/* -> analysis_export
  - scripts/* -> analysis_script
  - notes/* -> manual_note
  - ghidra_scripts/* -> ghidra_script
  - ghidra_proj/* -> ghidra_project
  - TeamBuddiesGameFiles/* -> game_asset
  - PSYQ_SDK/* -> sdk_vendor
  - PSYQ_Examples-master/* -> sdk_example
  - assets/* -> raw_asset
  - everything else -> misc

Outputs also include aggregate counts and total size per category.
"""

from __future__ import annotations
import os, json, hashlib, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / 'exports' / 'inventory'
OUT_DIR.mkdir(parents=True, exist_ok=True)

OVERLAY_EXTS = {'.BIN', '.bin'}

def categorize(rel: str) -> str:
    # Primary structured categories
    if rel.startswith('exports/'):
        return 'analysis_export'
    if rel.startswith('scripts/'):
        return 'analysis_script'
    if rel.startswith('notes/'):
        return 'manual_note'
    if rel.startswith('ghidra_scripts/'):
        return 'ghidra_script'
    if rel.startswith('ghidra_proj/'):
        return 'ghidra_project'
    if rel.startswith('TeamBuddiesGameFiles/'):
        # Differentiate overlay binaries vs general assets
        suffix = Path(rel).suffix
        if suffix in OVERLAY_EXTS and '/' not in rel[len('TeamBuddiesGameFiles/'):]:
            return 'overlay_binary'
        return 'game_asset'
    if rel.startswith('PSYQ_SDK/'):
        return 'sdk_vendor'
    if rel.startswith('PSYQ_Examples-master/'):
        return 'sdk_example'
    if rel.startswith('assets/'):
        return 'raw_asset'
    # Fallback
    return 'misc'

records = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    # Skip hidden directories (if any)
    rel_dir = os.path.relpath(dirpath, ROOT)
    for fn in filenames:
        fpath = Path(dirpath) / fn
        rel = os.path.relpath(fpath, ROOT).replace('\\', '/')
        try:
            size = fpath.stat().st_size
        except OSError:
            size = None
        cat = categorize(rel)
        records.append({
            'path': rel,
            'size': size,
            'category': cat,
        })

# Aggregation
from collections import defaultdict
agg_count = defaultdict(int)
agg_size = defaultdict(int)
total_size = 0
for r in records:
    agg_count[r['category']] += 1
    if r['size'] is not None:
        agg_size[r['category']] += r['size']
        total_size += r['size']

now = datetime.datetime.utcnow().isoformat() + 'Z'
inventory = {
    'generated_utc': now,
    'root': str(ROOT),
    'total_files': len(records),
    'total_size_bytes': total_size,
    'category_counts': agg_count,
    'category_sizes': agg_size,
    'files': records,
}

json_path = OUT_DIR / 'workspace_inventory.json'
json_path.write_text(json.dumps(inventory, indent=2))

def fmt_size(num: int) -> str:
    for unit in ['B','KB','MB','GB']:
        if num < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"

md_lines = []
md_lines.append('# Workspace Inventory Summary')
md_lines.append(f'Generated: {now}')
md_lines.append('')
md_lines.append('## Category Overview')
md_lines.append('| Category | Files | Size | Percent Files | Percent Size |')
md_lines.append('|----------|------:|-----:|--------------:|-------------:|')
for cat in sorted(agg_count.keys()):
    cf = agg_count[cat]
    cs = agg_size[cat]
    pf = (cf / len(records))*100 if records else 0
    ps = (cs / total_size)*100 if total_size else 0
    md_lines.append(f'| {cat} | {cf} | {fmt_size(cs)} | {pf:5.2f}% | {ps:5.2f}% |')

md_lines.append('\n## Category Definitions')
md_lines.append('- analysis_export: Generated reverse-engineering artifacts (pattern scans, coverage reports)')
md_lines.append('- analysis_script: Python or helper scripts used to perform scans and produce exports')
md_lines.append('- manual_note: Curated human-authored notes & progress tracking')
md_lines.append('- ghidra_script: Scripts intended to run inside Ghidra to extract or analyze disassembly')
md_lines.append('- ghidra_project: Raw Ghidra project data (do not edit manually)')
md_lines.append('- game_asset: Original game data files used for reverse engineering context')
md_lines.append('- sdk_vendor: PSYQ SDK toolchain/vendor libraries for reference & possible symbol inference')
md_lines.append('- sdk_example: PSYQ example projects for pattern comparison / library call usage')
md_lines.append('- raw_asset: Supplemental assets or demos outside primary game data')
md_lines.append('- misc: Files not falling cleanly into other categories')

md_lines.append('\n## File List (Exhaustive)')
md_lines.append('Path | Category | Size')
md_lines.append('---- | -------- | ----')
for r in sorted(records, key=lambda x: x['path']):
    sz = fmt_size(r['size']) if r['size'] is not None else 'NA'
    md_lines.append(f"{r['path']} | {r['category']} | {sz}")

md_path = OUT_DIR / 'workspace_inventory.md'
md_path.write_text('\n'.join(md_lines))

print(f"Inventory written: {json_path} ({len(records)} files)")
print(f"Markdown summary: {md_path}")
