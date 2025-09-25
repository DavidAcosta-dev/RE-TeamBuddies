#!/usr/bin/env python3
"""
Orientation Completion Report

Scans all exports/bundle_*.jsonl for orientation signatures (trig tables & masks)
and cross-references existing orientation role features to produce a completion report.

Outputs:
  exports/orientation_completion_report.md
  exports/orientation_completion_report.json

Heuristics:
  - Detect orientation usage if decompilation references 0x26800/0x27800 or '& 0xfff' mask
    together with likely table indexing ("* 4") or paired table refs.
  - Use exports/orientation_roles_features.csv if present to mark classified roles.
  - Compute completeness = classified / total_detected per-binary and overall.
"""
from __future__ import annotations
import csv, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
OUT_MD = EXPORTS / 'orientation_completion_report.md'
OUT_JSON = EXPORTS / 'orientation_completion_report.json'

bundle_paths = sorted(EXPORTS.glob('bundle_*.jsonl'))

ORIENT_TOKENS = [
    '0x26800', '0x27800', '& 0xfff', '& 0x0fff', '& 0xFFF', '& 0x0FFF'
]

roles_csv = EXPORTS / 'orientation_roles_features.csv'
classified: set[str] = set()
role_by_fn: dict[str, str] = {}
if roles_csv.exists():
    with roles_csv.open('r', encoding='utf-8', errors='ignore') as f:
        rd = csv.DictReader(f)
        # Expect columns: function, role (best guess), ...
        for row in rd:
            fn = row.get('function') or row.get('name') or ''
            role = row.get('role') or row.get('best_role') or row.get('role_guess') or ''
            if fn:
                classified.add(fn)
                if role:
                    role_by_fn[fn] = role

FUN_RE = re.compile(r'FUN_[0-9a-fA-F]{6,}')

def detect_orientation(body: str) -> bool:
    if not body:
        return False
    hits = sum(1 for t in ORIENT_TOKENS if t in body)
    if hits == 0:
        return False
    # Require either two table refs or mask + multiply-by-4 pattern nearby
    tables = (body.count('0x26800') > 0) + (body.count('0x27800') > 0)
    if tables >= 2:
        return True
    if ('& 0xfff' in body or '& 0x0fff' in body or '& 0xFFF' in body or '& 0x0FFF' in body) and '* 4' in body:
        return True
    return False

per_bin = {}
overall_detected: set[str] = set()
overall_classified: set[str] = set()

for bpath in bundle_paths:
    # Skip giant bundles if missing
    try:
        fh = bpath.open('r', encoding='utf-8', errors='ignore')
    except Exception:
        continue
    detected: set[str] = set()
    bodies: dict[str, str] = {}
    with fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            fn = obj.get('function', {}).get('name')
            if not fn:
                continue
            body = obj.get('decompilation') or ''
            bodies[fn] = body
            if detect_orientation(body):
                detected.add(fn)
    cls = detected & classified
    per_bin[bpath.name] = {
        'detected': sorted(detected),
        'classified': sorted(cls),
        'unclassified': sorted(detected - classified),
        'counts': {
            'detected': len(detected),
            'classified': len(cls),
            'unclassified': len(detected - classified),
        }
    }
    overall_detected |= detected
    overall_classified |= cls

summary = {
    'overall': {
        'detected': len(overall_detected),
        'classified': len(overall_classified),
        'unclassified': len(overall_detected - overall_classified),
        'completion_pct': round(100.0 * (len(overall_classified) / max(1, len(overall_detected))), 1)
    },
    'per_binary': {k: v['counts'] for k, v in per_bin.items()}
}

OUT_JSON.write_text(json.dumps({'summary': summary, 'per_binary': per_bin}, indent=2), encoding='utf-8')

lines = []
lines.append('# Orientation Completion Report')
lines.append('')
lines.append(f"Overall: detected={summary['overall']['detected']} | classified={summary['overall']['classified']} | unclassified={summary['overall']['unclassified']} | completion={summary['overall']['completion_pct']}%")
lines.append('')
lines.append('## Per-Binary Summary')
lines.append('')
lines.append('| Binary | Detected | Classified | Unclassified | Completion % |')
lines.append('|--------|---------:|----------:|------------:|-------------:|')
for b, data in sorted(per_bin.items()):
    cnt = data['counts']
    comp = round(100.0 * (cnt['classified'] / max(1, cnt['detected'])), 1)
    lines.append(f"| {b} | {cnt['detected']} | {cnt['classified']} | {cnt['unclassified']} | {comp} |")
lines.append('')
lines.append('## Unclassified Orientation Candidates')
lines.append('')
any_unc = False
for b, data in sorted(per_bin.items()):
    if not data['unclassified']:
        continue
    any_unc = True
    lines.append(f"### {b}")
    for fn in data['unclassified'][:100]:
        role = role_by_fn.get(fn, '')
        lines.append(f"- {fn} {f'({role})' if role else ''}")
    lines.append('')
if not any_unc:
    lines.append('_All detected orientation functions are classified. Orientation can be marked complete._')

OUT_MD.write_text('\n'.join(lines), encoding='utf-8')
print(f"Wrote {OUT_MD}")
