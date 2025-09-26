#!/usr/bin/env python3
from __future__ import annotations
"""
Crate Interaction Completion Report

Consolidates known crate/pickup/throw artifacts and estimates completion.
Outputs:
  exports/crate_completion_report.md
  exports/crate_completion_report.json
"""
import csv, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
NOTES = ROOT / 'notes'
OUT_MD = EXPORTS / 'crate_completion_report.md'
OUT_JSON = EXPORTS / 'crate_completion_report.json'

def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ''

def count_lines(path: Path, predicate=None) -> int:
    txt = read_text(path)
    if not txt:
        return 0
    if predicate is None:
        return sum(1 for _ in txt.splitlines() if _)
    return sum(1 for ln in txt.splitlines() if predicate(ln))

artifacts = {
    'pairs_md': EXPORTS / 'pickup_drop_pairs.md',
    'pairs_csv': EXPORTS / 'pickup_drop_pairs.csv',
    'cands_md': EXPORTS / 'pickup_drop_candidates.md',
    'cands_csv': EXPORTS / 'pickup_drop_candidates.csv',
    'crate_cands_md': EXPORTS / 'crate_system_candidates.md',
    'crate_cands_csv': EXPORTS / 'crate_system_candidates.csv',
    'crate_edges_md': EXPORTS / 'crate_candidate_edges.md',
    'crate_tokens_md': EXPORTS / 'crate_tokens_binary_scan.md',
    'crate_string_hits': EXPORTS / 'crate_string_hits.md',
    'indirect_slots': EXPORTS / 'indirect_slots.md',
    'neg_mut': EXPORTS / 'cratepath_neg_mutations.md',
    'state_machine': NOTES / 'crate_state_machine.md',
    'crate_signature_csv': ROOT / 'crate_signature_candidates.csv',
    'crate_signature_report': EXPORTS / 'crate_signature_report.md',
    'crate_signature_followup': NOTES / 'crate_signature_followup.md',
}

stats = {}
stats['pairs'] = count_lines(artifacts['pairs_md'], lambda l: l.strip().startswith('|'))
stats['pairs_csv_rows'] = 0
if artifacts['pairs_csv'].exists():
    with artifacts['pairs_csv'].open('r', encoding='utf-8', errors='ignore') as f:
        try:
            rd = csv.reader(f)
            stats['pairs_csv_rows'] = sum(1 for _ in rd)
        except Exception:
            pass
stats['cand_rows'] = count_lines(artifacts['cands_md'], lambda l: l.strip().startswith('|'))
stats['crate_cands'] = count_lines(artifacts['crate_cands_md'], lambda l: l.strip().startswith('|'))
stats['crate_edges'] = count_lines(artifacts['crate_edges_md'], lambda l: l.strip().startswith('|'))
stats['tokens_hits'] = count_lines(artifacts['crate_tokens_md'])
stats['string_hits'] = count_lines(artifacts['crate_string_hits'])
stats['indirect_slots'] = count_lines(artifacts['indirect_slots'])
stats['neg_mut'] = count_lines(artifacts['neg_mut'])
stats['has_state_machine'] = 1 if artifacts['state_machine'].exists() else 0
stats['crate_signature_rows'] = 0
if artifacts['crate_signature_csv'].exists():
    with artifacts['crate_signature_csv'].open('r', encoding='utf-8', errors='ignore') as f:
        try:
            rd = csv.reader(f)
            stats['crate_signature_rows'] = max(sum(1 for _ in rd) - 1, 0)
        except Exception:
            pass
stats['crate_signature_report_lines'] = count_lines(artifacts['crate_signature_report'])
stats['crate_signature_followup_lines'] = count_lines(artifacts['crate_signature_followup'])

# Heuristic completion scoring
score_items = []
def add(item, present, weight, note):
    score_items.append({'item': item, 'present': bool(present), 'weight': weight, 'note': note})

add('State machine documented', stats['has_state_machine'], 20, 'notes/crate_state_machine.md present')
add('Pickup/Drop pairs identified', max(stats['pairs'], stats['pairs_csv_rows']) > 2, 20, 'pickup_drop_pairs.* contains rows')
add('Crate system candidates enumerated', stats['crate_cands'] > 5, 10, 'crate_system_candidates.* present with rows')
add('Crate candidate edges', stats['crate_edges'] > 2, 10, 'crate_candidate_edges.md table populated')
add('Indirect slots analysis', stats['indirect_slots'] > 0, 10, 'indirect_slots.md has content')
add('Negative mutation scan', stats['neg_mut'] > 0, 10, 'cratepath_neg_mutations.md has content')
add('Pickup/Drop candidates', stats['cand_rows'] > 5, 5, 'pickup_drop_candidates.* present with rows')
add('Crate tokens scan', stats['tokens_hits'] > 0, 5, 'crate_tokens_binary_scan.md present')
add('Crate strings scan', stats['string_hits'] > 0, 5, 'crate_string_hits.md present')
add('Signature candidates triaged', stats['crate_signature_report_lines'] > 5, 10, 'crate_signature_report.md present with data')
add('Follow-up note drafted', stats['crate_signature_followup_lines'] > 10, 5, 'notes/crate_signature_followup.md generated')
# Timing constants: look for typical ms/frame constants in pairs_md as proxy
timing_hits = 1 if re.search(r'\b(0x[0-9a-f]{2,4}|\d{2,4})\b', read_text(artifacts['pairs_md'])) else 0
add('Timing constants captured', timing_hits, 5, 'placeholder until a dedicated timing extractor is added')

total_weight = sum(i['weight'] for i in score_items)
completed_weight = sum(i['weight'] for i in score_items if i['present'])
completion = int(round(100 * completed_weight / total_weight)) if total_weight else 0

gaps = [i for i in score_items if not i['present']]

payload = {
    'stats': stats,
    'score_items': score_items,
    'completion_pct': completion,
    'completed_weight': completed_weight,
    'total_weight': total_weight,
    'next_steps': [
        'Extract and normalize timing constants (pickup wind-up, throw cooldown, carry decay)',
        'Link input bits to pickup/drop transitions across all relevant hubs',
        'Enumerate edge cases: interrupted pickup, damage drop, multi-carry conflicts',
        'Confirm resource refs (animations/sounds) and callback ordering guarantees'
    ]
}
OUT_JSON.write_text(json.dumps(payload, indent=2), encoding='utf-8')

lines = []
lines.append('# Crate Interaction Completion Report')
lines.append('')
lines.append(f"Heuristic completion: {completion}% ({completed_weight}/{total_weight} weight)")
lines.append('')
lines.append('## Artifact Summary')
lines.append('')
for k, v in stats.items():
    lines.append(f"- {k}: {v}")
lines.append('')
lines.append('## Checklist')
lines.append('')
for it in score_items:
    lines.append(f"- [{'x' if it['present'] else ' '}] {it['item']}  — {it['note']}")
lines.append('')
lines.append('## Gaps')
lines.append('')
if not gaps:
    lines.append('None — looks complete. Consider adding tests and final naming pass.')
else:
    for it in gaps:
        lines.append(f"- {it['item']}")
lines.append('')
lines.append('## Next Steps to 100%')
lines.append('')
for step in payload['next_steps']:
    lines.append(f"1. {step}")

OUT_MD.write_text('\n'.join(lines), encoding='utf-8')
print(f"Wrote {OUT_MD}")
