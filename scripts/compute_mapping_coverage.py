import re, json
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'
OUT = EXPORTS / 'mapping_coverage_report.md'

# Source export files to derive category membership (low-effort heuristics)
# Base category source patterns (refined vertical handled separately)
CATEGORY_SOURCES = {
    'input': [r'input_candidates_.*\.md', r'input_edges_.*\.md', 'action_button_ids.json', r'action_candidates_.*\.md'],
    'crate': [r'crate_system_candidates\.md', r'crate_candidate_edges\.md', r'crate_tokens_binary_scan\.md'],
    'cdstream': [r'cdstream_.*\.md', r'cd_candidates\.md', r'cd_command_wrappers\.md'],
    # 'vertical' removed from generic glob ingestion; we inject refined sets below
    'gravity': [r'gravity_.*\.md'],
    'pickup_drop': [r'pickup_drop_.*\.md'],
    'naming_suggestions': [r'name_suggestions_.*\.csv'],
    'orientation': [r'orientation_candidates\.md'],
}

FUNC_NAME_RE = re.compile(r'\bFUN_[0-9a-fA-F]{8}\b')
TABLE_ROW_RE = re.compile(r'^\|\s*(FUN_[0-9a-fA-F]{8})\s*\|')
CSV_FUNC_RE = re.compile(r'^(FUN_[0-9a-fA-F]{8}),')

# Whitelist of clearly systemic helper function names we can treat as already understood even if not in categories.
KNOWN_RUNTIME = {
    'FUN_0001f5d4',  # allocator thunk
    'FUN_0002d220', 'FUN_0002d1a4',  # emit helpers
}

# Exclusion patterns to reduce vertical over-attribution (e.g., purely flag usage lists)
VERTICAL_EXCLUDE_FILES = {
    'vertical_flag_usage.md',
    'vertical_flag_usage_summary.md',
    'vertical_offset_0x88_usage.md'
}

def match_file(pattern, name):
    if pattern.startswith('r/'):
        return re.fullmatch(pattern[2:], name) is not None
    if pattern.startswith('^') or pattern.endswith('$') or ('[' in pattern and ']' in pattern):
        return re.fullmatch(pattern, name) is not None
    return re.fullmatch(pattern, name) is not None


def collect_functions_from_file(path: Path):
    funcs = set()
    name = path.name
    text = path.read_text(encoding='utf-8', errors='ignore')
    # Table rows
    for line in text.splitlines():
        m = TABLE_ROW_RE.match(line)
        if m:
            funcs.add(m.group(1))
            continue
        m2 = CSV_FUNC_RE.match(line)
        if m2:
            funcs.add(m2.group(1))
            continue
        for m3 in FUNC_NAME_RE.findall(line):
            funcs.add(m3)
    return funcs


def main():
    category_funcs = defaultdict(set)
    # gather category membership (excluding vertical which we treat refined)
    for cat, patterns in CATEGORY_SOURCES.items():
        for pat in patterns:
            regex = re.compile(pat)
            for f in EXPORTS.iterdir():
                if not f.is_file():
                    continue
                if not regex.fullmatch(f.name):
                    continue
                if cat == 'vertical' and f.name in VERTICAL_EXCLUDE_FILES:
                    continue
                try:
                    funcs = collect_functions_from_file(f)
                except Exception:
                    continue
                category_funcs[cat].update(funcs)
    # Inject refined vertical sets if present
    refined_core = EXPORTS / 'vertical_core_functions.md'
    refined_cons = EXPORTS / 'vertical_consumer_functions.md'
    legacy_vertical = set()
    if refined_core.exists():
        category_funcs['vertical_core'].update(collect_functions_from_file(refined_core))
    if refined_cons.exists():
        category_funcs['vertical_consumer'].update(collect_functions_from_file(refined_cons))
    # Also track legacy broad vertical for comparison (but not counted toward main categories)
    for f in EXPORTS.glob('vertical_*.md'):
        if f.name in {'vertical_core_functions.md','vertical_consumer_functions.md'}: continue
        if f.name in VERTICAL_EXCLUDE_FILES: continue
        legacy_vertical.update(collect_functions_from_file(f))

    # Build unified function set from bundles for denominator
    all_funcs = set()
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                if not line.startswith('{'):
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if 'function' not in obj:
                    continue
                name = obj['function'].get('name')
                if name and name.startswith('FUN_'):
                    all_funcs.add(name)
    categorized = set().union(*category_funcs.values())
    uncategorized = all_funcs - categorized - KNOWN_RUNTIME

    # Derive per-function multi-category tags
    func_tags = defaultdict(list)
    for cat, funcs in category_funcs.items():
        for fn in funcs:
            func_tags[fn].append(cat)

    # Compute coverage metrics
    total = len(all_funcs)
    metrics = []
    for cat, funcs in category_funcs.items():
        metrics.append((cat, len(funcs), f"{(len(funcs)/total*100 if total else 0):.2f}%"))
    metrics.sort(key=lambda x: x[1], reverse=True)

    # Identify single-category vs multi-category functions (signal of orchestrators)
    multi = [fn for fn, tags in func_tags.items() if len(tags) > 1]

    with OUT.open('w', encoding='utf-8') as f:
        f.write('# Mapping Coverage Report\n\n')
        f.write(f'Total unique functions (bundled): {total}\n\n')
        f.write('## Category Coverage (Refined)\n\n')
        f.write('| Category | Functions | Percent |\n|----------|----------:|--------:|\n')
        for cat, count, pct in metrics:
            f.write(f'| {cat} | {count} | {pct} |\n')
        if legacy_vertical:
            f.write('\n### Legacy Broad Vertical (for comparison, not counted above)\n\n')
            f.write(f'Legacy vertical unique functions (broad glob): {len(legacy_vertical)}\n\n')
        f.write('\n## Multi-Category Function Candidates (possible orchestrators / hubs)\n\n')
        for fn in sorted(multi):
            f.write(f'- {fn}: {"/".join(sorted(func_tags[fn]))}\n')
        f.write('\n## Uncategorized Functions Sample\n\n')
        for fn in list(sorted(uncategorized))[:200]:  # cap sample
            f.write(f'- {fn}\n')
        f.write('\n(End of report)\n')
    print('Wrote', OUT.name)

if __name__ == '__main__':
    main()
