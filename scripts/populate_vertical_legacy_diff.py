import re, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'
OUT = EXPORTS / 'vertical_legacy_consumer_diff.md'

FUNC_RE = re.compile(r'\bFUN_[0-9a-fA-F]{8}\b')

def collect(path: Path):
    funcs=set()
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        for m in FUNC_RE.findall(line):
            funcs.add(m)
    return funcs

def main():
    refined_core = collect(EXPORTS / 'vertical_core_functions.md') if (EXPORTS / 'vertical_core_functions.md').exists() else set()
    refined_cons = collect(EXPORTS / 'vertical_consumer_functions.md') if (EXPORTS / 'vertical_consumer_functions.md').exists() else set()
    refined = refined_core | refined_cons
    legacy = set()
    for f in EXPORTS.glob('vertical_*.md'):
        if f.name in {'vertical_core_functions.md','vertical_consumer_functions.md','vertical_legacy_consumer_diff.md'}:
            continue
        # broad legacy capture
        legacy |= collect(f)
    diff = sorted(legacy - refined)
    with OUT.open('w', encoding='utf-8') as fw:
        fw.write('# Vertical Legacy vs Refined Diff\n\n')
        fw.write(f'Total legacy (broad) functions: {len(legacy)}\n\n')
        fw.write(f'Refined vertical functions (core+consumer): {len(refined)}\n\n')
        fw.write(f'Legacy-only (not in refined sets): {len(diff)}\n\n')
        fw.write('## Legacy-Only Function List\n\n')
        for fn in diff:
            fw.write(f'- {fn}\n')
        fw.write('\n(End of diff)\n')
    print('Wrote vertical_legacy_consumer_diff.md with', len(diff), 'legacy-only functions')

if __name__ == '__main__':
    main()
