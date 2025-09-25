#!/usr/bin/env python3
"""
run_vertical_discovery_batch.py

Orchestrates a batch pass focused on vertical (gravity) discovery using the
enhanced secondary array index & helper correlation scripts.

Sequence:
  1. secondary_index_neighborhood.py
  2. scan_shift_secondary.py (if present)
  3. helper_caller_correlation.py
  4. Summarize key top-N results into vertical_batch_summary.md
"""
from __future__ import annotations
import subprocess,shutil,sys
from pathlib import Path

SCRIPTS=[
    'secondary_index_neighborhood.py',
    'scan_shift_secondary.py',
    'helper_caller_correlation.py'
]

def run_script(s):
    if not Path('scripts',s).exists():
        print('SKIP missing',s)
        return
    print('RUN',s)
    subprocess.run([sys.executable,str(Path('scripts',s))],check=False)

def extract_table(md_path,limit=5):
    p=Path(md_path)
    if not p.exists():
        return f'File {md_path} missing.'
    lines=p.read_text(encoding='utf-8',errors='ignore').splitlines()
    out=[]; count=0; header_seen=False
    for line in lines:
        if line.startswith('|'):
            if not header_seen:
                header_seen=True
                out.append(line)
                continue
            if line.startswith('|-'): # separator maybe
                out.append(line)
                continue
            if count<limit:
                out.append(line)
                count+=1
    return '\n'.join(out) if out else '(no table)'

def main():
    for s in SCRIPTS:
        run_script(s)
    summary=Path('vertical_batch_summary.md')
    with summary.open('w',encoding='utf-8') as f:
        f.write('# Vertical Discovery Batch Summary\n\n')
        f.write('## Secondary Index Neighborhood (Top)\n')
        f.write(extract_table('secondary_index_neighborhood.md'))
        f.write('\n\n## Shift Secondary Candidates (existing)\n')
        if Path('shift_secondary_candidates.md').exists():
            f.write(extract_table('shift_secondary_candidates.md'))
        else:
            f.write('(shift_secondary_candidates.md not present yet)')
        f.write('\n\n## Helper Caller Correlation (Top)\n')
        f.write(extract_table('helper_caller_correlation.md'))
    print('Wrote',summary)

if __name__=='__main__':
    main()
