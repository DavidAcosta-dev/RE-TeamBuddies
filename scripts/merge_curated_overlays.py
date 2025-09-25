#!/usr/bin/env python3
"""
Merge curated_overlays.json into suspects_bookmarks.json, preferring curated names.
Precedence: curated > existing suspect_ > stub_ret0/auto
"""
import os, json
from pathlib import Path

ROOT = Path(os.path.expanduser('~'))/ 'tb-re'
EX = ROOT / 'exports'
SUS = EX / 'suspects_bookmarks.json'
CUR = EX / 'curated_overlays.json'

def load(p):
    try:
        return json.loads(Path(p).read_text(encoding='utf-8'))
    except Exception:
        return {}

def main():
    sus = load(SUS)
    cur = load(CUR)
    if not cur:
        print('No curated_overlays.json; nothing to do')
        return
    # ensure structure
    if not isinstance(sus, dict):
        sus = {}
    # merge per-binary
    for b, entries in cur.items():
        lst = sus.setdefault(b, [])
        # build index by (ea or name)
        by_key = {}
        by_name = {}
        for it in lst:
            k = (it.get('ea'), it.get('name'))
            by_key[k] = it
            nm = it.get('name')
            if nm:
                by_name[nm] = it
        for it in entries or []:
            k = (it.get('ea'), it.get('name'))
            if k in by_key:
                # update fields; ensure new_name from curated wins
                tgt = by_key[k]
                if it.get('new_name'):
                    tgt['new_name'] = it['new_name']
                for fld in ('category','comment','tags'):
                    if it.get(fld):
                        tgt[fld] = it[fld]
            elif it.get('name') in by_name:
                # replace existing entry with same original name
                old = by_name[it['name']]
                try:
                    idx = lst.index(old)
                    lst[idx] = it
                except ValueError:
                    lst.append(it)
            else:
                lst.append(it)
    # write back
    tmp = SUS.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(sus, indent=2), encoding='utf-8')
    tmp.replace(SUS)
    print('Merged curated overlays into', SUS)

if __name__ == '__main__':
    main()
