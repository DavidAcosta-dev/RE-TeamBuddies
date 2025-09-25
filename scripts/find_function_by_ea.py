#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
import sys

def main():
    if len(sys.argv)<2:
        print('Usage: find_function_by_ea.py <hexEA like 0x95d6c>')
        sys.exit(1)
    target = int(sys.argv[1],16) if sys.argv[1].startswith('0x') else int(sys.argv[1])
    hits=0
    for p in Path('exports').glob('bundle_*.jsonl'):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try:
                    obj=json.loads(line)
                except json.JSONDecodeError:
                    continue
                fn=obj.get('function')
                if not fn: continue
                ea=fn.get('ea')
                if ea==target:
                    name=fn.get('name')
                    print('File:',p)
                    print('Name:',name,'EA:',hex(ea))
                    dec=obj.get('decompilation') or ''
                    print('----- decomp start -----')
                    print(dec)
                    print('----- decomp end -----')
                    hits+=1
    print('Total hits:',hits)

if __name__=='__main__':
    main()
