#!/usr/bin/env python3
"""
Parse the tutorial-like DSL text extracted from BUDDIES.DAT (LESSON, buttonSET, wait_*, crates, etc.).
Input: text file (e.g., exports/buddies_ascii.txt or pasted block)
Output: JSON and Markdown summaries under exports/ for quick cross-ref with input/action mapping.
"""
import re, os, json, sys
from pathlib import Path

ROOT = Path(os.path.expanduser('~'))/ 'tb-re'
OUT = ROOT / 'exports'

# Simple line grammar recognizers
RE_LESSON = re.compile(r'^LESSON\s+(\d+)', re.I)
RE_LABEL = re.compile(r'^:([A-Za-z_][A-Za-z0-9_]*)')
RE_GOTO = re.compile(r'^goto_([A-Za-z_][A-Za-z0-9_]*)', re.I)
RE_IF = re.compile(r'^if(NOT)?_([A-Za-z0-9]+)>([A-Za-z_][A-Za-z0-9_]*)(?:\s+(.*))?$', re.I)
RE_WAIT = re.compile(r'^wait(_?)([A-Za-z0-9]+)(?:\s+(.*))?$', re.I)
RE_BUTTONSET = re.compile(r'^buttonSET\s+(.+)$', re.I)
RE_BUTTONON = re.compile(r'^buttonON\s+(.+)$', re.I)
RE_BUTTONOFF = re.compile(r'^buttonOFF\s+(.+)$', re.I)
RE_TIMER = re.compile(r'^timer\s+(\d+)$', re.I)
RE_USEPAD = re.compile(r'^usePad\s+(.+)$', re.I)
RE_CRATES = re.compile(r'^crates\s+(\d+)$', re.I)
RE_ULAMMO = re.compile(r'^ULammo(?:\s+(\d+))?$', re.I)
RE_CREATESTATIC = re.compile(r'^createStatic\s*(.*)$', re.I)
RE_CREATEBUDDY = re.compile(r'^createBuddy\s*(.*)$', re.I)
RE_CREATEVEHICLE = re.compile(r'^createVehicle\s*(.*)$', re.I)
RE_X = re.compile(r'^x\s+(.+)$', re.I)
RE_ZONES = re.compile(r'^zones\s+(.+)$', re.I)
RE_STATICINV = re.compile(r'^staticInv\s+(\d+)$', re.I)

def tokenize_lines(text: str):
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # strip comments after ';'
        if ';' in line:
            line, _sep, _c = line.partition(';')
            line = line.rstrip()
        if not line:
            continue
        out.append(line)
    return out

def parse_script(lines):
    lessons = []
    cur = None
    for line in lines:
        m = RE_LESSON.match(line)
        if m:
            cur = {'lesson': int(m.group(1)), 'ops': []}
            lessons.append(cur)
            continue
        if cur is None:
            # allow a preamble block before first LESSON
            cur = {'lesson': -1, 'ops': []}
            lessons.append(cur)
        # order matters: labels first
        if RE_LABEL.match(line):
            cur['ops'].append({'op': 'label', 'name': RE_LABEL.match(line).group(1)})
            continue
        if RE_GOTO.match(line):
            cur['ops'].append({'op': 'goto', 'label': RE_GOTO.match(line).group(1)})
            continue
        if RE_IF.match(line):
            m = RE_IF.match(line)
            cur['ops'].append({'op': 'if', 'neg': bool(m.group(1)), 'cond': m.group(2), 'target': m.group(3), 'args': (m.group(4) or '').strip()})
            continue
        if RE_WAIT.match(line):
            m = RE_WAIT.match(line)
            cur['ops'].append({'op': 'wait', 'cond': m.group(2), 'args': (m.group(3) or '').strip()})
            continue
        if RE_BUTTONSET.match(line):
            vals = [v.strip() for v in RE_BUTTONSET.match(line).group(1).split(',') if v.strip()]
            cur['ops'].append({'op': 'buttonSET', 'values': vals})
            continue
        if RE_BUTTONON.match(line):
            vals = [v.strip() for v in RE_BUTTONON.match(line).group(1).split(',') if v.strip()]
            cur['ops'].append({'op': 'buttonON', 'values': vals})
            continue
        if RE_BUTTONOFF.match(line):
            vals = [v.strip() for v in RE_BUTTONOFF.match(line).group(1).split(',') if v.strip()]
            cur['ops'].append({'op': 'buttonOFF', 'values': vals})
            continue
        if RE_TIMER.match(line):
            cur['ops'].append({'op': 'timer', 'value': int(RE_TIMER.match(line).group(1))})
            continue
        if RE_USEPAD.match(line):
            vals = [v.strip() for v in RE_USEPAD.match(line).group(1).split(',') if v.strip()]
            cur['ops'].append({'op': 'usePad', 'pads': vals})
            continue
        if RE_CRATES.match(line):
            cur['ops'].append({'op': 'crates', 'value': int(RE_CRATES.match(line).group(1))})
            continue
        if RE_ULAMMO.match(line):
            val = RE_ULAMMO.match(line).group(1)
            cur['ops'].append({'op': 'ULammo', 'value': (int(val) if val else None)})
            continue
        if RE_ZONES.match(line):
            vals = [v.strip() for v in RE_ZONES.match(line).group(1).split(',') if v.strip()]
            cur['ops'].append({'op': 'zones', 'values': vals})
            continue
        if RE_STATICINV.match(line):
            cur['ops'].append({'op': 'staticInv', 'value': int(RE_STATICINV.match(line).group(1))})
            continue
        if RE_CREATESTATIC.match(line):
            cur['ops'].append({'op': 'createStatic', 'args': RE_CREATESTATIC.match(line).group(1).strip()})
            continue
        if RE_CREATEBUDDY.match(line):
            cur['ops'].append({'op': 'createBuddy', 'args': RE_CREATEBUDDY.match(line).group(1).strip()})
            continue
        if RE_CREATEVEHICLE.match(line):
            cur['ops'].append({'op': 'createVehicle', 'args': RE_CREATEVEHICLE.match(line).group(1).strip()})
            continue
        if RE_X.match(line):
            cur['ops'].append({'op': 'x', 'args': RE_X.match(line).group(1).strip()})
            continue
        # Fallback raw line
        cur['ops'].append({'op': 'raw', 'text': line})
    return lessons

def write_outputs(lessons, base='buddies_script'):
    OUT.mkdir(parents=True, exist_ok=True)
    jpath = OUT / f'{base}.json'
    mpath = OUT / f'{base}.md'
    jpath.write_text(json.dumps(lessons, indent=2), encoding='utf-8')
    with mpath.open('w', encoding='utf-8') as f:
        f.write(f"# Parsed tutorial script ({base})\n\n")
        for blk in lessons:
            f.write(f"## LESSON {blk['lesson']}\n\n")
            for op in blk['ops']:
                if op['op'] in ('buttonSET','buttonON','buttonOFF'):
                    f.write(f"- {op['op']}: {', '.join(op.get('values', []))}\n")
                elif op['op'] in ('timer','crates','staticInv'):
                    f.write(f"- {op['op']}: {op['value']}\n")
                elif op['op'] in ('usePad','zones'):
                    f.write(f"- {op['op']}: {', '.join(op.get('pads') or op.get('values') or [])}\n")
                elif op['op'] in ('label','goto'):
                    key = op.get('name') or op.get('label')
                    f.write(f"- {op['op']}: {key}\n")
                elif op['op'] == 'wait':
                    arg = (' ' + op['args']) if op.get('args') else ''
                    f.write(f"- wait_{op['cond']}{arg}\n")
                elif op['op'] == 'if':
                    neg = 'NOT_' if op['neg'] else ''
                    tail = (' ' + op['args']) if op.get('args') else ''
                    f.write(f"- if_{neg}{op['cond']}>{op['target']}{tail}\n")
                elif op['op'] in ('createStatic','createBuddy','createVehicle','x'):
                    f.write(f"- {op['op']}: {op['args']}\n")
                elif op['op'] == 'ULammo':
                    v = op.get('value')
                    f.write(f"- ULammo{(' '+str(v)) if v is not None else ''}\n")
                else:
                    f.write(f"- {op['op']}\n")
            f.write('\n')
    print('Wrote', jpath)
    print('Wrote', mpath)

def main():
    # Input: a text file with the extracted scripting block; default to exports/buddies_ascii.txt
    in_path = OUT / 'buddies_ascii.txt'
    if len(sys.argv) > 1:
        in_path = Path(sys.argv[1])
    text = in_path.read_text(encoding='utf-8', errors='ignore')
    lessons = parse_script(tokenize_lines(text))
    write_outputs(lessons)

if __name__ == '__main__':
    main()
