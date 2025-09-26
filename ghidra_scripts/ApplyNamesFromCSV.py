#@category TB-Re
# Apply function/label names from exports/rename_review.csv for the current program.
# Only rows with apply=1 are applied; others are ignored.

import csv
import os
import codecs

try:
    from ghidra.program.model.symbol import SourceType  # type: ignore
except Exception:  # pragma: no cover
    class SourceType:  # type: ignore
        USER_DEFINED = 0

try:
    currentProgram  # type: ignore
except Exception:
    currentProgram = None  # type: ignore


def popup(msg):  # type: ignore
    try:
        print(msg)
    except Exception:
        pass


def getSourceFile():  # type: ignore
    try:
        return __name__ and None
    except Exception:
        return None


DEFAULT_REL_PATH = os.path.join("..", "exports", "rename_review.csv")


def parse_addr_hex(s):
    try:
        s = (s or "").strip()
        if s.startswith("0x") or s.startswith("0X"):
            s = s[2:]
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(int(s, 16))  # type: ignore
    except Exception:
        return None


def apply_name(addr, name):
    if not addr or not name:
        return False
    try:
        fm = currentProgram.getFunctionManager()  # type: ignore
        func = fm.getFunctionContaining(addr)
        if func and func.getEntryPoint() == addr:
            func.setName(name, SourceType.USER_DEFINED)
            return True
        st = currentProgram.getSymbolTable()  # type: ignore
        sym = st.getPrimarySymbol(addr)
        if sym and sym.getName() != name:
            sym.setName(name, SourceType.USER_DEFINED)
            return True
        if not sym:
            st.createLabel(addr, name, None, SourceType.USER_DEFINED)
            return True
    except Exception:
        return False
    return False


def apply_from_csv(csv_path):
    prog = currentProgram.getName()  # type: ignore
    applied = 0
    with codecs.open(csv_path, "r", "utf-8") as fh:
        rdr = csv.DictReader(fh)
        for row in rdr:
            if row.get("apply") != "1":
                continue
            bin_name = (row.get("binary") or "").strip()
            if not (prog and bin_name and prog.lower().endswith(bin_name.lower())):
                continue
            addr = parse_addr_hex(row.get("ea_hex"))
            # Prefer curated placeholder in new_name (e.g., suspect_*, phys_*) over heuristic suggested_name
            name = (row.get("new_name") or row.get("suggested_name") or "").strip()
            if apply_name(addr, name):
                applied += 1
    print("Applied {} names from {}".format(applied, csv_path))


def run():
    if currentProgram is None:
        print("[ApplyNamesFromCSV] Skipping: not running inside Ghidra (currentProgram is None)")
        return
    # Allow explicit path via script args: -postScript ApplyNamesFromCSV.py <csvPath>
    path = None
    try:
        args = getScriptArgs()  # type: ignore
        if args and len(args) > 0 and args[0]:
            a0 = str(args[0])
            path = a0 if os.path.isabs(a0) else os.path.abspath(a0)
    except Exception:
        pass
    if not path:
        base = None
        try:
            sf = getSourceFile()
            base = os.path.dirname(sf.getAbsolutePath()) if sf else None
        except Exception:
            base = None
        if not base:
            try:
                base = os.path.dirname(__file__)  # type: ignore
            except Exception:
                base = os.getcwd()
        path = os.path.abspath(os.path.join(base, DEFAULT_REL_PATH))
    if not os.path.exists(path):
        popup("CSV not found: {}".format(path))
        return
    apply_from_csv(path)


run()
