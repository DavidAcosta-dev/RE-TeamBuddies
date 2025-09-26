#@category TB-Re
# Apply function names from exports/suspects_bookmarks.json into the current program.
# Only entries matching the current binary name are applied. If a function exists at the
# address, its name is set; otherwise a user label is created at that address.

import json
import os
import codecs

# Ghidra imports (tolerate running outside Ghidra)
try:  # type: ignore
    from ghidra.program.model.symbol import SourceType  # type: ignore
except Exception:  # pragma: no cover - non-Ghidra stub
    class SourceType:  # type: ignore
        USER_DEFINED = 0

try:
    currentProgram  # type: ignore  # noqa: F401
except Exception:  # pragma: no cover
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


def parse_addr_int(ea_int):
    try:
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(int(ea_int))  # type: ignore
    except Exception:
        return None


def set_function_or_label_name(addr, name):
    if not addr or not name:
        return False
    try:
        # Prefer function rename if a function exists at this address
        func_mgr = currentProgram.getFunctionManager()  # type: ignore
        func = func_mgr.getFunctionContaining(addr)
        if func and func.getEntryPoint() == addr:
            try:
                func.setName(name, SourceType.USER_DEFINED)
                return True
            except Exception:
                pass
        # Else, create/update a label
        symtab = currentProgram.getSymbolTable()  # type: ignore
        sym = symtab.getPrimarySymbol(addr)
        if sym and sym.getName() != name:
            try:
                sym.setName(name, SourceType.USER_DEFINED)
                return True
            except Exception:
                pass
        if not sym:
            try:
                symtab.createLabel(addr, name, None, SourceType.USER_DEFINED)
                return True
            except Exception:
                pass
    except Exception:
        return False
    return False


DEFAULT_REL_PATH = os.path.join("..", "exports", "suspects_bookmarks.json")


def apply_names(bookmarks_path):
    prog_name = currentProgram.getName()  # type: ignore
    with codecs.open(bookmarks_path, "r", "utf-8") as fh:
        data = json.load(fh)

    applied = 0
    dup_guard = set()
    # bookmarks structure: { "GAME.BIN": [ {"ea": int, "new_name": str, ...}, ...], ... }
    for bin_name, items in (data or {}).items():
        if not (bin_name and prog_name and prog_name.lower().endswith(bin_name.lower())):
            continue
        for it in (items or []):
            name = (it.get("new_name") or "").strip()
            if not name:
                continue
            ea = it.get("ea")
            key = (ea, name)
            if key in dup_guard:
                continue
            dup_guard.add(key)
            addr = parse_addr_int(ea)
            if addr is None:
                continue
            if set_function_or_label_name(addr, name):
                applied += 1
    print("Applied {} names from {}".format(applied, bookmarks_path))


def run():
    # Outside Ghidra, do nothing
    if currentProgram is None:
        print("[ApplyNamesFromBookmarks] Skipping: not running inside Ghidra (currentProgram is None)")
        return
    # Allow path via script args: -postScript ApplyNamesFromBookmarks.py <jsonPath>
    bookmarks_path = None
    try:
        args = getScriptArgs()  # type: ignore
        if args and len(args) > 0 and args[0]:
            a0 = str(args[0])
            bookmarks_path = a0 if os.path.isabs(a0) else os.path.abspath(a0)
    except Exception:
        pass
    if not bookmarks_path:
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
        bookmarks_path = os.path.abspath(os.path.join(base, DEFAULT_REL_PATH))
    if not os.path.exists(bookmarks_path):
        popup("Bookmarks JSON not found: {}".format(bookmarks_path))
        return
    apply_names(bookmarks_path)


run()
