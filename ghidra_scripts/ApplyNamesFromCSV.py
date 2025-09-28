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
    created = False
    try:
        fm = currentProgram.getFunctionManager()  # type: ignore
        # Prefer an exact function definition at addr; create one if missing
        func = fm.getFunctionAt(addr)
        if not func:
            try:
                from ghidra.app.script import FlatProgramAPI  # type: ignore
                api = FlatProgramAPI(currentProgram, monitor)  # type: ignore
                # Aggressively prep the site for a function: clear and disassemble
                try:
                    api.clearListing(addr)
                except Exception:
                    pass
                try:
                    api.disassemble(addr)
                except Exception:
                    pass
                # Remove existing labels that might block function creation
                try:
                    st = currentProgram.getSymbolTable()  # type: ignore
                    for s in list(st.getSymbols(addr)):
                        try:
                            st.removeSymbolSpecial(s)
                        except Exception:
                            pass
                except Exception:
                    pass
                # Try create via FlatProgramAPI
                try:
                    api.createFunction(addr, name)
                except Exception as e:
                    if name in {"sys_retain", "sys_release"}:
                        try:
                            print("[ApplyNamesFromCSV] DEBUG createFunction(addr,name) failed for {} @ {}: {}".format(name, addr, e))
                        except Exception:
                            pass
                if not fm.getFunctionAt(addr):
                    try:
                        api.createFunction(addr)
                    except Exception as e:
                        if name in {"sys_retain", "sys_release"}:
                            try:
                                print("[ApplyNamesFromCSV] DEBUG createFunction(addr) failed for {} @ {}: {}".format(name, addr, e))
                            except Exception:
                                pass
                func = fm.getFunctionAt(addr)
                # As a fallback, try FunctionManager.createFunction if available
                if not func:
                    try:
                        from ghidra.program.model.address import AddressSet  # type: ignore
                        body = AddressSet(addr, addr)
                        func = fm.createFunction(name, addr, body, SourceType.USER_DEFINED)
                    except Exception as e:
                        if name in {"sys_retain", "sys_release"}:
                            try:
                                print("[ApplyNamesFromCSV] DEBUG createFunction via FunctionManager failed for {} @ {}: {}".format(name, addr, e))
                            except Exception:
                                pass
                        func = fm.getFunctionAt(addr)
                if not func:
                    try:
                        from ghidra.app.cmd.function import CreateFunctionCmd  # type: ignore
                        cmd = CreateFunctionCmd(addr, None, name, SourceType.USER_DEFINED)
                        if cmd.applyTo(currentProgram, monitor):  # type: ignore
                            func = fm.getFunctionAt(addr)
                        else:
                            if name in {"sys_retain", "sys_release"}:
                                try:
                                    print("[ApplyNamesFromCSV] DEBUG CreateFunctionCmd failed for {} @ {}: {}".format(name, addr, cmd.getStatusMsg()))
                                except Exception:
                                    pass
                    except Exception:
                        func = fm.getFunctionAt(addr)
                created = bool(func)
            except Exception:
                func = fm.getFunctionAt(addr)
        # If we have a function starting exactly at addr, set its name
        if func and func.getEntryPoint() == addr:
            try:
                if func.getName() != name:
                    func.setName(name, SourceType.USER_DEFINED)
            except Exception:
                pass
            print("[ApplyNamesFromCSV] {} @ {} -> function{}".format(
                name, addr, " (new)" if created else ""))
            return True
        if not func:
            try:
                container = fm.getFunctionContaining(addr)
                if container:
                    print("[ApplyNamesFromCSV] INFO function containing {} is {} @ {}".format(
                        addr, container.getName(), container.getEntryPoint()))
            except Exception:
                pass
        # Otherwise, try renaming any existing symbol at this address
        st = currentProgram.getSymbolTable()  # type: ignore
        try:
            syms = list(st.getSymbols(addr))
        except Exception:
            syms = []
        # Prefer a function-class symbol or any symbol that looks auto-named like func_0x...
        target_sym = None
        for s in syms:
            try:
                if str(s.getSymbolType()).lower() == 'function':
                    target_sym = s
                    break
            except Exception:
                pass
        if not target_sym and syms:
            # Fallback: first symbol
            target_sym = syms[0]
        if target_sym and target_sym.getName() != name:
            try:
                target_sym.setName(name, SourceType.USER_DEFINED)
                print("[ApplyNamesFromCSV] {} @ {} -> symbol:{} (renamed)".format(
                    name, addr, target_sym.getSymbolType()))
                return True
            except Exception as e:
                try:
                    print("[ApplyNamesFromCSV] WARN rename failed for {} @ {}: {}".format(name, addr, e))
                except Exception:
                    pass
        # Finally, ensure a primary label exists
        sym = st.getPrimarySymbol(addr)
        if not sym:
            st.createLabel(addr, name, None, SourceType.USER_DEFINED)
            print("[ApplyNamesFromCSV] {} @ {} -> label (new)".format(name, addr))
            return True
        elif sym.getName() != name:
            try:
                sym.setName(name, SourceType.USER_DEFINED)
                print("[ApplyNamesFromCSV] {} @ {} -> label (renamed-primary)".format(name, addr))
                return True
            except Exception as e:
                try:
                    print("[ApplyNamesFromCSV] WARN primary label rename failed for {} @ {}: {}".format(name, addr, e))
                except Exception:
                    pass
    except Exception as e:
        try:
            print("[ApplyNamesFromCSV] ERROR applying {} @ {}: {}".format(name, addr, e))
        except Exception:
            pass
        return False
    try:
        st = currentProgram.getSymbolTable()  # type: ignore
        syms = list(st.getSymbols(addr))
        if syms:
            details = ["{}:{}".format(s.getName(), s.getSymbolType()) for s in syms]
            print("[ApplyNamesFromCSV] INFO existing symbols at {} -> {}".format(addr, ", ".join(details)))
        else:
            print("[ApplyNamesFromCSV] INFO no symbols at {} despite skip".format(addr))
    except Exception:
        pass
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
            else:
                try:
                    print("[ApplyNamesFromCSV] SKIP {} @ {} (no symbol/function applied)".format(name, addr))
                except Exception:
                    pass
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
