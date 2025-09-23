#@category Export
# Export functions (+callers/callees/strings/decompilation) to ~/tb-re/exports/bundle_<program>.jsonl
import json, os, re, codecs
from ghidra.app.decompiler import DecompInterface

OUT_DIR = os.path.expanduser("~" + "/tb-re/exports")
try:
    os.makedirs(OUT_DIR)
except Exception:
    pass

prog = currentProgram
listing = prog.getListing()
fm = prog.getFunctionManager()

# sanitize program name for file output
def sanitize(name):
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name

out_name = "bundle_" + sanitize(prog.getName()) + ".jsonl"
OUT = os.path.join(OUT_DIR, out_name)

iface = DecompInterface()
iface.openProgram(prog)

def decompile(func):
    try:
        res = iface.decompileFunction(func, 60, monitor)
        if res and res.getDecompiledFunction():
            return res.getDecompiledFunction().getC()
    except Exception:
        pass
    return None

def strings_used_in_body(func):
    seen = {}
    it = listing.getInstructions(func.getBody(), True)
    while it.hasNext():
        ins = it.next()
        for r in ins.getReferencesFrom():
            to = r.getToAddress()
            dt = listing.getDataAt(to)
            if dt and dt.isDefined():
                try:
                    name = dt.getDataType().getName().lower()
                    if "string" in name:
                        seen[int(to.getOffset())] = str(dt.getValue())
                except Exception:
                    pass
    return [{"offset": off, "text": seen[off]} for off in sorted(seen.keys())]

f = codecs.open(OUT, "w", "utf-8")
try:
    it = fm.getFunctions(True)
    while it.hasNext():
        fn = it.next()
        name = fn.getName()
        ea   = int(fn.getEntryPoint().getOffset())
        size = int(fn.getBody().getNumAddresses())

        # shallow callees from entry xrefs
        callees = []
        for ref in getReferencesFrom(fn.getEntryPoint()):
            if ref.getReferenceType().isCall():
                tf = getFunctionAt(ref.getToAddress())
                if tf:
                    callees.append(tf.getName())

        # callers from xrefs to entry
        callers = []
        for ref in getReferencesTo(fn.getEntryPoint()):
            if ref.getReferenceType().isCall():
                sf = getFunctionContaining(ref.getFromAddress())
                if sf:
                    callers.append(sf.getName())

        rec = {
            "tool": "ghidra",
            "binary": prog.getName(),
            "function": {"name": name, "ea": ea, "size": size},
            "callers": sorted(set(callers)),
            "callees": sorted(set(callees)),
            "strings_used": strings_used_in_body(fn),
            "decompilation": decompile(fn)
        }
    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
finally:
    f.close()
print("Wrote " + OUT)
