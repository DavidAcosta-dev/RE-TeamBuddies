#@category Export
# Reads exports/suspects_bookmarks.json and adds bookmarks to the current program
# Enhancements:
# - Supports optional per-item fields: category, comment, new_name
#   * category => bookmark type becomes "suspect:<category>" (e.g., suspect:physics)
#   * comment  => appended to the bookmark comment
#   * new_name => if provided, attempts to rename the function at or containing the EA
import json, os
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import SourceType

OUT_DIR = os.path.expanduser("~" + "/tb-re/exports")
INP = os.path.join(OUT_DIR, "suspects_bookmarks.json")

prog = currentProgram
if not os.path.exists(INP):
    print("No suspects_bookmarks.json found at " + INP)
else:
    try:
        with open(INP, "r") as fh:
            data = json.load(fh)
    except Exception as e:
        print("Failed to read JSON: " + str(e))
        data = {}

    key = prog.getName()
    items = data.get(key, [])
    if not items:
        print("No bookmarks for program: " + key)
    else:
        listing = prog.getListing()
        addr_factory = prog.getAddressFactory()
        mgr = prog.getBookmarkManager()
        count = 0
        for it in items:
            ea = it.get("ea")
            nm = it.get("name") or "suspect"
            if ea is None:
                continue
            try:
                addr = addr_factory.getDefaultAddressSpace().getAddress(ea)
                # Bookmark category and type
                category = "RE"
                btype = "suspect"
                it_cat = it.get("category") or it.get("topic")
                if it_cat:
                    btype = "suspect:%s" % str(it_cat)

                # Comment composition
                comment = nm
                extra = []
                if it.get("comment"):
                    extra.append(str(it.get("comment")))
                if it.get("score") is not None:
                    extra.append("score=" + str(it.get("score")))
                if it.get("tags"):
                    try:
                        extra.append("tags=" + ",".join([str(t) for t in it.get("tags")]))
                    except Exception:
                        pass
                if extra:
                    comment = comment + " | " + " ".join(extra)

                mgr.setBookmark(addr, category, btype, comment)
                count += 1

                # Optional rename if provided
                new_name = it.get("new_name")
                if new_name:
                    try:
                        func = listing.getFunctionAt(addr)
                        if func is None:
                            func = listing.getFunctionContaining(addr)
                        if func is not None:
                            func.setName(str(new_name), SourceType.USER_DEFINED)
                    except Exception:
                        pass
            except Exception:
                pass

        print("Bookmarked %d suspects for %s" % (count, key))
