#@category TB-Re
"""
EnsureRetainReleaseFunctions.py

Prepares the GAME.BIN program so that the retain/release helpers live in
standalone functions. This splits the container function at 0x74930 and creates
functions at 0x74950 (sys_retain) and 0x74970 (sys_release) so downstream naming
passes can stick.
"""

from ghidra.program.model.symbol import SourceType  # type: ignore

try:
    currentProgram  # type: ignore
except NameError:  # pragma: no cover
    currentProgram = None  # type: ignore

if currentProgram is None:
    print("[EnsureRetainReleaseFunctions] Skipping: not running inside Ghidra")
    exit()

program_name = (currentProgram.getName() or "").lower()
if not program_name.endswith("game.bin"):
    print("[EnsureRetainReleaseFunctions] Program {} not targeted; skipping".format(currentProgram.getName()))
    exit()

from ghidra.app.cmd.function import DeleteFunctionCmd, CreateFunctionCmd  # type: ignore
from ghidra.program.model.address import AddressSet  # type: ignore

try:
    monitor  # type: ignore
except NameError:  # pragma: no cover
    from ghidra.util.task import ConsoleTaskMonitor  # type: ignore
    monitor = ConsoleTaskMonitor()

fm = currentProgram.getFunctionManager()  # type: ignore
addr_factory = currentProgram.getAddressFactory()  # type: ignore
space = addr_factory.getDefaultAddressSpace()

TARGETS = [
    (0x00074950, "sys_retain"),
    (0x00074970, "sys_release"),
]

containers = {}

for offset, _ in TARGETS:
    addr = space.getAddress(offset)
    func = fm.getFunctionAt(addr)
    if func and func.getEntryPoint() == addr:
        continue
    container = fm.getFunctionContaining(addr)
    if container and container.getEntryPoint() != addr:
        entry = container.getEntryPoint()
        if entry not in containers:
            containers[entry] = {
                "name": container.getName(),
                "namespace": container.getParentNamespace(),
            }

for entry, info in containers.items():
    cmd = DeleteFunctionCmd(entry)
    if cmd.applyTo(currentProgram, monitor):
        print("[EnsureRetainReleaseFunctions] Removed container {} @ {}".format(info["name"], entry))
    else:
        print("[EnsureRetainReleaseFunctions] WARN failed to delete {} @ {}: {}".format(info["name"], entry, cmd.getStatusMsg()))

created = []

def ensure_function(offset, name=None, namespace=None):
    if hasattr(offset, "getOffset"):
        address_obj = offset
    else:
        address_obj = space.getAddress(int(offset))
    addr = address_obj
    func = fm.getFunctionAt(addr)
    if func and func.getEntryPoint() == addr:
        if name and func.getName() != name:
            try:
                func.setName(name, SourceType.USER_DEFINED)
                print("[EnsureRetainReleaseFunctions] Renamed existing function @ {} -> {}".format(addr, name))
            except Exception as exc:  # pragma: no cover
                print("[EnsureRetainReleaseFunctions] WARN rename failed for {} @ {}: {}".format(name, addr, exc))
        return fm.getFunctionAt(addr)

    cmd = CreateFunctionCmd(addr)
    if cmd.applyTo(currentProgram, monitor):
        func = fm.getFunctionAt(addr)
        if func and name and func.getName() != name:
            try:
                func.setName(name, SourceType.USER_DEFINED)
            except Exception as exc:  # pragma: no cover
                print("[EnsureRetainReleaseFunctions] WARN post-create rename failed for {} @ {}: {}".format(name, addr, exc))
        if func and namespace and func.getParentNamespace() != namespace:
            try:
                func.setParentNamespace(namespace, SourceType.USER_DEFINED)
            except Exception:
                pass
        created.append((addr, name or (func and func.getName()) or "<unnamed>"))
        return func

    # fallback: use FunctionManager.createFunction with minimal body
    try:
        body = AddressSet(addr, addr)
        fallback_name = name or "FUN_{:08X}".format(int(addr.getOffset()) & 0xFFFFFFFF)
        func = fm.createFunction(fallback_name, addr, body, SourceType.USER_DEFINED)
        if func and name and func.getName() != name:
            func.setName(name, SourceType.USER_DEFINED)
        return func
    except Exception as exc:  # pragma: no cover
        print("[EnsureRetainReleaseFunctions] ERROR failed to create function @ {}: {}".format(addr, exc))
        return None

for offset, name in TARGETS:
    ensure_function(offset, name=name)

for entry, info in containers.items():
    ensure_function(int(entry.getOffset()) & 0xFFFFFFFF, name=info["name"], namespace=info["namespace"])

if created:
    for addr, nm in created:
        print("[EnsureRetainReleaseFunctions] Created {} @ {}".format(nm, addr))
else:
    print("[EnsureRetainReleaseFunctions] No new functions created")
