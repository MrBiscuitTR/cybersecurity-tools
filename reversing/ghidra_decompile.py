# Ghidra headless post-script (runs inside Ghidra's Jython 2.7 — NOT CPython).
#
# Driven by reversing/decompile.py via analyzeHeadless. It emits marker-delimited
# output on stdout that the wrapper parses. Modes (first script arg):
#   list            -> imports, function table, and defined strings (a small map)
#   func <target>   -> decompiled pseudo-C for functions whose name/address matches
#   all             -> decompiled pseudo-C for every function
#
# Markers: @@@BEGIN@@@ ... @@@END@@@ wrap everything; @@@IMPORTS@@@ / @@@FUNCTIONS@@@
# / @@@STRINGS@@@ head list sections; @@@FUNC@@@ <name> @ <addr> precedes each
# decompiled function body.
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def emit(s):
    print(s)


args = getScriptArgs()
mode = args[0] if len(args) > 0 else "list"
target = args[1] if len(args) > 1 else ""

prog = currentProgram
fm = prog.getFunctionManager()
monitor = ConsoleTaskMonitor()

emit("@@@BEGIN@@@ mode=%s program=%s" % (mode, prog.getName()))

if mode == "list":
    emit("@@@IMPORTS@@@")
    try:
        for sym in prog.getSymbolTable().getExternalSymbols():
            emit("  %s" % sym.getName())
    except Exception as e:
        emit("  (imports error: %s)" % e)

    emit("@@@FUNCTIONS@@@")
    for f in fm.getFunctions(True):
        tag = " [external]" if f.isExternal() else ""
        emit("  %s @ %s size=%d%s" % (f.getName(), f.getEntryPoint(),
                                      f.getBody().getNumAddresses(), tag))

    emit("@@@STRINGS@@@")
    count = 0
    for d in prog.getListing().getDefinedData(True):
        try:
            if d.hasStringValue():
                emit("  %s: %s" % (d.getAddress(), d.getValue()))
                count += 1
                if count >= 500:
                    break
        except Exception:
            pass
else:
    decomp = DecompInterface()
    decomp.openProgram(prog)
    for f in fm.getFunctions(True):
        if f.isExternal():
            continue
        name = f.getName()
        if mode == "func" and target and (target not in name
                                          and target != str(f.getEntryPoint())):
            continue
        emit("@@@FUNC@@@ %s @ %s" % (name, f.getEntryPoint()))
        try:
            res = decomp.decompileFunction(f, 60, monitor)
            if res and res.decompileCompleted():
                emit(res.getDecompiledFunction().getC())
            else:
                emit("// decompilation failed: %s"
                     % (res.getErrorMessage() if res else "no result"))
        except Exception as e:
            emit("// decompile exception: %s" % e)
    decomp.dispose()

emit("@@@END@@@")
