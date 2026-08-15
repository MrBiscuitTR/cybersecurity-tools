// Ghidra headless post-script (Java GhidraScript — no PyGhidra/Jython needed).
//
// Driven by reversing/decompile.py via analyzeHeadless. Emits marker-delimited
// output on System.out (clean, no Ghidra log prefixes) that the wrapper parses.
// Modes (first script arg): list | func <target> | all.
//
// The filename MUST match the class name (Ghidra requirement): ghidra_decompile.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.ConsoleTaskMonitor;

public class ghidra_decompile extends GhidraScript {

    private void out(String s) {
        System.out.println(s);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "list";
        String target = args.length > 1 ? args[1] : "";
        FunctionManager fm = currentProgram.getFunctionManager();

        out("@@@BEGIN@@@ mode=" + mode + " program=" + currentProgram.getName());

        if (mode.equals("list")) {
            out("@@@IMPORTS@@@");
            for (Symbol s : currentProgram.getSymbolTable().getExternalSymbols()) {
                out("  " + s.getName());
            }
            out("@@@FUNCTIONS@@@");
            for (Function f : fm.getFunctions(true)) {
                out("  " + f.getName() + " @ " + f.getEntryPoint()
                    + " size=" + f.getBody().getNumAddresses()
                    + (f.isExternal() ? " [external]" : ""));
            }
            out("@@@STRINGS@@@");
            int cnt = 0;
            DataIterator di = currentProgram.getListing().getDefinedData(true);
            while (di.hasNext()) {
                Data d = di.next();
                if (d.hasStringValue()) {
                    out("  " + d.getAddress() + ": " + d.getValue());
                    if (++cnt >= 500) break;
                }
            }
        } else {
            // For func mode: if an EXACT name match exists, use only exact matches
            // (so "main" doesn't also grab "__libc_start_main"); else fall back to
            // substring so "crypt" can match "encrypt_buf", etc.
            boolean exact = false;
            if (mode.equals("func") && !target.isEmpty()) {
                for (Function f : fm.getFunctions(true)) {
                    if (f.getName().equals(target)) { exact = true; break; }
                }
            }
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
            for (Function f : fm.getFunctions(true)) {
                if (f.isExternal()) {
                    continue;
                }
                String name = f.getName();
                if (mode.equals("func") && !target.isEmpty()) {
                    boolean match = exact ? name.equals(target) : name.contains(target);
                    if (!match && !f.getEntryPoint().toString().equals(target)) {
                        continue;
                    }
                }
                out("@@@FUNC@@@ " + name + " @ " + f.getEntryPoint());
                DecompileResults res = decomp.decompileFunction(f, 60, monitor);
                if (res != null && res.decompileCompleted()) {
                    System.out.print(res.getDecompiledFunction().getC());
                } else {
                    out("// decompilation failed: "
                        + (res != null ? res.getErrorMessage() : "no result"));
                }
            }
            decomp.dispose();
        }
        out("@@@END@@@");
    }
}
