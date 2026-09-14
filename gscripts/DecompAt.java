import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        DecompInterface di = new DecompInterface();
        DecompileOptions o = new DecompileOptions();
        di.setOptions(o);
        di.openProgram(currentProgram);
        for (String a : args) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            Function f = getFunctionContaining(addr);
            if (f == null) {
                f = createFunction(addr, null);
            }
            if (f == null) { println("// NO FUNCTION AT " + a); continue; }
            println("// ==================== " + f.getName() + " @ " + f.getEntryPoint());
            DecompileResults r = di.decompileFunction(f, 120, monitor);
            if (r != null && r.decompileCompleted()) {
                println(r.getDecompiledFunction().getC());
            } else {
                println("// DECOMPILE FAILED: " + (r == null ? "null" : r.getErrorMessage()));
            }
        }
        di.dispose();
    }
}
