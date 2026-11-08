// Decompiled read-only UEFI LinuxLoader firmware. Do not flash or alter device.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class Honor70ABLDecompile extends GhidraScript {
    private static final long[] TARGETS = {
       0x27850L,0x25B88L,0x25C04L,0x25C0CL,0x27DB4L,
       0x27A74L,0x27A5CL,0x27A8CL,0x23FD0L,0x24154L,
       0x433A8L,0x433D8L,0x433E8L,0x13008L,
       0x12CF8L,0x12E90L,0x136A4L,0x1BF74L,
       0x25130L,0x25144L
    };
    @Override
    public void run() throws Exception {
        File reportDir = new File(System.getenv("GITHUB_WORKSPACE") + "/report");
        reportDir.mkdirs();
        File output = new File(reportDir, "GHIDRA_ABL_DECOMPILATION.txt");
        try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(output), "UTF-8"))) {
            pw.println("HONOR70 LinuxLoader exact firmware: 8.0.0.290; static analysis only");
            pw.println("Program: " + currentProgram.getName());
            pw.println("ImageBase: " + currentProgram.getImageBase());
            DecompInterface ifc = new DecompInterface();
            ifc.toggleCCode(true);
            ifc.toggleSyntaxTree(true);
            ifc.setSimplificationStyle("decompile");
            if (!ifc.openProgram(currentProgram)) {
                pw.println("ERROR Decompiler cannot open program");
                return;
            }
            FunctionManager fm = currentProgram.getFunctionManager();
            for (long offset : TARGETS) {
                Address at=toAddr(offset);
                Function f=fm.getFunctionContaining(at);
                pw.println("\n========== TARGET " + at + " ==========");
                if (f==null) {
                    pw.println("NO FUNCTION recognized. Attempt creating function at address.");
                    try {
                        f=createFunction(at, "honor_target_"+Long.toHexString(offset));
                    } catch (Exception ex) {
                        pw.println("Unable to define: "+ex.getMessage());
                    }
                }
                if (f == null) continue;
                pw.println("FUNCTION " + f.getName() + " ENTRY="+f.getEntryPoint()+" SIZE="+f.getBody().getNumAddresses());
                DecompileResults r=ifc.decompileFunction(f, 60, monitor);
                pw.println("COMPLETE: "+r.decompileCompleted()+" ERROR: "+r.getErrorMessage());
                if (r.decompileCompleted() && r.getDecompiledFunction() != null) {
                    String src=r.getDecompiledFunction().getC();
                    if (src.length()>24000)src=src.substring(0,24000)+"\n...TRUNCATED...";
                    pw.println(src);
                }
                pw.flush();
            }
            Address global=toAddr(0x1CDFD8L);
            pw.println("\n===== GLOBAL_UNLOCK_PERMISSION_REFERENCE_XREFS "+global+" =====");
            ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(global);
            int count=0;
            while(refs.hasNext() && count<100){
               Reference ref=refs.next();
               pw.println(ref.getFromAddress()+" "+ref.getReferenceType());
               count++;
            }
            pw.println("GLOBAL_REFS_FOUND "+count);
            ifc.dispose();
        }
        println("Wrote "+output.getAbsolutePath()+" "+output.length()+" bytes");
    }
}
