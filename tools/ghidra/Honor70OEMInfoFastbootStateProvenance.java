import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70OEMInfoFastbootStateProvenance extends GhidraScript {
  @Override public void run() throws Exception {
    File dir=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis"); dir.mkdirs();
    File output=new File(dir,"HONOR70_OEMINFO_FASTBOOT_STATE_PROVENANCE.txt");
    long[] targets={
      0x12cf8L, 0x12e90L, 0x13008L, 0x13054L, 0x134c0L, 0x13684L,
      0x136a4L, 0x13d58L, 0x1a7b0L, 0x1bf74L, 0x15690L, 0x1bb68L,
      0x23fd0L, 0x240c8L, 0x27850L, 0x37ac0L, 0x433a8L, 0x43688L
    };
    DecompInterface dec=new DecompInterface();
    dec.toggleCCode(true); dec.setSimplificationStyle("decompile");
    if(!dec.openProgram(currentProgram))throw new RuntimeException("Ghidra decomp unavailable");
    try(PrintWriter w=new PrintWriter(new OutputStreamWriter(new FileOutputStream(output),StandardCharsets.UTF_8))){
      w.println("HONOR70 EEA signed ABL, read-only Ghidra decompilation; target model FNE-NX9 8.0.0.290");
      w.println("Addresses are file-relative RVAs. Results reflect static firmware, not live device.");
      w.println("Please cross-check register arguments against ARM64; Ghidra can misrecover var types.");
      for(long off:targets){
        Address addr=toAddr(off);
        Function f=currentProgram.getFunctionManager().getFunctionContaining(addr);
        w.println("\n=============== TARGET "+String.format("0x%x",off)+" ===============");
        if(f==null){w.println("NOT_FOUND");continue;}
        w.println("FUNCTION "+f.getEntryPoint()+" "+f.getName()+" BODY_SIZE "+f.getBody().getNumAddresses());
        w.println("MATCHES_REQUESTED_ENTRY "+f.getEntryPoint().equals(addr));
        w.println("CALLERS");
        int n=0;
        ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        while(refs.hasNext()&&n<80){
          Reference r=refs.next();
          Function c=currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
          w.println("  "+r.getFromAddress()+" "+r.getReferenceType()+" "+(c==null?"UNKNOWN":c.getEntryPoint()));
          n++;
        }
        DecompileResults d=dec.decompileFunction(f,50,monitor);
        if(d.decompileCompleted()&&d.getDecompiledFunction()!=null){
          String code=d.getDecompiledFunction().getC();
          w.println("DECOMP "+code.substring(0,Math.min(35000,code.length())));
        }else{w.println("DECOMP_FAILED "+d.getErrorMessage());}
        w.flush();
      }
    }
    dec.dispose();
    println("CREATED "+output+" BYTES "+output.length());
  }
}
