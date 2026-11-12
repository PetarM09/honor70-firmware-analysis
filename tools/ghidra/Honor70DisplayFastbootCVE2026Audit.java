import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class Honor70DisplayFastbootCVE2026Audit extends GhidraScript {
  @Override public void run() throws Exception {
    File d=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");d.mkdirs();
    File out=new File(d,"HONOR70_DISPLAYMODE_CVE24092_SIGNED_ABL_HANDLERS.txt");
    long[] targets={0x25e2cL,0x25cc4L,0x25c6cL,0x49098L,0x492d0L,
                    0x26b7cL,0x134c0L,0x22f40L,0x25b88L,0x231e8L};
    DecompInterface dec=new DecompInterface();
    dec.toggleCCode(true);dec.setSimplificationStyle("decompile");
    if(!dec.openProgram(currentProgram))throw new RuntimeException("Cannot init Ghidra decompiler");
    try(PrintWriter p=new PrintWriter(new OutputStreamWriter(new FileOutputStream(out),StandardCharsets.UTF_8))){
      p.println("HONOR 70 FNE-NX9 Original EEA ABL 8.0.0.290; static display-mode Fastboot investigation");
      p.println("CVE-2026-24092 applicability is not established by a similarly named command.");
      p.println("No live Fastboot command or malformed input is sent.");
      for(long v:targets){
        Address a=toAddr(v);
        Function f=currentProgram.getFunctionManager().getFunctionContaining(a);
        p.println("\n===== DISPLAY_TARGET "+String.format("%08x",v)+" =====");
        if(f==null){p.println("MISSING");continue;}
        p.println("FUNCTION_ENTRY "+f.getEntryPoint()+" SIZE "+f.getBody().getNumAddresses()+" NAME "+f.getName());
        ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        int n=0;
        while(it.hasNext()&&n<50){
          Reference r=it.next();Function c=currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
          p.println("CALLER "+r.getFromAddress()+" WITHIN "+(c==null?"NONE":c.getEntryPoint()));
          n++;
        }
        DecompileResults res=dec.decompileFunction(f,65,monitor);
        if(res.decompileCompleted()&&res.getDecompiledFunction()!=null){
          String code=res.getDecompiledFunction().getC();
          p.println("DECOMPILE_BEGIN");
          p.println(code.length()>58000?code.substring(0,58000)+"\nTRUNCATED":code);
          p.println("DECOMPILE_END");
        }else p.println("DECOMP_ERROR "+res.getErrorMessage());
        p.flush();
      }
    }
    dec.dispose();
    println("ABL_DISPLAY_CVE_AUDIT_TEXT_BYTES "+out.length());
  }
}
