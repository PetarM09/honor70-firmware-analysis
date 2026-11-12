import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class Honor70FastbootRXAllocationAudit extends GhidraScript {
  @Override public void run() throws Exception {
    File dir=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    dir.mkdirs();
    File output=new File(dir,"HONOR70_FASTBOOT_RX_BUFFER_ALLOC_AND_EVENT_TRACE.txt");
    long[] targetSites={
      0x20328L,0x20578L,0x22a64L,0x22c7cL,0x24364L,
      0x2429cL,0x22d68L,0x22b90L,0x27b44L,0x27ab0L,
      0x242ecL,0x2439cL,0x23fd0L,0x23fb0L,
      0x20e4cL,0x20e2cL
    };
    DecompInterface dec=new DecompInterface();
    dec.toggleCCode(true);dec.setSimplificationStyle("decompile");
    if(!dec.openProgram(currentProgram))throw new RuntimeException("Could not create decompiler");
    try(PrintWriter w=new PrintWriter(new OutputStreamWriter(new FileOutputStream(output),StandardCharsets.UTF_8))){
      w.println("HONOR70 signed original 8.0.0.290 ABL Fastboot command pre-allowlist buffer size provenance");
      w.println("No live device operation. Parse buffer length may exceed logical Fastboot command length; no exploit claim.");
      for(long v:targetSites){
        Address a=toAddr(v);
        Function f=currentProgram.getFunctionManager().getFunctionContaining(a);
        w.println("\n===== ALLOC_TARGET "+String.format("%08x",v)+" =====");
        if(f==null){w.println("NO_FUNCTION");continue;}
        w.println("FUNCTION "+f.getEntryPoint()+" "+f.getName()+" BYTE_COUNT "+f.getBody().getNumAddresses());
        ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        int n=0;
        while(refs.hasNext()&&n<35){
          Reference r=refs.next();Function caller=currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
          w.println("CALLER "+r.getFromAddress()+" FROM "+(caller==null?"NONE":caller.getEntryPoint()));
          n++;
        }
        DecompileResults result=dec.decompileFunction(f,60,monitor);
        if(result.decompileCompleted()&&result.getDecompiledFunction()!=null){
          String code=result.getDecompiledFunction().getC();
          w.println("DECOMP_BEGIN");
          w.println(code.length()>65000?code.substring(0,65000)+"\nTRUNCATED":code);
          w.println("DECOMP_END");
        } else w.println("DECOMP_FAILED "+result.getErrorMessage());
        w.flush();
      }
    }
    dec.dispose();
    println("BOUNDS_REPORT_BYTES "+output.length());
  }
}
