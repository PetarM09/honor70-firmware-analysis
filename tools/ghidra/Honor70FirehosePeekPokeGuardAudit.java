import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70FirehosePeekPokeGuardAudit extends GhidraScript {
  @Override public void run() throws Exception {
    File dir=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    dir.mkdirs();
    File outFile=new File(dir,"HONOR70_FIREHOSE_PEEK_POKE_SECUREBOOT_GUARD_SOURCE.txt");
    // Both Board Firehose variants share nearby locations but differ in entry
    // addresses: getFunctionContaining finds the correct function for each.
    long[] sites={
      0x1481fcccL,0x1482011cL,0x148201e4L,
      0x14824300L,0x14824600L,0x14824900L,
      0x14824c00L,0x14824f00L,0x14825000L,
      0x1482528cL,0x14825300L,0x14825470L,
      0x14825600L,0x14825800L,0x14825b00L,
      0x14825dbcL,0x14825db0L,
      0x1482d740L
    };
    LinkedHashMap<Address,String> functions=new LinkedHashMap<>();
    try(PrintWriter p=new PrintWriter(new OutputStreamWriter(new FileOutputStream(outFile),StandardCharsets.UTF_8))) {
      p.println("SIGNED FNE-AN00 HMT FIREHOSE — PEEK/POKE GUARD + SECURE_BOOT FUNCTION FORENSICS");
      p.println("STATIC ONLY; original signing, no phone writes or bypass claim");
      p.println("PROGRAM "+currentProgram.getName()+" LANG "+currentProgram.getLanguageID());
      for(long a:sites) {
        Function f=currentProgram.getFunctionManager().getFunctionContaining(toAddr(a));
        p.println("SITE "+String.format("0x%x",a)+" ENTRY "+(f==null?"NONE":f.getEntryPoint().toString()));
        if(f!=null)functions.putIfAbsent(f.getEntryPoint(),"site "+String.format("0x%x",a));
      }
      DecompInterface dec=new DecompInterface();
      dec.toggleCCode(true);dec.setSimplificationStyle("decompile");
      if(!dec.openProgram(currentProgram))throw new RuntimeException("Ghidra decompiler initialization failed");
      for(Map.Entry<Address,String> entry:functions.entrySet()) {
        Function f=currentProgram.getFunctionManager().getFunctionAt(entry.getKey());
        if(f==null)continue;
        p.println("\n===== SECURITY_GATE "+f.getEntryPoint()+" "+f.getName()+" ["+entry.getValue()+"] =====");
        p.println("FUNCTION_BYTES "+f.getBody().getNumAddresses());
        ReferenceIterator callers=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        int count=0;
        while(callers.hasNext() && count<35) {
          Reference r=callers.next();
          Function cf=currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
          p.println("CALLER "+r.getFromAddress()+" FROM "+(cf==null?"NONE":cf.getEntryPoint()));
          count++;
        }
        DecompileResults result=dec.decompileFunction(f,65,monitor);
        if(result.decompileCompleted()&&result.getDecompiledFunction()!=null){
          String c=result.getDecompiledFunction().getC();
          p.println("BEGIN_DECOMP");
          p.println(c.length()>46000?c.substring(0,46000)+"\nTRUNCATED":c);
          p.println("END_DECOMP");
        }else p.println("DECOMP_FAILED "+result.getErrorMessage());
        p.flush();
      }
      dec.dispose();
      p.println("ANALYZED_FUNCTION_COUNT "+functions.size());
    }
    println("FIREHOSE_GUARD_REPORT_BYTES "+outFile.length());
  }
}