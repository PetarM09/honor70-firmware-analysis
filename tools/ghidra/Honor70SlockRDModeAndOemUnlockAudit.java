import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Honor70SlockRDModeAndOemUnlockAudit extends GhidraScript {
  @Override public void run() throws Exception {
    File outputDir = new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    outputDir.mkdirs();
    File output = new File(outputDir, "HONOR70_SIGNED_SERVICE_FASTBOOT_ENTRYPOINTS.txt");
    long[] candidateCallSites = {
      0x15758L, 0x15c2cL, 0x16798L, 0x16ff8L,
      0x1738cL, 0x27850L, 0x25c04L, 0x279ecL,
      0x12cf8L, 0x15690L, 0x1bb68L,
      0x240c8L, 0x23fd0L, 0x43688L
    };
    String[] tokens = {
      "flash:slockv1", "fastboot flash:slockv1",
      "fastboot flash:rdmodev1", "flash:rdmodev1",
      "oem frp-unlock", "oem unlock", "oem relock",
      "oem check-image", "oem oeminforead", "oem oeminfoerase",
      "get_unlock_ability"
    };
    SortedMap<Address, SortedSet<String>> targets = new TreeMap<>();
    try(PrintWriter w=new PrintWriter(new OutputStreamWriter(new FileOutputStream(output),StandardCharsets.UTF_8))) {
      w.println("HONOR 70 FNE-NX9 signed original EEA 8.0.0.290");
      w.println("OFFLINE AUDIT ONLY: no Fastboot, EDL, OEMINFO or other live actions");
      for(long site:candidateCallSites) {
        Address a=toAddr(site);
        Function fn=currentProgram.getFunctionManager().getFunctionContaining(a);
        w.println("CALLSITE "+String.format("0x%x",site)+" FUNCTION "+(fn==null?"NO_FUNCTION":fn.getEntryPoint()+" "+fn.getName()));
        if(fn!=null) {
          targets.computeIfAbsent(fn.getEntryPoint(), k->new TreeSet<>()).add("CALLSITE "+String.format("0x%x",site));
        }
      }
      for(ghidra.program.model.mem.MemoryBlock block:currentProgram.getMemory().getBlocks()){
        if(!block.isInitialized()||block.getSize()>20000000L) continue;
        byte[] bytes=new byte[(int)block.getSize()];
        int size=currentProgram.getMemory().getBytes(block.getStart(),bytes);
        for(String pattern:tokens) {
          byte[] token=pattern.getBytes(StandardCharsets.UTF_8);
          int found=0;
          for(int i=0;i<=size-token.length;i++){
            boolean ok=true;
            for(int j=0;j<token.length;j++){
              if(bytes[i+j]!=token[j]){ok=false;break;}
            }
            if(!ok) continue;
            Address a=block.getStart().add(i);
            w.println("STRING "+pattern+" ADDR "+a);
            ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(a);
            int count=0;
            while(refs.hasNext() && count<25){
              Reference ref=refs.next();
              Function fn=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
              w.println("  STRING_XREF "+ref.getFromAddress()+" FUNCTION "+(fn==null?"NO_FUNCTION":fn.getEntryPoint()));
              if(fn!=null) targets.computeIfAbsent(fn.getEntryPoint(),k->new TreeSet<>()).add("STRING "+pattern);
              count++;
            }
            if(++found>=8)break;
          }
          if(found==0) w.println("NO_STRING "+pattern);
        }
      }
      DecompInterface dec=new DecompInterface();
      dec.toggleCCode(true);
      dec.setSimplificationStyle("decompile");
      if(!dec.openProgram(currentProgram)) throw new RuntimeException("Cannot open Ghidra program");
      int count=0;
      for(Map.Entry<Address,SortedSet<String>> kv:targets.entrySet()){
        Function fn=currentProgram.getFunctionManager().getFunctionAt(kv.getKey());
        if(fn==null)continue;
        if(++count>32){w.println("TRUNCATED_AT_FUNCTION "+count);break;}
        w.println("===== FUNCTION "+fn.getEntryPoint()+" "+fn.getName()+" REASONS "+kv.getValue()+" =====");
        w.println("BODY_BYTE_COUNT "+fn.getBody().getNumAddresses());
        ReferenceIterator callers=currentProgram.getReferenceManager().getReferencesTo(fn.getEntryPoint());
        int n=0;
        while(callers.hasNext()&&n<50){
          Reference ref=callers.next();
          Function cf=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
          w.println(" CALLER "+ref.getFromAddress()+" IN "+(cf==null?"unknown":cf.getEntryPoint()));
          n++;
        }
        DecompileResults res=dec.decompileFunction(fn,65,monitor);
        if(res.decompileCompleted()&&res.getDecompiledFunction()!=null){
          String s=res.getDecompiledFunction().getC();
          w.println(s.length()>50000?s.substring(0,50000)+"\nTRUNCATED":s);
        }else w.println("DECOMP_FAILED "+res.getErrorMessage());
        w.flush();
      }
      dec.dispose();
    }
    println("HONOR70_SIGNED_SERVICE_ANALYSIS_BYTES "+output.length());
  }
}
