import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class Honor70AVBSelectionAndGPTGateAudit extends GhidraScript {
  @Override public void run() throws Exception {
    File dir=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    dir.mkdirs();
    File outFile=new File(dir,"HONOR70_AVB2_NOAVB_GPT_SELECTION_GHIDRA.txt");
    long[] targets={
      0x03144L,0x03134L,0x014d0L,0x03e268L,0x03e7e8L,
      0x02be30L,0x03b2e0L,0x012e90L,0x012cf8L,
      0x03bf90L
    };
    String[] names={"NoAVBLoad_fw_ufsdev","LoadImageAndAuthVB2",
      "Is_VERIFIED_BOOT_2","vbmeta_a","vbmeta","NO_AVB","VERIFIED_BOOT_ENABLED",
      "VB2","VerifiedBoot","Milestone Call","Sending Milestone"};
    LinkedHashMap<Address, String> discovered=new LinkedHashMap<>();
    try(PrintWriter w=new PrintWriter(new OutputStreamWriter(new FileOutputStream(outFile),StandardCharsets.UTF_8))) {
      w.println("HONOR 70 FNE-NX9 EEA 8.0.0.290 signed ABL — stock AVB2 vs NO_AVB selection");
      w.println("READ ONLY. No GPT renaming, EDL writes, or live commands.");
      for(long target:targets){
        Address a=toAddr(target);
        Function f=currentProgram.getFunctionManager().getFunctionContaining(a);
        w.println("TARGET "+String.format("0x%x",target)+" -> "+(f==null?"missing":f.getEntryPoint().toString()+" "+f.getName()));
        if(f!=null) discovered.put(f.getEntryPoint(),"preselected near "+String.format("0x%x",target));
      }
      for(MemoryBlock blk:currentProgram.getMemory().getBlocks()){
        if(!blk.isInitialized() || blk.getSize()>25000000L) continue;
        byte[] raw=new byte[(int)blk.getSize()];
        int count=currentProgram.getMemory().getBytes(blk.getStart(),raw);
        for(String token:names) {
          byte[] needle=token.getBytes(StandardCharsets.UTF_8);
          int matches=0;
          for(int i=0;i+needle.length<=count;i++){
            int j=0;while(j<needle.length&&raw[i+j]==needle[j])j++;
            if(j!=needle.length)continue;
            Address a=blk.getStart().add(i);
            w.println("STRING "+token+" AT "+a);
            ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(a);
            int k=0;
            while(refs.hasNext()&&k<25){
              Reference r=refs.next();
              Function f=currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
              w.println("  XREF "+r.getFromAddress()+" FUN "+(f==null?"none":f.getEntryPoint()));
              if(f!=null)discovered.putIfAbsent(f.getEntryPoint(),"string "+token);
              k++;
            }
            if(++matches>=16)break;
          }
          if(matches==0)w.println("NO_STRING "+token);
        }
      }
      DecompInterface dec=new DecompInterface();
      dec.toggleCCode(true);dec.setSimplificationStyle("decompile");
      if(!dec.openProgram(currentProgram))throw new RuntimeException("Failed to open Ghidra program");
      int idx=0;
      for(Map.Entry<Address,String> entry:discovered.entrySet()){
        if(++idx>28)break;
        Function f=currentProgram.getFunctionManager().getFunctionAt(entry.getKey());
        if(f==null)continue;
        w.println("\n===== AVB_FUNCTION "+f.getEntryPoint()+" "+f.getName()+" reason "+entry.getValue()+" =====");
        w.println("SIZE "+f.getBody().getNumAddresses());
        ReferenceIterator callers=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        int nc=0;
        while(callers.hasNext()&&nc<50){
          Reference r=callers.next();
          Function cf=currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
          w.println("CALLER "+r.getFromAddress()+" IN "+(cf==null?"NONE":cf.getEntryPoint()));
          nc++;
        }
        DecompileResults result=dec.decompileFunction(f,75,monitor);
        if(result.decompileCompleted() && result.getDecompiledFunction()!=null){
          String c=result.getDecompiledFunction().getC();
          w.println("DECOMP_START");
          w.println(c.length()>70000?c.substring(0,70000)+"\nTRUNCATED":c);
          w.println("DECOMP_END");
        }else w.println("DECOMP_FAILED "+result.getErrorMessage());
        w.flush();
      }
      dec.dispose();
    }
    println("AVB_SELECTOR_AUDIT_BYTES "+outFile.length());
  }
}