import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70FastbootCommandGateAudit extends GhidraScript {
  @Override public void run() throws Exception {
    File d=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    d.mkdirs();
    File output=new File(d,"HONOR70_EEA_FASTBOOT_COMMAND_GATE_GHIDRA.txt");
    String[] patterns={
      "Command not allowed",
      "command not allowed",
      "Command not support",
      "Flashing Unlock is not allowed",
      "get_unlock_ability:",
      "oem get-bootinfo",
      "oem lock-state info",
      "flashing get_unlock_ability",
      "getvar:",
      "getvar:unlocked",
      "getvar:product",
      "getvar:max-download-size",
      "getvar:vendorcountry",
      "getvar:devicemodel"
    };
    long[] targets={0x26598L,0x25b88L,0x25c04L,0x27850L,0x23fd0L};
    SortedSet<Address> functions=new TreeSet<>();
    try(PrintWriter out=new PrintWriter(new OutputStreamWriter(new FileOutputStream(output),StandardCharsets.UTF_8))){
      out.println("HONOR70 EEA FNE-N29 8.0.0.290 FASTBOOT REMOTE 'COMMAND NOT ALLOWED'");
      out.println("ACTION: code inspection only; no device; no firmware changes");
      out.println("PROGRAM="+currentProgram.getName()+" BASE="+currentProgram.getImageBase());
      for(long off:targets){
        Address addr=toAddr(off);
        Function f=currentProgram.getFunctionManager().getFunctionContaining(addr);
        out.println("TARGET "+String.format("0x%x",off)+" FUNCTION="+(f==null?"NOT_FOUND":f.getName()+" ENTRY="+f.getEntryPoint()));
        if(f!=null)functions.add(f.getEntryPoint());
      }
      for(MemoryBlock b:currentProgram.getMemory().getBlocks()){
        if(!b.isInitialized()||b.getSize()>20000000)continue;
        byte[] raw=new byte[(int)b.getSize()];
        int length=currentProgram.getMemory().getBytes(b.getStart(),raw);
        for(String token:patterns){
          byte[] needle=token.getBytes(StandardCharsets.US_ASCII);
          int found=0;
          for(int i=0;i<=length-needle.length;i++){
            boolean match=true;
            for(int j=0;j<needle.length;j++)if(raw[i+j]!=needle[j]){match=false;break;}
            if(!match)continue;
            Address loc=b.getStart().add(i);
            out.println("STRING "+token+" ADDRESS "+loc);
            ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(loc);
            int references=0;
            while(it.hasNext()&&references<45){
              Reference ref=it.next();
              Function f=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
              out.println("  XREF "+ref.getFromAddress()+" TYPE "+ref.getReferenceType()+
                " FUNCTION "+(f==null?"NONE":f.getEntryPoint()));
              if(f!=null)functions.add(f.getEntryPoint());
              references++;
            }
            out.println("  XREF_COUNT "+references);
            if(++found>=6)break;
          }
          if(found==0)out.println("STRING_NOT_FOUND "+token);
        }
      }
      DecompInterface api=new DecompInterface();
      api.toggleCCode(true);api.setSimplificationStyle("decompile");
      if(!api.openProgram(currentProgram))throw new RuntimeException("Decomp API failed");
      int counter=0;
      for(Address addr:functions){
        if(counter++>=35)break;
        Function f=currentProgram.getFunctionManager().getFunctionAt(addr);
        if(f==null)continue;
        out.println("\n========== FUNCTION "+addr+" NAME "+f.getName()+" SIZE "+f.getBody().getNumAddresses()+" ==========");
        DecompileResults res=api.decompileFunction(f,40,monitor);
        if(res.decompileCompleted()&&res.getDecompiledFunction()!=null){
          String code=res.getDecompiledFunction().getC();
          out.println(code.length()>38000?code.substring(0,38000)+"\nTRUNCATED":code);
        }else out.println("DECOMP_ERROR "+res.getErrorMessage());
      }
      out.println("FUNCTIONS_EXPORTED "+(counter-1));
      api.dispose();
    }
    println("WROTE "+output+" bytes="+output.length());
  }
}
