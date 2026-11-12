import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70FirehoseSecureBootPeekPokeRPMBAudit extends GhidraScript {
  @Override public void run() throws Exception {
    File outDir=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    outDir.mkdirs();
    File output=new File(outDir,"HONOR70_FIREHOSE_SECUREBOOT_PEEK_POKE_RPMB.txt");
    String[] markers={
      "Peek is disabled on secure boot devices",
      "Poke is disabled on secure boot devices",
      "UFS RPMB ReadWrite Size:",
      "patch command is deprecated",
      "The poke size",
      "Secure Boot:",
      "QSEE Dev Config"
    };
    Set<Address> owners=new LinkedHashSet<>();
    try(PrintWriter w=new PrintWriter(new OutputStreamWriter(new FileOutputStream(output),StandardCharsets.UTF_8))){
      w.println("ORIGINAL SIGNED HONOR70 BOARD FIREHOSE; NONEXECUTING OFFLINE REVERSE ENGINEERING");
      w.println("LANGUAGE "+currentProgram.getLanguageID()+" BASE "+currentProgram.getImageBase());
      for(MemoryBlock mem:currentProgram.getMemory().getBlocks()) {
        if(!mem.isInitialized()||mem.getSize()>14000000L) continue;
        int len=(int)mem.getSize();
        byte[] buf=new byte[len];
        int n=currentProgram.getMemory().getBytes(mem.getStart(),buf);
        for(String marker:markers){
          byte[] val=marker.getBytes(StandardCharsets.US_ASCII);
          int found=0;
          for(int pos=0;pos+val.length<=n;pos++){
            boolean matches=true;
            for(int i=0;i<val.length;i++)if(buf[pos+i]!=val[i]){matches=false;break;}
            if(!matches)continue;
            Address addr=mem.getStart().add(pos);
            w.println("STRING "+marker+" ADDRESS "+addr);
            ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(addr);
            int count=0;
            while(refs.hasNext()&&count<40){
              Reference ref=refs.next();
              Function fn=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
              w.println("STRING_XREF "+ref.getFromAddress()+" FUNCTION "+(fn==null?"NO_FUNCTION":fn.getEntryPoint()));
              if(fn!=null)owners.add(fn.getEntryPoint());
              count++;
            }
            if(++found>=10)break;
          }
          if(found==0)w.println("MISSING_STRING "+marker);
        }
      }
      DecompInterface dec=new DecompInterface();
      dec.toggleCCode(true);dec.setSimplificationStyle("decompile");
      if(!dec.openProgram(currentProgram))throw new RuntimeException("Decompiler not ready");
      int count=0;
      for(Address entry:owners){
        if(++count>30)break;
        Function fn=currentProgram.getFunctionManager().getFunctionAt(entry);
        if(fn==null)continue;
        w.println("===== MARKER_OWNER "+entry+" "+fn.getName()+" =====");
        ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(entry);
        int n=0;while(refs.hasNext()&&n<30){
          Reference ref=refs.next();
          Function caller=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
          w.println("CALLER "+ref.getFromAddress()+" OWNER "+(caller==null?"none":caller.getEntryPoint()));
          n++;
        }
        DecompileResults res=dec.decompileFunction(fn,65,monitor);
        if(res.decompileCompleted()&&res.getDecompiledFunction()!=null){
          String code=res.getDecompiledFunction().getC();
          w.println(code.length()>43000?code.substring(0,43000)+"\nTRUNCATED":code);
        }else w.println("DECOMP_FAILED "+res.getErrorMessage());
        w.flush();
      }
      dec.dispose();
      w.println("OWNER_FUNCTION_COUNT "+owners.size());
    }
    println("FIREHOSE_AUTH_POLICY_REPORT_BYTES "+output.length());
  }
}