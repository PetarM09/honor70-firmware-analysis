import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70FirehoseFirmwareWriteFixGPTEvidence extends GhidraScript {
  @Override public void run() throws Exception {
    File dir=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    dir.mkdirs();
    File outFile=new File(dir,"HONOR70_FIREHOSE_FIRMWAREWRITE_FIXGPT_CODE.txt");
    String loader=System.getenv("HONOR_LOADER");
    if(loader==null)throw new RuntimeException("Missing explicit loader variant");
    long[] sites="lite".equals(loader)
      ? new long[]{0x148258fcL,0x14825b60L,0x14825db0L,
                   0x148267e8L,0x14826a24L,0x14826bb8L,0x14827bc0L,
                   0x148298d4L,0x1482993cL}
      : new long[]{0x14825908L,0x14825b6cL,0x14825dbcL,
                   0x148267f4L,0x14826a30L,0x14826bc4L,0x14827bccL,
                   0x148298e0L,0x14829948L};
    LinkedHashMap<Address,String> functions=new LinkedHashMap<>();
    try(PrintWriter p=new PrintWriter(new OutputStreamWriter(new FileOutputStream(outFile),StandardCharsets.UTF_8))) {
      p.println("SIGNED FNE-AN00 HMT FIREHOSE — XML REGISTERED FIRMWAREWRITE FIXGPT HANDLERS");
      p.println("STATIC ONLY; original signing, no phone writes or bypass claim");
      p.println("PROGRAM "+currentProgram.getName()+" LANG "+currentProgram.getLanguageID());
      p.println("SOURCE_VARIANT "+loader);
      for(long a:sites) {
        Address at=toAddr(a);
        Function f=currentProgram.getFunctionManager().getFunctionAt(at);
        if(f==null){
          try {
            disassemble(at);
            f=createFunction(at,"Honor70_XML_"+
                             Long.toHexString(a));
          }catch(Exception ex){
            p.println("FUNCTION_RECOVERY_ERROR "+String.format("0x%x",a)+" "+ex.toString());
          }
        }
        if(f==null)f=currentProgram.getFunctionManager().getFunctionContaining(at);
        p.println("SITE "+String.format("0x%x",a)+" ENTRY "+(f==null?"NONE":f.getEntryPoint().toString()));
        if(f!=null)functions.putIfAbsent(f.getEntryPoint(),"registered XML "+String.format("0x%x",a));
      }
      DecompInterface dec=new DecompInterface();
      dec.toggleCCode(true);dec.setSimplificationStyle("decompile");
      if(!dec.openProgram(currentProgram))throw new RuntimeException("Ghidra decompiler initialization failed");
      for(Map.Entry<Address,String> entry:functions.entrySet()) {
        Function f=currentProgram.getFunctionManager().getFunctionAt(entry.getKey());
        if(f==null)continue;
        p.println("\n===== REGISTERED_HANDLER "+f.getEntryPoint()+" "+f.getName()+" ["+entry.getValue()+"] =====");
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