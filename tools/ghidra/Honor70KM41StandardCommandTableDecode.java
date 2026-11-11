// Read-only analysis of original signed HONOR70 EEA Keymaster 4.1 command array.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70KM41StandardCommandTableDecode extends GhidraScript {
  private long u32(byte[] b,int p){
    return ((long)b[p]&255L) | (((long)b[p+1]&255L)<<8) |
           (((long)b[p+2]&255L)<<16) | (((long)b[p+3]&255L)<<24);
  }
  private long u64(byte[] b,int p){
    return u32(b,p) | (u32(b,p+4)<<32);
  }
  @Override public void run() throws Exception {
    File dir=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    dir.mkdirs();
    File out=new File(dir,"KM41_EXACT_67_STANDARD_COMMANDS_AND_DELETE_ALL_KEYS.txt");
    try(PrintWriter p=new PrintWriter(new OutputStreamWriter(new FileOutputStream(out),StandardCharsets.UTF_8))){
      Address table=toAddr(0x138580L);
      int count=0x43; // FUN_0012366c() returns this constant.
      int stride=16;  // Confirmed by sequential 0x202/0x203/0x204 vendor registrations.
      byte[] buffer=new byte[count*stride];
      int n=currentProgram.getMemory().getBytes(table,buffer);
      if(n!=buffer.length)throw new IllegalStateException("Failed to read complete KM table");
      p.println("ORIGINAL_SIGNED_EEA_KM41_MEMORY_TABLE "+table+" COUNT "+count+" STRIDE "+stride);
      Long deleteHandler=null;
      boolean found202=false,found203=false;
      for(int i=0;i<count;i++){
        int pos=i*stride;
        long cmd=u32(buffer,pos), flags=u32(buffer,pos+4), cb=u64(buffer,pos+8);
        if(cmd==0x202 && cb==0x1185a8L)found202=true;
        if(cmd==0x203 && cb==0x118878L)found203=true;
        if(cmd==0x10e)deleteHandler=cb;
        String function="not_discovered";
        try {
          Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(cb));
          if(f!=null)function=f.getName();
        }catch(Exception ignored){}
        p.println(String.format("ENTRY %02d CMD 0x%04x FLAGS 0x%08x CALLBACK 0x%x FUNC %s",i,cmd,flags,cb,function));
      }
      p.println("ASSERT_0x202_REGISTERED "+found202);
      p.println("ASSERT_0x203_REGISTERED "+found203);
      p.println("DELETE_ALL_KEYS_0x10e_REGISTERED "+(deleteHandler!=null));
      p.println("DELETE_ALL_KEYS_0x10e_HANDLER "+(deleteHandler==null?"NOT_REGISTERED":String.format("0x%x",deleteHandler)));
      if(!found202||!found203)throw new IllegalStateException("Known device state callbacks missing - invalid memory layout");
      if(deleteHandler!=null){
        Address target=toAddr(deleteHandler.longValue());
        Function f=currentProgram.getFunctionManager().getFunctionAt(target);
        if(f==null)try{f=createFunction(target,"KM_DELETE_ALL_KEYS_HANDLER");}catch(Exception ex){p.println("CREATE_FUNCTION_WARNING "+ex);}
        if(f==null)f=currentProgram.getFunctionManager().getFunctionContaining(target);
        if(f==null){
          p.println("DELETE_ALL_KEYS_DECOMPILER_FAILED_NO_FUNCTION");
        }else{
          p.println("DELETE_ALL_KEYS_FUNCTION "+f.getName()+" ENTRY "+f.getEntryPoint());
          DecompInterface dec=new DecompInterface();
          dec.toggleCCode(true);
          dec.setSimplificationStyle("decompile");
          if(dec.openProgram(currentProgram)){
            DecompileResults decompiled=dec.decompileFunction(f,50,monitor);
            if(decompiled.decompileCompleted() && decompiled.getDecompiledFunction()!=null){
              String code=decompiled.getDecompiledFunction().getC();
              p.println("DELETE_ALL_KEYS_DECOMPILED_BEGIN");
              p.println(code.length()>35000?code.substring(0,35000):code);
              p.println("DELETE_ALL_KEYS_DECOMPILED_END");
            }else p.println("DECOMPILE_ERROR "+decompiled.getErrorMessage());
          }
          dec.dispose();
        }
      }
      // Independently decompile both real 0x10e callback dependencies.
      // These code addresses are read-only evidence, not entrypoints to invoke.
      long[] nested={0x1184d4L,0x1177a0L};
      for(long addr:nested){
        Address site=toAddr(addr);
        Function inner=currentProgram.getFunctionManager().getFunctionAt(site);
        if(inner==null)try{inner=createFunction(site,"KM_DELETE_KEYS_RELATED_"+Long.toHexString(addr));}
          catch(Exception ex){p.println("INNER_CREATE_WARNING "+site+" "+ex);}
        if(inner==null)inner=currentProgram.getFunctionManager().getFunctionContaining(site);
        p.println("KEY_DELETE_INNER_TARGET "+site+" RECOVERED "+(inner!=null));
        if(inner==null)continue;
        p.println("KEY_DELETE_INNER_FUNCTION "+inner.getName()+" ENTRY "+inner.getEntryPoint()+
                  " BODY_BYTES "+inner.getBody().getNumAddresses());
        DecompInterface dec=new DecompInterface();
        dec.toggleCCode(true);
        dec.setSimplificationStyle("decompile");
        if(dec.openProgram(currentProgram)){
          DecompileResults result=dec.decompileFunction(inner,65,monitor);
          if(result.decompileCompleted()&&result.getDecompiledFunction()!=null){
            String code=result.getDecompiledFunction().getC();
            p.println("KEY_DELETE_INNER_DECOMPILED_BEGIN "+site);
            p.println(code.length()>45000?code.substring(0,45000)+"\n...[TRUNCATED]":code);
            p.println("KEY_DELETE_INNER_DECOMPILED_END "+site);
          }else p.println("KEY_DELETE_INNER_ERROR "+site+" "+result.getErrorMessage());
        }else p.println("KEY_DELETE_INNER_ERROR "+site+" failed to open program");
        dec.dispose();
      }
    }
    println("KM41 original 67-slot callback table decoded, "+out.length()+" bytes");
  }
}
