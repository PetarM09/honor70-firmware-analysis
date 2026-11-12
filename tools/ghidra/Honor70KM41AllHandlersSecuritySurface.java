// Static source-pinned enumeration of every signed retail KM41 callback.
// No device operation and no trustlet invocation.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70KM41AllHandlersSecuritySurface extends GhidraScript {
  static long uint32(byte[] b,int p) {
    return ((long)b[p]&255L)|(((long)b[p+1]&255L)<<8)|
           (((long)b[p+2]&255L)<<16)|(((long)b[p+3]&255L)<<24);
  }
  static long uint64(byte[] b,int p) {
    return uint32(b,p)|(uint32(b,p+4)<<32);
  }
  public void run() throws Exception {
    File output=new File(System.getenv("GITHUB_WORKSPACE")+
                         "/analysis/KM41_ALL_67_HANDLER_SECURITY_SURFACE.tsv");
    output.getParentFile().mkdirs();
    DecompInterface dec=new DecompInterface();
    dec.toggleCCode(true);
    dec.setSimplificationStyle("decompile");
    if(!dec.openProgram(currentProgram))
      throw new RuntimeException("Cannot initialize Ghidra");
    byte[] raw=new byte[67*16];
    currentProgram.getMemory().getBytes(toAddr(0x138580L),raw);
    Set<Long> callbacks=new LinkedHashSet<>();
    int missing=0,errors=0;
    try(PrintWriter p=new PrintWriter(new OutputStreamWriter(
        new FileOutputStream(output),StandardCharsets.UTF_8))) {
      p.println("CMD\tFLAGS\tCALLBACK\tDECOMP_OK\tBYTES\tCALL_FUSE\tCALL_QSEE_IS_FUSE\tCALL_BLOW_FUSE\tCALL_QSEE_STOR_READ\tCALL_QSEE_STOR_WRITE\tKM_DEVICE_STATE_TEXT\tNEG15\tDIRECT_CALLS\tCOMMENTS");
      for(int i=0;i<67;i++) {
        int pos=i*16;
        long cmd=uint32(raw,pos),flags=uint32(raw,pos+4),cb=uint64(raw,pos+8);
        callbacks.add(cb);
        Address at=toAddr(cb);
        Function fn=currentProgram.getFunctionManager().getFunctionAt(at);
        if(fn==null) {
          try { fn=createFunction(at,"KM41_REGISTERED_"+Long.toHexString(cmd));}
          catch(Exception ex){}
        }
        if(fn==null)fn=currentProgram.getFunctionManager().getFunctionContaining(at);
        boolean ok=false;
        String source="";
        if(fn!=null) {
          DecompileResults de=dec.decompileFunction(fn,45,monitor);
          if(de.decompileCompleted() && de.getDecompiledFunction()!=null) {
            source=de.getDecompiledFunction().getC();
            ok=true;
          }
        }
        if(!ok){errors++;source="";}
        List<String> calls=new ArrayList<>();
        java.util.regex.Matcher m=java.util.regex.Pattern.compile("FUN_[0-9a-fA-F]{8}").matcher(source);
        while(m.find()){String name=m.group();if(!calls.contains(name))calls.add(name);}
        p.printf(Locale.ROOT,"0x%x\t0x%x\t0x%x\t%b\t%d\t%b\t%b\t%b\t%b\t%b\t%b\t%b\t%s\t%s%n",
          cmd,flags,cb,ok,source.length(),
          source.contains("FUN_00117980"),source.contains("qsee_is_sw_fuse_blown"),
          source.contains("qsee_blow_sw_fuse"),source.contains("qsee_stor_read_sectors"),
          source.contains("qsee_stor_write_sectors"),
          source.contains("KM_DEVICE_STATE")||source.contains("km_device_state"),
          source.contains("0xfffffff1"),
          String.join(",",calls.size()>30?calls.subList(0,30):calls),
          cmd==0x202?"KNOWN_KM_READ":cmd==0x203?"KNOWN_KM_WRITE":
          cmd==0x204?"KNOWN_MILESTONE":cmd==0x10e?"DELETE_KEYS":"");
      }
      p.println("#REGISTERED_CALLBACKS "+callbacks.size());
      p.println("#DECOMPILER_ERRORS "+errors);
      p.flush();
    }finally{dec.dispose();}
    if(errors>4)throw new RuntimeException("Too many decompilation failures: "+errors);
    println("KM41_SECURITY_SURFACE_67_SOURCE_HANDLERS "+callbacks.size()+
            " DECOMP_ERRORS "+errors+" OUTPUT "+output.length());
  }
}
