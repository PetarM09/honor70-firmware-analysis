import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70KM41ExtraStateHandlerAudit extends GhidraScript {
  public void run() throws Exception {
    File dir=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    dir.mkdirs();
    File output=new File(dir,"HONOR70_KM41_EXTRA_STATE_HANDLERS.txt");
    long[][] targets={
      {0x201L,0x10d4e4L},
      {0x208L,0x10d064L},
      {0x211L,0x10d6d0L},
      {0x200L,0x10e184L},
      {0x205L,0x117ed4L},
      {0x207L,0x10e270L},
      {0x215L,0x10e110L},
      {0x210eL,0x107c48L}
    };
    DecompInterface dec=new DecompInterface();
    dec.toggleCCode(true);
    dec.setSimplificationStyle("decompile");
    if(!dec.openProgram(currentProgram))throw new RuntimeException("Cannot open decompiler");
    try(PrintWriter p=new PrintWriter(new OutputStreamWriter(new FileOutputStream(output),StandardCharsets.UTF_8))) {
      p.println("ORIGINAL FNE-NX9 EEA SIGNED KM41 — 8 additional 67-table callbacks");
      for(long[] entry:targets) {
        long id=entry[0],addr=entry[1];
        Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(addr));
        if(f==null)f=currentProgram.getFunctionManager().getFunctionContaining(toAddr(addr));
        if(f==null)try{f=createFunction(toAddr(addr),"KM_ADDITIONAL_"+Long.toHexString(id));}catch(Exception ignored){}
        if(f==null)f=currentProgram.getFunctionManager().getFunctionAt(toAddr(addr));
        p.printf("===== COMMAND 0x%x HANDLER 0x%x =====%n",id,addr);
        if(f==null){p.println("NO_FUNCTION");continue;}
        DecompileResults r=dec.decompileFunction(f,65,monitor);
        if(!r.decompileCompleted()||r.getDecompiledFunction()==null){
          p.println("DECOMP_ERROR "+r.getErrorMessage());continue;
        }
        String body=r.getDecompiledFunction().getC();
        p.println("HANDLER_BODY_SHA256_UNAVAILABLE_LENGTH "+body.length());
        p.println("FUSE_CALL "+body.contains("FUN_00117980"));
        p.println("STORAGE_WRITE_CALL "+body.contains("qsee_stor_write_sectors"));
        p.println("MILESTONE_OPERATION "+body.contains("qsee_blow_sw_fuse"));
        p.println("BEGIN_PSEUDOCODE");
        p.println(body.length()>40000?body.substring(0,40000):body);
        p.println("END_PSEUDOCODE");
        p.flush();
      }
    }finally{dec.dispose();}
    println("KM41_EEA_EXTRA_STATE_AUDIT_BYTES "+output.length());
  }
}
