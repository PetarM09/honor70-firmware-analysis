import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70KM41WriteAndMilestoneAudit extends GhidraScript {
  @Override public void run() throws Exception {
    File dir=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");dir.mkdirs();
    File out=new File(dir,"KM41_WRITE_MILESTONE_DECOMPILE.txt");
    PrintWriter p=new PrintWriter(new OutputStreamWriter(new FileOutputStream(out),StandardCharsets.UTF_8));
    DecompInterface dec=new DecompInterface();dec.toggleCCode(true);dec.setSimplificationStyle("decompile");
    try{
      Address write=toAddr(0x118878L);
      Function f=currentProgram.getFunctionManager().getFunctionAt(write);
      if(f==null)try{f=createFunction(write,"KM_WRITE_DEVICE_STATE");}catch(Exception e){p.println("CREATE_FUNC_ERROR "+e.toString());}
      p.println("KM41 FNE-NX9 exact write state decompilation and milestone gate");
      p.println("WRITE_HANDLER_AT "+write+" PRESENT="+(f!=null));
      long[] targets={0x118878L,0x1185a8L,0x117980L,0x117a18L,0x11b174L,0x11b0e8L,0x10e144L,0x10e128L,0x109628L,0x12366cL,0x123674L};
      if(!dec.openProgram(currentProgram)){p.println("Could not initialize decompiler");return;}
      for(long target:targets){
        Address addr=toAddr(target);
        Function targetF=currentProgram.getFunctionManager().getFunctionAt(addr);
        if(targetF==null)targetF=currentProgram.getFunctionManager().getFunctionContaining(addr);
        p.println("\n===== TARGET "+Long.toHexString(target)+" =====");
        if(targetF==null){p.println("MISSING_FUNCTION");continue;}
        p.println("ENTRY "+targetF.getEntryPoint()+" BODY "+targetF.getBody().getNumAddresses());
        DecompileResults d=dec.decompileFunction(targetF,35,monitor);
        if(d.decompileCompleted() && d.getDecompiledFunction()!=null){
          String code=d.getDecompiledFunction().getC();
          p.println(code.length()>40000?code.substring(0,40000):code);
        }else p.println("ERROR "+d.getErrorMessage());
      }
    }finally{dec.dispose();p.close();}
    println("SAVED "+out.getAbsolutePath()+" bytes="+out.length());
  }
}
