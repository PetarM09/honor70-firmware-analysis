import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70BoardKM41WriteAndMilestoneAudit extends GhidraScript {
  @Override public void run() throws Exception {
    File dir=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");dir.mkdirs();
    File out=new File(dir,"BOARD_KM41_WRITE_MILESTONE_DECOMPILE.txt");
    PrintWriter p=new PrintWriter(new OutputStreamWriter(new FileOutputStream(out),StandardCharsets.UTF_8));
    DecompInterface dec=new DecompInterface();dec.toggleCCode(true);dec.setSimplificationStyle("decompile");
    try{
      Address write=toAddr(0x118790L);
      Function f=currentProgram.getFunctionManager().getFunctionAt(write);
      if(f==null)try{f=createFunction(write,"KM_WRITE_DEVICE_STATE");}catch(Exception e){p.println("CREATE_FUNC_ERROR "+e.toString());}
      p.println("KM41 FNE-AN00 Board 1.0.0.34 signed Keymaster secure write and fuse checks");
      p.println("WRITE_HANDLER_AT "+write+" PRESENT="+(f!=null));
      long[] targets={0x118790L,0x1184c0L,0x117898L,0x117930L,0x11b08cL,0x11b000L,0x10e11cL,0x10e128L,0x1095c0L,0x1235d8L,0x1235e0L};
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
