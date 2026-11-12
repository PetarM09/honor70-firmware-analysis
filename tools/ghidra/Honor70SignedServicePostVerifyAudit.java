import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70SignedServicePostVerifyAudit extends GhidraScript {
  @Override public void run() throws Exception {
    File d=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");d.mkdirs();
    File out=new File(d,"HONOR70_SLOCK_RDMODE_POSTVERIFY_BRANCHES.txt");
    long[] addresses={0x15b08L,0x1381cL,0x17a0cL,0x17ca4L,0x17e30L,
                      0x13d58L,0x136a4L,0x13008L,0x43688L,
                      0x1647cL,0x15334L,0x80e0cL};
    DecompInterface dec=new DecompInterface();
    dec.toggleCCode(true);dec.setSimplificationStyle("decompile");
    if(!dec.openProgram(currentProgram))throw new RuntimeException("Could not initialize decompiler");
    try(PrintWriter w=new PrintWriter(new OutputStreamWriter(new FileOutputStream(out),StandardCharsets.UTF_8))){
      w.println("SIGNED EEA HONOR70 FNE-NX9: SLock/RDMode post-verification state writes");
      w.println("Code inspection only; never invoke functions or write live OEMINFO");
      for(long address:addresses){
        Address a=toAddr(address);
        Function f=currentProgram.getFunctionManager().getFunctionContaining(a);
        w.println("\n===== POSTVERIFY_TARGET "+String.format("%08x",address)+" =====");
        if(f==null){w.println("FUNCTION_MISSING");continue;}
        w.println("FUNC_ENTRY "+f.getEntryPoint()+" NAME "+f.getName()+" BYTECOUNT "+f.getBody().getNumAddresses());
        ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        int n=0;
        while(refs.hasNext()&&n<40){
          Reference r=refs.next();Function caller=currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
          w.println("CALLER "+r.getFromAddress()+" WITHIN "+(caller==null?"none":caller.getEntryPoint()));
          n++;
        }
        DecompileResults x=dec.decompileFunction(f,65,monitor);
        if(x.decompileCompleted()&&x.getDecompiledFunction()!=null){
          String code=x.getDecompiledFunction().getC();
          w.println("DECOMP_BEGIN");
          w.println(code.length()>60000?code.substring(0,60000)+"\nTRUNCATED":code);
          w.println("DECOMP_END");
        }else w.println("DECOMP_ERROR "+x.getErrorMessage());
        w.flush();
      }
    }
    dec.dispose();
    println("POSTVERIFY_REPORT_BYTES "+out.length());
  }
}
