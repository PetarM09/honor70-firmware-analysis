import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70KM41CommandTableAudit extends GhidraScript {
  private long u32(byte[] a,int i){
    return ((long)(a[i]&255))|((long)(a[i+1]&255)<<8)|((long)(a[i+2]&255)<<16)|((long)(a[i+3]&255)<<24);
  }
  private long u64(byte[] a,int i){return (u32(a,i)&0xffffffffL)|((u32(a,i+4)&0xffffffffL)<<32);}
  private void decompile(PrintWriter p,DecompInterface iface, long addr,String label) {
    Address a=toAddr(addr);
    Function f=currentProgram.getFunctionManager().getFunctionAt(a);
    if(f==null)f=currentProgram.getFunctionManager().getFunctionContaining(a);
    p.println("\n====== DECOMPILE "+label+" TARGET "+a+" ======");
    if(f==null){p.println("No recovered function");return;}
    p.println("Function "+f.getName()+" AT "+f.getEntryPoint()+" body="+f.getBody().getNumAddresses());
    DecompileResults r=iface.decompileFunction(f,26,monitor);
    if(r.decompileCompleted()&&r.getDecompiledFunction()!=null){
      String code=r.getDecompiledFunction().getC();
      p.println(code.length()>22000?code.substring(0,22000):code);
    }else p.println("FAIL "+r.getErrorMessage());
  }
  @Override public void run() throws Exception {
    File dir=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    dir.mkdirs();File out=new File(dir,"KM41_COMMAND_TABLE_AND_MILESTONE.txt");
    Set<Long> handlers=new LinkedHashSet<>();
    try(PrintWriter p=new PrintWriter(new OutputStreamWriter(new FileOutputStream(out),StandardCharsets.UTF_8))){
      p.println("HONOR70 FNE-NX9 8.0.0.290 signed km41.mbn command table; read-only.");
      p.println("GHIDRA BASE "+currentProgram.getImageBase());
      long[] cmds={0x202,0x203,0x204,0x2202,0x2203,0x2204};
      for(MemoryBlock block:currentProgram.getMemory().getBlocks()) {
        if(!block.isInitialized()||block.getSize()>1500000)continue;
        byte[] b=new byte[(int)block.getSize()];
        int n=currentProgram.getMemory().getBytes(block.getStart(),b);
        for(int k=0;k<=n-16;k+=4){
          long cmd=u32(b,k);
          boolean targeted=false;
          for(long c:cmds)if(cmd==c){targeted=true;break;}
          if(!targeted)continue;
          Address a=block.getStart().add(k);
          long flags=u32(b,k+4), rawFunc=u64(b,k+8);
          long[] opts={rawFunc,rawFunc+0x100000L};
          boolean handlerExists=false;
          for(long h:opts){
            try{
              Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(h));
              if(f!=null){handlerExists=true;handlers.add(h);break;}
            }catch(Exception ex){}
          }
          if(handlerExists || (k+32<n && u32(b,k+16)==cmd+1)){
            p.println(String.format("TABLE_ENTRY addr=%s cmd=0x%x flags=0x%x handler_raw=0x%x resolved=%s",a,cmd,flags,rawFunc,handlerExists));
            for(int q=-32;q<=48;q+=16) {
              int o=k+q;if(o<0||o+16>n)continue;
              p.println(String.format("  SLOT %+d command=0x%x flags=0x%x callback=0x%x",q,u32(b,o),u32(b,o+4),u64(b,o+8)));
            }
          }
        }
      }
      DecompInterface decomp=new DecompInterface();decomp.toggleCCode(true);decomp.setSimplificationStyle("decompile");decomp.openProgram(currentProgram);
      long[] targets={0x12366cL,0x123674L,0x10e144L,0x10e128L,0x11b174L,0x11b0e8L,0x117980L,0x117a18L,0x109628L};
      for(long target:targets)decompile(p,decomp,target,"SUPPORT");
      for(long target:handlers)decompile(p,decomp,target,"KM_DEVICE_STATE_CALLBACK");
      decomp.dispose();
    }
    println("KM41 command table report bytes "+out.length());
  }
}
