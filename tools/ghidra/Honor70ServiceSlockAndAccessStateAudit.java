import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70ServiceSlockAndAccessStateAudit extends GhidraScript {
  @Override public void run() throws Exception {
    File directory=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    directory.mkdirs();
    File report=new File(directory,"HONOR70_EEA_SLOCK_AND_LOCKED_MODE_STATE.txt");
    long[] addresses={
      0x134c0L, 0x13608L, 0x14774L, 0x147dcL, 0x14748L,0x14888L,
      0x14568L,0x19c4cL,0x1545cL,0x19788L,0x27850L
    };
    String[] tokens={"flash:slock","flash:slockv1","oem hwdog certify","slock",
      "unlock key","certify","signature","password","frp-unlock","Device unlock",
      "device unlocked","hwunlock","OEMINFO","unlock critical"};
    SortedSet<Address> targets=new TreeSet<Address>();
    try(PrintWriter out=new PrintWriter(new OutputStreamWriter(new FileOutputStream(report),StandardCharsets.UTF_8))){
      out.println("Read-only Ghidra: exact EEA FNE-N29 8.0.0.290 service authorization and Fastboot whitelist state");
      for(long offset:addresses){
        Address a=toAddr(offset);Function f=currentProgram.getFunctionManager().getFunctionContaining(a);
        out.println("ENTRY "+String.format("0x%x",offset)+" "+(f==null?"NOT_FOUND":f.getEntryPoint()+" "+f.getName()));
        if(f!=null)targets.add(f.getEntryPoint());
      }
      for(MemoryBlock b:currentProgram.getMemory().getBlocks()){
        if(!b.isInitialized()||b.getSize()>12000000)continue;
        byte[] bytes=new byte[(int)b.getSize()];
        int length=currentProgram.getMemory().getBytes(b.getStart(),bytes);
        for(String token:tokens){
          byte[] needle=token.getBytes(StandardCharsets.US_ASCII);
          int count=0;
          for(int i=0;i<=length-needle.length;i++){
            boolean good=true;for(int j=0;j<needle.length;j++)if(bytes[i+j]!=needle[j]){good=false;break;}
            if(!good)continue;
            Address hit=b.getStart().add(i);
            out.println("STRING "+token+" AT "+hit);
            int n=0;
            ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(hit);
            while(it.hasNext()&&n<35){
              Reference ref=it.next();
              Function f=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
              out.println(" XREF "+ref.getFromAddress()+" "+(f==null?"NOFUNC":f.getEntryPoint()));
              if(f!=null)targets.add(f.getEntryPoint());
              n++;
            }
            if(++count==8)break;
          }
        }
      }
      DecompInterface decomp=new DecompInterface();
      decomp.toggleCCode(true);decomp.setSimplificationStyle("decompile");
      if(!decomp.openProgram(currentProgram))throw new RuntimeException("Cannot open current program");
      int count=0;
      for(Address addr:targets){
        if(count++>=45)break;
        Function f=currentProgram.getFunctionManager().getFunctionAt(addr);
        if(f==null)continue;
        out.println("\n====== SERVICE FUNCTION "+f.getEntryPoint()+" "+f.getName()+" SIZE "+f.getBody().getNumAddresses()+" ======");
        DecompileResults r=decomp.decompileFunction(f,30,monitor);
        if(r.decompileCompleted()&&r.getDecompiledFunction()!=null){
          String code=r.getDecompiledFunction().getC();
          out.println(code.substring(0,Math.min(28000,code.length())));
          if(code.length()>28000)out.println("TRUNCATED");
        }else out.println("Ghidra failed: "+r.getErrorMessage());
        out.flush();
      }
      out.println("FUNCTIONS "+count);
      decomp.dispose();
    }
    println("GENERATED "+report+" BYTES="+report.length());
  }
}
