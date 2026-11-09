import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Honor70KeymasterMilestoneAudit extends GhidraScript {
  private void addFunction(Set<Address> addresses, Address addr) {
    Function f=currentProgram.getFunctionManager().getFunctionContaining(addr);
    if(f!=null) addresses.add(f.getEntryPoint());
  }
  @Override
  public void run() throws Exception {
    File folder=new File(System.getenv("GITHUB_WORKSPACE")+"/analysis");
    folder.mkdirs();
    File output=new File(folder,"KM41_MILESTONE_SECURITY_MAP.txt");
    String[] tokens={"READ_KM_DEVICE_STATE","WRITE_KM_DEVICE_STATE","MILESTONE_CALL","KM_NEW_READ_KM_DEVICE_STATE","KM_NEW_WRITE_KM_DEVICE_STATE","KM_NEW_MILESTONE_CALL","km_set_milestone","is_unlocked","UNLOCKED_DEVICE_REQUIRED","qsee_get_secure_state","RPMB not provisioned"};
    Set<Address> interesting=new TreeSet<>();
    Set<Address> direct=new TreeSet<>();
    int allFunctions=0;
    try(PrintWriter p=new PrintWriter(new OutputStreamWriter(new FileOutputStream(output),StandardCharsets.UTF_8))) {
      p.println("READ-ONLY KM41 MILESTONE AUDIT ON STOCK SIGNED HONOR70 8.0.0.290");
      p.println("PROGRAM "+currentProgram.getName()+" IMAGE_BASE "+currentProgram.getImageBase());
      Memory memory=currentProgram.getMemory();
      for(MemoryBlock block:memory.getBlocks()) {
        if(!block.isInitialized()||block.getSize()>3000000) continue;
        byte[] buf=new byte[(int)block.getSize()];
        int read=memory.getBytes(block.getStart(),buf);
        p.println("MEMORY_BLOCK "+block.getName()+" start="+block.getStart()+" size="+read);
        for(String token:tokens) {
          byte[] needle=token.getBytes(StandardCharsets.US_ASCII);
          int count=0;
          for(int off=0;off<=read-needle.length;off++) {
            boolean match=true;
            for(int j=0;j<needle.length;j++)if(buf[off+j]!=needle[j]){match=false;break;}
            if(!match) continue;
            Address a=block.getStart().add(off);
            p.println("STRING "+token+" AT "+a);
            count++;
            ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(a);
            int references=0;
            while(refs.hasNext()) {
              Reference ref=refs.next();
              p.println("  REF "+ref.getFromAddress()+" type="+ref.getReferenceType());
              addFunction(interesting,ref.getFromAddress());
              references++;
              if(references>=35)break;
            }
            if(count>=25) break;
          }
        }
      }
      p.println("\n===== INSTRUCTION CONSTANTS (command ids 0x202 0x203 / milestone vicinity) =====");
      InstructionIterator it=currentProgram.getListing().getInstructions(true);
      int instructionCount=0,printed=0;
      while(it.hasNext()) {
        Instruction in=it.next();
        instructionCount++;
        String mnem=in.getMnemonicString().toLowerCase();
        if(!(mnem.startsWith("cmp")||mnem.startsWith("mov")||mnem.startsWith("subs")||mnem.startsWith("add")||mnem.startsWith("sub")))continue;
        for(int idx=0;idx<in.getNumOperands();idx++){
          Scalar sc=in.getScalar(idx);
          if(sc==null)continue;
          long val=sc.getUnsignedValue();
          if(val==0x202||val==0x203||val==0x204||val==0x205||val==0x206||val==0x207||val==0x208){
            p.println("IMMEDIATE "+in.getAddress()+" "+in+" value="+Long.toHexString(val));
            addFunction(interesting,in.getAddress());
            printed++;
            break;
          }
        }
      }
      p.println("INSTRUCTIONS "+instructionCount+" IMMEDIATE_MATCHES "+printed);
      // Add caller functions for a one-hop view into authorization and state changes.
      direct.addAll(interesting);
      int added=0;
      for(Address address:direct){
        ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(address);
        while(refs.hasNext()&&added<250){
          Reference ref=refs.next();
          Function fn=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
          if(fn!=null && interesting.add(fn.getEntryPoint()))added++;
        }
      }
      FunctionIterator fiter=currentProgram.getFunctionManager().getFunctions(true);
      while(fiter.hasNext()){fiter.next();allFunctions++;}
      p.println("GHIDRA_FUNCTION_COUNT "+allFunctions+" SELECTED "+interesting.size()+" DIRECT "+direct.size());
      DecompInterface iface=new DecompInterface();
      iface.toggleCCode(true);
      iface.setSimplificationStyle("decompile");
      iface.openProgram(currentProgram);
      int num=0;
      for(Address addr:interesting) {
        if(num++>150)break;
        Function f=currentProgram.getFunctionManager().getFunctionAt(addr);
        if(f==null)continue;
        p.println("\n======== FUNCTION "+f.getEntryPoint()+" "+f.getName()+" BODY "+f.getBody().getNumAddresses()+" ========");
        DecompileResults result=iface.decompileFunction(f,25,monitor);
        if(result.decompileCompleted()&&result.getDecompiledFunction()!=null){
          String code=result.getDecompiledFunction().getC();
          p.println(code.length()>24000?code.substring(0,24000)+" [TRUNCATED]":code);
        } else p.println("DECOMPILATION_ERROR "+result.getErrorMessage());
      }
      iface.dispose();
    }
    println("KM41 OUT "+output.getAbsolutePath()+" bytes="+output.length());
  }
}
