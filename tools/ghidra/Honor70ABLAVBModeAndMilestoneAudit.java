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

public class Honor70ABLAVBModeAndMilestoneAudit extends GhidraScript {
  @Override public void run() throws Exception {
    File folder=new File(System.getenv("GITHUB_WORKSPACE")+"/report");folder.mkdirs();
    File out=new File(folder,"HONOR70_ABL_VERIFIED_BOOT_MILESTONE_XREF.txt");
    Set<Address> selected=new TreeSet<>();
    String[] tokens={"Sending Milestone Call","Error sending milestone call to TZ",
       "NoAVBLoad_fw_ufsdev","LoadImageAndAuthVB2","vbmeta","VB2: boot state",
       "Is_VERIFIED_BOOT_2","get_unlock_ability"};
    long[] targetAddresses={0x70a4L,0x7150L,0x7970L,0x540cL,0x240c8L};
    try(PrintWriter p=new PrintWriter(new OutputStreamWriter(new FileOutputStream(out),StandardCharsets.UTF_8))){
      p.println("HONOR70 FNE-NX9 8.0.0.290 LinuxLoader AVB-selection and Keymaster milestone callsite audit");
      p.println("Image base "+currentProgram.getImageBase());
      for(long offset:targetAddresses){Function f=currentProgram.getFunctionManager().getFunctionContaining(toAddr(offset));if(f!=null)selected.add(f.getEntryPoint());}
      for(MemoryBlock block:currentProgram.getMemory().getBlocks()){
        if(!block.isInitialized()||block.getSize()>10000000)continue;
        byte[] b=new byte[(int)block.getSize()];int n=currentProgram.getMemory().getBytes(block.getStart(),b);
        for(String token:tokens){
          byte[] needle=token.getBytes(StandardCharsets.UTF_8);int count=0;
          for(int i=0;i<=n-needle.length;i++){
            boolean match=true;for(int j=0;j<needle.length;j++)if(b[i+j]!=needle[j]){match=false;break;}
            if(!match)continue;
            Address at=block.getStart().add(i);
            p.println("STRING "+token+" LOCATION "+at);
            ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(at);
            int rc=0;
            while(refs.hasNext()&&rc<50){
              Reference ref=refs.next();
              Function f=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
              p.println("  XREF "+ref.getFromAddress()+" TYPE "+ref.getReferenceType()+" FUNCTION "+(f==null?"UNKNOWN":f.getEntryPoint()));
              if(f!=null)selected.add(f.getEntryPoint());
              rc++;
            }
            p.println("REFERENCE_COUNT "+rc);
            if(++count>=14)break;
          }
        }
      }
      int imms=0;
      InstructionIterator iter=currentProgram.getListing().getInstructions(true);
      while(iter.hasNext()){
        Instruction in=iter.next();
        if(!in.getMnemonicString().toLowerCase().startsWith("mov") &&
           !in.getMnemonicString().toLowerCase().startsWith("cmp"))continue;
        for(int i=0;i<in.getNumOperands();i++){
          Scalar imm=in.getScalar(i);
          if(imm==null)continue;
          long v=imm.getUnsignedValue();
          if(v==0x204||v==0x2204){
            Function fn=currentProgram.getFunctionManager().getFunctionContaining(in.getAddress());
            p.println("IMMEDIATE "+in.getAddress()+" "+in+" FUNCTION "+(fn==null?"UNKNOWN":fn.getEntryPoint()));
            if(fn!=null)selected.add(fn.getEntryPoint());
            if(++imms>=150)break;
          }
        }
      }
      p.println("MILESTONE_CMD_IMMEDIATES "+imms+" SELECTED_FUNCTION_COUNT "+selected.size());
      DecompInterface decomp=new DecompInterface();
      decomp.toggleCCode(true);
      decomp.setSimplificationStyle("decompile");
      decomp.openProgram(currentProgram);
      int n=0;
      for(Address at:selected){
        if(n++>=90)break;
        Function f=currentProgram.getFunctionManager().getFunctionAt(at);
        if(f==null)continue;
        p.println("\n========== TARGET "+at+" FUNCTION "+f.getName()+" SIZE "+f.getBody().getNumAddresses()+" ==========");
        DecompileResults d=decomp.decompileFunction(f,28,monitor);
        if(d.decompileCompleted()&&d.getDecompiledFunction()!=null){
          String code=d.getDecompiledFunction().getC();
          p.println(code.length()>33000?code.substring(0,33000):code);
        }else p.println("DECOMPILE_FAILED "+d.getErrorMessage());
      }
      decomp.dispose();
    }
    println("ABL verifiedboot milestone report bytes "+out.length());
  }
}
