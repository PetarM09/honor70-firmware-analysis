// Read-only decompilation of the signed HONOR70 XBL VerifiedBootDxe (61,440 bytes).
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class Honor70VerifiedBootDxeAudit extends GhidraScript {
  @Override
  public void run() throws Exception {
    File dir=new File(System.getenv("GITHUB_WORKSPACE")+"/report");
    dir.mkdirs();
    File out=new File(dir,"VERIFIEDBOOT_DXE_GHIDRA.txt");
    String[] args=getScriptArgs();
    long guidRva=args.length>0?Long.decode(args[0]):0xd0a8L;
    long entryRva=args.length>1?Long.decode(args[1]):0L;
    try(PrintWriter p=new PrintWriter(new OutputStreamWriter(new FileOutputStream(out),"UTF-8"))){
      p.println("HONOR70 8.0.0.290 XBL VerifiedBootDxe - read-only static decompiler");
      p.println("Program "+currentProgram.getName()+" imagebase "+currentProgram.getImageBase());
      Address guid=currentProgram.getImageBase().add(guidRva);
      Address entry=currentProgram.getImageBase().add(entryRva);
      p.println("GUID_RVA "+Long.toHexString(guidRva)+" address "+guid);
      p.println("ENTRY_RVA "+Long.toHexString(entryRva)+" address "+entry);
      ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(guid);
      p.println("==== GUID REFERENCES ====");
      int count=0;
      while(refs.hasNext() && count++<70){
        Reference ref=refs.next();
        Function f=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
        p.println(ref.getFromAddress()+" "+ref.getReferenceType()+" in "+(f==null?"UNKNOWN":f.getName()+" "+f.getEntryPoint()));
      }
      DecompInterface di=new DecompInterface();
      di.toggleCCode(true);
      di.setSimplificationStyle("decompile");
      if(!di.openProgram(currentProgram)){p.println("DECOMPILER OPEN ERROR");return;}
      FunctionManager fm=currentProgram.getFunctionManager();
      List<Function> functions=new ArrayList<>();
      FunctionIterator fit=fm.getFunctions(true);
      while(fit.hasNext() && functions.size()<550)functions.add(fit.next());
      p.println("DISCOVERED_FUNCTIONS "+functions.size());
      for(Function f:functions){
        p.println("\n======== FUNCTION "+f.getEntryPoint()+" "+f.getName()+" size="+f.getBody().getNumAddresses()+" ========");
        DecompileResults r=di.decompileFunction(f,12,monitor);
        if(r.decompileCompleted() && r.getDecompiledFunction()!=null){
          String code=r.getDecompiledFunction().getC();
          if(code.length()>12000)code=code.substring(0,12000)+"\n...[TRUNCATED]";
          p.println(code);
        }else{
          p.println("FAILED: "+r.getErrorMessage());
        }
      }
      di.dispose();
    }
    println("VerifiedBootDxe report ready: "+out.getAbsolutePath()+" bytes="+out.length());
  }
}
