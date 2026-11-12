#!/usr/bin/env python3
"""Read-only, signed-source EEA HONOR70 'remove_waiter' kernel symbol audit.

Input is an ELF reconstructed from the original SHA-verified kernel in
FNE-NX9 C431 MagicOS 8.0.0.290; this script does not build/exercise an
exploit, derive corruption offsets or interact with a device.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from elftools.elf.elffile import ELFFile

KERNEL_SHA="bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
BOOT_SHA="5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--boot",type=Path,required=True)
 p.add_argument("--kernel",type=Path,required=True)
 p.add_argument("--elf",type=Path,required=True)
 p.add_argument("--out",type=Path,required=True)
 a=p.parse_args()
 boot=a.boot.read_bytes()
 raw=a.kernel.read_bytes()
 if hashlib.sha256(boot).hexdigest()!=BOOT_SHA:raise ValueError("Wrong stock EEA boot.img")
 if hashlib.sha256(raw).hexdigest()!=KERNEL_SHA:raise ValueError("Wrong stock EEA kernel")
 r=subprocess.run(["nm","-n","--defined-only",str(a.elf)],capture_output=True,text=True,check=True)
 syms=[]
 for line in r.stdout.splitlines():
  m=re.match(r"^([0-9a-fA-F]+)\s+([tT])\s+(\S+)$",line)
  if m and (m.group(3)=="remove_waiter" or m.group(3).startswith("remove_waiter$") or m.group(3).startswith("futex_wait_requeue_pi")):
   syms.append({"vaddr":int(m.group(1),16),"type":m.group(2),"symbol":m.group(3)})
 if not syms:raise ValueError("No source symbol named remove_waiter/futex_wait_requeue_pi recovered")
 with a.elf.open("rb") as f:
  ef=ELFFile(f)
  seg=[{"v":int(x["p_vaddr"]),"off":int(x["p_offset"]),"size":int(x["p_filesz"]),"flags":int(x["p_flags"])}
       for x in ef.iter_segments() if x["p_type"]=="PT_LOAD"]
  efsize=a.elf.stat().st_size
  frames=[]
  md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
  md.detail=False
  for entry in syms:
   segx=next((x for x in seg if x["v"]<=entry["vaddr"]<x["v"]+x["size"] and x["flags"]&1),None)
   if segx is None:
    entry["location"]="not-in-PT_LOAD-executable"
    continue
   f.seek(segx["off"]+entry["vaddr"]-segx["v"])
   code=f.read(384)
   decoded=[{"addr":hex(z.address),"mnemonic":z.mnemonic,"operands":z.op_str}
            for z in md.disasm(code,entry["vaddr"])]
   entry["decoded_instructions"]=decoded
   entry["load_segment_base"]=hex(segx["v"])
   entry["sp_el0_reads"]=sum(1 for z in decoded if "sp_el0" in z["operands"])
   entry["branch_calls"]=sum(1 for z in decoded if z["mnemonic"]=="bl")
  chosen=[x for x in syms if "remove_waiter" in x["symbol"]]
  if not chosen:raise ValueError("Original signed kernel has no remove_waiter in nm")
  if not any(x.get("sp_el0_reads",0)>0 for x in chosen):
   raise ValueError("Original exact remove_waiter source lacks expected current pointer read")
  if any(x["decoded_instructions"][0]["mnemonic"]=="udf" for x in chosen):
   raise ValueError("NOBITS/data incorrectly disassembled as source code")
  result={
   "source":"HONOR70 FNE-NX9 signed original 8.0.0.290 EEA kernel, independently SHA-verified",
   "stock_boot_sha256":BOOT_SHA,
   "stock_kernel_sha256":KERNEL_SHA,
   "vmlinux_elf_sha256":hashlib.sha256(a.elf.read_bytes()).hexdigest(),
   "interesting_exact_symbol_instances":syms,
   "remove_waiter_reads_sp_el0_current_register":True,
   "source_interpretation_limits":[
      "Kernel disassembly proves machine instructions at recovered symbol addresses, not exploitability.",
      "A recovered symbol may have compiler suffix and a Ghidra/capstone window may cross into other functions.",
      "A suspected vulnerable primitive does not prove arbitrary writes or safe successful root.",
      "No kernel physical base, task_struct offsets or usable exploit parameters are derived.",
      "Even a working temporary kernel root would not equal a persistent Keymaster/RPMB bootloader unlock."
   ],
   "execute_exploit":False,
   "permanent_unlock_demonstrated":False
  }
  a.out.parent.mkdir(parents=True,exist_ok=True)
  a.out.write_text(json.dumps(result,indent=2)+"\n")
  print("SIGNED_EEA_KERNEL_MATCH",KERNEL_SHA)
  print("RECOVERED_REMOVE_WAITER_COUNT",len(chosen))
  print("MATCHED_SOURCE_REMOVE_WAITER_READS_CURRENT_FROM_SP_EL0",True)
  for entry in syms:
   print("SOURCE_SYMBOL",entry["symbol"],hex(entry["vaddr"]),"SP_EL0_READS",entry.get("sp_el0_reads",0))
   print("SOURCE_ARM64_PREVIEW",json.dumps(entry.get("decoded_instructions",[])[:40]))
  print("SIGNED_KERNEL_STATIC_CODE_REVIEW_COMPLETE")
if __name__=="__main__":main()
