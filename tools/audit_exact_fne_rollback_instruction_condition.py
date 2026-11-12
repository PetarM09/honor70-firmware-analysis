#!/usr/bin/env python3
"""Source-authenticated disassembly of original HONOR 70 proxy-lock rollback.

Pure read-only provenance audit of the actual EEA 8.0.0.290 signed kernel.
Maps the branch that invokes remove_waiter() and the current-task accesses
inside that callee; never generates an exploit trigger.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from elftools.elf.elffile import ELFFile

BOOT_SHA="5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"
KERNEL_SHA="bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
SYMS=("rt_mutex_start_proxy_lock","remove_waiter","rt_mutex_cleanup_proxy_lock")
EXPECTED={
"rt_mutex_start_proxy_lock":0xffffffc01037e2c0,
"remove_waiter":0xffffffc01037e350,
}
DIRECT_CALL=(0xffffffc01037e300,0xffffffc01037e350)
CURRENT_READ=0xffffffc01037e384
CLEAR_AT=0xffffffc01037e3cc

def main():
 p=argparse.ArgumentParser()
 for name in ("boot","kernel","elf","out"):p.add_argument("--"+name,required=True,type=Path)
 a=p.parse_args()
 if hashlib.sha256(a.boot.read_bytes()).hexdigest()!=BOOT_SHA:raise ValueError("Exact signed retail boot mismatch")
 if hashlib.sha256(a.kernel.read_bytes()).hexdigest()!=KERNEL_SHA:raise ValueError("Exact EEA kernel mismatch")
 symbols=subprocess.run(["nm","-n","--defined-only",str(a.elf)],capture_output=True,text=True,check=True).stdout
 sym={}
 for line in symbols.splitlines():
  m=re.fullmatch(r"([0-9a-fA-F]+)\s+[Tt]\s+(\S+)",line)
  if m and m.group(2) in SYMS:sym[m.group(2)]=int(m.group(1),16)
 for n,addr in EXPECTED.items():
  if sym.get(n)!=addr:raise ValueError("Original vulnerable kernel symbol moved "+n)
 md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
 md.detail=False
 functions={}
 with a.elf.open("rb") as f:
  elf=ELFFile(f)
  segments=[(int(s["p_vaddr"]),int(s["p_offset"]),int(s["p_filesz"])) for s in elf.iter_segments()
            if s["p_type"]=="PT_LOAD" and int(s["p_flags"])&1]
  for name in SYMS:
   addr=sym.get(name)
   if addr is None:raise RuntimeError("Original kernel symbol absent "+name)
   sg=next(((base,off,size) for base,off,size in segments if base<=addr<base+size),None)
   if sg is None:raise RuntimeError("No executable segment "+name)
   base,off,size=sg
   # A small bounded disassembly source window only, not a driver or exploit.
   window={"rt_mutex_start_proxy_lock":0x90,
           "remove_waiter":0x250,
           "rt_mutex_cleanup_proxy_lock":0x180}[name]
   f.seek(off+addr-base)
   code=f.read(min(size-(addr-base),window))
   ins=[{"addr":hex(i.address),"mnemonic":i.mnemonic,"op_str":i.op_str}
        for i in md.disasm(code,addr)]
   functions[name]={"vaddr":hex(addr),"instructions":ins}
 every={int(i["addr"],16):i for fn in functions.values() for i in fn["instructions"]}
 call=every.get(DIRECT_CALL[0])
 if call is None or call["mnemonic"]!="bl" or int(call["op_str"].strip().lstrip("#"),0)!=DIRECT_CALL[1]:
  raise ValueError("Source original rollback direct call absent")
 branch_assertions={
  0xffffffc01037e2f0:("cbz","w0, #0xffffffc01037e320"),
  0xffffffc01037e2f4:("mov","w21, #1"),
  0xffffffc01037e2f8:("mov","x0, x19"),
  0xffffffc01037e2fc:("mov","x1, x20"),
  0xffffffc01037e338:("cbz","w0, #0xffffffc01037e304"),
  0xffffffc01037e33c:("ldr","x8, [x19, #0x18]"),
  0xffffffc01037e340:("cmp","x8, #2"),
  0xffffffc01037e344:("b.hs","#0xffffffc01037e2f8")
 }
 for address,(mnemonic,operand) in branch_assertions.items():
  instruction=every.get(address)
  if instruction is None or instruction["mnemonic"]!=mnemonic or instruction["op_str"]!=operand:
   raise ValueError("Signed original rollback mismatch "+hex(address)+" actual "+str(instruction))
 current=every.get(CURRENT_READ)
 if current is None or current["mnemonic"]!="mrs" or "sp_el0" not in current["op_str"]:
  raise ValueError("Known source current task pointer operation absent")
 clearing=every.get(CLEAR_AT)
 if clearing is None or clearing["mnemonic"]!="str" or "[x20, #0x990]" not in clearing["op_str"]:
  raise ValueError("Known source current task pi_blocked_on clearing absent")
 result={
  "source":"signed stock FNE-NX9 C431 8.0.0.290 exact kernel machine code",
  "stock_boot_sha256":BOOT_SHA,"extracted_kernel_sha256":KERNEL_SHA,
  "orig_signed_functions":functions,
  "signed_original_proxy_rollback_direct_call_validated":True,
  "byte_verified_rollback_predicates":{hex(a):m+" "+o for a,(m,o) in branch_assertions.items()},
  "signed_original_remove_waiter_current_use_validated":True,
  "current_task_pi_blocked_on_clear_machine_code":"str xzr, [x20, #0x990]",
  "relevant_offline_assessment":"The original code has the proxy-lock -> remove_waiter call and removes current task's PI state; exact triggering conditions not measured on the phone.",
  "does_not_establish":["userland reachable UAF conditions","working privilege escalation","Keymaster/RPMB unlock","persistence across reboot"],
  "device_operations":0
 }
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,indent=2)+"\n")
 print("ORIGINAL_PROXY_LOCK_ROLLBACK")
 for n,fn in functions.items():
  print("===== ORIG_FUNCTION",n,fn["vaddr"])
  for i in fn["instructions"]:
   print(i["addr"],i["mnemonic"],i["op_str"])
 print("EXACT_ROLLBACK_PREDICATES_ASSERTED",len(branch_assertions))
 print("VULNERABLE_SOURCE_PATTERN_ASSERTED",True)
if __name__=="__main__":main()
