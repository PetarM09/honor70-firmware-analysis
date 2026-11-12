#!/usr/bin/env python3
"""Identify CVE-2026-43499 proxy-lock prerequisite in exact C431 kernel.

No exploit creation. This audits a SHA-verified stock kernel vmlinux,
symbol names, executable code and direct callsites. Original source is
compared to Linux kernel official CVE summary.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

BOOT_SHA="5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"
KERNEL_SHA="bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
SYMBOL_PATTERNS=[
 r"^remove_waiter(?:\$.*)?$",
 r"^rt_mutex_start_proxy_lock(?:\$.*)?$",
 r"^futex_requeue(?:\$.*)?$",
 r"^futex_wait_requeue_pi(?:\$.*)?$",
 r"^__arm64_sys_futex(?:\$.*)?$",
 r"^rt_mutex_adjust_prio_chain(?:\$.*)?$"
]

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--boot",required=True,type=Path)
 p.add_argument("--kernel",required=True,type=Path)
 p.add_argument("--elf",required=True,type=Path)
 p.add_argument("--output",required=True,type=Path)
 a=p.parse_args()
 if hashlib.sha256(a.boot.read_bytes()).hexdigest()!=BOOT_SHA:
  raise RuntimeError("Stock boot SHA mismatch")
 if hashlib.sha256(a.kernel.read_bytes()).hexdigest()!=KERNEL_SHA:
  raise RuntimeError("Stock kernel SHA mismatch")
 output=subprocess.run(["nm","-n","--defined-only",str(a.elf)],capture_output=True,text=True,check=True)
 symbols=[]
 for line in output.stdout.splitlines():
  m=re.match(r"^([0-9a-f]+)\s+([Tt])\s+(\S+)$",line,re.I)
  if m:
   addr=int(m.group(1),16)
   symbols.append({"address":addr,"name":m.group(3)})
 symbols.sort(key=lambda r:r["address"])
 chosen={}
 for pattern in SYMBOL_PATTERNS:
  hits=[x for x in symbols if re.match(pattern,x["name"])]
  chosen[pattern]=hits[:12]
 if not chosen[SYMBOL_PATTERNS[0]]:
  raise RuntimeError("Missing canonical remove_waiter symbol")
 md=Cs(CS_ARCH_ARM64,CS_MODE_ARM);md.detail=True
 with a.elf.open("rb") as fd:
  elf=ELFFile(fd)
  segs=[{"v":int(s["p_vaddr"]),"size":int(s["p_filesz"]), "offset":int(s["p_offset"])}
     for s in elf.iter_segments() if s["p_type"]=="PT_LOAD" and int(s["p_flags"])&1]
  def read_code(addr,maxbytes=2048):
   for seg in segs:
    if seg["v"]<=addr<seg["v"]+seg["size"]:
     allowed=min(maxbytes,seg["v"]+seg["size"]-addr)
     fd.seek(seg["offset"]+addr-seg["v"])
     return fd.read(allowed)
   return b""
  dis={}
  for pattern,syms in chosen.items():
   for row in syms[:8]:
    addr=row["address"]
    following=next((s["address"] for s in symbols if s["address"]>addr),addr+512)
    size=min(2048,max(128,following-addr))
    ins=list(md.disasm(read_code(addr,size),addr))
    entries=[]
    for x in ins:
     if x.mnemonic=="bl" and len(x.operands) and x.operands[0].type==ARM64_OP_IMM:
      entries.append({"from":hex(x.address),"target":hex(x.operands[0].imm)})
    dis[row["name"]]={
     "entry":hex(addr),
     "estimated_code_bytes":size,
     "decoded_count":len(ins),
     "sp_el0_reads":[hex(x.address) for x in ins if x.mnemonic=="mrs" and "sp_el0" in x.op_str],
     "bl_targets":entries[:120],
     "first_20":[f"{x.address:#x} {x.mnemonic} {x.op_str}" for x in ins[:20]]
    }
  remove_entries=[v for k,v in dis.items() if k=="remove_waiter"]
  if not remove_entries or not remove_entries[0]["sp_el0_reads"]:
   raise RuntimeError("Source identity check: expected current-pointer read not found")
  remove_addr=int(remove_entries[0]["entry"],16)
  caller_hits=[]
  for name,obj in dis.items():
   if name.startswith("remove_waiter"):continue
   sites=[c for c in obj["bl_targets"] if int(c["target"],16)==remove_addr]
   if sites:caller_hits.append({"function":name,"call_sites":sites})
  report={
   "source":"Signed original C431 8.0.0.290 HONOR FNE-NX9 kernel read-only ARM64",
   "stock_boot_sha256":BOOT_SHA,"stock_kernel_sha256":KERNEL_SHA,
   "symbols":{k:v for k,v in chosen.items()},
   "function_disassembly":dis,
   "direct_calls_to_remove_waiter_in_selected_functions":caller_hits,
   "observed_remove_waiter_reads_current_via_sp_el0":True,
   "vulnerability_exploitable_proven":False,
   "successful_root_or_persistent_bootloader_unlock":False,
   "limitations":[
     "A short list of symbol callsites is not the complete CFG; inlining and indirect calls are not ruled out.",
     "CVE exposure depends on the actual proxy-lock rollback path and runtime conditions.",
     "No UAF trigger, write primitive, attack script, device test or privilege escalation was executed.",
     "Secure Keymaster/RPMB and software milestone remain separate from Android kernel code."
   ]
  }
  a.output.parent.mkdir(parents=True,exist_ok=True)
  a.output.write_text(json.dumps(report,indent=2)+"\n")
  print("EXACT_STOCK_SIGNED_KERNEL_SHA",KERNEL_SHA)
  for pat,rows in chosen.items():
   print("SYMBOLS_MATCH",pat,len(rows),[(x["name"],hex(x["address"])) for x in rows[:5]])
  for name,entry in dis.items():
   print("SOURCE_CODE_ENTRY",name,entry["entry"],"CURRENT_MRS",entry["sp_el0_reads"],
         "CALLS",[(x["from"],x["target"]) for x in entry["bl_targets"][:25]])
  print("KNOWN_DIRECT_CALLS_TO_REMOVE_WAITER",json.dumps(caller_hits))
if __name__=="__main__":main()
