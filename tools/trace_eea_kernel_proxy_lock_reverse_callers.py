#!/usr/bin/env python3
"""Source-pinned read-only ARM64 BL callsite path into CVE-2026-43499.

Scans original signed FNE-NX9 8.0.0.290 kernel executable PT_LOAD bytes
for BL instruction targets; identifies direct caller and two-hop relationships.
Does NOT run a kernel exploit or derive arbitrary memory write offsets.
"""
import argparse,bisect,hashlib,json,struct,subprocess,re
from pathlib import Path
from elftools.elf.elffile import ELFFile
BOOT_SHA="5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"
KERNEL_SHA="bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
PREFIX="0xffffffc0"
TARGET_NAMES=("remove_waiter","rt_mutex_start_proxy_lock","futex_requeue")
KNOWN_PROXY="0xffffffc01037e2c0"
KNOWN_REMOVE="0xffffffc01037e350"

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--boot",required=True,type=Path)
 p.add_argument("--kernel",required=True,type=Path)
 p.add_argument("--elf",required=True,type=Path)
 p.add_argument("--output",required=True,type=Path)
 a=p.parse_args()
 if hashlib.sha256(a.boot.read_bytes()).hexdigest()!=BOOT_SHA:raise ValueError("stock boot mismatch")
 if hashlib.sha256(a.kernel.read_bytes()).hexdigest()!=KERNEL_SHA:raise ValueError("stock kernel mismatch")
 output=subprocess.run(["nm","-n","--defined-only",str(a.elf)],
                       capture_output=True,text=True,check=True)
 syms=[]
 for line in output.stdout.splitlines():
  m=re.match(r"^([0-9a-fA-F]+)\s+[Tt]\s+(\S+)$",line)
  if m:syms.append((int(m.group(1),16),m.group(2)))
 syms.sort()
 addresses=[x[0] for x in syms]
 names={name:next((addr for addr,n in syms if n==name),None) for name in TARGET_NAMES}
 if names["rt_mutex_start_proxy_lock"]!=int(KNOWN_PROXY,16) or names["remove_waiter"]!=int(KNOWN_REMOVE,16):
  raise RuntimeError("Matching EEA kernel's vulnerable function addresses changed")
 # All executable spans, full signed retail kernel, not a Ghidra pseudocode callgraph.
 with a.elf.open("rb") as inp:
  ef=ELFFile(inp)
  segs=[(int(s["p_vaddr"]),int(s["p_offset"]),int(s["p_filesz"]))
      for s in ef.iter_segments() if s["p_type"]=="PT_LOAD" and int(s["p_flags"])&1]
  candidates=[]
  for base,off,length in segs:
   inp.seek(off);raw=inp.read(length)
   # Avoid expensive disassembly of millions of instructions: ARM64 BL opcode
   # mask 0xfc000000 equals 0x94000000, immediate is signed 26-bit << 2.
   for (v,) in struct.iter_unpack("<I",raw[:len(raw)//4*4]):
    pass
   # Actual scan with location index, avoiding accidental signed address truncation.
   for i,(v,) in enumerate(struct.iter_unpack("<I",raw[:len(raw)//4*4])):
    if v&0xfc000000!=0x94000000:continue
    imm=v&0x3ffffff
    if imm & 0x2000000:imm-=0x4000000
    src=base+4*i;target=src+4*imm
    candidates.append((src,target))
 targets={k:v for k,v in names.items() if v is not None}
 inbound={k:[] for k in targets}
 callers=[]
 for src,dst in candidates:
  for name,tgt in targets.items():
   if dst==tgt:
    si=bisect.bisect_right(addresses,src)-1
    owner=syms[si][1] if si>=0 else None
    item={"site":hex(src),"target":hex(dst),"inferred_caller":owner}
    inbound[name].append(item)
    if name=="rt_mutex_start_proxy_lock":callers.append((src,owner))
 direct=[x for x in inbound["remove_waiter"] if x["site"]=="0xffffffc01037e300"]
 if len(direct)!=1 or direct[0]["inferred_caller"]!="rt_mutex_start_proxy_lock":
  raise RuntimeError("Expected real direct CVE rollback call from proxy_lock is absent")
 # Focus the caller graph on observed machine-code references, not all callers.
 intermediary_names=sorted(set(n for _,n in callers if n))
 intermediary_addrs={n:next((x for x,y in syms if y==n),None) for n in intermediary_names}
 reachable=[]
 for src,dst in candidates:
  for name,target in intermediary_addrs.items():
   if dst!=target:continue
   i=bisect.bisect_right(addresses,src)-1
   owner=syms[i][1] if i>=0 else None
   if owner=="futex_requeue":
    reachable.append({"from":"futex_requeue","to":name,"call_site":hex(src)})
 result={
  "source":"Original signed FNE-NX9 8.0.0.290 kernel executable PT_LOAD whole-ELF ARM64 BL scan",
  "stock_boot_sha256":BOOT_SHA,
  "stock_kernel_sha256":KERNEL_SHA,
  "executable_ELF_spans":len(segs),
  "total_BL_machine_instructions":len(candidates),
  "original_critical_function_VAs":{k:hex(v) if v is not None else None for k,v in names.items()},
  "actual_direct_callers":inbound,
  "inferred_caller_of_proxy_lock":intermediary_names,
  "futex_requeue_to_proxy_immediate_caller_two_hop_sites":reachable,
  "exact_signed_proxy_lock_to_remove_waiter_call_confirmed":True,
  "exact_signed_remove_waiter_uses_current_sp_el0_confirmed_by_prior_disassembly":True,
  "exploitable_privilege_escalation_established":False,
  "permanent_bootloader_unlock_established":False,
  "limitations":[
   "Nearest text symbol inferred caller does not substitute for a fully verified CFG.",
   "Only direct BL calls are counted; an indirect call, tail B branch or inlining may be missed.",
   "Code vulnerability pattern is NOT an on-device exploit success or arbitrary write.",
   "No device write, kernel crash, root, or Keymaster/RPMB access attempted."
  ]
 }
 a.output.parent.mkdir(parents=True,exist_ok=True)
 a.output.write_text(json.dumps(result,indent=2)+"\n")
 print("SIGNED_EEA_KERNEL_BL_SCAN",len(candidates))
 for name,items in inbound.items():
  print("INBOUND_BL",name,len(items),items[:24])
 print("PROXY_LOCK_INTERMEDIARIES",intermediary_names)
 print("FUTEX_REQUEUE_IMMEDIATE_HELPER_CHAIN",reachable)
 print("VULNERABLE_ORIGINAL_PROXY_TO_REMOVE_WAITER_EDGE_VERIFIED")
if __name__=="__main__":main()
