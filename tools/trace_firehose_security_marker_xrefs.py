#!/usr/bin/env python3
"""ARM64 data-reference audit for original signed HONOR Board Firehose.

Resolve strings to ELF virtual addresses and locate ADRP+ADD/LDR references
directly in loadable code. No EDL or live-device operations.
"""
import argparse,hashlib,json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM,ARM64_OP_MEM
from elftools.elf.elffile import ELFFile
EXPECTED={
"ddr":"9c892e716320764c20055d8374bf8eca7418b3ff2177f81794e18d3656fc55a8",
"lite":"e029df6e2d532de87c2279e960472ec0e4799aca53bc27ed4fa3e4027b05d101"}
TARGETS=(
"Peek is disabled on secure boot devices",
"Poke is disabled on secure boot devices",
"UFS RPMB ReadWrite Size:",
"The poke size",
"Secure Boot: ",
"QSEE Dev Config",
"patch command is deprecated",
)

def main():
 p=argparse.ArgumentParser();p.add_argument("--loader",choices=EXPECTED,required=True)
 p.add_argument("--input",type=Path,required=True)
 p.add_argument("--out",type=Path,required=True);a=p.parse_args()
 b=a.input.read_bytes();sha=hashlib.sha256(b).hexdigest()
 if sha!=EXPECTED[a.loader]:raise RuntimeError("Original signed Firehose mismatch")
 with a.input.open("rb") as fd:
  el=ELFFile(fd)
  segments=[{"off":int(x["p_offset"]),"vaddr":int(x["p_vaddr"]),"filesz":int(x["p_filesz"]),
             "flags":int(x["p_flags"])} for x in el.iter_segments() if x["p_type"]=="PT_LOAD"]
 def virtual(fileoff):
  return next((x["vaddr"]+(fileoff-x["off"]) for x in segments
               if x["off"]<=fileoff<x["off"]+x["filesz"]),None)
 found={}
 for term in TARGETS:
  needle=term.encode("ascii");start=0;off=[]
  while True:
   i=b.find(needle,start)
   if i<0:break
   v=virtual(i);off.append({"file_offset":hex(i),"virtual_address":hex(v) if v is not None else None})
   start=i+len(needle)
  found[term]=off
 addr_targets={int(x["virtual_address"],16):(term,x["file_offset"])
               for term,v in found.items() for x in v if x["virtual_address"] is not None}
 pages={v & ~0xfff for v in addr_targets}
 print("DEBUG_ELF_SEGMENTS",json.dumps(segments))
 print("DEBUG_TARGETS",json.dumps({hex(k):v for k,v in addr_targets.items()}))
 md=Cs(CS_ARCH_ARM64,CS_MODE_ARM);md.detail=True;md.skipdata=True
 crossrefs={term:[] for term in TARGETS}
 for seg in segments:
  if not seg["flags"]&1:continue
  code=b[seg["off"]:seg["off"]+seg["filesz"]]
  ins=list(md.disasm(code,seg["vaddr"]))
  print("DEBUG_CODE_SEGMENT",hex(seg["vaddr"]),"FLAGS",seg["flags"],"LEN_BYTES",len(code),"DECODED",len(ins),"FIRST",[(hex(x.address),x.mnemonic,x.op_str) for x in ins[:5]])
  near=[(hex(x.address),x.mnemonic,x.op_str) for x in ins if 0x1482bd00<=x.address<=0x1482bd3c]
  if near:print("DEBUG_KNOWN_RPMB_REFERENCE",json.dumps(near))
  for i,cur in enumerate(ins):
   if cur.mnemonic!="adrp" or len(cur.operands)<2:continue
   if cur.operands[0].type!=ARM64_OP_REG or cur.operands[1].type!=ARM64_OP_IMM:continue
   page=cur.operands[1].imm
   if page not in pages:continue
   register=cur.operands[0].reg
   for nxt in ins[i+1:i+9]:
    if nxt.address-cur.address>32 or nxt.mnemonic in ("b","br","ret","bl","blr"):break
    resolved=None
    o=nxt.operands
    if nxt.mnemonic=="add" and len(o)>2 and o[1].type==ARM64_OP_REG and o[1].reg==register and o[2].type==ARM64_OP_IMM:
     resolved=page+o[2].imm
    if nxt.mnemonic.startswith("ldr") and len(o)>1 and o[1].type==ARM64_OP_MEM and o[1].mem.base==register:
     resolved=page+o[1].mem.disp
    for target,(term,offset) in addr_targets.items():
     if resolved is None or abs(resolved-target)>96:continue
     x={"adrp_addr":hex(cur.address),"resolution_addr":hex(nxt.address),
        "reference_literal_vaddr":hex(resolved),
        "target_literal_vaddr":hex(target),"reference_delta":resolved-target,
        "instruction":nxt.mnemonic+" "+nxt.op_str,
        "context":[f"{x.address:#x}: {x.mnemonic} {x.op_str}"
                   for x in ins[max(0,i-4):min(len(ins),i+10)]]}
     crossrefs[term].append(x)
 obj={"original_signed_loader":a.loader,"sha256":sha,"loadable_segments":segments,
      "original_literals":found,"original_adrp_add_code_crossrefs":crossrefs,
      "limits":[
       "Some data references are indirect or stored in tables not found by this scanner",
       "This does not prove the vendor compiled the branch as reachable in secure boot mode",
       "No EDL, RPMB, flash or memory operation is performed"] }
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(obj,indent=2)+"\n")
 print("ORIGINAL_SIGNED_FIREHOSE_CODE_XREFS",a.loader,sha)
 for key,refs in crossrefs.items():
  print("XREF",key,"COUNT",len(refs))
  for x in refs[:18]:print("XREF_SITE",json.dumps(x)[:2500])
if __name__=="__main__":main()
