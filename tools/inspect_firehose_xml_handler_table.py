#!/usr/bin/env python3
"""Identify original Board Firehose XML command function-pointer dispatch table.

Verify the signed DDR/Lite hashes; scan known Ghidra-discovered data
registration range for qwords resolving to code and command ASCII literals.
No device operations or untrusted files.
"""
import argparse, hashlib, json, struct
from pathlib import Path
from elftools.elf.elffile import ELFFile

SHA={
 "ddr":"9c892e716320764c20055d8374bf8eca7418b3ff2177f81794e18d3656fc55a8",
 "lite":"e029df6e2d532de87c2279e960472ec0e4799aca53bc27ed4fa3e4027b05d101"
}
START=0x148A27C0
STOP=0x148A2D60

def main():
  p=argparse.ArgumentParser()
  p.add_argument("--loader",required=True,choices=SHA)
  p.add_argument("--input",required=True,type=Path)
  p.add_argument("--out",required=True,type=Path)
  a=p.parse_args();raw=a.input.read_bytes()
  digest=hashlib.sha256(raw).hexdigest()
  if digest!=SHA[a.loader]:raise ValueError("Signed Firehose ELF mismatched")
  with a.input.open("rb") as fd:
    ef=ELFFile(fd)
    segs=[{"v":int(s["p_vaddr"]),"off":int(s["p_offset"]),
           "length":int(s["p_filesz"]),"flags":int(s["p_flags"])}
          for s in ef.iter_segments() if s["p_type"]=="PT_LOAD" and int(s["p_filesz"])>0]
  def fileoff(addr):
    return next((s["off"]+addr-s["v"] for s in segs if s["v"]<=addr<s["v"]+s["length"]),None)
  def seg_for(addr):
    return next((s for s in segs if s["v"]<=addr<s["v"]+s["length"]),None)
  def string_at(addr):
    loc=fileoff(addr)
    if loc is None:return None
    buf=raw[loc:loc+110]
    if not buf:return None
    result=buf.split(b"\0",1)[0]
    if len(result)<2 or len(result)>100 or any(x<32 or x>126 for x in result):return None
    return result.decode("ascii")
  rows=[]
  for addr in range(START,STOP,8):
    loc=fileoff(addr)
    if loc is None or loc+8>len(raw):continue
    value=struct.unpack_from("<Q",raw,loc)[0]
    t=seg_for(value)
    if t:
      kind="exec" if t["flags"] & 1 else "data"
      text=string_at(value)
      if text:kind="ascii";value_text=text
      else:value_text=None
      rows.append({"table_vaddr":hex(addr),"raw_qword":hex(value),
                   "target_type":kind,"ascii":value_text})
  code=[x for x in rows if x["target_type"]=="exec"]
  strings=[x for x in rows if x["target_type"]=="ascii"]
  sha_handler=0x14825120 if a.loader=="ddr" else 0x14825114
  sha_ptrs=[x for x in code if int(x["raw_qword"],16)==sha_handler]
  if not sha_ptrs:raise RuntimeError("Known original getsha256digest XML callback absent from table")
  result={
    "loader":a.loader,"sha256":digest,
    "table_range":[hex(START),hex(STOP)],
    "known_getsha256digest_handler":hex(sha_handler),
    "known_handler_references":sha_ptrs,
    "table_pointing_to_executable_code":code,
    "table_pointing_to_ascii_cstrings":strings,
    "all_mapped_pointer_rows":rows,
    "limitations":[
      "This range is a Ghidra-identified portion of Firehose callback registry, not a complete exhaustive search.",
      "A callback pointer reference does not prove it can be invoked from external EDL with Secure Boot on.",
      "The result is static and cannot prove a protected RPMB or RAM write.",
      "No live device, storage or other memory was accessed."
    ]
  }
  a.out.parent.mkdir(parents=True,exist_ok=True)
  a.out.write_text(json.dumps(result,indent=2)+"\n")
  print("SIGNED_XML_CALLBACK_TABLE_SHA",a.loader,digest)
  print("SHA256_HANDLER_PTR",json.dumps(sha_ptrs))
  print("REFERENCED_COMMAND_TEXTS",json.dumps(strings[:130]))
  print("REGISTERED_FUNCTION_POINTERS",json.dumps(code[:160]))
if __name__=="__main__":main()
