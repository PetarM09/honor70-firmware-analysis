#!/usr/bin/env python3
"""Signed original FNE-AN00 Board Firehose ELF capability audit (offline only).

A static string/ELF-segment audit never proves command acceptance on handset.
No external device, network, EDL, flash, RPMB or disk writes.
"""
from __future__ import annotations
import argparse,hashlib,json,re
from pathlib import Path
from elftools.elf.elffile import ELFFile

EXPECTED={
"ddr":"9c892e716320764c20055d8374bf8eca7418b3ff2177f81794e18d3656fc55a8",
"lite":"e029df6e2d532de87c2279e960472ec0e4799aca53bc27ed4fa3e4027b05d101"
}
COMMANDS=("configure","read","program","erase","patch","peek","poke",
          "getstorageinfo","getsha256digest","setbootablestoragedrive",
          "getdeviceinfo","sendimage","authenticate","nop","power","ufs")
SECURITY=("rpmb","keymaster","qsee","secure","fuse","rollback","milestone",
          "authenticated","authentication","signature","writeprotect",
          "partition","storage","xml","disable","enable","firehose","targetname")

def strings(data):
    return [(m.start(),m.group().decode("latin1","replace"))
            for m in re.finditer(rb"[\x20-\x7e]{6,200}",data)]

def audit(path,expected):
    raw=path.read_bytes();sha=hashlib.sha256(raw).hexdigest()
    if sha!=expected:raise ValueError(f"Original signed {path} hash mismatch: {sha}")
    if raw[:4]!=b"\x7fELF":raise ValueError("Source not ELF")
    with path.open("rb") as fd:
        e=ELFFile(fd)
        segments=[{"type":str(p["p_type"]),"file_bytes":int(p["p_filesz"]),
                   "flags":int(p["p_flags"]),"virtual_address":hex(int(p["p_vaddr"])),
                   "sha256":hashlib.sha256(p.data()).hexdigest()}
                  for p in e.iter_segments() if p["p_type"]=="PT_LOAD"]
    texts=strings(raw)
    commands={}
    for cmd in COMMANDS:
        pat=re.compile(r"(?i)(?:\b|<)"+re.escape(cmd)+r"(?:\b|\s|[=>])")
        hits=[{"offset":hex(offset),"string":v[:160]} for offset,v in texts if pat.search(v)]
        commands[cmd]=hits[:12]
    markers={}
    for term in SECURITY:
        pat=re.compile(re.escape(term),re.I)
        hits=[{"offset":hex(offset),"string":v[:160]} for offset,v in texts if pat.search(v)]
        markers[term]={"hits":len(hits),"samples":hits[:12]}
    return {"source":str(path),"sha256":sha,"size":len(raw),
            "loadable_segments":segments,"ascii_string_count":len(texts),
            "command_string_candidates":commands,"security_string_candidates":markers}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ddr",type=Path,required=True)
    p.add_argument("--lite",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    ddr=audit(a.ddr,EXPECTED["ddr"]);lite=audit(a.lite,EXPECTED["lite"])
    result={"target":"HONOR70 FNE-AN00 HMT 1.0.0.34 signed Board EDL",
            "programmers":{"ddr":ddr,"lite":lite},
            "conclusions":{
                "literal_only_not_execution_or_acceptance":True,
                "normal_gpt_ufs_program_capability_is_not_rpmb_write":True,
                "trustzone_keymaster_milestone_not_cleared_by_partition_write":True,
                "changing_abllinuxloader_requires_image_auth_approval":True,
                "no_live_edl_program_or_command_executed":True,
                "no_proven_unlock_route":True},
            "unsupported_inferences":[
                "Firehose command name in binary means parser permits it",
                "RPMB string proves arbitrary RPMB read/write over Firehose",
                "Board-loader acceptance implies ability to write a protected bootloader state",
                "Code patched on UFS would satisfy Qualcomm/HONOR secure-boot signatures",
                "A no-op partition write unlocks the phone"
            ]}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
    for name,obj in result["programmers"].items():
        print("SIGNED_PROGRAMMER",name,obj["sha256"],"FILE_BYTES",obj["size"])
        print("CANDIDATE_COMMANDS",name,{k:len(v) for k,v in obj["command_string_candidates"].items()})
        print("SECURITY_TERMS",name,{k:v["hits"] for k,v in obj["security_string_candidates"].items()})
        for k in ("peek","poke","patch","rpmb","qsee","secure","fuse"):
            d=obj["command_string_candidates"].get(k) or obj["security_string_candidates"].get(k,{})
            print("TARGETED_SOURCE",name,k,json.dumps(d)[:2200])
if __name__=="__main__":main()
