#!/usr/bin/env python3
"""HONOR70 stock Board EDL: prove what "peek" and "poke" ELF strings mean.

Hash checks both original signed binaries and distinguishes diagnostic text
from actual XML command registration and direct code/pointer references.
No device interaction, EDL packet or write.
"""
import argparse, hashlib, struct, json, re
from pathlib import Path
from elftools.elf.elffile import ELFFile

EXPECTED={
  "ddr":"9c892e716320764c20055d8374bf8eca7418b3ff2177f81794e18d3656fc55a8",
  "lite":"e029df6e2d532de87c2279e960472ec0e4799aca53bc27ed4fa3e4027b05d101",
}
NAMES=["peek","poke","patch","read","program","erase","configure","getstorageinfo"]
DIAGNOSTICS=[
"Peek is disabled on secure boot devices",
"Poke is disabled on secure boot devices",
"UFS RPMB ReadWrite Size:",
"Secure Boot:",
]

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--loader",required=True,choices=EXPECTED)
    p.add_argument("--input",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    raw=args.input.read_bytes()
    sha=hashlib.sha256(raw).hexdigest()
    if sha!=EXPECTED[args.loader]:raise ValueError("Original signed Board hash mismatch")
    with args.input.open("rb") as fd:
        elf=ELFFile(fd)
        segs=[{"file_start":int(x["p_offset"]),
                "file_end":int(x["p_offset"])+int(x["p_filesz"]),
                "virt_start":int(x["p_vaddr"])}
               for x in elf.iter_segments() if x["p_type"]=="PT_LOAD" and int(x["p_filesz"])>0]
    def vaddr(off):
        return next((s["virt_start"]+off-s["file_start"]
            for s in segs if s["file_start"]<=off<s["file_end"]),None)
    def find_all(value):
        offsets=[];start=0
        while True:
            i=raw.find(value,start)
            if i<0:break
            offsets.append(i)
            start=i+1
        return offsets
    xml={}
    for word in NAMES:
        matched={}
        for label,val in (
          ("nul_terminated",word.encode()+b"\0"),
          ("xml_tag",("<"+word).encode()),
          ("quoted_xml_name",('"'+word+'"').encode()),
          ("label_prefix",("name="+word).encode()),
        ):
            matched[label]=[hex(x) for x in find_all(val)[:20]]
        matched["terminated_candidate_context"]=[
            {"offset":hex(pos),
             "previous_byte":hex(raw[pos-1]) if pos else None,
             "has_nul_boundary":pos==0 or raw[pos-1]==0,
             "printable_prefix":raw[max(0,pos-58):pos].decode("ascii","replace"),
             "printable_suffix":raw[pos:pos+len(word)+2].decode("ascii","replace")}
            for pos in find_all(word.encode()+b"\0")[:20]]
        matched["strict_nul_delimited_literal_starts"]=[
            row["offset"] for row in matched["terminated_candidate_context"] if row["has_nul_boundary"]]
        xml[word]=matched
    # The adjacent Firehose XML dispatcher string cluster contains actual
    # NUL-delimited command tokens for common storage operations. Compare
    # those with the apparent peek/poke mentions in diagnostic sentences.
    for command in ("program","read","patch","erase","configure","getstorageinfo"):
        if not xml[command]["strict_nul_delimited_literal_starts"]:
            raise ValueError("Expected original Firehose XML command token missing: "+command)
    for command in ("peek","poke"):
        if xml[command]["strict_nul_delimited_literal_starts"]:
            raise ValueError("Unexpected independent memory command string: "+command)
    if not xml["poke"]["terminated_candidate_context"] or not all(
        row["previous_byte"]=="0x2f" for row in xml["poke"]["terminated_candidate_context"]):
        raise ValueError("Expected poke suffix only within 'peek/poke' diagnostic context")
    markers=[]
    for marker in DIAGNOSTICS:
        rows=[]
        for off in find_all(marker.encode()):
            virt=vaddr(off)
            refs=[]
            if virt is not None:
                for size in (8,4):
                    if virt>=2**(size*8):continue
                    needle=struct.pack("<Q" if size==8 else "<I",virt)
                    refs.extend({"pointer_width":size,"source_file_off":hex(k),
                                  "source_virt_addr":hex(vaddr(k)) if vaddr(k) is not None else None}
                                for k in find_all(needle)[:20])
            rows.append({"file_offset":hex(off),"virtual_address":hex(virt) if virt is not None else None,
                         "direct_4_8byte_pointer_occurrences":refs})
        markers.append({"literal":marker,"occurrences":rows})
    report={
      "source":args.loader,"sha256":sha,"bytes":len(raw),
      "exact_registration_candidates":xml,
      "diagnostic_string_references":markers,
      "facts_only_not_conclusions":{
        "literal_not_always_executable_handler":True,
        "absence_of_direct_string_reference_not_proof_of_absent_code":True,
        "presence_of_rpmb_diagnostic_not_auth_rpmb_write":True,
        "no_independent_nul_delimited_peek_or_poke_command_name_in_this_ELF":True,
        "phone_edl_loader_acceptance_not_tested":True
      }
    }
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+"\n")
    print("ORIGINAL_FIREHOSE_VERIFIED",args.loader,sha)
    for word,matches in xml.items():
        print("EXACT_CMD_REGISTRATION",word,{k:len(v) for k,v in matches.items()},matches)
    for obj in markers:
        print("DIAGNOSTIC",json.dumps(obj))
if __name__=="__main__":main()
