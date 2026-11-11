#!/usr/bin/env python3
"""Offline scan of archived, original EEA VerifiedBootDxe Ghidra pseudocode.

Index references to known RWDeviceState (0x153c), protocol registration,
and indirect function tables. Report is triage, not a proven pointer mapping.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

TOKENS = (
    "FUN_0000153c", "0000153c", "gQcomVerifiedBootProtocolGuid",
    "InstallProtocolInterface", "InstallMultipleProtocolInterfaces",
    "InstallMultipleProtocol", "InstallProtocol", "0xd0a8",
    "0x30", "0x38", "RWDeviceState", "VBRwDevice",
    "DAT_0000", "FUN_0000147c",
)


def split_funcs(report):
    sections = re.split(r"(?=^======== FUNCTION )", report, flags=re.M)
    return [(m.group(1).lower(), part) for part in sections
            if (m := re.match(r"======== FUNCTION ([0-9a-fA-F]{8})", part))]


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--ghidra",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    raw=args.ghidra.read_bytes()
    funcs=split_funcs(raw.decode("utf-8","replace"))
    if len(funcs)<150:
        raise ValueError(f"Expected original 164 function decompilation, got {len(funcs)}")
    result=[]
    for addr, body in funcs:
        hits=[(term, body.count(term)) for term in TOKENS if term in body]
        if not hits:
            continue
        evidence=[]
        lines=body.splitlines()
        for idx,line in enumerate(lines):
            if any(term in line for term in TOKENS):
                start=max(0,idx-2); end=min(len(lines),idx+3)
                evidence.append({"line_index":idx,"context":"\n".join(lines[start:end])[:1300]})
        result.append({"address":addr,"hits":hits,"evidence":evidence[:45],
                       "context_truncated":max(0,len(evidence)-45)})
    result.sort(key=lambda x:(-int(any(h[0]=="FUN_0000153c" for h in x["hits"])),
                              -sum(n for _,n in x["hits"]),x["address"]))
    out={
        "report_sha256":hashlib.sha256(raw).hexdigest(),
        "original_ghidra_functions":len(funcs),
        "candidate_count":len(result),
        "candidate_functions":result,
        "warning":"Decompiler text alone cannot confirm protocol vtable offset +0x30. Need original PE bytes / reference table."
    }
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(out,indent=2)+"\n")
    print("FUNCTIONS",len(funcs),"CANDIDATES",len(result),
          "SHA256",out["report_sha256"])
    for item in result[:20]:
        print("HIT",item["address"],repr(item["hits"]))
        for entry in item["evidence"][:8]:
            print("  CONTEXT",repr(entry["context"][:650]))
if __name__=="__main__":
    main()
