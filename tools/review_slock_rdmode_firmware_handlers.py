#!/usr/bin/env python3
"""Print and compare signed Huawei/HONOR Fastboot SLock/RD-mode routines.

Only processes original Ghidra output; does not send packets to the phone.
"""
import argparse, json, hashlib, re
from pathlib import Path

INTERESTING = ("00016dd4","000172a4","00015d20","00015c04","00015690",
               "0001bb68","000231e8","00025b88","00027850","00043688")

def sections(s):
    chunks=re.split(r'(?=^===== FUNCTION [0-9a-f]{8} )',s,flags=re.M)
    out={}
    for c in chunks:
        m=re.match(r'^===== FUNCTION ([0-9a-f]{8}) ',c)
        if m:out[m.group(1)]=c
    return out

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--ghidra",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    data=a.ghidra.read_bytes();src=data.decode("utf8","replace")
    funcs=sections(src)
    missing=[x for x in INTERESTING if x not in funcs]
    if missing: raise ValueError("Original Ghidra function missing: "+str(missing))
    out={"report_sha256":hashlib.sha256(data).hexdigest(),
         "source":"Signed EEA ABL 8.0.0.290 Ghidra output",
         "functions":{},"limitations":["Strings are not proof of a reachable privilege bypass",
              "Ghidra return types are heuristic; verify ARM64 branch conditions",
              "No token signing keys, no phone operations, no writes"]}
    for addr in INTERESTING:
        body=funcs[addr]
        if "DECOMP_FAILED" in body:raise ValueError("Original Ghidra decompiler failure "+addr)
        hits=[]
        for l in body.splitlines():
            if re.search(r"slock|rdmod|signature|sha256|pss|verify|oeminfo|unlock|FRP|0x82|0x104|Flash|VBRwDevice|^ +if\b",l,re.I):
                hits.append(l.strip()[:350])
        out["functions"][addr]={
            "content_sha256":hashlib.sha256(body.encode()).hexdigest(),
            "bytes":len(body),
            "interesting_lines":hits[:120]
        }
        print("=== ORIGINAL FUNCTION "+addr+" BYTES "+str(len(body))+" ===")
        print(body[:33000])
        print("=== END FUNCTION "+addr+" ===")
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(out,ensure_ascii=False,indent=2)+"\n")
    print("REPORT_SHA256",out["report_sha256"])

if __name__=="__main__": main()
