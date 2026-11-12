#!/usr/bin/env python3
"""Determine if stock XBL checks KM41 WRITE_KM_DEVICE_STATE (0x203) status.

An unlock confirmation/wipe does not prove the protected state write
persisted. This tool prints the original decompiled write branch, records
status read sites and prepares an evidence-only report. No device action.
"""
import argparse, hashlib, json, re
from pathlib import Path

def block(source,address):
    head=re.search(r"(?m)^======== FUNCTION "+address+r"\b[^\n]*$",source)
    if head is None: raise RuntimeError("Missing original signed VerifiedBoot function "+address)
    nxt=re.search(r"(?m)^======== FUNCTION ",source[head.end():])
    return source[head.start():head.end()+nxt.start() if nxt else len(source)]

def snippets(text,term,before=1300,after=3600):
    return [
      {"start":m.start(),"excerpt":text[max(0,m.start()-before):m.end()+after]}
      for m in list(re.finditer(re.escape(term),text,re.I))[:8]
    ]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    raw=a.report.read_bytes()
    text=raw.decode("utf-8","replace")
    f=block(text,"0000153c")
    for token in ("0x202)","0x203)","FUN_00003898","FUN_00002a1c"):
        if token not in f:raise RuntimeError("Signed original XBL source token missing "+token)
    w=f.split("if (param_2 != 1)",1)[-1]
    first=w.find("0x202)")
    second=w.find("0x203)")
    if first<0 or second<0 or second<=first:raise RuntimeError("No secure write preread ordering")
    contexts={
        "read_202":snippets(w,"0x202)",400,1400),
        "write_203":snippets(w,"0x203)",1500,7400),
        "qsee_transport":snippets(w,"Qsee",800,1600),
        "result_logging":snippets(w,"Succeed using rpmb",1800,1000),
        "fallback":snippets(w,"FUN_00003898",400,2400),
        "response_field":snippets(w,"local_d8",300,600),
    }
    result={
      "target":"original signed HONOR70 FNE-NX9 VerifiedBootDxe 0x153c",
      "source_ghidra_sha256":hashlib.sha256(raw).hexdigest(),
      "source_function_sha256":hashlib.sha256(f.encode()).hexdigest(),
      "source_function_bytes":len(f),
      "preread_command":"0x202",
      "write_command":"0x203",
      "write_branch_contains_pre_read":True,
      "only_guaranteed_from_static":"Ghidra pseudocode, not executed on device",
      "context":contexts,
      "unknown":"Whether a historical unlock callback reached KM 0x203 or what response it received",
      "no_live_phone_operations":True
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    print("STOCK_XBL_RW_DEVICE_STATE_SHA",result["source_function_sha256"])
    print("ORIGINAL_0x203_WRITER_CONTEXT")
    for x in contexts["write_203"]:
        print(x["excerpt"][:12500])
    print("ORIGINAL_RPMB_SUCCESS_LOG_CONTEXT")
    for x in contexts["result_logging"]:
        print(x["excerpt"][:6000])
    print("EVIDENCE_AUDIT_COMPLETE")
if __name__=="__main__":main()
