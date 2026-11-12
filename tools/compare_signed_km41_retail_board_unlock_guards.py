#!/usr/bin/env python3
"""Offline original-signed EEA vs Board KM41 protected lock-state comparison.

Compares exact original decompiler function evidence for:
  READ_KM_DEVICE_STATE (0x202), WRITE_KM_DEVICE_STATE (0x203),
  shared software-fuse check, and MILESTONE_CALL (0x204).

This comparison MUST NOT be used to justify writing Board firmware to an
incompatible target; no device or persistent storage is touched.
"""
import argparse, hashlib, json, re, difflib
from pathlib import Path

PAIR=[
 ("read_state_0x202","1185a8","1184c0"),
 ("write_state_0x203","118878","118790"),
 ("fuse_check","117980","117898"),
 ("milestone_0x204","117a18","117930")
]
GUARD_LABELS=[
 ("read_write_both_call_fuse_checker",r"FUN_00117980",r"FUN_00117898"),
 ("qsee_fuse_check",r"qsee_is_sw_fuse_blown",r"qsee_is_sw_fuse_blown"),
 ("denied_minus_15",r"(?:0xfffffff1|0xfffffffffffffff1)",r"(?:0xfffffff1|0xfffffffffffffff1)"),
 ("rpm_read",r"qsee_stor_read_sectors",r"qsee_stor_read_sectors"),
 ("rpm_write",r"qsee_stor_write_sectors",r"qsee_stor_write_sectors"),
 ("milestone_fuse_blow",r"qsee_blow_sw_fuse",r"qsee_blow_sw_fuse"),
]

def function(s,addr):
    m=re.search(r"(?m)^===== TARGET "+re.escape(addr)+r" =====[ \t]*$",s)
    if not m:raise RuntimeError("Original Ghidra entry not found: "+addr)
    n=re.search(r"(?m)^===== TARGET ",s[m.end():])
    result=s[m.end():m.end()+n.start() if n else len(s)]
    if not result.strip() or "MISSING_FUNCTION" in result[:150] or "ERROR " in result[:120]:
        raise RuntimeError("Decompilation missing or failed "+addr)
    return result

def normalize(s):
    # Remove version-specific absolute addresses; preserve security-relevant
    # logical constants 0x202, 0x203, 0x204 and denial/status codes.
    s=re.sub(r"(?m)^ENTRY [^\n]*\n","",s)
    s=re.sub(r"(?m)^Function [^\n]*\n","",s)
    s=re.sub(r"\bFUN_[0-9a-fA-F]{8}\b","FUN_SYMBOL",s)
    s=re.sub(r"\bDAT_[0-9a-fA-F]{8}\b","DATA_SYMBOL",s)
    s=re.sub(r"\bLAB_[0-9a-fA-F]{8}\b","LABEL",s)
    s=re.sub(r"\b0x([0-9a-fA-F]{6,})\b",
        lambda m:"ABS_ADDR" if int(m.group(1),16)<0xF0000000 else m.group(0),s)
    s=re.sub(r"\s+"," ",s).strip()
    return s

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--eea",required=True,type=Path)
    p.add_argument("--board",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    raw_e=a.eea.read_bytes();raw_b=a.board.read_bytes()
    eea=raw_e.decode("utf-8","replace")
    board=raw_b.decode("utf-8","replace")
    data=[]
    for name,e,b in PAIR:
        E=function(eea,e);B=function(board,b)
        nE=normalize(E);nB=normalize(B)
        report={
            "function":name,"eea_addr":"0x"+e,"board_addr":"0x"+b,
            "eea_decomp_sha256":hashlib.sha256(E.encode()).hexdigest(),
            "board_decomp_sha256":hashlib.sha256(B.encode()).hexdigest(),
            "eea_text_bytes":len(E),"board_text_bytes":len(B),
            "normalized_exact_match":nE==nB,
            "significant_token_presence":{
                label:{"eea":bool(re.search(pe,E,re.I)), "board":bool(re.search(pb,B,re.I))}
                for label,pe,pb in GUARD_LABELS
            }
        }
        if name.startswith(("read_state","write_state")):
            expected_e=r"FUN_00117980"
            expected_b=r"FUN_00117898"
            if not re.search(expected_e,E) or not re.search(expected_b,B):
                raise RuntimeError("The original signed firmware read/write function does not call its fuse gate")
        if name=="fuse_check":
            if "qsee_is_sw_fuse_blown" not in E or "qsee_is_sw_fuse_blown" not in B:
                raise RuntimeError("Fuses are not checked by both helpers")
        if name=="milestone_0x204":
            if "qsee_blow_sw_fuse" not in E or "qsee_blow_sw_fuse" not in B:
                raise RuntimeError("Missing signed milestone fuse operation")
        diff="\n".join(difflib.unified_diff(
            nE.replace(" ; ",";\n").splitlines(),
            nB.replace(" ; ",";\n").splitlines(),
            fromfile="EEA_"+e,tofile="BOARD_"+b,n=3))
        report["normalized_diff_preview"]=diff[:10000]
        report["normalized_diff_length"]=len(diff)
        data.append(report)
        print("KEYMASTER_PAIR",name,"EEA",e,"BOARD",b,
              "MATCH",nE==nB,"DIFF_LEN",len(diff))
        for lab,arr in report["significant_token_presence"].items():
            print("GUARD_TOKEN",name,lab,arr)
        if diff:print("GUARD_DIFF",name,diff[:4400])
        for which,src in (("EEA",E),("BOARD",B)):
            if name in ("read_state_0x202","write_state_0x203","fuse_check"):
                for term in ("qsee_is_sw_fuse_blown","FUN_00117980","FUN_00117898",
                             "0xfffffff1","qsee_stor_read_sectors","qsee_stor_write_sectors"):
                    m=re.search(re.escape(term),src,re.I)
                    if m:print("SOURCE_CONTEXT",name,which,term,repr(src[max(0,m.start()-220):m.end()+420]))
    obj={
        "source":"Original separately verified FNE-NX9 EEA and FNE-AN00 HMT signed KM41 Ghidra reports",
        "eea_source_sha256":hashlib.sha256(raw_e).hexdigest(),
        "board_source_sha256":hashlib.sha256(raw_b).hexdigest(),
        "function_pairs":data,
        "method":"source-text contextual comparison and address-insensitive normalization; not byte-for-byte equivalence",
        "never_live_edl_fastboot_qsee_or_fuse":True,
        "no_demonstrated_unlock":True
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(obj,indent=2,ensure_ascii=False)+"\n")
    print("ORIGINAL_KM41_GUARDS_AUDIT_COMPLETE")
if __name__=="__main__":main()
