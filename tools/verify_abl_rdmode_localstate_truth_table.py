#!/usr/bin/env python3
"""Verify signed HONOR 70 ABL rdmodev1-derived local state and unlock branch.

Input artifacts are the hash-pinned stock EEA ABL Capstone/PE report and
full Ghidra decompilation of the same original ABL. No handset operations.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

ORIGINAL_ABL_SHA256="ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087"
FULL_GHIDRA_SHA256="eeeee591a5a5f20ce2b6f0cc01ddb7fd29a21c663f90a06a19dd06aba82bba5e"

def check(ok, explanation):
    if not ok: raise RuntimeError("Signed firmware evidence failed: "+explanation)

def require_instruction(report, addr, prefix):
    ins={x["rva"]:x["mnemonic"]+" "+x["operand"]
         for x in report["asserted_instructions"]}
    check(ins.get(hex(addr),"").startswith(prefix),
          f"{addr:#x}: expected {prefix}, got {ins.get(hex(addr))}")

def body(src, addr):
    header=f"=============== TARGET 0x{addr} ==============="
    start=src.find(header)
    check(start>=0,"Missing original ABL Ghidra target "+addr)
    end=src.find("=============== TARGET ",start+len(header))
    return src[start:end if end>=0 else None]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--abl-json",type=Path,required=True)
    p.add_argument("--ghidra",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    base=json.loads(a.abl_json.read_text())
    raw=a.ghidra.read_bytes()
    check(base["abl_sha256"]==ORIGINAL_ABL_SHA256,"original EEA ABL hash")
    check(hashlib.sha256(raw).hexdigest()==FULL_GHIDRA_SHA256,"full Ghidra source hash")
    source=raw.decode("utf8","replace")
    f12=body(source,"12cf8")
    f15=body(source,"15690")
    f1b=body(source,"1bb68")
    fmode=body(source,"1bf74")
    # Original ARM64 establishes which branch is actually returning.
    for addr,mnemo in {
        0x12d20:"mov w0, #0x82",
        0x12d2c:"bl #0x136a4",
        0x12d34:"bl #0x1bf74",
        0x12d38:"cmp w0, #2",
        0x12d3c:"b.ne #0x12d70",
        0x12d48:"bl #0x15690",
        0x1bf88:"mov w0, #2",
        0x1bf8c:"b #0x1c678",
        0x156dc:"bl #0x1bb68",
        0x15780:"bl #0x1bb68",
        0x157b8:"mov w0, #1",
        0x157e0:"mov w0, wzr",
        0x13024:"ldr w8, [x0, #0x104]",
        0x13028:"cmp w8, #1",
        0x134d8:"ldr w8, [x0, #0x104]",
        0x134dc:"cmp w8, #1",
        0x436f8:"cmp w8, w23, uxtb",
        0x436fc:"b.eq #0x437a0",
    }.items(): require_instruction(base,addr,mnemo)
    for term in ('FUN_000136a4(0x82,auStack_228,0x100)',
                 'FUN_0001bf74()', 'FUN_00015690(auStack_228,0x100)'):
        check(term in f12,"record 0x82 and RD-mode branch "+term)
    for term in ('"0XEED6030008"','"fastboot flash:rdmodev1"',
                 'FUN_0001bb68(&local_158,2,2)',
                 'common_check_rdmod_v1_state'):
        check(term in f15,"RD-mode v1 verification "+term)
    check(f15.count("FUN_0001bb68(&local_158,2,2)")==2,
          "expected exactly two credential checks")
    check("data_set_sha256_rsa_check_pss" in f1b,
          "Ghidra RSA-PSS verification/check error log present")
    check("FUN_0001c678(2)" in fmode,"mode function normal return is 2")
    ui=base.get("verified_fastboot_ui_normal_critical_requested_values",{})
    for name,kind,request,idx in (
        ("normal_unlock",0,1,5),("normal_lock",0,0,8),
        ("critical_unlock",1,1,7),("critical_lock",1,0,9)
    ):
        check(ui.get(name)=={"entry_index":idx,"arg0_kind":kind,
                               "requested_state":request},
              "wrong UI requested state for "+name)
    strings={e["rva"]:e["string"] for e in
             base["oeminfo_validator_related_original_pe_literals"]}
    check(strings.get("0xb6792")=="0XEED6030008", "retail fallback identifier")
    check(strings.get("0xb67a2")=="fastboot flash:rdmodev1", "RD-mode v1 string")
    table=[
        {"local_context_state":0,"requested_unlock":1,"equals":False,
         "does_call_new_VBRwDevice_WRITE":True,
         "note":"Conditional on the caller having reached setter after initial READ"},
        {"local_context_state":1,"requested_unlock":1,"equals":True,
         "does_call_new_VBRwDevice_WRITE":False,
         "note":"Only the ABL-local equality shortcut, not proof of secure lock state"}
    ]
    outcome={
        "abl_sha256":ORIGINAL_ABL_SHA256,
        "full_ghidra_sha256":FULL_GHIDRA_SHA256,
        "oeminfo_api_record":130,
        "initialization_address":"0x12e90",
        "context_field":"+0x104",
        "normal_0x1bf74_return_value":2,
        "normal_verified_route":"0x12CF8 -> 0x15690 -> 0x1BB68",
        "two_rdmode_v1_identifiers":["0XEED6030008","fastboot flash:rdmodev1"],
        "linked_verification_log_text":"data_set_sha256_rsa_check_pss",
        "unlock_ui_request_value":1,
        "same_session_truth_table":table,
        "protected_write_skip_iff_local_getter_eq_requested":True,
        "keymaster_rpmb_persistent_state_not_observed":True,
        "historical_handset_callback_branch_unknown":True,
        "limits":[
            "Not evidence that the live device has a valid RD-mode credential",
            "The original 0x1BB68 decompiler misrecovers some prototypes, so cryptographic success conditions require ARM64-level confirmation",
            "0x104 is an initialized ABL logical field; its value is not a Keymaster 0x202 read",
            "No permission to infer that modifying OEMINFO ID 130 would change persistent secure device lock",
            "No flashing, Fastboot command, UEFI invocation, protected storage access or physical phone operation"
        ]
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(outcome,indent=2)+"\n")
    print("RD_MODE_0x82_TO_LOCAL_CONTEXT_VERIFIED",json.dumps(outcome,ensure_ascii=False))
if __name__=="__main__":
    main()
