#!/usr/bin/env python3
"""HONOR 70 XBL <-> ABL unlock error propagation, signed original firmware.

This evidence-only tool traces the protected Keymaster 0x203 write status
back through VerifiedBootDxe to the ABL state setter and physical UI
callback. It does not invoke keymaster or Fastboot and cannot prove which
branch a historical on-device event actually took.
"""
import argparse,hashlib,json,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM

EEA_ABL="ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087"
INSTRUCTIONS={
    0x3d9e0:"bl #0x37ac0",
    0x3d9e4:"cbz x0, #0x3da48",
    0x3da5c:"bl #0x43688",
    0x3da60:"cbz x0, #0x3da98",
    0x436f0:"bl #0x13008",
    0x436fc:"b.eq #0x437a0",
    0x43714:"bl #0x37ac0",
    0x43718:"cbz x0, #0x437a0",
    0x4376c:"bl #0x37ac0",
    0x43770:"cbz x0, #0x437a0",
}
def decode(abl):
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for addr,expected in INSTRUCTIONS.items():
        code=list(md.disasm(abl[addr:addr+4],addr))
        actual=f"{code[0].mnemonic} {code[0].op_str}" if code else None
        if actual!=expected:raise ValueError(f"Original signed ABL differs at {addr:#x}: expected {expected!r}, actual {actual!r}")
    return {hex(k):v for k,v in INSTRUCTIONS.items()}

def verifiedboot(s):
    head=re.search(r"(?m)^======== FUNCTION 0000153c\b[^\n]*$",s)
    if not head:raise RuntimeError("VerifiedBootDxe 0x153c function absent")
    nexthead=re.search(r"(?m)^======== FUNCTION ",s[head.end():])
    x=s[head.start():head.end()+nexthead.start() if nexthead else len(s)]
    start=x.find("if (param_2 != 1)")
    if start<0:raise RuntimeError("Secure write path not found")
    body=x[start:]
    preread=body.find("0x202)")
    write=body.find("0x203)")
    if not (0<=preread<write):raise RuntimeError("0x202 prerequisite missing before write")
    after=body[write:write+2000]
    checks={
        "keymaster_write_post_transport_reply_check":r"if\s*\(\s*\(lVar3\s*==\s*0\)\s*&&\s*\(local_f8\s*==\s*0\)\s*\)",
        "failure_logged":r"VB: RWDeviceState: write_req err! staus %d write status %d",
        "efi_failure_code_0x50":r"lVar3 = 0x50;"
    }
    for label,rx in checks.items():
        if not re.search(rx,after):raise RuntimeError("Original XBL assertion failed: "+label)
    return {"signed_write_function":"0x153c",
            "preread_0x202_before_write_0x203":True,
            "qsee_transport_must_return_zero":True,
            "qsee_reply_field_local_f8_must_return_zero":True,
            "failed_secure_write_returns_efi_error_0x50":True,
            "message":"VB: RWDeviceState: write_req err! staus %d write status %d"}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--abl",type=Path,required=True)
    p.add_argument("--xbl-ghidra",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    abl=a.abl.read_bytes(); xbl=a.xbl_ghidra.read_bytes()
    if hashlib.sha256(abl).hexdigest()!=EEA_ABL:
        raise RuntimeError("Wrong/or altered original retail LinuxLoader")
    if abl[:2]!=b"MZ":raise RuntimeError("Not original EFI executable")
    instructions=decode(abl)
    res=verifiedboot(xbl.decode("utf-8","replace"))
    report={
        "scope":"Signed original EEA HONOR70 FNE-NX9 C431 8.0.0.290 offline",
        "abl_sha256":EEA_ABL,
        "xbl_ghidra_source_sha256":hashlib.sha256(xbl).hexdigest(),
        "abl_original_instructions":instructions,
        "xbl_state_write_rules":res,
        "conclusion":[
            "XBL checks BOTH Keymaster write 0x203 transport status and reply status.",
            "A failed secure 0x203 yields XBL EFI failure 0x50, not a normal successful write.",
            "ABL state setter branches on nonzero VBRwDevice status; the physical UI callback likewise branches on nonzero setter status.",
            "A Fastboot OKAY and physical-confirmation UI do not prove this callback reached a successful protected write.",
            "A wipe does not prove a post-reboot persistent unlocked state."
        ],
        "unknowns":[
            "Actual historical Qualcomm SCM security-state bits",
            "Actual 0x202 and 0x203 transport and reply values during original Fastboot event",
            "Whether the event took the ABL early local equality/permission branch",
            "Why the physical handset remained LOCKED after reboot"
        ],
        "no_live_phone_operations":True
    }
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print("ORIGINAL_EEA_ABL_SHA_OK",EEA_ABL)
    print("VALIDATED_SECURE_203_REPLY_AND_TRANSPORT",True)
    print("VALIDATED_XBL_ERROR_0x50_AND_ABL_ERROR_BRANCH",True)
    print("NO_LIVE_UNLOCK_METHOD_OR_WRITE",True)

if __name__=="__main__":main()
