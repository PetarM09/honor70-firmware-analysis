#!/usr/bin/env python3
"""Read-only source-pinned trace of HONOR70 retail ABL +0x104 state.

Separates OEMINFO-derived ABL context from Keymaster persistent lock state.
Reads the original 8.0.0.290 EEA LinuxLoader and archived Ghidra decompilation.
No physical device operations, security-state writes or firmware patching.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM

EXPECTED_SHA256 = "ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087"
WINDOWS = {
    "oeminfo_record_reader_0x12cf8": (0x12cf8, 0x12e90),
    "state_initializer_0x12e90": (0x12e90, 0x12f10),
    "logical_state_getter_0x13008": (0x13008, 0x13054),
    "allowlist_state_consumer_0x134c0": (0x134c0, 0x13528),
    "oeminfo_record_helper_0x136a4": (0x136a4, 0x136f8),
    "frp_state_permission_0x27850": (0x27850, 0x27b10),
    "ui_confirmation_read_0x3d9b8": (0x3d9b8, 0x3dad0),
    "setter_normal_critical_0x43688": (0x43688, 0x438c0),
    "rdmod_status_helper_0x1bf74": (0x1bf74, 0x1bf9c),
    "oeminfo_validate_helper_0x15690": (0x15690, 0x15758),
    "init_select_fallback_0x13d58": (0x13d58, 0x13d94),
    "secure_backed_state_getter_0x433a8": (0x433a8, 0x43468),
    "fastboot_ui_menu_entry_0x3dab8": (0x3dab8, 0x3dd38),
}
FULL_GHIDRA = (
    "12cf8", "12e90", "13008", "136a4", "1a7b0",
    "1bf74", "13d58", "27850", "43688",
)
TARGETS = (0x12cf8, 0x12e90, 0x13008, 0x134c0, 0x136a4,
           0x13d58, 0x1a7b0, 0x1bf74, 0x27850, 0x43688)
KNOWN_ASSERTIONS = {
    0x12ea0: ("bl", "#0x176d8"),
    0x12ea8: ("bl", "#0x12cf8"),
    0x12eac: ("cbnz", "#0x12ec4"),
    0x12eb8: ("mov", "w0, wzr"),
    0x12ec4: ("str", "w0, [x19, #0x104]"),
    0x13014: ("bl", "#0x13608"),
    0x13024: ("ldr", "w8, [x0, #0x104]"),
    0x13028: ("cmp", "w8, #1"),
    0x1302c: ("cset", "w0, eq"),
    0x134d8: ("ldr", "w8, [x0, #0x104]"),
    0x134dc: ("cmp", "w8, #1"),
    0x134e0: ("b.eq", "#0x13518"),
    0x436f0: ("bl", "#0x13008"),
    0x436f8: ("cmp", "w8, w23, uxtb"),
    0x436fc: ("b.eq", "#0x437a0"),
    0x43748: ("bl", "#0x13008"),
    0x43750: ("cmp", "w8, w23, uxtb"),
    0x43754: ("b.eq", "#0x437a0"),
}


def get_ghidra_section(src, target):
    header = f"=============== TARGET 0x{target} ==============="
    start = src.find(header)
    if start < 0:
        raise ValueError("Missing archived original Ghidra target: "+target)
    end = src.find("=============== TARGET ", start + len(header))
    return src[start:end if end >= 0 else None]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--abl",type=Path,required=True)
    p.add_argument("--ghidra",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    raw=a.abl.read_bytes()
    sha=hashlib.sha256(raw).hexdigest()
    if sha!=EXPECTED_SHA256:
        raise ValueError(f"Abort: original signed EEA ABL mismatch ({sha})")
    ghidra_raw=a.ghidra.read_bytes()
    ghidra=ghidra_raw.decode("utf8","replace")
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    md.detail=True
    listing=list(md.disasm(raw[0x1000:0xb0000],0x1000))
    by_address={i.address:i for i in listing}
    for addr,(mnemonic,fragment) in KNOWN_ASSERTIONS.items():
        i=by_address.get(addr)
        if i is None or i.mnemonic!=mnemonic or fragment not in i.op_str:
            raise ValueError(f"Original ABL regression at {addr:#x}: expected {mnemonic} {fragment}, found {i}")
    call_xrefs={f"{target:#x}":[] for target in TARGETS}
    for inst in listing:
        if inst.mnemonic=="bl" and len(inst.operands)>0 and inst.operands[0].type==ARM64_OP_IMM:
            dest=inst.operands[0].imm
            if dest in TARGETS:
                call_xrefs[f"{dest:#x}"].append(hex(inst.address))
    # Callback argument layout: callback 0x3DA5C reads (int flag, uint8 value)
    # from the original PE constant array at RVA 0xC3B90, index * 16.
    import pefile
    pe=pefile.PE(data=raw,fast_load=True)
    table_rva=0xc3b90
    if pe.get_offset_from_rva(table_rva)<0:
        raise ValueError("Original UI callback data table mapping unavailable")
    import struct
    ui_rows=[]
    for idx in range(12):
        off=pe.get_offset_from_rva(table_rva+idx*16)
        if off+16>len(raw):break
        row=raw[off:off+16]
        arg0=struct.unpack_from("<I",row,0)[0]
        arg1=row[8]
        ui_rows.append({"index":idx,"table_rva":hex(table_rva+idx*16),
                        "arg0_kind":arg0,"arg1_requested_state_byte":arg1,
                        "row_raw_hex":row.hex()})
    windows={}
    for key,(lo,hi) in WINDOWS.items():
        ins=[i for i in listing if lo<=i.address<hi]
        windows[key]=[f"{i.address:#x} {i.mnemonic} {i.op_str}" for i in ins]
    sections={k:get_ghidra_section(ghidra,k) for k in FULL_GHIDRA}
    extracted={}
    for k,chunk in sections.items():
        at=chunk.find("DECOMP ")
        extracted[k]={
            "function_header":chunk[:at if at>=0 else len(chunk)][:600],
            "decomp":chunk[at+len("DECOMP "):][:24000] if at>=0 else None,
            "full_text_size":len(chunk)
        }
    result={
        "scope":"Original EEA ABL bytecode crosschecked with archived Ghidra report",
        "abl_sha256":sha,
        "ghidra_report_sha256":hashlib.sha256(ghidra_raw).hexdigest(),
        "asserted_instructions":[{"rva":hex(k),"mnemonic":by_address[k].mnemonic,
                                  "operand":by_address[k].op_str}
                                  for k in sorted(KNOWN_ASSERTIONS)],
        "direct_callers_by_target":call_xrefs,
        "arm64_windows":windows,
        "ui_callback_table_start_rva":"0xc3b90",
        "ui_callback_rows_static_pe":ui_rows,
        "archived_ghidra_source":extracted,
        "interpretation_limitations":[
            "OEMINFO record 0x82 is an API record identifier, not necessarily a physical OEMINFO byte offset.",
            "ABL local context +0x104 is not a direct persistent Keymaster RPMB read.",
            "The equal-state write shortcut is conditional on the caller's actual requested byte and the getter return.",
            "No dynamic evidence about the owner's previous UI confirmation path or live SCM flags is available.",
            "Do not write OEMINFO, FRP, devinfo, RPMB or firmware images based on this static report.",
        ]
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    print("ABL_SHA256_OK",sha)
    print("GHIDRA_SHA256",result["ghidra_report_sha256"])
    for target,callers in call_xrefs.items():
        print("DIRECT_CALLERS",target,",".join(callers))
    for row in ui_rows:
        print("UI_CALLBACK_ROW",json.dumps(row))
    for name,ins in windows.items():
        print("===== ARM64 WINDOW",name)
        print("\n".join(ins))
    for name,body in extracted.items():
        print("===== GHIDRA",name)
        print(body["function_header"])
        print((body["decomp"] or "NO_DECOMP")[:18000])


if __name__=="__main__":
    main()
