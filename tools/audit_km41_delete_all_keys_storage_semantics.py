#!/usr/bin/env python3
"""Offline audit of original HONOR70 EEA KM41 DELETE_ALL_KEYS call chain.

Consumes only an archived Ghidra text report created from the SHA-pinned
signed firmware. Does not read/write the phone or invoke QSEE/Keymaster.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path


def section(source, opening, closing):
    begin=source.find(opening)
    if begin<0: raise ValueError("Missing original Ghidra section: "+opening)
    end=source.find(closing,begin+len(opening))
    if end<0: raise ValueError("Unterminated Ghidra section: "+closing)
    return source[begin+len(opening):end]


def required(source, pattern, label):
    if not re.search(pattern,source,re.S|re.M):
        raise ValueError("Original signed KM41 evidence missing: "+label)


def audit(text):
    header="ORIGINAL_SIGNED_EEA_KM41_MEMORY_TABLE 00138580 COUNT 67 STRIDE 16"
    required(text,re.escape(header),"fixed command table")
    entries={}
    for m in re.finditer(r"(?m)^ENTRY\s+(\d+)\s+CMD\s+0x([0-9a-f]+)\s+FLAGS\s+0x([0-9a-f]+)\s+CALLBACK\s+0x([0-9a-f]+)",text):
        entries[int(m.group(2),16)]={
            "index":int(m.group(1)),"flags":int(m.group(3),16),
            "callback":int(m.group(4),16)
        }
    if len(entries)!=67:
        raise ValueError(f"Expected 67 unique command IDs, found {len(entries)}")
    for cmd, addr in ((0x10e,0x107c48),(0x210e,0x107c48),
                      (0x202,0x1185a8),(0x203,0x118878)):
        if cmd not in entries or entries[cmd]["callback"]!=addr:
            raise ValueError(f"Wrong callback for original command {cmd:#x}")
    main=section(text,"DELETE_ALL_KEYS_DECOMPILED_BEGIN","DELETE_ALL_KEYS_DECOMPILED_END")
    funcs={}
    for addr in ("001184d4","001177a0","0011aa6c","0011aa78","0011ab10","001174bc"):
        funcs[addr]=section(text,"KEY_DELETE_INNER_DECOMPILED_BEGIN "+addr,
                                 "KEY_DELETE_INNER_DECOMPILED_END "+addr)

    required(main,r"func_0x001184d4\(\)","Delete-all-keys storage helper")
    required(main,r"if \(iVar1 == 0\)\s*\{\s*FUN_001177a0\(\)","conditional cache clearing")
    required(funcs["001184d4"],r"FUN_0011aa6c\(\)","Keymaster storage enable check")
    required(funcs["001184d4"],r"if \(\(uVar2 & 1\) == 0\)\s*\{\s*return 0;","early successful return")
    required(funcs["001184d4"],r"FUN_00117480\(0x3000\)","12 KiB allocation")
    required(funcs["001184d4"],r"FUN_0012d16c\(DAT_001391c8,0,0x3000\)","12 KiB zeroing")
    required(funcs["001184d4"],r"FUN_0011aa78\(\)","storage sector size helper")
    required(funcs["001184d4"],r"FUN_0011ab10\(iVar1 << 4,DAT_001391c8,0x3000\)","sector write wrapper")
    required(funcs["0011aa78"],r"return 0x200;","sector size is 512 bytes")
    required(funcs["0011ab10"],r"qsee_stor_write_sectors\(&DAT_001391e0,param_1 >> 9 & 0x7fffff,param_3 >> 9,param_2\)","protected sector write")
    required(funcs["001177a0"],r"while \(lVar1 != 0x10\)","16 cache entries")
    required(funcs["001174bc"],r"qsee_free\(\)","free helper")
    required(funcs["0011aa6c"],r"return DAT_001391d0;","internal storage-enable byte")
    all_pseudocode=main+"\n"+"\n".join(funcs.values())
    # Absence in these six function bodies is not a proof of all indirect
    # implementation paths or runtime permission gates.
    direct_fuse_call="FUN_00117980(" in all_pseudocode or "qsee_is_sw_fuse_blown(" in all_pseudocode
    if direct_fuse_call:
        raise ValueError("New direct fuse check found: revisit semantics")

    sector_bytes=0x200
    initial_offset_bytes=sector_bytes<<4
    zeroed_bytes=0x3000
    result={
        "scope":"Original stock EEA KM41 signed trustlet Ghidra source, read-only",
        "dispatch_table":{"base":"0x138580","entries":67,"stride":16,
                          "delete_all_keys_0x10e_callback":"0x107c48",
                          "vendor_variant_0x210e_callback":"0x107c48",
                          "read_device_state_0x202_callback":"0x1185a8",
                          "write_device_state_0x203_callback":"0x118878"},
        "delete_all_keys_chain":{
            "handler":"0x107c48",
            "checks_internal_enable_bit":"DAT_001391d0 & 1",
            "early_success_if_enable_bit_zero":True,
            "storage_alloc_and_zero_length_bytes":zeroed_bytes,
            "storage_sector_size_bytes":sector_bytes,
            "storage_write_offset_sectors_if_enabled":initial_offset_bytes//sector_bytes,
            "storage_write_count_sectors_if_enabled":zeroed_bytes//sector_bytes,
            "uses_qsee_stor_write_sectors":True,
            "conditional_internal_cache_slots_cleared":16,
            "no_direct_fuse_check_in_reconstructed_chain":not direct_fuse_call,
        },
        "limitations":[
            "No observation of the enabled flag on the actual phone.",
            "No actual key deletion, RPMB write or lock-state change is performed.",
            "qsee_stor_write_sectors is a protected-storage function, not an EDL sector-offset instruction.",
            "The decompiler may misassign some types and prototype details.",
            "No direct fuse call in selected functions does not exclude other downstream security checks.",
            "Neither deletion success nor a recovery wipe implies persistent UNLOCKED bootloader state."
        ]
    }
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ghidra",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    raw=a.ghidra.read_bytes()
    result=audit(raw.decode("utf-8","replace"))
    result["source_report_sha256"]=hashlib.sha256(raw).hexdigest()
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    print("ORIGINAL_DISPATCH_VERIFIED",json.dumps(result["dispatch_table"]))
    print("DELETE_ALL_KEYS_STORAGE_VERIFIED",json.dumps(result["delete_all_keys_chain"]))
    print("SOURCE_SHA256",result["source_report_sha256"])

if __name__=="__main__":
    main()
