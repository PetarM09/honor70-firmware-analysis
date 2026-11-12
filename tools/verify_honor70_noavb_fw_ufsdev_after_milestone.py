#!/usr/bin/env python3
"""HONOR70 signed stock ABL: prove fw_ufsdev NoAVB label follows milestone.

This distinguishes the firmware-updater helper from the public Redmi 14R
GPT-dependent NO_AVB boot bypass. No live device or firmware writes.
"""
import argparse, hashlib, json, re
from pathlib import Path

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--ghidra",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    source=a.ghidra.read_bytes()
    s=source.decode("utf-8","replace")
    start=s.find("===== AVB_FUNCTION 00003144 ")
    if start<0:
        raise ValueError("Original signed ABL 0x3144 decompilation missing")
    end=s.find("===== AVB_FUNCTION ",start+18)
    f=s[start:end if end>=0 else None]
    if len(f)<30000:
        raise ValueError("Original ABL 0x3144 function is truncated")
    names={
        "vb2_verification_failure_logging": 'LoadImageAndAuthVB2 fail errno',
        "milestone_logging": 'Sending Milestone Call',
        "milestone_provider_invocation": '(*(longlong *)(param_1 + 0x430) + 0x20))();',
        "noavb_named_ufs_device_helper": 'NoAVBLoad_fw_ufsdev Start',
        "named_firmware_partition": 'L"fw_ufsdev"',
        "ufs_firmware_image_marker": "pcVar34[1] == 'P'",
        "ufs_flash_handler": 'FUN_00028190('
    }
    offsets={}
    for label,literal in names.items():
        at=f.find(literal)
        if at<0:
            raise ValueError("Expected original source evidence not present: "+label)
        offsets[label]=at
    order=[
        offsets["vb2_verification_failure_logging"],
        offsets["milestone_logging"],
        offsets["milestone_provider_invocation"],
        offsets["noavb_named_ufs_device_helper"],
        offsets["named_firmware_partition"],
        offsets["ufs_firmware_image_marker"],
    ]
    if order != sorted(order):
        raise ValueError("Original signed ABL execution/source text order changed")
    if "if (unaff_x28 == (undefined8 *)0x0)" not in f[
            offsets["milestone_provider_invocation"]:offsets["noavb_named_ufs_device_helper"]]:
        raise ValueError("Expected milestone return-gated UFS path not present")
    result={
        "original_signed_abl_symbol":"FUN_00003144",
        "original_source_sha256":hashlib.sha256(source).hexdigest(),
        "function_bytes":len(f),
        "exact_pseudocode_token_positions":offsets,
        "confirmed":{
            "vb2_path_before_milestone":True,
            "milestone_provider_method_plus_0x20_before_fw_ufsdev":True,
            "NoAVB_named_path_targets_fw_ufsdev_firmware_partition":True,
            "the_label_NoAVBLoad_fw_ufsdev_is_not_evidence_of_android_boot_NO_AVB":True
        },
        "not_proven":[
            "All possible boot-mode selection paths were exhaustively analyzed",
            "Whether signed ABL uses a GPT-dependent Is_VERIFIED_BOOT_2 predicate elsewhere",
            "Live milestone software-fuse status",
            "A persistent HONOR70 bootloader unlock",
        ],
        "safe_scope":"offline decompiled signed firmware only; no GPT writes, no EDL, no Fastboot commands"
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    print("HONOR70_NOAVB_FW_UFSDEV_IS_AFTER_MILESTONE_CONFIRMED")
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":
    main()
