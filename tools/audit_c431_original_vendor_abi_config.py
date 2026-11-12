#!/usr/bin/env python3
"""Signed C431 embedded IKCONFIG OEM ABI feature inventory.

Read-only; measures actual compiled options instead of inferring them from
an unrelated generic 5.4.295 source tree. No exploit or device operations.
"""
import argparse
import hashlib
import json
from pathlib import Path

from audit_fne_embedded_ikconfig import KERNEL_SHA256, scan
from audit_c431_original_kernel_hardening import (
    EXPECTED_IKCONFIG_SHA, parse_options
)

WATCH = (
    "CONFIG_HN_VIP_THREAD", "CONFIG_HONOR_SCHED_VIP",
    "CONFIG_HN_RTG", "CONFIG_HN_QOS_THREAD",
    "CONFIG_HN_RTG_FRAME_USE_MIN_UTIL", "CONFIG_HN_RTG_FRAME",
    "CONFIG_HN_RTG_FRAME_USE_PREFER_IDLE",
    "CONFIG_HONOR_SCHED_VIP", "CONFIG_SCHED_WALT",
    "CONFIG_ANDROID_VENDOR_HOOKS", "CONFIG_ANDROID_KABI_RESERVE",
    "CONFIG_ANDROID_KABI", "CONFIG_LTO_CLANG",
    "CONFIG_LTO_CLANG_THIN", "CONFIG_THINLTO", "CONFIG_CFI_CLANG",
    "CONFIG_GCC_PLUGIN_RANDSTRUCT", "CONFIG_RANDSTRUCT",
    "CONFIG_VMAP_STACK", "CONFIG_RANDOMIZE_BASE",
    "CONFIG_STACKPROTECTOR_STRONG",
    "CONFIG_FUTEX", "CONFIG_FUTEX_PI",
)

def inspect(raw, expected_ikconfig=EXPECTED_IKCONFIG_SHA):
    if hashlib.sha256(raw).hexdigest()!=expected_ikconfig:
        raise ValueError("Not the exact original C431 signed kernel config")
    config=parse_options(raw.decode("utf-8"))
    result={key:config.get(key,"not_listed") for key in WATCH}
    return {
       "schema_version":1,
       "signed_kernel_image_sha256":KERNEL_SHA256,
       "signed_ikconfig_sha256":expected_ikconfig,
       "compiled_feature_status":result,
       "generic_source_abi_is_not_automatically_c431":True,
       "source_declarations_do_not_prove_compiled_struct_offsets":True,
       "actual_c431_task_struct_layout_fully_recovered":False,
       "userland_root_or_uaf_executed":False,
       "device_operations":0
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kernel",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    b=args.kernel.read_bytes()
    if hashlib.sha256(b).hexdigest()!=KERNEL_SHA256:
        raise SystemExit("Wrong C431 kernel image")
    status,raw,offset=scan(b)
    if status!="embedded_config_found" or raw is None:
        raise SystemExit("Original embedded config unavailable")
    report=inspect(raw)
    report["kernel_image_verified"]=True
    report["source_marker_offset"]=offset
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+"\n")
    for name,value in report["compiled_feature_status"].items():
        print(name,value)
    print("OEM_BINARY_ABI_FROM_GENERIC_SOURCE",False)
if __name__=="__main__":
    main()
