#!/usr/bin/env python3
"""Offline audit of hardening CONFIGs in original SHA-verified C431 kernel.

Read-only exact kernel Image inspection. This is a build-config inventory,
not evidence of active runtime mitigations or working GhostLock exploit.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path

from audit_fne_embedded_ikconfig import KERNEL_SHA256, scan

EXPECTED_IKCONFIG_SHA = "99107cb0eb989d1381321f560664c78bf4b47ebdecb2cc33e9a7d430e1e973c4"

CATEGORIES = {
    "memory_layout": (
        "CONFIG_RANDOMIZE_BASE", "CONFIG_RANDOMIZE_MEMORY",
        "CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT", "CONFIG_VMAP_STACK",
        "CONFIG_THREAD_INFO_IN_TASK", "CONFIG_GCC_PLUGIN_RANDSTRUCT",
    ),
    "control_flow_and_stack": (
        "CONFIG_CFI_CLANG", "CONFIG_CFI_PERMISSIVE", "CONFIG_SHADOW_CALL_STACK",
        "CONFIG_ARM64_PTR_AUTH", "CONFIG_ARM64_PTR_AUTH_KERNEL",
        "CONFIG_ARM64_BTI_KERNEL", "CONFIG_STACKPROTECTOR",
        "CONFIG_STACKPROTECTOR_STRONG",
    ),
    "kernel_memory_policy": (
        "CONFIG_STRICT_KERNEL_RWX", "CONFIG_STRICT_MODULE_RWX",
        "CONFIG_HARDENED_USERCOPY", "CONFIG_FORTIFY_SOURCE",
        "CONFIG_SLAB_FREELIST_RANDOM", "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON", "CONFIG_INIT_ON_FREE_DEFAULT_ON",
    ),
    "debug_and_fault_detection": (
        "CONFIG_KASAN", "CONFIG_KFENCE", "CONFIG_KCSAN", "CONFIG_SLUB_DEBUG",
    ),
    "relevant_os_gates": (
        "CONFIG_FUTEX", "CONFIG_FUTEX_PI", "CONFIG_RT_MUTEXES",
        "CONFIG_SECCOMP_FILTER", "CONFIG_SECURITY_SELINUX",
        "CONFIG_PREEMPT", "CONFIG_PREEMPT_NONE", "CONFIG_PREEMPT_VOLUNTARY",
    ),
}

VALID = {"y", "m", "n", "not_listed"}

def parse_options(text: str):
    value = {}
    for line in text.splitlines():
        enabled = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(y|m|n)", line)
        disabled = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
        if enabled:
            name, flag = enabled.groups()
        elif disabled:
            name, flag = disabled.group(1), "n"
        else:
            continue
        if name in value and value[name] != flag:
            raise ValueError("Conflicting kernel config entries: " + name)
        value[name] = flag
    return value

def classify(raw: bytes, *, expected_hash=EXPECTED_IKCONFIG_SHA):
    digest=hashlib.sha256(raw).hexdigest()
    if expected_hash is not None and digest != expected_hash:
        raise ValueError("Exact stock C431 IKCONFIG digest mismatch")
    text=raw.decode("utf-8")
    options=parse_options(text)
    categories={}
    for name, keys in CATEGORIES.items():
        categories[name]={key:options.get(key,"not_listed") for key in keys}
        if not all(v in VALID for v in categories[name].values()):
            raise ValueError("Unrecognized kernel build flag state")
    return {
        "schema_version":1,
        "kernel_image_sha256":KERNEL_SHA256,
        "kernel_ikconfig_sha256":digest,
        "source_identity":"exact-original stock HONOR 70 FNE-NX9 C431 8.0.0.290",
        "source_sha256_verified":expected_hash is not None,
        "flags":categories,
        "interpretation_limits":[
            "Compile-time CONFIG is not a live proof of runtime mitigation enforcement",
            "Option absence is not necessarily a negative value: not_listed is distinct from n",
            "Built-in kernel functions and hardening do not prove exploitability or root",
            "This report does not infer kernel physical addresses, exploitation offsets or access to bootloader keys",
        ],
        "ghostlock_root_demonstrated":False,
        "persistent_bootloader_unlock_demonstrated":False,
        "device_operations":0,
    }

def inspect_image(image:bytes, *, require_image_sha=KERNEL_SHA256):
    actual=hashlib.sha256(image).hexdigest()
    if require_image_sha is not None and actual!=require_image_sha:
        raise ValueError("Wrong C431 original kernel Image SHA256")
    status,raw,offset=scan(image)
    if status!="embedded_config_found" or raw is None:
        raise ValueError("Original embedded IKCONFIG absent or malformed")
    output=classify(raw)
    output["kernel_image_sha256"]=actual
    output["original_ikconfig_marker_offset"]=offset
    output["source_image_verified"]=require_image_sha is not None
    return output

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kernel",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    result=inspect_image(args.kernel.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("C431_ORIGINAL_HARDENING_CONFIG_VERIFIED",result["source_sha256_verified"])
    for category,flags in result["flags"].items():
        for name,state in flags.items():
            print("CONFIG",category,name,state)
    print("GHOSTLOCK_ROOT_OR_UNLOCK_DEMONSTRATED",False)

if __name__=="__main__":
    main()
