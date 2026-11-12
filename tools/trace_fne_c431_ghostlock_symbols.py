#!/usr/bin/env python3
"""Inventory exact-C431 ARM64 symbols relevant to GhostLock compatibility.

This is a read-only stock-firmware *symbol inventory*, NOT an exploit profile.
Missing, duplicated and struct-field symbols are never guessed from FNE-AN00.
No physical load address, writes, fault trigger or runtime payload is emitted.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

BOOT_SHA = "5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"
KERNEL_SHA = "bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
BASE = 0xffffffc010080000
ANCHOR = ("remove_waiter", 0xffffffc01037e350)
SYMBOLS = (
    "remove_waiter", "rt_mutex_start_proxy_lock", "rt_mutex_cleanup_proxy_lock",
    "futex_requeue", "__arm64_sys_futex", "do_futex",
    "init_task", "init_cred", "init_uts_ns", "empty_zero_page",
    "root_task_group", "selinux_state", "sig_enforce", "kptr_restrict",
    "selinux_blob_sizes", "security_hook_heads", "kmalloc_caches",
    "anon_pipe_buf_ops", "ashmem_misc", "ashmem_fops",
    "system_unbound_wq", "call_usermodehelper_exec_work",
    "configfs_read_file", "configfs_write_bin_file",
    "copy_splice_read", "noop_llseek"
)
ENTRY = re.compile(r"^([0-9a-fA-F]{8,16})\s+([a-zA-Z])\s+(\S+)$")


def canonical(symbol):
    """Discard kallsyms numeric suffixes, but do not conflate CFI trampolines."""
    if ".cfi_jt" in symbol or symbol.startswith("__cfi_"):
        return None
    return symbol.split("$", 1)[0]


def parse_nm(lines):
    wanted = set(SYMBOLS)
    found = {name: [] for name in SYMBOLS}
    for line in lines.splitlines():
        match = ENTRY.fullmatch(line.strip())
        if not match:
            continue
        address, kind, symbol = match.groups()
        name = canonical(symbol)
        if name in wanted and kind.upper() not in ("U", "A"):
            va = int(address, 16)
            if va >= BASE:
                found[name].append({"va": va, "kind": kind, "raw_name": symbol})
    output = {}
    for name, candidates in found.items():
        addresses = {item["va"] for item in candidates}
        if not candidates:
            output[name] = {"status": "missing", "offset": None}
        elif len(addresses) > 1:
            output[name] = {
                "status": "ambiguous", "offset": None,
                "candidate_virtual_addresses": [hex(a) for a in sorted(addresses)]
            }
        else:
            va = next(iter(addresses))
            output[name] = {
                "status": "one_address",
                "virtual_address": hex(va),
                "relative_to_original_image_base": hex(va - BASE),
                "symbol_types": sorted({item["kind"] for item in candidates})
            }
    return output


def audit_symbol_lines(text):
    resolved = parse_nm(text)
    anchor = resolved[ANCHOR[0]]
    if anchor["status"] != "one_address" or anchor["virtual_address"] != hex(ANCHOR[1]):
        raise ValueError("Signed EEA remove_waiter symbol anchor does not match")
    return {
        "schema_version": 1,
        "kernel_release": "5.4.295-qgki-ga2d8945339ca",
        "symbol_base": hex(BASE),
        "anchor_name": ANCHOR[0],
        "anchor_expected": hex(ANCHOR[1]),
        "exact_symbol_status": resolved,
        "resolved_count": sum(1 for item in resolved.values() if item["status"] == "one_address"),
        "missing_count": sum(1 for item in resolved.values() if item["status"] == "missing"),
        "ambiguous_count": sum(1 for item in resolved.values() if item["status"] == "ambiguous"),
        "never_infer_from_other_builds": True,
        "struct_layout_fields_inferred": False,
        "kernel_phys_load": None,
        "ready_to_build_or_execute_ghostlock": False,
        "device_operations": 0,
        "interpretation": "Exact executable/global symbol inventory only. Does not establish a functional root exploit."
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boot", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    a = parser.parse_args()
    for path, expected in ((a.boot, BOOT_SHA), (a.kernel, KERNEL_SHA)):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit("Refusing non-original C431 signed input: " + path.name)
    nm = subprocess.run(
        ["nm", "-n", "--defined-only", str(a.elf)],
        capture_output=True, text=True, check=True
    )
    result = audit_symbol_lines(nm.stdout)
    result["original_boot_sha256"] = BOOT_SHA
    result["original_kernel_sha256"] = KERNEL_SHA
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("EXACT_STOCK_C431_SYMBOLS_RESOLVED", result["resolved_count"])
    print("MISSING", result["missing_count"], "AMBIGUOUS", result["ambiguous_count"])
    print("UNSAFE_TO_EXECUTE_GHOSTLOCK_WITH_THIS_INVENTORY", True)


if __name__ == "__main__":
    main()
