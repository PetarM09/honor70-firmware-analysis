#!/usr/bin/env python3
"""Verify exact C431 Linux task PI field sites against SHA-pinned HONOR sources.

This is a non-operational ABI evidence report. It never builds or runs any
GhostLock exploit, has no phone operations, and emits no boot/physical map.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

BOOT_SHA = "5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"
KERNEL_SHA = "bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
SCHED_SHA = "9f93a2b3c26269a749db7ca74ac184812249be60280012cd3e7d43ac7bc3f024"
RTMUTEX_SHA = "70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9"
# Sites are checked against a separately generated, original SHA-pinned ARM64
# disassembly artifact. Their source-level interpretation is documented below.
SITES = (
 ("task_blocks_on_rt_mutex", "0xffffffc01037dfcc", "ldr", "x8, [x0, #0x18]"),
 ("task_blocks_on_rt_mutex", "0xffffffc01037dfd0", "and", "x23, x8, #0xfffffffffffffffe"),
 ("task_blocks_on_rt_mutex", "0xffffffc01037dfdc", "add", "x24, x2, #0x96c"),
 ("task_blocks_on_rt_mutex", "0xffffffc01037dfec", "mov", "x20, x2"),
 ("task_blocks_on_rt_mutex", "0xffffffc01037dff0", "mov", "x22, x1"),
 ("task_blocks_on_rt_mutex", "0xffffffc01037dffc", "ldr", "w8, [x20, #0x11c]"),
 ("task_blocks_on_rt_mutex", "0xffffffc01037e004", "str", "w8, [x22, #0x40]"),
 ("task_blocks_on_rt_mutex", "0xffffffc01037e008", "ldr", "x10, [x20, #0x488]"),
 ("task_blocks_on_rt_mutex", "0xffffffc01037e00c", "str", "x10, [x22, #0x48]"),
 ("task_blocks_on_rt_mutex", "0xffffffc01037e0c0", "str", "x22, [x20, #0x990]"),
 ("task_blocks_on_rt_mutex", "0xffffffc01037e18c", "ldr", "x8, [x23, #0x980]"),
 ("task_blocks_on_rt_mutex", "0xffffffc01037e1b4", "ldr", "x14, [x23, #0x978]"),
 ("rt_mutex_adjust_prio_chain", "0xffffffc01037d360", "mov", "x19, x0"),
 ("rt_mutex_adjust_prio_chain", "0xffffffc01037d398", "ldr", "x25, [x19, #0x990]"),
 ("remove_waiter", "0xffffffc01037e384", "mrs", "x20, sp_el0"),
 ("remove_waiter", "0xffffffc01037e388", "add", "x21, x20, #0x96c"),
 ("remove_waiter", "0xffffffc01037e3cc", "str", "xzr, [x20, #0x990]"),
)
FIELDS = {
 "task_struct.prio": {"offset": "0x11c", "confidence": "original instruction + HONOR GPL role"},
 "task_struct.dl.deadline": {"offset": "0x488", "confidence": "original instruction + HONOR GPL role"},
 "task_struct.pi_lock": {"offset": "0x96c", "confidence": "original instruction + HONOR GPL role"},
 "task_struct.pi_waiters.rb_root": {"offset": "0x978", "confidence": "binary owner PI tree + GPL struct"},
 "task_struct.pi_waiters.rb_leftmost": {"offset": "0x980", "confidence": "binary owner PI tree + GPL struct"},
 "task_struct.pi_blocked_on": {"offset": "0x990", "confidence": "multiple original task-side read/write sites"},
}
REQUIRED_FIELDS = (
 r"\bint\s+prio\s*;",
 r"\bstruct\s+sched_dl_entity\s+dl\s*;",
 r"\braw_spinlock_t\s+pi_lock\s*;",
 r"\bstruct\s+rb_root_cached\s+pi_waiters\s*;",
 r"\bstruct\s+rt_mutex_waiter\s*\*\s*pi_blocked_on\s*;"
)
REQUIRED_SOURCE = (
 "waiter->prio = task->prio;",
 "waiter->deadline = task->dl.deadline;"
)

def verify(binary, sched_bytes, rtmutex_bytes, *, expected_sched=SCHED_SHA, expected_rtmutex=RTMUTEX_SHA):
    if (binary.get("boot_sha256"), binary.get("kernel_image_sha256")) != (BOOT_SHA, KERNEL_SHA):
        raise ValueError("Original signed kernel provenance missing")
    if hashlib.sha256(sched_bytes).hexdigest() != expected_sched:
        raise ValueError("HONOR sched.h source mismatch")
    if hashlib.sha256(rtmutex_bytes).hexdigest() != expected_rtmutex:
        raise ValueError("HONOR rtmutex.c source mismatch")
    sched = sched_bytes.decode("utf-8")
    match = re.search(r"struct\s+task_struct\s*\{(.*?)\n\};", sched, re.S)
    if not match:
        raise ValueError("Could not find task_struct declaration")
    for expression in REQUIRED_FIELDS:
        if re.search(expression, match.group(1)) is None:
            raise ValueError("Required GPL task field absent: " + expression)
    code = rtmutex_bytes.decode("utf-8")
    if not all(source in code for source in REQUIRED_SOURCE):
        raise ValueError("Required GPL waiter assignment absent")
    functions = binary.get("functions", {})
    for fn, address, mnemonic, operand in SITES:
        entry = functions.get(fn, {})
        matches = [i for i in entry.get("initial_instructions_for_register_flow", ())
                   if i.get("address") == address]
        if len(matches) != 1 or (matches[0].get("mnemonic"), matches[0].get("operand")) != (mnemonic, operand):
            raise ValueError("Machine instruction mismatch: " + fn + "@" + address)
        if not re.fullmatch("[0-9a-f]{8}", matches[0].get("bytes", "")):
            raise ValueError("Missing instruction bytes: " + fn + "@" + address)
    return {
        "schema_version": 1,
        "target": "HONOR 70 FNE-NX9, MagicOS 8 C431, Linux 5.4.295",
        "original_boot_sha256": BOOT_SHA,
        "original_kernel_sha256": KERNEL_SHA,
        "honor_gpl_sched_h_sha256": expected_sched,
        "honor_gpl_rtmutex_c_sha256": expected_rtmutex,
        "independent_original_arm64_instruction_sites_confirmed": len(SITES),
        "task_struct_fields": FIELDS,
        "comparative_GPL_version": "5.4.242, not exact 5.4.295",
        "evidence_scope": "binary register flow and source-identity corroboration",
        "full_C431_struct_ABI_established": False,
        "userland_GhostLock_trigger_tested": False,
        "kernel_root_demonstrated": False,
        "bootloader_unlock_demonstrated": False,
        "device_operations": 0
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--arm64-report", required=True, type=Path)
    p.add_argument("--sched", required=True, type=Path)
    p.add_argument("--rtmutex", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    result = verify(json.loads(a.arm64_report.read_text()), a.sched.read_bytes(), a.rtmutex.read_bytes())
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2) + "\n")
    print("EXACT_ORIGINAL_C431_TASK_PI_INSTRUCTION_EVIDENCE", len(SITES))
    print("VERIFIED_TASK_FIELDS", json.dumps(FIELDS, sort_keys=True))
    print("GHOSTLOCK_ROOT_DEMONSTRATED", False)

if __name__ == "__main__":
    main()
