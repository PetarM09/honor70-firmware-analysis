#!/usr/bin/env python3
"""Offline source+machine-code proof of early invalid CMP_REQUEUE_PI rejection.

This only verifies the original signed C431 futex_requeue equal-address
branch occurs before get_futex_key / futex hash operations. NOT an exploit,
NOT proof of a UAF, and NEVER calls syscalls or the phone itself.
"""
import argparse, hashlib, json, re
from pathlib import Path

BOOT_SHA = "5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"
IMAGE_SHA = "bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
FENNIE_FUTEX_SHA = "71b9c7591dc611e6f92e742858bcc044cf01b605208058498e31d444b7704106"
SITES = (
    ("0xffffffc0103ca528", "mov", "w24, w6"),
    ("0xffffffc0103ca530", "mov", "x25, x2"),
    ("0xffffffc0103ca538", "mov", "x27, x0"),
    ("0xffffffc0103ca540", "cbz", "w6, #0xffffffc0103ca560"),
    ("0xffffffc0103ca544", "cmp", "x27, x25"),
    ("0xffffffc0103ca548", "b.eq", "#0xffffffc0103cb828"),
    ("0xffffffc0103ca550", "ldr", "x8, [x19, #0xa98]"),
    ("0xffffffc0103ca558", "cmp", "w3, #1"),
    ("0xffffffc0103ca56c", "mov", "w1, w22"),
    ("0xffffffc0103ca574", "bl", "#0xffffffc0103cd3dc"),
)
SOURCE_NEEDLES = (
    "if (nr_wake < 0 || nr_requeue < 0)",
    "if (!IS_ENABLED(CONFIG_FUTEX_PI) && requeue_pi)",
    "if (uaddr1 == uaddr2)",
    "if (refill_pi_state_cache())",
    "if (nr_wake != 1)",
    "ret = get_futex_key(uaddr1, flags & FLAGS_SHARED",
)

def verify(report, source, *, expected_source=FENNIE_FUTEX_SHA):
    if (report.get("boot_sha256"), report.get("kernel_image_sha256")) != (
        BOOT_SHA, IMAGE_SHA
    ):
        raise ValueError("Wrong original C431 binary evidence")
    if hashlib.sha256(source).hexdigest() != expected_source:
        raise ValueError("Wrong HONOR GPL futex.c source")
    text = source.decode("utf-8")
    start = text.find("static int futex_requeue(")
    if start < 0:
        raise ValueError("Missing Fennie futex_requeue")
    end = text.find("retry:", start)
    if end < start:
        raise ValueError("Missing early futex guard section")
    block = text[start:end]
    positions = [block.find(needle) for needle in SOURCE_NEEDLES]
    if min(positions) < 0 or positions != sorted(positions):
        raise ValueError("Source guard sequence changed")
    funcs = report.get("functions", {})
    f = funcs.get("futex_requeue", {})
    if f.get("symbol_va") != "0xffffffc0103ca4d8":
        raise ValueError("Wrong C431 futex_requeue anchor")
    ins = f.get("initial_instructions_for_register_flow", [])
    by_addr = {}
    for i in ins:
        by_addr.setdefault(i["address"], []).append(i)
    for addr, mnemonic, operand in SITES:
        candidates = by_addr.get(addr, [])
        if len(candidates) != 1:
            raise ValueError("Missing or duplicated original instruction " + addr)
        inst = candidates[0]
        if (inst.get("mnemonic"), inst.get("operand")) != (mnemonic, operand):
            raise ValueError("Different original instruction " + addr)
        if not re.fullmatch(r"[0-9a-f]{8}", inst.get("bytes", "")):
            raise ValueError("No original instruction bytes " + addr)
    return {
        "schema_version": 1,
        "device": "HONOR 70 FNE-NX9 C431, original signed kernel 5.4.295",
        "boot_sha256": BOOT_SHA,
        "kernel_sha256": IMAGE_SHA,
        "honor_fennie_futex_c_sha256": expected_source,
        "assertions_passed": len(SITES),
        "equal_addresses_branch_before_kernel_queue_operations": True,
        "app_test_request": {
            "operation": "FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG",
            "same_source_and_destination_address": True,
            "nr_wake": 1, "nr_requeue": 0, "cmpval": 0,
            "expected_error": "EINVAL (22)"
        },
        "does_not_enter_requeue_waiter_processing": True,
        "runtime_app_syscall_dispatch": "not_yet_measured",
        "ghostlock_rollback_uaf_triggered": False,
        "root_or_unlock_demonstrated": False,
        "device_operations": 0,
        "scope_note": "The original kernel rejects equal addresses before any queue access. This fails-before-trigger test is not an exploit."
    }

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original-arm64", required=True, type=Path)
    p.add_argument("--fennie-futex", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    result = verify(
        json.loads(a.original_arm64.read_text()), a.fennie_futex.read_bytes()
    )
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2) + "\n")
    print("ORIGINAL_C431_EQUAL_ADDR_GUARD_CHECKS", result["assertions_passed"])
    print("REJECTS_BEFORE_WAITERS", True)
    print("ROOT_EXPLOIT_RUN", False)
