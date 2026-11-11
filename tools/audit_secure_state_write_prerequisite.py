#!/usr/bin/env python3
"""Audit signed EEA VerifiedBootDxe state-write prerequisite and SCM mask classes.

Input: prior SHA-pinned Ghidra textual report, *not* a device partition.
Does not send Fastboot, EDL, QSEE or RPMB commands.
"""
import argparse
from collections import Counter
import hashlib
import json
import re
from pathlib import Path

PRIMARY_MASK = 0x8703
FALLBACK_MASK = 0x8723
FUNCTION_IDS = ("0000153c", "00003904", "00003898")


def section(report, address):
    match = re.search(
        r"(?m)^======== FUNCTION " + re.escape(address) + r"\b[^\n]*\n", report
    )
    if not match:
        raise ValueError("Missing Ghidra function " + address)
    next_section = re.search(r"(?m)^======== FUNCTION ", report[match.end():])
    end = match.end() + next_section.start() if next_section else len(report)
    return report[match.end():end]


def require(pattern, source, label):
    if not re.search(pattern, source, re.S):
        raise ValueError("Expected firmware evidence missing: " + label)


def classify(s):
    # Based on Ghidra's two selector functions. This is NOT a live SCM read.
    primary_secure = (s & PRIMARY_MASK) == 0
    fallback_secure = (s & FALLBACK_MASK) == 0
    return {
        "security_state": hex(s),
        "primary_backend": "keymaster_RPMB" if primary_secure else "raw_devinfo",
        "if_keymaster_transport_failed": (
            "no_raw_fallback" if fallback_secure else "raw_fallback_condition_met"
        ) if primary_secure else "not_applicable_to_direct_path"
    }


def audit(text):
    funcs = {addr: section(text, addr) for addr in FUNCTION_IDS}
    rw = funcs["0000153c"]
    primary = funcs["00003904"]
    fallback = funcs["00003898"]

    require(r"uVar1\s*&\s*0x8703\s*\)\s*==\s*0", primary, "primary secure mask")
    require(r"uVar1\s*&\s*0x8723\s*\)\s*==\s*0", fallback, "fallback secure mask")
    require(r"\*param_1\s*=\s*1", primary, "primary 1 flag on zero masked state")
    require(r"\*param_1\s*=\s*1", fallback, "fallback 1 flag on zero masked state")
    require(r"param_2\s*==\s*0", rw, "read operation branch")
    require(r"param_2\s*!=\s*1", rw, "write operation branch")
    # Focus exclusively on the decompiled write branch. The read branch also has 0x202.
    w = rw.split("if (param_2 != 1)", 1)[-1]
    pre_read = re.search(r"0x202\)", w)
    post_write = re.search(r"0x203\)", w)
    if not pre_read or not post_write or pre_read.start() >= post_write.start():
        raise ValueError("No 0x202 prerequisite before 0x203 in write branch")
    between = w[pre_read.end():post_write.start()]
    require(r"if\s*\(\s*\(lVar3\s*==\s*0\)\s*&&\s*\(local_d8\s*==\s*0\)\s*\)", 
            between, "QSEE read success gate before 0x203")
    require(r"FUN_00003898\(local_ac\)", w[post_write.end():],
            "failed pre-read falls through to second SCM check")
    require(r"if\s*\(local_ac\[0\]\s*!=\s*'\\0'\)", w[post_write.end():],
            "fallback secure flag rejects raw write")
    require(r"FUN_00002a1c\(", w, "direct partition write function")
    # Read status and error labels extracted from the same function. These are
    # possible branches, not evidence of their execution on the actual handset.
    diagnostic_strings = sorted(set(re.findall(
        r'"(VB: RWDeviceState:[^"\n]*)', rw
    )))
    affected_bits = [1 << k for k in range(16) if FALLBACK_MASK & (1 << k)]
    counts = Counter()
    for value in range(1 << 16):
        c = classify(value)
        counts[(c["primary_backend"], c["if_keymaster_transport_failed"])] += 1
    cases = [
        {"class": "all_considered_mask_bits_zero", **classify(0x0000)},
        {"class": "only_bit_0x20_set", **classify(0x0020)},
        {"class": "primary_mask_bit_0x01_set", **classify(0x0001)},
        {"class": "bit_0x20_and_primary_mask_bit_set", **classify(0x0021)},
        {"class": "primary_mask_bit_0x8000_set", **classify(0x8000)}
    ]
    return {
        "source": "Signed EEA VerifiedBootDxe Ghidra textual reconstruction, firmware only",
        "observed_functions": {
            "read_write_protocol": "0x153c",
            "primary_selector": "0x3904",
            "fallback_selector": "0x3898"
        },
        "firmware_observations": {
            "write_branch_issues_read_0x202_before_write_0x203": True,
            "write_0x203_requires_successful_read_transport_and_status": True,
            "fallback_after_failed_secure_preread_rechecks_SCM": True,
            "failure_means_write_0x203_was_necessarily_invoked": False,
            "read_response_error_can_prevent_write_0x203": True
        },
        "primary_mask": hex(PRIMARY_MASK),
        "fallback_mask": hex(FALLBACK_MASK),
        "mask_xor": hex(PRIMARY_MASK ^ FALLBACK_MASK),
        "special_disagreement_bit": hex(FALLBACK_MASK & ~PRIMARY_MASK),
        "distinct_significant_bits": [hex(v) for v in affected_bits],
        "example_bit_classes_not_live_device_values": cases,
        "16bit_state_class_counts": [
            {"primary_backend": k[0], "fallback_on_failed_keymaster": k[1],
             "16bit_states": n} for k, n in sorted(counts.items())
        ],
        "diagnostic_strings_in_rw_function": diagnostic_strings,
        "limitations": [
            "The text decompiler may misinfer types, register provenance and error values.",
            "No direct observation of device SCM security state or milestone fuse.",
            "A mask class permitting raw fallback is not proof that hardware can enter it.",
            "A status returned by Fastboot/UI does not establish persistent unlock.",
            "Firmware analysis did not execute or modify any phone operation."
        ]
    }


def selftest():
    assert FALLBACK_MASK ^ PRIMARY_MASK == 0x20
    assert classify(0)["primary_backend"] == "keymaster_RPMB"
    assert classify(0)["if_keymaster_transport_failed"] == "no_raw_fallback"
    assert classify(0x20)["primary_backend"] == "keymaster_RPMB"
    assert classify(0x20)["if_keymaster_transport_failed"] == "raw_fallback_condition_met"
    assert classify(1)["primary_backend"] == "raw_devinfo"
    assert classify(0x21)["primary_backend"] == "raw_devinfo"
    print("SELFTEST_OK")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args()
    if args.selftest:
        selftest()
        return
    if args.report is None or args.output is None:
        p.error("--report and --output are required unless --selftest")
    src = args.report.read_text(encoding="utf-8", errors="replace")
    result = audit(src)
    result["ghidra_report_sha256"] = hashlib.sha256(args.report.read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("EVIDENCE_READ_THEN_WRITE", result["firmware_observations"]["write_branch_issues_read_0x202_before_write_0x203"])
    print("MASKS", result["primary_mask"], result["fallback_mask"], "XOR", result["mask_xor"])
    for item in result["16bit_state_class_counts"]:
        print("CLASS", json.dumps(item, sort_keys=True))
    for item in result["example_bit_classes_not_live_device_values"]:
        print("EXAMPLE", json.dumps(item, sort_keys=True))


if __name__ == "__main__":
    main()
