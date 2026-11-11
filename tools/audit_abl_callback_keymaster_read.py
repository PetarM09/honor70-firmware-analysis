#!/usr/bin/env python3
"""Offline ABL confirmation callback / Keymaster READ gate joint audit.

Only consumes original hash-pinned firmware and old Ghidra text reports.
No phone interaction, no EDL writes, and no Keymaster execution.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM

EXPECTED_ABL_SHA = "ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087"
TARGETS = {
    "km_read_device_state": "1185a8",
    "km_write_device_state": "118878",
    "km_milestone_check": "117980",
    "km_milestone_set": "117a18",
    "km_command_eligibility": "11b174",
}

WINDOWS = {
    "UI_confirmation_callback": (0x3d9b8, 0x3dac0),
    "VBRwDevice_call_wrapper": (0x37ac0, 0x37b90),
    "ABL_device_state_setter": (0x43688, 0x437d0),
    "unlock_command_UI_route": (0x279b0, 0x27a40),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ghidra_function(report, address):
    marker = re.search(r"(?m)^===== TARGET " + address + r" =====\s*$", report)
    if marker is None:
        raise ValueError("Missing original Keymaster target " + address)
    next_marker = re.search(r"(?m)^===== TARGET ", report[marker.end():])
    end = marker.end() + next_marker.start() if next_marker else len(report)
    body = report[marker.end():end]
    if "MISSING_FUNCTION" in body or "ERROR " in body[:120]:
        raise ValueError("Original decompilation incomplete for " + address)
    return body


def parse_abl(binary):
    if sha(binary) != EXPECTED_ABL_SHA:
        raise ValueError("Original EEA LinuxLoader hash mismatch")
    cap = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cap.detail = True
    output = {}
    for label, (low, high) in WINDOWS.items():
        ins = list(cap.disasm(binary[low:high], low))
        if not ins or len(ins) < 8:
            raise ValueError("Disassembly empty/truncated for " + label)
        output[label] = {
            "start": hex(low),
            "end_exclusive": hex(high),
            "instructions": [f"{i.address:#x} {i.mnemonic} {i.op_str}" for i in ins],
            "direct_calls": [
                {"site": hex(i.address), "target": hex(i.operands[0].imm)}
                for i in ins if i.mnemonic == "bl" and
                len(i.operands) > 0 and i.operands[0].type == ARM64_OP_IMM
            ]
        }
    # Check byte-backed, known call/branch sites, not just decompiler prose.
    byaddr = {}
    for w in output.values():
        for line in w["instructions"]:
            a = int(line.split(" ", 1)[0], 16)
            byaddr[a] = line
    for address, mnemonic, target in [
        (0x3d9e0, "bl", "0x37ac0"),
        (0x3d9e4, "cbz", "0x3da48"),
        (0x3da5c, "bl", "0x43688"),
        (0x279d0, "bl", "0x3dab8"),
    ]:
        found = byaddr.get(address, "")
        if not re.search(r"^0x[0-9a-f]+ " + mnemonic + r"\b", found) or target not in found:
            raise ValueError(f"Expected EEA ABL instruction absent at {address:#x}: {found}")
    return output


def parse_keymaster(text):
    result = {}
    for name, addr in TARGETS.items():
        body = ghidra_function(text, addr)
        calls = sorted(set(re.findall(r"\b(?:FUN|thunk_FUN)_[0-9a-fA-F]{8}\b|\bqsee_[A-Za-z0-9_]+\b", body)))
        raw_ret = sorted(set(re.findall(r"\b0x(?:fff[0-9a-fA-F]{5}|[0-9a-fA-F]{1,8})\b", body)))
        guards = {
            "mentions_fuse_checker": ("qsee_is_sw_fuse_blown" in body or "FUN_00117980" in body),
            "mentions_fuse_blow": "qsee_blow_sw_fuse" in body,
            "mentions_negative_15_constant": (
                "0xfffffff1" in body.lower() or "0xfffffffffffffff1" in body.lower()
            ),
            "mentions_return_code_15_decimal": bool(re.search(r"(?:return|=)\s*-15\s*;", body)),
        }
        result[name] = {
            "ghidra_target": "0x" + addr,
            "body_sha256": sha(body.encode()),
            "body_bytes": len(body),
            "calls_and_symbols": calls[:100],
            "status_constants": raw_ret[:80],
            "guards": guards,
        }
    # Check presence of the previously identified fuse-check helper in BOTH handlers.
    for label in ("km_read_device_state", "km_write_device_state"):
        if not result[label]["guards"]["mentions_fuse_checker"]:
            raise ValueError("Previously documented fuse check not found in " + label)
    if not result["km_milestone_check"]["guards"]["mentions_fuse_checker"]:
        raise ValueError("Milestone checker did not reference expected qsee fuse primitive")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abl", required=True, type=Path)
    parser.add_argument("--km-ghidra", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    abi = args.abl.read_bytes()
    ghidra = args.km_ghidra.read_text(errors="replace")
    callback = parse_abl(abi)
    keymaster = parse_keymaster(ghidra)
    report = {
        "scope": "Original signed EEA firmware, offline only",
        "eea_abl_sha256": sha(abi),
        "km_ghidra_report_sha256": sha(args.km_ghidra.read_bytes()),
        "verified_callback_calls_read_first": True,
        "verified_callback_contains_write_setter": True,
        "abl_windows": callback,
        "keymaster_functions": keymaster,
        "limitations": [
            "Adjacent disassembly windows are not a full proven CFG.",
            "Ghidra pseudo-C is not a hardware runtime trace.",
            "No evidence that the user's prior UI callback reached the protected write.",
            "A detected error constant is not proof of the live error reason.",
            "No code is injected, no storage or security state is modified."
        ]
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print("ABL_SHA256_OK", report["eea_abl_sha256"])
    for name in ("UI_confirmation_callback", "ABL_device_state_setter", "VBRwDevice_call_wrapper"):
        print("ABL_WINDOW", name)
        for line in callback[name]["instructions"]:
            print("ARM64", line)
    for name, item in keymaster.items():
        print("KM", name, item["ghidra_target"], json.dumps(item["guards"]),
              "CALLS", json.dumps(item["calls_and_symbols"]))


if __name__ == "__main__":
    main()
