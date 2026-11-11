#!/usr/bin/env python3
"""Compare original ABL normal/critical state-set and recovery-wipe branch.

Pure offline analysis of SHA-pinned EEA LinuxLoader and its archived Ghidra
decompilation. Never sends EDL, Fastboot, UEFI, Keymaster or storage commands.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

EXPECTED_SHA256 = "ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087"
FUNCS = ("00043688", "00013008", "00038370", "00037ac0")

INSTRUCTION_ASSERTIONS = {
    0x436f0: ("bl", "#0x13008", "normal state check"),
    0x436f8: ("cmp", "w8, w23, uxtb", "normal state equality check"),
    0x436fc: ("b.eq", "#0x437a0", "normal equal-state skip to shared path"),
    0x4370c: ("mov", "w0, #1", "normal VBRwDevice write operation"),
    0x43714: ("bl", "#0x37ac0", "normal secure state setter"),
    0x43718: ("cbz", "#0x437a0", "normal successful write joins shared path"),
    0x43748: ("bl", "#0x13008", "critical state check"),
    0x43750: ("cmp", "w8, w23, uxtb", "critical state equality check"),
    0x43754: ("b.eq", "#0x437a0", "critical equal-state skip to shared path"),
    0x43764: ("mov", "w0, #1", "critical VBRwDevice write operation"),
    0x4376c: ("bl", "#0x37ac0", "critical secure state setter"),
    0x43770: ("cbz", "#0x437a0", "critical successful write joins shared path"),
    0x437a0: ("bl", "#0x38370", "shared helper"),
    0x437a4: ("cbz", "#0x43814", "branch to recovery command construction"),
    0x43834: ("adrp", "#0xc5000", "recovery string pointer page"),
    0x4383c: ("add", "x0, x0, #0x19d", "recovery string pointer offset"),
    0x43864: ("add", "x2, x2, #0x19d", "recovery command source"),
    0x43870: ("bl", "#0x5692c", "recovery command copy/helper"),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def text_section(source, addr):
    pattern = re.search(r"(?m)^========== TARGET " + addr + r" =+\s*$", source)
    if not pattern:
        return {"found": False, "body": None}
    nxt = re.search(r"(?m)^========== TARGET ", source[pattern.end():])
    end = pattern.end() + nxt.start() if nxt else len(source)
    section = source[pattern.start():end]
    return {
        "found": True,
        "body": section[:14000],
        "body_length": len(section),
        "function_names": sorted(set(re.findall(r"FUN_[0-9a-fA-F]{8}", section)))[:60],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--abl", type=Path, required=True)
    p.add_argument("--ghidra", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()

    binary = args.abl.read_bytes()
    if sha(binary) != EXPECTED_SHA256:
        raise ValueError("Unexpected signed ABL; abort")
    ghidra = args.ghidra.read_text(errors="replace")
    cap = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    instructions = list(cap.disasm(binary[0x43688:0x43940], 0x43688))
    address_map = {i.address: i for i in instructions}
    for addr, (mnemonic, operand, label) in INSTRUCTION_ASSERTIONS.items():
        i = address_map.get(addr)
        if i is None or i.mnemonic != mnemonic or operand not in i.op_str:
            raise ValueError(f"{label}: mismatch at {addr:#x}; got {i}")

    import pefile
    pe = pefile.PE(data=binary, fast_load=True)
    rva = 0xc5000 + 0x19d
    offset = pe.get_offset_from_rva(rva)
    extracted = binary[offset:offset+128].split(b"\x00", 1)[0].decode("ascii", "strict")
    expected_prefix = "recovery\n--wipe_data\n--reason=MasterClearConfirm"
    if not extracted.startswith(expected_prefix):
        raise ValueError(f"Unexpected recovery string: {extracted!r}")

    decomp = {a: text_section(ghidra, a) for a in FUNCS}
    if not all(decomp[a]["found"] for a in ("00043688", "00013008", "00038370")):
        raise ValueError("Missing Ghidra decompilation of essential setter/helper functions")

    # Ghidra pseudocode constraints complement the byte-level branch assertions.
    # Ghidra sometimes mislabels the return type of 0x13008, hence tests focus
    # on the data-source expression, not its guessed signature.
    setter_c = decomp["00043688"]["body"]
    state_c = decomp["00013008"]["body"]
    reset_c = decomp["00038370"]["body"]
    required_c = {
        "ABL state getter uses initialized context field +0x104":
            "*(int *)(lVar2 + 0x104) == 1" in state_c,
        "state setter short-circuits when local state equals requested":
            setter_c.count("if ((cVar6 == param_2) ||") == 2,
        "state setter joins the reset call and recovery command":
            "lVar9 = FUN_00038370();" in setter_c and
            "lVar9 = FUN_000380e0(" in setter_c,
        "reset helper has a mode-based zero-result short circuit":
            "iVar3 == 3" in reset_c and "lVar6 = 0;" in reset_c,
        "reset helper can call verified-boot protocol offset 0x30":
            "+ 0x30))()" in reset_c,
        "setter may attempt reverse state write after reset error":
            "bVar5 = param_2 ==" in setter_c and
            "FUN_00037ac0(1,&DAT_001e1b18,0xa18)" in setter_c,
    }
    if not all(required_c.values()):
        raise ValueError("Ghidra source assertion failed: " +
                         repr([name for name, ok in required_c.items() if not ok]))

    # These helpers sit immediately before the known 0x3144 ABL main function.
    # Print exact original instructions rather than inferring their output
    # from Ghidra's guessed signatures.
    mode_listing = list(cap.disasm(binary[0x3110:0x3144], 0x3110))
    mode_helper_assembly = [
        f"{ins.address:#x} {ins.mnemonic} {ins.op_str}" for ins in mode_listing
    ]
    source_excerpt = {}
    for addr, entry in decomp.items():
        if not entry["found"]:
            continue
        relevant = [line.strip() for line in entry["body"].splitlines()
                    if any(term in line for term in ("0x104", "0x13008", "0x38370",
                                                     "0x37ac0", "0x437a0", "0x43814",
                                                     "recovery", "write", "0x82", "0x13008"))]
        source_excerpt[addr] = {"found": True, "body_length": entry["body_length"],
                                "relevant_lines": relevant[:35],
                                "function_names": entry["function_names"]}

    result = {
        "scope": "Original signed EEA ABL byte-level and archived Ghidra offline analysis",
        "abl_sha256": EXPECTED_SHA256,
        "ghidra_report_sha256": sha(args.ghidra.read_bytes()),
        "verified_equal_state_shortcut": {
            "normal_compare_0x13008_result_to_requested_value": True,
            "normal_branch_if_equal_to_shared_path": "0x436fc -> 0x437a0",
            "normal_write_success_to_shared_path": "0x43718 -> 0x437a0",
            "critical_compare_0x13008_result_to_requested_value": True,
            "critical_branch_if_equal_to_shared_path": "0x43754 -> 0x437a0",
            "critical_write_success_to_shared_path": "0x43770 -> 0x437a0",
            "shared_path_invokes_0x38370": "0x437a0",
            "conditional_recovery_command_branch": "0x437a4 -> 0x43814",
            "recovery_command_rva": hex(rva),
            "recovery_command": extracted,
        },
        "verified_instruction_assertions": [
            {"address": hex(addr), "description": desc,
             "instruction": f"{address_map[addr].mnemonic} {address_map[addr].op_str}"}
            for addr, (_, _, desc) in INSTRUCTION_ASSERTIONS.items()
        ],
        "ghidra_function_evidence": source_excerpt,
        "verified_ghidra_source_constraints": required_c,
        "mode_helpers_original_arm64_window_0x3110_0x3144": mode_helper_assembly,
        "interpretation_guardrails": [
            "The equal-state compare is against an ABL +0x104 context helper, not a direct Keymaster READ.",
            "Either the local equal-state branch OR a successful VBRwDevice WRITE can reach the same recovery stage.",
            "A successful return from 0x38370 can occur on an internal mode short circuit without invoking the reset protocol method.",
            "The recovery BCB command is staged only after that helper returns zero and other operations succeed.",
            "Rollback code may attempt the opposite state if 0x38370 returns failure; it is not evidence this happened live.",
            "Neither wipe nor Fastboot OKAY proves persistent secure unlock."
        ],
        "limitations": [
            "Equal-state skip occurs on one specific branch, not proof the user's device took it.",
            "0x13008 is an ABL helper; do not equate it with an observed secure RPMB value.",
            "0x38370 semantics need decompilation interpretation; wipe command construction is conditional.",
            "A BCB recovery command string is not proof wipe was scheduled or executed.",
            "No evidence which path caused the user's prior wipe or why the bootloader remained locked.",
            "No physical device operations or firmware writes were performed."
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print("ABL_SHA256_OK", EXPECTED_SHA256)
    print("EQUAL_BRANCH_NORMAL", result["verified_equal_state_shortcut"]["normal_branch_if_equal_to_shared_path"])
    print("EQUAL_BRANCH_CRITICAL", result["verified_equal_state_shortcut"]["critical_branch_if_equal_to_shared_path"])
    print("WRITE_SUCCESS_NORMAL", result["verified_equal_state_shortcut"]["normal_write_success_to_shared_path"])
    print("WRITE_SUCCESS_CRITICAL", result["verified_equal_state_shortcut"]["critical_write_success_to_shared_path"])
    print("RECOVERY_CMD", repr(extracted))
    for line in mode_helper_assembly:
        print("MODE_HELPER_ARM64", line)
    for key, info in source_excerpt.items():
        print("GHIDRA_FUNCTION", key, json.dumps(info, ensure_ascii=False)[:11000])
    # Full control-flow context: the common helper decides whether the
    # BCB recovery command construction branch is reached.
    for addr in ("00013008", "00038370", "00043688"):
        body = decomp[addr]["body"]
        print("GHIDRA_FULL_BEGIN", addr)
        print(body)
        print("GHIDRA_FULL_END", addr)


if __name__ == "__main__":
    main()
