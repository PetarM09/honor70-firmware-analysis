#!/usr/bin/env python3
"""Original EEA HONOR70 ABL: read-only UI callback error / recovery branch audit.

Reads an SHA256-pinned original LinuxLoader.efi and existing decompiled XBL
VerifiedBootDxe text. Never calls Fastboot/EDL/QSEE or modifies device firmware.
Uses Capstone to verify instruction-level branches, and pefile for PE RVA strings.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

ABL_SHA256 = "ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087"
CALLBACK = (0x3d9b8, 0x3dab4)
SETTER = (0x43688, 0x43940)
WRAPPER = (0x37ac0, 0x37bc8)
UNLOCK_ENTRY = (0x279b0, 0x27a18)
WINDOWS = {"ui_callback": CALLBACK, "state_setter": SETTER,
           "uefi_protocol_wrapper": WRAPPER, "unlock_entry": UNLOCK_ENTRY}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def assert_instruction(mapping, addr, mnemonic, target):
    inst = mapping.get(addr)
    if inst is None or inst.mnemonic != mnemonic or target not in inst.op_str:
        raise ValueError(f"Expected instruction at {addr:#x}: {mnemonic} {target}; found {inst}")


def read_c_string(data, addr):
    if addr < 0 or addr >= len(data):
        return None
    raw = data[addr:min(len(data), addr + 360)]
    raw = raw.split(b"\0", 1)[0]
    if len(raw) < 4 or not all(0x20 <= c <= 0x7e or c in (9, 10, 13) for c in raw):
        return None
    return raw.decode("ascii")


def rva_string(image, pe, rva):
    candidate = None
    try:
        o = pe.get_offset_from_rva(rva)
        candidate = read_c_string(image, o)
        if candidate:
            return {"rva": hex(rva), "file_offset": o, "text": candidate, "method": "PE_RVA_mapping"}
    except (ValueError, KeyError, TypeError):
        pass
    candidate = read_c_string(image, rva)
    if candidate:
        return {"rva": hex(rva), "file_offset": rva, "text": candidate, "method": "raw_identity_offset"}
    return {"rva": hex(rva), "text": None, "method": "not_decoded"}


def resolve_strings(image, pe, listing):
    # Track short, intra-basic-block ADRP -> ADD sequences, validating register use.
    output = []
    for idx, op in enumerate(listing):
        if op.mnemonic != "adrp" or len(op.operands) < 2:
            continue
        if op.operands[0].type != ARM64_OP_REG or op.operands[1].type != ARM64_OP_IMM:
            continue
        register = op.operands[0].reg
        base = op.operands[1].imm
        for n in listing[idx + 1:idx + 5]:
            if n.address - op.address > 16 or n.mnemonic in ("b", "ret", "br", "blr", "bl"):
                break
            if n.mnemonic != "add" or len(n.operands) < 3:
                continue
            if n.operands[0].type == ARM64_OP_REG and n.operands[1].type == ARM64_OP_REG and n.operands[2].type == ARM64_OP_IMM and n.operands[1].reg == register:
                resolved = base + n.operands[2].imm
                msg = rva_string(image, pe, resolved)
                output.append({"adrp_instruction": hex(op.address),
                               "add_instruction": hex(n.address),
                               "register": n.reg_name(n.operands[0].reg),
                               **msg})
                break
    # de-duplicate by site
    return list({v["adrp_instruction"]: v for v in output}.values())


def disassemble(image):
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cs.detail = True
    return {label: list(cs.disasm(image[a:b], a)) for label, (a, b) in WINDOWS.items()}


def xbl_section(text, addr):
    pattern = re.search(r"(?m)^======== FUNCTION " + re.escape(addr) + r"\b[^\n]*$", text)
    if not pattern:
        raise ValueError("XBL Ghidra function missing: " + addr)
    nxt = re.search(r"(?m)^======== FUNCTION ", text[pattern.end():])
    return text[pattern.end():pattern.end() + nxt.start() if nxt else len(text)]


def xbl_errors(src):
    rw = xbl_section(src, "0000153c")
    expected = (
        "read_req err", "wread_req err", "write_req err",
        "Succeed using rpmb", "Succeed using devinfo",
        "Cannot read security state", "QseecomStartApp",
    )
    for word in expected:
        if word not in rw:
            raise ValueError("XBL message/branch missing: " + word)
    candidates = re.findall(r'"([^"\r\n]*(?:VB: RWDeviceState:| VB: RWDeviceState:)[^"\r\n]*)"', rw)
    unique = sorted(set(candidates))
    return {
        "ghidra_found_diagnostic_strings": unique,
        "read_failure_message": next((s for s in unique if "read_req err" in s and "wread" not in s), None),
        "preread_failure_message": next((s for s in unique if "wread_req err" in s), None),
        "write_failure_message": next((s for s in unique if "write_req err" in s and "wread" not in s), None),
        "note": "Labels identify potential paths, not messages observed on this phone."
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--abl", type=Path, required=True)
    p.add_argument("--xbl-ghidra", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    image = args.abl.read_bytes()
    if sha(image) != ABL_SHA256:
        raise ValueError("Original stock EEA ABL mismatch")
    if image[:2] != b"MZ":
        raise ValueError("Not a PE/EFI image")
    import pefile
    pe = pefile.PE(data=image, fast_load=True)
    source = args.xbl_ghidra.read_text(errors="replace")
    listings = disassemble(image)
    all_ops = {i.address: i for listing in listings.values() for i in listing}
    # These checks are assertions on original ABL bytes; not device runtime assertions.
    for addr, mnemonic, target in [
        (0x3d9e0, "bl", "0x37ac0"),
        (0x3d9e4, "cbz", "0x3da48"),
        (0x3da5c, "bl", "0x43688"),
        (0x3da60, "cbz", "0x3da98"),
        (0x43714, "bl", "0x37ac0"),
        (0x4376c, "bl", "0x37ac0"),
        (0x37b1c, "blr", "x8"),
        (0x37b64, "blr", "x8"),
    ]:
        assert_instruction(all_ops, addr, mnemonic, target)
    for addr, mnemonic, op in [
        (0x3d9d8, "mov", "wzr"),    # zero operation: VBRw READ
        (0x4370c, "mov", "#1"),    # setter's VBRw WRITE
        (0x43764, "mov", "#1"),
    ]:
        assert_instruction(all_ops, addr, mnemonic, op)

    windows = {}
    for label, listing in listings.items():
        lo, hi = WINDOWS[label]
        windows[label] = {
            "first_address": hex(lo), "end_exclusive": hex(hi),
            "direct_calls": [
                {"site": hex(i.address), "target": hex(i.operands[0].imm)}
                for i in listing if i.mnemonic == "bl" and i.operands and i.operands[0].type == ARM64_OP_IMM
            ],
            "direct_conditional_edges": [
                {"site": hex(i.address), "instruction": i.mnemonic + " " + i.op_str,
                 "branch_target": hex(i.operands[-1].imm)}
                for i in listing if (i.mnemonic.startswith("b.") or i.mnemonic in ("cbz", "cbnz", "tbz", "tbnz"))
                and i.operands[-1].type == ARM64_OP_IMM
            ],
            "strings_near_function": resolve_strings(image, pe, listing)
        }

    report = {
        "scope": "Static original ABL and original EEA XBL decompilation only; no phone actions",
        "abl_sha256": ABL_SHA256,
        "ghidra_xbl_report_sha256": sha(args.xbl_ghidra.read_bytes()),
        "verified": {
            "callback_reads_state_before_setter": True,
            "only_zero_result_from_callback_read_branches_directly_to_setter_path": True,
            "callback_checks_state_setter_result": True,
            "setter_forwards_write_using_op_1": True,
            "uefi_wrapper_contains_indirect_protocol_call": True
        },
        "instruction_derived_windows": windows,
        "xbl_errors": xbl_errors(source),
        "relevant_abl_sites": {
            "callback_read": "0x3d9e0",
            "read_success_branch": "0x3d9e4",
            "read_success_destination": "0x3da48",
            "state_setter_invocation": "0x3da5c",
            "state_setter_success_branch": "0x3da60",
            "uefi_wrapper_indirect_protocol_method": "0x37b64",
            "write_operation_at_setter_sites": ["0x43714", "0x4376c"]
        },
        "limitations": [
            "Local branch listing is not proof of full whole-program reachability.",
            "An ABL message stored in a signed binary does not mean it appeared on screen.",
            "EFI callback may report errors after initial Fastboot host OKAY.",
            "This offline analysis does not establish whether 0x202 or 0x203 executed in prior device attempts.",
            "A successful write response is not proof of persistent UNLOCKED after reboot.",
            "No firmware, secure state, RPMB or partition was written or read from live device."
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print("HASH_OK", report["abl_sha256"], "XBL_REPORT_SHA256", report["ghidra_xbl_report_sha256"])
    for key in ("ui_callback", "state_setter", "uefi_protocol_wrapper"):
        window = windows[key]
        print("WINDOW", key, "CALLS", len(window["direct_calls"]),
              "BRANCHES", len(window["direct_conditional_edges"]))
        for string in window["strings_near_function"]:
            if string["text"] is not None:
                print("ABL_STRING", key, string["rva"], repr(string["text"][:180]), string["method"])
    for role in ("read_failure_message", "preread_failure_message", "write_failure_message"):
        print("XBL_MESSAGE", role, repr(report["xbl_errors"][role]))


if __name__ == "__main__":
    main()
