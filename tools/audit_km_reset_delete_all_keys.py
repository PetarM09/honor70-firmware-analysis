#!/usr/bin/env python3
"""Cross-validate stock XBL +0x30 function's 0x10E QSEE request and KM naming.

Inputs:
  1. SHA-pinned PE/ARM64 evidence JSON from the user's stock EEA firmware
  2. Archived original signed EEA km41.mbn Ghidra command-name decompilation.
Only reads existing public firmware-derived artifacts, no phone operations.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

PE_SHA = "f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def assert_regexp(pattern, text, desc):
    if not re.search(pattern, text, re.S | re.I | re.M):
        raise ValueError("Original firmware evidence absent: " + desc)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--xbl-json", type=Path, required=True)
    p.add_argument("--km-ghidra", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a=p.parse_args()
    src=json.loads(a.xbl_json.read_text())
    km_src=a.km_ghidra.read_text(errors="replace")
    if src.get("verified_pe_sha256")!=PE_SHA:
        raise ValueError("Not the exact original retail XBL binary report")
    if not src.get("unique_high_confidence_table_candidate") or src.get("reset_slot_0x30_rva_if_unique")!="0x1c84":
        raise ValueError("Expected XBL protocol table and +0x30 handler not verified")
    tables=src.get("vtable_candidates_with_rwdevice_slot_at_0x08",[])
    if len(tables)!=1 or tables[0].get("file_offset")!=0xd160:
        raise ValueError("Vtable layout unexpected")
    slots=tables[0]["slots"]
    if not slots[1].get("target_rva")=="0x153c" or slots[6].get("target_rva")!="0x1c84":
        raise ValueError("RW or reset function slot mismatch")

    byte_src=src.get("original_arm64_reset_function_and_provider_table_xrefs")
    if not byte_src:
        raise ValueError("Missing original byte-level disassembly")
    code="\n".join(byte_src["reset_target_disassembly"])
    # Request buffer: W8 gets 0x10e, then stored to the 4-byte command
    # at x29+0x18; x0=QSEE protocol; x9 is its method at +0x18.
    # This is separate from 0x202/0x203 state-storage commands.
    for address, mnemonic, operand in (
        ("0x1d68","mov","w8, #0x10e"),
        ("0x1d6c","add","x2, x29, #0x18"),
        ("0x1d74","mov","w3, #4"),
        ("0x1d78","mov","w5, #4"),
        ("0x1d7c","str","w8, [x29, #0x18]"),
        ("0x1d80","ldr","x9, [x0, #0x18]"),
        ("0x1d84","blr","x9"),
        ("0x1d88","ldr","w3, [sp]"),
        ("0x1d90","cbnz","x0, #0x1da0"),
        ("0x1d94","cbnz","w3, #0x1da0"),
    ):
        assert_regexp(r"^" + re.escape(address) + r"\s+" +
                      re.escape(mnemonic) + r"\s+" +
                      re.escape(operand) + r"\s*$",
                      code, "XBL exact instruction "+address)
    # Prove the discovered original table and protocol GUID are passed
    # together at the registered-protocol call site, not just near in data.
    xrefs=byte_src.get("direct_adrp_references",[])
    indexed={(x.get("kind"),x.get("source_at")) for x in xrefs}
    if not {("protocol_guid","0x27e8"),("vtable","0x27ec")}.issubset(indexed):
        raise ValueError("Missing original UEFI table/GUID registration xrefs")

    km_body=re.search(r"(?m)^======== FUNCTION 0010d7c8\b(?s:.*?)"
                      r"(?=^======== FUNCTION |\Z)",km_src,re.M)
    if not km_body:
        raise ValueError("Original EEA Keymaster function 0010d7c8 not found")
    command_map=km_body.group(0)
    for command,name in (("0x10d","DELETE_KEY"),("0x10e","DELETE_ALL_KEYS"),
                         ("0x202","READ_KM_DEVICE_STATE"),
                         ("0x203","WRITE_KM_DEVICE_STATE"),
                         ("0x204","MILESTONE_CALL")):
        assert_regexp(r"case\s+" + command + r"\s*:\s*"
                      r"pcVar2\s*=\s*\"" + name + r"\"\s*;",
                      command_map,"Keymaster command name "+command)

    outcome={
        "source":"Hash-verified stock EEA XBL bytes and original EEA Keymaster decompiler",
        "stock_xbl_sha256":PE_SHA,
        "original_km_decompiler_sha256":sha(a.km_ghidra.read_bytes()),
        "xbl_protocol_guid":"8e5eff91-21b6-47d3-af2b-c15a01e020ec",
        "verified_registration_xrefs":["0x27e8 GUID","0x27ec vtable"],
        "registered_vtable_file_offset":"0xd160",
        "vbrwdevice_entry":"+0x08 -> 0x153c",
        "reset_method_entry":"+0x30 -> 0x1c84",
        "reset_handler_sends_qsee_keymaster_command":"0x10e",
        "keymaster_command_name":"DELETE_ALL_KEYS",
        "distinct_read_command":"0x202 READ_KM_DEVICE_STATE",
        "distinct_write_command":"0x203 WRITE_KM_DEVICE_STATE",
        "qsee_transport_and_response_must_both_succeed":True,
        "evidence_lines":[line for line in code.splitlines()
            if line.startswith(("0x1d68 ","0x1d6c ","0x1d74 ","0x1d78 ",
                                "0x1d7c ","0x1d80 ","0x1d84 ","0x1d88 ",
                                "0x1d90 ","0x1d94 "))],
        "limitations":[
            "Keymaster string naming is verified, not dynamic proof of all internal effects.",
            "The QSEE delete-all-keys call is not Keymaster WRITE_KM_DEVICE_STATE 0x203.",
            "Neither a successful wipe nor delete-all-keys implies UNLOCKED state.",
            "No live phone state/SCM bit/RPMB state or actual callback trace was observed.",
            "No device commands or firmware writes were executed."
        ]
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(outcome,indent=2)+"\n")
    print("CROSSCHECK_SUCCESS",outcome["keymaster_command_name"])
    print("CALL_SITE","0x1d84","REQUEST_ID",outcome["reset_handler_sends_qsee_keymaster_command"])
    print("SEPARATE_STATE_COMMANDS",outcome["distinct_read_command"],
          outcome["distinct_write_command"])
    print("REGISTERED_PROTOCOL",outcome["registered_vtable_file_offset"])
    print("KM_DECOMP_SHA256",outcome["original_km_decompiler_sha256"])


if __name__=="__main__":
    main()
