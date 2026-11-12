#!/usr/bin/env python3
"""Three independent, parallel, read-only research lanes for HONOR 70.

These are deterministic CI workers, NOT autonomous AI agents. All source
artifacts come from the signed stock EEA firmware and are SHA/provenance
annotated. Never accesses a live device or writes a firmware partition.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path


def verify(condition, explanation):
    if not condition:
        raise ValueError("Unverified source assertion: " + explanation)


def section(text, token):
    i = text.find(token)
    verify(i >= 0, "section " + token)
    return text[i:]


def lane_abl(raw):
    data = json.loads(raw.decode("utf-8"))
    verify(data["abl_sha256"] ==
           "ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087",
           "exact retail ABL digest")
    ranges = data["arm64_windows"]
    def checked(key, required):
        text = "\n".join(ranges[key])
        for instruction in required:
            verify(instruction in text, key + " instruction " + instruction)
        return text
    checked("frp_state_permission_0x27850", (
        "0x2788c bl #0x433a8",
        "0x27890 and w8, w0, #0xff",
        "0x27894 cmp w8, w21, uxtb",
        "0x27898 b.ne #0x278b8",
        "0x2789c bl #0x27f64",
        "0x278ac bl #0x27b18",
        "0x278b4 b #0x278d8",
        "0x278b8 tst w21, #0xff",
        "0x278cc cbnz w8, #0x278f8",
        "0x279d0 bl #0x3dab8",
        "0x279ec bl #0x43688",
    ))
    checked("secure_backed_state_getter_0x433a8", (
        "0x433ac bl #0x13008",
        "0x433b4 ret",
    ))
    checked("setter_normal_critical_0x43688", (
        "0x436f0 bl #0x13008",
        "0x436f8 cmp w8, w23, uxtb",
        "0x436fc b.eq #0x437a0",
        "0x43714 bl #0x37ac0",
        "0x43748 bl #0x13008",
        "0x43754 b.eq #0x437a0",
        "0x4376c bl #0x37ac0",
    ))
    checked("ui_confirmation_read_0x3d9b8", (
        "0x3d9e0 bl #0x37ac0",
        "0x3da54 ldr w0, [x8]",
        "0x3da58 ldrb w1, [x8, #8]",
        "0x3da5c bl #0x43688",
    ))
    ui = data["verified_fastboot_ui_normal_critical_requested_values"]
    verify(ui["normal_unlock"]["requested_state"] == 1, "unlock request byte 1")
    return {
        "lane": "abl_fastboot_early_gate",
        "significant_new_finding":
            "The normal Fastboot handler compares the local logical state to the requested state at 0x27894 BEFORE entering its confirmation and setter paths. When equal, it dispatches Device already and exits; its later setter equality shortcut is not reached from this normal command under unchanged local state.",
        "fastboot_normal_early_state_check": "0x2788c -> 0x433a8 -> 0x13008",
        "normal_equal_state_branch": "0x27898 (falls through equality) -> 0x27b18 -> 0x278d8 (response and exit)",
        "normal_not_equal_branch": "0x27898 -> 0x278b8 -> permission/confirmation, possible setter 0x279ec",
        "physical_ui_callback": "0x3d9b8: VBRwDevice READ before setter 0x43688",
        "requested_unlock_byte": 1,
        "cannot_infer_live_historical_branch": True,
        "abl_original_digest": data["abl_sha256"],
    }


def lane_xbl(raw):
    # Reuse independently source-asserted review maintained in repo.
    from audit_secure_state_write_prerequisite import audit, classify
    parsed = audit(raw.decode("utf-8", "replace"))
    fw = parsed["firmware_observations"]
    verify(fw["write_branch_issues_read_0x202_before_write_0x203"],
           "Keymaster pre-read required")
    verify(parsed["mask_xor"] == "0x20", "distinct selector bit")
    return {
        "lane": "xbl_scm_backend_selector",
        "confirmed_prewrite_read": "0x202, QSEE transport and status must both return zero",
        "state_write_on_successful_preread": "0x203",
        "primary_scm_mask": parsed["primary_mask"],
        "failure_fallback_scm_mask": parsed["fallback_mask"],
        "difference_bit": parsed["mask_xor"],
        "comparison_examples_are_hypothetical_only":
            [classify(s) for s in (0, 0x20, 1)],
        "root_cause_unresolved": "Live SCM security-state bits and XBL failure status were never captured",
        "no_claimed_bypass": True,
    }


def km_section(source, addr):
    pattern = r"(?m)^===== TARGET " + re.escape(addr) + r" =====\s*$"
    match = re.search(pattern, source)
    verify(match is not None, "Keymaster Ghidra target " + addr)
    nxt = re.search(r"(?m)^===== TARGET ", source[match.end():])
    end = match.end() + nxt.start() if nxt else len(source)
    return source[match.end():end]


def lane_km(raw):
    src = raw.decode("utf-8", "replace")
    r = km_section(src, "1185a8")
    w = km_section(src, "118878")
    gate = km_section(src, "117980")
    milestone = km_section(src, "117a18")
    for name, body in (("READ", r), ("WRITE", w)):
        verify("FUN_00117980" in body or "func_0x00117980" in body,
               name + " invokes the software-fuse gate")
    verify("qsee_is_sw_fuse_blown" in gate,
           "actual software-fuse operation")
    verify("qsee_blow_sw_fuse" in milestone,
           "milestone handler writes fuses, not an authorized unlock")
    return {
        "lane": "km41_persistent_state_fuse",
        "read_command": "0x202 -> 0x1185A8",
        "write_command": "0x203 -> 0x118878",
        "common_gate": "0x117980 -> qsee_is_sw_fuse_blown(1)",
        "milestone_command": "0x204 -> 0x117A18, references fuse-blow operation",
        "important_negative": "There is no measured live fuse value and no observed 0x202/0x203 transaction from the original handset unlock event",
        "no_live_fuse_operations": True,
    }


LANES = {"abl": lane_abl, "xbl": lane_xbl, "km": lane_km}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lane", choices=sorted(LANES), required=True)
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    raw = a.input.read_bytes()
    result = LANES[a.lane](raw)
    result.update({
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "evidence_bytes": len(raw),
        "research_mode": "original_signed_firmware_static_only",
        "not_a_claim_of_unlock": True,
        "never_edl_flash_fastboot_or_keymaster_runtime_calls": True,
    })
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n")
    print("LANE_SUCCESS", a.lane)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
