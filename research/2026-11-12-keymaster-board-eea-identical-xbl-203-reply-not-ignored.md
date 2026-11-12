# 12.11.2026 — HONOR 70: Board Keymaster NOT weaker; original XBL checks secure 0x203 reply and ABL propagates failure

**Target:** FNE-NX9, Europe C431, MagicOS 8.0.0.290. Original EEA signed ABL SHA256 `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`, VerifiedBootDxe SHA256 `f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55`. Analysis uses source-pinned original Keymaster (KM41) from this stock EEA firmware and separately signed FNE-AN00 HMT Board firmware.

**Result:** no reproducible permanent unlock or code execution. The critical new facts are proven **offline** in GitHub Actions, with source assertions checked against original signed data. No device command, EDL write or RPMB operation was performed.

## 1. Four secure state KM41 functions are the same in retail and Board decompilation

- [Successful complete independent comparison — run 43141115024](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43141115024).
- [Verifier Python](../tools/compare_signed_km41_retail_board_unlock_guards.py).
- Original EEA Ghidra [run 42540518094](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42540518094).
- Original Board Ghidra [run 42605355587](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42605355587).

| Protected Keymaster function | Original EEA function address | Original Board address | Normalized Ghidra source difference |
|---|---:|---:|---:|
| `READ_KM_DEVICE_STATE (0x202)` | `0x1185A8` | `0x1184C0` | **0** |
| `WRITE_KM_DEVICE_STATE (0x203)` | `0x118878` | `0x118790` | **0** |
| `qsee_is_sw_fuse_blown(1)` helper | `0x117980` | `0x117898` | **0** |
| `MILESTONE_CALL (0x204)` | `0x117A18` | `0x117930` | **0** |

This normalizes absolute Ghidra relocation labels, function names, global addresses and (large) absolute address literals. Status values, QSEE function names, branch conditions and smaller constants remain. Thus **these four decompiled source functions have matching control flow and guards, not necessarily identical raw ELF bytes, global configuration or every other function**. The initial false-positive difference from a `code_r0x...` Ghidra-generated relocation label was caught and fixed, and then all four comparisons passed.

Both READ and WRITE call their own version of the common fuse helper before proceeding to RPMB storage. Both include the `-15` failure and the `RPMB not provisioned or enabled` branch; the milestones invoke software fuse operations.

**Consequence:** flashing the original FNE-AN00 Board `km41` into a retail FNE-NX9 **does not remove the discovered lock-state/fuse guard**. Any different behavior would need external evidence such as other bootchain policy or live QSEE state, not a guessed code difference in these handlers.

## 2. Original XBL DOES verify the actual `0x203` reply status

- [Successful direct XBL verification run 43141651329](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43141651329).
- [Verifier for original `FUN_0000153C`](../tools/audit_xbl_203_response_status_propagation.py).
- [End-to-end signed ABL bytes + XBL decompiler crosscheck run 43141819717](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43141819717).
- [Combined static test](../tools/verify_honor70_xbl_203_reply_abl_ui_error_flow.py).

In signed retail `VerifiedBootDxe` the secure-state-write branch of `FUN_0000153C`:

```c
// XBL protected write, decompiled structure and exact constants:
QSEE_SEND(0x202);                   // protected preread
if (transport_result == 0 && read_reply_status == 0) {
    QSEE_SEND(0x203);               // protected WRITE request
    if (transport_result == 0 && write_reply_status == 0) {
        goto SUCCESS;
    }
    LOG("VB: RWDeviceState: write_req err! staus %d write status %d");
} else {
    // SCM-dependent fallback or refusal, not a successful 0x203
}
efi_status = 0x50;                 // failure
```

Original Ghidra vars for the actual write: `lVar3` is the QSEE transport result, `local_f8` is the write response status; both are checked:

```c
lVar3 = (**(code **)(DAT_0000d1f0 + 0x18))(... &local_f0,0xc,&local_100,0xc);
if ((lVar3 == 0) && (local_f8 == 0)) goto LAB_00001a2c;
pcVar7 = "VB: RWDeviceState: write_req err! staus %d write status %d\n";
...
lVar3 = 0x50;
```

**This excludes the simple hypothesis that the retail XBL always declares a `0x203` attempt successful without checking its Keymaster reply.** It also confirms that prior `Succeed using rpmb!` log, if ever captured, would be materially better evidence of that protected path than the USB `OKAY` response. It has not been captured during the original unlock event.

The same original ABL PE byte-backed disassembly confirms:

```asm
0x3D9E0 bl  0x37AC0       ; UI callback reads VBRwDevice state
0x3D9E4 cbz x0,0x3DA48   ; only success continues
0x3DA5C bl  0x43688      ; unlocked-state setter
0x3DA60 cbz x0,0x3DA98   ; nonzero result follows separate error/log path

0x43714 bl  0x37AC0      ; setter normal-state write
0x43718 cbz x0,0x437A0   ; successful VBRwDevice status
0x4376C bl  0x37AC0      ; critical-state write variant
0x43770 cbz x0,0x437A0
```

The original ABL setter has an **earlier local-state equality shortcut**, so this does not mean every apparent confirmation event reaches QSEE `0x203`. The original Fastboot handler also has its own earlier equality check; source-verified study in [parallel ABL/XBL/KM triage](2026-11-12-parallel-three-lanes-abl-xbl-km-unlock-triage.md) limits the default shortcut explanation.

## 3. Correct interpretation of the software milestone fuse

Keymaster `0x202` and `0x203` both call `qsee_is_sw_fuse_blown(1)` in the common guard. The error `0xFFFFFFF1` / `-15` occurs if **either** that check fails or it reports a blown software fuse. The retail/Board helpers have the same logic, and the helper's own QSEE check-error diagnostic includes `0xFFFFFFF5`. Therefore an isolated `-15` **does not distinguish underlying SCM/QSEE read failure from an already set software fuse**.

**Important vocabulary:** this `qsee_blow_sw_fuse` *software milestone fuse* must not automatically be equated with the permanent QFPROM hardware Secure Boot/anti-rollback eFuse. The original KM41 binary proves a software fuse API is used, but it does **not** independently prove lifetime across cold boots or whether resetting that state is possible in the production secure world. Do not attempt hardware fuse or storage modification on that assumption. [Qualcomm's secure boot documentation](https://docs.qualcomm.com/bundle/publicresource/topics/80-70017-11/secure-boot.html) describes the separate hardware trust root.

## 4. Newly reviewed public Keymaster vulnerability (scope check, no compatibility proof)

[CVE-2026-21085](https://nvd.nist.gov/vuln/detail/CVE-2026-21085), published 9 September 2026, concerns an **out-of-bounds write in a Samsung Mobile Keymaster trustlet**, with a local high-privilege attacker prerequisite and patch reference to Samsung's September 2026 security update. Samsung's CNA affected-product designation **does not establish that HONOR's `km41.mbn` includes the same vulnerable code**. No public, model/build-matched HONOR 70 exploit or exact vulnerable function has been verified.

A separate [public MINK chain](https://www.getyahrootback.com/research/mink-chain) demonstrates **other hardware** invoking Keymaster via authenticated service interfaces and encountering a milestone denial; it does **not** demonstrate a HONOR 70 unlock. Calls to a Keymaster trustlet are not a substitute for a failure/bypass of the proven fuse gate.

The Redmi 14R [GPT/AVB PoC](https://github.com/atlas4381/qualcomm_avb_exploit_poc) demonstrates one distinct implementation whose GPT-dependent NO_AVB boot skips milestone. The signed HONOR ABL's similarly named `NoAVBLoad_fw_ufsdev` was already verified as a post-milestone **UFS firmware update helper**, not an Android NO_AVB bypass: [HONOR-specific disambiguation](2026-11-12-noavb-fw-ufsdev-after-milestone-not-boot-bypass.md).

## 5. What remains unmeasured and would actually decide the next physical experiment

The original Fastboot confirmation/wipe and `LOCKED` after reboot are **not enough to establish** which of these occurred:

1. ABL early permission/local-state branch never reached secure WRITE.
2. UI callback `VBRwDevice READ` returned an error.
3. XBL's `0x202` pre-read failed and suppressed `0x203`.
4. XBL issued `0x203` and Keymaster replied nonzero; XBL returned EFI `0x50`.
5. A protected write succeeded but a separate verified state/boot policy prevented the later `UNLOCKED` state.

The signed source now proves XBL checks the actual write reply and ABL receives the status **if that call was reached**. It does **not** show the original device's log or actual path. A definite root-cause conclusion needs an **event-specific preserved status/log**, not a repeated guessed EDL offset or a later normal Android boot `-15` message.

**No new EDL write target or verified permanent unlock has been found in these checks.** Invasive tests would require a known exploitable primitive or model/build-matched signed engineering bootchain plus a restorable backup.
