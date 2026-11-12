# 2026-11-12 — Stock EEA ABL: OEMINFO ID 130 RDMode-v1 authorization feeds local +0x104, not direct RPMB lock

**Device / source:** HONOR 70 FNE-NX9 European MagicOS 8.0.0.290 original signed `LinuxLoader.efi`, SHA256 `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`.

**Scope:** offline static code and literal cross-verification. This report is **not a bootloader unlock and not evidence of any successful protected-write operation on the owner's handset**.

## Source-pinned and reproducible tests

- [Original ARM64 source and signed UI constant table, run 43124622604](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43124622604)
- [Expanded original signed ABL Ghidra decompilation, run 43124806546](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43124806546)
- [Independent matching original ABL + Ghidra RDMode truth-table assertions, run 43125419237](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43125419237)
- [Source cross-checker](../tools/verify_abl_rdmode_localstate_truth_table.py) and [GitHub workflow](../.github/workflows/verify-abl-rdmode-localstate-20261112.yml)
- Full signed ABL Ghidra report SHA256 `eeeee591a5a5f20ce2b6f0cc01ddb7fd29a21c663f90a06a19dd06aba82bba5e`

All original ABL machine-code assertions and all four UI menu table fields passed.

## Confirmed source chain

```text
Stock ABL start-up, FUN_00012E90
  └─ FUN_00012CF8
     ├─ read OEMINFO API record ID 0x82 (decimal 130), 0x100-byte buffer
     ├─ on returning path FUN_0001BF74 returns integer 2
     │    └─ select FUN_00015690; alternate FUN_0001A7B0 branch is
     │       not taken on this normal returning path
     └─ FUN_00015690
          ├─ FUN_0001BB68(credential descriptor for "0XEED6030008")
          └─ if first fails, FUN_0001BB68(descriptor for
                                        "fastboot flash:rdmodev1")
               └─ implementation contains data_set_sha256_rsa_check_pss
                  verification/error-reporting path

FUN_00012E90: store result into initialized ABL context +0x104
FUN_00013008: return context[+0x104]==1, subject to init guard
FUN_000134C0: allow unrestricted Fastboot dispatch iff context[+0x104]==1,
              otherwise use a fixed 49-prefix allowlist
FUN_00043688: if getter's result equals requested byte, skip another
              VBRwDevice WRITE and enter the shared cleanup/wipe stage
```

**Do not confuse OEMINFO record ID `0x82` with raw partition offset 0x82.** The original implementation invokes `FUN_000136A4(0x82, buffer, 0x100)`, an OEMINFO record API. Nor is the context field `+0x104` an RPMB offset: it is an in-memory field of an ABL object.

### Key original ARM64 instructions

```asm
0x12d20 mov  w0, #0x82
0x12d2c bl   #0x136a4
0x12d34 bl   #0x1bf74
0x12d38 cmp  w0, #2
0x12d3c b.ne #0x12d70
0x12d48 bl   #0x15690   // normal returning branch
...
0x1bf88 mov  w0, #2
0x1bf8c b    #0x1c678  // epilogue; error branch is fatal
...
0x12ea8 bl   #0x12cf8
0x12eac cbnz w0, #0x12ec4
0x12ec4 str  w0, [x19, #0x104]
...
0x13024 ldr  w8, [x0, #0x104]
0x13028 cmp  w8, #1
0x1302c cset w0, eq
...
0x134d8 ldr  w8, [x0, #0x104]
0x134dc cmp  w8, #1
0x134e0 b.eq #0x13518  // bypass limited allowlist
```

The two `0x15690` checks occur at `0x156DC` and `0x15780`. It returns `1` at `0x157B8` on a zero-return branch of either helper, and otherwise `0` at `0x157E0`. Code and literals directly label this pathway `common_check_rdmod_v1_state` and `fastboot flash:rdmodev1`.

`FUN_0001BB68` contains code and logging that refer to `data_set_sha256_rsa_check_pss`; this suggests a signed credential verification path rather than a raw bootloader lock bit. Its Ghidra decompilation misrecovers return signatures and other details, so this report does **not** assert that every verification substep is proven at the pseudocode level or that the owner's device possesses an accepted credential.

## Normal vs critical UI request argument proven from original PE

At `0x3DA54` and `0x3DA58` the actual UI callback loads `w0` and `w1` from the original 16-byte table at RVA `0xC3B90 + 16*index`. At `0x3DA5C` it calls `FUN_00043688`. UI code near `0x3DC80..` selects indices **5/8** for normal unlock/lock, and **7/9** for critical unlock/lock:

| UI operation | Row index | w0 (kind) | w1 (requested byte) |
|---|---:|---:|---:|
| Normal unlock | 5 | 0 | **1** |
| Normal lock | 8 | 0 | 0 |
| Critical unlock | 7 | 1 | **1** |
| Critical lock | 9 | 1 | 0 |

**Therefore normal unlock requests value 1**; the previously found equality-based WRITE shortcut is not automatically used just because an unlock confirmation and a wipe occurred.

## What "Command not allowed" does and does not establish

For this exact signed ABL, the `FUN_000134C0` permission gate returns allow-unconditionally when **the same ABL-context `+0x104` equals 1**, and checks its limited prefix list when the context value is **not** 1. The previously observed `flashing get_unlock_ability` denial matches pre-handler limited mode; it is **not** a `get_unlock_ability=0` result.

Conditional inference for an otherwise unchanged state in the **same Fastboot session**:

| Local getter | Desired normal unlock | Equality shortcut | ABL next step |
|---:|---:|---|---|
| 0 | 1 | No | Attempts a new `VBRwDevice WRITE` after the initial UI READ |
| 1 | 1 | Yes | Skips the *new* WRITE and moves to separate Keymaster `DELETE_ALL_KEYS (0x10E)` stage if reached |

If the device just denied an unallowlisted command because `+0x104 != 1`, then on that same unchanged context the equality shortcut **cannot** be the explanation for a subsequent requested unlock of 1. It could only be relevant if the context had value 1 in the earlier attempt, or changed between observations.

**No historical simultaneous ABL-context, Keymaster state, and UI callback logs were captured**, so we cannot tell which branch caused the owner's earlier wipe and persistent `LOCKED` result.

## Reassessment

The `+0x104` field is supported by **RD-mode v1 credential-verification-related firmware logic**, not by a direct `READ_KM_DEVICE_STATE (0x202)` call. It is shared between restricted Fastboot dispatch and a logical lock-state helper, but this does **not** prove it is identical to Keymaster/RPMB's persistent bootloader lock state.

The next useful question is the **actual secure storage path** taken on the device, i.e. ABL VBRwDevice -> XBL SCM security-state selector -> Keymaster 0x202/0x203. No unlocked result can be declared from this static analysis.

**Do not modify OEMINFO ID 130 to force local state 1.** There is no verified path from such a modification to a legitimate persistent `UNLOCKED` state; it can instead alter service authorization or damage the phone. No phone commands or writes were performed in these automated checks.
