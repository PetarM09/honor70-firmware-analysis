# 2026-11-12 — Confirmed: HONOR 70 NoAVBLoad_fw_ufsdev is a **post-milestone UFS firmware helper**, not evidence of the Redmi 14R unlock bypass

**Target:** Original, signed HONOR 70 FNE-NX9 (C431, MagicOS 8.0.0.290) `LinuxLoader.efi`, SHA256 `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`.

**Status:** Original source-level observation has been **independently reproduced**. A GPT-based unlock or another exploit has **not** been demonstrated.

## Why this matters

The public [Qualcomm AVB/Keymaster PoC](https://github.com/atlas4381/qualcomm_avb_exploit_poc) was tested on the **Redmi 14R (Snapdragon 4 Gen 2)**, not HONOR 70. Its chain requires all of the following:

1. A bootloader function `Is_VERIFIED_BOOT_2()` determines AVB2 vs `NO_AVB` **dynamically**, based on GPT `vbmeta` or `vbmeta_a` partition presence.
2. On the `NO_AVB` path the normal `MILESTONE_CALL` must be skipped **before** Keymaster services are used.
3. Unprivileged alternatives for reading or writing the persistent state through `READ_KM_DEVICE_STATE=0x202` / `WRITE_KM_DEVICE_STATE=0x203` are not blocked.
4. An independently bootable, authorized test environment must be available.

Mere presence of both `NoAVB...` and `LoadImageAndAuthVB2` diagnostic strings in the signed HONOR binary is **not enough**.

## What the exact signed EEA HONOR 70 ABL shows

- [Ghidra extraction run #43132274937](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43132274937): `FUN_00003144` (entire original decompilation, 42,194 characters).
- [Detailed source trace #43132901340](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43132901340).
- [Original ARM64 text reference finder #43132793701](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43132793701).
- [Independent source evidence assertions #43133171655](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43133171655) — **SUCCESS**.
- [Verifier source](../tools/verify_honor70_noavb_fw_ufsdev_after_milestone.py).

Within the *same* original Ghidra function `FUN_00003144`, the relevant pseudocode is ordered:

```text
1. Earlier: AVB2 verification and diagnostics:
   "LoadImageAndAuthVB2 fail errno:%d"

2. Later: normal boot-state logic and:
   "Sending Milestone Call"
   (**(code **)(*(longlong *)(param_1 + 0x430) + 0x20))();

3. On the following path:
   "NoAVBLoad_fw_ufsdev Start : %u ms"
   ... use partition name L"fw_ufsdev"
   ... parse UFS firmware package marker FPKG
   ... call FUN_00028190(...) for UFS firmware handling
   "NoAVBLoad_fw_ufsdev End : %u ms"
```

The condition on the branch entering this specifically named UFS helper occurs **after** the milestone protocol call. It is **not evidence** of a `NO_AVB` alternative for the Android boot chain which skips Keymaster milestone. The use of `L"fw_ufsdev"`, `FPKG`, and UFS flash messages additionally identifies its purpose as **UFS device firmware handling**. Sending a malformed `fw_ufsdev` image is high-risk and has no verified bootloader-unlock result.

The independent assertion report records exact Ghidra source-text positions:

| Evidence | Index in decompilation |
|---|---:|
| `LoadImageAndAuthVB2 fail errno` | 9,892 |
| `Sending Milestone Call` | 34,784 |
| UEFI/VerifiedBoot provider call `+0x20` | 34,834 |
| `NoAVBLoad_fw_ufsdev Start` | 35,080 |
| `L"fw_ufsdev"` | 35,205 |
| Firmware package marker check | 38,882 |

Order of decompiler text is not an execution trace. Here the **same normal C control-flow branch** contains a direct milestone protocol call **before** the `NoAVBLoad_fw_ufsdev` section. Actual on-device milestone success and hardware fuse state were not measured.

## What the signed source string search does and does not establish

The exact EEA ABL binary contains ASCII strings `NoAVBLoad_fw_ufsdev` (three mentions), `LoadImageAndAuthVB2`, and `vbmeta`, but exact `Is_VERIFIED_BOOT_2`, `VERIFIED_BOOT_ENABLED`, or `vbmeta_a` literals were **not found** in this binary's ASCII or UTF-16LE text by the signed-source scanner. This is a **weak negative**, not proof that no dynamically synthesized GPT-name check exists anywhere in the compiled program.

Original xrefs for `NoAVBLoad_fw_ufsdev` point to `0x4364`/`0x446C` inside `FUN_00003144`, **not** to an alternative externally verified boot-policy selector. Original AVB2 error reference is at `0x49B8` in the same function.

## Decision: do not run the GPT-rename exploit on HONOR 70 yet

Changing the GPT `vbmeta` partition names could lead to an unbootable device or inconsistent AVB metadata. It has **not** been proven to skip Keymaster's milestone on FNE-NX9, and the visible `NoAVBLoad_fw_ufsdev` label is **not that bypass**.

The remaining highest-value static question is whether any other signed original ABL function contains a **dynamic boot-mode selector** based on the existence of `vbmeta` partitions. A reliable result must show its **real ARM64 caller, partition lookup, branch target, and whether the milestone is omitted**. Neither raw text nor a missing `vbmeta_a` string is enough.

**No permanent unlock has been achieved; no live phone command or flash was performed in this investigation.**
