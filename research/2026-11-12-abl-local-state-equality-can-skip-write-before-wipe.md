# 2026-11-12 — ABL local-state equality can skip a new VBRwDevice WRITE before recovery wipe

**Target:** HONOR 70 FNE-NX9 EEA, original signed MagicOS 8.0.0.290 `LinuxLoader.efi`.  
**Status:** **firmware-side branch confirmed; device-side branch selection and permanent unlock NOT confirmed.**

## Reproducible evidence

- [Run 43118223385 — successful hash-pinned ARM64 + archived Ghidra assertions](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43118223385)
- [Run 43117954988 — full relevant decompilation printed to logs](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43117954988)
- [Run 43117415577 — exact ABL/XBL stage-specific error strings](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43117415577)
- [Source audit tool](../tools/audit_abl_equal_state_wipe.py)
- [GitHub Actions workflow](../.github/workflows/audit-abl-equal-state-wipe-20261112.yml)
- Original EEA LinuxLoader SHA256 **`ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`**

Both normal and critical variants are confirmed from original executable bytes and independent Ghidra decompilation; the analyzer explicitly refuses source-hash or expected-instruction mismatches.

## New core finding: write-skipping equality branch

`FUN_00043688(int param_1, char param_2)` selects the normal (`param_1=0`) or critical (`param_1=1`) unlock state field, and checks the **ABL-local** getter `FUN_00013008()` against the requested `param_2`.

The essential behavior (condensed from the original Ghidra output) is:

```c
current_logical_state = FUN_00013008();
if (current_logical_state == requested_state ||
    (prepare_state_buffer(requested_state),
     status = FUN_00037ac0(1, buffer, 0xa18),
     status == 0)) {
    status = FUN_00038370();
    if (status == 0) {
        prepare_recovery_wipe_command();
        // Persist recovery command through recovery-message helper.
    }
}
```

The equality shortcut and write-success branch converge at the **same RVA 0x437A0**, checked with these direct ARM64 instructions:

| Branch | Equality shortcut (skips WRITE) | WRITE success (after invoking `VBRwDevice`) |
|---|---|---|
| Normal unlock | `0x436F0` calls `0x13008`; `0x436F8` compares; `0x436FC b.eq 0x437A0` | `0x43714` calls `0x37AC0`; `0x43718 cbz x0, 0x437A0` |
| Critical unlock | `0x43748` calls `0x13008`; `0x43750` compares; `0x43754 b.eq 0x437A0` | `0x4376C` calls `0x37AC0`; `0x43770 cbz x0, 0x437A0` |

**Therefore, on the equality branch, a new `VBRwDevice WRITE` and the dependent Keymaster pre-read/`0x203` sequence can be skipped, even when execution then continues to the next shared stage.** This is **not** evidence that this branch was taken during the owner's old handset experiment.

## The equality getter is not a direct Keymaster state read

The original ABL `FUN_00013008` Ghidra report includes:

```c
lVar2 = FUN_00013608(0x1b5000);
// Subject to an additional DAT_001c1390 guard:
in_ZR = *(int *)(lVar2 + 0x104) == 1;
```

Note: Ghidra guesses this function's return type incorrectly (`void`) in one report; the actual ARM64 caller tests the returned low byte. The object read is **the ABL context field `+0x104`**. This does *not* call `READ_KM_DEVICE_STATE (0x202)` directly.

Earlier [Fastboot state-init research](2026-11-09-fastboot-unlock-failure-branch-triage.md) traced `+0x104` initialization through `0x12CF8`, including an OEMINFO API record `0x82` (decimal 130) path. This strengthens the possibility that the local equality test and the secure, persistent Keymaster/RPMB lock state represent **different observations**. It does **not** establish that they disagree on the live device, or that changing OEMINFO #130 would cause a secure unlock.

## What the shared stage does: protocol reset helper and conditional wipe

At `0x437A0`, both branches call `FUN_00038370()`; at `0x437A4`, a **zero return** proceeds to `0x43814`, where the firmware prepares the literal:

```text
recovery
--wipe_data
--reason=MasterClearConfirm
--locale=en_US
```

The recovery-message write helper is `FUN_000380E0`; the code is conditional on intermediate successes and cannot be equated with proof that a wipe was actually performed on a given boot.

`FUN_00038370` is a *separate* reset-state routine with more than one possible zero-return branch:

- The function contains a generic shortcut if `FUN_0000313C()==0` **or** `FUN_00003134()==3`. In that case the reset method would be bypassed.
- **But in this exact stock EEA ABL those helpers are constants**: at `0x313C` the instruction is `mov w0,#1; ret`, and at `0x3134` it is `mov w0,#2; ret`. Therefore neither shortcut condition can be satisfied in this build.
- The actual retail path locates the VerifiedBoot UEFI protocol and invokes its method at protocol offset `+0x30`, unless locating the protocol fails. Errors contain `Error Reseting device state: %r` or `Unable to locate VB protocol: %r`.
- The exact semantics and persistence effects of the protocol's `+0x30` method remain the next static reverse-engineering target.

**Correction verified in [run 43118516950](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43118516950):** a zero return from `0x38370` in this retail build goes through the VerifiedBoot reset protocol; its *generic* internal shortcut is dead for the present constants. It still does **not** prove that permanent unlock occurred.

## Additional recovery branch: attempt to reverse the requested state on reset error

When `FUN_00038370` returns nonzero, the setter contains conditional recovery logic which checks `FUN_00013008` again and may attempt to write the **inverse** of the requested state using `FUN_00037AC0(1, ...)`. The messages include `Unable set the unlock value` and `Unable set the unlock critical value` if rollback operations fail.

This is a **potential rollback attempt**, not proof that rollback happened to the live device; depending on conditions it may not issue a reverse write. Crucially, the reset-failure path is distinct from the zero-return path that stages a recovery wipe command.

## What this changes in the investigation

Previously, the old wipe and final `LOCKED` outcome were mistakenly tempting evidence that Keymaster `0x203` failed *after* a write. The exact code now demonstrates at least one other sequence:

1. UI callback performs its initial VBRwDevice READ.
2. ABL-local equality check in the setter may match the requested value.
3. The setter **skips a new VBRwDevice WRITE** and proceeds to the common reset helper.
4. The reset helper may return zero; the setter stages a recovery wipe.
5. Secure persistent state might remain unchanged; whether that actually occurred is **unmeasured**.

This is a **verified alternative code path** that can explain how wipe and no unlock could coexist **without a new Keymaster write request**. It is a hypothesis for the past device event, **not its confirmed forensic cause**.

## Next genuinely useful offline question

The mode helpers are now **resolved to constants** (1 and 2). The next question is which concrete `VerifiedBootDxe` implementation is behind protocol method `+0x30`, whether it resets a persistent lock record or a different verified-boot state, and how that interacts with ABL's OEMINFO-derived `+0x104` local check. Distinguishing the **live** path still requires genuine historical logs or non-destructive, authorized device-state evidence. There is no justified EDL write target or verified permanent unlock yet.

No EDL/fastboot/ADB call or device flash took place in these GitHub analyses. Do not attempt to force the equality condition, reset helper, RPMB, SCM bit, or OEMINFO record by writing phone partitions.
