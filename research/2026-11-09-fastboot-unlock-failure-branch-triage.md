# HONOR 70 FNE-NX9 — post-Fastboot unlock failure branch triage (2026-11-09)

**Scope:** Read-only continuation after live Mac Fastboot diagnostic. Model FNE-NX9, stock EEA build `FNE-N29 8.0.0.290(C431E4R3P1)`. No device operations or flashing were performed in this follow-up. **Permanent bootloader unlock remains UNPROVEN.**

## 1. Isolate dispatch filtering from unlock policy

A verified original signed EEA `LinuxLoader.efi`, SHA-256 `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`, has:
- Fastboot dispatcher `0x22c7c`: invokes `0x134c0(command)`; a denied command returns `Command not allowed` without entering its handler.
- Permission gate `0x134c0`: tests context field `FUN_00013608(0x1b5000) + 0x104`, then a **49-prefix allowlist** at `0x1b41b0` if not in unrestricted mode. Exact semantic name of `+0x104` is not yet proven.
- `flashing unlock` is allowlisted and registered at `0x25c04`; `flashing get_unlock_ability` is registered at `0x25b88` but *not* allowlisted for locked mode.
- Thus the live `FAILED (remote: 'Command not allowed')` for `flashing get_unlock_ability` is a pre-handler **dispatch denial**, not `get_unlock_ability=0` and not proof of any Keymaster failure.
- `oem get-bootinfo` and `oem lock-state info` are allowlisted, matching live `LOCKED` output.

Source: [prior command gate report](2026-11-09-live-fastboot-denied-allowlist-root-cause.md); [exact decompilation run](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42622306553).

## 2. Two distinct failure conditions in the real EEA common unlock handler

The `flashing unlock` wrapper `0x25c04` passes an unlock request to common handler `0x27850`. Exact retrieved Ghidra function body in [Board/EEA side-by-side run](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42616465352) contains:

```c
/* Illustrative lines from decompilation: argument/prototype restoration is imperfect */
else if (((uVar8 & 0xff) == 0) || (DAT_001cdfd8 != 0)) {
    /* user confirmation / platform-specific checks ... */
    lVar12 = FUN_00043688(0, uVar8);
    if (lVar12 == 0) {
        FUN_00027a8c();  /* sends a Fastboot success response via helper */
        /* conditional follow-up/reboot logic */
    } else {
        FUN_00001fd4(pcVar14, 0x40, "\tSet device %a failed: %r", ...);
        /* response failure path */
    }
} else {
    pcVar14 = "Flashing Unlock is not allowed\n";
}
```

**Distinctions:**
1. ABL FRP permission global `DAT_001cdfd8` is tested for an *unlock* request. Android's observed `sys.oem_unlock_allowed=1` is supportive but **not a direct measurement** of the FRP final byte as read during Fastboot initialization.
2. When permission/confirmation checks pass, a **separate device-state transition** is requested by `FUN_00043688`. Its failure is formatted as `Set device ... failed`. This is not the same error as `Flashing Unlock is not allowed`.
3. Earlier user-observed confirmation and data wipe with final `LOCKED` status are insufficient to determine whether a secure write was attempted, failed, reported success without persistence, or was never reached. **The actual old unlock Fastboot console transcript is missing.** Do not retry a potentially wiping command purely to diagnose.

If any future genuine **historic** transcript exists, distinguish `FAILFlashing Unlock is not allowed`, `FAILSet device ... failed`, `OKAY`, physical confirmation, and reboot/reset ordering without running a new unlock attempt.

## 3. Actual XBL storage backend failure path

Original EEA `VerifiedBootDxe` SHA-256 `f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55`: `FUN_0000153c` implements read/write device state via:
- `FUN_00003904` selects secure storage when `(SCM_security_state & 0x8703) == 0`, otherwise direct `devinfo`.
- Secure mode initializes QSEE `keymaster`, issues `READ_KM_DEVICE_STATE (0x202)` and then `WRITE_KM_DEVICE_STATE (0x203)` in the write path.
- If secure read/write fails, `FUN_00003898` rechecks SCM security mode (a separate mask `0x8723`) before any possible direct partition fallback; a Keymaster failure does **not** automatically permit unprotected `devinfo` writes on a secure device.
- The corresponding `km41.mbn` read/write handlers include a `qsee_is_sw_fuse_blown(1)` milestone gate. Whether the live handset's SCM flags and fuse have the denying values remains **unmeasured**.

Sources: [verifiedbootdxe analysis](verifiedbootdxe-lock-state-analysis.md), [KM41 milestone audit](2026-11-09-km41-milestone-abl2-honor70-audit.md), [raw XBL Ghidra run](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42538078141).

## 4. Service SLOCK is not a demonstrated alternative unlock

EEA and Chinese Board ABL have similarly structured `flash:slock`, `flash:slockv1`, and hwdog certification wrappers that appear to validate credential/certification payloads before success. No authenticated token, alternate lock-state write route, or permanent unlock result was demonstrated. Presence on a locked Fastboot allowlist says only that the command can be dispatched, **not** that an unauthenticated user can perform a state transition. Do not test arbitrary payloads.

Source: [EEA / Board SLOCK comparison](2026-11-09-slock-service-board-retail-comparison.md).

## 5. Most useful safe next actions

1. Continue offline static xref/semantic analysis of Fastboot context `+0x104`, and `FUN_00043688` result codes / return paths, with correct ARM64 call signatures; do not treat uncertain Ghidra variables as proven.
2. If additional handset data is needed, use only existing read-only Android OEM lock service diagnostic tools in `tools/` with the phone in **Android**, never a raw FRP/RPMB dump or write.
3. Do not re-run `fastboot flashing unlock` to reproduce an old wipe. Do not flash Board ABL/XBL/GPT, mutate FRP, OEMINFO, devinfo, antirollback, or Keymaster state speculatively.
4. Evidence needed for a **confirmed** result is persisted `UNLOCKED` after power cycles with verified boot state consistent with actual unlock. OEM toggle, Firehose loader acceptance, FRP reset or factory wipe alone are not enough.

**Assessment:** Current evidence narrows the unresolved case to FRP permission, a post-confirmation state-set error, or persistence/backend failure. It does **not** identify a demonstrated safe/reproducible permanent unlock procedure.
