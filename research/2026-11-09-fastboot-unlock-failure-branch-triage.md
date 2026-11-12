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


## 6. Newly confirmed: command gate shares a concrete initialized state field with lock-state query

An additional offline ARM64 XREF workflow analyzed the same verified signed EEA LinuxLoader:

- [Full run and read-only artifact](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42626091468)
- [Source of reproducible Capstone audit](https://github.com/PetarM09/honor70-firmware-analysis/blob/main/.github/workflows/trace-fastboot-access-state-readonly-20261109.yml)

At `0x12ea0`, initialization calls `0x176d8`, obtains a context pointer in `x19`, and at `0x12ec4` **writes the +0x104 state field**. It initializes this field using `0x13684` in one branch, or zero in another. That code path is not purely a Fastboot allowlist: the state value is initialized first, then consulted by multiple unrelated functions.

```asm
0x12ea0 bl  #0x176d8
0x12ea4 mov x19, x0
0x12ea8 bl  #0x12cf8
0x12eac cbnz w0, #0x12ec4
0x12eb0 bl  #0x13d58
0x12eb4 cbz w0, #0x12ec0
0x12eb8 mov w0, wzr
0x12ebc b   #0x12ec4
0x12ec0 bl  #0x13684
0x12ec4 str w0, [x19, #0x104]
```

**Independent READ of the same context**: `0x13008` invokes `0x13608` (which calls `0x176d8`), then `0x13024` reads `[x0,#0x104]`, compares to 1, and returns a boolean (subject to an additional guard at `0x1301c`).

```asm
0x13014 bl  #0x13608
0x1301c ldr w8, [x8, #0x390]
0x13020 cbz w8, #0x13034
0x13024 ldr w8, [x0, #0x104]
0x13028 cmp w8, #1
0x1302c cset w0, eq
```

**The Fastboot allowlist gate** uses the *same context pointer* returned by `0x13608` and checks exactly `[x0,#0x104]==1` at `0x134d8..0x134e0`; otherwise applies 49 allowed command prefixes.

```asm
0x134d4 bl  #0x13608
0x134d8 ldr w8, [x0, #0x104]
0x134dc cmp w8, #1
0x134e0 b.eq #0x13518     // unrestricted command dispatch
```

**Conclusion supported by exact instructions:** the Fastboot allowlist gate's `+0x104` is **not merely a hard-coded property of Fastboot command strings**. It is a genuine initialized field also read by lock-state related logic. This makes the interpretation “device unlock state gates access to broad Fastboot commands” substantially stronger, although the *exact semantic identity* of `0x13684`'s return value and the phone's live stored value remain unproven.

Do not confuse context-relative `[x0,#0x104]` with absolute address `0x1b5104`: `0x176d8` resolves a context pointer from a global. All scans of arbitrary `[reg,#0x104]` include unrelated structures; only the linked call chain is relevant.

**No device operation occurred:** both successful workflow runs operate only on the offline firmware.

## 2026-11-12 correction: ABL +0x104 derives from OEMINFO RD-mode-v1 credential checks

[New original-ABL ARM64/Ghidra crosscheck](2026-11-12-abl-oeminfo-rdmode-v1-localstate-unlock-shortcut.md) [successful test](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43125419237):

- The returning path from `FUN_0001BF74` is constant `2`, selecting `FUN_00015690` from the caller `0x12CF8`.
- The selected `0x15690` routine checks two RD-mode-v1 identifiers (`0XEED6030008` and `fastboot flash:rdmodev1`) using `0x1BB68`, whose Ghidra body includes `data_set_sha256_rsa_check_pss` logging. This sources the local access field `+0x104` through a service-mode-related OEMINFO **record ID 0x82**, not a direct Keymaster/RPMB state read.
- Normal and critical UI `unlock` both request the byte **1**, verified from the original signed PE data and UI selection instructions.
- The Fastboot allowlist checks only when local context `+0x104 != 1`. If an unallowlisted command was blocked in the **same unchanged session**, an unlock request of 1 cannot take the local-state equality shortcut and would next attempt the VBRwDevice WRITE after its initial callback READ.
- The past confirmation and wipe are older, non-concurrent observations: they do not prove the live state at the time, nor which secure WRITE stage ran. **Permanent unlock remains unconfirmed.**

Do not equate a service RD-mode authorization bit with a persistent bootloader unlock bit, or write OEMINFO record 130 on this basis.



### Follow-up: exact source branch for +0x104 initialization

A third successful [read-only workflow](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42626334313) expanded the initializer around `0x12cf8` and its helper `0x13684`.

```asm
0x12ea0 bl #0x176d8       // same context resolver used by lock-state and Fastboot gate
0x12ea4 mov x19,x0
0x12ea8 bl #0x12cf8       // candidate source of a nonzero state
0x12eac cbnz w0,#0x12ec4 // nonzero is stored into context
0x12eb0 bl #0x13d58
0x12eb4 cbz w0,#0x12ec0
0x12eb8 mov w0,wzr        // force 0
0x12ebc b #0x12ec4
0x12ec0 bl #0x13684       // guard/canary helper, returns 0 on normal path
0x12ec4 str w0,[x19,#0x104]
```

`0x13684` **does not retrieve a secret or secure device state**: its normal path calls `0x140b4` (stack guard comparison), then `mov w0,wzr`. It thus initializes +0x104 to zero on that branch. The nonzero value can enter from `0x12cf8`.

At `0x12cf8`, ARM64 includes `mov w0,#0x82` followed by `bl #0x136a4` (the already identified OEMINFO record reader), checks another function `0x1bf74`, and later calls `0x1a7b0` before potentially returning 1. That establishes **an OEMINFO 0x82 (decimal 130) dependent initialization route** for the Fastboot access field. It does NOT establish that changing OEMINFO #130 unlocks the bootloader. Real lock persistence remains via a separate VBRwDevice/Keymaster protocol, and the meaning of each OEMINFO record's values remains unproven.

This refines the interpretation of the gate: it is a device/context state derived at least partly from OEMINFO, rather than a direct live Keymaster unlock bit necessarily. Do **not** write OEMINFO to try to force `+0x104=1`, as this could brick or alter security without affecting permanent lock state.
