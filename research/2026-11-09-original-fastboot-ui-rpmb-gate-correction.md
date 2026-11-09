# HONOR 70 FNE-NX9: original Fastboot and RPMB gate audit (2026-11-09)

Device: FNE-N29 MagicOS 8.0.0.290 C431 EEA. Method: executable-byte verification on the handset's original stock EFI / Keymaster images, checked against redacted EDL logs. **No device write, new unlock or security bypass has been performed.**

## Verified source hashes

- ABL LinuxLoader: `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`
- XBL VerifiedBootDxe: `f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55`
- EEA Keymaster: `8ee4a327f1d055b34c9d3dcb7864c2583b80f2940791ed845af25d5fc4d86cc1`

## Important correction: `flashing unlock` uses asynchronous UI, never directly calls the writer on the unmodified retail handler

Exact ABL instructions:

```asm
0x25c04: mov w0,#1; b 0x27850
0x279bc: bl 0x304e0
0x304e0: mov w0,#1; ret
0x279c0: tst w0,#0xff
0x279c4: b.eq 0x279e4        // NOT TAKEN: w0=1
0x279d0: bl 0x3dab8         // interactive confirmation
0x279ec: bl 0x43688        // direct writer branch NOT REACHED by normal command
```

Thus a host `OKAY` is an acknowledgement that the UI was launched, not proof of a persistent state write. The user confirmation runs separately. In callback `0x3d9b8`:

```asm
0x3d9e0: bl 0x37ac0         // READ via VerifiedBoot UEFI protocol
0x3d9e4: cbz x0,0x3da48    // proceed only if READ returned 0
0x3da5c: bl 0x43688        // request secure WRITE
```

ABL `0x43688` sets `+0xd` or `+0xe` in an **in-memory** state structure before issuing VerifiedBoot operation; these are not proved UFS devinfo offsets. Previous single UFS devinfo byte write did not unlock even though persisted.

## Keymaster -15 may be after Fastboot, NOT the unlock failure

Comparison of user's EDL BEFORE/AFTER extracted FAT log records:
- AFTER `UefiLog4.txt` has 7 fastboot markers, no `BootLinux: Entered`, one RPMB success, and **no** `read status -15` or `VBRwDevice 0x50`.
- The other four AFTER log files include `BootLinux: Entered` and show the `-15 → 0x50` sequence.
- Therefore `-15` is not yet linked to the **UI callback**. Treating it as the cause of failed `flashing unlock` is premature.
- The genuine Keymaster read handler `0x185a8` calls software fuse checker `0x17980` at `0x1862c`. Error `-15` arises if fuse check itself failed OR if fuse was reported blown; live fuse state has not been read.

## Exact state backend

XBL VerifiedBootDxe `0x3904` selects state backend based on `SCM_security_state & 0x8703`, so direct UFS `devinfo` is not proven authoritative on the real phone. Do not assume manipulating another UFS flag will change Keymaster/RPMB state.

## Research priorities (original methods, not only external success monitoring)

1. Trace actual *post-confirmation* outcome in `0x3d9b8` (`0x37ac0 READ → 0x43688 WRITE`) and the operation's result.
2. Identify if an existing authenticated/factory or pre-milestone, user-owned device execution path can legitimately reach the secure state setter; require device/build-specific proof before any firmware write.
3. Examine unsigned EFI staging claims against exact secure boot chain, not only presence of PoCs elsewhere. Retail ABL has no literal `efisp` or `gpu-preemption` string, which is a string-only absence finding.
4. Confirm any exploit by *both* Fastboot lock states reading UNLOCKED after repeated power cycles.

**Current state:** no validated permanent unlock, no evidence-based EDL write target. An unvalidated change to GPT/ABL/XBL/RPMB or fuses risks irreparable device failure. 
