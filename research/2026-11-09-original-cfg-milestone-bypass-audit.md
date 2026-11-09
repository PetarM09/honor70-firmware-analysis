# HONOR 70 FNE-NX9: independent original-code unlock pre-milestone audit (2026-11-09)

Target: FNE-N29 8.0.0.290(C431E4R3P1), original EEA `LinuxLoader.efi` SHA256 `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`.

**Status: no demonstrated persistent unlock/bypass or EDL write target. No live writes during this analysis.**

- All direct ARM64 BL callsites to `0x43688` (normal/critical state setter) in the original EFI are **exactly two**: `0x279EC` and `0x3DA5C`. Other indirect paths cannot be excluded by this statement.
- The normal Fastboot command at `0x25C04` enters common `0x27850`; `0x304E0` returns a constant 1, so default path creates an asynchronous UI menu at `0x3DAB8`, not direct call `0x279EC`.
- The menu callback reaches `0x3D9B8`, which must successfully `VBRwDevice READ` at `0x3D9E0` before the state setter at `0x3DA5C`.
- In the ABL function at `0x3144`, debug string `Sending Milestone Call` points at `0xAFAB5`; the corresponding `BLR` call is `0x42A4`. A later block near `0x42E8` logs `NoAVBLoad_fw_ufsdev Start` (string `0xAFAF1`). Static direct-branch CFG for `0x3144..0x4934` finds one *external direct branch* into `0x42D0..0x42F8`: `0x42B0 -> 0x42D0`, executed after `0x42A4`. This **argues against** copying a Redmi 14R GPT-vbmeta rename milestone skip on FNE-NX9. Static CFG is not proof against computed branch or another executable path.
- Plain string `oem unlock` at `0xB5A7E` appears in the Fastboot **allow-prefix** pointer table (`0x1B4210`); this alone does not establish an alternative registered handler.
- `0x12D20` reads OEMINFO API ID `0x82` (decimal 130) as an input to the Fastboot-context field `+0x104`. This is not evidence that editing a raw v8 ID 130 or an arbitrary OEMINFO byte changes persistent RPMB state.

**Live observations supplied by owner:** OEM permission bit in FRP is 1; ABL/Keymaster/VerifiedBootDxe images are unchanged; a persistent EDL write at UFS devinfo[0x10]=1 did not unlock; Fastboot returned OKAY for UI launch, physical confirmation/wipe occurred but lock remained; Fastboot-only UEFI log slot lacks `-15`, while Linux-boot slots have `read status -15` and `VBRwDevice 0x50`. Do not mistake those normal-boot errors for proof of a failed Fastboot UI state write.

**Operational direction:** seek a device/build-specific pre-milestone in-memory execution surface (or verified alternative authenticated state-set path), not random GPT/OEMINFO/FRP/devinfo upserts. A potentially damaging EDL experiment should require a validated mechanism, exact target partition and backup/readback/restore. Completion requires persistent Fastboot `UNLOCKED` and a matching AVB result across two cold boots.
