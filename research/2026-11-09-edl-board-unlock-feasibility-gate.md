# FNE-NX9 — EDL / factory board firmware feasibility gate (2026-11-09)

Device: HONOR 70 FNE-NX9 EEA C431, FNE-N29 8.0.0.290, Qualcomm SM7325, UFS 6 LUN. **No tested permanent bootloader unlock has been found.**

## Independent evidence (NOT equivalent to bootloader unlock)

- Public QcFire and Pandora service logs for exact model FNE-NX9 demonstrate that an accepted Qualcomm Sahara/Firehose loader can be started in EDL 9008 mode, and that UFS GPT can be enumerated and FRP service operations performed. Device model and loader acceptance were observed in those other devices, **not tested on user's handset**.
- Public third-party support lists OEMINFO operations for FNE-NX9, but no reproducible permanently-unlocked demonstration or retail FNE-NX9-specific one-click unlock.
- Exact FNE-NX9-BD engineering/Board package listing: `FNE-NX9-BD 1.0.0.34_Board Software_general_Magic UI 6.0_05023HNJ.zip` (4.07 GB, vendor subscription). Existence is documented; payload has not been downloaded or checked against FNE-N29 8.0.0.290 and current antirollback.
- Technician's firsthand report on gsmforum.ru thread `chipset-sm7325-honor-70-fne-nx9-vykladki-po-pitaniyu.349600`: engineering board mode can affect OEMINFO protection, **but flashing the EDL board component alone did not unlock their bootloader** and technician couldn't complete Fastboot-side board flashing. This is anecdotal, not a validated method.

## Why GPT write, OEMINFO write or devinfo write is not itself unlock

Exact stock ABL `LinuxLoader` (`ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`) gate:

```text
flashing unlock [0x25c04]
 -> common unlock handler 0x27850
 -> FRP allow indicator DAT_001cdfd8
 -> FUN_00043688
 -> UEFI VBRwDevice 0x37ac0
 -> XBL VerifiedBootDxe device-state handler 0x153c
```

Original XBL `VerifiedBootDxe` (`f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55`) selects protected RPMB via Keymaster when `(SCM_security_state & 0x8703)==0`. Other configurations use raw `devinfo`; Keymaster error does not force unsafe fallback on secure devices.

Original Keymaster `km41.mbn` (`c7f389b80444a9c9e3956efd427abbae1b5b2753b3c905107ca7888dca496afd`) rejects read/write when milestone soft fuse 1 is active. Read `0x202` and write `0x203` check `qsee_is_sw_fuse_blown(1)`. Boot firmware can invoke milestone `0x204` through UEFI protocol. A successful EDL GPT enumeration or OEMINFO rewrite cannot prove its RPMB persistent state is writable.

**Decisive unknowns:** active SCM security state; exact live ABL/XBL variant and persistent-state readback; FRP last-byte actual value; signed service loader's privilege set and authorized operations; engineering board ABL/XBL policy and signature / antirollback acceptance.

## First serious non-destructive hardware test (conditional)

Precondition: user has a **verified signed FNE-NX9 loader** that is compatible with their exact phone and a recovery plan; do not download generic firehose binaries from unknown sites.

1. Linux/Windows PC and a known-good USB data cable. Back up user data normally. Enter Qualcomm EDL 9008 only using documented phone-specific safe procedure; avoid guessed short circuits. Stop if USB identification is inconsistent or recovery path unknown.
2. If using an *open ELF/MBN* signed programmer accepted by the device (note proprietary QcFire `.ufl` is **not necessarily** compatible with open-source edl tool), use the read-only bkerler/edl `edl printgpt --memory=ufs --loader=/path/to/verified_loader.elf`. Read-only means this command has no flash/erase request; still verify correct model and use a controlled environment. Export text-only logs with device serial and other identifiers redacted.
3. Success criteria for this stage are loader acceptance and *all six* UFS LUN GPT layouts with expected model partitions; it proves only access to enumerate, **not writable lock state**. Stop before any write.
4. With legally obtained engineering board ZIP, run `python3 tools/board_firmware_probe.py '/path/to/FNE-NX9-BD.zip' --output HONOR70_BOARD_FIRMWARE_INSPECTION.json`, send JSON and if necessary actual ABL/XBL/TrustZone metadata for deeper comparative analysis. The utility **scans ZIP top-level entries** and is not a proof of compatibility.
5. Only after board bootloader signature/rollback, secure storage backend and verified recovery can be demonstrated should any write be considered. A full GPT, OEMINFO, devinfo or XBL flash based on guesswork risks hard brick and can permanently destroy calibration/security data.

## Proof required to declare permanent unlock

The target should report both Fastboot lock state and AVB device state **unlocked after multiple power cycles and actual loading of a permitted unsigned image**. Neither FRP removal, root, technician diagnostic mode, ability to write generic partitions, nor OEM Unlock toggle is sufficient.

## Proven analysis job links

- https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42543573988
- https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42543746415
- https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42544432248
- https://github.com/PetarM09/honor70-firmware-analysis/blob/main/tools/board_firmware_probe.py

## Public external resources

- https://gsmforum.ru/threads/chipset-sm7325-honor-70-fne-nx9-vykladki-po-pitaniyu.349600/
- https://forum.gsmhosting.com/vbb/f1110/post-here-successfully-job-pandoras-2953984-print/index41.html
- https://support.halabtech.com/index.php?a=downloads&b=folder&id=185933
- https://github.com/bkerler/edl/blob/master/README.md
