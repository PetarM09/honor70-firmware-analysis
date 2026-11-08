# HONOR 70 FNE-NX9 — Verified unlock path analysis

**Target:** FNE-N29 8.0.0.290(C431E4R3P1), Android 14, ABL LinuxLoader SHA256 `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`.

**Research status:** Signed stock firmware analyzed offline, with no writes to the phone. **No reproducible bootloader unlock method verified**. Do not flash modified bootchain or erase FRP as a trial.

## Static chain recovered from original ABL

1. Fastboot command registry contains `flashing unlock` at 0x25c04 and `flashing lock` at 0x25c0c. Both call a common handler 0x27850 with different requested operations.
2. The permission field is at relative address 0x1cdfd8, read at 0x25bcc (`flashing get_unlock_ability`) and 0x278c8 (unlock gate). It is initialized at 0x240c8, as confirmed by original ARM64 instructions and Ghidra memory cross references.
3. Initializer function 0x23fd0 locates the UTF-16 named GPT partition `frp` (string at 0xbbe26), uses a partition read callback, and copies the last-byte bit0 into the permission field.
4. From the **exact stock `/system/framework/services.jar`**, `PersistentDataBlockService.doSetOemUnlockEnabledLocked` seeks to `getBlockDeviceSize()-1`, writes one byte, flushes it and updates `sys.oem_unlock_allowed`. The same class's `doGetOemUnlockEnabled` reads the byte at end-of-block. It uses `computeAndWriteDigestLocked` in the authorized binder setter. The `sys.oem_unlock_allowed` property alone does **not** prove the disk write succeeded, since exception paths also set this property.
5. Separate persistent lock state is read via a routine near 0x13008. The actual lock-state transition handler near 0x43688 writes a ~0xa18-byte state structure through `FUN_00037ac0`. Ghidra shows it locates the UEFI `VBRwDevice` protocol, then calls an abstract write method. It can schedule a recovery wipe request. This is **not equivalent** to setting the FRP allow bit.
6. The `FAILCommand not allowed` literal near 0xb7973 is referenced by `FUN_00019c4c`, an FRP erase operation handler. **Correction:** this reference does not prove a general Fastboot dispatch filter; cannot attribute user-observed failures for other commands to this function.
7. Android phone ADB runtime reports locked + verified boot green despite `sys.oem_unlock_allowed=1`. No live FRP byte has been directly verified; no transition confirmed.

## Verified investigations

- [Ghidra initial Fastboot policy decompilation](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42533269683)
- [0x240c8 permission writer disassembly](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42533590805)
- [FRP partition name and Fastboot handlers](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42533690027)
- [Ghidra state writer / UEFI VBRwDevice](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42534382784)
- [Stock PersistentDataBlockService bytecode](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42533989312)
- [Specific FRP erase Command not allowed handler](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42534718752)

## Other lead: CVE-2026-43499 / GhostLock

Exact kernel has a potentially vulnerable `remove_waiter()` instruction pattern. Upstream GhostLock extractor confirms the primitive; however, the generated profile is **incomplete and unsafe**, lacking exact BTF structural offsets and correct physical address info. No root was achieved and root alone would not unlock bootloader.

## Next grounded checks

- Inspect read-only live `PersistentDataBlockService` diagnostic output if available, without dumping block partitions or personal data. Distinguish userspace property from actual on-disk boolean.
- Trace `VBRwDevice` GUID/protocol implementation, authorization and secure storage backend.
- Do not erase FRP or write OEMINFO 95/130, ABL/XBL/vbmeta or raw partitions as speculative trials. Unlock results require persistent state readback across reboot with no unauthorized modifications.

## Further validated protocol / GPT inventory

- `FUN_00037ac0` obtains `QCOM_VERIFIEDBOOT_PROTOCOL` whose GUID, decoded from `DAT_001b390c` in the exact stock LinuxLoader, is **`8e5eff91-21b6-47d3-af2b-c15a01e020ec`**. Verified by [ABI/GUID extraction](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42534863723). This GUID is shared with a public GBL vulnerability write-up; GUID equality alone does not imply the vulnerable boot chain exists on this model.
- Firmware `gpt_both0.bin` was independently parsed as **six 4-KiB-sector GPT LUNs with all partition-entry CRCs valid**. There are **135 identified partitions**, including `frp`, `oeminfo`, `devinfo`, `abl_a/b`, `xbl_a/b`, `uefisecapp_a/b`. The firmware's GPT contains **neither `efisp` nor a `gbl` partition**; the published unsigned-GBL-from-efisp attack does not have its named entry point on this firmware. [GPT inspection and checksums](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42535247420).
- The public GBL attack also needs the ability to modify a boot-time EFI application / efisp from a locked device. No such write channel has been confirmed. No speculative flashing.
- The Android stock `PersistentDataBlockService` sets `sys.oem_unlock_allowed` even in some exception paths after attempting its FRP last-byte write, so the live system property `1` is **insufficient to establish that bootloader reads `1` from disk**. Read-only live service diagnostics requested; no raw FRP contents should be shared.
