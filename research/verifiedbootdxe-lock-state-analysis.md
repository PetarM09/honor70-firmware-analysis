# HONOR 70 FNE-NX9 — VerifiedBootDxe / OEM lock-state forensic audit

**Date:** 2026-11-09. **Device build:** HONORFNE-N29 8.0.0.290(C431E4R3P1), Android 14. **Method:** static read-only disassembly and decompilation of an original, matching signed firmware, plus basic non-invasive device diagnostics. **Status:** no validated bootloader unlock or root method; no write or flash operation performed on user's device.

## Proven exact-binary chain

1. Original signed `image/abl.elf`: compressed firmware volume includes `LinuxLoader` UEFI image, SHA-256 **`ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`**.
2. Original signed `image/xbl.elf`: compressed firmware volume includes separate `VerifiedBootDxe` UEFI driver (FFS file GUID `a25f5839-4d55-428f-8f0b-5ce1d565f53e`). PE image 61,440 bytes; SHA-256 **`f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55`**. This module contains the same protocol GUID referenced by the LinuxLoader `gQcomVerifiedBootProtocolGuid` `8e5eff91-21b6-47d3-af2b-c15a01e020ec`.
3. `flashing get_unlock_ability` at LinuxLoader 0x25b88 reports the runtime global at 0x1cdfd8. This permission is read from the final byte of the `frp` partition, lowest bit, at initialization (ABL 0x240c8). `flashing unlock` calls common handler 0x27850. If permission is allowed and other conditions pass, its code may call Verified Boot device-state function through the protocol.
4. The ABL lock-state writer at 0x43688 passes a ~0xa18-byte structure to the `VBRwDevice` UEFI protocol via 0x37ac0. Recovery wipe is possible as part of the authorized unlock state change.
5. **Original system/framework/services.jar** `PersistentDataBlockService` uses `ro.frp.pst` for FRP and sets `sys.oem_unlock_allowed` based on `doGetOemUnlockEnabled()` at startup unless `isPayJoyControlledDevice()` short-circuits. This property can also be set after a failed attempted write: **property 1 alone does not prove the physical FRP last bit was read 1**. The authorized `getOemUnlockEnabled` binder getter enforces privileged permissions.
6. Phone diagnostic reported the FRP device path `/dev/block/bootdevice/by-name/frp`, lock state=1, `sys.oem_unlock_allowed=1`, no `efisp`. The exact full stock GPT had six 4KiB-sector UFS LUNs and 135 entries; no `efisp` or `gbl` partition. The unsigned GBL exploit that requires `efisp` cannot be applied verbatim.

## New: exact VerifiedBootDxe implementation (Ghidra, 164 functions)

- **`FUN_0000153c`**: implementation of read/write device-state protocol, with `param_2==0` read, `param_2==1` write, other operation rejected. It validates buffer pointer and size.
- It uses `FUN_00003904` to determine backend from secure state, with `FUN_000037dc` obtaining state via Qualcomm SCM interface, SIP call **`0x02000604`**. State lookup errors fail with status 0x50.
- `FUN_00003904` sets secure-backend flag when **`(security_state & 0x8703)==0`**. When the masked bits are nonzero, it chooses direct `devinfo` partition I/O. **This predicate is a static firmware result; the phone's actual SCM security_state is not known**.
- **Secure-backed path:** locates `gQcomQseecomProtocolGuid`, launches `keymaster` app, exchanges requests via QSEE protocol (decompiled request IDs include 0x202 and 0x203) using buffer length 0x1000 and reports `Succeed using rpmb!` on success. The ultimate storage/authenticity decisions occur inside trustlet/TEE, **not visible in this UEFI module**, so we cannot assume that direct modification of devinfo would persist or be accepted.
- **Direct devinfo path:** uses `FUN_00002870` and `FUN_00002a1c` to access `devinfo` via UEFI block I/O, reads before a write, and reports `Succeed using devinfo!` on success. Partition data not captured from live phone.
- **Failure fallback:** if secure QSEE request fails, `FUN_00003898` rechecks SCM state with mask **`0x8723`**. The source's branch only attempts fallback direct partition I/O when this second check determines the device is **not** secure. The secure state cannot trivially fall back by making Keymaster fail. More work could reconcile the difference between the two masks but no vulnerability has been demonstrated.
- **`FUN_000037dc`** fails closed with all-ones state when SCM status is invalid.
- **`FUN_0000147c`** initialization logs `VB: DeviceInit: Device is unlocked! Skipping verification!` when passed unlock flag; this is a runtime result, not a technique for changing persistent state.

### Reconstructed high-level *descriptive* pseudocode

```text
read_or_write_lock_state(operation, input_buffer, length):
    if invalid parameters: return ERROR
    state = SCM.read_security_state()
    if state unavailable: return ERROR
    secure_backend = ((state & 0x8703) == 0)
    locate("devinfo")
    if secure_backend:
        start QSEE keymaster
        result = QSEE.transport(request(operation), state_buffer)
        if result unsuccessful:
            if no secure fallback permitted per second SCM predicate:
                return ERROR
            else:
                return direct_devinfo(operation)
        return result
    else:
        return direct_devinfo(operation)
```

Not intended as executable code. Details of error paths need to be checked against raw ARM64 disassembly because Ghidra reports return values and stack aliases imperfectly. No direct ADB command can invoke UEFI services in Android normal operation.

## Fastboot request routing unresolved

The static LinuxLoader `flashing get_unlock_ability` handler simply reports global permission; it contains no local `Command not allowed` error. LinuxLoader `getvar:` reports `GetVar Variable Not found` for unsupported entries. The literal `FAILCommand not allowed` at 0x19c4c is specifically in the `oem_frp_erase` handler, not a proven general Fastboot filter. Prior device Fastboot returned `Command not allowed` for standard requests. **It is not established whether this comes from a separate pre-dispatch policy or a different active bootloader firmware version/module**.

## Scope / safety

The device's `devinfo`, `frp`, `oeminfo`, RPMB, vbmeta, ABL, XBL, and critical boot-chain partitions were not written, erased, or modified. No live personal data dumps were generated. Do **not** infer an unlock method from masks, GUIDs, or this decompilation. Any attempt to run unsigned EFI code, patch locked boot-chain stages, or modify protected storage may brick the device, bypass anti-theft protections, or erase user data.

## Reproducible GitHub research artifacts

- [Exact LinuxLoader fastboot handler decompilation](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42536785118)
- [Stock Android OEM Lock HAL startup and FRP service](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42537052942)
- [OEM Lock + FRP boot synchronization](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42537249856)
- [XBL UEFI decompression and VerifiedBootDxe PE discovery](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42537571936)
- [Ghidra decompilation of 164 VerifiedBootDxe functions](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42538078141)
- [Exact SCM selector masks / QSEE / RPMB / devinfo references](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42538280154)

## Next evidence to collect safely

Read-only Android diagnostics to establish whether the vendor OEM Lock AIDL or HIDL HAL exists on *this specific device*, and whether OEM unlock restrictions are sourced from the persistent data block or HAL. Use `tools/honor70_oemlock_hal_readonly.py` from this repo, review report locally before sharing, do not publish private phone logs. Results cannot expose SCM security state from boot and cannot prove a bypass of protected storage. Investigate the active ABL version matching signed stock. No further raw partition reads needed yet.
