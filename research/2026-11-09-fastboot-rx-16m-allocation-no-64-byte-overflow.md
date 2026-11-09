# 2026-11-09: HONOR 70 FNE-NX9 Fastboot RX allocation (original byte verification)

Target stock EEA LinuxLoader SHA256 `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`.

**Correction to previous candidate:** terminator store at `0x22CD4` does **not** establish a one-byte overflow on the traced retail Fastboot USB command paths.

## Verified provenance

- `0x20948..0x20958`: USB transfer buffer allocator via interface vtable `+0x20`, requested `0x1000000` (16 MiB), output pointer `global+0x08` (RX).
- `0x20960..0x20970`: same method requests 16 MiB for `global+0x10` (TX).
- USB device interface's `+0x20` method corresponds to `UsbDeviceAllocateBuffer`, and `+0x28` to `UsbDeviceFreeTransferBuffer` (consistent with code and literal ABL error strings for RX/TX allocation/freeing).
- `0x20410..0x20420`: requests up to `0x1ff` bytes (511) via USB method `+0x10`, from the RX pointer in `global+8`.
- `0x20570..0x20578` passes same pointer to `0x22A64`; `0x22A6C` preserves it as `x20`, `0x22B8C..0x22B90` passes it to parser `0x22C7C).
- Event callback alternate route stores the same parser pointer at `0x22D4C`, reloads it at `0x24398`, then calls parser at `0x2439C`.
- `0x22CC8..0x22CD4` sets `buffer[min(length,64)] = 0`, **inside** a successfully allocated 16-MiB RX buffer.

The original XBL's USB drivers were extracted/hashed from the same on-device signed bootchain:
- `UsbfnDwc3Dxe.efi`: `756803f30f6ad7f3a8515b8b2930830eb65d6ae96409670e2a2d5b7781c270d0`
- `UsbDeviceDxe.efi`: `4455202c89239d114eb6757cabf8e67c31ca70a43352f128bdab3f760843f679`
- `UsbConfigDxe.efi`: `6b018d053919054d6028ca6cdd74250a22cc2564620b888d03970c0fc8491195`

**Security conclusion:** earlier proposed 64-byte off-by-one is not supported for these proven pointers. This does not prove whole Fastboot code memory-safe or refute every CVE. No malformed USB commands or EDL writes were issued.

## Work still needed for the user's requested persisted UNLOCKED state

The Fastboot UI callback `0x3D9B8` needs successful VBRwDevice `READ` through `0x37AC0` before calling `0x43688` WRITE; a host `fastboot flashing unlock` OKAY acknowledges menu launch only. No proved bypass into authoritative Keymaster/RPMB state yet; do not perform random OEMINFO/DEVINFO/GPT/ABL/RPMB writes. Investigate authenticated callback error/success semantics or distinct pre-milestone state writer, and require real unlocked readback after cold boots.
