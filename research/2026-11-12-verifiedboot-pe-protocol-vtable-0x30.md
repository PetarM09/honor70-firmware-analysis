# 2026-11-12 — VerifiedBootDxe protocol vtable: +0x08 RWDeviceState and +0x30 target RVA 0x1C84

## Exact provenance

**[Successful GitHub Actions run 43119964672](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43119964672)** recovered the original signed EEA `VerifiedBootDxe` PE using the user's uploaded 14-part MagicOS 8.0.0.290 firmware release and checked its SHA256 against the previously pinned source:

`f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55`

The image is **61,440 bytes**, PE ARM64, image base `0x0`. The matched VerifiedBoot protocol GUID `8e5eff91-21b6-47d3-af2b-c15a01e020ec` appears at file offset `0xD0A8`. The executable RVA range reported by the parser is `0x1000..0xD000`.

The [hash-pinned analyzer](../tools/audit_verifiedboot_pe_protocol_table.py) located **exactly one** 8-byte-aligned contiguous array in the original PE with the known `RWDeviceState (0x153C)` handler at offset `+0x08`, and with 7 function-pointer entries targeting valid executable RVAs.

## Verified pointer array (file offset 0xD160)

| Array offset | Original little-endian qword | Static interpretation |
|---:|---:|---|
| `+0x00` | `0x10003` | Protocol revision-like value |
| `+0x08` | `0x153C` | `FUN_0000153C`, known `RWDeviceState` READ/WRITE handler |
| `+0x10` | `0x147C` | `FUN_0000147C`, `DeviceInit` implementation |
| `+0x18` | `0x1FE0` | Executable method (not recognized as a function start in the archived Ghidra text) |
| `+0x20` | `0x1ADC` | Executable method (same naming limit) |
| `+0x28` | `0x24D8` | Executable method, recognized as `FUN_000024D8` |
| **`+0x30`** | **`0x1C84`** | **Actual executable target in this array for ABL's reset-method slot** |
| `+0x38` | `0x2474` | Executable method (not recognized as function start in archived Ghidra text) |

The array begins **184 bytes after** the known VerifiedBoot GUID in the file. ABL previously verified that `VBRwDevice` is called at `protocol+0x08` and the separate reset-helper method is called at `protocol+0x30`. The **known handler at +0x08** provides a particularly strong positional anchor.

**Confidence:** very strong identification of a candidate contiguous protocol-method table; final registration proof still requires code xrefs connecting the GUID and table to `InstallProtocolInterface`, not only proximity. A function pointer is a code address **not** an EDL partition offset, a place to write data, or proof that the method executed on the user's phone.

## Resolved by the follow-up original PE + Keymaster crosscheck

- [Original XBL ARM64 instructions and GUID+vtable UEFI registration, run 43120424282](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43120424282)
- [Independent original Keymaster command mapping, run 43121032094](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43121032094)
- [Full durable interpretation](2026-11-12-xbl-reset-slot-0x10e-is-delete-all-keys-not-unlock.md)

**The vtable is registered with the VerifiedBoot GUID.** The exact original ARM64 implementation at **RVA 0x1C84** prepares a 4-byte Keymaster QSEE request **0x10E** and validates the transport and returned result. Original signed `km41.mbn` labels **`0x10E = DELETE_ALL_KEYS`**, whereas `0x203 = WRITE_KM_DEVICE_STATE`.

This makes provider slot **`+0x30` an independent Keymaster key-deletion request, not the protected device-lock-state writer**. It is on the route leading to recovery wipe but does not alone prove the live handset executed it or that any bootloader state was modified.

No phone operation or firmware write was performed in any of these two automated analyses.
