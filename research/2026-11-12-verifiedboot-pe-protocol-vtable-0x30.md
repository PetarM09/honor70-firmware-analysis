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

## Next step

Disassemble **RVA `0x1C84`** from the verified original ARM64 PE and correlate it with initialization code references to the vtable RVA `0xD160` and GUID RVA `0xD0A8`. The previous full-file Ghidra text index did not include a function starting at `0x1C84` by name, so disassembling exact instruction bytes is necessary.

No device connection, EDL read/write, Keymaster invocation, RPMB access or security state change was performed. There is still **no confirmed permanent bootloader unlock**.
