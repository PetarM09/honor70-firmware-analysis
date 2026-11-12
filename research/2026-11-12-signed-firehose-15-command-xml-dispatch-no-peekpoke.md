# HONOR 70 — 12 Nov 2026: Original signed DDR/Lite Firehose XML dispatcher (15 actual callbacks)

**Target:** HONOR 70 FNE-NX9 C431 MagicOS 8.0.0.290; static inspection of the available **FNE-AN00 HMT signed Board programmers**. No physical device was connected. No EDL/Fastboot command or write was executed. **No verified persistent bootloader unlock method has been found.**

## Fully reproducible, newly established facts

The signed ELF binaries SHA-256:

- DDR: `9c892e716320764c20055d8374bf8eca7418b3ff2177f81794e18d3656fc55a8`
- Lite: `e029df6e2d532de87c2279e960472ec0e4799aca53bc27ed4fa3e4027b05d101`

GitHub Actions results:

- [DDR/Lite original Ghidra security predicate decompilation (both successful)](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43136649865).
- [DDR/Lite precise command NUL token inventory with false-positive exclusion (both successful)](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43137433674).
- [DDR/Lite actual registered XML callback table (both successful)](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43137871278).
- [Original signed ELF command table parser](../tools/inspect_firehose_xml_handler_table.py).
- [False-positive diagnostic substring verifier](../tools/audit_firehose_peekpoke_registration.py).

### Actual binary table, not just free-floating log strings

The signed Board Firehose includes an explicit **array of 15 adjacent 16-byte entries** starting at virtual address `0x148A2968`:

```text
entry + 0x0: pointer to zero-terminated command name
entry + 0x8: pointer to executable ARM64 handler
```

The names and valid executable callbacks in the exact original binaries are:

| XML command name | DDR function VA | Lite function VA |
|---|---|---|
| `program` | `0x14825908` | `0x148258FC` |
| `read` | `0x14825B6C` | `0x14825B60` |
| `nop` | `0x14825D5C` | `0x14825D50` |
| `patch` | `0x14825DBC` | `0x14825DB0` |
| `configure` | `0x148261F0` | `0x148261E4` |
| `setbootablestoragedrive` | `0x14826564` | `0x14826558` |
| `erase` | `0x1482667C` | `0x14826670` |
| `power` | `0x148267F4` | `0x148267E8` |
| `firmwarewrite` | `0x14826A30` | `0x14826A24` |
| `getstorageinfo` | `0x14826BC4` | `0x14826BB8` |
| `benchmark` | `0x14826E24` | `0x14826E18` |
| `emmc` | `0x148276F8` | `0x148276EC` |
| `ufs` | `0x148276F8` | `0x148276EC` |
| `fixgpt` | `0x14827BCC` | `0x14827BC0` |
| `getsha256digest` | `0x14825120` | `0x14825114` |

**Neither `peek` nor `poke` appears in the complete original 15-entry table.** This is stronger than the earlier negative finding that the ELF does not contain a standalone `peek\0` or `poke\0` string. The seemingly positive `poke\0` substring occurs only in a diagnostic sentence ending with `nothing to peek/poke\0` (offset `0x775F7`, preceded by `/`).

No standard XML dispatcher entry therefore leads to a registered `peek/poke` RAM memory handler in these signed programmers. This is a **registered-table finding**, not a proof that every conceivable hidden, indirect or vendor-private code path is unreachable.

### Original Secure Boot state source is an SCM call

Both Ghidra builds contain original `FUN_1482011C`, which invokes an SMC-like secure-monitor operation `0x82000119`, and returns `1` when its returned word equals `1`. The confirmed immediate caller `FUN_1481FCCC` uses that result to print the `Secure Boot:` status.

This shows a real runtime security-state query inside the signed programmer. However, **we have not proven that this result gates any memory `peek/poke` handler**; such a handler is not registered in the XML callback table. Do not state that setting an XML attribute or patching a UFS byte can change the secure monitor's result.

### EDL write consequence

The actual supported command table **does** contain sector-based `program`, `read`, `patch`, `erase` and vendor `firmwarewrite` / `fixgpt`, which can be dangerous for UFS integrity. They do **not** prove direct authenticated RPMB, Keymaster `WRITE_KM_DEVICE_STATE (0x203)`, or unsigned ABL/XBL execution. Earlier signed Ghidra established that the `UFS RPMB ReadWrite Size:` line belongs to a storage-descriptor log function, not a Keymaster writer.

No new EDL write experiment has a verified expected permanent-unlock effect from these binaries. The on-device last known bootloader state remains **LOCKED**, and the user previously tested `frp`, `devinfo` and OEMINFO avenues unsuccessfully.

## Other public update

UMT QcFire's October 2026 supported-model updates include HONOR 70 FNE-NX9 with an internal loader database refresh. This is **not** a public reproducible permanent bootloader-unlock procedure; FRP and loader support must remain distinct from secured lock-state changes. Reference: https://www.ultimatemultitool.com/modules-support/qualcomm/

## Follow-up completed: original `firmwarewrite` and `fixgpt` also decoded

- [Both signed original DDR/Lite Ghidra jobs successful](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43138202304).
- [Original full function bodies extracted for direct inspection](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43138463218).
- [Reproducible Ghidra decompiler script](../tools/ghidra/Honor70FirehoseFirmwareWriteFixGPTEvidence.java).

Original DDR `firmwarewrite`, `FUN_14826A30`, and Lite `FUN_14826A24` parse an XML request's `SECTOR_SIZE_IN_BYTES` and require it to equal **1**, obtain `num_partition_sectors` as the firmware payload length, receive the payload, then log:

```text
Will do firmware update on storage part of size %d
```

They invoke **DDR `FUN_14829B8C(...)` / Lite `FUN_14829B80(...)`** to send the update to the underlying storage-device firmware path. This is **not** a demonstrated ABL unlock-state setter, Keymaster call or authenticated RPMB writer. Flashing arbitrary UFS microcode could render the device unusable.

Original DDR `fixgpt`, now explicitly recovered as a registered Ghidra function at **`0x14827BCC`**, and Lite at **`0x14827BC0`**, parse `grow_last_partition` and call **DDR `FUN_148284CC` / Lite `FUN_148284C0`** to repair GPT for one or multiple physical LUNs, logging:

```text
G Failed to fix the GPT for LUN/PhyPart %d
```

This handler manages the storage partition table. It does **not** have any direct call to Keymaster `0x203`, nor does it prove that modifying GPT will change the platform's signed AVB2 versus NO_AVB boot decision. `fixgpt` should **not** be used experimentally as a bootloader bypass.

Both recovered handler versions were obtained from the verified executable function pointers in the **15-entry signed XML command table**; the original Ghidra binary importer failed to discover `fixgpt` automatically, so the audit explicitly disassembled and created its function at the known callback address before decompiling. No function bytes were patched.

## Current decision

All normal registered Firehose XML commands can manipulate storage, update storage firmware, or read storage metadata, but **no standard registered memory `peek`/`poke` entry exists** and no studied handler demonstrates authenticated Keymaster/RPMB bootloader-state write.

The remaining source-level research would require a different, verified secure-world primitive, a genuine bootloader parser exploit reachable from LOCKED, or the **actual signed FNE-NX9-BD** engineering firmware with compatible security/rollback and a proved persistent unlock path. No new blind EDL, GPT, XBL or firmwarewrite action is justified from these binaries.

**No confirmed permanent HONOR 70 unlock method yet.**

