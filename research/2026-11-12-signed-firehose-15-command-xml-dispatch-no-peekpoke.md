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

## Best next verifiable question

Examine **the registered executable `firmwarewrite` and `fixgpt` functions** and confirm whether they have any actual Secure Boot or Keymaster/RPMB interaction rather than normal UFS-only I/O. Do not send arbitrary firmware or GPT to the physical phone without original image signatures, rollback compatibility and an explicit reproducible unlock mechanism.

Current research has no evidence of a viable protected-state unlock primitive.
