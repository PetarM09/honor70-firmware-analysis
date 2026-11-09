# FNE-NX9 live Fastboot report — decisive locked-command gate, 2026-11-09

## Evidence sources
- User's read-only Fastboot report from Mac, timestamp `2026-11-09T12:53:34Z`. Model `FNE-NX9`, build `FNE-N29 8.0.0.290(C431E4R3P1)`.
- Original signed EEA LinuxLoader module from earlier local firmware archive, SHA256 `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`. Independently verified in Ghidra and binary parser.
- [Exact Fastboot command denial decompilation](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42622015805).
- [Full decompiled gate and dispatch functions](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42622306553).
- [49-entry EEA ABL allowlist (RVA `0x1b41b0`)](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42622469175).

## Verified live device observations (user-supplied; no secrets committed)

Android after boot:

| Android property | Observed value |
|---|---|
| `ro.product.model` | `FNE-NX9` |
| `ro.build.display.id` | `FNE-N29 8.0.0.290(C431E4R3P1)` |
| `ro.boot.flash.locked` | `1` |
| `ro.boot.verifiedbootstate` | `green` |
| `ro.boot.vbmeta.device_state` | `locked` |
| `sys.oem_unlock_allowed` | `1` |
| `ro.frp.pst` | `/dev/block/bootdevice/by-name/frp` |

All 8 `fastboot getvar` requests (`product`, `version-bootloader`, `version`, `secure`, `unlocked`, `is-userspace`, `current-slot`, `slot-count`) returned `FAILED (remote: 'Command not allowed')`, as did `fastboot flashing get_unlock_ability`.

`fastboot oem get-bootinfo` returned `INFO locked`, and `fastboot oem lock-state info` returned `FB LockState: LOCKED`, `USER LockState: LOCKED` with `OKAY`.

**Subtlety:** for the failed `fastboot getvar` requests, the macOS Fastboot CLI reports process exit code `0` although the protocol response contains `FAILED`. The protocol response is authoritative, not the shell status. `flashing get_unlock_ability` exits `1` in the tool version used.

## NEW ROOT CAUSE: Fastboot has an explicit locked-mode allowlist

Original ABL dispatcher `FUN_00022c7c` at RVA `0x22c7c` calls `FUN_000134c0(command)` before invoking the registered handler:

```c
int admitted = FUN_000134c0(command);
if (admitted == 1) {
    /* walk registered Fastboot prefix-handler table and invoke matching handler */
    ...
} else {
    pcVar8 = "Command not allowed";
    FUN_00020e2c(pcVar8); /* Fastboot FAIL response */
}
```

This reproduces the user's **remote** rejection directly in the firmware.

The gate function `FUN_000134c0` consults a state field at `FUN_00013608(0x1b5000) + 0x104`. When that field equals `1`, it returns allow-all. Otherwise it scans a `0x188`-byte table of 49 pointers, beginning at RVA `0x1b41b0`, comparing command text against permitted prefixes.

**Unproven:** exact semantic name of `+0x104` (e.g. current unlock state vs service state). Do not simply call it a verified `unlocked` flag without additional cross-references.

The following are on the 49-prefix allowlist and match live responses:

- `oem get-bootinfo`
- `oem lock-state info`

The following are **absent** from the table and match live `Command not allowed` results:

- `getvar:product`, `getvar:version`, `getvar:secure`, `getvar:unlocked`, `getvar:is-userspace`, `getvar:current-slot`, `getvar:slot-count`, and `flashing get_unlock_ability`.

This means **denial of `flashing get_unlock_ability` is a COMMAND GATE refusal**, *not* an unlock permission value of `0`, and *not* a Keymaster write-denial result.

The following also appear in allowlist, but have NOT been invoked on device in this analysis:
`flashing unlock`, `flashing lock`, `oem unlock`, `oem relock`,
`flash:slock`, `flash:slockv1`, `oem frp-unlock`, `getvar:vendorcountry`,
`getvar:max-download-size`, `getvar:devicemodel`,
`oem get-build-number`, `oem get-product-model`.
**Allowed at dispatcher is not equivalent to effective success or existence of a registered handler**. The `oem unlock` string appears in the allowlist but was not found in the examined active Fastboot handler table by an earlier registered-prefix scan; avoid assuming it is functional. Several entries are sensitive, destructive, or require proprietary signed service credentials — do NOT use as diagnostic commands.

## Why prior reset-without-unlock is plausible

The user's prior attempt at `fastboot flashing unlock` reportedly wiped data but bootloader remained locked. This command is on the restricted-mode allowlist **and** has an actual registered handler pointing to `0x25c04` then `0x27850`. Therefore a request may legitimately proceed beyond the command filter, initiate a confirmation/reset, but fail to persist secure-state transition after a later policy check. **The prior unlock response transcript is not available**, so it remains uncertain whether the device-state write was attempted and rejected, or whether the data reset happened earlier in the protocol.

Board and EEA firmware share VerifiedBootDxe executable code exactly, and their Keymaster READ/WRITE/MILESTONE routines have practically equivalent decompiled logic. None of those differences confirms a permanent unlock exploit.

## Read-only research next
- Map all callers of `FUN_00013608` and device context `+0x104` to identify the meaning of the command access condition.
- Reconstruct service credential verification in `flash:slock` / `flash:slockv1` / `oem hwdog certify`, but do NOT run token/erase/unlock service commands.
- If further handset evidence is required, test only whitelisted **nonmutating** commands such as `fastboot getvar vendorcountry` and `fastboot getvar devicemodel`, with privacy filtering; not necessary to prove gate existence.
- Focus on old `flashing unlock` response failure and verified persistent state; avoid retrying a data-destructive procedure just to reproduce it.

## Security and recovery
Never execute `flash:slock`, `oem frp-unlock`, `oem unlock`, `fastboot flashing unlock`, `fastboot erase`, `fastboot flash`, `download_for_7325_v1.0.bat`, Board `rawprogram*.xml` or `fh_loader --erase` as a 'read-only test'. The user can work entirely with original firmware on GitHub for the next reverse-engineering steps.
