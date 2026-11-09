# HONOR 70 FNE-NX9 — service slock versus Chinese Board, after live Fastboot allowlist analysis

**Date:** 2026-11-09. **Target:** stock EEA FNE-N29 8.0.0.290(C431E4R3P1), FNE-NX9 vs Chinese FNE-AN00 Board HMT 1.0.0.34. Original signed LinuxLoader modules, read-only reverse engineering. No phone changes made.

## Why we investigated `slock`

The live Mac Fastboot log showed `FAILED (remote: 'Command not allowed')` for generic `getvar` and `flashing get_unlock_ability`, but successful `oem get-bootinfo` and `oem lock-state info`. Static analysis proved these are consequences of a restricted-mode command whitelist of **49 strings**, starting at `0x1b41b0` in EEA ABL. Dispatcher `0x22c7c` calls command-permission gate `0x134c0`. See [live allowlist and decision tree report](https://github.com/PetarM09/honor70-firmware-analysis/blob/main/research/2026-11-09-live-fastboot-denied-allowlist-root-cause.md).

The allowlist has not only `flashing unlock` but also two special registered service protocols:
- `flash:slock`
- `flash:slockv1`

`oem unlock` is in the allowlist but NOT found in the investigated active Fastboot handler registration table; allowlisting a string is **not** proof of a working handler.

## Registered service handlers — actual signed EEA ABL

- `flash:slock` -> `0x14774`
- `flash:slockv1` -> `0x147dc`
- `oem hwdog certify enc begin` -> `0x14748`
- `oem hwdog certify close` -> `0x14888`
- `oem frp-unlock` -> `0x14568`, destructive/authenticated FRP operation, not a diagnostic.

From original ARM64:

```asm
; EEA slock v0
0x147a0 bl  #0x16a2c
0x147a4 cmp w0, #0x55
0x147a8 b.ne #0x147c4

; EEA slock v1
0x14808 bl  #0x16dd4
0x1480c cmp w0, #0x55
0x14810 b.ne #0x1482c
```

The tested `0x55` sentinel alone is **not** sufficient to infer the exact signature algorithm or protocol. However, the `0x16a2c` path's Ghidra output contains `verify_certify_encrypt_data`, `common_cmd_hwdog_certify_put`, `signature unused pss` and `memcmp plain str fail`, which are substantial evidence of a separate, certificate-based service authorization path, **not** a generic unlock toggle or proof of an exploitable flaw.

`oem frp-unlock` verification path `0x19d78` emits `FAILFRP KEY parse fail`, `FAILpassword matching failed`, `FAILdevice will reboot after 30S due to 5 times of wrong key`, `FAILfrp_unlock failed` and a successful branch mentioning a factory reset. Do **NOT** use this command to test anything.

Sources:
- [Ghidra string references, service functions and protected routes](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42623117765)
- [Actual signed EEA handler entrypoint ARM64 and Ghidra function body](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42623419084)

## Chinese Board comparison — no obvious service bypass in wrapper code

Matched original signed Board `LinuxLoader.efi` SHA256 `1b7cbcf021a929d4f0fc3deea0d5f0c6594ea1c6203da62d00dd4672f4651497` against EEA SHA256 `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`.

Service wrapper handler correspondence:

| Route | EEA RVA | Board RVA | Structural behavior |
|---|---|---|---|
| `flash:slock` | `0x14774` | `0x13650` | Calls service verification helper, compares result `w0` with `0x55`, branches on failure |
| `flash:slockv1` | `0x147dc` | `0x136b8` | Same general gate, separate v1 verification helper, compares result with `0x55` |
| `oem hwdog certify enc begin` | `0x14748` | `0x13624` | Similar certification handler wrapper |
| `oem hwdog certify close` | `0x14888` | `0x13764` | Similar close handler wrapper |

The signed Board code includes `verify_certify_encrypt_data`, `common_cmd_hwdog_certify_put` and `password_check` identifiers too. This strongly undercuts the simple hypothesis that Board's service handlers omit the authorization check, though **their exact downstream internals have not yet been proved semantically identical**.

Source: [Board vs EEA service wrapper comparison](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42623638345).

## Status and next research gate

**Confirmed**: EEA ABL locked-mode command whitelist explains all 9 failures and both OEM successes in Mac log; ordinary `flashing unlock` is on the allowed list and has a real handler. Board firmware's critical unlock only dispatches to common handler; the secure backend VerifiedBootDxe/Keymaster is not less restrictive. Slock service is a credential-verified mechanism in both Board and EEA.

**Unconfirmed**: whether the user's previous `flashing unlock` operation actually reached a protected Keymaster write; whether `frp` last-byte is `1` as read by the ABL; the live SCM security state / milestone fuse value; a reproducible **permanent** bootloader unlock.

Next decision should be based on authentic original prior `flashing unlock` transcript **if one exists**; do not repeat a data-wiping attempt solely for diagnosis. Continue offline by comparing v0/v1 service-verification helper routines and the Fastboot state gate's `+0x104` variable if necessary. A future, optionally read-only live test of `getvar:vendorcountry` / `getvar:devicemodel` can validate allowed-list behavior without unlocking, but provides little new evidence toward persistent lock write.

**Prohibited for our proposed diagnostic workflow:** Do NOT send `flash:slock`, `flash:slockv1`, `oem frp-unlock`, `oem unlock`, or `flashing unlock` as 'harmless probes'; do not flash Board GPT/ABL or run its bat.
