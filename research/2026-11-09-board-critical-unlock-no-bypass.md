# 2026-11-09 — Chinese Board FNE-AN00 vs EEA FNE-NX9: critical unlock and AVB cross-check

**Scope:** Offline static analysis of user's uploaded original `Honor_70_FNE-AN00_1.0.0.34_220721_HMT.zip` and corresponding stock EEA FNE-N29 8.0.0.290(C431E4R3P1) firmware. **No tested bootloader unlock, flashing, EDL operation or writes to the user's handset.**

## 1. Actual registered Fastboot `unlock_critical`

The Chinese Board `LinuxLoader.efi` has a genuine command registry entry `flashing unlock_critical` at table RVA `0xb1dd0`, pointing to ARM64 code `0x23b9c`:

```asm
0x23b84 mov w0, wzr      // normal scope
0x23b88 mov w1, #1       // unlock request
0x23b8c b   #0x25f14

0x23b90 mov w0, wzr      // normal scope
0x23b94 mov w1, wzr      // lock request
0x23b98 b   #0x25f14

0x23b9c mov w0, #1       // critical partition scope
0x23ba0 mov w1, #1       // unlock request
0x23ba4 b   #0x25f14

0x23ba8 mov w0, #1       // critical partition scope
0x23bac mov w1, wzr      // lock request
0x23bb0 b   #0x25f14
```

These four commands jump to the **same common handler** at Board `0x25f14`. They are distinct lock/critical-lock requests, **not an alternate bypass of the FRP/unlock permission**. The comparable retail handler is `0x27850`. Ghidra decompilation of each shows a permission gate, error string `Flashing Unlock is not allowed`, and transition via the device-state protocol. Source: [handler registry ARM64](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42607900947), [side-by-side full handler decompilation](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42616465352).

**Interpretation caveat:** Some Ghidra decompiled variable assignments show uninitialized registers and impossible branches, because function signatures/calling conventions are not restored. The raw branch register assignments above are unambiguous; do not infer exploitability from Ghidra artifacts.

## 2. Board's actual secure backend is NOT an unlocked development Keymaster

- `VerifiedBootDxe` PE32 code section (`.text`, RVA `0x1000`, 49,152 bytes) has **the exact same SHA-256** `201e99c3edcd4b70969c35fabd060a9e2629e134677e8bc2a1de5640391e6e39` in Board and EEA. `.data` differs in 237 bytes and is **not** proof of changed policy. Source: [exact PE section hashes](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42607301965).
- Decompiled Keymaster `km41.mbn` `READ_KM_DEVICE_STATE`, milestone-fuse checker, milestone setter, and per-command eligibility check show the **same normalized Ghidra logic** in both builds (similarity 1.0). Write handler similarity is **0.9979**. This is evidence of equivalent protections in compared routines, not evidence of complete file identity. Source: [normalized Board vs EEA secure semantics](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42605644738).
- Both have the milestone soft-fuse check in read and write; no evidence that Board BDs automatically remove that lock. We do not know the live value of the fuse.
- Both ABL and XBL files carry overlapping HONOR/Qualcomm cert public keys. An identical embedded certificate key does **not** establish image signature validity on the current device or that older firmware passes rollback and hardware policy. Source: [certificate audit](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42607030631).

## 3. Board GPT differs in a destructive way

All 6 UFS GPT regions were parsed with primary table CRC verification. Five regions have the same named-partition extents; LUN 0 differs:

| Region | EEA stock start/end LBAs | Board start/end LBAs |
|---|---|---|
| `super` | `829440..3209215` | `829440..2799615` |
| `flash_ageing` | absent | `2799616..2930687` |
| `userdata` | `3209216..3209215` (placeholder in stock update GPT) | `2930688..2930687` (placeholder) |

The apparent inverted `userdata` range is a **zero-length placeholder in the firmware GPT**; do not interpret it as a real on-device userdata size. The `super` partition is **409,600 sectors (1.5625 GiB) smaller** in Board vs stock. Flashing the Board GPT as-is would change partition mapping and is not an approved solution. Source: [6-LUN GPT layout comparison](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42606351625).

The factory `download_for_7325_v1.0.bat` includes full UFS operations (including `fh_loader --erase=0..5` and writes to GPT, bootloader stages and factory images). **Do not execute it on the EEA device**, even though it ships in the Board ZIP. Source: [Board factory script audit](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42606015357).

## 4. `patch_avb.img` is NOT a confirmed bootloader-unlock patch

- Original `patch_avb.img` SHA256 `960dfa5b9dc563cc60a648632d86344cb9d0cfc1299b6e8e4908e92edc71d7d6`.
- Android sparse image 2,158,740 bytes -> 134,217,728 bytes (128 MiB) raw ext4 volume label `patch_hn`.
- Root ext4 contents: only `lost+found`. An AVB footer / `avbtool 1.2.0` metadata near end of raw image.
- It is an ordinary signed/AVB-formatted partition image, **not evidence of a patch that turns off AVB or unlocks the device**.
Source: [raw sparse image inspection](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42616995892).

## What remains actually unproven

1. Whether the user's device accepts the Board signed ABL/XBL/Firehose programmer in EDL while boot chain is locked, and whether antirollback policy blocks it.
2. Whether Qualcomm SCM state on their specific handset selects RPMB/Keymaster or direct `devinfo` backend (stock default strongly suggests secure path but is not directly measured).
3. Whether the FRP last-byte is read as 1 by ABL; `sys.oem_unlock_allowed=1` is supportive but not definitive.
4. Why previously attempted `fastboot flashing unlock` did not produce persistent unlocked state even after a wipe; the actual live Fastboot failure/success console log was not fully captured here.
5. Whether a **validated service tool with official device-specific procedure** can complete persistent unlock; generic FRP flashing logs do not show this.

**Do not infer that bootloader unlock is possible simply by loading a Board image, toggling `unlock_critical`, flashing `patch_avb.img` or rewriting GPT/OEMINFO/FRP/devinfo.** The above results eliminate those as *proved* paths and narrow the next useful evidence to signed-programmer acceptance, accurate active firmware version, and the read-only runtime failure code during an authorized unlock attempt.

## Primary reproducible research evidence

- [Board registered handlers](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42607900947)
- [Board vs EEA common unlock handler Ghidra decompilation](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42616465352)
- [Keymaster and VerifiedBootDxe semantic comparison](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42605644738)
- [Signed-bootchain comparison](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42607030631)
- [GPT layout and factory script](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42606351625)
- [AVB patch filesystem audit](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42616995892)
