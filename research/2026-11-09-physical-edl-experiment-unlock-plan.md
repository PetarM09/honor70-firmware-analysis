# HONOR 70 FNE-NX9 — physical EDL experiment and permanent-unlock feasibility (9 Nov 2026)

**Scope:** User explicitly authorizes irreversible firmware writes on their own test device. Exact target: FNE-NX9 EEA, FNE-N29 8.0.0.290(C431E4R3P1), Qualcomm SM7325. This note is research, not evidence of successful unlock. **No physical device or EDL session was available to the analyst; nothing was flashed in this session.**

## Executive status

- The real FNE-NX9 remains **LOCKED** according to user's live Fastboot report. Android has `sys.oem_unlock_allowed=1`, while `ro.boot.flash.locked=1` and AVB remains green.
- The 49-command locked Fastboot allowlist is real, but **`flashing unlock` itself is already allowlisted**; merely removing the command filter does not modify Keymaster state.
- Signed Board `LinuxLoader.efi` and EEA ABL both retain FRP checks; Board `VerifiedBootDxe` executable code is identical to retail and Keymaster read/write/milestone guards are nearly identical.
- No independently verified permanent bootloader unlock has been reproduced.

## New signed EEA ABL evidence: OEMINFO record 130 is an R&D service authorization check

Exact original LinuxLoader SHA256: `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`. At `FUN_00012cf8`:

```c
iVar3 = FUN_000136a4(0x82, auStack_228, 0x100); // read OEMINFO entry 130
if (iVar3 >= 0) {
   if (FUN_0001bf74() == 2)
      result = FUN_00015690(auStack_228,0x100);
   else
      result = FUN_0001a7b0(/* signed data request */);
}
```

`FUN_0001a7b0` contains `data_set_SHA256_RSA_check` verification; `FUN_00015690` recognizes `fastboot flash:rdmodev1` and `0XEED6030008`. Its return is incorporated into `FUN_00012e90`, which initializes `[FastbootContext + 0x104]`, gate checked by `FUN_000134c0`. The field appears to represent a signed R&D/service state, not a verified direct Keymaster unlock flag.

**Crucial:** Writing an arbitrary value to OEMINFO 130 is therefore not a supported bypass; its authorization data is checked by cryptographic routines. See [exact compiled signed-EEA decompilation](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42628585348) and [Ghidra source](https://github.com/PetarM09/honor70-firmware-analysis/blob/main/tools/ghidra/Honor70OEMInfoFastbootStateProvenance.java).

## Board OEMINFO image inspection

A verified reconstruction of the author's original 2.57 GB FNE-AN00 HMT Board release produced one `Firmware/fastbootimage/oeminfo.mbn`, **100,663,296 bytes**, SHA256 `0820a084897b34dfda0e9953c409f1e9b5cc6b3431a20d0dcd906128505e5d12`. It is ~99.8% zero bytes. Searches found zero ASCII occurrences of the service markers `rdmod`, `certify`, `RSA`, `fastboot flash:rdmodev1` or `0XEED6030008`. Four accidental or possible occurrences of the little-endian integer 130 are not sector aligned and do not establish a usable, signed service token.

**No evidence this Board OEMINFO contains a compatible signed R&D unlock credential.** Direct full-image flashing onto the EEA device may destroy device-specific provisioning and has no supported unlock rationale.

[Verified read-only Board OEMINFO structure audit](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42630412253).

## Possible EDL loader and signing evidence

Original HMT Board Firehose ELF binaries:

| Loader | SHA256 | Size |
|---|---|---:|
| prog_firehose_ddr.elf | `9c892e716320764c20055d8374bf8eca7418b3ff2177f81794e18d3656fc55a8` | 954,208 |
| prog_firehose_lite.elf | `e029df6e2d532de87c2279e960472ec0e4799aca53bc27ed4fa3e4027b05d101` | 954,208 |

Each contains six public-certificate keys that match all six keys found embedded in the EEA XBL; each overlaps with three Honor keys in the EEA ABL. **Embedded public-key identity is not Sahara acceptance or evidence of antirollback compatibility.** The two Firehose files have different executable code; do not swap arbitrarily.

[Certificate evidence](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42607435669), [DDR/lite executable diff](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42618766739).

A lightweight **5.7 MB** archived original signed Board subset, containing both original Firehose ELF binaries, is already on GitHub:
[HONOR70_FNE_AN00_BOARD_SIGNED_BOOTCHAIN artifact](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42553239190/artifacts/13646301497).

## Most actionable physical experiment — gated and reproducible

A tested offline Python harness `honor70_edl_lab.py` is available to the user as `HONOR70_EDL_LAB.zip` in the ChatGPT conversation. It wraps the documented [bkerler/edl](https://github.com/bkerler/edl) command interface and has separate:

- `inspect`: tries the unmodified signed programmer against an actual Qualcomm EDL 9008 device; sends `edl printgpt --memory=ufs --loader=...`; requires real UFS partitions `frp`, `oeminfo`, `devinfo`, `abl_a`, `xbl_a`. Does not send write.
- `backup`: reads selected physical partitions, checks nonempty outputs and hashes them, preserves original partition images locally and privately. The back-up does not guarantee post-brick recovery.
- `flash`: a **real** Firehose `w` path, but only after a known existing partition, nonempty local backup, matching old hash, matching new-image hash, same-size prewrite live comparison, and two explicit irreversible-write flags. Default is dry-run and cannot write. This operation must never be invoked with an arbitrary image; an EDL tool's write success does not indicate the device will boot.

The harness was syntax-checked and tested with a fake EDL executable for inspect, backup, dry-run, and gated write. **No physical phone EDL behavior was tested.**

The package also contains `inspect_devinfo_backup.py`, a read-only local inspector checking for `ANDROID-BOOT!` at partition start and reporting candidate lock-flag offsets, without patching or exposing raw data.

### If the Firehose accepts

1. Verify actual partition layout, create backups and keep private `frp`, `oeminfo`, `devinfo` / calibration binaries.
2. Inspect the local `devinfo` backup to see whether it uses the expected DeviceInfo magic, and reconcile structure layout with the exact original EEA VerifiedBootDxe/ABL. **Do not blindly use offsets from generic tools**; bkerler's generic Qualcomm module uses offsets `0x10`/`0x18` on some devices, while the EEA ABL sets two offsets `+0xD`/`+0xE` in an in-memory state structure passed to `VBRwDevice`. This does **not** prove identical offsets in the physical UFS devinfo partition.
3. Only if a valid direct-`devinfo` backend and exact state structure are confirmed would a one-partition reversible write experiment be meaningful. If the real handset uses Keymaster/RPMB, patching ordinary `devinfo` will not unlock its secure state.
4. Any final success must be observed after independent power cycles as Fastboot `UNLOCKED` and Android AVB `orange`/unlocked. A destructive reset is not evidence of success.

## Why direct recompilation and flashing of modified ABL is not the next experiment

Both signed ABL and XBL are Qualcomm/Honor signature controlled. Modified/recompiled ABL won't pass secure boot solely because it has the same format or model string. An EDL programmer may accept generic UFS writes while PBL/XBL later reject a patched ABL signature or rollback version. Board ABL and Keymaster already retain the relevant secure guards. In contrast, verifying a device-compatible Firehose and the actual state storage route produces the first decision-quality evidence for a real flash attempt.

## Remaining proof gaps

- Does the physical FNE-NX9 accept either FNE-AN00 signed programmer via Sahara?
- What are the actual on-device SCM security-state bits selecting RPMB vs direct devinfo?
- Is a valid OEM-signed R&D/SLOCK service credential available for the exact model?
- Does a backed-up `devinfo` show correct magic/fields and is it the active persistence backend?
- Can a true permanent state transition occur without defeating milestone checks?

**No claim of a working exploit/unlock is warranted as of this report.**
