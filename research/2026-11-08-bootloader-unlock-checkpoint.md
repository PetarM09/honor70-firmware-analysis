# HONOR 70 FNE-NX9 — Static research checkpoint

Date: 2026-11-08
Target: FNE-N29 8.0.0.290(C431E4R3P1), model FNE-NX9 (HNFNE), Android 14.
Research goal: determine whether there is a **verifiable, non-destructive bootloader unlocking method**.
**No unlock procedure has been validated.** These are static research notes.

## Matching firmware and live kernel

The user's latest read-only ADB inventory reports:

- Linux release: `5.4.295-qgki-ga2d8945339ca`.
- Vendor hardware: `qcom`.
- OEMINFO by-name symlink: `/dev/block/by-name/oeminfo -> /dev/block/sda9` (**do not read/write partition unless appropriately authorized, do not publicly upload partition contents**).
- `/proc/config.gz` exists and is readable.
- `CONFIG_FUTEX=y`, `CONFIG_RT_MUTEXES=y`, `CONFIG_KALLSYMS=y`, `CONFIG_RANDOMIZE_BASE=y`.
- `/sys/kernel/btf/vmlinux` absent; `/proc/iomem` returns Permission denied.
- `ro.boot.flash.locked=1`, `ro.boot.verifiedbootstate=green`, vbmeta device state `locked`, SELinux enforcing.

The kernel release matches the extracted stock kernel from the published 8.0.0.290 firmware. No live-device kernel exploit has been executed or validated.

## Verified binary hashes

- Decompressed LinuxLoader EFI: `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`.
- Kernel from boot image: `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`.
- Vendor libBootloaderOeminfo.so: `704e984bcbe85acbe89986f107646ba3614d731c4ad4191657a07eee85a8b266`.

## Confirmed static ABL findings

- `flashing unlock` handler at `0x25c04` and `flashing lock` handler at `0x25c0c` route to common unlock decision function at `0x27850`.
- `flashing get_unlock_ability` handler is present at `0x25b88`.
- Both query and unlock denial branch read a 32-bit field at relative address `0x1cdfd8`: instructions `0x25bcc` and `0x278c8`.
- [ABL permission scan](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42532487326) tracked 24 locations referring to the broader `0x1cdfc8` static structure. It recorded reads of `0x1cdfd8` and direct stores to *other* fields, but **did not identify a direct store** to `0x1cdfd8`. This is NOT evidence that the field is immutable; indirect writes, initializers and copies are unexamined.
- [ABL initialisation disassembly](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42532663183) is available to trace the full bootloader state initialization.
- An ABL OEMINFO reader uses logical record `0x82` (130), while the vendor anti-theft library's bootloader lock accessor reads/writes record `0x5f` (95). No identity/mapping between them is established.

## Kernel vulnerability research status

- [Recovered kernel symbols and RT mutex disassembly](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42529867841) show a potentially vulnerable `remove_waiter()` pattern consistent with a described GhostLock primitive.
- [GhostLock extractor](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42530618542) reported `CVE-2026-43499 primitive present` when given recovered kallsyms.
- The extracted profile is NOT usable: absent BTF and missing `task_struct`, credential and `rt_mutex_waiter` field offsets; its `kernel_phys_load` and `kernel_phys_offset` values are contaminated by the **GitHub runner's** /proc/iomem, not the phone.
- No device exploit has been run and no root access established.

## Safety and next steps

1. Keep entire analysis read-only; do not flash modified ABL/XBL/boot/vbmeta or change OEMINFO just to test a hypothesis.
2. Continue reverse-engineering initialization of `0x1cdfd8`, identifying relevant privilege/signature checks.
3. Investigate exact source/debug information for FNE-NX9 kernel. No BTF available from device.
4. Do not copy guessed physical addresses or kernel struct offsets from other devices; a wrong exploit profile may corrupt memory.
5. Only ask the user for live ADB/fastboot commands when an exact, targeted unknown cannot be resolved from the firmware itself.
