# HONOR 70 FNE-NX9 — ranking official HONOR GPL source packages (2026-11-12)

The user located these **literal listing names** on the HONOR Open Source Release Center:

1. `MagicOS8.0-ROM-Fennie_MagicOS8.0_Opensource` — listed for `荣耀70,HONOR 70`.
2. `FNE-AN00_MagicUI6.1_Code_Opensource` — listed for `荣耀70`.
3. `MagicOS8.0-ROM-Robin-Oversea_MagicOS8.0_Opensource` — listed for HONOR 70 Lite, HONOR X8a 5G, HONOR X6 5G.
4. Mark5G/Mark4G, Nala-AN00, Labu4G, LGN-AN00, BRP-NX series — other devices and/or MagicOS 9/10.

**Highest priority** is Fennie MagicOS 8 because it is the only *user-confirmed listing* matching both the HONOR 70 model family and the MagicOS 8 generation. FNE-AN00 MagicUI 6.1 is a secondary cross-version source reference. Robin and other entries are not expected to match the target device.

The target handset is **FNE-NX9 C431**, MagicOS **8.0.0.290**, kernel `5.4.295-qgki-ga2d8945339ca`. **An archive listing name does not prove that this exact firmware revision or kernel commit is included.** The official catalog is dynamic; no verified direct download URL was retrieved. Do not invent one.

## Next step

Download the Fennie entry from the official portal: https://www.honor.com/global/opensource/detail.html

The user may run this offline package inventory on macOS without extracting the archive:

```bash
cd "$HOME/honor70-firmware-analysis"
git pull --ff-only origin main
python3 tools/inventory_honor_opensource_archive.py \
  "$HOME/Downloads/ACTUAL_FENNIE_ARCHIVE_FILENAME.zip" \
  --out "$HOME/Downloads/HONOR70_FENNIE_SOURCE_INVENTORY.json"
```

Replace the ZIP argument with the exact downloaded file path, including extension. ZIP and tar-format packages work. A nested ZIP/tar is reported without opening; a 7z/RAR package is not supported by this tool.

The JSON inventory lists `kernel/locking/rtmutex.c`, `kernel/futex.c`, `include/linux/rtmutex.h`, `include/linux/sched.h`, defconfigs, Kbuild files, device trees and nested archives when present in the **outer** archive. It does not send or execute data from the archive or touch the phone. No source compatibility claims are made until real sources and configuration are checked against the SHA-pinned original C431 kernel.

## GhostLock research implications

If Fennie contains relevant kernel sources, compare the original `rtmutex` and `futex` implementation, target config and type definitions with the original source-hash verified EEA kernel disassembly. This is useful for understanding the reported CVE-2026-43499 candidate and resolving static ambiguities. It does not automatically produce a usable root exploit, kernel physical address, or bootloader unlock.

Official portal information: https://www.honor.com/global/opensource1/
