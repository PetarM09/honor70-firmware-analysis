# 2026-11-12 — What is required for an exact C431 GhostLock port

**Primary target:** own HONOR 70 FNE-NX9 C431 MagicOS 8.0.0.290, Android 14, exact kernel `5.4.295-qgki-ga2d8945339ca`.

## Exploit source inspected

- `MSEDGE-CORE/GhostLock-HonorFne/root/exploit/src/core/main.c` performs `uname()` exact string matching with its `known_offsets` table, and stops if no entry exists. Its provided FNE `offsets.h` contains `5.4.289` and multiple `5.4.295` releases but NOT `5.4.295-qgki-ga2d8945339ca`. Running the current binary on this C431 image therefore has no verified matching offset entry.
- The FNE upstream header comments call HONOR FNE-AN00 `SM8350`, whereas official HONOR 70 specifications say Snapdragon 778G Plus, and independent HONOR 70 datasheets identify SM7325-AE. Treat the SoC comment as an unsupported header label, NOT as reliable physical-memory evidence. This discrepancy alone doesn't prove the exploit is broken; it is another reason to require precise source-derived addresses.
- Exact signed C431 kernel source-level branches and `current->pi_blocked_on` are validated. The existing candidate profile still has **32 null fields** and a CI-runner physical memory address; it is unfit for direct execution.

## New actual porting preparation on `main`

- `tools/trace_fne_c431_ghostlock_symbols.py` validates exact original boot and Image SHA256; reconstructs symbol offsets from the recovered exact stock `vmlinux.elf` using `nm`; crosschecks the original `remove_waiter` anchor; marks missing or ambiguous named symbols instead of guessing them.
- `tools/test_trace_fne_c431_ghostlock_symbols.py` has 7 synthetic tests guarding wrong anchor, hashed names, ambiguity and missing fields.
- `.github/workflows/audit-fne-exact-proxy-rollback-instructions.yml` now invokes this tool to produce `ORIGINAL_EEA_GHOSTLOCK_SYMBOL_INVENTORY.json` with no device operations.
- The inventory is **not** a C `OFFSETS_ENTRY` ready to run. It does not infer struct layouts, pselect overlap geometry or the handset physical kernel load. Those are separate preconditions and cannot be substituted from an FNE-AN00 build.

## Sources for the remaining struct-layout task

The official HONOR Open Source Release Center accepts source-code downloads or requests. Search by FNE-NX9 first, or request the matching Linux kernel sources and build config for MagicOS 8.0.0.290 C431 EEA; a close upstream Qualcomm 5.4 tree is a comparison aid, **not proof of an exact match**.

- HONOR Open Source Release Center: https://www.honor.com/global/opensource/
- HONOR 70 official chipset: https://www.honor.com/pk/phones/honor-70/spec/
- FNE upstream offsets: https://github.com/MSEDGE-CORE/GhostLock-HonorFne/blob/main/root/exploit/src/devices/fne/offsets.h
- FNE upstream runtime selection: https://github.com/MSEDGE-CORE/GhostLock-HonorFne/blob/main/root/exploit/src/core/main.c

## Concrete user-side prerequisite already prepared

The real handset has reported `/proc/config.gz` readable. `tools/collect_fne_live_ikconfig_readonly.py` can read it without root and produce `HONOR70_LIVE_IKCONFIG_SUMMARY.json`. A successful copy verifies only build flags, **not** exploitability. No actual user result for that command has been received yet.

**Current state:** exact-firmware candidate bug with partial symbols; **no working EEA root exploit and no persistent bootloader unlock**.
