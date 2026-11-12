# 2026-11-12 — Byte-verified FNE-NX9 C431 DTB #13 + DTBO #18 patch reference audit

**Target device:** owner's HONOR 70 FNE-NX9 C431, MagicOS 8.0.0.290, signed kernel `5.4.295-qgki-ga2d8945339ca`.

**Why this exact pair:** the real phone reported `ro.boot.dtb_idx=13`, `ro.boot.dtbo_idx=18`, `ro.board.boardid=8790`, and `ro.board.hardware_version=HN2FNEM03_VA`. The uploaded `vendor_boot_a.img` base entry #13 is the Yupik SoC FDT. The uploaded `dtbo_a.img` entry #18 is `Honor Technologies, Inc. FNE-NX9-781-208` with `qcom,board-id=0x2256=8790`. Another same-model entry #25 has board-ID 8780 and is not the indicated one.

## New original-byte evidence

The offline auditor [`tools/audit_fne_c431_selected_fdt_overlay.py`](../tools/audit_fne_c431_selected_fdt_overlay.py) was run against the **actual extracted FDT binaries**, not only the earlier JSON metadata, inside `HONOR70_C431_NX9_DTB_REFERENCE_SET.zip`.

| Fact | Exact observed result |
|---|---|
| Base DTB #13 SHA-256 | `bc692b769082c3db077864b82b6410b0d8ca93c0ce6985f9a5adedfb8b9854e9` |
| Overlay DTBO #18 SHA-256 | `c278a52783cc0c4093f79772dd9f1036d38135098deb56159150da3f82c985cc` |
| Parsed base FDT nodes | **3,323** |
| Parsed overlay FDT nodes | **1,092** |
| Base `/__symbols__` entries with valid target paths | **1,574** |
| Overlay `/__fixups__` symbol names found in base | **165 / 165** |
| External property patch-site offsets within bounds | **468 / 468** |
| Overlay `/fragment@N` target declarations resolved in base | **137 / 137** |
| Overlay `/__local_fixups__` node paths | **207** |
| Local phandle patch-site offsets within bounds | **262 / 262** |
| Fragments targeting `/memory` | **0** |
| Fragments targeting `/reserved-memory` | **1** |

The base FDT contains a large `/__symbols__` table, and **all** external overlay references resolve to valid base symbol paths. Each of the **137** overlay fragments has exactly one valid target. All 468 external and 262 local patch-site offsets are in bounds, for **730 validated patch positions**. These validations establish **static reference compatibility of this selected pair**, not successful application by `libfdt` or a verified live merged tree.

### Reserved memory is not evidence of live kernel physical loading

The one fragment targeting `/reserved-memory`, `/fragment@130`, adds/overrides `removed_region@c0000000` with the **same** `reg` and `no-map` properties already present in the base tree. Its phandle value differs, as expected for a relocatable overlay, but those memory properties are unchanged.

The base `/reserved-memory/hyp@80000000` reserves **start `0x80000000`, length `0x600000`**. The base `/memory/reg` remains the placeholder `start=0, size=0`. None of the 137 fragments directly targets `/memory`.

Therefore this offline pair **cannot justify a runtime `kernel_phys_load`, a live DRAM map or KASLR slide**. In particular, `0x80080000` lies inside the hypervisor-reserved region and must not be assigned as the kernel load address merely because it matches a generic ARM64 example.

## Reproducible checks and scope

- [Local byte-based auditor](../tools/audit_fne_c431_selected_fdt_overlay.py): `python3 tools/audit_fne_c431_selected_fdt_overlay.py --reference-zip HONOR70_C431_NX9_DTB_REFERENCE_SET.zip --out selected-fdt-report.json`. Uses Python 3 standard library only.
- [10 synthetic positive/negative parser tests](../tools/test_audit_fne_c431_selected_fdt_overlay.py): [successful CI 43327066196](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43327066196).
- [SHA-pinned, original-byte-derived FDT fixup evidence manifest](../profiles/evidence/fne-nx9-c431-dtb13-dtbo18-fixup-integrity-2026-11-12.json).
- [Experimental research profile v0.6](../profiles/fne-nx9-c431-8.0.0.290.profile-v0.6.json): keeps the previous 10 confirmed ARM64 struct offsets and all 10 unresolved fields set to JSON `null`. The exact overlay reference status is recorded separately from runtime kernel state.
- [8 profile-evidence provenance checks](../tools/test_verify_c431_profile_v06_selected_overlay_fixups.py): [successful CI 43327395660](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43327395660).

**CI evidence boundary:** the parser CI runs **synthetic FDT fixtures** (including intentionally corrupted fixups), and the v0.6 CI checks the committed original-byte-derived manifest. The original extracted binary files were audited **locally** as user uploads; they were **not** reconstructed and rehashed independently on the GitHub Actions runner. The SHA digests record exactly which original bytes were analyzed.

**Not yet done or proved:** actual `fdtoverlay` application using libfdt with local/external phandle relocation, comparison to live partition bytes, bootloader-selected live FDT, dynamic `kernel_phys_load`, actual kernel slide, a triggered GhostLock UAF, a controlled memory primitive, temporary root or persistent unlock. This update performs **zero EDL writes, phone operations, kernel writes, UAF races or root attempts**.

## What is technically worth doing next?

The selected Device Tree hardware-identity question has been answered as far as public properties and uploaded bytes permit. Repeated readings of `ro.boot.dtb_idx` and `ro.board.boardid` will not recover the ten missing GhostLock runtime or struct fields. A genuinely new proof would need **actual signed-original ARM64 instruction sites** for remaining struct fields or original-build debug metadata, and for dynamic memory values a valid independent runtime measurement. Source-level or DTB guesses must remain separated from original C431 facts.
