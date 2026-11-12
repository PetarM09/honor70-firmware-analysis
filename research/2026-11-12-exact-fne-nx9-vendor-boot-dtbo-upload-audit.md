# 2026-11-12 — Uploaded real FNE-NX9 vendor_boot v3 and DTBO tables

**Input:** User-uploaded `vendor_boot_a.img` (96 MiB, SHA-256 `ca0ef34c45c55e91bd8da2bf02a0c5d9f359feb5e5d7873ee2aab1f61d903f46`) and `dtbo_a.img` (24 MiB, SHA-256 `ecb2e289d49b6e51f89c0e4a16233521bc87a38c16c36753faa8a4a2fddca328`). Both were inspected **offline**, no phone or EDL operation. Their contents have not independently been authenticated against a trusted factory-signed vendor_boot / DTBO reference.

## Confirmed file structure

| Property | Source-proven result |
|---|---|
| Vendor boot container | `VNDRBOOT`, header version **3**, header size **2112**, page size **4096** |
| Header raw `kernel_addr` | **`0x8000`** — declared header field, **not** proof of the actual live kernel load |
| Header raw `ramdisk_addr` | `0x1000000` |
| Header raw `dtb_addr` | `0x1f00000` |
| Vendor ramdisk bytes | **34,656,434** |
| DTB region file offset | **34,664,448** (`0x210f000`) |
| DTB region bytes | **8,372,423** |
| DTB region SHA-256 | `f743cd276035b69d4ab19b1bbeb3784c9f682c4b2618f51fc651ee698fe0eb58` |
| Consecutive FDTs in DTB region | **18** — **17 full SoC trees** and one tiny 173-byte FDT |
| DTBO table | Magic **`0xd7b7ab1e`**, table size **9,203,281** bytes |
| DTBO entries | **29**, all structurally valid, each includes an in-range FDT |
| HONOR FNE-NX9 overlays | **10 entries**, **9 distinct model labels** |
| Active overlay currently selected by phone | **Not established** |

## Actual FNE-NX9 overlays in DTBO

The 10 confirmed entries are:

| DTBO index | Embedded HONOR model |
|---:|---|
| 1 | `FNE-NX9-781-205` |
| 5 | `FNE-NX9-781-203` |
| 6 | `FNE-NX9-781-202` |
| 11 | `FNE-NX9-781-207` |
| 14 | `FNE-NX9-781-200` |
| 18 | `FNE-NX9-781-208` |
| 20 | `FNE-NX9-781-206` |
| 24 | `FNE-NX9-781-204` |
| 25 | `FNE-NX9-781-208` (different binary from #18) |
| 27 | `FNE-NX9-781-201` |

Each carries compatible strings including `qcom,yupik-qrd` and `qcom,yupik`. Thus the uploaded images contain genuine-looking **device-specific FNE-NX9** declarations, but they do not identify the active hardware revision on the particular handset.

## SoC base DTB and RAM assumptions

The vendor_boot FDT region contains `qcom,yupik` primary trees at **indices 11 and 13**. Their static `/memory/reg` property is **start 0x0, size 0x0**. This is a placeholder, not a live DRAM measurement; bootloader fixes or applies memory layout at runtime.

Both relevant `qcom,yupik` base device trees contain a reserved hypervisor node `/reserved-memory/hyp@80000000`, `reg` start **`0x80000000`**, size **`0x600000`**. The previously suggested generic `kernel_phys_load=0x80080000` lies **inside** that reserved region. **Do not adopt the guessed 0x80080000 base** as a verified or safe value.

Android AOSP [vendor_boot header v3 format](https://source.android.com/docs/core/architecture/partitions/vendor-boot-partitions) defines `kernel_addr` and `dtb_addr` as load-address fields. Here the raw `kernel_addr` is `0x8000`, and its presence is *not* a measurement of final bootloader-adjusted kernel placement. Actual loaded physical address and KASLR virtual slide remain **unverified**.

## Next read-only diagnostic on the same physical phone

If Android's file permissions permit, these three commands can identify the active Device Tree model and memory `reg` without rooting or modifying the phone:

```sh
adb exec-out cat /proc/device-tree/model | tr -d '\\000'; echo
adb exec-out cat /proc/device-tree/compatible | tr '\\000' '\\n'
adb exec-out cat /proc/device-tree/memory/reg | xxd -g 4
```

A permission error is expected on some Android builds; do not bypass it. Reading `memory/reg` yields the live *RAM map*, not a definitive kernel load address. Do not disclose hardware serial IDs.

## Status of original C431 GhostLock profile

**Newly confirmed:** valid vendor_boot v3, real DTB region, HONOR FNE-NX9 hardware overlay families and reserved-memory constraints. **Not confirmed:** currently active overlay, live `kernel_phys_load`, KASLR, remaining missing kernel struct offsets, writable UAF, or temporary root. Do not transfer generic offsets or call this a working root profile.

The full source-file SHA-256 inventory, decoded memory regions and all 29 overlays are preserved in the local JSON report made from the two user-provided files. A reference ZIP contains the 10 exact NX9 overlays and two `qcom,yupik` base FDTs; their unchanged bytes have been SHA-256 indexed.

**No kernel exploitation or device writes were performed.**

## Owner's non-root live DTB read attempt (2026-11-12)

The owner executed the recommended read-only commands from the macOS host:

```sh
adb exec-out cat /proc/device-tree/model
adb exec-out cat /proc/device-tree/compatible
adb exec-out cat /proc/device-tree/memory/reg
```

**All three failed with `cat: ... Permission denied`.** The apparent hex from piping the final error through `xxd -g 4` is simply the ASCII bytes of the error text (`63 61 74 3a` = `cat:`), **not** a device memory map. No active DTBO index, selected hardware revision, DTB memory range, bootloader physical load, or root state was discovered by this attempt.

This is normal for a restricted Android `shell` context and does not establish that the stored FNE-NX9 overlays are invalid. Do not retry with kernel privilege bypass, and do not interpret the error bytes as hardware addresses.

Next read-only fallback for the **specific remaining active-overlay identification question**, from the host:

```sh
adb shell getprop | grep -Ei 'board|hwrev|hwid|hardware|dtbo|dtb|sku|revision|project'
```

If present, hardware/bootloader properties may help identify the overlay family; even a `ro.boot.dtbo_idx` value, when available, needs comparison against the image's actual table and selection rules. A result is **not** proof of runtime physical load or kernel credentials. Redact serial numbers or other personal identifiers before sharing raw property output. No device operation was performed in committing this observation.

## Owner's live boot-selection properties — DTB #13 + DTBO #18 (2026-11-12)

The owner supplied non-root `adb shell getprop` results after the original `/proc/device-tree` reads failed with `Permission denied`. These *bootloader-supplied Android property strings* are direct on-device observations:

```text
ro.boot.dtb_idx=13
ro.boot.dtbo_idx=18
ro.board.boardid=8790
ro.board.hardware_version=HN2FNEM03_VA
ro.board.platform=lahaina
ro.boot.product.hardware.sku=FNE-N29
ro.boot.product.vendor.sku=yupik
ro.product.hardwareversion=HN2FNEM02
```

Using the unchanged user-uploaded image files, the selected indices were rechecked **directly against the original FDT bytes and SHA-256**, not merely a prose label:

| Bootloader property | Entry in uploaded image | Exact FDT SHA-256 | Model |
|---|---|---|---|
| `ro.boot.dtb_idx=13` | `vendor_boot_a.img` base DTB index **13** | `bc692b769082c3db077864b82b6410b0d8ca93c0ce6985f9a5adedfb8b9854e9` | `Qualcomm Technologies, Inc. Yupik SoC` — `qcom,yupik` |
| `ro.boot.dtbo_idx=18` | `dtbo_a.img` overlay index **18** | `c278a52783cc0c4093f79772dd9f1036d38135098deb56159150da3f82c985cc` | `Honor Technologies, Inc. FNE-NX9-781-208` |

**Stronger independent selector proof:** the selected DTBO #18 root `qcom,board-id` has first 32-bit big-endian cell **`0x2256` = decimal `8790`**, *exactly matching the phone's `ro.board.boardid`*. The same overlay's `hardware_version` property is **`HN2FNEM03_VA`**, also matching the reported value, and its board-name field is `FNE_NX9_LV_VA_SCP`.

An **alternative** overlay at index **25** also has the model label `FNE-NX9-781-208`, but it is a distinct FDT (SHA-256 `9945c3106547e82fb18cb91c9d09c2cbcee9a7ace7445cc0209aabb3beeb33a4`) and its first `qcom,board-id` cell is **`0x224c` = decimal `8780`**, which **does not match** the phone. Its board-name is `FNE_NX9_LV_VA`. Thus both the index and the independent board-id select **entry #18, not #25**.

The two reported hardware strings `HN2FNEM03_VA` and `HN2FNEM02` are distinct system properties and may describe different aspects of the hardware or product build; this observation alone does not imply corruption or force them to be equal.

### Scope boundary

The chosen indices match the file order of **the images the user uploaded**, and the SHA-256 checks validate each extracted FDT within those uploaded files. Without comparing those image bytes against the actual on-device partitions, we **cannot formally attest that the selected live merged Device Tree is byte-identical**. The blocked `/proc/device-tree` reads also mean that the live memory `reg` was not obtained. The Qualcomm yupik base DTB's static `/memory/reg` placeholder remains `0x0/0x0`. No physical kernel load, KASLR, use-after-free or root primitive is established.

[**C431 profile v0.5**](../profiles/fne-nx9-c431-8.0.0.290.profile-v0.5.json) stores the live bootloader indices, selected uploaded FDT SHA hashes, board-ID and hardware revision without changing any of the ten still-unresolved exploit/runtime fields. The [live boot property evidence](../profiles/evidence/fne-nx9-c431-phone-boot-dtb13-dtbo18-2026-11-12.json) and [SHA-pinned selected FDT manifest](../profiles/evidence/fne-nx9-c431-uploaded-fdt-index-selected-sha-manifest-2026-11-12.json) are permanently versioned for further read-only work. [GitHub Actions C431 v0.5 validation](../../actions/workflows/verify-c431-profile-v05-selected-fdt.yml) rejects wrong indices, board-ID, source hashes and accidental root/UAF claims.
