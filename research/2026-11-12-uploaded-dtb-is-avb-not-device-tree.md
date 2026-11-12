# 2026-11-12 — Owner-uploaded `extracted.dtb` is AVB metadata, not a Device Tree

Read-only local analysis of two user-uploaded files; no active kernel, EDL, root or device operations.

## File identities (original uploaded bytes)

| File | Bytes | SHA-256 | Meaning |
|---|---:|---|---|
| `extracted_kernel` | 47,041,024 | `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece` | **Exact byte-for-byte SHA match** to our previously proven signed-stock C431 `Image` |
| `extracted.dtb` | 53,612,544 | `98b46c6c17dc21541b271e54593ef0b71db39ff1eb536ab8d38960c9332c0e68` | **Not an FDT/DTB**. Starts `AVB0`, contains Android Verified Boot metadata and mostly zero padding |

The genuine original C431 kernel's ARM64 header has `ARM\x64` at offset 0x38, `text_offset=0x80000`, `image_size=51,261,440` and flags `0xA`. These values do not reveal the live kernel physical load address or runtime KASLR slide.

### Why `extracted.dtb` is not a DTB

- Expected standard FDT magic: **`d0 0d fe ed`**. This pattern appears **zero times** anywhere in the 53 MB submitted file.
- The first four bytes are **`41 56 42 30` = `AVB0`**, and the file ends with an **`AVBf`** footer. Neither `ANDROID!` nor `VNDRBOOT` appears as a file header.
- Embedded AVB metadata total is **1,728 bytes** with a **SHA-256 hash descriptor for the `boot` partition**, recorded `image_size=47,050,752` bytes. This is **not** a physical RAM memory node.
- AVB build metadata includes `com.android.build.boot.os_version=11` and `security_patch=2026-06-01`. This is metadata **inside the uploaded AVB blob**, not an independently verified measurement of the phone running Android 14.
- The `AVBf` footer claims `vbmeta_offset=47,050,752`, yet there is **no `AVB0` at that position**; the AVB metadata is at file offset 0. This mismatch means the submitted file must **not** be trusted as a complete, internally consistent, raw boot partition image. Its AVB signature has **not** been cryptographically verified.

## Correct remaining source for DTB data

Our separately verified stock `boot.img` is **Android boot image header v3**. On Android GKI boot v3, the device-specific DTB is normally in the **`vendor_boot` partition**, not the `boot` kernel Image. Android source documentation: https://source.android.com/docs/core/architecture/partitions/vendor-boot-partitions

Next appropriate **read-only input**: `vendor_boot_a.img` from the same original C431 firmware/slot (optionally `dtbo_a.img` if there are device-tree overlays). Identify `VNDRBOOT` before trying to parse the container and the embedded DTB's `d00dfeed` magic. Do not run `dtc` on the submitted AVB-only blob.

Even a genuine `memory@...` / `reg` entry describes RAM ranges; **it does not prove** the actual bootloader-chosen `kernel_phys_load`, and cannot determine a live KASLR slide.

## Research impact

The user-provided `extracted_kernel` establishes the original stock C431 Image identity, which strengthens provenance. The invalidly labelled `extracted.dtb` establishes **no new kernel memory geometry**. Retain all unknown fields in `profiles/fne-nx9-c431-8.0.0.290.profile-v0.3.json` as `null`. No UAF, kernel R/W, GhostLock root or authenticated bootloader unlock was demonstrated.

**Local reproducible extraction tool:** `inspect_uploaded_honor70_dtb.py` (uses Python stdlib to classify FDT/AVB signatures, parse AVB descriptors and footer, and SHA-256 match the exact C431 Image). Full original uploaded binary is not republished here.
