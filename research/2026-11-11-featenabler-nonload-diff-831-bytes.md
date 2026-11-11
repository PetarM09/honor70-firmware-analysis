# 2026-11-11 — FNE-AN00 / FNE-NX9 featenabler non-code delta

## Verified GitHub Actions result

**Run:** https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43112669504  
**Execution:** completed successfully, using byte-verified Board and EEA featenabler images extracted from the owner's uploaded releases. No connection to the device or EDL write.

The research scripts and metadata-only outputs:
- `tools/compare_featenabler.py`
- `tools/audit_featenabler_regions.py`
- `.github/workflows/compare-board-eea-featenabler.yml`

## Key measured results

- Both outer ELF files have the same length: **86,480 bytes**.
- Both have one executable PT_LOAD segment, length **39,525 bytes**, SHA-256 `edb450792ca6af5a6ffce58dd52ab902cea3526524ff4330895c59549de6b253`.
- All five PT_LOAD file segments (program-header indexes 2, 3, 4, 5, 7) are **byte-for-byte identical** between the two images.
- Non-load program-header indexes 0 and 6 also have matching hashes.
- The complete images differ by **831 bytes in the overlapping file** (~0.96%), grouped into **21** contiguous runs.
- **All 831 differences are located in the non-PT_LOAD program-header index 1**, file region starting at offset **4096**, declared length **19928**.
- Program-header index 1 SHA-256:
  - Board: `4f9a2b75b824ddc0a5966a55d42fb1d74dc278aeed3c4413eb8ce65ce812aad2`
  - EEA: `6649ec27523dd8a8ebf15c75c1041e060728280629cb587fd037165973d89871`
- Largest changed contiguous run: file offsets **11016..11372** inclusive (357 bytes).

### Common loadable segment hashes

| Program header | Type | Flags | File offset | Length | SHA-256 (both) |
|---:|---|---:|---:|---:|---|
| 2 | PT_LOAD | 5 | 24576 | 39525 | `edb450792ca6af5a6ffce58dd52ab902cea3526524ff4330895c59549de6b253` |
| 3 | PT_LOAD | 67108870 | 65536 | 231 | `50f7622e5e2ebb82a29e02474b7daa845a491bb4a7be8e737438469cabf855aa` |
| 4 | PT_LOAD | 6 | 69632 | 904 | `120c5d1504dbfcf77d26e818948803d1868017c58ca11782b87e7ccdb95a1170` |
| 5 | PT_LOAD | 6 | 73728 | 464 | `67204e254834192542e1abb25db06ee128a10ebd56c4da28d0bd6b7507b9f413` |
| 7 | PT_LOAD | 6 | 77824 | 8656 | `e9eda924a033293cd401ec283f0c541a5db8c07ed6f36862744770bc4ed9fee3` |

### Conservative interpretation

The signed Chinese Board and European EEA `featenabler` **do not differ in any ELF PT_LOAD file segment**. The byte differences are confined to a segment whose ELF type is **0x0**, not PT_LOAD. This supports deprioritizing a factory `featenabler` swap as a means of obtaining new executable unlock logic.

**Do not equate 'non-PT_LOAD' with 'irrelevant'.** OEM-specific signature/header/hash/metadata blocks might be used by the loader or trust chain; the present structural script does not prove their cryptographic identity or boot-time policy effects. Also, dynamic fuse/RPMB state is unknown.

### Next research priority

Classify the differing non-PT_LOAD region using a dedicated read-only signed-metadata and certificate audit, avoiding any raw `secdata` upload. No further EDL writes are warranted from these data alone.

This finding replaces the earlier weaker claim that only the executable segment was known to be identical.
