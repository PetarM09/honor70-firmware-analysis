# 2026-11-11 — featenabler.mbn Board vs EEA executable-code comparison

## Provenance

Automated read-only analysis: [GitHub Actions run 43109960550](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43109960550), job `compare`, **completed successfully**.

The workflow reuses signed firmware modules previously extracted from the user's two GitHub Release archives and verifies their original whole-file SHA-256 hashes before analysis:

| Input | Whole-file SHA-256 | Bytes |
|---|---|---:|
| FNE-AN00 HMT Board `featenabler.mbn` | `142eaec4ad05958140860743905aa5d5c8374b10387e48cd5a05697291111dea` | 86,480 |
| FNE-NX9 EEA stock `featenabler.mbn` | `5cd32cd0b7d6e9d91cef22ddb07f2659aad0fd9c3b8be0c95a1e81ac6294b369` | 86,480 |

## Exact observed result

Both files have one executable ELF PT_LOAD segment in the analyzed layout.

- Executable segment length (Board and EEA): **39,525 bytes**
- Executable-segment SHA-256, identical in both: `edb450792ca6af5a6ffce58dd52ab902cea3526524ff4330895c59549de6b253`
- Mismatched executable bytes in the aligned overlap: **0**
- Unpaired executable tail bytes: **0**
- Executable segment virtual address: `0x0` in both images

**Conclusion:** swapping these two stock/Board versions is not supported as a way to obtain a different `featenabler` executable implementation. Although the overall signed files differ, this comparison did not find any executable-code delta.

## What this does NOT establish

- Equality of firmware configuration, certificates or non-executable data.
- The actual live value of security fuse bits or secure storage on a specific handset.
- The security backend chosen by the live boot chain.
- Boot acceptance of Chinese signed images on the EEA production handset.
- A permanent bootloader unlock procedure.

Only offline signed release images were analyzed; no EDL read/write, RPMB operation or physical phone test was performed.

## What changes in the research plan

- Deprioritize Chinese Board `featenabler` substitution as an unlock attempt.
- Preserve previously closed negative EDL tests (FRP/devinfo/OEMINFO generic writes); do not repeat them on the basis of this result.
- If needed, separately map non-executable signed-data/configuration differences **before** assigning them security-policy meaning.
- Any device-specific `secdata` image is potentially sensitive and should stay local, not be committed to this public repository.
- Require verified, device-specific secure-state evidence before contemplating another write to production boot firmware.

## Reproduction

The script is [`tools/compare_featenabler.py`](../tools/compare_featenabler.py) and the workflow is [`compare-board-eea-featenabler.yml`](../.github/workflows/compare-board-eea-featenabler.yml). The run uploaded a metadata-only JSON artifact, `HONOR70_FEATENABLER_BOARD_VS_EEA_STATIC_COMPARISON`. It has a 14-day Actions retention period; this Markdown document preserves the key measured outcome.
