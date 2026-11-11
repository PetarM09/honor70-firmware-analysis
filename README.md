# HONOR 70 FNE-NX9 — bootloader / secure firmware research

Reproducible research on a personally owned **HONOR 70 FNE-NX9** (EEA C431, MagicOS **8.0.0.290**) against the Chinese **FNE-AN00 HMT Board** firmware.

> **Current result (2026-11-11): permanent bootloader unlock has NOT been demonstrated.** Code-level firmware findings must not be mistaken for the actual secure state of the handset. No proposed research here authorizes an unverified EDL write to signed boot firmware, secure state, RPMB, GPT, FRP, OEMINFO or `devinfo`.

## Source firmware

The original uploaded archives are in this repository's [GitHub Releases](../../releases):
- `v8.0.0.290` — EEA firmware, stored in 14 chunks.
- `board-fne-an00-1.0.0.34-hmt` — Chinese Board firmware, stored in 3 chunks and a checksum manifest.

The `.github/workflows/` directory has reproducible offline extraction / Ghidra / byte-level analysis. **GitHub Actions artifacts expire**; important outcomes are also preserved in `research/` Markdown.

## Current evidence, prioritized

| Topic | Reproducible result |
|---|---|
| [VerifiedBoot reset slot is Keymaster DELETE_ALL_KEYS 0x10E (new)](research/2026-11-12-xbl-reset-slot-0x10e-is-delete-all-keys-not-unlock.md) | Original GUID+vtable registration links ABL `+0x30` to XBL `0x1C84`; that routine sends `DELETE_ALL_KEYS (0x10E)` — **not** `WRITE_KM_DEVICE_STATE (0x203)`. A wipe does not prove the bootloader unlock state changed. |
| [ABL local-state equality shortcut, keys reset and wipe](research/2026-11-12-abl-local-state-equality-can-skip-write-before-wipe.md) | The setter may skip a secure-state WRITE when its context `+0x104` state getter matches the request. Both this shortcut and a successful WRITE converge before the separate Keymaster key-deletion command and conditional recovery wipe. |
| [ABL UI callback and conditional two protected reads](research/2026-11-11-abl-ui-two-reads-keymaster-fuse-15.md) | The UI callback READ precedes the state setter. **If** the setter issues a secure-backed VBRwDevice WRITE, it must first issue another Keymaster `0x202` before `0x203`; the local-state equality branch may skip this whole second sequence. `-15` does not distinguish blown fuse from failed fuse check. |
| [Secure storage masks](research/2026-11-11-secure-state-read-before-write-scm-mask-0x20.md) | `0x8703` and `0x8723` differ by `0x20`; firmware conditional classes are documented, not measured on the phone. |
| [Featenabler Board vs EEA](research/2026-11-11-featenabler-nonload-diff-831-bytes.md) | Five loadable ELF segments identical; 831 differing outer-file bytes reside in a non-loaded region including a distinct Qualcomm leaf certificate / public key. |
| [Exact locked Fastboot allowlist](research/2026-11-09-live-fastboot-denied-allowlist-root-cause.md) | “Command not allowed” for `flashing get_unlock_ability` is pre-handler dispatch rejection, not a Keymaster error. |
| [Original EEA Fastboot/RPMB correction](research/2026-11-09-original-fastboot-ui-rpmb-gate-correction.md) | Fastboot-only UEFI log slot did not include the Linux-boot `-15` result; no direct attribution to the unlock callback. |
| [Board security comparison](research/2026-11-09-board-critical-unlock-no-bypass.md) | Chinese `unlock_critical`, ABL, Keymaster and VerifiedBootDxe have no established alternative bypass of the device lock. |
| [Past EDL tests / limitations](research/2026-11-09-physical-edl-experiment-unlock-plan.md) | Reviews hypotheses, risks and what would be needed for a reliable permanent unlock claim. |

## Latest successfully completed GitHub analyses

- [Cross-verified stock XBL +0x30 = QSEE DELETE_ALL_KEYS (0x10E), distinct from unlock WRITE 0x203](../../actions/runs/43121032094)
- [Original signed XBL PE vtable registration and exact reset-handler ARM64](../../actions/runs/43120424282)
- [Verified ABL equality shortcut, retail mode helper constants and conditional wipe](../../actions/runs/43118668948)
- [XBL reset-provider name-only inventory: no distinct named reset method found](../../actions/runs/43119045596)
- [Exact ABL UI/XBL READ / preread / WRITE error strings](../../actions/runs/43117415577)
- [ABL callback ↔ Keymaster `0x202` fuse / `-15` provenance](../../actions/runs/43116216616)
- [VBRwDevice read-before-write and SCM selector](../../actions/runs/43114969428)
- [Featenabler certificate and public-key comparison](../../actions/runs/43113403744)
- [Featenabler all-ELF-region byte comparison](../../actions/runs/43112669504)

## Security and research hygiene

- Offline analysis can run entirely within GitHub Actions. It cannot operate the phone's EDL interface.
- Do not commit raw live `secdata`, RPMB, OEMINFO or identifying device dumps to a public repository.
- An EDL write to an ordinary UFS sector does **not** mean that Keymaster/RPMB persistent lock state is writable.
- Similar signing certificates or matching executable code do not establish anti-rollback compatibility or on-device image acceptance.
- Previous FRP, OEMINFO and `devinfo` writes did not produce confirmed permanent unlock and should not be repeated without a new verified causal mechanism.
- All future experiments should separate **observed on-device behavior** from **static firmware hypothesis**.

## Outstanding question

During the prior physical UI confirmation that still left the bootloader **LOCKED**, did the ABL-local equality check skip a new secure write, or did the device reach the protected pre-write READ `0x202` and WRITE `0x203`? The ABL may stage recovery wipe after a separate reset even without a new WRITE. The existing Fastboot-only log does not answer the live-path question. **The +0x30 function-pointer ambiguity is resolved:** it sends `DELETE_ALL_KEYS (0x10E)`, independently of the `0x202/0x203` device-state pair. The unresolved question is which **live** local-state comparison, SCM backend and protected-write gate were taken on the owner's handset; existing offline images alone cannot establish them.
