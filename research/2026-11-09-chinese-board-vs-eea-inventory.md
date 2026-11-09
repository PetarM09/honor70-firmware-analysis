# Honor 70 Chinese FNE-AN00-BD 1.0.0.34 — preliminary EEA comparison from user-supplied ZIP inventory

**Audit date:** 2026-11-09. **Input:** locally generated `HONOR70_BOARD_FIRMWARE_INSPECTION.json` from `Honor_70_FNE-AN00_1.0.0.34_220721_HMT.zip`; original unmodified ZIP not uploaded. **Device:** user's FNE-NX9 (EEA) FNE-N29 8.0.0.290(C431E4R3P1).

## Findings backed by SHA256 and actual original EEA firmware inspection

| Signed firmware artifact | Chinese Board ZIP SHA256 | Original EEA stock SHA256 | Bytes Board vs EEA |
|---|---|---|---|
| `abl.elf` (outer signed ELF, NOT inner LinuxLoader EFI) | `d4ec54ade577420aba332424696e64e03efab0eeb984823ae968109c2f055fda` | `21b95d40a9337af53e0173867a2f07dfc4ceb84ff53129c463f4e0f1bdf0abd8` | 536576 vs 536576 |
| `xbl.elf` | `32475f11b3081d5c957cc52ee8fb71d786dbb756ee6e39067a60b1e16eb4b570` | `a2c2ffb2c711c477054d6f9f5e745912a56bd104506374606f54ee0eac06226b` | 4391552 vs 4434976 |
| `xbl_config.elf` | `655f3fa6a040eae900e2fbea562d0784b23ddb8605548d75b05e2f17203af916` | `f87edd52fa25e17621c4b0b5f2be9e9910734e31149c007e740e4359e5c7e342` | 225120 vs 225504 |
| `km41.mbn` | `b548a4a0cfd3b21d08164600593881e5a1b57bdc960ab0a3437309bc92ba5f78` | `c7f389b80444a9c9e3956efd427abbae1b5b2753b3c905107ca7888dca496afd` | 267645 vs 267645 |
| `tz.mbn` | `7ea35b41137e24681b70afe88d03fd86661acc69e87f866f7700ccef1971a189` | `d554da6a7e2a42ae86e3bcaa9bb4ffe0abeb7f839891fd44c60c213a9e4f3a72` | 3722636 vs 3675284 |
| `featenabler.mbn` | `142eaec4ad05958140860743905aa5d5c8374b10387e48cd5a05697291111dea` | `5cd32cd0b7d6e9d91cef22ddb07f2659aad0fd9c3b8be0c95a1e81ac6294b369` | 86480 vs 86480 |

**Original stock evidence:** [GitHub job showing exact EEA outer-ELF hashes](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42526467603). All listed outer signed files are different by SHA256. **Difference does NOT prove that unlock policy differs, or that the Board images are accepted by an upgraded EEA phone.**

## Board package content

Uncompressed files found in `Firmware/bootloaderimage/` and `Firmware/fastbootimage/`:

- `abl.elf`, `xbl.elf`, `km41.mbn`, `tz.mbn`, `uefi_sec.mbn`, `xbl_config.elf`, `featenabler.mbn`;
- Two Qualcomm Firehose programmer candidates: `prog_firehose_ddr.elf` SHA256 `9c892e716320764c20055d8374bf8eca7418b3ff2177f81794e18d3656fc55a8`, `prog_firehose_lite.elf` SHA256 `e029df6e2d532de87c2279e960472ec0e4799aca53bc27ed4fa3e4027b05d101`. These are **not** confirmed to be authorized for FNE-NX9 EEA MagicOS 8 EDL mode.
- 6 GPT layouts (`gpt_main0..5.bin`, `gpt_backup0..5.bin`, plus `gpt_both0.bin`), `rawprogram0..5.xml`, `patch0..5.xml`, `FNE-AN00-BD_1.0.0.34_Download.xml`, and `download_for_7325_v1.0.bat`. **None should be executed or applied to a locked EEA phone before compatibility/rollback and recovery checks.**
- `eng_system.img`, `eng_vendor.img`, `patch_avb.img` and `oeminfo.mbn` in the fastbootimage directory; presence is not proof of a root or unlock capability.
- `frp.img`, `oeminfo.mbn`, `userdata.img` present in original bundle, potentially damaging if flashed. These are deliberately excluded from further shared analysis subset.

## Immediate next work

The user's **JSON reports file identities, sizes and hashes but not executable bytes**; further policy analysis of Chinese LinuxLoader/VerifiedBootDxe/Keymaster requires their actual binaries, not only hash values.

Prepared [read-only extraction tool](https://github.com/PetarM09/honor70-firmware-analysis/blob/main/tools/extract_board_core.py) which operates on local original HMT ZIP, produces `HONOR70_BOARD_CORE_FOR_ANALYSIS.zip` containing only essential bootchain/Firehose/GPT/XML files; it excludes FRP, OEMINFO and USERDATA and does **not** flash phone. [Synthetic validation workflow](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42549211758) completed successfully.

Once core subset is supplied, compare exact UEFI GUID-defined decompression and callback routines in Board `abl.elf` and `xbl.elf`, actual milestone guards in `km41.mbn`, GPT differences, QFIL/firehose permissions. Do not infer production-board cross-flashing safety from matching model family or same `1.0.0.34` version.
