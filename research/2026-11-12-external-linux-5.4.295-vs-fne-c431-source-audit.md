# 2026-11-12 — User-supplied Linux 5.4.295 source compared with actual HONOR 70 C431

## Source and identity

The user uploaded **`linux-5.4.295.tar.xz`** as a [GitHub release asset](https://github.com/PetarM09/honor70-firmware-analysis/releases/tag/linux-5.4.295).

- Archive: 113,052,244 bytes, SHA-256 **`c48158f7735668aac78b9d74bb3616f57a4ea0816ca09f7db83f7834d705b6a9`**.
- 70,094 TAR members were examined without extracting arbitrary archive paths or executing content.
- The source-tree `Makefile` reads `VERSION=5`, `PATCHLEVEL=4`, `SUBLEVEL=295`, empty `EXTRAVERSION`, `NAME=Kleptomaniac Octopus`.
- This establishes that the archive contains a **Linux 5.4.295 source tree**, **not** that it is the complete HONOR kernel tree used to compile the user's stock device.
- Original user-owned signed C431 kernel `Image` SHA-256 remains `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`. A source archive is **not** a cryptographic equivalence proof to the running Image.

## Exact comparison to the user-provided HONOR Fennie MagicOS 8 GPL sources

[**Complete successful source comparison CI 43299436582**](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43299436582), 9 regression tests passed. Both source inputs were SHA-checked. The original HONOR Fennie code was published as a 5.4.242-based tree and had already been cross-checked against exact stock C431 ARM64 machine code.

| Source file | Byte-for-byte identical? | Approximate line similarity | Interpretation |
|---|---|---:|---|
| `kernel/futex.c` | **No** | 99.169% | HONOR includes OEM futex hooks, conditional VIP fields and other changes |
| `kernel/locking/rtmutex.c` | **No** | 99.896% | Small differences in unrelated deadlock handling |
| `kernel/locking/rtmutex_common.h` | **Yes** | 100% | This header matches the Fennie source exactly |
| `include/linux/sched.h` | **No** | 89.167% | 2,004 generic source lines vs 2,464 HONOR source lines: substantial scheduler and ABI differences |
| Root `Makefile` | **No** | 94.467% | Different kernel sublevel, toolchain/build options, vendor hooks |

**Important positive result:** the actual source text bodies of **four functions** are byte-identical in the generic and Fennie sources, despite the differences in the full source files:

- `futex_requeue()`
- `futex_wait_requeue_pi()`
- `rt_mutex_start_proxy_lock()`
- `remove_waiter()`

This is useful independent source corroboration of the earlier original-C431 disassembly showing the known wrong-task `remove_waiter` pattern. It is **not** a live UAF or root proof.

## Why the generic 5.4.295 source cannot fill the remaining C431 struct offsets

HONOR's `include/linux/sched.h` includes `ANDROID_KABI_RESERVE`, `CONFIG_HN_VIP_THREAD`, `CONFIG_HONOR_SCHED_VIP` and other vendor fields absent from the new generic source. The Fennie `kernel/futex.c` also includes `CONFIG_HN_VIP_THREAD`-dependent `futex_q` fields and vendor hooks absent from the generic source.

To avoid relying only on a GPL source that targets a different sublevel, I independently checked the **embedded signed retail C431 IKCONFIG**, in [successful CI 43299954797](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43299954797), **5/5 tests passed**:

| Signed C431 compile-time flag | Value |
|---|---|
| `CONFIG_HN_VIP_THREAD` | `y` |
| `CONFIG_HN_RTG` | `y` |
| `CONFIG_HN_QOS_THREAD` | `y` |
| `CONFIG_HN_RTG_FRAME` | `y` |
| `CONFIG_ANDROID_VENDOR_HOOKS` | `y` |
| `CONFIG_HONOR_SCHED_VIP` | `n` |
| `CONFIG_LTO_CLANG` | `y` |
| `CONFIG_THINLTO` | `y` |
| `CONFIG_CFI_CLANG` | `y` |

Therefore the phone *actually compiles* key OEM and Android differences not described by the generic `linux-5.4.295` source tree. In particular, adopting generic `struct task_struct` or `struct futex_q` declaration offsets without checking actual C431 signed ARM64 would produce an **unverified exploit profile**.

The original Fennie `sched.h` contains hundreds of added lines relative to generic. Source-level field names or struct order alone cannot supply trustworthy numeric layout in the signed original kernel, especially with differing compiler options, conditional fields and optimizations.

## Experimental C431 profile v0.2

[**Source-checked C431 v0.2 profile**](../profiles/fne-nx9-c431-8.0.0.290.profile-v0.2.json) retains the **ten** signed-original, machine-code-validated `task_struct` and `rt_mutex_waiter` offsets from v0.1, includes the nine original C431 OEM compile flags above, and records the exact origin/compatibility of the generic 5.4.295 release.

[**Profile v0.2 validation: CI 43300398918 — 9/9 tests pass**](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43300398918):

- `known_c431_field_offset_count = 10`.
- `oem_compiled_flags_verified = 9`.
- `new_5_4_295_derived_numeric_offsets_added = 0`.
- `unresolved_fields_kept_null = 10`.
- `ready_for_live_ghostlock_uaf_root = false`.

**The zero newly derived numeric offsets is intentional:** the newly supplied source lacks the HONOR OEM ABI features actually compiled into the phone. The still-unknown physical kernel base, current memory slide, credential fields, full futex layout, actual UAF lifetime and privilege primitive **must not be invented**.

The prior v0.1 profile remains preserved because the owner's FNE PI Gate v0.3 app already matched the exact model/kernel/Android on-device. v0.2 updates offline research confidence, not that live identity result.

## Explicit four-task GhostLock status after investigating Linux 5.4.295

1. **Live vulnerable kernel UAF:** not demonstrated. Source function equality and original ARM64 linkage do not show real use-after-free.
2. **Live stack reuse and user-controlled overlap:** not demonstrated. Earlier conditional 80-byte interval remains only a static arithmetic model.
3. **Complete trustworthy signed-C431 profile:** partial. Ten offsets and additional flags confirmed; remaining needed fields cannot be copied from vanilla.
4. **Temporary root on actual FNE-NX9 C431:** not demonstrated. No active exploitation process was run and no elevated `uid`, kernel capabilities or authenticated boot state were obtained.

This work **did not create, distribute or execute a GhostLock UAF/root payload**, and **no EDL/partition/device modification occurred**. Presenting a source-compatible but incomplete profile as a working exploit would not be technically justified.

## Reproduce

- [Read-only source archive analyzer](../tools/inspect_external_linux_5_4_295_release.py).
- [Nine source archive parser tests](../tools/test_inspect_external_linux_5_4_295_release.py).
- [Signed retail C431 OEM configuration inspector](../tools/audit_c431_original_vendor_abi_config.py).
- [Signed OEM config regression tests](../tools/test_audit_c431_original_vendor_abi_config.py).
- [C431 v0.2 profile fail-closed validator](../tools/verify_c431_profile_v02_with_external_5_4_295.py).
- [Profile validator regression tests](../tools/test_verify_c431_profile_v02_with_external_5_4_295.py).

**Summary:** the uploaded source is genuinely useful to validate source-level CVE logic. It is *not* a substitute for the exact OEM C431 build profile or a verified way to elevate privileges.
