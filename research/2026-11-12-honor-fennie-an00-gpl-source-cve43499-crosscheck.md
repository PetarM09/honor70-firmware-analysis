# HONOR 70 GhostLock: direct comparison of official OEM GPL source releases — 12 November 2026

## Asset provenance

Both packages are **user-uploaded copies of official HONOR Open Source Release Center packages** in this GitHub repository's Releases; SHA-256 is checked before source inspection.

| Release | Asset | Bytes | SHA-256 |
|---|---|---:|---|
| [Fennie MagicOS8](../../releases/tag/MagicOS8.0-ROM-Fennie_MagicOS8.0_Opensource) | `MagicOS8.0-ROM-Fennie_MagicOS8.0_Opensource.zip` | 494,893,191 | `0323a0381c0035ede14ef9827da0e7aecd0d836d83552f727ed7f7e5160d5672` |
| [FNE-AN00 MagicUI6.1](../../releases/tag/FNE-AN00_MagicUI6.1_Code_Opensource) | `FNE-AN00_MagicUI6.1_Code_Opensource.rar` | 553,754,313 | `645f129c46b2e1b5ad17be29f0bc304448a3872004d70d4d1c2010ab41a869e7` |

The inner packages are named `Code_Opensource.tar.gz`:
- Fennie inner TAR SHA-256: `d4d477fa5153c09673e97b37602313bf45d19015a0f1b9b37c67f4afb895e6b6`
- AN00 inner TAR SHA-256: `e65274ba1977fb41e868463849cf347a6d6037c102a6bd9a963a3223885e67f6`

[First successful archive audit](../../actions/runs/43160868037) checked archive identity and saw Fennie kernel sources (including `kernel/kernel/locking/rtmutex.c`, `kernel/kernel/futex.c`). [Successful source exports](../../actions/runs/43161885225) recovered the actual relevant text from both signed-digest assets.

**Important terminology:** SHA checking guarantees correspondence to these uploaded release assets. It does not cryptographically prove that every file was compiled into the retail 8.0.0.290 C431 image.

## Source tree age — highest-impact compatibility caveat

The **top-level Linux Makefiles** state:

| | Fennie MagicOS 8 | FNE-AN00 MagicUI 6.1 | User's stock FNE-NX9 C431 |
|---|---|---|---|
| Linux version | **5.4.242** | **5.4.147** | **5.4.295-qgki-ga2d8945339ca** |

Thus even Fennie MagicOS8 is **not an exact source snapshot of the original running 5.4.295 kernel** based on its Makefile. Vendor patch backports or build-time changes could exist. Never infer exact structure offsets or runtime layout from a release label alone.

## Actual byte-for-byte source comparisons

| Original kernel source file | Fennie vs AN00 |
|---|---|
| `kernel/locking/rtmutex.c` | **byte-identical**, SHA-256 `70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9` |
| `kernel/locking/rtmutex_common.h` | **byte-identical** |
| `kernel/locking/rtmutex.h` | **byte-identical** |
| `include/linux/rtmutex.h` | **byte-identical** |
| `kernel/futex.c` | **different**; Fennie adds `CONFIG_HN_VIP_THREAD`-gated futex wait/owner logic |
| `include/linux/sched.h` | **different**; Fennie has additional conditional scheduler/task fields |
| `arch/arm64/configs/gki_defconfig` | **different** |

The key OEM **source-level** evidence in `kernel/locking/rtmutex.c`, line 1067 onward, is the actual `remove_waiter(struct rt_mutex *lock, struct rt_mutex_waiter *waiter)` function. Lines 1076–1079 hold:

```c
raw_spin_lock(&current->pi_lock);
rt_mutex_dequeue(lock, waiter);
current->pi_blocked_on = NULL;
raw_spin_unlock(&current->pi_lock);
```

This matches the **mechanism** described in [Linux CVE-2026-43499](https://lists.openwall.net/linux-cve-announce/2026/05/21/7) and is consistent with the **original signed EEA machine-code evidence** (`mrs x20, sp_el0` and `str xzr,[x20,#0x990]` in the rollback target). It confirms the relevant source pattern is present in the published OEM kernels. It does **not** by itself show a reproducible runtime UAF.

The common `rtmutex_common.h` also contains the same `struct rt_mutex_waiter` field declarations in both releases, but **compiled byte offsets depend on architecture, configuration and build details**. Identical source text must not be promoted to exact C431 in-memory geometry.

## OEM build configuration — not an on-device configuration read

The exported `arch/arm64/configs/merge_lahaina_defconfig` files contain:

| Option | Fennie MagicOS8 source | AN00 MagicUI6.1 source |
|---|---|---|
| `CONFIG_FUTEX` | y | y |
| `CONFIG_FUTEX_PI` | y | y |
| `CONFIG_RT_MUTEXES` | y | y |
| `CONFIG_IKCONFIG_PROC` | y | y |
| `CONFIG_SECCOMP_FILTER` | y | y |
| `CONFIG_HN_VIP_THREAD` | y | y |
| `CONFIG_HN_VIP_RUNNABLE_TIME_LIMIT` | **y** | **n** |
| `CONFIG_HN_SET_ASYNC_BINDER_RT` | **y** | not listed |
| `CONFIG_SCHED_ENHANCEMENT_INTRUSIVE` | **n** | not listed |

The conditional Fennie `sched.h` field `hn_vip_last_queued` is an example of a change that can affect layout if actually compiled in. In the stock original C431 kernel two PI task fields were already independently machine-code corroborated; this source study does not establish the other missing offsets.

On the physical device the previous read-only snapshot reported `/proc/config.gz` readable. The effective config can be compared to these source configs using `tools/collect_fne_live_ikconfig_readonly.py`, without an exploit or storage write. **That live config has not been supplied yet.**

## Exact state after source recovery

- **Confirmed:** both uploaded GPL packages were SHA-verified and inspected; Fennie contains real Linux source; their `remove_waiter` implementations are the same and use `current` for the PI lock and clear; Fennie merged source config supports PI futex.
- **Not confirmed:** matching C431 5.4.295 source revision, full struct geometry, physical load and KASLR conditions, Android-app eligibility to reach the vulnerable rollback, repeatable GhostLock exploit or root.
- **Independent second objective:** neither source archive nor kernel root by itself changes the protected Keymaster/RPMB bootloader state. No persistent unlock has been demonstrated.

**Do not use FNE-AN00 precompiled GhostLock profiles or the earlier CI-host-derived `0xfffff000` physical address against FNE-NX9 C431.**

## Reproducibility

- [Archive and nested-source scanner](../tools/audit_honor_fennie_release_sources.py)
- [GPL core-source extractor](../tools/extract_honor_gpl_core_sources.py)
- [Source-hash and CVE function comparer](../tools/compare_honor_oem_source_releases.py)
- [Automated end-to-end workflow](../.github/workflows/extract-honor-fne-kernel-sources.yml)
- [Exact C431 original signed ARM64 GhostLock rollback](2026-11-12-exact-ghostlock-proxy-to-remove-waiter-and-km41-67-handlers.md)
