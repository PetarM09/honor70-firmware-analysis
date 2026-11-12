# 2026-11-12 — GhostLock C431: IKCONFIG extraction and CVE distinction

**Scope:** HONOR 70 FNE-NX9, EEA C431 MagicOS 8.0.0.290, original extracted `kernel.Image` SHA256 `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`.

## First objective: runtime feasibility; later objective: permanent unlock

The current original ARM64 image has a source-verified `do_futex -> futex_requeue -> rt_mutex_start_proxy_lock -> remove_waiter` direct call graph and a `current` task access relevant to **CVE-2026-43499**. This is static evidence, not a running exploit or root permission.

**Do not conflate CVEs:**

- **CVE-2026-43499:** original wrong-task use in `remove_waiter()` when invoked through proxy-lock rollback.
  Official disclosure: https://lists.openwall.net/linux-cve-announce/2026/05/21/7
- **CVE-2026-53166:** NULL pointer dereference introduced in certain upstream stable branches by a fix for CVE-2026-43499, involving `waiter->task` not yet assigned. The upstream advisory lists introductions in 6.1.175, 6.6.140, 6.12.86, 6.18.27, and 7.0.4; **the stock FNE-NX9 kernel is 5.4**, and no evidence of that specific fix-backport is established. Do not claim 53166 applicability or attempt a crashing self-deadlock trigger.
  Official disclosure: https://lists.openwall.net/linux-cve-announce/2026/06/25/43

## New offline config audit

Added `tools/audit_fne_embedded_ikconfig.py`, with synthetic test suite `tools/test_audit_fne_embedded_ikconfig.py`, to the signed image GitHub Actions workflow `.github/workflows/audit-fne-exact-proxy-rollback-instructions.yml`.

Pipeline provenance:
1. Retrieve previously uploaded original `boot.img` artifact.
2. Hard-verify SHA256 for both `boot.img` and raw `kernel.Image`.
3. Search original Image for `IKCFG_ST`/gzip/`IKCFG_ED` and parse only after a successful bounded gzip decode.
4. Emit `report/ORIGINAL_EEA_KERNEL_IKCONFIG.json`, reporting actual `CONFIG_FUTEX`, `CONFIG_FUTEX_PI`, `CONFIG_RT_MUTEXES`, `CONFIG_SECCOMP` and related flags when embedded.
5. Test explicitly that missing/invalid markers produce an unknown state; never silently mark a feature disabled.

This mirrors the provenance concept of Linux's official `scripts/extract-ikconfig`, which **only works when CONFIG_IKCONFIG is compiled in**:
https://github.com/torvalds/linux/blob/master/scripts/extract-ikconfig

**Note:** absence of embedded IKCONFIG is neither evidence that FUTEX_PI is off nor that the phone is patched. Source-level function presence is not evidence that Android sandbox policy permits exploitation.

## Separate live-phone diagnostic, not yet run

`tools/collect_fne_kernel_policy_readonly.py` has been corrected to execute commands via a single adb shell argument and to sample the `/proc/self/status` of a simple child process. It reads basic boot/kernel metadata, shell SELinux context, inherited seccomp status, SELinux enforcing and `/proc/config.gz` readability, but **does not execute futex syscalls or change phone state**. It cannot verify app-context access to the vulnerable path.

There is **no new physical operation required at this point**. Once the exact-stock GitHub Actions config artifact is inspected, decide whether a further, separately documented, bounded functional diagnostic would add real information. Never run FNE-AN00 GhostLock prebuilt offsets on FNE-NX9 C431.

## Evidence needed before claiming GhostLock success

- Reproducibly triggered behavior on exact FNE-NX9 build and runtime environment.
- Independently observed privilege escalation; precise limitations and crash risk documented.
- Distinction between *temporary kernel root* and the separate authenticated Keymaster/RPMB lock state.
- For permanent unlock claims, a verified unlock state after a cold reboot.

**Current conclusion:** static CVE-43499 candidate, corrected diagnostics and offline config audit committed; no working C431 GhostLock root or persistent bootloader unlock has been demonstrated.
