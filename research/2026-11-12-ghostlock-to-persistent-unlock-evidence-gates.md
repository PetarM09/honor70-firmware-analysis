# 2026-11-12 — GhostLock-to-unlock evidence gate for FNE-NX9 C431

Target: FNE-NX9 C431 MagicOS 8.0.0.290, kernel `5.4.295-qgki-ga2d8945339ca`.

## Independently verified public disclosure

Linux CVE-2026-43499 (21 May 2026) attributes a proxy-lock rollback bug to `remove_waiter()` accessing `current` instead of `waiter->task` after `futex_requeue()`. Consequences include locking the wrong `pi_lock`, failing to clear the waiter's `pi_blocked_on`, and possible dangling-pointer use.

Primary disclosure: https://lists.openwall.net/linux-cve-announce/2026/05/21/7

**Do not infer that all 5.4.295 builds are vulnerable solely from a version number.** The signed EEA binary observations, not generic kernel-version matching, underpin the candidate.

## Evidence ladder (do not collapse levels)

| Level | Required proof | State as of 12 Nov 2026 |
|---|---|---|
| 1. Vulnerable instruction pattern | Original signed EEA binary uses `current` in the proxy rollback's `remove_waiter` path | Supported by successful source-byte audits |
| 2. Reachable function edges | Original binary contains direct `do_futex -> futex_requeue -> rt_mutex_start_proxy_lock -> remove_waiter` edges | Supported by whole-ELF direct-call scan |
| 3. Reproducible trigger | Android userspace can actually produce a waiter/task mismatch through permitted futex operations on this exact firmware | **Not established** |
| 4. Reliability | Reproducible UAF/privilege change on this particular phone, without reliance on mismatched physical memory offsets | **Not established** |
| 5. Secure-state effect | Any controlled privilege change affects protected QSEE/Keymaster/RPMB lock state | **Not established** |
| 6. Persistent unlock | Verified `UNLOCKED` after reboot, with verified-boot and bootloader state observations | **Not established; device remains LOCKED** |

## Specific verification gaps before making stronger claims

1. **Kernel configuration and system-call policy.** Establish that the exact retail kernel was built with the pertinent PI-futex functionality, and inspect the actual Android process seccomp/SELinux environment rather than assuming calls are permitted from an app. Neither a symbol nor a direct-call edge proves a useful trigger.
2. **Trigger predicates.** The two source-confirmed branches around `0xffffffc01037e2f0` and `0xffffffc01037e338` require precise interpretation of their helper return semantics and the mutex state at `[lock+0x18]`. A nonzero return must not automatically be labeled an error.
3. **Actual vulnerable task mismatch.** Show that a real runtime invocation could have `waiter->task != current`, not merely that these operands appear in the disassembly.
4. **Kernel memory geometry.** Reject the current GhostLock profile for execution while it lacks 32 fields and uses a CI-host-derived `kernel_phys_load`. A source-level candidate is not a deployable binary.
5. **Trust boundary.** Distinguish kernel privilege (EL1) from QSEE trusted execution, fuses, secure boot configuration and authenticated RPMB writes. A kernel exploit does not itself prove `WRITE_KM_DEVICE_STATE (0x203)` can succeed.
6. **Causal unlock evidence.** Any proposed unlock mechanism must specify a verified authorized state-changing path and survive reboot; `fastboot flashing unlock` returning `OKAY` while remaining `LOCKED` is a counterexample to command-success-based conclusions.

## What should not be repeated

The existing FRP, OEMINFO and `devinfo+0x0D/+0x10` edits and conventional fastboot unlock attempts did not persistently unlock the device. Do not reinterpret these negative experiments as new evidence. Likewise, `0x208` runtime `is_unlocked` reporting must not be conflated with persistent `0x203` writes.

## Working conclusion

The strongest fresh signal is a source-verified kernel vulnerability *candidate* in the exact EEA image. This materially improves the precision of the kernel investigation but **does not currently provide a tested root exploit, safe executable GhostLock profile, Keymaster bypass or persistent bootloader unlock**. Further claims require distinct evidence at each step.
