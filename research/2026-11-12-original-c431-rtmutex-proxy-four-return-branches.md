# 2026-11-12 — Four original C431 rtmutex proxy-lock return paths established

## Tested scope

**Device / firmware:** own HONOR 70 FNE-NX9 C431, MagicOS 8.0.0.290; original kernel `5.4.295-qgki-ga2d8945339ca`. This is a **read-only original-binary control-flow inspection**, not a runtime GhostLock trigger, root experiment or device modification.

Primary evidence: [successfully completed original C431 branch audit](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43277193764) — **23 exact ARM64 instruction assertions and all 10 regression tests passed**.

- Original signed boot SHA256 `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256`.
- Original extracted kernel Image SHA256 `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`.
- Original `rt_mutex_start_proxy_lock` function VA `0xffffffc01037e2c0`.
- Reference HONOR Fennie GPL `kernel/locking/rtmutex.c` SHA256 `70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9`. **It is Linux 5.4.242-based source, not exact C431 5.4.295. The original retail ARM64 instructions are the decisive evidence.**

## Exact stock ARM64 instructions supporting the decision paths

```asm
0xffffffc01037e2ec bl   #0xffffffc01037ddb8
0xffffffc01037e2f0 cbz  w0, #0xffffffc01037e320
0xffffffc01037e2f4 mov  w21, #1
0xffffffc01037e2f8 mov  x0, x19
0xffffffc01037e2fc mov  x1, x20
0xffffffc01037e300 bl   #0xffffffc01037e350   ; remove_waiter
0xffffffc01037e304 mov  x0, x19
0xffffffc01037e30c mov  w0, w21

0xffffffc01037e320 mov  w3, #1
0xffffffc01037e324 mov  x0, x19
0xffffffc01037e328 mov  x1, x20
0xffffffc01037e32c mov  x2, x21
0xffffffc01037e330 bl   #0xffffffc01037dfb4   ; task_blocks_on_rt_mutex
0xffffffc01037e334 mov  w21, w0
0xffffffc01037e338 cbz  w0, #0xffffffc01037e304
0xffffffc01037e33c ldr  x8, [x19, #0x18]
0xffffffc01037e340 cmp  x8, #2
0xffffffc01037e344 b.hs #0xffffffc01037e2f8
0xffffffc01037e348 mov  w21, wzr
0xffffffc01037e34c b    #0xffffffc01037e304
```

### Four cases

| Original code state | Original return | `remove_waiter` | Interpretation |
|---|---|---|---|
| Immediate acquisition returns nonzero | `1` | Called | **Success**, not failure; the waiter can be unenqueued |
| Initial try fails; `task_blocks_on_rt_mutex` returns zero | `0` | Skipped | Task is blocked; waiter can remain in queue |
| Initial try fails; block returns nonzero and owner exists | nonzero | Called | Failure/rollback path where wrong-`current` bug is relevant |
| Initial try fails; block returns nonzero, owner vanished | normalized to `0` | Skipped | Exception suppressed by owner-gone safeguard |

The reference source spells out the distinction:

```c
if (try_to_take_rt_mutex(lock, task, NULL))
    return 1;
...
ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
if (unlikely(ret))
    remove_waiter(lock, waiter);
```

This matches the original C431 branch decisions. The exact original code in the third case still uses `current->pi_blocked_on` and `current->pi_lock` in `remove_waiter` instead of necessarily using `waiter->task`.

## Relationship to two different upstream bug fixes

**CVE-2026-43499:** original documented issue where proxy-lock rollback may dequeue another task's waiter using `current`, leaving the real waiter's `pi_blocked_on` in an invalid state. See [Linux CVE team, 21 May 2026](https://lists.openwall.net/linux-cve-announce/2026/05/21/7).

**CVE-2026-53163:** a later patch addresses calling `remove_waiter` on a waiter that was *never enqueued*, and explains why an immediate-success `ret=1` must **not** cause cleanup. The [Linux CVE team advisory, 25 June 2026](https://lists.openwall.net/linux-cve-announce/2026/06/25/20) explicitly lists affected *newer/backported* branches (e.g. 6.18.27, 7.0.4, 6.1.175 and others); it **does not list** the retail C431 5.4.295. Thus **we do not assert that the phone is affected by CVE-2026-53163** merely because an analogous nonzero-return cleanup pattern exists in its code. The documented syzbot null pointer dereference in CVE-2026-53163 specifically followed the `waiter->task` fix from CVE-2026-43499. The older C431 code still uses `current`, so the consequences can differ.

The correct **relevant C431 fact** is only that the original compiled function's positive-result branch also goes to `remove_waiter`; another independent live check would be necessary to establish any effects.

## Next investigation (still offline)

- Distinguish actual original control flow on the error vs positive return path without conflating CVE labels.
- Identify independent evidence of **whether the intended rollback ever occurs on this retail phone**; prior v0.2 `EINVAL` app test deliberately stops before futex waiters, so it does not do this.
- Avoid importing Chinese FNE-AN00 physical kernel base or unresolved layout fields into a runnable exploit. Current work does **not** demonstrate root, kernel read/write, persistent bootloader unlock or reliable UAF exploitation.

**Reproduce:** [source- and machine-code-checked parser](../tools/audit_c431_proxy_result_branches.py), [10 synthetic tests](../tools/test_audit_c431_proxy_result_branches.py), [GitHub CI](../.github/workflows/audit-c431-proxy-result-branches.yml).

No device commands are necessary for this analysis.
