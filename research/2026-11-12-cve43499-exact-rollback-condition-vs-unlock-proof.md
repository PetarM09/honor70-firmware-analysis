# 2026-11-12 — Exact stock C431 GhostLock proxy rollback condition, source-byte verified

**Target:** HONOR 70 FNE-NX9 EEA, MagicOS 8.0.0.290(C431E4R3P1); kernel `5.4.295-qgki-ga2d8945339ca`. **State: NOT unlocked; no exploit executed; no device/EDL writes.**

## New result from the signed original EEA kernel

- Original `boot.img` SHA256 `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256`.
- Extracted original `Image` SHA256 `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`.
- [Source-confirmed exact ARM64 code and branch assertions, SUCCESS run 43148246581](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43148246581).
- [Ghidra-independent source disassembler and hard assertions](../tools/audit_exact_fne_rollback_instruction_condition.py).
- [GitHub Actions workflow](../.github/workflows/audit-fne-exact-proxy-rollback-instructions.yml).
- [Whole-ELF scan of 482,252 ARM64 BLs proving the incoming futex and proxy lock edges, SUCCESS](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43146924266).

**The source proof goes one level beyond finding a vulnerable function:** it verifies the original branch that leads to the `remove_waiter()` call AND the exact field it clears on the *current* task rather than the task associated with the waiter.

### Original actual signed ARM64 rollback branch

```asm
; rt_mutex_start_proxy_lock(lock,waiter,task)
0xffffffc01037e2d0 mov x21, x2              ; task argument kept separately
0xffffffc01037e2d4 mov x20, x1              ; waiter argument
0xffffffc01037e2d8 mov x19, x0              ; lock argument
...
0xffffffc01037e2ec bl  0xffffffc01037ddb8
0xffffffc01037e2f0 cbz w0, 0xffffffc01037e320
0xffffffc01037e2f4 mov w21, #1
0xffffffc01037e2f8 mov x0, x19              ; lock
0xffffffc01037e2fc mov x1, x20              ; waiter
0xffffffc01037e300 bl  0xffffffc01037e350 ; remove_waiter
...
0xffffffc01037e330 bl  0xffffffc01037dfb4
0xffffffc01037e338 cbz w0, 0xffffffc01037e304
0xffffffc01037e33c ldr x8, [x19, #0x18]
0xffffffc01037e340 cmp x8, #2
0xffffffc01037e344 b.hs 0xffffffc01037e2f8  ; alternate route to remove_waiter
```

The signed source therefore has **two distinct machine-code paths** converging into the `remove_waiter` invocation:
1. The original `0x37DDB8` call returns a **nonzero** value; the `cbz` is not taken, so `remove_waiter` is called directly.
2. The first call returns zero, and the subsequent `0x37DFB4` returns nonzero with the `[lock+0x18]` state compare satisfying `b.hs`; then the same `remove_waiter` call is reached.

**Important:** nonzero is **not automatically an error**. An older Linux rtmutex implementation can call `remove_waiter` for a nonzero success/status as well as for rollback; distinguishing exact semantics of every internal helper needs more function-level work. The demonstrated fact is the **branching/call structure**, not which runtime predicate a userland process can force.

### Confirmed wrong-task accesses in `remove_waiter`

```asm
0xffffffc01037e36c mov x23, x1              ; waiter pointer
...
0xffffffc01037e384 mrs x20, sp_el0          ; current task
0xffffffc01037e388 add x21, x20, #0x96c     ; current->pi_lock
0xffffffc01037e38c mov x0, x21
0xffffffc01037e390 bl  0xffffffc01192c084 ; current pi_lock operation
...
0xffffffc01037e3cc str xzr, [x20, #0x990]   ; current->pi_blocked_on = NULL
```

The field offsets `0x96C` and `0x990` were independently source-verified against the signed original FNE EEA kernel and pinned FNE Linux-5.4 struct definitions in [SUCCESS run 43144056294](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43144056294). The program has a waiter pointer in `x23`, but accesses `current` through `sp_el0` at the vulnerable lock and clearing stages.

This matches the *mechanism* in the [official Linux kernel CVE-2026-43499 disclosure](https://lists.openwall.net/linux-cve-announce/2026/05/21/7) (21 May 2026). An upstream [historical rtmutex implementation](https://code.googlesource.com/linux/torvalds/linux/+/56bf6fc266ca14d2b9276c8a62e4ff6783bfe68b/kernel/locking/rtmutex.c) identifies the API `rt_mutex_start_proxy_lock(lock,waiter,task)` as acting for another task and distinguishes the normal return/status paths.

### Whole-original-kernel reachability (static only)

An independently executed, signed source, **whole-ELF scan of 482,252 original direct ARM64 `BL` machine instructions** confirmed:

```text
do_futex
  → futex_requeue
     → rt_mutex_start_proxy_lock
        → remove_waiter (current mismatch candidate)
```

And a second direct `rt_mutex_cleanup_proxy_lock → remove_waiter` callsite. All four exact direct edges were independently hard-asserted in [SUCCESS run 43146924266](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43146924266). However, **a source call graph is not proof of unprivileged exploitability**.

## What is still unproven

- Userland-triggerable waiter/task mismatch and a reproducible UAF in this precise FNE-NX9 build.
- Correct complete memory geometry: the existing GhostLock candidate has **32 missing fields**, and `kernel_phys_load=0xfffff000` is wrongly derived from the CI runner instead of the phone.
- Any reproducible privilege escalation/root on the user's actual Android system.
- Any causal effect on hardware Secure Boot, QSEE Keymaster `0x202/0x203`, software fuse milestone, protected RPMB device state, or persistent bootloader `UNLOCKED`.

## Implications for the unlock goal

**The only strengthened line is an exact-firmware Linux kernel bug candidate.** If eventually independently validated, it could allow better OS-level diagnosis. It does **not** by itself change the original secure Keymaster milestone/fuse or allow unsigned EEA boot images. The previous original verified Keymaster source analysis already established that `0x208 is_unlocked` is a **runtime boot-state report**, not the protected `0x203` permanent lock write; [the 67-handler proof succeeded](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43145878827).

No new physical EDL flash or exploit is justified on the basis of these static findings alone. **There is still no proved permanent unlock method on this handset.**
