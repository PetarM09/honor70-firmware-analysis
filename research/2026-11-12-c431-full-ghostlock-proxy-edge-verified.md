# 2026-11-12 — Full original C431 futex-to-rtmutex proxy call edge confirmed

**Scope:** offline static verification only. Target is owner-operated HONOR 70 FNE-NX9 C431, MagicOS 8.0.0.290, exact kernel `5.4.295-qgki-ga2d8945339ca`. **No GhostLock trigger, UAF, root, EDL write or bootloader unlock was executed.**

## Three independent evidence layers

### A. Original phone's signed kernel

- Stock C431 `boot.img` SHA-256: `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256`.
- Original extracted `Image` SHA-256: `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`.
- Exact recovered ARM64 ELF function `futex_requeue` begins at `0xffffffc0103ca4d8`. Nearest next text symbol begins at `0xffffffc0103cb884`; original function region is exactly **5036 bytes**, digest `1c392836dc77856de0eb2070505c1b0f498ea8f2a110773b2941010b271281b8`.
- [Completed CI 43275022781](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43275022781) found **one exact direct ARM64 `bl` instruction** at `0xffffffc0103cb3f8` targeting `rt_mutex_start_proxy_lock` at `0xffffffc01037e2c0`. Seven synthetic regression tests passed.
- At that callsite the previous register setup is:

```asm
0xffffffc0103cb3e4  ldr x1, [x24, #0x48]
0xffffffc0103cb3e8  ldr x2, [x24, #0x10]
0xffffffc0103cb3f0  ldr x0, [sp, #0x28]
0xffffffc0103cb3f4  str x8, [x24, #0x40]
0xffffffc0103cb3f8  bl  #0xffffffc01037e2c0
0xffffffc0103cb3fc  mov w26, w0
0xffffffc0103cb400  cbz w0, #0xffffffc0103cb438
```

The original C431 `futex_requeue` wrapper therefore genuinely calls the target proxy-lock function, rather than merely containing unrelated strings or compile-time support.

### B. Original proxy rollback to wrong-task cleanup

[Completed CI 43274625423](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43274625423) checked **18 exact original ARM64 sites** in `rt_mutex_start_proxy_lock`, `task_blocks_on_rt_mutex`, and `remove_waiter`, against SHA-pinned HONOR reference sources. Ten regression tests passed.

- `rt_mutex_start_proxy_lock` copies its task argument from `x2`, waiter from `x1` and lock from `x0`, then directly calls original `remove_waiter` at `0xffffffc01037e350` on its compiled nonzero-return path (direct BL at `0xffffffc01037e300`).
- `task_blocks_on_rt_mutex` stores the proxy waiter task pointer into the waiter structure and sets **that** task's `pi_blocked_on` at offset `0x990`.
- `remove_waiter` instead uses `mrs x20, sp_el0` to obtain **current**, locks current's `pi_lock` at `0x96c` and clears `[current+0x990]` at `0xffffffc01037e3cc`. In proxy rollback `waiter->task` and `current` can differ: this matches the officially described **CVE-2026-43499** wrong-task cleanup defect.

### C. Source compatibility and runtime evidence

The HONOR Fennie MagicOS 8 GPL `kernel/futex.c`, hash `71b9c7591dc611e6f92e742858bcc044cf01b605208058498e31d444b7704106`, contains the matching caller with `this->rt_waiter` and `this->task` arguments. `kernel/locking/rtmutex.c`, hash `70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9`, contains the same incorrect current-based `remove_waiter` cleanup. **Caution:** this GPL source tree declares base Linux 5.4.242, whereas the signed original kernel is 5.4.295. The actual signed ARM64 call and cleanup evidence above are the primary proof.

**Important nuance:** `struct futex_q` in the published source has `__randomize_layout`; it also conditionally includes HONOR VIP fields. Thus the `x24+0x10`, `x24+0x40`, `x24+0x48` accesses in the actual caller provide concrete compiled evidence; deriving other structure offsets merely from declaration order would be unsound without the matching compiler layout seed.

**On-device:** the user already demonstrated `APP_PI_FUTEX_OK` and (in v0.2) intentionally invalid equal-address `FUTEX_CMP_REQUEUE_PI` returns `-EINVAL` (`errno=22`) from Android `untrusted_app` with `Seccomp:2`. Those calls do **not** reach the waiter/proxy/rollback region.

## Further upstream nuance: nonzero versus negative result

The old HONOR source has `if (unlikely(ret)) remove_waiter(lock, waiter)`. Proxy-lock APIs document `ret=1` as **successful immediate acquisition** and negative values as failure. An upstream follow-up fix, tracked as CVE-2026-53163, changed the condition to `ret < 0` and added a NULL waiter-task guard, because positive returns or an error before enqueue must not attempt the same cleanup. This official downstream discussion is instructive but is **not** independent evidence of an additional working exploit on this C431 handset.

- Linux CVE team description of wrong-task rollback: https://lists.openwall.net/linux-cve-announce/2026/05/21/7
- Follow-up upstream patch as reproduced in Ubuntu kernel list: https://lists.ubuntu.com/archives/kernel-team/2026-July/170235.html

## Evidence ladder — what we have and do not have

| Research requirement | Current evidence |
|---|---|
| Stock kernel supports futex PI | **Confirmed** from original embedded IKCONFIG |
| Normal app can perform PI lock/unlock | **Confirmed** by owner screenshot, `untrusted_app` |
| Normal app can reach invalid PI-requeue early guard | **Consistent with successful** owner screenshot, `EINVAL` (single errno cannot uniquely attribute guard) |
| Exact stock `futex_requeue` calls `rt_mutex_start_proxy_lock` | **Confirmed** direct original ARM64 BL |
| Exact stock proxy wrapper can call `remove_waiter` | **Confirmed** direct ARM64 BL and compiled control flow |
| Exact stock cleanup uses `current` instead of the proxy waiter task | **Confirmed** ARM64 registers + HONOR GPL interpretation |
| Live vulnerable rollback on FNE-NX9 | **Not demonstrated** |
| Controlled kernel UAF / exploit primitives | **Not demonstrated** |
| Temporary root | **Not demonstrated** |
| Permanent authenticated bootloader unlock | **Not demonstrated** |

**Conclusion:** the exact signed retail C431 kernel has now been shown to contain the complete relevant *static code linkage* to the CVE-2026-43499 wrong-task cleanup, not just an analogous older source. **An exploit is not thereby proven**, and physical-address/32-null profile guesses must not be used to jump directly to a root attempt.
