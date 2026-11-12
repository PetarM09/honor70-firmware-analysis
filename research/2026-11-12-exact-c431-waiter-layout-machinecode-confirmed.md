# 2026-11-12 — Original C431 `rt_mutex_waiter` field offsets confirmed (source + machine code)

## Target and verification

- Phone: HONOR 70 **FNE-NX9**, C431 MagicOS 8.0.0.290, kernel `5.4.295-qgki-ga2d8945339ca`.
- Original signed retail `boot.img` SHA256: `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256`.
- Exact extracted `Image` SHA256: `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`.
- HONOR Fennie MagicOS 8 GPL `kernel/locking/rtmutex.c` SHA256: `70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9`.
- HONOR GPL `kernel/locking/rtmutex_common.h` SHA256: `c79353d84625e4d352be7d96193cf162fba7857a85171540996f499679ea3d08`.
- **[Successful direct source + original ARM64 19-site verification](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43229427485)**. Six negative/regression tests passed. Generated artifact: `HONOR70_C431_VERIFIED_WAITER_FIELDS`.
- Original machine-code register-flow inspection: [success run 43228734050](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43228734050).

These results do not rely on FNE-AN00 profile guesses. They are a **read-only reconstruction of four struct field offsets in the actual signed C431 binary**, not an exploit.

## Exact `task_blocks_on_rt_mutex` register-to-field proof

At `0xffffffc01037dfb4`, original `task_blocks_on_rt_mutex` takes AArch64 arguments `x0=lock`, `x1=waiter`, `x2=task`. From signed C431 code:

```asm
0xffffffc01037dfe0  mov x19, x0             ; lock
0xffffffc01037dfec  mov x20, x2             ; task
0xffffffc01037dff0  mov x22, x1             ; waiter
0xffffffc01037dff8  stp x20, x19, [x22,#0x30] ; waiter.task/lock
0xffffffc01037dffc  ldr w8, [x20,#0x11c]    ; task.prio
0xffffffc01037e004  str w8, [x22,#0x40]     ; waiter.prio
0xffffffc01037e008  ldr x10, [x20,#0x488]   ; task.dl.deadline
0xffffffc01037e00c  str x10, [x22,#0x48]    ; waiter.deadline
0xffffffc01037e0c0  str x22, [x20,#0x990]   ; task.pi_blocked_on = waiter
```

The corresponding HONOR GPL source contains exactly `waiter->task=task`, `waiter->lock=lock`, `waiter->prio=task->prio`, `waiter->deadline=task->dl.deadline`.

| Original signed FNE-NX9 C431 field | Byte offset | Proof |
|---|---:|---|
| `rt_mutex_waiter.task` | **`0x30`** | `stp x20,x19,[x22,#0x30]` where `x20=task` |
| `rt_mutex_waiter.lock` | **`0x38`** | Adjacent 64-bit store with `x19=lock` and separate dereferences |
| `rt_mutex_waiter.prio` | **`0x40`** | `str w8,[x22,#0x40]` after loading `task.prio` |
| `rt_mutex_waiter.deadline` | **`0x48`** | `str x10,[x22,#0x48]` after loading task deadline |

Independent original C431 `rt_mutex_init_waiter` clears `[waiter+#0x30]` at `0xffffffc01037db0c`. Original `rt_mutex_adjust_prio_chain` loads `x25=[task+#0x990]`, then reads `[x25+#0x38]`, `[x25+#0x40]` and `[x25+#0x48]`. Thus source and two independently examined C431 consumers corroborate the assignments.

## Why this is highly relevant to the GhostLock port

The existing FNE-AN00 public port's [static `target.h` fallbacks](https://github.com/MSEDGE-CORE/GhostLock-HonorFne/blob/main/root/exploit/src/core/target.h) include `WAITER_TASK_OFF=0x50` and `WAITER_LOCK_OFF=0x58`. Those **fallback values do not describe this original C431 `rt_mutex_waiter` layout**. Whether the port overrides them in a given build must be audited separately. Applying those two offsets to the present C431 structure as if verified would be incorrect.

Previous signed-C431 task-side evidence also showed `task_struct.pi_lock=0x96c` and `task_struct.pi_blocked_on=0x990`. The original `remove_waiter` still does `mrs x20,sp_el0` and `str xzr,[x20,#0x990]` instead of clearing the protected pointer for `waiter->task` when those differ. This connects the source-described CVE-2026-43499 rollback defect to the original phone build. It **does not prove that a third-party Android process can provoke the vulnerable lifetime conditions**.

## What is *not* solved

- The recovered exact waiter field layout is **not** a complete kernel exploit profile. Many other original candidate fields remain unresolved; no validated handset physical kernel load, address-translation geometry or controlled root path exists.
- HONOR's Fennie GPL tree uses Linux 5.4.242 and its scheduler configuration has conditionally added fields compared with the MagicUI 6.1 tree. Consequently, do **not** infer remaining `task_struct`, credential, `file_operations`, security, timer or memory geometry directly from those published sources without original binary validation.
- No reproducible, authorized low-privilege runtime trigger, UAF-to-root transition, or post-reboot `UNLOCKED` state has been shown. Kernel root would not imply Keymaster / QSEE / RPMB bootloader state change.
- **No EDL write, phone operation, exploit trigger or firmware modification was attempted.**

## Reproducibility

- [Exact signed ELF ARM64 register-flow collector](../tools/inspect_exact_c431_rtmutex_abi.py)
- [Fail-closed original binary + GPL 19-site assertion](../tools/assert_exact_c431_waiter_field_evidence.py)
- [Six synthetic negative/positive regression tests](../tools/test_assert_exact_c431_waiter_field_evidence.py)
- [Completed CI workflow](../.github/workflows/assert-exact-c431-waiter-layout.yml)

**Conclusion:** Four essential `rt_mutex_waiter` field positions are now source- and byte-verified for the exact FNE-NX9 C431 build. This is a significant static porting prerequisite achieved, but **not a working GhostLock root exploit or permanent bootloader unlock**.
