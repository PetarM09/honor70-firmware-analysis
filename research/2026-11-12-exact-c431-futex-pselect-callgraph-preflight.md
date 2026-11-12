# 2026-11-12 — Exact FNE-NX9 C431 futex/pselect direct-call preflight

## Scope and provenance

This is a **read-only static feasibility preflight**, not a GhostLock exploit. Original stock HONOR 70 **FNE-NX9 C431**, MagicOS 8.0.0.290, exact kernel `5.4.295-qgki-ga2d8945339ca`.

- Signed `boot.img` SHA256: `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256`.
- Extracted original `Image` SHA256: `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`.
- [**Successful GitHub Actions run 43278166210**](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43278166210); original ARM64 ELF reconstructed under SHA checks, **8 of 8 synthetic regression tests passed**.
- Artifact: `HONOR70_C431_ORIGINAL_FUTEX_PSELECT_GRAPH`, contains `ORIGINAL_C431_FUTEX_PSELECT_CALLGRAPH.json` and CI logs. **8 of 12 watched symbols found, 10 direct call edges to watched functions**.

## Direct original ARM64 edges

| Calling function | Source instruction (original VA) | Direct callee |
|---|---|---|
| `__arm64_sys_futex` | `0xffffffc0103cc094` | `do_futex` |
| `do_futex` | `0xffffffc0103c91a8` | `futex_requeue` |
| `futex_requeue` | `0xffffffc0103cb3f8` | `rt_mutex_start_proxy_lock` |
| `__arm64_sys_pselect6` | `0xffffffc010563a80` | `core_sys_select` |
| `core_sys_select` | `0xffffffc010562c34`, `0xffffffc010562c4c`, `0xffffffc010562c64` | `get_fd_set` |
| `core_sys_select` | `0xffffffc010562cd0`, `0xffffffc010562ce4`, `0xffffffc010562cf8` | `set_fd_set` |

Each edge was identified from decoded direct `bl` or `b` operands pointing to separately recovered text symbol addresses in the exact stock ELF. This is stronger than inferring a path from similarly named HONOR GPL source alone.

## Original function entry stack adjustments

| Function | Entry stack adjustment(s) | Combined initial reserved bytes |
|---|---|---:|
| `__arm64_sys_futex` | `sub sp,sp,#0x70` | `0x70` |
| `do_futex` | `stp x29,x30,[sp,#-0x60]!` then `sub sp,sp,#0x1c0` | `0x220` |
| `futex_requeue` | `sub sp,sp,#0x160` | `0x160` |
| `rt_mutex_start_proxy_lock` | `stp x29,x30,[sp,#-0x30]!` | `0x30` |
| `__arm64_sys_pselect6` | `sub sp,sp,#0x90` | `0x90` |
| `core_sys_select` | `sub sp,sp,#0x1c0` | `0x1c0` |

**These are function entry stack reservations, not measured kernel-stack-overlap offsets.** Compiler optimization and ABI local-variable placement can change whether the user's temporary bytes align with a freed waiter, even with identical syscall support.

## Symbols not present as separately named exact-text entries

- `futex_wait_requeue_pi` — **not found** as a separate original text symbol.
- `__se_sys_futex`, `__se_sys_pselect6`, `do_pselect` — **not found** as separate original text symbols.

Absence does not prove inlining, optimization away, inability to call the kernel functionality, or infeasibility. However, **the exact C431 layout must be checked** rather than borrowing the feasible waiter placement from unrelated OnePlus/HONOR builds.

## What public GhostLock projects tell us (external reference, not proof of C431 status)

[JoinChang/ghostlock-oneplus: stack-layout feasibility](https://github.com/JoinChang/ghostlock-oneplus#stack-layout-feasibility) documents confirmed working and non-working build profiles where `pselect6` kernel-stack reuse depends on compiler PGO/LTO, function call depth and placement in `stack_fds`. The upstream table does **not** verify this FNE-NX9 kernel. We therefore neither endorse nor reject that exploit technique on this specific handset.

## Current evidence classification

- Original C431 has real `__arm64_sys_futex -> do_futex -> futex_requeue -> rt_mutex_start_proxy_lock` direct calls.
- Original C431 has real `__arm64_sys_pselect6 -> core_sys_select` direct call and fd_set-copy helpers.
- `do_futex` reserves `0x220` bytes at entry, whereas `core_sys_select` reserves `0x1c0`; the actual local waiter position and alignment are **unknown**, and no positive pselect stack-overlap test was performed.
- Owner's already reported real-app basic `APP_PI_FUTEX_OK` and invalid `CMP_REQUEUE_PI` `EINVAL` tests do not reach the waiter lifetime or kernel UAF.
- **No live GhostLock UAF, controlled kernel R/W, root or bootloader unlock.** No phone operation was needed for this run.

### Next genuinely different offline question

Determine whether `futex_wait_requeue_pi` was inlined into a larger C431 function and establish a safe, source-attributed map of the original local waiter object. Do not claim overlap feasibility based on `nm` symbols alone, nor run a borrowed-profile payload with unknown phys load and remaining unresolved offsets.

**Reproducibility:** [original-ELF read-only collector](../tools/audit_c431_futex_pselect_callgraph.py), [eight tests](../tools/test_audit_c431_futex_pselect_callgraph.py), [CI workflow](../.github/workflows/audit-c431-futex-pselect-callgraph.yml).
