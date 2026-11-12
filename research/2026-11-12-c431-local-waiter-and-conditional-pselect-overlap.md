# 2026-11-12 — Exact FNE-NX9 C431 waiter inlining and conditional select stack interval

## Target and scope

**Device:** personally owned HONOR 70 FNE-NX9 C431 MagicOS 8.0.0.290, original `5.4.295-qgki-ga2d8945339ca`. All work here is **read-only offline** with the original, SHA-256 verified stock firmware and the separately SHA-verified HONOR Fennie GPL `kernel/futex.c`.

- Original `boot.img` SHA256: `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256`
- Original kernel `Image` SHA256: `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`
- Original recovered `do_futex` function 6452-byte SHA256: `dafc0e0138313ba88c2bbaad6fdd71509561325ce232bcbd19ea1e4f98a6108a`
- Original `core_sys_select` 608-byte SHA256: `244a0f29b764672a7ec642a7dc469a156777dd352d12379fcf52ecc6b0d53fd2`
- Original `__arm64_sys_pselect6` 980-byte SHA256: `0f24235338d5ddb266220076c0cdf28fbf1346401fbd9655985b0903054cb4ca`
- HONOR Fennie GPL `kernel/futex.c` SHA256: `71b9c7591dc611e6f92e742858bcc044cf01b605208058498e31d444b7704106`

## 1. Local `rt_mutex_waiter` really occurs in original `do_futex` compiled code

[Successful stock-C431 ARM64 inspection, CI 43281477811](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43281477811) decoded the complete exact 6,452-byte `do_futex` function and captured 79 direct `bl` calls, 115 syntactic `sp` references, and 14 `sp`-address computations. Eight regression tests passed.

In HONOR's GPL `futex_wait_requeue_pi()` a `struct rt_mutex_waiter rt_waiter` and a `struct futex_q q` are locally allocated. This source function is based on Linux 5.4.242 rather than the exact 5.4.295 retail revision; **the original C431 binary is independently checked** below.

Distinct relevant helper calls seen inside original `do_futex`:

| Original signed ARM64 callsite | Direct callee |
|---|---|
| `0xffffffc0103c96e4` | `rt_mutex_init_waiter` |
| `0xffffffc0103c9724` | `futex_wait_setup` |
| `0xffffffc0103c9800` | `futex_wait_queue_me` |
| `0xffffffc0103c9864` | `rt_mutex_wait_proxy_lock` |
| `0xffffffc0103c9884` | `rt_mutex_cleanup_proxy_lock` |

The original binary computes the same waiter pointer, `x29 - 0xd0`, before initializing, proxy-waiting and cleanup. It separately computes `sp + 0x70` for the futex queue, which is passed to its setup and queue-me routines.

At function entry:

```asm
0xffffffc0103c84e4  stp x29, x30, [sp, #-0x60]!
0xffffffc0103c84fc  mov x29, sp
0xffffffc0103c8500  sub sp, sp, #0x1c0
```

The arithmetic relation of the waiter pointer to the post-prologue stack pointer is `(x29 - 0xd0) = (sp + 0x1c0 - 0xd0) = sp + 0xf0`, **subject to SP remaining at the entry-prologue frame depth along the relevant path**.

[Successful independently checked pointer provenance, CI 43282279278](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43282279278): 9 exact ARM64 instruction assertions and 5 helper-call checks; 9 synthetic negative/positive tests passed.

This is compelling evidence the relevant wait-requeue implementation has been compiled into the original `do_futex` function. The absence of a separate `futex_wait_requeue_pi` symbol is consistent with inlining; static evidence still does **not** constitute an observed use-after-free.

## 2. Conditional static interval arithmetic against `pselect6`

The original `__arm64_sys_futex` reserves `0x70` bytes before entering `do_futex`, which reserves `0x60 + 0x1c0 = 0x220` bytes. The original waiter pointer is `do_futex`'s post-prologue SP `+0xf0`. From its last source/binary-verified field (`deadline` at waiter +`0x48` and 8-byte length), the **minimum observed waiter span** is `0x50` bytes.

The original `__arm64_sys_pselect6` reserves `0x90` bytes before calling `core_sys_select`, which reserves `0x1c0`. This helper forms `x23 = sp + 0x50`, then passes it to `get_fd_set`; the original prologue also clears a local stack region up to at least `[sp + 0x140, sp + 0x150)`. This is **syntactic stack-buffer evidence**, not a proof that every byte of that range can be copied from userspace.

**Only for the mathematical hypothesis that both paths enter with the same kernel-thread SP:**

| Interval relative to a hypothetical common entry SP | Start | End (exclusive) |
|---|---:|---:|
| Minimum waiter field region | `-0x1a0` | `-0x150` |
| Candidate select stack region | `-0x200` | `-0x100` |
| Intersection | `-0x1a0` | `-0x150` |

The **conditional arithmetic intersection is 0x50 = 80 bytes**.

[Successful conditional interval CI 43283106736](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43283106736) verified exact signed C431 prologues, function hashes, direct syscall-to-helper edges and the observed select base, with **eight synthetic regression tests passed**.

**Three critical facts remain unproven**:

1. That the two particular executions in a real exploit run begin at the same effective kernel-stack origin and reproduce this static mapping, including the relevant branch-specific SP changes and scheduling transitions.
2. That the select-side bytes overlapping the hypothetical waiter region are actually user-controllable on this specific phone and for a sufficient byte span; source-level zeroing alone is not a user-controlled write primitive.
3. That an actual `rt_mutex_waiter` survives as a dangling pointer on the user's phone, is reused under these conditions, and produces a controlled kernel operation.

Thus **this is a conditional static compatibility indicator, not a working GhostLock exploit, kernel memory primitive, temporary root or bootloader unlock**. Do not turn the computed region into a borrowed, executable UAF payload.

## Reproduction and audit files

- [Source+signed-ELF stack evidence extractor](../tools/audit_c431_waiter_local_source_binary.py)
- [Eight original disassembly parser tests](../tools/test_audit_c431_waiter_local_source_binary.py)
- [Independent source+instruction pointer verifier](../tools/verify_exact_c431_inlined_waiter_provenance.py)
- [Nine strict verifier tests](../tools/test_verify_exact_c431_inlined_waiter_provenance.py)
- [Conditional stack interval calculator](../tools/audit_c431_conditional_stack_geometry.py)
- [Eight static geometry tests](../tools/test_audit_c431_conditional_stack_geometry.py)

**Research status as of 2026-11-12:** exact binary wait-requeue helper path confirmed, stack-local waiter pointer strongly attributed, conditional stack intervals calculated; no live GhostLock rollback/UAF or root. No new operation on the phone is required to reproduce these offline findings.
