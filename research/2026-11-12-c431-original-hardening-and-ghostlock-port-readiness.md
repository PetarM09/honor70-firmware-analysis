# 2026-11-12 — Verified original FNE-NX9 C431 hardening and GhostLock port limitations

## Scope

Original HONOR 70 **FNE-NX9 C431 MagicOS 8.0.0.290**, exact running-kernel identity `5.4.295-qgki-ga2d8945339ca`.

The original signed `boot.img` SHA256 `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256` contains the kernel `Image` SHA256 `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`. This stock kernel embeds an exact kernel configuration with uncompressed SHA256 `99107cb0eb989d1381321f560664c78bf4b47ebdecb2cc33e9a7d430e1e973c4`.

[**Successful exact-C431 kernel hardening inventory — GitHub Actions 43287116480**](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43287116480), artifact `HONOR70_C431_VERIFIED_KERNEL_HARDENING`. Nine synthetic, fail-closed regression checks passed. No phone operation or vulnerability trigger was performed.

## What the stock binary actually compiles

| Option (verbatim original IKCONFIG) | State | Interpretation boundary |
|---|---|---|
| `CONFIG_FUTEX` | `y` | PI-futex availability is separately confirmed by owner's app screenshots |
| `CONFIG_FUTEX_PI` | `y` | Same |
| `CONFIG_RT_MUTEXES` | `y` | Present in original stock Image |
| `CONFIG_RANDOMIZE_BASE` | `y` | Kernel address randomization compiled in; not a measured runtime slide |
| `CONFIG_VMAP_STACK` | `y` | Virtual mapping for kernel stacks compiled in |
| `CONFIG_THREAD_INFO_IN_TASK` | `y` | Kernel task representation |
| `CONFIG_CFI_CLANG` | `y` | Kernel control-flow integrity compiled in |
| `CONFIG_CFI_PERMISSIVE` | `n` | The permissive option is explicitly not selected |
| `CONFIG_SHADOW_CALL_STACK` | `n` | Explicitly disabled; not equivalent to no stack protections |
| `CONFIG_ARM64_PTR_AUTH` | `y` | Architecture support option; runtime PAC coverage not proven |
| `CONFIG_ARM64_PTR_AUTH_KERNEL` | `not_listed` | **Unknown/not listed**, not the same as `n` |
| `CONFIG_STACKPROTECTOR_STRONG` | `y` | Strong stack protector compiled in |
| `CONFIG_STRICT_KERNEL_RWX` | `y` | Kernel text/data permission hardening compiled in |
| `CONFIG_STRICT_MODULE_RWX` | `y` | Module permission hardening compiled in |
| `CONFIG_HARDENED_USERCOPY` | `y` | User-copy checks compiled in |
| `CONFIG_SLAB_FREELIST_RANDOM` | `y` | Slab freelist randomization compiled in |
| `CONFIG_SLAB_FREELIST_HARDENED` | `y` | Slab freelist hardening compiled in |
| `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` | `y` | Default-on allocation initialization compiled in |
| `CONFIG_INIT_ON_FREE_DEFAULT_ON` | `n` | Explicitly off |
| `CONFIG_KASAN` | `n` | No KASAN diagnostic instrumentation compiled in |
| `CONFIG_SECCOMP_FILTER` | `y` | App screenshot additionally confirmed running `Seccomp: 2` |
| `CONFIG_SECURITY_SELINUX` | `y` | App screenshot additionally confirmed `u:r:untrusted_app` |
| `CONFIG_PREEMPT` | `y` | Preemptive kernel configured |

Values are taken from the **original exact kernel**; HONOR's Fennie 5.4.242 and Chinese FNE-AN00 source are reference points only. `not_listed` means no explicit assignment in this signed IKCONFIG; it is **not** evidence of disabled runtime behavior.

## Concrete GhostLock readiness status (do not confuse static linkage and exploit success)

| Prerequisite | Status | Evidence |
|---|---|---|
| Real CVE-2026-43499 wrong-task `remove_waiter` code pattern | **Found** | Signed C431 ARM64 and HONOR GPL static comparison |
| Native PI futex from ordinary Android app | **Passed** | Owner photograph: `APP_PI_FUTEX_OK`, `untrusted_app`, `Seccomp:2` |
| Deliberately invalid early PI requeue dispatch | **Consistent with passing** | Owner photograph: identical addresses → `EINVAL` |
| Complete original futex → proxy → rollback call chain | **Found** | SHA-verified exact C431 disassembly |
| Inlined waiter implementation in original `do_futex` | **Strong original binary evidence** | Signed kernel waiter helper calls, local pointer provenance |
| Predicted waiter/select stack overlap | **Only a conditional 80-byte arithmetic intersection** | No proven same-stack reuse or user-controlled write over overlap |
| Actual device UAF or vulnerable rollback event | **Not demonstrated** | Earlier app tests intentionally avoid queue operations |
| Full exact target profile, memory geometry and reliable privilege primitive | **Not demonstrated** | Previous candidate had many null fields and an invalid CI-host `kernel_phys_load` assumption |
| Reproducible temporary root on this exact phone | **Not demonstrated** | No running root proof |
| Permanent bootloader unlocked state | **Not demonstrated** | Authenticated secure-world bootloader state is separate |

The upstream [Linux CVE advisory for CVE-2026-43499](https://lists.openwall.net/linux-cve-announce/2026/05/21/7) confirms the underlying wrong-task cleanup and UAF risk. It does not claim this specific FNE-NX9 can be rooted using a particular public exploit.

## Why simply copying the FNE-AN00 profile is not a valid C431 port

- Public [MSEDGE-CORE/GhostLock-HonorFne](https://github.com/MSEDGE-CORE/GhostLock-HonorFne) documents Chinese HONOR 70 FNE-AN00 and other different releases, **not exact** `5.4.295-qgki-ga2d8945339ca`.
- Other public GhostLock registries match on the exact kernel release and refuse mismatches. Thus similar Linux version numbers cannot establish payload compatibility.
- The original signed C431 kernel has confirmed compile-time KASLR, nonpermissive Clang CFI, VMAP_STACK, strong stack protector and hardened usercopy; their effect on any particular exploitation method needs separate runtime evidence.
- The earlier host-derived `0xfffff000` `kernel_phys_load` candidate was not a phone measurement. **Do not treat it as a device address**.
- The existing conditional 80-byte arithmetic intersection assumes reused kernel-stack origin and has **not shown a user-controlled overwrite**. An overlap of two nominal address ranges alone is insufficient.
- Privilege escalation, even if eventually found, does not itself bypass signed boot-chain and Keymaster/RPMB authentication for persistent unlock.

## Reproduction

- [Exact-stock hardening collector](../tools/audit_c431_original_kernel_hardening.py)
- [Nine hardening evidence tests](../tools/test_audit_c431_original_kernel_hardening.py)
- [SHA-verified read-only CI](../.github/workflows/audit-c431-original-kernel-hardening.yml)
- [Original conditional stack calculation](../tools/audit_c431_conditional_stack_geometry.py)

**Outcome:** original signed kernel hardening is now determined; neither its presence nor the confirmed static CVE-related code is a ready-to-run root exploit. This report intentionally does not include a vulnerability trigger, UAF manipulation, kernel address bypass, root payload or EDL write.
