# 12 November 2026 — Exact retail C431 GhostLock kernel candidate: original remove_waiter signal, incomplete profile, no permanent unlock

**Device:** HONOR 70 FNE-NX9 EEA, MagicOS 8.0.0.290(C431E4R3P1), original kernel `5.4.295-qgki-ga2d8945339ca`.

## Grounded original source identity

- `boot.img`: `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256`
- extracted original kernel `Image`: `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`
- [Original unmodified signed EEA boot image export (run 42530238358)](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42530238358)
- [Original matching kernel kallsyms/profile extraction (run 42530618542)](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42530618542)
- [Independent source-asserted candidate safety audit run 43143170752](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43143170752), status **SUCCESS**.
- [Safety assertion source](../tools/audit_prior_stock_ghostlock_profile_incompleteness.py).

The original release is an archive of the exact retail FNE-NX9 EEA firmware, not the nearby Chinese FNE-AN00 model. The source extraction rebuilt **204,661 kallsyms lines** from the exact EEA kernel.

The upstream Rust extractor emitted this precise diagnostic:

```text
info: (CVE-2026-43499 primitive present (remove_waiter@0x2fe350 still uses current)
warning: embedded BTF not found; symbols come from kallsyms and struct offsets fall back to target.h defaults
warning: 5.4.295-qgki-ga2d8945339ca is unverified; no family-derived geometry will be emitted
warning: pselect_waiter_shift unavailable; no family fallback is defined for this release
warning: rt_mutex_waiter task/lock offsets are missing from BTF; the multicast geometry is partial
```

**Interpretation:** an *offline static signal* of code associated with the GhostLock primitive has been found in the **correct EEA kernel**. This does not establish triggerability, the availability of controlled writes, or reproducible privilege escalation. The original upstream executable itself rejects missing geometry.

## New separate check: original machine instructions corroborate the `remove_waiter` observation

A new independent [signed EEA kernel ARM64 analysis](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43143437566) reconstructed symbols from the **original matched 8.0.0.290 kernel**, checked the exact `boot.img` and `Image` SHA256 digests, and found `remove_waiter` at virtual address `0xffffffc01037e350` (relative to typical `_text` base `0xffffffc010080000`, offset **`0x2fe350`**, agreeing with the previously independent extractor). Unlike untrusted diagnostic text, the source contains actual ARM64 instructions:

```asm
0xffffffc01037e380  ldr x24, [x19, #0x18]
0xffffffc01037e384  mrs x20, sp_el0
0xffffffc01037e388  add x21, x20, #0x96c
0xffffffc01037e38c  mov x0, x21
0xffffffc01037e390  bl  0xffffffc01192c084
```

In the ARM64 Linux kernel, **`mrs x20, sp_el0`** reads the thread's current task pointer in this context, consistent with the earlier GhostLock profile tool's assessment that `remove_waiter` still uses `current`. This is a **new, byte-backed source observation on the correct European build**, rather than an inference from the Chinese kernel's known offsets.

The disassembly does **not** by itself prove the CVE's use-after-free can be triggered, that the many required C data-structure offsets are known, or that root can be achieved. It certainly does **not** bypass verified boot or the separate Keymaster fuse gate. Do not run precompiled FNE-AN00 exploit binaries against this unverified profile.

## One step further: two EEA task-lock offsets verified in machine code

A separate code-level validator cross-checked the exact retail kernel disassembly against the pinned common FNE Linux 5.4 struct layout and **passed** in [CI run 43144056294](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43144056294). The machine-code identity audit also passed after excluding the unrelated BSS symbol `klist_remove_waiters` in [CI run 43143727454](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43143727454).

The original exact EEA instructions:

```asm
0xffffffc01037e384  mrs x20, sp_el0
0xffffffc01037e388  add x21, x20, #0x96c
...
0xffffffc01037e3cc  str xzr, [x20, #0x990]
```

Those offsets match two fields in the pinned upstream FNE 5.4 common layout:

| Field | Byte offset | Origin of evidence |
|---|---:|---|
| `task_pi_lock` | `0x96C` | Current task pointer from `sp_el0`, `add x21,x20,#0x96c`, followed by lock helper call |
| `task_pi_blocked_on` | `0x990` | `str xzr,[x20,#0x990]` in the same original function |

This is valuable *source-level corroboration* for exactly **two** fields on this retail kernel. It does not supply a valid `GhostLock` exploitation profile, the phone-specific physical load address, the full waiter geometry, credential fields or any persistent bootloader state transition. [Reproducible checker](../tools/crosscheck_eea_remove_waiter_pi_layout.py).

## Important verified safety problems

The independent audit of the extractor's `HONOR70_CANDIDATE.conf` found:

1. **32 distinct `null` profile fields**, including critical `task_struct`, waiter `task_offset`/`lock_offset` and credential layout details. The kernel has no embedded BTF and the extractor explicitly declined to fabricate missing geometry.
2. The candidate contains **`kernel_phys_load = 4294963200` (`0xfffff000`)** derived from the **GitHub Actions runner's HOST `/proc/iomem`**, not a Qualcomm/HONOR handset value. It must not be copied into a phone exploit.
3. The public Chinese FNE-AN00 GhostLock profiles (such as `5.4.295-qgki-g0fb2656b2b50`) are for **different exact kernels**. Using those hard-coded offsets against `5.4.295-qgki-ga2d8945339ca` could corrupt arbitrary kernel addresses.
4. Even a proven **temporary Android kernel root** would not establish the protected bootloader lock transition in TrustZone Keymaster, let alone persistence across cold boot.

Both the upstream [FNE profile](https://github.com/MSEDGE-CORE/GhostLock-HonorFne/blob/1cdaebd47bf34fa29d95b0b9e929f360cfe8b8fb/root/exploit/src/devices/fne/offsets.h) and the matched EEA candidate were checked in the same CI run.

## Next useful question

An original [ARM64 function-level review of `remove_waiter`](../tools/audit_exact_eea_kernel_remove_waiter_arm64.py) has been added to the repo with an automated job [`audit-exact-eea-remove-waiter-arm64.yml`](../.github/workflows/audit-exact-eea-remove-waiter-arm64.yml). That reviewer verifies the signed exact stock kernel hashes, reconstructs symbols and extracts read-only original disassembly. **No source offset or exploitable kernel memory geometry should be inferred until the machine code and original symbol provenance are confirmed.**

A potential future diagnostic advantage would require exact machine code, correct layout, measured phone-only kernel physical mapping and an independent evaluation of privilege escalation. It would **still** require separate evidence for a Keymaster/RPMB permanent bootloader unlock.

**Status:** no kernel exploit has been executed, no permanent bootloader unlock has been demonstrated, and no EDL write was performed in this investigation. The prior handset bootloader remains last observed as **LOCKED**.
