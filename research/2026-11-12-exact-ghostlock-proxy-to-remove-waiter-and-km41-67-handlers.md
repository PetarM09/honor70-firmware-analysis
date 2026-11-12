# HONOR 70 — 12 Nov 2026: Exact C431 GhostLock source path and all 67 KM41 commands

**Device / build:** HONOR 70 **FNE-NX9** (EEA C431), MagicOS **8.0.0.290**, kernel `5.4.295-qgki-ga2d8945339ca`.

**Method:** original source-hash verified signed firmware; static ARM64 disassembly, Ghidra source-decompilation, source-asserted GitHub Actions. **No physical handset was connected or modified.** No exploit was executed. **No permanently unlocked state has been demonstrated.**

## 1. CVE-2026-43499: exact stock European kernel confirms the vulnerable source pattern

The [official Linux CVE announcement dated 21 May 2026](https://lists.openwall.net/linux-cve-announce/2026/05/21/7) states that the problem in `rtmutex` was **introduced in Linux 2.6.39**, not only in versions 5.7 and later as an unrelated README suggests. In the `rt_mutex_start_proxy_lock()` rollback path, `remove_waiter()` may wrongly use the task executing `current` rather than `waiter->task`, potentially leaving a dangling `pi_blocked_on` pointer / use-after-free.

Our original **stock** signed EEA sources:

- `boot.img` SHA256 `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256`.
- original `Image` SHA256 `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`.
- [Independent signed kernel symbol and direct-call analysis, success run 43145768042](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43145768042).
- [Source-asserted ARM64 analysis script](../tools/audit_eea_futex_proxy_lock_cve_path.py).
- [Source-pinned GitHub workflow](../.github/workflows/audit-eea-futex-proxy-lock-cve-path.yml).

**New exact machine-code fact**: on this EEA build, the actual `rt_mutex_start_proxy_lock` code calls the original `remove_waiter` with a **direct ARM64 BL**:

```asm
0xffffffc01037e2c0   ; rt_mutex_start_proxy_lock function begins
0xffffffc01037e300   bl 0xffffffc01037e350  ; remove_waiter
0xffffffc01037e350   ; remove_waiter function begins
...
0xffffffc01037e384   mrs x20, sp_el0        ; current task
0xffffffc01037e388   add x21, x20, #0x96c
...
0xffffffc01037e3cc   str xzr, [x20, #0x990]
```

The two current-task offsets `0x96C` and `0x990` are independently verified against the FNE kernel 5.4 `task_pi_lock` / `task_pi_blocked_on` struct layout in [successful CI 43144056294](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43144056294). The pre-rollback and `remove_waiter` instruction coordinates are **original retail source values**, not assumed Chinese FNE-AN00 offsets.

Also recovered from signed C431 EEA `vmlinux`:

| Symbol | EEA original VA | Source-backed status |
|---|---|---|
| `rt_mutex_start_proxy_lock` | `0xffffffc01037e2c0` | Directly invokes `remove_waiter` at `+0x40` |
| `remove_waiter` | `0xffffffc01037e350` | Uses `current` via `sp_el0` |
| `futex_requeue` | `0xffffffc0103ca4d8` | Code present; complete runtime triggering condition not proven |
| `__arm64_sys_futex` | `0xffffffc0103cbfd4` | Syscall code present; no exploit executed |
| `rt_mutex_adjust_prio_chain` | `0xffffffc01037d334` | Referenced from `remove_waiter`, consistent with the official bug description |

**Conservative scope:** this now establishes **the exact vulnerable call/use-current code structure** in the real signed HONOR EEA kernel; it does **not** prove an achievable UAF trigger, reliable address selection, arbitrary write, successful temporary root or persistent bootloader unlock.

The earlier [candidate GhostLock profile safety verification](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43143170752) detected **32 missing `null` fields** and a wrongly assumed `kernel_phys_load = 0xfffff000` taken from the GitHub Actions HOST's `/proc/iomem`, **not** from the phone. Do not execute the original FNE-AN00 exploit with those data. Unlike the genuine ARM64 code finding, this guessed physical address is incorrect source attribution.

## New whole-kernel call-graph verification — four direct ARM64 `BL` links

A separate [successful whole-original-kernel caller scan, run 43146638395](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43146638395) parsed the **actual executable PT_LOAD ARM64 instruction stream** from the exact stock EEA `vmlinux` ELF, rather than relying on decompiler function names. It scanned **482,252 executable direct `BL` machine instructions** and mapped targets back to the recovered original signed kernel kallsyms.

[Reproducible whole-ELF scanner](../tools/trace_eea_kernel_proxy_lock_reverse_callers.py) found these exact source-backed incoming call edges:

| Caller | Actual ARM64 `BL` instruction VA | Direct callee |
|---|---|---|
| `do_futex` | `0xffffffc0103c91a8` | `futex_requeue` at `0xffffffc0103ca4d8` |
| `futex_requeue` | `0xffffffc0103cb3f8` | `rt_mutex_start_proxy_lock` at `0xffffffc01037e2c0` |
| `rt_mutex_start_proxy_lock` | `0xffffffc01037e300` | `remove_waiter` at `0xffffffc01037e350` |
| `rt_mutex_cleanup_proxy_lock` | `0xffffffc01037e698` | `remove_waiter` at `0xffffffc01037e350` |

There is also another inbound `BL` to `remove_waiter` from the signed `rt_mutex_slowlock$...` function at `0xffffffc01192ac30`. The location of these direct branches and the destination's `mrs x20,sp_el0` are all evidence **from the original C431 EEA kernel**.

The result **closes a prior uncertainty**: it is not merely a dormant uncalled function; the actual `do_futex → futex_requeue → rt_mutex_start_proxy_lock → remove_waiter` branch-call chain exists in the signed retail executable. The **runtime predicate** that leads into the vulnerable cancellation/rollback branch, and its reproducible unprivileged triggerability on this build, **have not been established**. No exploitability claim, kernel root or persistent unlock follows solely from an incoming branch.

The first implementation of the whole-kernel workflow incorrectly invoked the older per-function audit and checked the wrong JSON filename; the corrected workflow succeeded as run 43146638395. A further source assertion of all four exact edges was committed to the scanner so future runs fail closed on any firmware/analysis drift.

## 2. ALL 67 original, registered Keymaster handlers inspected

[Source-pinned GitHub run 43144963456](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43144963456) completed successfully. It read the original signed retail `km41.mbn` registration table (`0x138580`; 67 entries, 16 bytes each) and decompiled **all 67 actual registered handlers**, checking direct software fuse, persistent storage and fuse-blow calls.

- [Ghidra source enumerator](../tools/ghidra/Honor70KM41AllHandlersSecuritySurface.java).
- [Second independent selected-handler decompilation, success run 43145296648](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43145296648).
- [Independent 67 handler + 8 full function source-asserted crosscheck, success run 43145878827](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43145878827).
- [Reproducible assertion script](../tools/audit_km41_set_boot_state_runtime_vs_persistent.py).

**Exactly five registered callback bodies directly call** `FUN_00117980` — the helper invoking `qsee_is_sw_fuse_blown(1)`:

| Original KM41 command | Callback | Verified meaning from original pseudocode |
|---|---|---|
| `0x201` | `0x10D4E4` | **Set root of trust**; checks fuse and one-time `KM_ERROR_ROOT_OF_TRUST_ALREADY_SET` state |
| `0x202` | `0x1185A8` | **Protected READ_KM_DEVICE_STATE**, fuse check and direct `qsee_stor_read_sectors` |
| `0x203` | `0x118878` | **Protected WRITE_KM_DEVICE_STATE**, fuse check and direct `qsee_stor_write_sectors` |
| `0x208` | `0x10D064` | **Set boot state**; parses a 48-byte input, updates Keymaster runtime memory, logs `is_unlocked`, fuse gated |
| `0x211` | `0x10D6D0` | Copies 32-byte input into Keymaster's memory; fuse gated |

Among the **direct registered callback bodies**, `0x203` is the **only one containing `qsee_stor_write_sectors` directly**. This does **not** prove the whole trustlet has no other indirect storage writers; for example, the independently known `DELETE_ALL_KEYS` handler calls a helper which performs protected key storage writes **without changing the bootloader device-state API**.

### 2a. New apparent alternative `0x208 is_unlocked` is NOT an unlock

The original Ghidra source for `0x208` explicitly:

```c
iVar4 = FUN_00117980(local_64);
if ((iVar4 == 0) && (local_64[0] == '\0')) {
    if (DAT_00139518 == '\0') {
        ...
        FUN_0012d130(&DAT_0013955c,0x30,local_48,0x30);
        DAT_00138b08 = *puVar6;
        DAT_00139518 = '\x01';
        qsee_log(8,"is_unlocked: %u", ... );
        ...
    }
}
```

**Meaning:** Keymaster receives and records *reported boot state* in its **runtime variables**, including `is_unlocked` for its cryptographic root-of-trust decision making. It is **not** the persistent `0x203` RPMB state setter. It runs behind the **same software milestone fuse gate** as the normal persistent state commands.

Likewise the original `0x201` operation initializes a root-of-trust value and one-time in-memory flag, while `0x211` copies a fixed-size trustlet input. Neither makes a new persistent bootloader unlock.

### 2b. Other actual handlers checked for mistaken alternative semantics

- `0x200` reports version information.
- `0x205` selects an authentication-token key through Keymaster inter-app operations.
- `0x207` initializes TA/API version state.
- `0x215` is a no-op success return.
- `0x210E` aliases `0x10E DELETE_ALL_KEYS`, using the known protected-storage key-deletion helper, **not the persistent bootloader state setter**.

These concrete functions have original decompiler output and source-pinned assertions, rather than only string/ID guesses.

## 3. Priority based on newly proven evidence

**Most substantive new lead:** the original FNE-NX9 EEA **kernel source pattern for CVE-2026-43499**, including the proxy-lock `BL` into `remove_waiter` and use of `current` in that destination. Unlike replacing Chinese Board Keymaster (guards identical), this provides an actual device-matched vulnerability candidate. It still needs the exact C431 kernel memory/structure geometry, permission/trigger analysis and a recoverable reproduction before any device execution. **Temporary Android root would only improve diagnostics**; it would not itself bypass authenticated Keymaster/RPMB, milestone fuse checks or turn a locked ABL into an unlocked one.

**Keymaster alternate command search:** all 67 registered handlers were inspected; `0x208` is a false friend for permanent unlock, since it controls the **reported boot state** used inside a running trustlet, not secure persistent device state.

## Conclusions and constraints

- No demonstrated permanent FNE-NX9 bootloader unlock procedure.
- No direct source-backed alternative to guarded `0x203` for authenticated lock-state persistence.
- No live handset, EDL/UFS writes, RPMB modifications, arbitrary kernel writes, crashes, or QSEE fuse operations.
- The original handset last reported **LOCKED**. Historical Fastboot `OKAY` / wipe did not prove permanent success; the already verified XBL `0x203` implementation checks both transport and reply and propagates failure.

**For future investigation**: focus on verified device-matched vulnerability reproducibility and whether any authorized, independent XBL/TEE state-write path exists; do not randomly flash GPT, KM, ABL, or XBL based on an unverified branch.
