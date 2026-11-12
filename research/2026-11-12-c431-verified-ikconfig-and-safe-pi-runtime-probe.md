# HONOR70 C431 — GhostLock prerequisites closed by original IKCONFIG; bounded on-device PI futex probe

**Date:** 2026-11-12. **Device:** own HONOR 70 FNE-NX9 (C431), Android 14, kernel `5.4.295-qgki-ga2d8945339ca`.

## NEW: exact original retail IKCONFIG already contains the key compile-time options

The earlier, source-pinned GitHub Actions [run 43160260421](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43160260421), artifact `HONOR70_STOCK_EEA_PROXY_LOCK_ROLLBACK_INSTRUCTIONS`, includes `ORIGINAL_EEA_KERNEL_IKCONFIG.json`. This is *not* a FNE-AN00 or Fennie 5.4.242 configuration guess. Original exact boot/Image SHA256 identities were checked by the job.

- Image SHA256 `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`
- Uncompressed embedded config SHA256 `99107cb0eb989d1381321f560664c78bf4b47ebdecb2cc33e9a7d430e1e973c4`
- `CONFIG_FUTEX=y`; `CONFIG_FUTEX_PI=y`; `CONFIG_RT_MUTEXES=y`.
- `CONFIG_IKCONFIG=y`; `CONFIG_IKCONFIG_PROC=y`.
- `CONFIG_SECCOMP=y`; `CONFIG_SECCOMP_FILTER=y`; `CONFIG_SECURITY_SELINUX=y`.

**Implication:** PI futex support is definitely compiled into the exact stock C431 kernel image. The user does **not** need to repeat the earlier live IKCONFIG extraction solely to prove these build options. They have no bearing on whether the exact GhostLock race/lifetime bug can be triggered by an Android userspace process.

## NEW: original task PI ABI evidence

[Successful source+original-machine-code run 43231676902](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43231676902) checked **17 original ARM64 instructions** and eight regression tests. Source-attributed C431 fields:

| Field | Byte offset |
|---|---:|
| `task_struct.prio` | `0x11c` |
| `task_struct.dl.deadline` | `0x488` |
| `task_struct.pi_lock` | `0x96c` |
| `task_struct.pi_waiters.rb_root` | `0x978` |
| `task_struct.pi_waiters.rb_leftmost` | `0x980` |
| `task_struct.pi_blocked_on` | `0x990` |

The exact waiter fields in the separate [19-instruction crosscheck run 43229427485](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43229427485) remain `task=0x30`, `lock=0x38`, `prio=0x40`, `deadline=0x48`. **This is partial ABI evidence, not an exploit-ready profile.**

## Android process accessibility

AOSP's bionic common seccomp allowlist explicitly includes `futex(...)` for all supported architectures:
https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/SECCOMP_ALLOWLIST_COMMON.TXT

The official [Android app sandbox](https://source.android.com/docs/security/app-sandbox) still uses seccomp-BPF and SELinux, and device/vendor-specific additional restrictions are possible. The earlier real-phone snapshot observed `Seccomp:0` for an **ADB-shell-spawned cat process**; it does not prove arbitrary third-party app syscall permission.

## Android 2026-11 security classification

The Android Open Source Vulnerabilities record [ASB-A-496407345](https://osv.dev/vulnerability/ASB-A-496407345) (published 2026-11-01, last modified 2026-11-11) lists CVE-2026-43499 as **High**, local elevation of privilege requiring no additional execution privileges or user interaction, with a reported Android kernel fix SPL of **2026-11-05**. The observed user's C431 handset reported June 2026 patch and original kernel disassembly still contains the wrong-task `remove_waiter` code. This strengthens the *candidate vulnerability* assessment; it does **not** establish a reproducing root exploit on this precise retail kernel or show whether HONOR backported unrelated controls.

## Safely test an uncontended PI futex (NO GhostLock vulnerability trigger)

A separate [successful GitHub Actions build run 43232829028](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43232829028) generated artifact **`HONOR70_SAFE_PI_FUTEX_ARM64_PROBE`**. It contains statically linked ARM64 executable `fne_pi_futex_probe_arm64` with SHA256:

`753d08e6fe8b0fd3f669b52521baad91f57eef8cdc901eddc0819820eb4cc767`.

The original assembly is in [`tools/fne_pi_futex_probe_arm64.S`](../tools/fne_pi_futex_probe_arm64.S). Its only futex syscalls are:

- **`FUTEX_LOCK_PI|FUTEX_PRIVATE_FLAG`** (operation 134) on its own initially-zero 32-bit futex; 
- **`FUTEX_UNLOCK_PI|FUTEX_PRIVATE_FLAG`** (operation 135) on the same futex.

There is NO `FUTEX_CMP_REQUEUE_PI`, `FUTEX_WAIT_REQUEUE_PI`, intentional race, memory UAF, root action, system partition update, or kernel-address manipulation. Like any userspace probe, pushing the executable to `/data/local/tmp` is a normal userspace file write and requires authorized USB debugging; the test does not flash firmware.

To execute from Mac after downloading the artifact ZIP from the **successful** CI run:

```bash
unzip -o "$HOME/Downloads/HONOR70_SAFE_PI_FUTEX_ARM64_PROBE.zip" \
  -d "$HOME/Downloads/HONOR70_PI_PROBE"
shasum -a 256 "$HOME/Downloads/HONOR70_PI_PROBE/fne_pi_futex_probe_arm64"
adb shell getprop ro.product.model
adb push "$HOME/Downloads/HONOR70_PI_PROBE/fne_pi_futex_probe_arm64" \
  /data/local/tmp/fne_pi_futex_probe_arm64
adb shell chmod 700 /data/local/tmp/fne_pi_futex_probe_arm64
adb shell '/data/local/tmp/fne_pi_futex_probe_arm64; echo EXIT_CODE:$?'
```

Make sure the displayed device model is FNE-NX9 and the SHA256 matches before execution.

Expected `FUTEX_LOCK_PI returned 0`, `FUTEX_UNLOCK_PI returned 0`, `EXIT_CODE:0`. Exit 11 indicates the lock failed or is blocked; exit 12 indicates unlock failure. A blocked process may be terminated by seccomp (e.g., SIGSYS), in which case the terminal output and exit code are evidence. **This probe confirms only uncontended PI-futex behavior for the ADB-shell user, not UAF feasibility, a GhostLock exploit or root.**

## ON-DEVICE RESULT — owner-reported, 2026-11-12

**Result: successful.** The owner executed the exact SHA-verified safe probe on an authorized HONOR 70 FNE-NX9 from macOS over ADB. This is **user-provided terminal output**, not an independently captured device log.

- Host-side SHA256 matched the published static ARM64 ELF: `753d08e6fe8b0fd3f669b52521baad91f57eef8cdc901eddc0819820eb4cc767`.
- `adb shell getprop ro.product.model` returned `FNE-NX9`.
- `adb push` transferred 2,344 bytes to `/data/local/tmp/fne_pi_futex_probe_arm64`.
- The user ran the program via `adb shell`; stdout:
  ```text
  HONOR70 safe PI futex syscall check (NOT GhostLock)
  FUTEX_LOCK_PI returned 0
  FUTEX_UNLOCK_PI returned 0
  EXIT_CODE:0
  ```
- **Established:** uncontended, privately scoped PI futex LOCK/UNLOCK operations succeeded under the Android ADB-shell execution context. The previously confirmed exact original C431 IKCONFIG already had `CONFIG_FUTEX_PI=y`, `CONFIG_FUTEX=y`, `CONFIG_RT_MUTEXES=y`.
- **Not established:** whether `FUTEX_CMP_REQUEUE_PI` can be used from any particular Android security domain, whether the GhostLock rollback defect is dynamically reachable, whether a UAF could be reliably triggered, whether application processes have identical access, or whether root/bootloader unlock occurs.
- No need to repeat this diagnostic. Future tests should examine a **new, discriminating prerequisite**; do not turn this green signal into a claim of successful exploitability.

## What remains unresolved

- Actual unprivileged/ADB-shell *vulnerable rollback state* reachability on C431; source presence is not a runtime demonstration.
- OEM additional policy restrictions if execution originates in an ordinary app rather than ADB shell.
- Reliable kernel memory geometry and many essential fields outside the verified subset; prior candidate contains 32 missing fields and a host-derived wrong physical address.
- Reproducible privilege escalation and a separate authenticated Keymaster/RPMB bootloader unlock path.

Official CVE announcement: https://lists.openwall.net/linux-cve-announce/2026/05/21/7

**Current state:** exact configuration and several ABI prerequisites now verified; the bounded PI-futex test has passed on the user's actual FNE-NX9 (user-provided terminal output). No GhostLock root or persistent bootloader unlock has yet been demonstrated.
