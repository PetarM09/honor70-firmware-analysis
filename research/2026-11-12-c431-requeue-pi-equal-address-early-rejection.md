# HONOR 70 C431 — bounded CMP_REQUEUE_PI early-rejection test (2026-11-12)

## Why a different test

The user has already demonstrated `APP_PI_FUTEX_OK` for uncontended private `FUTEX_LOCK_PI` and `FUTEX_UNLOCK_PI` from an ordinary Android 14 `untrusted_app` process (SELinux `u:r:untrusted_app:s0:...`, Seccomp mode 2, UID 10227) on retail HONOR 70 FNE-NX9, kernel `5.4.295-qgki-ga2d8945339ca`.

However, the GhostLock regression CVE-2026-43499 concerns **PI requeue rollback**. Normal PI lock/unlock success does not establish access to `FUTEX_CMP_REQUEUE_PI`, correct wait/wake state transitions, UAF, root or bootloader unlock.

## Exact-stock binary guard checked

The original retail `boot.img` and `Image` were already SHA-256 verified:

- Boot: `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256`.
- Kernel: `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`.

**[Successful CI 43267966235](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43267966235)** compared 10 actual original ARM64 instructions with the original HONOR Fennie GPL `kernel/futex.c` (SHA-256 `71b9c7591dc611e6f92e742858bcc044cf01b605208058498e31d444b7704106`). Eight regression tests passed.

When PI requeue is selected, original C431 `futex_requeue` includes:

```asm
0xffffffc0103ca530  mov x25, x2   ; target futex user address
0xffffffc0103ca538  mov x27, x0   ; source futex user address
0xffffffc0103ca540  cbz w6, #0xffffffc0103ca560
0xffffffc0103ca544  cmp x27, x25
0xffffffc0103ca548  b.eq #0xffffffc0103cb828
```

The corresponding Fennie source rejects `uaddr1 == uaddr2` with `-EINVAL` **before** `refill_pi_state_cache()`, `get_futex_key()`, futex bucket locks or waiter traversal. The signed C431 binary independently shows the equal-address conditional branch before those paths.

## New FNE PI Gate v0.2 one-shot probe

[Android app source](../android/fne-pi-gate/app/src/main/c/fne_pi_gate.c). A new, separate UI button sends only:

```c
int word __attribute__((aligned(4))) = 0;
long rc = syscall(SYS_futex, &word,
                  FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                  1, (void *)0, &word, 0);
```

The same 32-bit word is used for source and target. No `FUTEX_WAIT_REQUEUE_PI` call, no waiting task, no contention, no requeue operation, no race or kernel state corruption is attempted. The original C431 kernel should reject this **before the vulnerability-related queue logic**.

**Expected result on a normal app process:**

- `rc=-1 errno=22` and `Outcome: REQUEUE_PI_EARLY_GUARD_OK`: application syscall dispatch appears to reach the early kernel invalid-address check. Does **not** prove queue processing or GhostLock exploitability.
- `rc=-1 errno=1` (`EPERM`) or `13` (`EACCES`): denied/restricted or policy-related; inspect SELinux/seccomp and logs.
- `rc=-1 errno=38` (`ENOSYS`): missing/filtered opcode or syscall; need further evidence.
- Anything else: unexpected, retain exact result; do not interpret as a successful exploit.

The native code executes only when the user taps the new button. No data is uploaded. The original `FUTEX_LOCK_PI`/unlock test remains available, but need not be repeated.

**No firmware/partition writes, EDL test, GhostLock exploit, temporary root or permanent bootloader unlock have been performed.**

## Installation note

App is a GitHub Actions **debug** APK signed with a per-run ephemeral debug certificate. If the earlier v0.1 app remains installed, its signing certificate will not necessarily match v0.2. If `adb install -r` reports `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, uninstall the old app (`adb uninstall org.openhonor.fnepigate`) and install v0.2. This removes the old app's local state, which contains no essential files.

The final APK is verified by the latest [CI build](../../.github/workflows/build-fne-pi-gate-app.yml): AArch64 native JNI, zero Android permissions, package `org.openhonor.fnepigate`, launcher title `FNE PI Gate`.

## Research conclusion

A normal Android app was already demonstrated capable of private PI futex lock/unlock. This new invalid early-rejection check tests **distinct dispatch availability** without entering the vulnerable requeue operation. Passing it still leaves GhostLock's lifetime trigger, memory geometry, controlled primitives, temporary root and authenticated bootloader state **unproven**.
