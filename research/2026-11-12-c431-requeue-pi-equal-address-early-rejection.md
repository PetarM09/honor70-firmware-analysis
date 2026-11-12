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

## Verified v0.2 APK available

- **[Successful v0.2 build, GitHub Actions 43268029573](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43268029573)**.
- Artifact ID: `13966123983`, name `HONOR70_FNE_PI_GATE_SAFE_ANDROID_APK`.
- App version code `2`, version name `0.2-invalid-requeue-guard`.
- Verified APK SHA256: **`b8e919e38deec221cac0734ad232b6b0b9fc204f3eadcb8fcab5a37c88980f87`**.
- JNI arm64-v8a SHA256: `d809e601264d095439b844ea6c665a60833ecfeae503ac7538b0e69e0e3fd8f2`.
- Package `org.openhonor.fnepigate`, label `FNE PI Gate`, permission audit: zero requested Android permissions.
- Source CI also asserts the native code has `&word` as both source and destination futex addresses.
- v0.2 builds on v0.1 and retains the original verified LOCK_PI/UNLOCK_PI button. **Use only the new second button** to answer the current, previously unmeasured question.

If the earlier v0.1 app is present, the new GitHub-run debug signing certificate may differ. Remove the earlier installation first and then install v0.2:

```bash
adb uninstall org.openhonor.fnepigate
adb install -r "$HOME/Downloads/HONOR70_FNE_PI_GATE_V02.apk"
```

Open the app and tap **`Proveri CMP_REQUEUE_PI rano odbijanje`**. Copy the report with **`Kopiraj rezultat`**. Expected: `rc=-1 errno=22` and `REQUEUE_PI_EARLY_GUARD_OK`.

## Owner-reported live result: passed on FNE-NX9 (2026-11-12)

The user submitted a photograph of the **actual FNE PI Gate v0.2** app screen showing the new **`FNE_PI_GATE_APP_REQUEUE_GUARD_REPORT_V2`** output. The photo is not copied into the repository; this transcribes visible findings, retaining their observational scope:

| Property | Value shown in app |
|---|---|
| `Model` | `FNE-NX9` |
| `Device` | `HNFNE` |
| `Kernel` | `5.4.295-qgki-ga2d8945339ca` |
| `Android SDK` | `34` |
| `App UID` | `10228` |
| `SELinux context` | `u:r:untrusted_app:s0:c228,c256,c512,c768` |
| `CapEff` | `0000000000000000` |
| `NoNewPrivs` | `0` |
| `Seccomp` | `2` (filter) |
| Native `FUTEX_CMP_REQUEUE_PI | PRIVATE` (identical source & target addresses) | `rc=-1 errno=22` |
| Report outcome | **`REQUEUE_PI_EARLY_GUARD_OK`** |

**Interpretation:** This is an on-device normal-app-domain success for a deliberately invalid PI requeue request: the observed `EINVAL` matches the SHA-checked original C431 early equal-address rejection path, even with `Seccomp:2` and no effective capabilities. This is stronger evidence of normal app syscall dispatch than prior shell PI lock/unlock results.

**Strict evidence boundary:** The return code alone does not cryptographically prove which stage produced `EINVAL`; another early validation or a deliberately synthesized seccomp errno could in principle return it. Combined with the original machine-code source/destination guard, it is *consistent with* the expected early guard. No futex waiter was created or requeued, no vulnerable rollback was reached, and **no GhostLock UAF, arbitrary kernel write, root, or bootloader unlock was demonstrated**.

The test should not be repeated for the same reason. A future meaningful probe must answer a new question while respecting the risk of triggering unstable futex lifetime conditions.

## Research conclusion

A normal Android app was already demonstrated capable of private PI futex lock/unlock. This new invalid early-rejection check tests **distinct dispatch availability** without entering the vulnerable requeue operation. Passing it still leaves GhostLock's lifetime trigger, memory geometry, controlled primitives, temporary root and authenticated bootloader state **unproven**.
