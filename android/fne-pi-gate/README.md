# HONOR 70 FNE-NX9 — safe Android app PI-futex access check

**Purpose:** distinguish successful `adb shell` PI-futex calls already measured on the owner's device from **PI-futex access inside a normal Android application domain**. This is a runtime prerequisite test, **not** a GhostLock proof of concept and **not** a bootloader unlock.

## Application behavior

- A minimal Android app, package `org.openhonor.fnepigate`, no Android permissions and **no INTERNET permission**.
- Bundles an ARM64 `libfnepi.so` JNI library compiled from `app/src/main/c/fne_pi_gate.c`.
- When the user taps the button, calls exactly one uncontended `FUTEX_LOCK_PI|FUTEX_PRIVATE_FLAG` and one `FUTEX_UNLOCK_PI|FUTEX_PRIVATE_FLAG` on its own initialized 32-bit futex.
- Reports return code and `errno` for both calls, its own app UID, current SELinux domain (if readable), seccomp state from `/proc/self/status`, Android SDK and kernel string.
- Results are displayed on-device and may be copied manually to clipboard. **No data is uploaded.** The source has no root, requeue, task-memory manipulations, shell commands or persistent changes.

## Build

[GitHub Actions build](../../.github/workflows/build-fne-pi-gate-app.yml) compiles the JNI library and debug APK for arm64-v8a and audits the resulting APK to verify no permissions and the expected native library. A successful workflow saves an artifact named `HONOR70_FNE_PI_GATE_SAFE_ANDROID_APK`.

The APK is signed with an **ephemeral GitHub Actions debug key**, not a verified retail signing key. Do not distribute it as a production app.

## Device test — only after a successful build

Download artifact `HONOR70_FNE_PI_GATE_SAFE_ANDROID_APK` from the **successful** Actions workflow run. Extract it to a local directory. Verify the `APK_SHA256.txt` hash against the APK bytes using `shasum -a 256`.

```bash
adb install -r HONOR70_FNE_PI_GATE_SAFE_APP_DEBUG.apk
```

Open **FNE PI Gate** on the phone, press **Proveri PI-futex iz Android aplikacije**, then **Kopiraj rezultat** and share the text report for analysis. The normal Android installation may prompt for installation authorization; the user can decline. `adb uninstall org.openhonor.fnepigate` removes the app afterward.

Expected success text is `Outcome: APP_PI_FUTEX_OK` with both return codes 0. The app process UID, SELinux domain, and `Seccomp` fields tell whether the result came from an ordinary app sandbox rather than ADB shell. A failure does not automatically mean the syscall is blocked: the observed `errno`, app context, and build/loader errors must be examined.

**Not demonstrated**: ability to invoke GhostLock's `FUTEX_CMP_REQUEUE_PI` path, timing/race conditions, use-after-free, root privileges, kernel physical addressing, or persistent bootloader unlock.

## Already established

- The exact SHA-pinned C431 Linux 5.4.295 IKCONFIG includes `CONFIG_FUTEX=y`, `CONFIG_FUTEX_PI=y` and `CONFIG_RT_MUTEXES=y`.
- On 2026-11-12, the owner executed the previous static ARM64 ADB-shell probe on FNE-NX9; `FUTEX_LOCK_PI` and `FUTEX_UNLOCK_PI` both returned 0, final exit code 0.

This application tests **a different security execution context** and avoids repeating the shell diagnostic.
