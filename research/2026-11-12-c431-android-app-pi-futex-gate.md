# 2026-11-12 — Android application-domain PI-futex diagnostic built for FNE-NX9

## Why this new test matters

On the user's actual FNE-NX9 C431, an earlier SHA-verified static AArch64 binary successfully performed uncontended `FUTEX_LOCK_PI_PRIVATE` and `FUTEX_UNLOCK_PI_PRIVATE` under **ADB shell** (owner-provided stdout, EXIT_CODE 0). ADB shell and normal installed apps use different Android UIDs and often different seccomp and SELinux profiles. The exact C431 original kernel IKCONFIG already proves `CONFIG_FUTEX=y`, `CONFIG_FUTEX_PI=y`, `CONFIG_RT_MUTEXES=y`. These should **not** be retested unnecessarily.

## New native app and verified build

- Source root: [`android/fne-pi-gate`](../android/fne-pi-gate), package `org.openhonor.fnepigate`, label `FNE PI Gate`.
- JNI native library: [`app/src/main/c/fne_pi_gate.c`](../android/fne-pi-gate/app/src/main/c/fne_pi_gate.c), compiled to one `arm64-v8a/libfnepi.so`. Calls only uncontended private `FUTEX_LOCK_PI` and `FUTEX_UNLOCK_PI`, on an initially zero local `int`.
- Java UI: [`MainActivity.java`](../android/fne-pi-gate/app/src/main/java/org/openhonor/fnepigate/MainActivity.java). Displays app UID, kernel, app `/proc/self/attr/current` SELinux label (if readable), app `/proc/self/status` Seccomp/NoNewPrivs/CapEff, native return codes and errno. Clipboard button is manual; no upload.
- No `INTERNET`, system, storage, or root permissions. Manifest has `allowBackup=false`, `usesCleartextTraffic=false`, launcher activity only.
- GitHub Actions [successful final build run **43261841313**](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43261841313) asserts the AArch64 JNI ELF, that exactly one `libfnepi.so` is packaged, that AAPT reports **zero requested permissions**, and that label is `FNE PI Gate`.
- Built debug APK SHA256: **`bdbd48f72d1161f738aea1f9ebdca62006e4216aa23e0aebf6003b75336d1f09`**.
- Artifact name: **`HONOR70_FNE_PI_GATE_SAFE_ANDROID_APK`** containing `HONOR70_FNE_PI_GATE_SAFE_APP_DEBUG.apk`, APK SHA256, ELF metadata, scopes. Signed with ephemeral GitHub Actions debug key.

## Executing on the user's own phone

Install APK from successful Actions artifact or local downloaded APK (verify SHA256 first):

```bash
shasum -a 256 "$HOME/Downloads/HONOR70_FNE_PI_GATE_ANDROID_APP_VERIFIED.apk"
adb install -r "$HOME/Downloads/HONOR70_FNE_PI_GATE_ANDROID_APP_VERIFIED.apk"
```

Open `FNE PI Gate` on the phone and tap `Proveri PI-futex iz Android aplikacije`. Copy the report from the app using `Kopiraj rezultat`; provide the output in chat. No need to repeat the prior shell test. Remove later with `adb uninstall org.openhonor.fnepigate`.

Expected native result under a permissive normal app sandbox: both return codes `0`, output `Outcome: APP_PI_FUTEX_OK`. If not, capture errno and SELinux/seccomp fields before attribution. Success in an ordinary app proves one further userspace prerequisite, **not** `FUTEX_CMP_REQUEUE_PI` triggering or any use-after-free.

## Evidence boundaries

- Build and static APK permission checks are confirmed; **real-device installation and execution are NOT yet reported**.
- This app does not call GhostLock requeue, create waiter contention, attempt races, write kernel memory, request root or touch bootloader firmware.
- An app's ability to run ordinary futex syscalls does not show the necessary vulnerable rollback conditions or a reliable UAF-to-root primitive.
- No full working C431 GhostLock exploit profile, temporary root or persistent bootloader unlock has been demonstrated.
