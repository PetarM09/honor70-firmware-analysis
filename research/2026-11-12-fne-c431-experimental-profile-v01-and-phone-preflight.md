# FNE-NX9 C431 experimental profile v0.1 — first phone test

**Target:** HONOR 70 `FNE-NX9`, device code `HNFNE`, original EU `C431`, MagicOS `8.0.0.290`, Android 14 (SDK 34), original kernel `5.4.295-qgki-ga2d8945339ca`.

The profile file is **[profiles/fne-nx9-c431-8.0.0.290.profile.json](../profiles/fne-nx9-c431-8.0.0.290.profile.json)**. It is a **C431-specific, evidence-grounded experimental profile**, **not** a drop-in GhostLock `offsets.json`, root payload, or completed exploit. All values used here come from previously documented SHA-verified C431 research.

## Confirmed profile values

| Kernel field | Decimal offset | Hex offset |
|---|---:|---|
| `rt_mutex_waiter.task` | 48 | `0x30` |
| `rt_mutex_waiter.lock` | 56 | `0x38` |
| `rt_mutex_waiter.prio` | 64 | `0x40` |
| `rt_mutex_waiter.deadline` | 72 | `0x48` |
| `task_struct.prio` | 284 | `0x11c` |
| `task_struct.dl.deadline` | 1160 | `0x488` |
| `task_struct.pi_lock` | 2412 | `0x96c` |
| `task_struct.pi_waiters.rb_root` | 2424 | `0x978` |
| `task_struct.pi_waiters.rb_leftmost` | 2432 | `0x980` |
| `task_struct.pi_blocked_on` | 2448 | `0x990` |

Original `do_futex` local waiter is passed as `x29-0xd0` to the waiter init/proxy-wait/cleanup helpers; its post-prologue location is `sp+0xf0`. Original `futex_q` local evidence points to `sp+0x70`. A hypothetical common kernel-stack entry produces an **80-byte mathematical intersection** with a select-side frame region; neither actual reuse nor user-controlled overwrite has been established.

**Missing fields are stored as real JSON `null`, not guessed zeros.** These include `kernel_phys_load`, actual kernel slide, complete `cred` and `seccomp` layouts, relevant full `futex_q` geometry, live stack reuse, controlled kernel memory and privilege transition. The earlier `0xfffff000` value derived from a GitHub runner's `/proc/iomem` is **not a valid phone kernel physical base**.

The original firmware hash is pinned to `boot.img` SHA-256 `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256` and extracted `Image` SHA-256 `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`.

## Built and verified test package (2026-11-12)

The **[v0.3 build succeeded in GitHub Actions run 43294501535](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43294501535)**. The CI passed **11 fail-closed profile tests**, compiled the Android arm64 JNI app, verified zero Android permissions, and compared the **exact SHA of the bundled asset** against this repository's C431 profile.

- Android APK version: `0.3-c431-profile-preflight`, versionCode `3`, package `org.openhonor.fnepigate`.
- Exact compiled APK SHA-256: `fa380ae95155e92531940b6ea152d4b73f3fe4ddbcaa60620021818dac11f706`.
- The bundled profile SHA-256: `0dd061b002413b4547733e433e080e523044ac349465e8758f3b6dfc65ac9979`.
- Actions artifact: `HONOR70_C431_PROFILE_PREFLIGHT_V03_ANDROID_APK` (includes APK and audit files). Debug-signed with an ephemeral Actions certificate.

## Live handset test: **PASSED** (owner photo received 2026-11-12)

The owner installed and ran the **actual FNE PI Gate v0.3** APK on the HONOR 70 and submitted a **photograph of the application report**. The following values were legible on the photographed screen. The screenshot is recorded by transcription rather than adding the personal photo to this public repository.

| App field | Direct owner-photo observation |
|---|---|
| Profile | `honor70-fne-nx9-c431-8.0.0.290-5.4.295-ga2d8945339ca` |
| Version | `0.1.0` |
| Model | `FNE-NX9` (expected `FNE-NX9`) **OK** |
| Device | `HNFNE` (expected `HNFNE`) **OK** |
| Kernel | `5.4.295-qgki-ga2d8945339ca` (exact expected value) **OK** |
| Android SDK | `34` (expected `34`) **OK** |
| Firmware build (runtime) | `8.0.0.290C431E4R3P1` |
| Profile region label | `C431`, explicitly marked **not independently attested** |
| Kernel Image SHA | Taken from offline reference; **not checked against running kernel** |
| Unresolved `kernel_phys_load` | `null` |
| Outcome | **`PROFILE_MODEL_KERNEL_ANDROID_MATCH`** |

The visible `C431` suffix in runtime build metadata additionally **corroborates the intended regional firmware family**, but it does not independently establish the signed boot image bytes or the actual kernel physical load.

**Evidence update:** exact **model/device/kernel release/SDK profile identity and bundled JSON parsing have now passed on the owner's real Android phone.** There is no need to repeat this preflight. The older `APP_PI_FUTEX_OK` and invalid PI-requeue `EINVAL` tests also already passed independently.

**What did NOT happen:** no live CVE-2026-43499 rollback was triggered, no dangling waiter or user-controlled stack memory was observed, no elevated UID/capabilities or kernel memory access was obtained, and the bootloader was not unlocked. This is a successful **identity-level** gate only.

## How to test on the actual phone, without changing it

### Option A: FNE PI Gate v0.3 APK

Use the successful [GitHub Actions **FNE PI Gate v0.3** build](https://github.com/PetarM09/honor70-firmware-analysis/actions/workflows/build-fne-pi-gate-app.yml), download the APK artifact `HONOR70_C431_PROFILE_PREFLIGHT_V03_ANDROID_APK` from its successful run. This packages the identical checked JSON in an Android asset. The installer requests no Android permissions.

If older v0.2 was installed, the CI debug signing key probably differs. Uninstall the earlier app before installing v0.3:

```bash
adb uninstall org.openhonor.fnepigate
adb install -r "$HOME/Downloads/HONOR70_C431_PROFILE_PREFLIGHT_V03.apk"
```

Tap **`Proveri C431 profil bez root-a`**, then **`Kopiraj rezultat`**. A matching device reports `PROFILE_MODEL_KERNEL_ANDROID_MATCH`. **This reports model, Android SDK, device and kernel-release identity only. It does not attest that C431 region or the signed Image SHA is live**, and is not UAF/root.

The original tested PI-futex lock/unlock and intentionally invalid CMP_REQUEUE_PI early-rejection buttons remain in the app. **No need to rerun them**; those results were already reported by the owner.

### Option B: read-only Mac ADB preflight

From the repository root:

```bash
python3 tools/check_fne_c431_profile.py
python3 tools/check_fne_c431_profile.py --device \
    --out "$HOME/Downloads/HONOR70_C431_PROFILE_PREFLIGHT.json"
```

The script only reads `getprop`, `uname`, `getenforce`, and `id` through `adb shell`. It does not create files on the device, need root, run UAF, call futex requeue, invoke EDL or write kernel memory. On shared ADB setups, `--serial` selects a specific device; serial is **not** recorded in the report.

Send the new JSON report or the app's copied output to continue profile validation.

## Interpreting test results

- `MODEL_KERNEL_ANDROID_MATCH` / `PROFILE_MODEL_KERNEL_ANDROID_MATCH`: correct build-family identity only; the signed firmware evidence is stored separately.
- `MODEL_KERNEL_ANDROID_MISMATCH`: do **not** treat the profile as matching that software build.
- `PROFILE_PREFLIGHT_ERROR`: report the exact error; it does not imply a rooted or exploitable kernel.
- A match **never** means a working GhostLock exploit. The actual UAF trigger, reusable memory, kernel primitive, temporary root and authenticated bootloader unlock remain separate unsolved questions.

## Links and reproducibility

- [Profile JSON](../profiles/fne-nx9-c431-8.0.0.290.profile.json)
- [Profile validation and ADB preflight](../tools/check_fne_c431_profile.py)
- [Negative and positive unit tests](../tools/test_check_fne_c431_profile.py)
- [FNE PI Gate Android code](../android/fne-pi-gate)
- [APK build workflow with SHA-pinned bundled profile](../.github/workflows/build-fne-pi-gate-app.yml)
- [Original four-task evidence audit](2026-11-12-c431-four-ghostlock-tasks-evidence-audit.md)

This is the **first reproducible, incrementally improvable original-C431 profile**. Its static fields are genuinely populated; its unknown fields and runtime safety limits are explicit. No modified kernel or persistent bootloader change is attempted.
