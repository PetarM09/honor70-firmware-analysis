# GhostLock: exact FNE-NX9 C431 Android runtime prerequisites (12 Nov 2026)

## Objective
Priority 1 is validating whether CVE-2026-43499 has a **reproducible and meaningful runtime manifestation** on stock HONOR 70 FNE-NX9 C431 MagicOS 8.0.0.290. Priority 2, which must remain separate, is determining whether any demonstrated privilege change crosses the hardware trust boundary to persistent unlock.

Official disclosure: https://lists.openwall.net/linux-cve-announce/2026/05/21/7

## Verified vs unknown

Original signed image static evidence indicates the proxy-lock caller path and `remove_waiter()` current-task accesses. This proves an instruction pattern, **not** a working local trigger. An Android application can have different seccomp, SELinux, UID, capabilities, sandbox and ABI restrictions than `adb shell`. The latter is useful environment context only.

Red Hat's July 2026 advisory emphasizes that the PI-futex functionality and real-time scheduling affect exposure, and warns that kernel code-path presence alone is insufficient for measuring practical exploitability in a specific environment: https://access.redhat.com/security/vulnerabilities/RHSB-2026-010

## New non-invasive runtime diagnostic

`tools/collect_fne_kernel_policy_readonly.py` collects: kernel release, selected *non-identifier* system properties, shell SELinux context, shell process seccomp mode and relevant process status lines, SELinux enforcing state and whether `/proc/config.gz` is readable. It performs zero futex calls, device writes or modifications.

Use, **only if an authorized phone is connected**:

```bash
python3 tools/collect_fne_kernel_policy_readonly.py --out HONOR70_READONLY_POLICY_SNAPSHOT.json
```

An online authorized `adb` device and Python 3 are prerequisites. For multiple devices, set `ANDROID_SERIAL`. Do not publish raw device logs or serial numbers. The script does not require root.

## Important limits

- `adb shell` process evidence cannot establish that a third-party Android app may issue a specific syscall or access a futex path.
- `/proc/config.gz` being unavailable does not mean PI-futex is disabled; Android builds may omit that endpoint.
- Kernel release `5.4.295` alone is not dispositive because vendors backport fixes.
- Byte-verified direct-call edges prove compile-time code, not activation of a particular rollback branch at runtime.
- The current GhostLock execution profile with 32 missing fields is **not safe to execute**.
- The secure Keymaster/RPMB state is outside the kernel's ordinary authority. Neither root nor an EL1 write implies persistent bootloader unlock.

## Decision rule

Keep the research state as **source-level candidate** until independently reproduced runtime effects are observed on the exact firmware. Do not label the phone rooted or unlocked without direct observed post-condition evidence. The latest diagnostic provides **environment data**, not exploit proof.
