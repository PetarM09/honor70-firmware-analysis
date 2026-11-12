# 2026-11-12 — FNE-NX9 C431 live diagnostic and next meaningful test

The user's read-only ADB report, captured 2026-11-12T03:56:11Z, gives FNE-NX9 / HNFNE, Android 14, kernel 5.4.295-qgki-ga2d8945339ca, security patch 2026-06-01. It reports locked boot state (`ro.boot.flash.locked=1`; `vbmeta.device_state=locked`; `verifiedbootstate=green`); enforcing SELinux; `u:r:shell:s0`; and `/proc/config.gz` as **readable** according to a shell permission test.

`Seccomp: 0` refers to an ADB-started `cat` process (UID 2000), **not arbitrary Android app permissions**. None of these observations proves a GhostLock exploit.

## Exact Mac-side test for the authorized user's FNE-NX9

```bash
cd "$HOME/honor70-firmware-analysis"
git pull origin main
python3 tools/collect_fne_live_ikconfig_readonly.py \
  --out "$HOME/Downloads/HONOR70_LIVE_IKCONFIG_SUMMARY.json"
```

Share only the resulting summary JSON. The collector reads on-device `/proc/config.gz` via ADB exec-out, validates the device/kernel identity, decompresses and hashes the config, and extracts selected kernel options. **It never writes to the phone, calls futex, attempts root or flashes firmware.**

Linux 5.4 `CONFIG_FUTEX_PI` is conditional on `CONFIG_FUTEX` and `CONFIG_RT_MUTEXES`; compile-time presence is not proof of a reproducible GhostLock runtime trigger. If the file is unreadable or invalid, do not infer that PI futex is disabled.

The script's 7 synthetic regression tests passed locally on 12 November 2026. Its real-device execution has not yet been verified.

**Next evidence gate:** assess three kernel configuration flags and compare the parsed live config SHA256 with the exact signed stock C431 Image's embedded IKCONFIG result, if available. Keep application seccomp and runtime reachability as separate unknowns.

Official CVE: https://lists.openwall.net/linux-cve-announce/2026/05/21/7
CONFIG_FUTEX_PI reference: https://cateee.net/lkddb/web-lkddb/FUTEX_PI.html
