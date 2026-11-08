#!/usr/bin/env python3
"""HONOR 70 read-only boot/kernel inventory. No root, writes, flashing or state changes.
Cross-platform (Windows/macOS/Linux), requires adb in PATH and USB debugging allowed.
Prints no device serials, IMEIs, accounts or other unique identifiers.
"""
from __future__ import annotations
import pathlib
import shutil
import subprocess
import sys
import time

CHECKS = [
    ("android_release", "getprop ro.build.version.release"),
    ("system_build", "getprop ro.build.version.incremental"),
    ("model", "getprop ro.product.model"),
    ("device", "getprop ro.product.device"),
    ("hardware", "getprop ro.hardware"),
    ("kernel_release", "uname -r"),
    ("kernel_build", "cat /proc/version"),
    ("kernel_security", "getenforce"),
    ("verified_boot", "getprop ro.boot.verifiedbootstate"),
    ("flash_lock_property", "getprop ro.boot.flash.locked"),
    ("vbmeta_state", "getprop ro.boot.vbmeta.device_state"),
    ("BTF_files_status", "ls -ld /sys/kernel/btf /sys/kernel/btf/vmlinux 2>&1"),
    ("BTF_read_access", "test -r /sys/kernel/btf/vmlinux && echo BTF_READABLE || echo BTF_NOT_READABLE"),
    ("config_status", "ls -l /proc/config.gz 2>&1"),
    ("config_relevant", "zcat /proc/config.gz 2>/dev/null | grep -E '^(CONFIG_DEBUG_INFO_BTF|CONFIG_KALLSYMS|CONFIG_FUTEX|CONFIG_RT_MUTEXES|CONFIG_ARM64|CONFIG_RANDOMIZE_BASE)=' | head -n 35"),
    ("iomem_relevant", "cat /proc/iomem 2>/dev/null | grep -Ei 'Kernel code|Kernel data|System RAM|DRAM|reserved' | head -n 65"),
    ("proc_iomem_permissions", "ls -l /proc/iomem 2>&1"),
    ("oeminfo_partition_exists", "ls -l /dev/block/by-name/oeminfo 2>&1"),
]

def adb(args: list[str], timeout=25) -> tuple[int,str]:
    try:
        p = subprocess.run(["adb", *args], text=True, capture_output=True, timeout=timeout, errors="replace")
        return p.returncode, (p.stdout + ("\n[stderr] " + p.stderr if p.stderr.strip() else "")).strip()
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    except Exception as e:
        return 125, type(e).__name__ + ": " + str(e)

def main() -> int:
    if not shutil.which("adb"):
        print("ERROR: adb not found in PATH. Install Android Platform Tools.")
        return 2
    code, status = adb(["get-state"])
    if code != 0 or status != "device":
        print("ERROR: ADB device not connected/authorized. Connect by USB, allow USB debugging.")
        return 3
    sections = [
        "HONOR70_READONLY_RUNTIME",
        "Safety: no root, no fastboot, no flashing, no changes, no user identifiers collected.",
        "All commands are adb shell reads; errors are preserved.",
        "Host timestamp: "+time.strftime("%Y-%m-%d %H:%M:%S"),
    ]
    for label, command in CHECKS:
        rc, output = adb(["shell", "sh", "-c", command])
        sections.extend(["", "=== "+label+" (rc="+str(rc)+") ===", output[:12000] or "(empty/unavailable)"])
    out = pathlib.Path.cwd() / "HONOR70_RUNTIME_READONLY_NEXT.txt"
    out.write_text("\n".join(sections) + "\n", encoding="utf-8")
    print("Wrote: "+str(out))
    print("Please attach the file in our ChatGPT conversation. Do not upload it publicly without reviewing.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
