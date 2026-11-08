#!/usr/bin/env python3
"""Read-only Android service diagnosis. No root, fastboot, writes, service calls, flashes or FRP dumps.
Only selected lines from Android's service diagnostic output are retained.
"""
import pathlib
import re
import shutil
import subprocess
import sys

CHECKS = [
    ("phone", "getprop ro.product.model"),
    ("build", "getprop ro.build.version.incremental"),
    ("frp_path", "getprop ro.frp.pst"),
    ("reported_oem_permission", "getprop sys.oem_unlock_allowed"),
    ("flash_locked", "getprop ro.boot.flash.locked"),
    ("vbmeta_state", "getprop ro.boot.vbmeta.device_state"),
    ("frp_partition_link", "ls -l /dev/block/by-name/frp 2>&1"),
    ("devinfo_partition_link", "ls -l /dev/block/by-name/devinfo 2>&1"),
    ("efisp_partition_exists", "test -e /dev/block/by-name/efisp && echo EXISTS || echo NOT_PRESENT"),
    ("oem_lock_dump", "dumpsys -t 8 oem_lock 2>&1"),
    ("persistent_data_block_dump", "dumpsys -t 8 persistent_data_block 2>&1"),
]

# Do not expose arbitrary service dump content: redact long tokens and keep only relevant lines.
WHITELIST = re.compile(r"(?i)unlock|oem|flash|frp|persistent|access.denied|permission|unsupported|not.found|unavailable|error|no.service|service|carrier|device.policy|user.restriction")
LONG_SECRET = re.compile(r"(?i)(?:[0-9a-f]{16,}|[A-Za-z0-9+/]{28,}={0,2})")
MAX_LINE = 240
MAX_MATCHES = 50

def run(command):
    try:
        p=subprocess.run(["adb", "shell", command], capture_output=True, text=True, timeout=20, errors="replace")
        return p.returncode, (p.stdout+"\n"+p.stderr).strip()
    except Exception as exc:
        return 99, type(exc).__name__+": "+str(exc)

def main():
    if not shutil.which("adb"):
        print("ADB is not installed or is not in PATH.")
        return 2
    state=subprocess.run(["adb", "get-state"],capture_output=True,text=True,timeout=10)
    if state.returncode or state.stdout.strip()!="device":
        print("ADB device not ready. Connect phone and allow USB debugging.")
        return 3
    lines=["HONOR70_FRP_OEMLOCK_READONLY","Collected without root, writes, dumps of partitions, or Binder service call transactions.",""]
    for label, command in CHECKS:
        status,out=run(command)
        lines.append("=== "+label+" return="+str(status)+" ===")
        if label.endswith("_dump"):
            matches=[v.strip() for v in out.splitlines() if WHITELIST.search(v)]
            if not matches:matches=["(No matching diagnostic lines. Full dump intentionally discarded.)"]
            for s in matches[:MAX_MATCHES]:
                lines.append(LONG_SECRET.sub("[REDACTED]",s[:MAX_LINE]))
            if len(matches)>MAX_MATCHES:lines.append("... additional matching lines omitted")
        else:
            lines.append(LONG_SECRET.sub("[REDACTED]",out[:MAX_LINE] or "(empty)"))
        lines.append("")
    target=pathlib.Path.cwd()/"HONOR70_FRP_OEMLOCK_READONLY.txt"
    target.write_text("\n".join(lines)+"\n",encoding="utf-8")
    print("Report saved:",target)
    print("Read the file before sharing it in the private chat; do not publish live device diagnostics to a public GitHub release.")
    return 0

if __name__=="__main__":
    sys.exit(main())
