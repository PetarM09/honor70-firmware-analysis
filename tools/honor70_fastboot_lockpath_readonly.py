#!/usr/bin/env python3
"""HONOR70 FNE-NX9 EEA readonly live-Fastboot lock-path diagnostic.
Windows/macOS/Linux; Python 3.9+. NEVER invokes unlock, flash, erase, format,
OEMINFO changes, partition writes, or tests exploit code.

Usage (phone ALREADY in bootloader/Fastboot mode):
    py -3 honor70_fastboot_lockpath_readonly.py
Or with authorized ADB debugging enabled (switches into Fastboot, then back):
    py -3 honor70_fastboot_lockpath_readonly.py --enter-fastboot --reboot-at-end

Output: HONOR70_FASTBOOT_LOCKPATH_READONLY.txt
"""
from __future__ import annotations
import argparse
import datetime
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

SAFE_FASTBOOT = [
    ["getvar", "product"],
    ["getvar", "version-bootloader"],
    ["getvar", "version"],
    ["getvar", "secure"],
    ["getvar", "unlocked"],
    ["getvar", "is-userspace"],
    ["getvar", "current-slot"],
    ["getvar", "slot-count"],
    ["flashing", "get_unlock_ability"],
    ["oem", "get-bootinfo"],
    ["oem", "lock-state", "info"],
]
ADB_PROPERTIES = [
    "ro.product.model",
    "ro.build.display.id",
    "ro.boot.flash.locked",
    "ro.boot.verifiedbootstate",
    "ro.boot.vbmeta.device_state",
    "sys.oem_unlock_allowed",
    "ro.frp.pst",
    "ro.boot.bootloader",
    "ro.oem_unlock_supported",
]
ALLOWED_COMMAND_TYPES = {
    ("getvar",),
    ("flashing", "get_unlock_ability"),
    ("oem", "get-bootinfo"),
    ("oem", "lock-state", "info"),
}
MAX_SECONDS_PER_CMD = 17

def redact(text: str) -> str:
    text = re.sub(r"(?im)(\b(?:serial(?:no|number)?|imei|meid|device.?id)\b\s*[:=]\s*)[^\r\n ]+",
                  r"\1[REDACTED]", text)
    text = re.sub(r"(?im)(\b(?:SN|IMSI|ICCID)\b\s*[:=]\s*)[^\r\n ]+",
                  r"\1[REDACTED]", text)
    # Don't include any accidentally emitted USB path or host username.
    return text.replace(os.environ.get("USERNAME", "__NO_USER__"), "[USER]") if os.environ.get("USERNAME") else text

def run(argv, timeout=MAX_SECONDS_PER_CMD):
    try:
        p=subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, shell=False)
        return p.returncode, redact(((p.stdout or "") + "\n" + (p.stderr or "")).strip())[:9000]
    except subprocess.TimeoutExpired:
        return 124, f"Timeout after {timeout}s, process killed"
    except Exception as exc:
        return 125, f"{type(exc).__name__}: {exc}"

def locate(binary: str, explicit: str|None) -> str|None:
    if explicit and Path(explicit).is_file():
        return str(Path(explicit).resolve())
    found=shutil.which(binary)
    if found:
        return found
    if os.name == "nt":
        target=binary+".exe"
        home=Path.home()
        choices=[
            home/"Downloads"/"platform-tools"/target,
            home/"platform-tools"/target,
            Path(os.environ.get("LOCALAPPDATA","C:/notfound"))/"Android"/"Sdk"/"platform-tools"/target,
            Path("C:/platform-tools")/target,
        ]
        for item in choices:
            if item.is_file():return str(item)
    return None

def attached_ids(text: str, expected_mode: str) -> int:
    count=0
    for line in text.splitlines():
        parts=line.strip().split()
        if len(parts)>1 and parts[1]==expected_mode:
            count+=1
    return count

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--enter-fastboot", action="store_true",
                   help="If Android/ADB is connected and Fastboot is not active, reboot into bootloader.")
    p.add_argument("--reboot-at-end", action="store_true",
                   help="After read-only queries, reboot from Fastboot into Android (no erase).")
    p.add_argument("--fastboot-path", default=None, help="Path to fastboot(.exe) binary.")
    p.add_argument("--adb-path", default=None, help="Path to adb(.exe) binary.")
    p.add_argument("--output", default="HONOR70_FASTBOOT_LOCKPATH_READONLY.txt")
    args=p.parse_args()
    fastboot=locate("fastboot", args.fastboot_path)
    adb=locate("adb", args.adb_path)
    if not fastboot:
        print("Fastboot executable not found. Install Google's Android platform-tools or pass --fastboot-path.")
        return 2
    log=[
       "HONOR70_FNE-NX9_LIVE_FASTBOOT_LOCKPATH_READONLY",
       "UTC="+datetime.datetime.now(datetime.timezone.utc).isoformat(),
       "METHOD=readonly_fastboot_getvar_and_state_query",
       "NOTICE=No unlock/flash/erase/wipe/format/write commands were executed.",
       "ADB_PROPERTIES="+",".join(ADB_PROPERTIES),
    ]

    code,raw=run([fastboot,"devices"],timeout=12)
    active=attached_ids(raw,"fastboot")
    log.append("FASTBOOT_DEVICE_COUNT="+str(active))
    if active==0 and adb and args.enter_fastboot:
        rc,device_result=run([adb,"devices"],timeout=10)
        adb_online=attached_ids(device_result,"device")
        log.append("AUTHORIZED_ADB_DEVICE_COUNT="+str(adb_online))
        if adb_online!=1:
            print("Need exactly one authorized ADB device; got",adb_online)
            return 3
        for prop in ADB_PROPERTIES:
            rc,val=run([adb,"shell","getprop",prop],timeout=10)
            log.append("ADB_PROP "+prop+" = "+(val[:120] if rc==0 else "ERROR:"+val[:120]))
        print("Rebooting authorized Android device to Fastboot (no data modifications).")
        rc,output=run([adb,"reboot","bootloader"],timeout=15)
        log.append("ADB_REBOOT_BOOTLOADER_RC="+str(rc))
        if rc!=0:
            print("adb reboot bootloader failed:",output)
            return 4
        for _ in range(20):
            time.sleep(1)
            code,raw=run([fastboot,"devices"],timeout=7)
            active=attached_ids(raw,"fastboot")
            if active==1:
                break
    if active!=1:
        print("Exactly one Fastboot device is required; detected",active)
        print("On the same Windows PC with ADB debugging enabled you can run:")
        print("    py -3 honor70_fastboot_lockpath_readonly.py --enter-fastboot --reboot-at-end")
        print("Or manually boot your phone into Fastboot and rerun.")
        print("No changes were made to any partitions.")
        return 5

    print("Fastboot found. Running only read-only getvar / get_unlock_ability / oem status commands.")
    for pieces in SAFE_FASTBOOT:
        if not (pieces[0]=="getvar" or tuple(pieces) in ALLOWED_COMMAND_TYPES):
            raise RuntimeError("Internal disallowed command check failed: "+repr(pieces))
        rc,output=run([fastboot]+pieces)
        log.append("")
        log.append("COMMAND=fastboot "+" ".join(pieces))
        log.append("EXIT_CODE="+str(rc))
        log.append("RESPONSE_BEGIN")
        log.append(output)
        log.append("RESPONSE_END")
        print("QUERY", " ".join(pieces), "EXIT",rc)

    target=Path(args.output)
    target.write_text("\n".join(log)+"\n",encoding="utf-8")
    print("RESULT_FILE="+str(target.resolve()))
    if args.reboot_at_end:
        rc,output=run([fastboot,"reboot"],timeout=15)
        print("BOOTLOADER_REBOOT_RC",rc)
        if rc!=0:
            print("If the phone stays in bootloader, press and hold Power to restart it.")
    else:
        print("Phone remains in Fastboot. Run 'fastboot reboot' to return to Android.")
    print("Share only the sanitized report. Never run fastboot flashing unlock / fastboot erase / fastboot flash.")
    return 0

if __name__=="__main__":
    sys.exit(main())
