#!/usr/bin/env python3
"""Read-only, exact-device HONOR 70 live kernel configuration audit.

ADB requirements: one authorized FNE-NX9, Android 14, matching kernel.
Only invokes get-state/getprop/uname and reads /proc/config.gz via exec-out.
No futex calls, root, device file modifications, reboot or flashing.
Outputs only a compact, identifying-data-free JSON summary.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import zlib
from pathlib import Path

EXPECTED_MODEL = "FNE-NX9"
EXPECTED_DEVICE = "HNFNE"
EXPECTED_KERNEL = "5.4.295-qgki-ga2d8945339ca"
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_CONFIG_BYTES = 4 * 1024 * 1024
RELEVANT_KEYS = (
    "CONFIG_FUTEX", "CONFIG_FUTEX_PI", "CONFIG_RT_MUTEXES",
    "CONFIG_HAVE_FUTEX_CMPXCHG", "CONFIG_PREEMPT", "CONFIG_PREEMPT_RT",
    "CONFIG_IKCONFIG", "CONFIG_IKCONFIG_PROC", "CONFIG_SECCOMP",
    "CONFIG_SECCOMP_FILTER", "CONFIG_SECURITY_SELINUX",
)


def adb(*args: str, timeout: int = 15) -> bytes:
    try:
        result = subprocess.run(
            ["adb", *args], capture_output=True, check=False, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        raise RuntimeError("ADB command unavailable or timed out") from err
    if result.returncode != 0:
        raise RuntimeError("ADB command failed; verify USB authorization and permissions")
    return result.stdout


def parse_config(raw: bytes) -> dict:
    if not raw.startswith(b"\x1f\x8b\x08"):
        raise ValueError("/proc/config.gz is not a gzip stream")
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("Compressed kernel config unexpectedly large")
    try:
        inflater = zlib.decompressobj(wbits=31)
        plain = inflater.decompress(raw, MAX_CONFIG_BYTES + 1)
    except zlib.error as err:
        raise ValueError("Invalid kernel config gzip data") from err
    if not inflater.eof or len(plain) > MAX_CONFIG_BYTES:
        raise ValueError("Incomplete or oversized kernel config")
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError as err:
        raise ValueError("Kernel config is not UTF-8") from err
    options: dict[str, str] = {}
    for line in text.splitlines():
        yes = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(y|n|m)", line)
        unset = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
        if yes:
            options[yes.group(1)] = yes.group(2)
        elif unset:
            options[unset.group(1)] = "n"
    if len(options) < 100:
        raise ValueError("Kernel config format not recognized")
    relevant = {name: options.get(name, "not_listed") for name in RELEVANT_KEYS}
    futex_prereqs = (
        "confirmed_config_enabled"
        if relevant["CONFIG_FUTEX"] == "y" and
           relevant["CONFIG_FUTEX_PI"] == "y" and
           relevant["CONFIG_RT_MUTEXES"] == "y"
        else "configuration_incomplete_or_disabled"
    )
    if "not_listed" in (relevant["CONFIG_FUTEX"], relevant["CONFIG_FUTEX_PI"], relevant["CONFIG_RT_MUTEXES"]):
        futex_prereqs = "inconclusive"
    return {
        "config_sha256": hashlib.sha256(plain).hexdigest(),
        "config_entry_count": len(options),
        "relevant_options": relevant,
        "pi_futex_compile_prerequisites": futex_prereqs,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("HONOR70_LIVE_IKCONFIG_SUMMARY.json"))
    args = parser.parse_args()
    if adb("get-state").decode("ascii", errors="replace").strip() != "device":
        raise SystemExit("ADB device is not authorized and online")
    model = adb("shell", "getprop", "ro.product.model").decode().strip()
    device = adb("shell", "getprop", "ro.product.device").decode().strip()
    kernel = adb("shell", "uname", "-r").decode().strip()
    if (model, device, kernel) != (EXPECTED_MODEL, EXPECTED_DEVICE, EXPECTED_KERNEL):
        raise SystemExit("Model or kernel mismatch: refused to attribute data to stock FNE-NX9 C431")
    raw = adb("exec-out", "cat", "/proc/config.gz", timeout=20)
    parsed = parse_config(raw)
    report = {
        "schema_version": 1,
        "capture_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "model": model,
        "device_code": device,
        "kernel_release": kernel,
        "source": "on-device /proc/config.gz (read-only adb exec-out)",
        **parsed,
        "runtime_vulnerability_trigger": "not_tested",
        "userspace_app_permission": "not_tested",
        "root_exploit": "not_tested",
        "persistent_bootloader_unlock": "not_tested",
        "device_writes": 0,
        "warning": "Kernel configuration cannot demonstrate GhostLock exploitability, app syscall policy or unlock.",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Created", args.out)
    print("Compilation prerequisites:", parsed["pi_futex_compile_prerequisites"])
    print("This tool performed no device writes, futex calls or exploit attempts.")


if __name__ == "__main__":
    main()
