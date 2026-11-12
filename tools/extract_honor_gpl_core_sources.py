#!/usr/bin/env python3
"""Extract only select GPL Linux kernel sources from a HONOR release inner TAR.

Streams the tar.gz; never extracts arbitrary member paths or executes content.
No device operations. Output is source-provenance manifest + selected small text.
"""
import argparse, hashlib, json, tarfile
from pathlib import Path

ROLES = {
    "kernel_rtmutex_c": "/kernel/kernel/locking/rtmutex.c",
    "kernel_rtmutex_h": "/kernel/kernel/locking/rtmutex.h",
    "include_rtmutex_h": "/kernel/include/linux/rtmutex.h",
    "include_sched_h": "/kernel/include/linux/sched.h",
    "kernel_futex_c": "/kernel/kernel/futex.c",
    "kernel_makefile": "/kernel/Makefile",
    "source_root_makefile": "/Code_Opensource/kernel/Makefile",
    "kernel_locking_kconfig": "/kernel/kernel/locking/Kconfig",
    "arch64_gki_defconfig": "/kernel/arch/arm64/configs/gki_defconfig",
}
MAX_MEMBER = 8_000_000

def extract(source, out):
    out.mkdir(parents=True, exist_ok=True)
    entries, total = {}, 0
    config_candidates = []
    with tarfile.open(source, mode="r|gz") as tf:
        for member in tf:
            if not member.isfile():
                continue
            total += 1
            name = "/" + member.name.replace("\\", "/").lstrip("/")
            if "/arch/arm64/configs/" in name and any(t in name.lower() for t in ("fne", "fennie", "gki", "vendor", "lahaina", "sm7325")) and len(config_candidates) < 200:
                config_candidates.append(member.name)
            role = next((name_key for name_key, suffix in ROLES.items()
                         if name.endswith(suffix)), None)
            if role is None or role in entries:
                continue
            if member.size > MAX_MEMBER:
                entries[role] = {"path": member.name, "error": "size_exceeds_limit"}
                continue
            fd = tf.extractfile(member)
            if fd is None:
                continue
            data = fd.read(MAX_MEMBER + 1)
            if len(data) > MAX_MEMBER:
                entries[role] = {"path": member.name, "error": "oversized"}
                continue
            dest = out / (role + ".txt")
            dest.write_bytes(data)
            entries[role] = {
                "path": member.name, "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "output_name": dest.name,
            }
    result = {
        "source_archive": source.name, "tar_entries": total,
        "selected_sources": entries, "arm64_config_candidates": config_candidates,
        "source_exact_c431_match_proven": False,
        "file_operations": "read-only source archive, local report output only",
        "device_operations": 0,
    }
    (out / "SOURCE_FILE_MANIFEST.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print("TAR_ENTRIES", total)
    for key, entry in sorted(entries.items()):
        print("SOURCE", key, entry.get("sha256", "unavailable"), entry["path"])
    return result

if __name__ == "__main__":
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--inner-tar", required=True, type=Path)
    a.add_argument("--out", required=True, type=Path)
    opt = a.parse_args()
    extract(opt.inner_tar, opt.out)
