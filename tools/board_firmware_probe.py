#!/usr/bin/env python3
"""Read-only inventory of HONOR 70 FNE-NX9-BD engineering/board firmware.
Never flashes, modifies or executes device firmware. Python 3.10+.
Outputs only package metadata, content hashes, and selected *public* strings.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path

BOOT_NAMES = (
    "abl", "xbl", "xbl_config", "tz", "km41", "keymaster", "uefisecapp",
    "vbmeta", "devinfo", "firehose", "prog_", "edl", "bootloader",
    "fastboot", "factory", "board", "recovery", "oeminfo",
)
UNLOCK_TERMS = (
    b"get_unlock_ability", b"flashing unlock", b"unlock bootloader",
    b"unlock critical", b"VBRwDevice", b"VerifiedBootDxe",
    b"QcomVerifiedBoot", b"NoAVBLoad", b"milestone",
    b"keymaster", b"devinfo", b"oeminfo", b"factory",
)
STOCK_SHA256 = {
    "linuxloader_efi": "ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087",
    "verifiedboot_dxe": "f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55",
    "km41": "c7f389b80444a9c9e3956efd427abbae1b5b2753b3c905107ca7888dca496afd",
}

def sha_stream(stream, sample_limit=0):
    digest = hashlib.sha256()
    total = 0
    sample = bytearray()
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
        if len(sample) < sample_limit:
            sample.extend(chunk[:sample_limit - len(sample)])
    return digest.hexdigest(), total, bytes(sample)

def inventory(path, inventory_only=False):
    results = {
        "source_name": path.name,
        "source_size_bytes": path.stat().st_size,
        "read_only": True,
        "stock_reference_hashes": STOCK_SHA256,
        "entries": [],
        "interesting": [],
    }
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = info.filename
            kind = "directory" if info.is_dir() else "file"
            entry = {
                "path": name,
                "type": kind,
                "bytes": info.file_size,
                "compressed_bytes": info.compress_size,
                "encrypted": bool(info.flag_bits & 1),
            }
            results["entries"].append(entry)
            if info.is_dir():
                continue
            basename = name.replace("\\", "/").lower().split("/")[-1]
            if any(k in basename for k in BOOT_NAMES) or basename.endswith((".xml", ".cfg", ".ini", ".json")):
                row = dict(entry)
                if not inventory_only and not row["encrypted"] and info.file_size <= 512 * 1024 * 1024:
                    with archive.open(info) as stream:
                        sha, size, sample = sha_stream(stream, sample_limit=4 * 1024 * 1024)
                    row["sha256"] = sha
                    row["size_verified"] = size
                    row["matches_stock_module"] = [k for k, value in STOCK_SHA256.items() if value == sha]
                    row["firmware_string_matches_first_4MiB"] = sorted({
                        t.decode("ascii", "replace") for t in UNLOCK_TERMS if t.lower() in sample.lower()
                    })
                else:
                    row["hash_not_computed_reason"] = (
                        "Encrypted or >512 MiB (inventory only; do not use huge memory reads)"
                    )
                results["interesting"].append(row)
    return results

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("board_zip", help="FNE-NX9-BD engineering board package ZIP from a legitimate source")
    p.add_argument("--output", default="HONOR70_BOARD_FIRMWARE_INSPECTION.json",
                   help="Destination JSON report (no device identifiers)")
    p.add_argument("--inventory-only", action="store_true",
                   help="Only list ZIP filenames and uncompressed sizes")
    args=p.parse_args()
    src=Path(args.board_zip).expanduser()
    if not src.is_file():p.error("Board archive not found: "+str(src))
    if not zipfile.is_zipfile(src):p.error("Input is not a valid ZIP archive")
    result=inventory(src,args.inventory_only)
    output=Path(args.output).expanduser()
    output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("PROBE_DONE source="+src.name+" package_bytes="+str(result["source_size_bytes"]))
    print("ZIP_ENTRIES",len(result["entries"]),"INTERESTING_FILES",len(result["interesting"]))
    for row in result["interesting"]:
        print("CANDIDATE",row["path"],"SIZE",row["bytes"],"SHA256",row.get("sha256","NOT_HASHED"),
              "STOCK_IDENTICAL",row.get("matches_stock_module",[]))
    print("JSON_REPORT",str(output))
    print("NO DEVICE PARTITIONS OR SECURITY SETTINGS WERE MODIFIED")

if __name__=="__main__":
    main()
