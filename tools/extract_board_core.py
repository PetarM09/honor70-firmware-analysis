#!/usr/bin/env python3
"""Extract only the non-personal, bootchain-relevant files from a downloaded
FNE-AN00-BD ZIP. Read-only; never executes, flashes, or modifies firmware.
Produces a small archive for the FNE-NX9 cross-model comparison.

Usage:
 python3 tools/extract_board_core.py Honor_70_FNE-AN00_1.0.0.34_220721_HMT.zip
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

BASE = "Firmware/"
PREFERRED = {
    "bootloaderimage/abl.elf",
    "bootloaderimage/xbl.elf",
    "bootloaderimage/xbl_config.elf",
    "bootloaderimage/km41.mbn",
    "bootloaderimage/tz.mbn",
    "bootloaderimage/uefi_sec.mbn",
    "bootloaderimage/featenabler.mbn",
    "bootloaderimage/prog_firehose_ddr.elf",
    "bootloaderimage/prog_firehose_lite.elf",
    "fastbootimage/gpt_both0.bin",
    "fastbootimage/patch_avb.img",
    "FNE-AN00-BD_1.0.0.34_Download.xml",
}
MAX_EACH = 9 * 1024 * 1024
MAX_ALL = 35 * 1024 * 1024
MAX_ENTRIES = 5000

def include(rel: str) -> bool:
    if rel in PREFERRED:
        return True
    return bool(re.fullmatch(
        r"bootloaderimage/(?:gpt_main[0-5]\.bin|"
        r"rawprogram[0-5]\.xml|patch[0-5]\.xml|download_for_7325_v1\.0\.bat)",
        rel
    ))

def find_rel(name: str):
    # Absolute and untrusted archive paths are never used as output paths.
    norm = name.replace("\\", "/")
    index = norm.find("/" + BASE)
    if index >= 0:
        return norm[index + 1 + len(BASE):]
    if norm.startswith(BASE):
        return norm[len(BASE):]
    return None

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("board_zip", help="Original downloaded HMT/BD ZIP")
    parser.add_argument("--out", default="HONOR70_BOARD_CORE_FOR_ANALYSIS.zip")
    args = parser.parse_args()
    source = Path(args.board_zip).expanduser()
    if not source.is_file() or not zipfile.is_zipfile(source):
        parser.error("Input must be an existing ZIP firmware archive")
    output = Path(args.out).expanduser()
    if source.resolve() == output.resolve():
        parser.error("Output must differ from source")
    selected = []
    with zipfile.ZipFile(source) as firmware:
        entries = firmware.infolist()
        if len(entries) > MAX_ENTRIES:
            raise SystemExit("Unexpected ZIP entry count; stopping safely")
        for entry in entries:
            if entry.is_dir():
                continue
            rel = find_rel(entry.filename)
            if rel is None or not include(rel):
                continue
            if entry.flag_bits & 1:
                raise SystemExit("Encrypted required file: " + rel)
            if entry.file_size > MAX_EACH:
                raise SystemExit("Unexpected oversized selected entry: " + rel)
            selected.append((rel, entry))
        selected.sort(key=lambda pair: pair[0])
        paths = [rel for rel, _ in selected]
        if len(set(paths)) != len(paths):
            raise SystemExit("Ambiguous duplicate selected firmware paths; stopping")
        required = {
            "bootloaderimage/abl.elf",
            "bootloaderimage/xbl.elf",
            "bootloaderimage/km41.mbn",
            "bootloaderimage/prog_firehose_ddr.elf",
        }
        missing = sorted(required - set(paths))
        if missing:
            raise SystemExit("Missing required paths: " + ", ".join(missing))
        expected_bytes = sum(item.file_size for _, item in selected)
        if expected_bytes > MAX_ALL:
            raise SystemExit("Unexpected selected uncompressed bytes; stopping")
        manifest = {
            "source_zip": source.name,
            "source_size_bytes": source.stat().st_size,
            "purpose": "read_only_original_board_vs_eea_bootchain_comparison",
            "safe_to_flash": False,
            "selected_uncompressed_bytes": expected_bytes,
            "entries": [],
        }
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=7) as target:
            for rel, member in selected:
                digest = hashlib.sha256()
                with firmware.open(member) as f:
                    buf = bytearray()
                    while True:
                        chunk = f.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                        buf.extend(chunk)
                if len(buf) != member.file_size:
                    raise SystemExit("Read length mismatch: " + rel)
                target.writestr(rel, bytes(buf))
                manifest["entries"].append({
                    "path": rel,
                    "size": member.file_size,
                    "sha256": digest.hexdigest(),
                })
            target.writestr("BOARD_CORE_MANIFEST.json",
                            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print("OUTPUT", output.resolve())
    print("OUTPUT_BYTES", output.stat().st_size)
    print("FILES", len(selected))
    print("IMPORTANT: NOT A FLASHING PACKAGE; DO NOT FLASH OR RUN EMBEDDED TOOLS")
    print("Share only this extracted ZIP privately for analysis.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
