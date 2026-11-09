#!/usr/bin/env python3
"""Verify a Windows-uploaded HONOR 70 Board ZIP release, then extract only
engineering bootchain evidence for read-only research. No flash commands.
"""
import argparse
import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path

STOCK = {
    "abl.elf": "21b95d40a9337af53e0173867a2f07dfc4ceb84ff53129c463f4e0f1bdf0abd8",
    "xbl.elf": "a2c2ffb2c711c477054d6f9f5e745912a56bd104506374606f54ee0eac06226b",
    "xbl_config.elf": "f87edd52fa25e17621c4b0b5f2be9e9910734e31149c007e740e4359e5c7e342",
    "km41.mbn": "c7f389b80444a9c9e3956efd427abbae1b5b2753b3c905107ca7888dca496afd",
    "tz.mbn": "d554da6a7e2a42ae86e3bcaa9bb4ffe0abeb7f839891fd44c60c213a9e4f3a72",
    "featenabler.mbn": "5cd32cd0b7d6e9d91cef22ddb07f2659aad0fd9c3b8be0c95a1e81ac6294b369",
}
KEEP = set([
    "bootloaderimage/abl.elf",
    "bootloaderimage/xbl.elf",
    "bootloaderimage/km41.mbn",
    "bootloaderimage/tz.mbn",
    "bootloaderimage/uefi_sec.mbn",
    "bootloaderimage/xbl_config.elf",
    "bootloaderimage/featenabler.mbn",
    "bootloaderimage/prog_firehose_ddr.elf",
    "bootloaderimage/prog_firehose_lite.elf",
    "fastbootimage/gpt_both0.bin",
    "fastbootimage/patch_avb.img",
    "FNE-AN00-BD_1.0.0.34_Download.xml",
])
PART_PATTERN = re.compile(r"^HONOR70_BOARD_HMT_part_([0-9]{3})\.bin$")

def sha_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for buf in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(buf)
    return h.hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-dir", default="incoming")
    parser.add_argument("--output-dir", default="board_audit")
    args = parser.parse_args()
    asset_dir = Path(args.asset_dir)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_file = asset_dir / "HONOR70_BOARD_HMT_SHA256_manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8-sig"))
    if manifest.get("format") != "consecutive-byte-split-v1":
        raise ValueError("Unexpected split release manifest")
    entries = manifest.get("parts", [])
    if not (2 <= len(entries) <= 50 and len(entries) == manifest.get("part_count")):
        raise ValueError("Wrong number of parts")
    if not (1024 <= manifest.get("source_bytes", 0) <= 8 * 1024**3):
        raise ValueError("Unexpected source ZIP size")
    rebuilt = out_dir / "reconstructed_board.zip"
    total = 0
    digest = hashlib.sha256()
    with rebuilt.open("wb") as dest:
        for i, row in enumerate(entries, 1):
            expected = f"HONOR70_BOARD_HMT_part_{i:03}.bin"
            if row.get("name") != expected or not PART_PATTERN.fullmatch(expected):
                raise ValueError("Manifest part sequence mismatch")
            src = asset_dir / expected
            if not src.is_file() or src.stat().st_size != row["bytes"]:
                raise ValueError("Part is missing or wrong size: " + expected)
            if sha_file(src) != row["sha256"]:
                raise ValueError("Part digest mismatch: " + expected)
            with src.open("rb") as f:
                for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
                    dest.write(block)
                    digest.update(block)
                    total += len(block)
            print("VALIDATED_PART",expected,row["bytes"],flush=True)
    if total != manifest["source_bytes"] or digest.hexdigest() != manifest["source_sha256"]:
        raise ValueError("Reconstructed ZIP size/hash mismatch")
    print("ORIGINAL_ZIP_VERIFIED",total,digest.hexdigest(),flush=True)

    report = {
        "safe_to_flash": False,
        "source": manifest["source"],
        "source_bytes": total,
        "source_sha256": digest.hexdigest(),
        "entries": [],
    }
    selected = []
    with zipfile.ZipFile(rebuilt) as archive:
        for info in archive.infolist():
            norm = info.filename.replace("\\", "/")
            idx = norm.find("/Firmware/")
            if idx >= 0:
                rel = norm[idx + len("/Firmware/"):]
            elif norm.startswith("Firmware/"):
                rel = norm[len("Firmware/"):]
            else:
                continue
            if rel in KEEP or re.fullmatch(r"bootloaderimage/(gpt_main[0-5]\.bin|rawprogram[0-5]\.xml|patch[0-5]\.xml|download_for_7325_v1\.0\.bat)",rel):
                if info.file_size > 10 * 1024**2:
                    raise ValueError("Unexpected huge selected file " + rel)
                selected.append((rel,info))
        if not any(name=="bootloaderimage/abl.elf" for name,_ in selected):
            raise ValueError("Signed ABL not found")
        if not any(name=="bootloaderimage/km41.mbn" for name,_ in selected):
            raise ValueError("Keymaster not found")
        # Output artifact intentionally excludes OEMINFO, FRP, personal data.
        with zipfile.ZipFile(out_dir / "selected_bootchain.zip", "w", compression=zipfile.ZIP_DEFLATED) as output:
            for name,info in sorted(selected):
                data=archive.read(info)
                digest=hashlib.sha256(data).hexdigest()
                basename=name.split("/")[-1]
                stock_sha=STOCK.get(basename)
                record={
                    "name":name,
                    "bytes":len(data),
                    "sha256":digest,
                    "eea_sha256":stock_sha,
                    "identical_to_eea":(digest==stock_sha) if stock_sha else None,
                }
                report["entries"].append(record)
                output.writestr(name,data)
                print("EXTRACTED",name,len(data),digest,"EEA_MATCH",record["identical_to_eea"],flush=True)
    (out_dir / "board_audit_manifest.json").write_text(json.dumps(report,indent=2)+"\n")
    rebuilt.unlink()   # no need to retain 2.6 GB duplicate on runner
    print("AUDIT_COMPLETE: no phone interaction; files are NOT safe to flash.",flush=True)

if __name__=="__main__":
    main()
