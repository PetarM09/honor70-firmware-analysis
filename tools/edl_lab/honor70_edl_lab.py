#!/usr/bin/env python3
"""HONOR 70 FNE-NX9 EDL experiment harness.

Designed for the user's own lab device. External Qualcomm EDL executable
(bkerler/edl) and a signed programmer are prerequisites.

The default commands inspect/backup NEVER write to the handset. The flash
command requires an explicit irreversible-risk acknowledgement, SHA256 of
both the replacement image and the original backup, a previous GPT probe,
and a fresh pre-flash readback to reduce wrong-device/wrong-image mistakes.

This script does NOT unlock the bootloader automatically and DOES NOT defeat
Qualcomm secure boot, Keymaster/RPMB, or programmer authentication.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

RESEARCH_DEVICE = "FNE-NX9"
BOARD_LOADERS = {
    "9c892e716320764c20055d8374bf8eca7418b3ff2177f81794e18d3656fc55a8": "FNE-AN00 HMT Board DDR Firehose (not validated on FNE-NX9)",
    "e029df6e2d532de87c2279e960472ec0e4799aca53bc27ed4fa3e4027b05d101": "FNE-AN00 HMT Board Lite Firehose (not validated on FNE-NX9)",
}
BACKUP_PARTITIONS = [
    "abl_a", "abl_b", "xbl_a", "xbl_b", "xbl_config_a", "xbl_config_b",
    "devinfo", "oeminfo", "frp", "boot_a", "boot_b", "vbmeta", "vbmeta_a",
    "vbmeta_b", "uefisecapp_a", "uefisecapp_b", "tz_a", "tz_b",
]
DANGEROUS_PARTITIONS = set(BACKUP_PARTITIONS) | {"super", "dtbo_a", "dtbo_b", "recovery_a", "recovery_b"}
UNSAFE_LOG_PATTERN = re.compile(r"(?i)(serial\s*(?:number|no)?\s*[:=]\s*)[^\s]+")
FATAL = re.compile(r"(?i)(?:sahara.*(?:fail|error)|unable to connect|no device found|firehose.*(?:fail|error)|invalid programmer|loader rejected|authentication failed)")


def sha256_file(file: Path) -> str:
    h = hashlib.sha256()
    with file.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_hex(s: str) -> str:
    s = s.strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", s):
        raise ValueError("Expected exactly 64 hexadecimal SHA256 digits")
    return s


def sanitize(s: str) -> str:
    return UNSAFE_LOG_PATTERN.sub(r"\1[REDACTED]", s)


def save_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run_edl(edl: str, args: list[str], cwd: Path, timeout: int = 180) -> tuple[int, str]:
    cmd = [edl] + args
    print("Running:", " ".join(str(x) for x in cmd))
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, timeout=timeout, text=True, errors="replace", shell=False)
        return p.returncode, sanitize((p.stdout or "") + "\n" + (p.stderr or ""))[:1_000_000]
    except subprocess.TimeoutExpired as ex:
        return 124, "EDL timeout after " + str(ex.timeout) + " seconds. The programmer or device may be unresponsive."
    except Exception as ex:
        return 125, type(ex).__name__ + ": " + str(ex)


def probe(args, ctx) -> tuple[bool, dict]:
    code, output = run_edl(args.edl, ["printgpt", "--memory=ufs", "--loader=" + str(args.loader)], ctx, 240)
    (ctx / "gpt_probe.log").write_text(output, encoding="utf-8")
    lower = output.lower()
    markers = {name: bool(re.search(r"(?<![a-z0-9_])" + re.escape(name) + r"(?![a-z0-9_])", lower)) for name in BACKUP_PARTITIONS}
    essentials = ("frp", "oeminfo", "devinfo", "abl_a", "xbl_a")
    ok = code == 0 and not FATAL.search(output) and all(markers.get(x, False) for x in essentials)
    result = {
        "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "operation": "UFS GPT probe; read only",
        "loader_sha256": sha256_file(args.loader),
        "loader_source": BOARD_LOADERS.get(sha256_file(args.loader), "Unknown/not on known Board loader list"),
        "edl_exit_code": code, "passed_basic_gpt_checks": ok,
        "required_partition_markers": {x: markers.get(x, False) for x in essentials},
        "detected_named_partitions": [x for x in BACKUP_PARTITIONS if markers[x]],
    }
    save_json(ctx / "gpt_probe.json", result)
    print("GPT inspection:", "PASS" if ok else "FAIL", "- see gpt_probe.log")
    return ok, result


def backup(args, ctx, probe_result) -> bool:
    dest = ctx / "backups"
    dest.mkdir(exist_ok=True)
    found = set(probe_result["detected_named_partitions"])
    manifest = {"target": RESEARCH_DEVICE, "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "loader_sha256": sha256_file(args.loader), "partitions": {},
                "warning": "Keep raw backups PRIVATE; OEMINFO/FRP/DEVINFO may contain device-specific identifiers and calibration material."}
    for part in BACKUP_PARTITIONS:
        if part not in found:
            continue
        out = dest / (part + ".img")
        if out.exists():
            print("Existing backup:", out, "- will not overwrite.")
            manifest["partitions"][part] = {"status": "existing", "size": out.stat().st_size, "sha256": sha256_file(out)}
            continue
        code, log = run_edl(args.edl, ["r", part, str(out.resolve()), "--memory=ufs", "--loader=" + str(args.loader)], ctx, 600)
        (dest / (part + ".log")).write_text(log, encoding="utf-8")
        if code != 0 or FATAL.search(log) or not out.exists() or out.stat().st_size == 0:
            out.unlink(missing_ok=True)
            manifest["partitions"][part] = {"status": "failed", "exit_code": code}
            print("Backup failed/skipped:", part)
        else:
            manifest["partitions"][part] = {"status": "ok", "size": out.stat().st_size, "sha256": sha256_file(out)}
            print("Backup OK:", part, out.stat().st_size, "bytes")
        save_json(ctx / "backup_manifest.json", manifest)
    save_json(ctx / "backup_manifest.json", manifest)
    return bool(manifest["partitions"]) and all(x["status"] != "failed" for x in manifest["partitions"].values())


def flash(args, ctx, probe_result) -> int:
    part = args.partition.lower().strip()
    if not re.fullmatch(r"[a-z0-9_]+", part):
        print("Invalid partition name."); return 5
    if part not in set(probe_result["detected_named_partitions"]):
        print("Target partition is absent from the current UFS GPT probe; refusing write."); return 5
    expected_new = canonical_hex(args.expected_sha256)
    new_sha = sha256_file(args.image)
    if new_sha != expected_new:
        print("STOP: image SHA256 differs from expected SHA256", new_sha); return 5
    old = ctx / "backups" / (part + ".img")
    if not old.is_file() or old.stat().st_size == 0:
        print("STOP: exact original-partition backup is missing", old); return 5
    expected_original = canonical_hex(args.expected_original_sha256)
    old_sha = sha256_file(old)
    if old_sha != expected_original:
        print("STOP: old-partition backup hash mismatch", old_sha); return 5
    manifest = json.loads((ctx / "backup_manifest.json").read_text(encoding="utf-8")) if (ctx / "backup_manifest.json").exists() else {}
    recorded = manifest.get("partitions", {}).get(part, {})
    if recorded.get("sha256") != old_sha or recorded.get("status") not in ("ok", "existing"):
        print("STOP: backup manifest does not validate the exact partition/hash"); return 5
    if args.image.stat().st_size > old.stat().st_size:
        print("STOP: replacement image exceeds original-partition byte size"); return 5
    print("Plan: write", part, "from", args.image)
    print("Before partition:", old.stat().st_size, "bytes, SHA256", old_sha)
    print("New image:", args.image.stat().st_size, "bytes, SHA256", new_sha)
    print("DANGER: permanent brick, lost calibration, antirollback rejection, or EDL-only recovery possible.")
    if not args.commit_unsafe_write:
        print("DRY RUN ONLY: add --commit-unsafe-write to execute. No device write attempted.")
        return 0
    if args.confirm != "FNE-NX9:IRREVERSIBLE":
        print("STOP: exact confirmation token not supplied."); return 5
    fresh = ctx / ("live_before_" + part + ".img")
    fresh.unlink(missing_ok=True)
    code, log = run_edl(args.edl, ["r", part, str(fresh.resolve()), "--memory=ufs", "--loader=" + str(args.loader)], ctx, 600)
    (ctx / ("preflash_" + part + ".log")).write_text(log, encoding="utf-8")
    if code != 0 or not fresh.is_file() or sha256_file(fresh) != old_sha:
        print("STOP: fresh on-device partition does not match backup. No write performed."); return 6
    write_args = ["w", part, str(args.image.resolve()), "--memory=ufs", "--loader=" + str(args.loader)]
    print("Executing explicitly authorized partition write.")
    code, log = run_edl(args.edl, write_args, ctx, 600)
    (ctx / ("flash_" + part + ".log")).write_text(log, encoding="utf-8")
    save_json(ctx / ("flash_" + part + ".json"), {
        "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "partition": part, "before_sha256": old_sha, "after_image_sha256": new_sha,
        "loader_sha256": sha256_file(args.loader), "edl_exit_code": code,
        "NOTE": "Successful Firehose write does NOT prove bootloader unlock or signature/rollback acceptance."
    })
    print("EDL returned", code, "- see log and power-cycle/readback before claiming success.")
    return code


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--edl", default="edl", help="Location of bkerler/edl command (default: edl)")
    p.add_argument("--loader", type=Path, required=True, help="Exact signed Qualcomm ELF loader to try")
    p.add_argument("--out", type=Path, default=Path("HONOR70_EDL_LAB"), help="Output directory; keep backups private")
    sub = p.add_subparsers(dest="phase", required=True)
    sub.add_parser("inspect", help="Read-only loader acceptance and UFS GPT verification")
    sub.add_parser("backup", help="Read-only backup of GPT-listed critical partitions")
    write = sub.add_parser("flash", help="Explicitly gated write of an exact image to an existing backed-up partition")
    write.add_argument("--partition", required=True)
    write.add_argument("--image", type=Path, required=True)
    write.add_argument("--expected-sha256", required=True)
    write.add_argument("--expected-original-sha256", required=True)
    write.add_argument("--commit-unsafe-write", action="store_true")
    write.add_argument("--confirm", default="", help="Exact confirmation token FNE-NX9:IRREVERSIBLE")
    args = p.parse_args(argv)
    args.loader = args.loader.expanduser().resolve()
    args.out = args.out.expanduser().resolve()
    if not args.loader.is_file():
        print("Signed EDL programmer file not found:", args.loader); return 2
    edl = shutil.which(args.edl)
    if not edl and Path(args.edl).is_file():
        edl = str(Path(args.edl).resolve())
    if not edl:
        print("bkerler/edl not found in PATH. Install it first (official README).")
        return 2
    args.edl = edl
    if args.phase == "flash" and not args.image.expanduser().is_file():
        print("Replacement image file does not exist."); return 2
    if args.phase == "flash":
        args.image = args.image.expanduser().resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    loader_hash = sha256_file(args.loader)
    print("Loader SHA256", loader_hash, "-", BOARD_LOADERS.get(loader_hash, "unrecognized loader"))
    if loader_hash in BOARD_LOADERS:
        print("IMPORTANT: Board programmer is from FNE-AN00, and acceptance on FNE-NX9 is not verified!")
    ok, result = probe(args, args.out)
    if not ok:
        print("EDL probe did not pass basic checks; no partition reads/writes will be attempted.")
        return 4
    if args.phase == "inspect":
        return 0
    if args.phase == "backup":
        return 0 if backup(args, args.out, result) else 5
    return flash(args, args.out, result)


if __name__ == "__main__":
    sys.exit(main())
