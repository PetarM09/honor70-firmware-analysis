#!/usr/bin/env python3
"""Offline inventory of a downloaded HONOR GPL source archive (NO extraction).

Use on the official Fennie MagicOS 8 or FNE-AN00 MagicUI 6.1 package.
ZIP and tar(.gz/.xz/.bz2) supported via Python stdlib. Lists names ONLY.
Nested archives are reported, not opened, and never treated as verified source.
No Android phone, ADB, root or firmware write required.
"""
import argparse
import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path

GROUPS = {
    "rtmutex_source": re.compile(r"(?:^|/)(?:rtmutex(?:_common)?\.c|rtmutex\.h)$", re.I),
    "futex_source": re.compile(r"(?:^|/)(?:futex(?:_pi)?\.c|futex\.h)$", re.I),
    "sched_headers": re.compile(r"(?:^|/)(?:sched\.h|sched/rt\.h|sched/priority\.h)$", re.I),
    "kernel_config": re.compile(r"(?:^|/)(?:[^/]*defconfig|\.config|config-[^/]+)$", re.I),
    "kernel_build": re.compile(r"(?:^|/)(?:Kbuild|Kconfig|Makefile)$", re.I),
    "kernel_dts": re.compile(r"(?:^|/)[^/]+\.(?:dts|dtsi)$", re.I),
}
SOURCE_HINTS = ("kernel", "msm", "qcom", "lahaina", "sm7325", "fne", "fennie", "honor")
MAX_MATCHES = 120
MAX_NESTED = 100


def stream_sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(2 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def classify(names):
    report = {name: [] for name in GROUPS}
    nested = []
    total = 0
    source_candidates = []
    for name in names:
        total += 1
        normalized = name.replace("\\", "/").lstrip("/")
        low = normalized.lower()
        if low.endswith((".zip", ".tar", ".tar.gz", ".tar.xz", ".tgz", ".txz", ".7z", ".rar")):
            if len(nested) < MAX_NESTED:
                nested.append(normalized)
        for group, pattern in GROUPS.items():
            if pattern.search(normalized) and len(report[group]) < MAX_MATCHES:
                report[group].append(normalized)
        if (
            any(s in low for s in SOURCE_HINTS)
            and low.endswith(("rtmutex.c", "futex.c", "defconfig", "rtmutex.h"))
            and len(source_candidates) < MAX_MATCHES
        ):
            source_candidates.append(normalized)
    return {
        "entries": total,
        "matches": report,
        "nested_archives": nested,
        "likely_source_candidates": source_candidates,
        "limits": {"max_matches_per_group": MAX_MATCHES, "max_nested": MAX_NESTED},
    }


def inventory(path):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            return "zip", classify(i.filename for i in zf.infolist() if not i.is_dir())
    if tarfile.is_tarfile(path):
        with tarfile.open(path, mode="r:*") as tf:
            return "tar", classify(item.name for item in tf if item.isfile())
    raise ValueError("Unsupported or invalid archive; ZIP or tar-based package required")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("archive", type=Path, help="Official downloaded archive file")
    p.add_argument("--out", type=Path, default=Path("HONOR70_FENNIE_SOURCE_INVENTORY.json"))
    args = p.parse_args()
    if not args.archive.is_file():
        p.error("Official archive file not found")
    kind, results = inventory(args.archive)
    report = {
        "schema_version": 1,
        "archive_name": args.archive.name,
        "archive_bytes": args.archive.stat().st_size,
        "archive_sha256": stream_sha256(args.archive),
        "archive_format": kind,
        **results,
        "contents_extracted": False,
        "nested_contents_inspected": False,
        "kernel_version_verified": False,
        "exact_c431_source_verified": False,
        "ghostlock_profile_ready": False,
        "device_operations": 0,
        "interpretation": (
            "Archive filename inventory only. Relevance and C431 matching must be "
            "established by inspecting source/config; nested archives remain unopened."
        ),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("Saved", args.out)
    print("Entries:", report["entries"], "nested archives:", len(report["nested_archives"]))
    for group, items in report["matches"].items():
        print(group, len(items), "(capped)")
    if report["nested_archives"]:
        print("NOTE: Source may be inside a nested archive; inventory is not conclusive.")


if __name__ == "__main__":
    main()
