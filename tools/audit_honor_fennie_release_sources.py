#!/usr/bin/env python3
"""Bounded, read-only examination of HONOR Open Source Release ZIP packages.

Never executes code inside archives, never extracts onto working filesystem,
only opens directly relevant small text files and bounded nested ZIP/TARs.
Reports source presence + snippets for human comparison to exact signed kernel.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import tarfile
import zipfile
from pathlib import Path

MAX_NESTED_DEPTH = 2
MAX_NESTED_ARCHIVES = 20
MAX_NESTED_BYTES = 800 * 1024 * 1024
MAX_TEXT_BYTES = 5 * 1024 * 1024
MAX_SOURCE_MATCHES = 1000
MAX_SOURCE_SAMPLES = 80
RELEVANT = re.compile(
    r"(?:^|/)(?:rtmutex(?:_common)?\.c|rtmutex\.h|futex(?:_pi)?\.c|"
    r"sched\.h|(?:[\w.-]*defconfig)|"
    r"fennie[\w.-]*\.(?:dts|dtsi)|"
    r"qcom[\w.-]*\.config)$", re.I
)
NESTED = re.compile(r"\.(?:zip|tar|tar\.gz|tgz|tar\.xz|txz|tar\.bz2|tbz2)$", re.I)
CODE_TERMS = re.compile(
    r"remove_waiter|rt_mutex_start_proxy_lock|rt_mutex_cleanup_proxy_lock|"
    r"pi_blocked_on|CONFIG_FUTEX(?:_PI)?|CONFIG_RT_MUTEXES|"
    r"(?:struct\s+rt_mutex_waiter)|(?:struct\s+task_struct)|"
    r"5\.4\.295|ga2d8945339ca", re.I
)
KEY_TERMS = ("remove_waiter", "rt_mutex_start_proxy_lock",
             "pi_blocked_on", "CONFIG_FUTEX_PI", "CONFIG_RT_MUTEXES")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def kind(path):
    n = path.lower()
    if n.endswith(".zip"):
        return "zip"
    if n.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2")):
        return "tar"
    return None


class Auditor:
    def __init__(self):
        self.stats = {"archives_opened": 0, "entries_examined": 0,
                      "nested_skipped": 0, "files_matched": 0,
                      "text_read_errors": 0}
        self.source = []
        self.nested = []
        self.errors = []
        self.total_nested_bytes = 0

    def record_source(self, path, data):
        if len(self.source) >= MAX_SOURCE_SAMPLES:
            return
        decoded = data.decode("utf-8", errors="replace")
        hits = []
        lines = decoded.splitlines()
        for i, line in enumerate(lines, 1):
            if CODE_TERMS.search(line):
                hits.append({"line": i, "text": line[:260]})
                if len(hits) >= 35:
                    break
        self.source.append({
            "path": path, "bytes": len(data), "sha256": sha256(data),
            "relevant_line_samples": hits,
            "line_count": len(lines),
            "caution": "Source file text; not proof that this is exact retail compiled revision"
        })

    def visit(self, label, archive, depth=0):
        self.stats["archives_opened"] += 1
        if isinstance(archive, zipfile.ZipFile):
            entries = ((e.filename, e.file_size, lambda e=e: archive.open(e))
                       for e in archive.infolist() if not e.is_dir())
        else:
            entries = ((e.name, e.size, lambda e=e: archive.extractfile(e))
                       for e in archive if e.isfile())
        # Prioritize core source and nested kernel archives ahead of large
        # vendor defconfig/header collections, avoiding biased sample caps.
        entries = list(entries)
        def priority(item):
            n = item[0].lower()
            if n.endswith(("rtmutex.c", "futex.c", "rtmutex.h")):
                return 0
            if NESTED.search(n) and any(s in n for s in ("kernel", "source", "fennie", "android")):
                return 1
            if NESTED.search(n):
                return 2
            if "defconfig" in n:
                return 3
            return 4
        entries.sort(key=priority)
        for name, size, opener in entries:
            self.stats["entries_examined"] += 1
            canonical = name.replace("\\", "/").strip("/")
            fullname = label + "::" + canonical
            if RELEVANT.search(canonical):
                self.stats["files_matched"] += 1
                if (size <= MAX_TEXT_BYTES and
                        len(self.source) < MAX_SOURCE_SAMPLES):
                    try:
                        with opener() as f:
                            if f is None:
                                raise OSError("No text stream")
                            data = f.read(MAX_TEXT_BYTES + 1)
                        if len(data) <= MAX_TEXT_BYTES:
                            self.record_source(fullname, data)
                    except Exception as exc:
                        self.stats["text_read_errors"] += 1
                        if len(self.errors) < 15:
                            self.errors.append({"path": fullname,
                                                "reason": type(exc).__name__})
            if not NESTED.search(canonical):
                continue
            record = {"path": fullname, "stored_member_bytes": size,
                      "depth": depth, "inspected": False}
            if len(self.nested) < 150:
                self.nested.append(record)
            if (depth >= MAX_NESTED_DEPTH or
                    self.stats["archives_opened"] >= MAX_NESTED_ARCHIVES or
                    size > MAX_NESTED_BYTES or
                    self.total_nested_bytes + size > MAX_NESTED_BYTES):
                self.stats["nested_skipped"] += 1
                record["reason"] = "depth/count/budget limit"
                continue
            try:
                with opener() as f:
                    if f is None:
                        raise ValueError("Unreadable nested member")
                    data = f.read(MAX_NESTED_BYTES + 1)
                if len(data) > MAX_NESTED_BYTES:
                    self.stats["nested_skipped"] += 1
                    record["reason"] = "byte limit"
                    continue
                self.total_nested_bytes += len(data)
                b = io.BytesIO(data)
                if kind(canonical) == "zip":
                    with zipfile.ZipFile(b) as inner:
                        self.visit(fullname, inner, depth + 1)
                else:
                    with tarfile.open(fileobj=b, mode="r:*") as inner:
                        self.visit(fullname, inner, depth + 1)
                record["inspected"] = True
            except (OSError, ValueError, RuntimeError, zipfile.BadZipFile,
                    tarfile.TarError, EOFError, MemoryError) as exc:
                record["reason"] = type(exc).__name__
                self.stats["nested_skipped"] += 1

    def report(self, identity):
        findings = {term: [] for term in KEY_TERMS}
        for file in self.source:
            for hit in file["relevant_line_samples"]:
                for term in KEY_TERMS:
                    if term.lower() in hit["text"].lower() and len(findings[term]) < 10:
                        findings[term].append(
                            {"file": file["path"], "line": hit["line"],
                             "text": hit["text"]}
                        )
        return {
            **identity, "schema_version": 1, "statistics": self.stats,
            "nested_archives": self.nested,
            "selected_source_files": self.source,
            "term_index": findings, "errors": self.errors,
            "exact_c431_source_revision_proven": False,
            "ghostlock_runtime_trigger_proven": False,
            "working_exploit_or_bootloader_unlock_proven": False,
            "device_operations": 0,
            "limits": {"max_nested_depth": MAX_NESTED_DEPTH,
                       "max_nested_total_bytes": MAX_NESTED_BYTES,
                       "max_source_samples": MAX_SOURCE_SAMPLES}
        }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("archive", type=Path)
    p.add_argument("--expect-sha256", required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    if not a.archive.is_file():
        p.error("Archive missing")
    h = hashlib.sha256()
    with a.archive.open("rb") as src:
        for part in iter(lambda: src.read(2 * 1024 * 1024), b""):
            h.update(part)
    actual = h.hexdigest()
    if actual != a.expect_sha256.lower():
        raise SystemExit("RELEASE_ASSET_SHA256_MISMATCH")
    audit = Auditor()
    with zipfile.ZipFile(a.archive) as z:
        audit.visit(a.archive.name, z)
    report = audit.report({
        "asset_name": a.archive.name, "asset_sha256": actual,
        "asset_bytes": a.archive.stat().st_size
    })
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print("VERIFIED_RELEASE", report["asset_name"], actual)
    print("STATS", json.dumps(report["statistics"], sort_keys=True))
    for term, hits in report["term_index"].items():
        print("TERM", term, "hits", len(hits))
        for hit in hits[:3]:
            print("HIT", term, hit["file"], "line", hit["line"],
                  hit["text"][:160].replace("\t", " "))
    if any(not item["inspected"] for item in report["nested_archives"]):
        print("WARNING_NOT_ALL_NESTED_ARCHIVES_INSPECTED")
    print("REPORT", a.out)


if __name__ == "__main__":
    main()
