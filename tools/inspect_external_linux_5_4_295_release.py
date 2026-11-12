#!/usr/bin/env python3
"""Read-only inspection of externally supplied linux-5.4.295 source release.

Compares source identity and selected functions to SHA-pinned HONOR Fennie GPL.
Generic upstream source NEVER establishes an OEM struct offset or a runnable
kernel privilege escalation profile on the signed FNE-NX9 C431 Image.
"""
import argparse
import difflib
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

TARGET = (
    "Makefile",
    "kernel/futex.c",
    "kernel/locking/rtmutex.c",
    "kernel/locking/rtmutex_common.h",
    "include/linux/sched.h",
    "include/linux/cred.h",
    "include/linux/seccomp.h",
    "include/linux/fs.h",
    "fs/select.c",
    "arch/arm64/Kconfig",
    "kernel/sched/core.c",
    "kernel/fork.c",
)
MAX_FILE = 4 * 1024 * 1024
FENNIE_SHA = {
    "kernel/futex.c": "71b9c7591dc611e6f92e742858bcc044cf01b605208058498e31d444b7704106",
    "kernel/locking/rtmutex.c": "70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9",
}
FNS = (
    ("kernel/futex.c", "futex_requeue"),
    ("kernel/futex.c", "futex_wait_requeue_pi"),
    ("kernel/locking/rtmutex.c", "remove_waiter"),
    ("kernel/locking/rtmutex.c", "rt_mutex_start_proxy_lock"),
)
TOKENS = ("HONOR", "HUAWEI", "FNE-NX9", "FNE-AN00",
          "CONFIG_HISI", "CONFIG_QCOM", "CONFIG_ANDROID",
          "vip_prio", "pselect", "__randomize_layout")

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def normalized_path(name):
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts:
        return None
    return "/".join(x for x in p.parts if x not in ("", "."))

def name_of_interest(name):
    p = normalized_path(name)
    if not p:
        return None
    for rel in TARGET:
        if p == rel or p.endswith("/" + rel):
            # Never accept unrelated deep nested copies under the main tree
            prefix = p[: -(len(rel))].strip("/")
            if prefix.count("/") <= 2:
                return rel
    return None

def extract_function(source, name):
    # Source-level semantic comparison only; not a verified compiler ABI.
    pattern = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    for m in pattern.finditer(source):
        start = source.rfind("\n", 0, m.start()) + 1
        pos = m.end()
        depth = 1
        while pos < len(source) and depth > 0:
            if source[pos] == "(": depth += 1
            elif source[pos] == ")": depth -= 1
            pos += 1
        if depth:
            continue
        brace = source.find("{", pos, min(len(source), pos + 500))
        semicolon = source.find(";", pos, min(len(source), pos + 500))
        if brace < 0 or (0 <= semicolon < brace):
            continue
        depth = 1
        j = brace + 1
        while j < len(source) and depth:
            if source[j] == "{": depth += 1
            elif source[j] == "}": depth -= 1
            j += 1
        if depth == 0:
            return source[start:j]
    return None

def version_from_makefile(raw):
    data = raw.decode("utf-8", "replace")
    options = {}
    for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL", "EXTRAVERSION", "NAME"):
        m = re.search(r"(?m)^" + re.escape(key) + r"\s*=\s*(.*)$", data)
        options[key] = m.group(1).strip() if m else None
    return options

def collect_sources(tar_path):
    chosen = {}
    ambiguous = {}
    file_count = 0
    skip = {"unsafe_paths": 0, "oversized": 0, "links": 0}
    with tarfile.open(tar_path, mode="r|xz") as tar:
        for info in tar:
            file_count += 1
            rel = name_of_interest(info.name)
            if not rel:
                if normalized_path(info.name) is None:
                    skip["unsafe_paths"] += 1
                continue
            if not info.isfile():
                skip["links"] += 1
                continue
            if info.size > MAX_FILE:
                skip["oversized"] += 1
                continue
            f = tar.extractfile(info)
            if f is None:
                continue
            data = f.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                skip["oversized"] += 1
                continue
            # Choose shallowest source path and retain evidence of duplicates
            existing = chosen.get(rel)
            if existing:
                ambiguous.setdefault(rel, []).append(info.name)
                if info.name.count("/") >= existing["archive_path"].count("/"):
                    continue
            chosen[rel] = {"archive_path": info.name, "data": data}
    return chosen, file_count, skip, ambiguous

def compare_source(generic, fennie):
    exact = sha256(generic) == sha256(fennie)
    a = generic.decode("utf-8", "replace").splitlines()
    b = fennie.decode("utf-8", "replace").splitlines()
    sm = difflib.SequenceMatcher(None, a, b, autojunk=True)
    return {
        "exact_byte_match": exact,
        "generic_sha256": sha256(generic),
        "fennie_sha256": sha256(fennie),
        "approx_line_similarity_ratio": round(sm.ratio(), 5),
        "generic_line_count": len(a),
        "fennie_line_count": len(b),
    }

def inspect(chosen, fennie):
    values = {"schema_version": 1, "analysis_type": "source_tree_not_signed_kernel",
              "archive_selected_source_count": len(chosen),
              "selected_files": {}, "function_comparison": {},
              "kernel_5_4_295_base_is_not_honor_provenance": True,
              "exact_c431_binary_ABI_validated_by_generic_source": False,
              "unresolved_profile_fields_auto_filled": 0,
              "root_or_uaf_triggered": False, "device_operations": 0}
    for path, item in chosen.items():
        raw = item["data"]
        text = raw.decode("utf-8", "replace")
        values["selected_files"][path] = {
            "path_in_tar": item["archive_path"],
            "size": len(raw),
            "sha256": sha256(raw),
            "vendor_markers": {marker: text.count(marker) for marker in TOKENS
                               if marker in text},
            "matches_honor_fennie_file": (
                sha256(raw) == FENNIE_SHA[path] if path in FENNIE_SHA else None),
        }
    if "Makefile" in chosen:
        values["makefile_version"] = version_from_makefile(chosen["Makefile"]["data"])
    for path, fn in FNS:
        original = chosen.get(path, {}).get("data", b"").decode("utf-8", "replace")
        ref = fennie.get(path, b"").decode("utf-8", "replace")
        body = extract_function(original, fn)
        ref_body = extract_function(ref, fn)
        values["function_comparison"][fn] = {
            "source_file": path,
            "generic_function_present": body is not None,
            "honor_reference_function_present": ref_body is not None,
            "same_source_body_sha256": (
                sha256(body.encode()) == sha256(ref_body.encode())
                if body is not None and ref_body is not None else None),
            "generic_current_pi_cleanup": (
                "current->pi_blocked_on" in body if body else None),
            "honor_current_pi_cleanup": (
                "current->pi_blocked_on" in ref_body if ref_body else None),
            "generic_has_proxy_lock_call": (
                "rt_mutex_start_proxy_lock(" in body if body else None),
            "honor_has_proxy_lock_call": (
                "rt_mutex_start_proxy_lock(" in ref_body if ref_body else None),
        }
    for path, ref in fennie.items():
        if path in chosen:
            values.setdefault("fennie_comparison", {})[path] = compare_source(
                chosen[path]["data"], ref)
    return values

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--fennie-futex", type=Path, required=True)
    p.add_argument("--fennie-rtmutex", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--selected-output-dir", type=Path)
    a = p.parse_args()
    fennie = {
        "kernel/futex.c": a.fennie_futex.read_bytes(),
        "kernel/locking/rtmutex.c": a.fennie_rtmutex.read_bytes(),
    }
    for path, expected in FENNIE_SHA.items():
        if sha256(fennie[path]) != expected:
            raise SystemExit("SHA_MISMATCH_ON_ORIGINAL_HONOR_GPL_REFERENCE")
    chosen, count, skipped, ambiguities = collect_sources(a.archive)
    if "Makefile" not in chosen or "kernel/futex.c" not in chosen:
        raise SystemExit("NOT_A_RECOGNIZABLE_LINUX_KERNEL_SOURCE_TREE")
    result = inspect(chosen, fennie)
    result["archive_sha256"] = sha256(a.archive.read_bytes())
    result["archive_bytes"] = a.archive.stat().st_size
    result["archive_members_visited"] = count
    result["skipped_selected_file_categories"] = skipped
    result["duplicate_selected_paths"] = ambiguities
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if a.selected_output_dir:
        a.selected_output_dir.mkdir(parents=True, exist_ok=True)
        for rel, item in chosen.items():
            target = a.selected_output_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item["data"])
    print("ARCHIVE_SHA256", result["archive_sha256"])
    print("KERNEL_MAKEFILE", json.dumps(result.get("makefile_version", {})))
    print("HONOR_FENNIE_SOURCE_SAME", {
        path: x["exact_byte_match"]
        for path, x in result.get("fennie_comparison", {}).items()})
    print("MATCHES_SIGNED_C431_KERNEL_ABI", False)
    print("UAF_ROOT_TESTED", False)

if __name__ == "__main__":
    main()
