#!/usr/bin/env python3
"""Offline, read-only comparison of factory and retail featenabler ELF images.

This does not evaluate the live device, RPMB or whether an image would boot.
Requires only Python standard library.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

PF_X = 1
PT_LOAD = 1
PATTERN = re.compile(rb"[ -~]{5,160}")
KEYWORDS = (b"rpmb", b"fuse", b"milestone", b"unlock", b"keymaster", b"device_state",
            b"qsee", b"secure", b"feature", b"rollback", b"oeminfo")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def elf_segments(data):
    if data[:4] != b"\x7fELF":
        return {"error": "not an ELF image", "segments": []}
    cls, endian = data[4], data[5]
    if cls not in (1, 2) or endian not in (1, 2):
        return {"error": "unsupported ELF class/endianness", "segments": []}
    prefix = "<" if endian == 1 else ">"
    eh_fmt = prefix + ("HHIIIIIHHHHHH" if cls == 1 else "HHIQQQIHHHHHH")
    if len(data) < 16 + struct.calcsize(eh_fmt):
        return {"error": "truncated ELF header", "segments": []}
    fields = struct.unpack_from(eh_fmt, data, 16)
    phoff, phentsize, phnum = fields[4], fields[8], fields[9]
    phfmt = prefix + ("IIIIIIII" if cls == 1 else "IIQQQQQQ")
    if phentsize < struct.calcsize(phfmt) or phnum > 4096:
        return {"error": "invalid ELF program-header layout", "segments": []}
    if phoff + phentsize * phnum > len(data):
        return {"error": "ELF program headers out of bounds", "segments": []}
    segments = []
    for idx in range(phnum):
        f = struct.unpack_from(phfmt, data, phoff + idx * phentsize)
        if cls == 1:
            p_type, offset, vaddr, _, size, _, flags, _ = f
        else:
            p_type, flags, offset, vaddr, _, size, _, _ = f
        if p_type != PT_LOAD:
            continue
        if offset + size > len(data):
            return {"error": "ELF segment out of bounds", "segments": []}
        raw = data[offset:offset + size]
        segments.append({"header_index": idx, "executable": bool(flags & PF_X),
                         "vaddr": hex(vaddr), "offset": offset, "size": size,
                         "sha256": digest(raw), "raw": raw})
    return {"error": None, "elf_class": 32 if cls == 1 else 64,
            "endianness": "little" if endian == 1 else "big", "segments": segments}


def inspect(path):
    content = path.read_bytes()
    elf = elf_segments(content)
    hits = sorted({s.decode("ascii", "replace") for s in PATTERN.findall(content)
                   if any(term in s.lower() for term in KEYWORDS)})
    return {"path": path.name, "bytes": len(content), "sha256": digest(content),
            "elf_error": elf.get("error"), "elf_class": elf.get("elf_class"),
            "endianness": elf.get("endianness"), "segments": elf["segments"],
            "security_related_strings": hits[:100]}


def public_info(info):
    return {k: v if k != "segments" else
            [{x: y for x, y in s.items() if x != "raw"} for s in v]
            for k, v in info.items()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--board", type=Path, required=True)
    p.add_argument("--eea", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--board-sha256", default="")
    p.add_argument("--eea-sha256", default="")
    args = p.parse_args()
    board, eea = inspect(args.board), inspect(args.eea)
    for name, value, expected in (("Board", board, args.board_sha256), ("EEA", eea, args.eea_sha256)):
        if expected and value["sha256"] != expected.lower():
            raise SystemExit(f"{name}: SHA256 MISMATCH: expected {expected}, got {value['sha256']}")
    a = [s for s in board["segments"] if s["executable"]]
    b = [s for s in eea["segments"] if s["executable"]]
    diffs = []
    for i in range(max(len(a), len(b))):
        if i >= len(a) or i >= len(b):
            diffs.append({"index": i, "error": "executable segment missing from one image"})
            continue
        left, right = a[i]["raw"], b[i]["raw"]
        overlap = min(len(left), len(right))
        count = sum(x != y for x, y in zip(left[:overlap], right[:overlap]))
        diffs.append({"index": i, "board_sha256": a[i]["sha256"], "eea_sha256": b[i]["sha256"],
                      "board_vaddr": a[i]["vaddr"], "eea_vaddr": b[i]["vaddr"],
                      "board_size": len(left), "eea_size": len(right),
                      "identical": left == right, "mismatched_bytes_in_overlap": count,
                      "unpaired_tail_bytes": abs(len(left) - len(right)),
                      "first_mismatch_in_overlap": next((j for j in range(overlap)
                                                         if left[j] != right[j]), None)})
    report = {
        "scope": "Offline Board vs EEA stock featenabler; no EDL or RPMB observation",
        "board": public_info(board), "eea": public_info(eea),
        "executable_segments_compared_by_ordinal": diffs,
        "executable_code_identical": bool(a and b and len(a) == len(b)
                                           and all(x["raw"] == y["raw"] for x, y in zip(a, b))),
        "only_board_strings": sorted(set(board["security_related_strings"]) -
                                     set(eea["security_related_strings"])),
        "only_eea_strings": sorted(set(eea["security_related_strings"]) -
                                   set(board["security_related_strings"])),
        "limitations": [
            "A difference in executable bytes does not establish different unlock policy.",
            "Equal executable bytes do not establish equal runtime fuse/RPMB state.",
            "No signature verification, rollback acceptance, or live EDL state is established.",
            "String matching is heuristic; absence of a string does not prove absence of functionality."
        ]
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print("BOARD", board["sha256"], board["bytes"], "EEA", eea["sha256"], eea["bytes"])
    print("EXECUTABLE_SEGMENTS", len(a), len(b), "CODE_IDENTICAL", report["executable_code_identical"])
    for item in diffs:
        print("SEGMENT", json.dumps(item, sort_keys=True))
    if not a or not b:
        print("WARNING: executable PT_LOAD not found in one or both images; code comparison inconclusive")


if __name__ == "__main__":
    main()
