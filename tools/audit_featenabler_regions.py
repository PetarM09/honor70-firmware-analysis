#!/usr/bin/env python3
"""Map Board-vs-EEA featenabler byte differences by ELF file region (read-only).

Outputs *only* metadata, hashes, offsets and counts, never raw image bytes.
Segment labels are structural, not claims about cryptographic meaning.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("Not a valid ELF header")
    kind, endian = data[4], data[5]
    if kind not in (1, 2) or endian not in (1, 2):
        raise ValueError("Unsupported ELF")
    pre = "<" if endian == 1 else ">"
    ehfmt = pre + ("HHIIIIIHHHHHH" if kind == 1 else "HHIQQQIHHHHHH")
    vals = struct.unpack_from(ehfmt, data, 16)
    phoff, ehsize, phentsize, phnum = vals[4], vals[7], vals[8], vals[9]
    phfmt = pre + ("IIIIIIII" if kind == 1 else "IIQQQQQQ")
    if (phnum > 2048 or phentsize < struct.calcsize(phfmt) or
            phoff + phentsize * phnum > len(data) or ehsize > len(data)):
        raise ValueError("Invalid ELF program-header table")
    headers = []
    for i in range(phnum):
        fields = struct.unpack_from(phfmt, data, phoff + i * phentsize)
        if kind == 1:
            kind_id, offset, vaddr, paddr, filesz, memsz, flags, align = fields
        else:
            kind_id, flags, offset, vaddr, paddr, filesz, memsz, align = fields
        if offset + filesz > len(data):
            raise ValueError(f"Segment {i} extends beyond image")
        headers.append({
            "index": i, "type": hex(kind_id), "type_integer": kind_id,
            "flags": flags, "offset": offset, "vaddr": hex(vaddr),
            "file_size": filesz, "memory_size": memsz, "alignment": align,
            "sha256": sha(data[offset:offset + filesz]) if filesz else None
        })
    return {"file_sha256": sha(data), "length": len(data), "elf_class": 32 if kind == 1 else 64,
            "phoff": phoff, "phentsize": phentsize, "phnum": phnum,
            "ehsize": ehsize, "headers": headers}


def classification(meta):
    mask = ["unmapped"] * meta["length"]
    def mark(offset, length, tag):
        if length and offset + length <= len(mask):
            mask[offset:offset + length] = [tag] * length
    mark(0, meta["ehsize"], "ELF header")
    mark(meta["phoff"], meta["phnum"] * meta["phentsize"], "program header table")
    for h in meta["headers"]:
        if not h["file_size"]:
            continue
        if h["type_integer"] == 1:
            label = "executable PT_LOAD" if h["flags"] & 1 else "non-executable PT_LOAD"
        else:
            label = "other ELF segment"
        mark(h["offset"], h["file_size"], label)
    return mask


def compare(a, b, ma, mb):
    mask_a, mask_b = classification(ma), classification(mb)
    n = min(len(a), len(b))
    categories = Counter()
    spans = []
    current = None
    mismatch = 0
    for i in range(n):
        if a[i] == b[i]:
            if current:
                spans.append(current)
                current = None
            continue
        mismatch += 1
        region_a, region_b = mask_a[i], mask_b[i]
        label = region_a if region_a == region_b else f"{region_a} / {region_b}"
        categories[label] += 1
        if current and current["end_exclusive"] == i and current["region"] == label:
            current["end_exclusive"] = i + 1
            current["changed_bytes"] += 1
        else:
            if current:
                spans.append(current)
            current = {"start_offset": i, "end_exclusive": i + 1,
                       "region": label, "changed_bytes": 1}
    if current:
        spans.append(current)
    if len(a) != len(b):
        categories["unpaired trailing bytes"] += abs(len(a) - len(b))
    # Keep longest changed spans, sufficient to triage large signed-data blocks.
    ranked = sorted(spans, key=lambda item: (-item["changed_bytes"], item["start_offset"]))
    return {
        "overlap_bytes": n,
        "different_bytes_in_overlap": mismatch,
        "unpaired_trailing_bytes": abs(len(a) - len(b)),
        "difference_fraction_in_overlap": round(mismatch / n, 8) if n else None,
        "difference_count_by_region": dict(sorted(categories.items())),
        "different_contiguous_spans": len(spans),
        "largest_difference_spans": ranked[:60],
        "remaining_spans_not_listed": max(0, len(ranked) - 60)
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--board", type=Path, required=True)
    parser.add_argument("--eea", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--board-sha256", required=True)
    parser.add_argument("--eea-sha256", required=True)
    args = parser.parse_args()
    a, b = args.board.read_bytes(), args.eea.read_bytes()
    for name, raw, expected in (("Board", a, args.board_sha256),
                                ("EEA", b, args.eea_sha256)):
        if sha(raw) != expected.lower():
            raise ValueError(f"{name}: whole-image SHA256 mismatch")
    meta_a, meta_b = parse_elf(a), parse_elf(b)
    diff = compare(a, b, meta_a, meta_b)
    report = {
        "scope": "Offline structural comparison only; no device, RPMB or signature verification",
        "board": meta_a, "eea": meta_b,
        "byte_differences": diff,
        "notes": [
            "Regions named 'other ELF segment' may contain signatures, hashes, certificates or other data.",
            "This tool does not cryptographically parse these regions or infer a change in unlock policy.",
            "If segment layouts differ, region categories can span dissimilar content.",
            "Executable PT_LOAD equality does not establish identical device-side security state."
        ]
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print("IMAGE_LENGTHS", len(a), len(b))
    print("BYTE_DIFFERENCES", diff["different_bytes_in_overlap"],
          "SPANS", diff["different_contiguous_spans"],
          "TRAILING", diff["unpaired_trailing_bytes"])
    print("DIFFERENCES_BY_REGION", json.dumps(diff["difference_count_by_region"], sort_keys=True))
    for side, meta in (("BOARD", meta_a), ("EEA", meta_b)):
        for h in meta["headers"]:
            print("PROGRAM_HEADER", side, h["index"], h["type"], "flags", h["flags"],
                  "offset", h["offset"], "size", h["file_size"], "sha256", h["sha256"])
    print("LARGEST_SPANS", json.dumps(diff["largest_difference_spans"][:10]))


if __name__ == "__main__":
    main()
