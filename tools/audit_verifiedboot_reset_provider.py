#!/usr/bin/env python3
"""Search an original EEA VerifiedBootDxe Ghidra report for reset-state provider.

This is an offline evidence index, not an identified protocol-pointer proof.
It produces only function addresses, text snippets and provenance metadata.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

RESET_TOKENS = (
    "reset", "Reset", "Reseting", "VBRwDevice", "device state",
    "DeviceState", "clear", "Clear", "erase", "Erase",
)


def blocks(text):
    parts = re.split(r"(?=^======== FUNCTION )", text, flags=re.M)
    result = []
    for part in parts:
        match = re.match(r"======== FUNCTION ([0-9a-fA-F]{8})\s+([^\n]*)", part)
        if match:
            result.append((match.group(1).lower(), match.group(2).strip(), part))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ghidra", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    raw = args.ghidra.read_bytes()
    text = raw.decode("utf-8", "replace")
    funs = blocks(text)
    if len(funs) < 120:
        raise ValueError(f"Unexpectedly small original XBL Ghidra report ({len(funs)} functions)")
    matches = []
    for address, header, body in funs:
        strs = re.findall(r'"((?:\\.|[^"\\])*)"', body)
        hits = [s[:240] for s in strs if any(t.lower() in s.lower() for t in RESET_TOKENS)]
        token_hits = sorted({term for term in RESET_TOKENS if term.lower() in body.lower()})
        refs = sorted(set(re.findall(r"FUN_[0-9a-fA-F]{8}", body)))
        if not hits and not any(term in token_hits for term in ("Reset", "reset", "VBRwDevice", "DeviceState")):
            continue
        score = sum(8 for s in hits if "reset" in s.lower())
        score += 5 * sum("device" in s.lower() for s in hits)
        score += 3 if "0x153c" in body.lower() else 0
        score += min(3, body.lower().count("vbrwdevice"))
        score += min(3, body.lower().count("rpmb"))
        relevant = []
        for line in body.splitlines():
            if any(term.lower() in line.lower() for term in RESET_TOKENS):
                relevant.append(line.strip()[:450])
        matches.append({
            "function_address": "0x" + address,
            "function_header": header,
            "score_heuristic_only": score,
            "matched_string_literals": hits[:24],
            "relevant_decompiled_lines": relevant[:48],
            "function_references": refs[:60]
        })
    ordered = sorted(matches, key=lambda x: (-x["score_heuristic_only"], x["function_address"]))
    report = {
        "source": "Archived exact original EEA VerifiedBootDxe Ghidra report",
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "function_count": len(funs),
        "relevant_function_count": len(ordered),
        "candidates": ordered[:30],
        "observations": [
            "ABL FUN_00038370 invokes VerifiedBoot protocol method offset 0x30 only after locating the protocol.",
            "Any XBL decompiled function containing reset strings is a candidate, not proven to occupy method offset 0x30.",
            "Confirming exact provider mapping requires a verified pointer table reference or original PE data cross-reference.",
            "This script does not access the phone or execute ResetDeviceState."
        ]
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print("FUNCTION_COUNT",len(funs),"CANDIDATES",len(ordered),
          "GHIDRA_SHA256",report["report_sha256"])
    for item in ordered[:18]:
        print("CANDIDATE", item["function_address"],
              "SCORE", item["score_heuristic_only"],
              "STRINGS",repr(item["matched_string_literals"][:6]),
              "LINES",repr(item["relevant_decompiled_lines"][:10]))


if __name__ == "__main__":
    main()
