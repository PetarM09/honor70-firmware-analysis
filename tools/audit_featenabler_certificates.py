#!/usr/bin/env python3
"""Identify DER X.509 certificates in featenabler non-load region and compare them.

Uses OpenSSL for DER parsing, returns certificate identities and changed-byte counts.
The result is structural evidence, NOT a validation of Qualcomm signed image trust.
No raw firmware or certificates are written into the output report.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


REGION_START = 4096
REGION_END = 4096 + 19928


def sha(data):
    return hashlib.sha256(data).hexdigest()


def certificates(raw):
    out = []
    pos = REGION_START
    candidates = 0
    while pos < min(REGION_END, len(raw) - 4):
        found = raw.find(b"\x30\x82", pos, min(REGION_END, len(raw) - 4))
        if found < 0:
            break
        pos = found + 2
        length = int.from_bytes(raw[found + 2:found + 4], "big")
        end = found + 4 + length
        if length < 300 or end > REGION_END or end > len(raw):
            continue
        candidates += 1
        if candidates > 256:
            raise ValueError("Too many DER candidates; aborting")
        cert = raw[found:end]
        p = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer",
             "-fingerprint", "-sha256"],
            input=cert, capture_output=True, timeout=4
        )
        if p.returncode:
            continue
        parsed = p.stdout.decode("utf-8", "replace")
        fingerprint = next((v.split("=", 1)[1].strip()
                            for v in parsed.splitlines() if "Fingerprint=" in v), None)
        out.append({
            "start": found, "end_exclusive": end, "length": len(cert),
            "der_sha256": sha(cert), "openssl_fingerprint": fingerprint,
            "subject": next((x for x in parsed.splitlines() if x.startswith("subject=")), ""),
            "issuer": next((x for x in parsed.splitlines() if x.startswith("issuer=")), "")
        })
        pos = end
    return {"candidate_sequences_tested": candidates, "valid_der_certificates": out}


def membership(index, certificates):
    return any(c["start"] <= index < c["end_exclusive"] for c in certificates)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--board", required=True, type=Path)
    p.add_argument("--eea", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--board-sha256", required=True)
    p.add_argument("--eea-sha256", required=True)
    a = p.parse_args()
    board, eea = a.board.read_bytes(), a.eea.read_bytes()
    if sha(board) != a.board_sha256.lower() or sha(eea) != a.eea_sha256.lower():
        raise ValueError("Source image SHA256 verification failed")
    if len(board) != len(eea):
        raise ValueError("This positional mapping requires equal-length images")
    board_certs = certificates(board)
    eea_certs = certificates(eea)
    board_list = board_certs["valid_der_certificates"]
    eea_list = eea_certs["valid_der_certificates"]
    counts = {"inside_certificates_in_both": 0, "inside_certificate_in_one": 0,
              "outside_identified_certificates": 0}
    for idx in range(len(board)):
        if board[idx] == eea[idx]:
            continue
        inside_a = membership(idx, board_list)
        inside_b = membership(idx, eea_list)
        if inside_a and inside_b:
            counts["inside_certificates_in_both"] += 1
        elif inside_a or inside_b:
            counts["inside_certificate_in_one"] += 1
        else:
            counts["outside_identified_certificates"] += 1
    sig_a = {x["der_sha256"] for x in board_list}
    sig_b = {x["der_sha256"] for x in eea_list}
    report = {
        "scope": "X.509 DER scan in non-PT_LOAD ELF region only; no cryptographic chain validation",
        "board": board_certs, "eea": eea_certs,
        "all_identified_certificates_have_same_hashes": sig_a == sig_b and bool(sig_a),
        "board_only_cert_sha256": sorted(sig_a - sig_b),
        "eea_only_cert_sha256": sorted(sig_b - sig_a),
        "difference_counts": counts,
        "limitations": [
            "If a certificate cannot be parsed by OpenSSL, it will not be counted.",
            "Certificate equality does not establish signature equality or boot image acceptance.",
            "Changed bytes outside DER certificates may be signatures, hash lists or other metadata.",
            "Does not test an actual handset, RPMB, fuse state or bootloader unlock."
        ]
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(report, indent=2) + "\n")
    print("DER_CERTIFICATES", len(board_list), len(eea_list),
          "SAME_CERT_SHA256_SET", report["all_identified_certificates_have_same_hashes"])
    print("CHANGED_BYTES_BY_CERT_REGION", json.dumps(counts))
    for side, certs in (("BOARD", board_list), ("EEA", eea_list)):
        for cert in certs:
            print("CERT", side, cert["start"], cert["length"], cert["der_sha256"],
                  cert["subject"], cert["issuer"])


if __name__ == "__main__":
    main()
