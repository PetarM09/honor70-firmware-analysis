#!/usr/bin/env python3
"""Read-only extraction of embedded IKCONFIG from an exact stock kernel Image.

This script never performs phone operations or syscalls on the device. Finding
a valid IKCONFIG proves configuration provenance only when the input Image
SHA-256 is checked. Not finding IKCONFIG is NOT proof a kernel option is off.
"""
import argparse
import hashlib
import json
import re
import zlib
from pathlib import Path

KERNEL_SHA256 = "bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
START = b"IKCFG_ST"
END = b"IKCFG_ED"
MAX_COMPRESSED = 2 * 1024 * 1024
MAX_DECOMPRESSED = 4 * 1024 * 1024
CONFIG_KEYS = (
    "CONFIG_FUTEX", "CONFIG_FUTEX_PI", "CONFIG_HAVE_FUTEX_CMPXCHG",
    "CONFIG_RT_MUTEXES", "CONFIG_PREEMPT_RT", "CONFIG_IKCONFIG",
    "CONFIG_IKCONFIG_PROC", "CONFIG_SECCOMP", "CONFIG_SECCOMP_FILTER",
    "CONFIG_SECURITY_SELINUX"
)

def decode_config(config):
    values = {}
    for line in config.splitlines():
        m = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(y|m|n)", line)
        if m:
            values[m.group(1)] = m.group(2)
        m = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
        if m:
            values[m.group(1)] = "n"
    return {key: values.get(key, "not_listed") for key in CONFIG_KEYS}

def scan(data):
    """Return (status, raw_config_or_none, byte_offset_or_none)."""
    offset = 0
    malformed = 0
    while True:
        pos = data.find(START, offset)
        if pos < 0:
            return ("embedded_config_invalid" if malformed else "embedded_config_not_found", None, None)
        offset = pos + len(START)
        end = data.find(END, offset, offset + MAX_COMPRESSED)
        if end < 0:
            malformed += 1
            continue
        blob = data[offset:end]
        if not blob.startswith(b"\x1f\x8b\x08"):
            malformed += 1
            continue
        try:
            stream = zlib.decompressobj(wbits=31)
            config = stream.decompress(blob, MAX_DECOMPRESSED + 1)
            if not stream.eof or len(config) > MAX_DECOMPRESSED:
                malformed += 1
                continue
            text = config.decode("utf-8")
        except (ValueError, UnicodeError, zlib.error):
            malformed += 1
            continue
        if (not text.startswith("#") and not text.startswith("CONFIG_")) or text.count("CONFIG_") < 30:
            malformed += 1
            continue
        return ("embedded_config_found", config, pos)

def inspect_kernel(data, require_sha256=KERNEL_SHA256):
    sha = hashlib.sha256(data).hexdigest()
    if require_sha256 is not None and sha != require_sha256:
        raise ValueError("Input kernel Image does not match original signed C431 image")
    status, config, offset = scan(data)
    result = {
        "schema_version": 1, "source": "exact-original FNE-NX9 C431 kernel Image",
        "kernel_sha256": sha, "integrity_verified": require_sha256 is not None,
        "status": status, "embedded_ikconfig_offset": offset,
        "device_operations": 0,
        "finding_scope": "kernel config provenance, NOT GhostLock exploitation",
        "evidence_gaps": [
            "Missing IKCONFIG does not prove FUTEX_PI is disabled",
            "Configuration availability does not prove Android app syscall access",
            "Configuration cannot establish a trigger, root or unlock"
        ],
    }
    if config is not None:
        result["ikconfig_sha256"] = hashlib.sha256(config).hexdigest()
        result["options"] = decode_config(config.decode("utf-8"))
    else:
        result["options"] = {key: "unknown" for key in CONFIG_KEYS}
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel",required=True,type=Path)
    parser.add_argument("--out",required=True,type=Path)
    args = parser.parse_args()
    report = inspect_kernel(args.kernel.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
