#!/usr/bin/env python3
"""Cross-evidence check: stock EEA ABL display Fastboot command reachability.

Deterministic read-only comparison of separately SHA-pinned original signed
LinuxLoader metadata reports. Does not send commands or produce an exploit.
"""
import argparse, hashlib, json
from pathlib import Path

ORIGINAL_SHA = "ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087"
DISPLAY_COMMANDS = {
  "oem select-display-panel":"0x25e2c",
  "oem set-dg-img":"0x49098",
  "oem set-dg-img-resume":"0x492d0"
}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--allowlist",required=True,type=Path)
    p.add_argument("--cmds",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    b=a.allowlist.read_bytes()
    c=a.cmds.read_bytes()
    allow=json.loads(b); cmds=json.loads(c)
    if allow["eea_linuxloader_sha256"]!=ORIGINAL_SHA or cmds["sha256"]!=ORIGINAL_SHA:
        raise ValueError("Different or non-original ABL binaries")
    if allow["gate_function_rva"]!="0x134c0" or allow["dispatcher_rva"]!="0x22c7c":
        raise ValueError("Original locked mode dispatcher mismatch")
    if allow["table_entries"]!=49 or len(allow["entries"])!=49:
        raise ValueError("Original locked allowlist count mismatch")
    labels=[row["label"] for row in allow["entries"]]
    rows=[]
    for name,target in DISPLAY_COMMANDS.items():
        occurrences=cmds["command_literals"].get(name)
        if not occurrences:
            raise ValueError("Registered command literal missing "+name)
        expected=False
        for record in occurrences:
            for ptr in record["data_pointer_references"]:
                for candidate in ptr["nearby_executable_qwords"]:
                    if candidate["delta_from_ref"]==8 and candidate["candidate_code_rva"]==target:
                        expected=True
        if not expected:
            raise ValueError("Missing original adjacent command function pointer "+name+" -> "+target)
        allowed_prefixes=[s for s in labels if name.startswith(s)]
        rows.append({
            "command":name,
            "registered_handler_rva":target,
            "original_registration_evidence":True,
            "on_locked_fastboot_allowlist":bool(allowed_prefixes),
            "matched_locked_prefixes":allowed_prefixes,
            "direct_handler_reachable_when_local_context_0x104_not_one":bool(allowed_prefixes),
            "vulnerability_demonstrated":False,
        })
    result={
        "original_sha256":ORIGINAL_SHA,
        "locked_dispatcher":"0x22c7c -> 0x134c0",
        "source_allowlist_sha256":hashlib.sha256(b).hexdigest(),
        "source_command_scan_sha256":hashlib.sha256(c).hexdigest(),
        "commands":rows,
        "conclusion":"Display-mode commands exist with registered handlers but are not permitted by the 49-prefix locked-mode Fastboot allowlist on this stock EEA ABL.",
        "important_limitations":[
            "This does not prove CVE-2026-24092 is patched or absent.",
            "This rejects straightforward direct command reachability through the locked Fastboot command dispatch, not every conceivable bug before that gate.",
            "No malformed input or live command was sent.",
            "A service token or authorization bypass remains unproven; no permanent unlock achieved."
        ]
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    print("CROSSCHECK_SIGNED_ABL_DISPATCH_SUCCESS")
    for row in rows:print("LOCKED_HANDLER_REACHABILITY",json.dumps(row,sort_keys=True))

if __name__=="__main__":main()
