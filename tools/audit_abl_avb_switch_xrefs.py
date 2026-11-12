#!/usr/bin/env python3
"""HONOR 70 signed EEA ABL: offline AVB2/NO_AVB branch literal code xref audit.

No Fastboot packets are sent. No exploit or firmware is constructed.
The scanner checks PE string literals, command strings and direct ARM64
ADRP+ADD references from original hash-pinned LinuxLoader.efi.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

SHA256 = "ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087"

EXACT_PROBES = {
    "noavb_branch": "NoAVBLoad_fw_ufsdev",
    "vb2_branch": "LoadImageAndAuthVB2",
    "runtime_select_hint": "Is_VERIFIED_BOOT_2",
    "compile_select_hint": "VERIFIED_BOOT_ENABLED",
    "vbmeta_a": "vbmeta_a",
    "vbmeta": "vbmeta",
    "milestone_call": "Sending Milestone",
    "boot_verify_disabled": "DisableVerity",
}
SURFACE_RE = re.compile(r"(AVB|vbmeta|Milestone|VERIFIED_BOOT|VerifiedBoot|LoadImageAndAuth|NoAVB)", re.I)


def utf16le(word):
    return word.encode("utf-16le")


def findall(data, word):
    pattern = re.escape(word)
    return [x.start() for x in re.finditer(pattern, data, re.I)]


def collect_literals(raw, pe):
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{8,300}\x00", raw):
        string = m.group()[:-1].decode("ascii", "replace")
        if SURFACE_RE.search(string) and len(string) < 240:
            try:
                rva = pe.get_rva_from_offset(m.start())
            except Exception:
                rva = None
            out.append({"offset": m.start(), "rva": rva, "text": string})
    return out


def get_direct_adrp_refs(pe, candidate_literals):
    target_rvas = {x["rva"] for x in candidate_literals if x["rva"] is not None}
    refs = {rva: [] for rva in target_rvas}
    if not target_rvas:
        return refs
    from collections import defaultdict
    pages = defaultdict(set)
    for r in target_rvas:
        pages[r & ~0xfff].add(r)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for sec in pe.sections:
        if not (int(sec.Characteristics) & 0x20000000):
            continue
        rva0 = int(sec.VirtualAddress)
        size = int(sec.Misc_VirtualSize)
        ins = list(md.disasm(pe.get_data(rva0, size), rva0))
        for idx, op in enumerate(ins):
            if op.mnemonic != "adrp" or len(op.operands) < 2:
                continue
            if op.operands[0].type != ARM64_OP_REG or op.operands[1].type != ARM64_OP_IMM:
                continue
            reg = op.operands[0].reg
            page = op.operands[1].imm
            if page not in pages:
                continue
            for nxt in ins[idx+1:idx+7]:
                if nxt.address - op.address > 24 or nxt.mnemonic in ("b", "ret", "br", "blr", "bl"):
                    break
                v = None
                o = nxt.operands
                if (nxt.mnemonic == "add" and len(o) >= 3 and o[1].type == ARM64_OP_REG
                        and o[1].reg == reg and o[2].type == ARM64_OP_IMM):
                    v = page + o[2].imm
                elif (nxt.mnemonic.startswith("ldr") and len(o) >= 2
                        and o[1].type == ARM64_OP_MEM and o[1].mem.base == reg):
                    v = page + o[1].mem.disp
                if v in refs:
                    refs[v].append({"adrp": hex(op.address),
                                    "resolution": hex(nxt.address),
                                    "instruction": nxt.mnemonic + " " + nxt.op_str})
    return refs


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--abl",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    raw=a.abl.read_bytes()
    digest=hashlib.sha256(raw).hexdigest()
    if digest!=SHA256:
        raise ValueError("Original signed EEA LinuxLoader hash mismatch")
    if raw[:2] != b"MZ":
        raise ValueError("Expected stock EFI PE")
    import pefile
    pe=pefile.PE(data=raw,fast_load=True)
    strings=collect_literals(raw,pe)
    xrefs=get_direct_adrp_refs(pe,strings)
    for lit in strings:
        lit["direct_code_references"]=xrefs.get(lit["rva"],[])[:12]
    selected=[]
    for k,q in EXACT_PROBES.items():
        bs=q.encode()
        hits=findall(raw,bs)
        unicode_hits=findall(raw,utf16le(q))
        selected.append({
            "name":k,"literal":q,
            "ascii_occurrences":hits[:35],
            "utf16le_occurrences":unicode_hits[:35],
            "present_in_original_pe":bool(hits or unicode_hits)
        })
    danger={"noavb_string":selected[0]["present_in_original_pe"],
            "vb2_string":selected[1]["present_in_original_pe"],
            "runtime_selector_string":selected[2]["present_in_original_pe"]}
    report={
        "target":"HONOR 70 FNE-NX9 C431 8.0.0.290 original signed LinuxLoader.efi",
        "sha256":digest,"pe_bytes":len(raw),
        "pe_image_base":hex(pe.OPTIONAL_HEADER.ImageBase),
        "exact_candidate_literals":selected,
        "candidate_fastboot_command_and_log_strings":strings[:400],
        "candidate_string_count":len(strings),
        "avb_selection_string_clues_in_this_abl":danger,
        "limitations":[
            "String absence does not formally prove a whole code path is unreachable; binary and UEFI data references can be indirect.",
            "Literal presence alone does not establish dynamic GPT-dependent selection. Inspect branch predicates and true callers.",
            "This is a static signed-firmware scan, not exploitation or exploitability validation.",
            "No malformed Fastboot commands, EDL writes or on-phone actions were executed."
        ]
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(report,indent=2)+"\n")
    print("ABL_DIGEST_OK",digest,"SIZE",len(raw),"SURFACE_STRINGS",len(strings))
    for item in selected:
        print("EXACT_CANDIDATE",item["name"],item["literal"],
              "ASCII",item["ascii_occurrences"],"UTF16",item["utf16le_occurrences"])
    for lit in strings:
        if any(x in lit["text"].lower() for x in ("avb","vbmeta","milestone","verifiedboot","loadimage")):
            print("CMD_LIT",hex(lit["rva"] or 0),repr(lit["text"][:140]),
                  "REFS",json.dumps(lit["direct_code_references"][:5]))

if __name__=="__main__":
    main()
