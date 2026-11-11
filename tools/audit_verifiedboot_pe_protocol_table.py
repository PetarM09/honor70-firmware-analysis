#!/usr/bin/env python3
"""Offline verified EEA XBL VerifiedBoot protocol table audit.

Uses the SHA256-pinned original 61,440-byte VerifiedBootDxe PE, and archived
Ghidra function listing. Identifies contiguous function-pointer arrays whose
+0x08 slot points to RWDeviceState (0x153c), then inspects the +0x30 slot.

Conservative: a candidate pointer array alone is NOT a proof of a registered
protocol instance. No device operations, patching or security-state changes.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

EXPECTED_SHA256 = "f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55"
RW_DEVICE_RVA = 0x153c
PROTOCOL_GUID_BYTES_LE = bytes.fromhex("91ff5e8eb621d347af2bc15a01e020ec")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parser_targets(report):
    parts=re.split(r"(?=^======== FUNCTION )", report, flags=re.M)
    mapping={}
    for part in parts:
        m=re.match(r"======== FUNCTION ([0-9a-fA-F]{8})\s+([^\n]*)", part)
        if m:
            mapping[int(m.group(1),16)]={"header":m.group(2).strip(),
                                          "body":part[:11000]}
    if len(mapping)<140 or RW_DEVICE_RVA not in mapping:
        raise ValueError("Ghidra evidence is missing original RWDeviceState function")
    if "RWDeviceState" not in mapping[RW_DEVICE_RVA]["body"]:
        raise ValueError("Original handler content does not mention RWDeviceState")
    return mapping


def pointer_rva(value, base, size_image):
    if base <= value < base+size_image:
        return value - base
    if value < size_image:
        return value
    return None


def scan_candidates(raw, base, size_image, exec_ranges, known_functions):
    def valid_executable(rva):
        return rva is not None and rva%4 == 0 and any(lo<=rva<hi for lo,hi in exec_ranges)
    matches=[]
    for pos in range(8,len(raw)-8,8):
        value=struct.unpack_from("<Q",raw,pos)[0]
        if pointer_rva(value,base,size_image)!=RW_DEVICE_RVA:
            continue
        start=pos-8
        # +0x30 is the seventh pointer (including first at +0x00)
        if start+8*8>len(raw):
            continue
        slots=[]
        for idx in range(8):
            v=struct.unpack_from("<Q",raw,start+8*idx)[0]
            rva=pointer_rva(v,base,size_image)
            is_exec=valid_executable(rva)
            info=known_functions.get(rva) if rva is not None else None
            slots.append({
                "slot":hex(8*idx),"raw_pointer":hex(v),"target_rva":hex(rva) if rva is not None else None,
                "is_executable_rva":is_exec,
                "exact_ghidra_function_start":info["header"] if info else None,
            })
        count=sum(x["is_executable_rva"] for x in slots)
        matches.append({
            "file_offset":start,"anchor_offset":pos,
            "valid_executable_slots":count,
            "rw_slot_0x08_confirmed":slots[1]["target_rva"]=="0x153c",
            "reset_slot_0x30_executable":slots[6]["is_executable_rva"],
            "reset_slot_0x30_ghidra_function_start":slots[6]["exact_ghidra_function_start"],
            "slots":slots,
            "score":count + (4 if slots[6]["is_executable_rva"] else 0),
        })
    return sorted(matches,key=lambda x:(-x["score"],x["file_offset"]))


def code_audit(pe, binary, reset_rva, table_rva, guid_rva):
    """Disassemble the target and locate direct ADRP+ADD/LDR references.

    The output is a byte-derived static trace, not proof the code executed.
    """
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM
    dis = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    dis.detail = True
    source = pe.get_data(reset_rva, 0x200)
    instructions = list(dis.disasm(source, reset_rva))
    if len(instructions) < 4:
        raise ValueError("Reset slot points to an undecodable region")
    reset_lines = [f"{inst.address:#x} {inst.mnemonic} {inst.op_str}"
                   for inst in instructions[:120]]
    targets = {"vtable": table_rva, "protocol_guid": guid_rva}
    refs = []
    for sec in pe.sections:
        if not (int(sec.Characteristics) & 0x20000000):
            continue
        start = int(sec.VirtualAddress)
        code = pe.get_data(start, int(sec.Misc_VirtualSize))
        decoded = list(dis.disasm(code, start))
        for i, op in enumerate(decoded):
            if op.mnemonic != "adrp" or len(op.operands)<2:
                continue
            if op.operands[0].type != ARM64_OP_REG or op.operands[1].type != ARM64_OP_IMM:
                continue
            reg = op.operands[0].reg
            for name, target in targets.items():
                if op.operands[1].imm != (target & ~0xfff):
                    continue
                for next_ins in decoded[i+1:i+14]:
                    if next_ins.address-op.address>52:
                        break
                    ops=next_ins.operands
                    hit=False
                    if (next_ins.mnemonic=="add" and len(ops)>=3 and
                            ops[1].type==ARM64_OP_REG and ops[1].reg==reg and
                            ops[2].type==ARM64_OP_IMM and ops[2].imm==(target & 0xfff)):
                        hit=True
                    if (next_ins.mnemonic.startswith("ldr") and len(ops)>=2 and
                            ops[1].type==ARM64_OP_MEM and
                            ops[1].mem.base==reg and ops[1].mem.disp==(target & 0xfff)):
                        hit=True
                    if hit:
                        context=decoded[max(0,i-3):min(len(decoded),i+16)]
                        refs.append({"kind":name,"adrp_at":hex(op.address),
                                     "source_at":hex(next_ins.address),
                                     "target_rva":hex(target),
                                     "context":[f"{k.address:#x} {k.mnemonic} {k.op_str}"
                                                for k in context]})
    return {"reset_target_disassembly":reset_lines,
            "direct_adrp_reference_count":len(refs),
            "direct_adrp_references":refs[:30],
            "nearest_ghidra_function_not_required":True}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pe",type=Path)
    p.add_argument("--ghidra",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--selftest",action="store_true")
    a=p.parse_args()
    if a.selftest:
        synthetic=bytearray(0x200)
        funcs={x:{"header":f"FUN_{x:08x}","body":"demo"} for x in [0x100,0x153c,0x180,0x1c0,0x1e0,0x210,0x240,0x280]}
        vals=[0x100,0x153c,0x180,0x1c0,0x1e0,0x210,0x240,0x280]
        for i,val in enumerate(vals):
            struct.pack_into("<Q",synthetic,0x40+i*8,val)
        found=scan_candidates(synthetic,0,0x10000,[(0x100,0x10000)],funcs)
        assert len(found)==1 and found[0]["file_offset"]==0x40
        assert found[0]["slots"][6]["target_rva"]=="0x240"
        assert found[0]["valid_executable_slots"]==8
        print("SELFTEST_OK")
        return
    if not (a.pe and a.ghidra and a.out):
        p.error("--pe, --ghidra and --out required")
    b=a.pe.read_bytes()
    if sha(b)!=EXPECTED_SHA256:
        raise ValueError("Original signed EEA VerifiedBootDxe PE digest mismatch")
    import pefile
    pe=pefile.PE(data=b,fast_load=True)
    if pe.FILE_HEADER.Machine!=0xaa64:
        raise ValueError("Expected ARM64 UEFI PE")
    if b.count(PROTOCOL_GUID_BYTES_LE)<1:
        raise ValueError("Expected VerifiedBoot protocol GUID missing from PE")
    base=int(pe.OPTIONAL_HEADER.ImageBase)
    size_image=int(pe.OPTIONAL_HEADER.SizeOfImage)
    exec_ranges=[]
    for sec in pe.sections:
        if int(sec.Characteristics)&0x20000000:
            exec_ranges.append((int(sec.VirtualAddress),
                                int(sec.VirtualAddress)+max(int(sec.Misc_VirtualSize),
                                                            int(sec.SizeOfRawData))))
    if not exec_ranges:
        raise ValueError("No executable PE sections")
    ghidra_raw=a.ghidra.read_bytes()
    known=parser_targets(ghidra_raw.decode("utf-8","replace"))
    candidates=scan_candidates(b,base,size_image,exec_ranges,known)
    guid_offsets=[m.start() for m in re.finditer(re.escape(PROTOCOL_GUID_BYTES_LE),b)]
    for item in candidates:
        item["distance_from_nearest_guid_file_offset"]=min(
            abs(item["file_offset"]-o) for o in guid_offsets)
        for slot in item["slots"]:
            rva=int(slot["target_rva"],16) if slot["target_rva"] is not None else None
            if rva in known:
                slot["body_sha256"]=sha(known[rva]["body"].encode())
    reliable=[x for x in candidates if x["valid_executable_slots"]>=5 and
              x["reset_slot_0x30_executable"]]
    exactly_one=len(reliable)==1
    reset_rva=(int(reliable[0]["slots"][6]["target_rva"],16)
               if exactly_one else None)
    reset_func=known.get(reset_rva) if reset_rva is not None else None
    table_rva=(pe.get_rva_from_offset(reliable[0]["file_offset"])
               if exactly_one else None)
    guid_rva=(pe.get_rva_from_offset(guid_offsets[0]) if guid_offsets else None)
    byte_derived_code=(code_audit(pe,b,reset_rva,table_rva,guid_rva)
                       if reset_rva is not None and table_rva is not None and
                       guid_rva is not None else None)
    result={
        "scope":"Original verified stock EEA VerifiedBootDxe PE, static only",
        "verified_pe_sha256":sha(b),
        "pe_file_size":len(b),
        "pe_image_base":hex(base),
        "pe_size_image":size_image,
        "elf_or_pe":"ARM64_PE_COFF",
        "ghidra_report_sha256":sha(ghidra_raw),
        "ghidra_functions":len(known),
        "protocol_guid_file_offsets":guid_offsets,
        "executable_rva_ranges":[[hex(lo),hex(hi)] for lo,hi in exec_ranges],
        "vtable_candidates_with_rwdevice_slot_at_0x08":candidates[:24],
        "total_anchor_candidates":len(candidates),
        "high_confidence_contiguous_arrays":len(reliable),
        "unique_high_confidence_table_candidate":exactly_one,
        "reset_slot_0x30_rva_if_unique":hex(reset_rva) if reset_rva is not None else None,
        "reset_slot_0x30_decompiled_function_if_exact":reset_func["header"] if reset_func else None,
        "reset_slot_0x30_decompiled_body_if_exact":reset_func["body"] if reset_func else None,
        "original_arm64_reset_function_and_provider_table_xrefs":byte_derived_code,
        "limitations":[
            "A plausible contiguous array is not sufficient to prove InstallProtocolInterface used it.",
            "To prove registration, inspect code references to this table and the protocol GUID.",
            "PE relocation and runtime rebasing could change in-memory absolute pointers.",
            "A reset handler name/argument signature inferred from Ghidra remains tentative.",
            "This analysis never calls any UEFI, Keymaster, EDL or Fastboot method."
        ]
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    print("PE_SHA256_OK",result["verified_pe_sha256"])
    print("GHIDRA_FUNCTIONS",len(known),"GUIDS",guid_offsets,
          "PE_BASE",hex(base),"EXEC_RANGES",exec_ranges)
    print("ANCHORS",len(candidates),"HIGH_CONFIDENCE",len(reliable))
    for x in candidates[:12]:
        print("TABLE",hex(x["file_offset"]),"EXECUTABLE_SLOTS",x["valid_executable_slots"],
              "NEAREST_GUID_DISTANCE",x["distance_from_nearest_guid_file_offset"])
        for slot in x["slots"]:
            print(" SLOT",slot["slot"],slot["raw_pointer"],slot["target_rva"],
                  "EXEC",slot["is_executable_rva"],"GHIDRA",slot["exact_ghidra_function_start"])
    if reset_func:
        print("RESET_0x30_CANDIDATE_START")
        print(reset_func["body"][:10000])
        print("RESET_0x30_CANDIDATE_END")
    if byte_derived_code:
        print("RESET_TARGET_RVA",hex(reset_rva),
              "TABLE_RVA",hex(table_rva),"GUID_RVA",hex(guid_rva))
        for line in byte_derived_code["reset_target_disassembly"][:85]:
            print("RESET_ARM64",line)
        print("DIRECT_DATA_XREFS",byte_derived_code["direct_adrp_reference_count"])
        for ref in byte_derived_code["direct_adrp_references"][:18]:
            print("DATA_XREF",ref["kind"],ref["source_at"],
                  "CONTEXT",json.dumps(ref["context"][:20]))
    if not exactly_one:
        print("NOT_PROVEN: PE pointer array not uniquely resolved; dynamic Ghidra xrefs required")


if __name__=="__main__":
    main()
