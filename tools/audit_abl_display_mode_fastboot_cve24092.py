#!/usr/bin/env python3
"""Static original HONOR70 ABL Fastboot display-mode command registration audit.

Read-only: locate 'oem select-display-panel' in exact signed EEA LinuxLoader,
map direct instruction and data references and adjacent executable callbacks.
Do not send malformed Fastboot packets; no exploitability claims.
"""
import argparse, hashlib, json, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

ORIGINAL_SHA="ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087"
STRINGS=("oem select-display-panel","oem set-dg-img",
         "oem set-dg-img-resume","oem enable-charger-screen",
         "oem disable-charger-screen","oem display-cmdline",
         "oem off-mode-charge","Command not allowed")

def find_bytes(data, needle):
    return [m.start() for m in re.finditer(re.escape(needle),data)]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abl",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    image=args.abl.read_bytes()
    digest=hashlib.sha256(image).hexdigest()
    if digest != ORIGINAL_SHA:raise ValueError("Not the signed original EEA ABL")
    import pefile
    pe=pefile.PE(data=image,fast_load=True)
    base=int(pe.OPTIONAL_HEADER.ImageBase)
    image_size=int(pe.OPTIONAL_HEADER.SizeOfImage)
    ex_sections=[s for s in pe.sections if int(s.Characteristics) & 0x20000000]
    is_code=lambda r: r is not None and any(
        int(s.VirtualAddress)<=r<int(s.VirtualAddress)+int(s.Misc_VirtualSize) for s in ex_sections
    )
    cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM);cs.detail=True
    result={}
    for label in STRINGS:
        encoded=label.encode("ascii")
        raw_offsets=find_bytes(image,encoded)
        rows=[]
        for offset in raw_offsets:
            rva=pe.get_rva_from_offset(offset)
            pointer_values=[rva,base+rva]
            pointer_occurrences=[]
            for val in set(pointer_values):
                v=struct.pack("<Q",val)
                for i in find_bytes(image,v)[:30]:
                    nearby=[]
                    for delta in range(-32,65,8):
                        at=i+delta
                        if at<0 or at+8>len(image):continue
                        word=struct.unpack_from("<Q",image,at)[0]
                        r=word-base if base<=word<base+image_size else word
                        if is_code(r):
                            nearby.append({"file_off":at,"delta_from_ref":delta,
                                            "candidate_code_rva":hex(r)})
                    pointer_occurrences.append({"file_offset":i,"pointer_value":hex(val),
                                                 "nearby_executable_qwords":nearby[:15]})
            direct=[]
            page=rva & ~0xfff
            for sec in ex_sections:
                start=int(sec.VirtualAddress)
                instructions=list(cs.disasm(pe.get_data(start,int(sec.Misc_VirtualSize)),start))
                for j,ins in enumerate(instructions):
                    if ins.mnemonic!="adrp" or len(ins.operands)<2:continue
                    if ins.operands[1].type!=ARM64_OP_IMM or ins.operands[1].imm!=page:continue
                    reg=ins.operands[0].reg
                    for k in instructions[j+1:j+8]:
                        if k.address-ins.address>28:break
                        v=None
                        ops=k.operands
                        if (k.mnemonic=="add" and len(ops)>=3 and ops[1].type==ARM64_OP_REG
                            and ops[1].reg==reg and ops[2].type==ARM64_OP_IMM):
                            v=page+ops[2].imm
                        if v==rva:
                            ctx=instructions[max(0,j-3):min(len(instructions),j+10)]
                            direct.append({"site":hex(ins.address),"resolved_at":hex(k.address),
                                           "context":[f"{x.address:#x} {x.mnemonic} {x.op_str}" for x in ctx]})
            rows.append({"file_offset":offset,"rva":hex(rva),
                         "data_pointer_references":pointer_occurrences[:30],
                         "direct_adrp_add_code_references":direct[:30]})
        result[label]=rows
    report={"scope":"Original signed EEA HONOR 70 ABL static inspection only",
            "sha256":digest,"base":hex(base),
            "command_literals":result,
            "limitations":[
                "A matching string is not proof of CVE-2026-24092.",
                "Data QWORDs adjacent to strings are candidate pointers only, not confirmed callback registrations.",
                "Handler reachability may be blocked by a separate Fastboot allowlist.",
                "No malformed command or device operation was executed."
            ]}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+"\n")
    print("HASH_VERIFIED",digest)
    for label,rows in result.items():
        print("COMMAND",label,"OCCURRENCES",len(rows))
        for row in rows:
            print(" LOCATION",row["rva"],"QWORD_REFERENCES",len(row["data_pointer_references"]),
                  "DIRECT_CODE_REFERENCES",len(row["direct_adrp_add_code_references"]))
            for x in row["data_pointer_references"][:6]:
                print(" DATA_XREF",json.dumps(x)[:2600])
            for x in row["direct_adrp_add_code_references"][:8]:
                print(" CODE_XREF",json.dumps(x)[:2300])

if __name__=="__main__":main()
