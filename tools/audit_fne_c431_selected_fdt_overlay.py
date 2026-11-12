#!/usr/bin/env python3
"""Offline SHA-pinned FNE-NX9 selected FDT #13 + DTBO #18 fixup audit.

Validates FDT tokens, external symbol targets and local patch bounds.
Does NOT perform an actual libfdt merge, attest live bootloader memory,
touch a device or attempt GhostLock.
"""
import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path

BASE_FILE="base_yupik_entry_13.dtb"
OVERLAY_FILE="FNE-NX9_781-208_entry_18.dtbo"
BASE_SHA="bc692b769082c3db077864b82b6410b0d8ca93c0ce6985f9a5adedfb8b9854e9"
OVERLAY_SHA="c278a52783cc0c4093f79772dd9f1036d38135098deb56159150da3f82c985cc"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def parse(raw):
    if len(raw)<40:raise ValueError("Truncated FDT")
    magic,size,off,strings_off,reserve,version,last,_,strings_size,struct_size=struct.unpack_from(">10I",raw)
    if magic!=0xd00dfeed or not 40<=size<=len(raw):raise ValueError("Wrong FDT magic/size")
    if version not in (16,17,18) or not 1<=last<=version:raise ValueError("Wrong FDT version")
    if min(off,strings_off,reserve)<40 or off+struct_size>size or strings_off+strings_size>size:
        raise ValueError("Invalid FDT section pointers")
    nodes={};stack=[];pos=off;limit=off+struct_size;ended=False
    while pos+4<=limit:
        token=struct.unpack_from(">I",raw,pos)[0];pos+=4
        if token==1:
            z=raw.find(b"\0",pos,limit)
            if z<0:raise ValueError("Unterminated node")
            name=raw[pos:z].decode("utf-8");pos=(z+4)&~3
            stack.append(name)
            path="/"+"/".join(p for p in stack if p)
            if path in nodes:raise ValueError("Duplicate FDT path")
            nodes[path]={}
        elif token==2:
            if not stack:raise ValueError("Unbalanced END_NODE")
            stack.pop()
        elif token==3:
            if pos+8>limit:raise ValueError("Truncated FDT property")
            n,idx=struct.unpack_from(">II",raw,pos);pos+=8
            if idx>=strings_size or pos+n>limit:raise ValueError("Property bounds error")
            z=raw.find(b"\0",strings_off+idx,strings_off+strings_size)
            if z<0:raise ValueError("Unterminated property name")
            name=raw[strings_off+idx:z].decode("utf-8")
            path="/"+"/".join(p for p in stack if p)
            if path not in nodes or name in nodes[path]:raise ValueError("Invalid FDT property placement")
            nodes[path][name]=raw[pos:pos+n];pos=(pos+n+3)&~3
        elif token==4:continue
        elif token==9:
            if stack:raise ValueError("Open FDT nodes")
            ended=True;break
        else:raise ValueError("Unexpected FDT token")
    if not ended:raise ValueError("Missing FDT_END")
    return nodes

def strings(raw):
    return [v.decode("utf-8") for v in raw.split(b"\0") if v]

def cell(raw):
    if len(raw)!=4:raise ValueError("Bad FDT 32-bit cell")
    return struct.unpack(">I",raw)[0]

def regs(raw):
    if len(raw)%16:raise ValueError("Bad 64-bit reg encoding")
    return [{"start":hex(a),"size":hex(b)} for a,b in struct.iter_unpack(">QQ",raw)]

def verify(base_raw,overlay_raw,*,expected_base=BASE_SHA,expected_overlay=OVERLAY_SHA):
    if sha(base_raw)!=expected_base or sha(overlay_raw)!=expected_overlay:
        raise ValueError("Original selected FDT SHA mismatch")
    b=parse(base_raw);o=parse(overlay_raw)
    symbols={k:strings(v) for k,v in b.get("/__symbols__",{}).items()}
    if not symbols or any(len(v)!=1 or v[0] not in b for v in symbols.values()):
        raise ValueError("Malformed base FDT symbol table")
    names={k:v[0] for k,v in symbols.items()}
    fixups=o.get("/__fixups__",{})
    if not fixups:raise ValueError("Missing external fixups")
    fragments={p for p in o if p.startswith("/fragment@") and p.count("/")==1}
    targets={};patches=0
    for name,raw in fixups.items():
        if name not in names:raise ValueError("Unresolved base FDT symbol "+name)
        for loc in strings(raw):
            fields=loc.rsplit(":",2)
            if len(fields)!=3:raise ValueError("Malformed external fixup")
            path,prop,offset=fields
            try:position=int(offset,10)
            except ValueError as exc:raise ValueError("Bad external fixup offset") from exc
            value=o.get(path,{}).get(prop)
            if value is None or position<0 or position%4 or position+4>len(value):
                raise ValueError("External fixup out of bounds")
            patches+=1
            if path in fragments and prop=="target" and position==0:
                targets.setdefault(path,[]).append(name)
    if set(targets)!=fragments or any(len(v)!=1 for v in targets.values()):
        raise ValueError("Missing or ambiguous fragment target")
    if any(cell(o[k]["target"])!=0xffffffff for k in fragments):
        raise ValueError("Already-patched/invalid fragment target")
    resolved={k:names[v[0]] for k,v in targets.items()}
    local=[p for p in o if p.startswith("/__local_fixups__/")]
    local_patches=0
    for path in local:
        original=path[len("/__local_fixups__"):]
        for prop,data in o[path].items():
            value=o.get(original,{}).get(prop)
            if value is None or len(data)%4:raise ValueError("Bad local fixup property")
            for (position,) in struct.iter_unpack(">I",data):
                local_patches+=1
                if position%4 or position+4>len(value):
                    raise ValueError("Local fixup out of bounds")
    reserved={k:v for k,v in resolved.items() if v=="/reserved-memory" or v.startswith("/reserved-memory/")}
    memory={k:v for k,v in resolved.items() if v=="/memory" or v.startswith("/memory@")}
    region="/reserved-memory/removed_region@c0000000"
    f=next((k for k,v in resolved.items() if v=="/reserved-memory"),None)
    added=o.get(f+"/__overlay__/removed_region@c0000000",{}) if f else {}
    existing=b.get(region,{})
    props=o.get("/fragment@134/__overlay__",{})
    return {
      "schema_version":1,
      "source":"original uploaded FDT byte identity, not authenticated running FDT",
      "base_dtb":{"index":13,"sha256":sha(base_raw),"model":strings(b["/"].get("model",b""))},
      "selected_overlay":{"index":18,"sha256":sha(overlay_raw),
          "model":strings(o["/"].get("model",b"")),
          "board_id_decimal":cell(o["/"]["qcom,board-id"][:4]),
          "hardware_version":strings(props.get("hardware_version",b"")),
          "board_name":strings(props.get("qcom,board_name",b""))},
      "external_fixups":{"base_exported_symbols":len(names),
          "external_symbols_count":len(fixups),"external_symbols_resolved":len(fixups),
          "patch_sites_valid":patches},
      "fragments":{"total":len(fragments),"targets_resolved":len(resolved),
          "targeting_memory":len(memory),"targeting_reserved_memory":len(reserved),
          "reserved_memory_targets":reserved},
      "internal_fixups":{"local_fixup_nodes":len(local),"patch_sites_valid":local_patches},
      "memory_evidence":{"base_hyp_reserved":regs(b["/reserved-memory/hyp@80000000"]["reg"]),
         "base_memory_reg":regs(b["/memory"]["reg"]),
         "removed_region_reg_unchanged":bool(added) and added.get("reg")==existing.get("reg"),
         "removed_region_no_map_unchanged":bool(added) and ("no-map" in added)==("no-map" in existing)},
      "actual_fdtoverlay_merge_performed":False,
      "live_partition_identity_proven":False,
      "active_merged_fdt_read":False,
      "kernel_phys_load_known":False,
      "runtime_slide_known":False,
      "ghostlock_uaf_or_root_tested":False,
      "device_operations":0
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--reference-zip",type=Path)
    g.add_argument("--base",type=Path)
    p.add_argument("--overlay",type=Path)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    if a.reference_zip:
        with zipfile.ZipFile(a.reference_zip) as z:
            base=z.read(BASE_FILE);overlay=z.read(OVERLAY_FILE)
    else:
        if not a.overlay:p.error("--overlay required with --base")
        base=a.base.read_bytes();overlay=a.overlay.read_bytes()
    report=verify(base,overlay)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(report,indent=2)+"\n")
    print("EXTERNAL_FIXUP_PATCHES",report["external_fixups"]["patch_sites_valid"])
    print("INTERNAL_FIXUP_PATCHES",report["internal_fixups"]["patch_sites_valid"])
    print("FRAGMENT_TARGETS",report["fragments"]["targets_resolved"])
    print("KERNEL_PHYS_LOAD_PROVEN",False)

if __name__=="__main__":main()
