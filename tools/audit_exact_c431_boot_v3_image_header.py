#!/usr/bin/env python3
"""Read-only, SHA-verified original C431 Android boot v3 / ARM64 Image audit.

Does not assume that DRAM base, boot header or DTB gives a runtime kernel
physical address, and never derives an exploit slide or a UAF/root payload.
"""
import argparse,hashlib,json,struct
from pathlib import Path
from audit_fne_embedded_ikconfig import scan, KERNEL_SHA256
from audit_c431_original_kernel_hardening import EXPECTED_IKCONFIG_SHA, parse_options

BOOT_SHA="5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"
ARM64_MAGIC=b"ARM\x64"
ANDROID_MAGIC=b"ANDROID!"
FDT_MAGIC=b"\xd0\x0d\xfe\xed"
ALIGN=4096
DEBUG_KEYS=(
 "CONFIG_DEBUG_INFO","CONFIG_DEBUG_INFO_BTF","CONFIG_DEBUG_INFO_DWARF4",
 "CONFIG_DEBUG_INFO_DWARF5","CONFIG_DEBUG_INFO_SPLIT",
 "CONFIG_KALLSYMS","CONFIG_KALLSYMS_ALL","CONFIG_IKCONFIG",
 "CONFIG_IKCONFIG_PROC","CONFIG_RANDOMIZE_BASE","CONFIG_VMAP_STACK",
 "CONFIG_CFI_CLANG",
)

def sha(data):return hashlib.sha256(data).hexdigest()
def align_up(n,align=ALIGN):return (n+align-1)//align*align

def fdt_candidates(data):
    """Detect plausible FDT headers, NOT a trusted DTB interpretation."""
    out=[]
    i=0
    while True:
        p=data.find(FDT_MAGIC,i)
        if p<0:break
        i=p+4
        if len(data)-p<40:continue
        size,off_struct,off_strings,off_reserved,version,lastcomp,bootid,szstr,szstruct=struct.unpack_from(">9I",data,p+4)
        if not (40<=size<=2*1024*1024 and p+size<=len(data)):continue
        if not (16<=version<=18 and 1<=lastcomp<=version):continue
        if not (40<=off_reserved<size and 40<=off_struct<size and 40<=off_strings<size):continue
        if off_strings+szstr>size or off_struct+szstruct>size:continue
        out.append({"offset":p,"totalsize":size,"fdt_version":version,
                    "sha256":sha(data[p:p+size]),"validated_as_active_device_tree":False})
        if len(out)>=12:break
    return out

def inspect(boot,kernel,*,expected_boot_sha=BOOT_SHA,expected_kernel_sha=KERNEL_SHA256,
            expected_ikconfig_sha=EXPECTED_IKCONFIG_SHA):
    if sha(boot)!=expected_boot_sha or sha(kernel)!=expected_kernel_sha:
        raise ValueError("Inputs are not exact original FNE-NX9 C431 signed firmware")
    if len(boot)<4096 or boot[:8]!=ANDROID_MAGIC:
        raise ValueError("Not an Android boot image")
    kernel_size,ramdisk_size,os_version,header_size=struct.unpack_from("<4I",boot,8)
    version=struct.unpack_from("<I",boot,40)[0]
    if version!=3 or header_size!=1580:
        raise ValueError("Expected Android boot image header v3; inspect other layouts separately")
    if not (0<kernel_size<=len(boot)-ALIGN and boot[ALIGN:ALIGN+kernel_size]==kernel):
        raise ValueError("Extracted signed Image does not match boot header's kernel payload")
    ramdisk_offset=align_up(ALIGN+kernel_size)
    if ramdisk_offset+ramdisk_size>len(boot):
        raise ValueError("Ramdisk extends beyond signed boot image")
    if len(kernel)<64 or kernel[56:60]!=ARM64_MAGIC:
        raise ValueError("Kernel payload is not an ARM64 Image")
    text_offset,image_size,flags=struct.unpack_from("<3Q",kernel,8)
    if image_size==0:
        raise ValueError("Zero image_size: requires ARM64 legacy semantics review")
    status,raw,marker=scan(kernel)
    if status!="embedded_config_found" or sha(raw)!=expected_ikconfig_sha:
        raise ValueError("Original signed C431 embedded IKCONFIG mismatch")
    conf=parse_options(raw.decode("utf-8"))
    dbg={key:conf.get(key,"not_listed") for key in DEBUG_KEYS}
    return {
      "schema_version":1,
      "source":"SHA-verified stock HONOR 70 FNE-NX9 C431 Android boot.img, Image",
      "boot_img_sha256":sha(boot),"kernel_Image_sha256":sha(kernel),
      "boot_image_header":{
        "version":version,"header_size_bytes":header_size,
        "kernel_size_bytes":kernel_size,"ramdisk_size_bytes":ramdisk_size,
        "kernel_file_offset":ALIGN,"ramdisk_file_offset":ramdisk_offset,
        "os_version_raw":os_version,
        "has_kernel_offset_field":False,
        "has_inline_dtb_addr_or_size_fields":False,
        "normal_dtb_location":"vendor_boot partition for Android GKI boot header v3",
      },
      "arm64_Image_header":{
        "magic":"ARM\\x64","text_offset_hex":hex(text_offset),
        "image_size_bytes":image_size,"flags_hex":hex(flags),
        "endianness":"big" if flags&1 else "little",
        "page_size_selector":(flags>>1)&3,
        "physical_placement_selector":(flags>>3)&1,
        "physical_base_alignment_bytes":0x200000,
        "address_relationship":"load_phys=2MiB_aligned_loader_selected_base+text_offset",
        "bootloader_selected_base_measured":False
      },
      "fdt_candidates_in_boot_image":fdt_candidates(boot),
      "fdt_candidates_in_extracted_kernel_Image":fdt_candidates(kernel),
      "DTB_memory_reg_only_describes_memory_not_actual_kernel_load":True,
      "original_IKCONFIG_sha256":sha(raw),
      "original_IKCONFIG_marker_offset":marker,
      "debug_symbols_build_options":dbg,
      "original_external_DWARF_or_BTF_sections_proven_accessible":False,
      "kernel_phys_load":None,
      "actual_runtime_kernel_slide":None,
      "cred_layout_recovered_from_original_debug_symbols":False,
      "actual_runtime_UAF_or_root_observed":False,
      "device_operations":0
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--boot",required=True,type=Path)
    p.add_argument("--kernel",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    result=inspect(a.boot.read_bytes(),a.kernel.read_bytes())
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    print("ORIGINAL_BOOT_V3_VERIFIED",True)
    print("IMAGE_TEXT_OFFSET",result["arm64_Image_header"]["text_offset_hex"])
    print("IMAGE_SIZE_BYTES",result["arm64_Image_header"]["image_size_bytes"])
    print("IMAGE_FLAGS",result["arm64_Image_header"]["flags_hex"])
    print("FDT_CANDIDATES_BOOT",len(result["fdt_candidates_in_boot_image"]))
    for name,value in result["debug_symbols_build_options"].items():print(name,value)
    print("PHYSICAL_KERNEL_LOAD_OR_ROOT_DEMONSTRATED",False)

if __name__=="__main__":
    main()
