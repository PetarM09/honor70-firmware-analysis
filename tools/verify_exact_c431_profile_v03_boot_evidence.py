#!/usr/bin/env python3
"""Fail-closed original signed C431 boot/Image evidence checker for v0.3 profile.

Disallows filling runtime GhostLock properties from a boot Image or a DTB
memory node. No device access, root attempt or writes.
"""
import argparse,json
from pathlib import Path
BOOT="5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"
IMAGE="bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
HEADER={
 "boot_image_header_version":("boot_image_header","version"),
 "boot_image_header_size_bytes":("boot_image_header","header_size_bytes"),
 "boot_kernel_size_bytes":("boot_image_header","kernel_size_bytes"),
 "boot_ramdisk_size_bytes":("boot_image_header","ramdisk_size_bytes"),
 "boot_kernel_file_offset_bytes":("boot_image_header","kernel_file_offset"),
 "arm64_text_offset_hex":("arm64_Image_header","text_offset_hex"),
 "arm64_image_size_bytes":("arm64_Image_header","image_size_bytes"),
 "arm64_flags_hex":("arm64_Image_header","flags_hex"),
 "arm64_endianness":("arm64_Image_header","endianness"),
 "arm64_page_size_selector":("arm64_Image_header","page_size_selector"),
 "arm64_physical_placement_selector":("arm64_Image_header","physical_placement_selector"),
 "arm64_physical_alignment_bytes":("arm64_Image_header","physical_base_alignment_bytes"),
 "boot_has_kernel_offset_field":("boot_image_header","has_kernel_offset_field"),
 "boot_has_dtb_addr_size_fields":("boot_image_header","has_inline_dtb_addr_or_size_fields"),
}
EXPECTED_DEBUG=(
 "CONFIG_DEBUG_INFO","CONFIG_DEBUG_INFO_BTF",
 "CONFIG_DEBUG_INFO_DWARF4","CONFIG_DEBUG_INFO_DWARF5",
 "CONFIG_KALLSYMS","CONFIG_KALLSYMS_ALL"
)
RUNTIME=(
 "kernel_phys_load","actual_runtime_kernel_slide",
 "exact_cred_layout","exact_task_cred_fields",
 "exact_task_seccomp_fields","exact_futex_q_complete_layout",
 "actual_select_user_controlled_stack_write",
 "reliable_dangling_waiter_lifetime","proven_kernel_memory_primitive",
 "controlled_privilege_transition"
)

def verify(old,new,evidence):
 if old.get("profile_version")!="0.2.0" or new.get("profile_version")!="0.3.0":
  raise ValueError("Expected existing v0.2 and new v0.3")
 if new.get("status")!="experimental_static_verified_non_executable":
  raise ValueError("Unexpected execution status")
 if new.get("confirmed_binary_offsets_bytes")!=old.get("confirmed_binary_offsets_bytes"):
  raise ValueError("Known original machine-code offsets changed")
 if new.get("confirmed_stack_evidence")!=old.get("confirmed_stack_evidence"):
  raise ValueError("Signed waiter stack evidence changed")
 if new.get("unresolved_required_fields")!=old.get("unresolved_required_fields"):
  raise ValueError("Unknown runtime fields improperly changed")
 if sorted(new["unresolved_required_fields"])!=sorted(RUNTIME):
  raise ValueError("Expected ten unresolved properties")
 if any(new["unresolved_required_fields"][key] is not None for key in RUNTIME):
  raise ValueError("Unconfirmed dynamic/struct values invented")
 if evidence.get("boot_img_sha256")!=BOOT or evidence.get("kernel_Image_sha256")!=IMAGE:
  raise ValueError("Wrong original C431 signed images")
 if new.get("provenance",{}).get("boot_img_sha256")!=BOOT or new.get(
    "provenance",{}).get("extracted_kernel_image_sha256")!=IMAGE:
  raise ValueError("Wrong profile provenance")
 if evidence.get("device_operations")!=0:
  raise ValueError("This workflow must be read-only offline")
 meta=new.get("verified_boot_image_header",{})
 for field,(section,key) in HEADER.items():
  if meta.get(field)!=evidence.get(section,{}).get(key):
   raise ValueError("Original header value mismatch "+field)
 if meta.get("valid_fdt_candidates_in_original_boot")!=len(evidence.get(
    "fdt_candidates_in_boot_image",[])):
  raise ValueError("Original boot FDT evidence mismatch")
 if meta.get("valid_fdt_candidates_in_extracted_kernel")!=len(evidence.get(
    "fdt_candidates_in_extracted_kernel_Image",[])):
  raise ValueError("Original extracted Image FDT evidence mismatch")
 for key in EXPECTED_DEBUG:
  if meta.get("debug_config",{}).get(key)!=evidence.get(
     "debug_symbols_build_options",{}).get(key):
   raise ValueError("Original IKCONFIG option mismatch "+key)
 for field in ("physical_kernel_base_measured","original_image_DWARF_or_BTF_extracted",
               "vendor_boot_dtb_examined"):
  if meta.get(field) is not False:
   raise ValueError("Unsupported direct original-image claim "+field)
 for field in ("absolute_kernel_phys_load_proven","actual_runtime_kernel_slide_proven",
               "runnable_ghostlock_root_proven"):
  if new.get("checks",{}).get(field) is not False:
   raise ValueError("Unverified runtime claim "+field)
 if evidence.get("kernel_phys_load") is not None or evidence.get(
    "actual_runtime_kernel_slide") is not None:
  raise ValueError("Static header cannot assert runtime locations")
 return {
  "profile_version":"0.3.0",
  "stock_boot_and_Image_SHA256_verified":True,
  "boot_header_version":3,
  "original_text_offset":meta["arm64_text_offset_hex"],
  "physical_placement_flag":meta["arm64_physical_placement_selector"],
  "original_BTF_compiled":meta["debug_config"]["CONFIG_DEBUG_INFO_BTF"],
  "original_fdt_candidates_in_boot":meta["valid_fdt_candidates_in_original_boot"],
  "signed_old_kernel_struct_offsets_preserved":len(new["confirmed_binary_offsets_bytes"]),
  "unresolved_runtime_or_struct_fields":len(RUNTIME),
  "new_unverified_numeric_exploit_fields_filled":0,
  "status":"original_boot_header_passed_only_no_UAF_or_root",
  "root_attempt_performed":False,
  "device_operations":0
 }

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for arg in ("old","new","evidence","out"):
  p.add_argument("--"+arg,required=True,type=Path)
 a=p.parse_args()
 result=verify(*[json.loads(getattr(a,k).read_text()) for k in
                 ("old","new","evidence")])
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,indent=2)+"\n")
 print(json.dumps(result,indent=2))
if __name__=="__main__":main()
