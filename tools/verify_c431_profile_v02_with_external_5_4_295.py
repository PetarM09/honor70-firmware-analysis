#!/usr/bin/env python3
"""Verify C431 v0.2 profile source augmentation without generating exploit data.

Fail closed if generic Linux 5.4.295 ABI is claimed to be exact stock C431,
or any earlier unknown runtime UAF/physical address becomes guessed.
"""
import argparse,json
from pathlib import Path

BOOT="5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"
IMAGE="bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
EXTERNAL="c48158f7735668aac78b9d74bb3616f57a4ea0816ca09f7db83f7834d705b6a9"
SAME_FUNCTIONS=(
 "futex_requeue","futex_wait_requeue_pi",
 "remove_waiter","rt_mutex_start_proxy_lock"
)
EXPECTED_FLAGS={
 "CONFIG_HN_VIP_THREAD":"y",
 "CONFIG_HN_RTG":"y",
 "CONFIG_HN_QOS_THREAD":"y",
 "CONFIG_HN_RTG_FRAME":"y",
 "CONFIG_ANDROID_VENDOR_HOOKS":"y",
 "CONFIG_HONOR_SCHED_VIP":"n",
 "CONFIG_LTO_CLANG":"y",
 "CONFIG_THINLTO":"y",
 "CONFIG_CFI_CLANG":"y"
}
def verify(v1,v2,source,kconf):
 if v2.get("profile_version")!="0.2.0":raise ValueError("Unexpected profile version")
 if v2.get("status")!="experimental_static_verified_non_executable":
  raise ValueError("Cannot claim executable profile")
 if v1.get("provenance")!=v2.get("provenance") or (
    v2.get("provenance",{}).get("boot_img_sha256"),
    v2.get("provenance",{}).get("extracted_kernel_image_sha256")
 ) !=(BOOT,IMAGE):
  raise ValueError("Different or missing stock firmware provenance")
 if v1.get("confirmed_binary_offsets_bytes")!=v2.get("confirmed_binary_offsets_bytes"):
  raise ValueError("C431 known offsets changed by generic source")
 if v1.get("unresolved_required_fields")!=v2.get("unresolved_required_fields"):
  raise ValueError("Previously unknown exploit fields cannot be filled from generic source")
 if any(value is not None for value in v2["unresolved_required_fields"].values()):
  raise ValueError("Unresolved kernel geometry must remain unknown")
 if v1.get("confirmed_stack_evidence")!=v2.get("confirmed_stack_evidence"):
  raise ValueError("Unsupported modification to original C431 stack evidence")
 for key in ("exploit_loader_enabled","active_uaf_trigger_enabled","kernel_memory_write_enabled",
             "root_installation_enabled","persistent_unlock_enabled"):
  if v2.get("checks",{}).get(key) is not False:
   raise ValueError("Runnable exploit unexpectedly enabled")
 if v2.get("checks",{}).get("run_ready_ghostlock_profile") is not False:
  raise ValueError("No runnable exploit profile demonstrated")
 source_meta=v2.get("external_linux_reference",{})
 if source_meta.get("archive_sha256")!=EXTERNAL or source.get("archive_sha256")!=EXTERNAL:
  raise ValueError("Wrong user-submitted archive")
 for fn in SAME_FUNCTIONS:
  if fn not in source_meta.get("same_source_bodies",[]):
   raise ValueError("Missing source function")
  ref=source.get("function_comparison",{}).get(fn,{})
  if ref.get("same_source_body_sha256") is not True:
   raise ValueError("Referenced function not identical to HONOR Fennie GPL: "+fn)
 flags=v2.get("confirmed_compiled_oem_config",{})
 actual=kconf.get("compiled_feature_status",{})
 if kconf.get("signed_kernel_image_sha256")!=IMAGE or not kconf.get("kernel_image_verified"):
  raise ValueError("OEM config is not from original signed C431")
 for k,v in EXPECTED_FLAGS.items():
  if flags.get(k)!=v or actual.get(k)!=v:
   raise ValueError("OEM compilation mismatch "+k)
 same_files=v2.get("external_linux_reference",{}).get("full_file_byte_comparison",{})
 for key,expected in same_files.items():
  ref=source.get("fennie_comparison",{}).get(key,{})
  if ref.get("exact_byte_match") is not expected:
   raise ValueError("Source file identity claim unverified "+key)
 if source_meta.get("safe_to_transfer_struct_ABI_from_generic_source") is not False:
  raise ValueError("Generic structs must not be treated as exact C431 layout")
 if source.get("exact_c431_binary_ABI_validated_by_generic_source") is not False:
  raise ValueError("Source report contradicts signed kernel ABI scope")
 if source.get("oem_scheduler_layout_warnings",{}).get(
    "unmodified_struct_task_layout_usable_as_C431_ABI") is not False:
  raise ValueError("Unsupported scheduler source equivalence claim")
 return {
  "schema_version":1,
  "profile_version":"0.2.0",
  "target":"FNE-NX9 C431 8.0.0.290",
  "original_c431_image_sha256":IMAGE,
  "third_party_5_4_295_archive_sha256":EXTERNAL,
  "honor_fennie_functions_identical":list(SAME_FUNCTIONS),
  "known_c431_field_offset_count":len(v2["confirmed_binary_offsets_bytes"]),
  "new_5_4_295_derived_numeric_offsets_added":0,
  "unresolved_fields_kept_null":len(v2["unresolved_required_fields"]),
  "oem_compiled_flags_verified":len(EXPECTED_FLAGS),
  "source_comparison_confirmed":True,
  "ready_for_live_ghostlock_uaf_root":False,
  "temporary_root_observed":False,
  "device_operations":0
 }

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for arg in ("v1","v2","source","kconf","out"):
  p.add_argument("--"+arg,required=True,type=Path)
 a=p.parse_args()
 result=verify(*[json.loads(getattr(a,name).read_text()) for name in
                 ("v1","v2","source","kconf")])
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,indent=2)+"\n")
 print("C431_V02_PROFILE_SOURCE_AUDIT_PASSED")
 for key,value in result.items():print(key,value)
if __name__=="__main__":main()
