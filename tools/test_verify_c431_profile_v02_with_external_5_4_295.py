"""Test the C431 profile v0.2 provenance validator without phone or exploit."""
import copy,json,unittest
from pathlib import Path
from verify_c431_profile_v02_with_external_5_4_295 import verify,EXTERNAL,IMAGE,SAME_FUNCTIONS

ROOT=Path(__file__).resolve().parents[1]
def example():
 v1=json.loads((ROOT/"profiles/fne-nx9-c431-8.0.0.290.profile.json").read_text())
 v2=json.loads((ROOT/"profiles/fne-nx9-c431-8.0.0.290.profile-v0.2.json").read_text())
 source={
  "archive_sha256":EXTERNAL,
  "function_comparison":{fn:{"same_source_body_sha256":True} for fn in SAME_FUNCTIONS},
  "fennie_comparison":{
    k:{"exact_byte_match":v}
    for k,v in v2["external_linux_reference"]["full_file_byte_comparison"].items()
  },
  "exact_c431_binary_ABI_validated_by_generic_source":False,
  "oem_scheduler_layout_warnings":{
    "unmodified_struct_task_layout_usable_as_C431_ABI":False
  }}
 flags={k:v for k,v in v2["confirmed_compiled_oem_config"].items() if k.startswith("CONFIG_")}
 kconf={"signed_kernel_image_sha256":IMAGE,"kernel_image_verified":True,
        "compiled_feature_status":flags}
 return v1,v2,source,kconf

class Tests(unittest.TestCase):
 def test_profile_v02_passes_cautious_evidence(self):
  r=verify(*example())
  self.assertEqual(r["known_c431_field_offset_count"],10)
  self.assertEqual(r["new_5_4_295_derived_numeric_offsets_added"],0)
  self.assertFalse(r["ready_for_live_ghostlock_uaf_root"])
 def test_must_not_guess_missing_phys_load(self):
  x=list(example())
  x[1]["unresolved_required_fields"]["kernel_phys_load"]=0xfffff000
  with self.assertRaises(ValueError):verify(*x)
 def test_must_not_add_unknown_cred_offsets(self):
  x=list(example())
  x[1]["unresolved_required_fields"]["exact_cred_layout"]={"uid":8}
  with self.assertRaises(ValueError):verify(*x)
 def test_generic_function_mutation_rejected(self):
  x=list(example())
  x[2]["function_comparison"]["remove_waiter"]["same_source_body_sha256"]=False
  with self.assertRaises(ValueError):verify(*x)
 def test_wrong_archive_rejected(self):
  x=list(example())
  x[2]["archive_sha256"]="0"*64
  with self.assertRaises(ValueError):verify(*x)
 def test_wrong_signed_kernel_rejected(self):
  x=list(example())
  x[3]["signed_kernel_image_sha256"]="0"*64
  with self.assertRaises(ValueError):verify(*x)
 def test_wrong_oem_compile_flags_rejected(self):
  x=list(example())
  x[3]["compiled_feature_status"]["CONFIG_HN_VIP_THREAD"]="n"
  with self.assertRaises(ValueError):verify(*x)
 def test_runnable_exploit_flag_rejected(self):
  x=list(example())
  x[1]["checks"]["run_ready_ghostlock_profile"]=True
  with self.assertRaises(ValueError):verify(*x)
 def test_generic_source_not_exact_c431_abi(self):
  x=list(example())
  x[1]["external_linux_reference"]["safe_to_transfer_struct_ABI_from_generic_source"]=True
  with self.assertRaises(ValueError):verify(*x)
if __name__=="__main__":unittest.main()
