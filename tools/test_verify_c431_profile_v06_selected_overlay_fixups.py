"""Positive and negative tests of C431 selected FDT v0.6 profile evidence."""
import json,unittest
from pathlib import Path
from verify_c431_profile_v06_selected_overlay_fixups import verify
ROOT=Path(__file__).resolve().parents[1]
def fixture():
    return [json.loads((ROOT/path).read_text()) for path in (
      "profiles/fne-nx9-c431-8.0.0.290.profile-v0.5.json",
      "profiles/fne-nx9-c431-8.0.0.290.profile-v0.6.json",
      "profiles/evidence/fne-nx9-c431-dtb13-dtbo18-fixup-integrity-2026-11-12.json"
    )]
class Tests(unittest.TestCase):
    def test_original_fdt_fixup_evidence_pass(self):
        r=verify(*fixture())
        self.assertEqual(r["external_relocation_patch_sites"],468)
        self.assertEqual(r["local_relocation_patch_sites"],262)
        self.assertEqual(r["confirmed_C431_struct_offsets"],10)
        self.assertEqual(r["unresolved_kernel_ghostlock_fields"],10)
        self.assertFalse(r["uaf_or_root_proven"])
    def test_fragments_mutation_rejected(self):
        x=fixture();x[1]["selected_fdt_overlay_fixup_audit"]["overlay_fragments_total"]=136
        with self.assertRaises(ValueError):verify(*x)
    def test_unverified_root_flag_rejected(self):
        x=fixture();x[1]["checks"]["run_ready_ghostlock_profile"]=True
        with self.assertRaises(ValueError):verify(*x)
    def test_runtime_phys_load_guess_rejected(self):
        x=fixture();x[1]["unresolved_required_fields"]["kernel_phys_load"]=0x80080000
        with self.assertRaises(ValueError):verify(*x)
    def test_unverified_merged_fdt_claim_rejected(self):
        x=fixture();x[1]["selected_fdt_overlay_fixup_audit"]["actual_live_merged_fdt_attested"]=True
        with self.assertRaises(ValueError):verify(*x)
    def test_source_hash_change_rejected(self):
        x=fixture();x[2]["selected_overlay"]["sha256"]="0"*64
        with self.assertRaises(ValueError):verify(*x)
    def test_reserved_region_change_rejected(self):
        x=fixture();x[2]["memory_evidence"]["removed_region_reg_unchanged"]=False
        with self.assertRaises(ValueError):verify(*x)
    def test_existing_c431_offsets_not_changed(self):
        x=fixture();x[1]["confirmed_binary_offsets_bytes"]["task_struct.pi_blocked_on"]=0
        with self.assertRaises(ValueError):verify(*x)
if __name__=="__main__":
    unittest.main()
