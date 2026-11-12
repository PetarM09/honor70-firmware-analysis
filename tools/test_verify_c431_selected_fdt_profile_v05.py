"""Synthetic-only negative tests for exact C431 boot-selected FDT lookup."""
import copy,json,unittest
from pathlib import Path

from verify_c431_selected_fdt_profile_v05 import verify

ROOT=Path(__file__).resolve().parents[1]
def fixture():
    paths=[
      ROOT/"profiles/fne-nx9-c431-8.0.0.290.profile-v0.4.json",
      ROOT/"profiles/fne-nx9-c431-8.0.0.290.profile-v0.5.json",
      ROOT/"profiles/evidence/fne-nx9-c431-phone-boot-dtb13-dtbo18-2026-11-12.json",
      ROOT/"profiles/evidence/fne-nx9-c431-uploaded-fdt-index-selected-sha-manifest-2026-11-12.json"
    ]
    return [json.loads(p.read_text()) for p in paths]

class Tests(unittest.TestCase):
    def test_real_declarations_pass_read_only_evidence(self):
        x=verify(*fixture())
        self.assertEqual(x["matching_overlay_model"],
                         "Honor Technologies, Inc. FNE-NX9-781-208")
        self.assertEqual(x["ro_boot_dtbo_idx_reported"],18)
        self.assertFalse(x["genuinely_selected_merged_fdt_attested"])
    def test_index_change_rejected(self):
        a=fixture();a[2]["phone_reported_properties"]["ro.boot.dtbo_idx"]="25"
        with self.assertRaises(ValueError):verify(*a)
    def test_original_c431_layout_mutation_rejected(self):
        a=fixture();a[1]["confirmed_binary_offsets_bytes"]["task_struct.pi_lock"]=0x990
        with self.assertRaises(ValueError):verify(*a)
    def test_live_phys_guess_rejected(self):
        a=fixture();a[1]["unresolved_required_fields"]["kernel_phys_load"]=0x80080000
        with self.assertRaises(ValueError):verify(*a)
    def test_wrong_uploaded_image_hash_rejected(self):
        a=fixture();a[3]["source_files"]["dtbo_a_img"]["sha256"]="0"*64
        with self.assertRaises(ValueError):verify(*a)
    def test_wrong_overlay_digest_rejected(self):
        a=fixture();a[3]["selected_fdt_entries"]["overlay_dtbo_18"]["sha256"]="0"*64
        with self.assertRaises(ValueError):verify(*a)
    def test_wrong_base_model_rejected(self):
        a=fixture();a[3]["selected_fdt_entries"]["base_dtb_13"]["model"]=["Other SoC"]
        with self.assertRaises(ValueError):verify(*a)
    def test_mistaken_alternate_overlay_selection_rejected(self):
        a=fixture()
        a[1]["on_device_boot_tree_selection"]["selected_overlay_from_uploaded_dtbo"]["alternate_same_model_table_index_not_selected"]=18
        with self.assertRaises(ValueError):verify(*a)
    def test_board_id_mismatch_rejected(self):
        a=fixture()
        a[2]["phone_reported_properties"]["ro.board.boardid"]="8780"
        with self.assertRaises(ValueError):verify(*a)
    def test_board_variant_mismatch_rejected(self):
        a=fixture()
        a[3]["selected_fdt_entries"]["overlay_dtbo_18"]["hardware_version"]="WRONG"
        with self.assertRaises(ValueError):verify(*a)
    def test_wrong_alternate_board_id_rejected(self):
        a=fixture()
        a[3]["selected_fdt_entries"]["overlay_dtbo_25"]["qcom_board_id_decimal"]=8790
        with self.assertRaises(ValueError):verify(*a)
    def test_untrusted_runtime_fdt_attestation_rejected(self):
        a=fixture();a[1]["on_device_boot_tree_selection"]["actual_active_merged_fdt_directly_read"]=True
        with self.assertRaises(ValueError):verify(*a)
    def test_accidental_uaf_enable_rejected(self):
        a=fixture();a[1]["checks"]["active_uaf_trigger_enabled"]=True
        with self.assertRaises(ValueError):verify(*a)

if __name__=="__main__":
    unittest.main()
