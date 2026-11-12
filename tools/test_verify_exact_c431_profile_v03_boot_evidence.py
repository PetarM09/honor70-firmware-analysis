"""Unit tests for original C431 boot v3/Image evidence in experimental profile v0.3.

No root, no EDL, no exploit, no phone operations.
"""
import copy,json,unittest
from pathlib import Path
from verify_exact_c431_profile_v03_boot_evidence import verify,BOOT,IMAGE

ROOT=Path(__file__).resolve().parents[1]
def fixtures():
    old=json.loads((ROOT/"profiles/fne-nx9-c431-8.0.0.290.profile-v0.2.json").read_text())
    new=json.loads((ROOT/"profiles/fne-nx9-c431-8.0.0.290.profile-v0.3.json").read_text())
    meta=new["verified_boot_image_header"]
    evidence={
        "boot_img_sha256":BOOT,"kernel_Image_sha256":IMAGE,"device_operations":0,
        "boot_image_header":{
            "version":meta["boot_image_header_version"],
            "header_size_bytes":meta["boot_image_header_size_bytes"],
            "kernel_size_bytes":meta["boot_kernel_size_bytes"],
            "ramdisk_size_bytes":meta["boot_ramdisk_size_bytes"],
            "kernel_file_offset":meta["boot_kernel_file_offset_bytes"],
            "has_kernel_offset_field":meta["boot_has_kernel_offset_field"],
            "has_inline_dtb_addr_or_size_fields":meta["boot_has_dtb_addr_size_fields"]
        },
        "arm64_Image_header":{
            "text_offset_hex":meta["arm64_text_offset_hex"],
            "image_size_bytes":meta["arm64_image_size_bytes"],
            "flags_hex":meta["arm64_flags_hex"],
            "endianness":meta["arm64_endianness"],
            "page_size_selector":meta["arm64_page_size_selector"],
            "physical_placement_selector":meta["arm64_physical_placement_selector"],
            "physical_base_alignment_bytes":meta["arm64_physical_alignment_bytes"]
        },
        "fdt_candidates_in_boot_image":[],
        "fdt_candidates_in_extracted_kernel_Image":[],
        "debug_symbols_build_options":meta["debug_config"],
        "kernel_phys_load":None,"actual_runtime_kernel_slide":None
    }
    return old,new,evidence

class Tests(unittest.TestCase):
    def test_profile_v03_header_evidence_passes(self):
        report=verify(*fixtures())
        self.assertTrue(report["stock_boot_and_Image_SHA256_verified"])
        self.assertEqual(report["original_text_offset"],"0x80000")
        self.assertEqual(report["unresolved_runtime_or_struct_fields"],10)
        self.assertEqual(report["new_unverified_numeric_exploit_fields_filled"],0)
        self.assertFalse(report["root_attempt_performed"])
    def test_phys_base_guess_fails(self):
        v=list(fixtures())
        v[1]["unresolved_required_fields"]["kernel_phys_load"]=0x80080000
        with self.assertRaises(ValueError):verify(*v)
    def test_slide_guess_fails(self):
        v=list(fixtures())
        v[1]["unresolved_required_fields"]["actual_runtime_kernel_slide"]=0x200000
        with self.assertRaises(ValueError):verify(*v)
    def test_image_header_modified_fails(self):
        v=list(fixtures())
        v[2]["arm64_Image_header"]["text_offset_hex"]="0x100000"
        with self.assertRaises(ValueError):verify(*v)
    def test_dtb_not_claimed_verified(self):
        v=list(fixtures())
        v[1]["verified_boot_image_header"]["vendor_boot_dtb_examined"]=True
        with self.assertRaises(ValueError):verify(*v)
    def test_debug_metadata_not_claimed_recovered(self):
        v=list(fixtures())
        v[1]["verified_boot_image_header"]["original_image_DWARF_or_BTF_extracted"]=True
        with self.assertRaises(ValueError):verify(*v)
    def test_trusted_abi_not_changed(self):
        v=list(fixtures())
        v[1]["confirmed_binary_offsets_bytes"]["rt_mutex_waiter.task"]=0x50
        with self.assertRaises(ValueError):verify(*v)
    def test_no_exploit_flag(self):
        v=list(fixtures())
        v[1]["checks"]["runnable_ghostlock_root_proven"]=True
        with self.assertRaises(ValueError):verify(*v)
    def test_wrong_original_image_hash(self):
        v=list(fixtures())
        v[2]["kernel_Image_sha256"]="0"*64
        with self.assertRaises(ValueError):verify(*v)
    def test_no_active_device_operations(self):
        v=list(fixtures())
        v[2]["device_operations"]=1
        with self.assertRaises(ValueError):verify(*v)

if __name__=="__main__":unittest.main()
