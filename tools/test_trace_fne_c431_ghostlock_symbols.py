"""Synthetic tests: no device, firmware, or exploit calls."""
import unittest
from trace_fne_c431_ghostlock_symbols import audit_symbol_lines, parse_nm

ANCHOR = "ffffffc01037e350 t remove_waiter"
class TestSymbolInventory(unittest.TestCase):
    def test_anchor_is_verified(self):
        report = audit_symbol_lines(ANCHOR)
        self.assertEqual(report["exact_symbol_status"]["remove_waiter"]["relative_to_original_image_base"], "0x2fe350")
        self.assertFalse(report["ready_to_build_or_execute_ghostlock"])
    def test_fails_on_wrong_kernel_anchor(self):
        with self.assertRaises(ValueError):
            audit_symbol_lines("ffffffc01037e354 t remove_waiter")
    def test_multiple_addresses_ambiguous(self):
        data = ANCHOR + "\nffffffc010200000 T init_cred\nffffffc010200008 D init_cred$abc\n"
        report = audit_symbol_lines(data)
        self.assertEqual(report["exact_symbol_status"]["init_cred"]["status"], "ambiguous")
        self.assertIsNone(report["exact_symbol_status"]["init_cred"]["offset"])
    def test_hashed_symbol_suffix(self):
        data = ANCHOR + "\nffffffc010200000 T init_task$7f83\n"
        report = audit_symbol_lines(data)
        self.assertEqual(report["exact_symbol_status"]["init_task"]["relative_to_original_image_base"], "0x180000")
    def test_cfi_trampolines_ignored(self):
        symbols = parse_nm(ANCHOR + "\nffffffc010200000 T remove_waiter.cfi_jt\n")
        self.assertEqual(symbols["remove_waiter"]["status"], "one_address")
    def test_missing_explicit(self):
        report = audit_symbol_lines(ANCHOR)
        self.assertEqual(report["exact_symbol_status"]["init_task"]["status"], "missing")
    def test_phys_addr_not_invented(self):
        report = audit_symbol_lines(ANCHOR)
        self.assertIsNone(report["kernel_phys_load"])
        self.assertFalse(report["struct_layout_fields_inferred"])

if __name__ == "__main__":
    unittest.main()
