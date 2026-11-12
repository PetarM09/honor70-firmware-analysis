"""Synthetic-only hardening inventory tests: no device, exploit or network."""
import gzip
import unittest
from unittest.mock import patch
from audit_c431_original_kernel_hardening import classify,parse_options,inspect_image
from audit_fne_embedded_ikconfig import START,END

def text_config():
    return (
        "# generated test fixture, not real HONOR firmware\n"
        + "".join("CONFIG_FAKE_OPTION_%02d=y\n" % i for i in range(36))
        + "CONFIG_FUTEX=y\nCONFIG_FUTEX_PI=y\n"
        + "CONFIG_CFI_CLANG=y\n"
        + "# CONFIG_VMAP_STACK is not set\n"
        + "CONFIG_SECCOMP_FILTER=y\n"
    ).encode()

class TestInventory(unittest.TestCase):
    def test_three_state_preserved(self):
        flags=classify(text_config(),expected_hash=None)["flags"]
        self.assertEqual(flags["control_flow_and_stack"]["CONFIG_CFI_CLANG"],"y")
        self.assertEqual(flags["memory_layout"]["CONFIG_VMAP_STACK"],"n")
        self.assertEqual(flags["memory_layout"]["CONFIG_RANDOMIZE_BASE"],"not_listed")
    def test_no_root_claim(self):
        report=classify(text_config(),expected_hash=None)
        self.assertFalse(report["ghostlock_root_demonstrated"])
        self.assertFalse(report["persistent_bootloader_unlock_demonstrated"])
        self.assertEqual(report["device_operations"],0)
    def test_source_hash_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError,"IKCONFIG digest mismatch"):
            classify(text_config())
    def test_option_conflict_rejected(self):
        with self.assertRaisesRegex(ValueError,"Conflicting"):
            parse_options("CONFIG_FUTEX=y\n# CONFIG_FUTEX is not set\n")
    def test_unknown_config_value_ignored(self):
        v=parse_options("CONFIG_FUTEX=maybe\nCONFIG_CFI_CLANG=y\n")
        self.assertNotIn("CONFIG_FUTEX",v)
        self.assertEqual(v["CONFIG_CFI_CLANG"],"y")
    def test_correct_embedded_config_with_explicit_mock_hash(self):
        raw=text_config()
        image=b"\x00"*64+START+gzip.compress(raw)+END+b"\x00"*15
        with patch("audit_c431_original_kernel_hardening.classify") as verifier:
            verifier.return_value={"flags":{}}
            result=inspect_image(image,require_image_sha=None)
            self.assertEqual(result["original_ikconfig_marker_offset"],64)
            self.assertFalse(result["source_image_verified"])
            verifier.assert_called_once_with(raw)
    def test_wrong_original_image_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"Wrong C431 original"):
            inspect_image(b"not the original retail kernel")
    def test_corrupt_gzip_refused(self):
        with self.assertRaisesRegex(ValueError,"absent or malformed"):
            inspect_image(START+b"invalid"+END,require_image_sha=None)
    def test_flags_do_not_claim_dynamic_mitigation(self):
        report=classify(text_config(),expected_hash=None)
        self.assertTrue(any("not a live proof" in item for item in report["interpretation_limits"]))

if __name__=="__main__":
    unittest.main()
