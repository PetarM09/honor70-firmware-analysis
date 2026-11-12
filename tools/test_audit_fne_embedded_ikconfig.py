"""Synthetic-only tests for embedded kernel configuration provenance."""
import gzip
import unittest
from audit_fne_embedded_ikconfig import START, END, scan, inspect_kernel

def fake_config():
    lines = ["# synthetic Android kernel config, NOT from a device"]
    lines.extend("CONFIG_TEST_OPTION_%02d=y" % i for i in range(40))
    lines.extend(("CONFIG_FUTEX=y", "CONFIG_FUTEX_PI=y",
                  "# CONFIG_PREEMPT_RT is not set"))
    return ("\n".join(lines) + "\n").encode()

def fake_image():
    return b"\x00" * 64 + START + gzip.compress(fake_config()) + END + b"\x00" * 32

class TestEmbeddedConfig(unittest.TestCase):
    def test_extract_fixture(self):
        status, body, pos = scan(fake_image())
        self.assertEqual(status,"embedded_config_found")
        self.assertEqual(body,fake_config())
        self.assertEqual(pos,64)
    def test_flags_not_proof_of_runtime(self):
        report=inspect_kernel(fake_image(),require_sha256=None)
        self.assertEqual(report["options"]["CONFIG_FUTEX_PI"],"y")
        self.assertEqual(report["options"]["CONFIG_PREEMPT_RT"],"n")
        self.assertEqual(report["options"]["CONFIG_RT_MUTEXES"],"not_listed")
        self.assertFalse(report["integrity_verified"])
        self.assertEqual(report["device_operations"],0)
    def test_wrong_digest_fails_closed(self):
        with self.assertRaises(ValueError):
            inspect_kernel(fake_image())
    def test_missing_marker_unknown(self):
        report=inspect_kernel(b"unrelated non-kernel data",require_sha256=None)
        self.assertEqual(report["status"],"embedded_config_not_found")
        self.assertEqual(report["options"]["CONFIG_FUTEX_PI"],"unknown")
    def test_corrupt_marker_does_not_claim_config(self):
        status,_,_=scan(START+b"bad gzip"+END)
        self.assertEqual(status,"embedded_config_invalid")
    def test_valid_after_corrupt_marker(self):
        data=START+b"bad gzip"+END+fake_image()
        status,content,_=scan(data)
        self.assertEqual(status,"embedded_config_found")
        self.assertEqual(content,fake_config())

if __name__=="__main__":
    unittest.main()
