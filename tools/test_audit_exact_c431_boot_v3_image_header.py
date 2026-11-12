"""Synthetic-only original-boot v3 / ARM64 Image header tests."""
import hashlib,struct,unittest
from unittest.mock import patch
from audit_exact_c431_boot_v3_image_header import inspect,sha,fdt_candidates

def sample():
    kernel=bytearray(256)
    kernel[56:60]=b"ARM\x64"
    struct.pack_into("<3Q",kernel,8,0x80000,0x500000,0x8)
    boot=bytearray(8192)
    boot[:8]=b"ANDROID!"
    struct.pack_into("<4I",boot,8,len(kernel),0,0,1580)
    struct.pack_into("<I",boot,40,3)
    boot[4096:4096+len(kernel)]=kernel
    return bytes(boot),bytes(kernel)

def run(boot=None,kernel=None):
    original_boot,original_kernel=sample()
    boot=original_boot if boot is None else boot
    kernel=original_kernel if kernel is None else kernel
    config=b"CONFIG_DEBUG_INFO_BTF=y\nCONFIG_RANDOMIZE_BASE=y\n"
    with patch("audit_exact_c431_boot_v3_image_header.scan",
               return_value=("embedded_config_found",config,20)):
        return inspect(boot,kernel,expected_boot_sha=sha(boot),
                       expected_kernel_sha=sha(kernel),
                       expected_ikconfig_sha=sha(config))

class Tests(unittest.TestCase):
    def test_header_and_no_fake_phys_base(self):
        r=run()
        self.assertEqual(r["boot_image_header"]["version"],3)
        self.assertFalse(r["boot_image_header"]["has_kernel_offset_field"])
        self.assertEqual(r["arm64_Image_header"]["text_offset_hex"],"0x80000")
        self.assertEqual(r["arm64_Image_header"]["physical_placement_selector"],1)
        self.assertIsNone(r["kernel_phys_load"])
        self.assertIsNone(r["actual_runtime_kernel_slide"])
    def test_embedded_debug_config_not_dwarf_proof(self):
        r=run()
        self.assertEqual(r["debug_symbols_build_options"]["CONFIG_DEBUG_INFO_BTF"],"y")
        self.assertFalse(r["original_external_DWARF_or_BTF_sections_proven_accessible"])
    def test_wrong_kernel_payload_refused(self):
        boot,kernel=sample()
        broken=bytearray(boot)
        broken[4096+60]=99
        with self.assertRaises(ValueError):run(bytes(broken),kernel)
    def test_wrong_android_header_version_refused(self):
        boot,kernel=sample()
        b=bytearray(boot);struct.pack_into("<I",b,40,2)
        with self.assertRaises(ValueError):run(bytes(b),kernel)
    def test_legacy_kernel_size_header_rejected(self):
        boot,kernel=sample()
        b=bytearray(boot);struct.pack_into("<I",b,20,1660)
        with self.assertRaises(ValueError):run(bytes(b),kernel)
    def test_wrong_arm64_magic_refused(self):
        boot,kernel=sample()
        k=bytearray(kernel);k[56:60]=b"BAD!"
        b=bytearray(boot);b[4096:4096+len(k)]=k
        with self.assertRaises(ValueError):run(bytes(b),bytes(k))
    def test_no_fake_dtb_header(self):
        self.assertEqual(fdt_candidates(b"\xd0\x0d\xfe\xed"+b"\x00"*100),[])
    def test_invalid_gzip_ikconfig_rejected(self):
        boot,kernel=sample()
        with patch("audit_exact_c431_boot_v3_image_header.scan",
                   return_value=("embedded_config_invalid",None,None)):
            with self.assertRaises(ValueError):
                inspect(boot,kernel,expected_boot_sha=sha(boot),
                        expected_kernel_sha=sha(kernel),
                        expected_ikconfig_sha=sha(b"config"))
if __name__=="__main__":unittest.main()
