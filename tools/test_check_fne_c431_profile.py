"""Synthetic tests of C431 non-operational profile and read-only ADB checker."""
import copy, json, unittest
from pathlib import Path
from types import SimpleNamespace

from check_fne_c431_profile import (
    DEFAULT_PROFILE, ADB_COMMANDS, KERNEL,
    validate_profile, evaluate_identity, run_adb
)

def profile():
    return json.loads(DEFAULT_PROFILE.read_text())

def live():
    return {
      "model":"FNE-NX9","device":"HNFNE","kernel":KERNEL,
      "android_sdk":"34","android_release":"14","build_incremental":"8.0.0.290",
      "selinux_enforcing":"Enforcing","verified_boot_state":"green",
      "flash_locked":"1","shell_uid":"2000"
    }

class TestC431ReadOnlyProfile(unittest.TestCase):
    def test_known_profile_valid(self):
        self.assertTrue(validate_profile(profile()))
    def test_device_identity_matches(self):
        r=evaluate_identity(profile(),live())
        self.assertEqual(r["identity_result"],"MODEL_KERNEL_ANDROID_MATCH")
        self.assertFalse(r["firmware_region_c431_live_attested"])
        self.assertFalse(r["temporary_root_proven"])
    def test_wrong_kernel_is_rejected_as_match(self):
        x=live();x["kernel"]="5.4.295-qgki-wrong"
        self.assertEqual(evaluate_identity(profile(),x)["identity_result"],
                         "MODEL_KERNEL_ANDROID_MISMATCH")
    def test_wrong_region_profile_fails_closed(self):
        p=profile();p["target"]["region"]="C00"
        with self.assertRaises(ValueError):validate_profile(p)
    def test_wrong_waiter_offsets_fail_closed(self):
        p=profile();p["confirmed_binary_offsets_bytes"]["rt_mutex_waiter.task"]=0x50
        with self.assertRaises(ValueError):validate_profile(p)
    def test_fabricated_runtime_base_refused(self):
        p=profile();p["unresolved_required_fields"]["kernel_phys_load"]=0xfffff000
        with self.assertRaises(ValueError):validate_profile(p)
    def test_root_enabled_refused(self):
        p=profile();p["checks"]["root_installation_enabled"]=True
        with self.assertRaises(ValueError):validate_profile(p)
    def test_untrusted_image_hash_refused(self):
        p=profile();p["provenance"]["extracted_kernel_image_sha256"]="0"*64
        with self.assertRaises(ValueError):validate_profile(p)
    def test_no_unsafe_adb_commands(self):
        self.assertTrue(all(c[:1]==["shell"] for c in ADB_COMMANDS.values()))
        for command in ADB_COMMANDS.values():
            # Each command is argv-only: no command shell interpretation.
            self.assertEqual(command[0],"shell")
            self.assertIn(command[1],{"getprop","uname","getenforce","id"})
            for token in command[1:]:
                self.assertNotIn(token,{"fastboot","flash","write","reboot",
                                        "su","dd","futex","edl","push","pull"})
    def test_adb_uses_mock_reader_only(self):
        invoked=[]
        def fake_runner(args,**kwargs):
            invoked.append(args)
            return SimpleNamespace(returncode=0,stdout="FNE-NX9\n",stderr="")
        obs=run_adb(runner=fake_runner)
        self.assertEqual(len(invoked),len(ADB_COMMANDS))
        self.assertEqual(obs["model"],"FNE-NX9")
    def test_adb_failed_command_fails_closed(self):
        def bad_runner(args,**kwargs):
            return SimpleNamespace(returncode=1,stdout="",stderr="offline")
        with self.assertRaises(RuntimeError):
            run_adb(runner=bad_runner)

if __name__=="__main__":
    unittest.main()
