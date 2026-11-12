"""No-device synthetic verification of signed C431 OEM configuration classification."""
import hashlib
import unittest
from audit_c431_original_vendor_abi_config import inspect

def config():
 return (b"CONFIG_HN_VIP_THREAD=y\n"
         b"# CONFIG_HN_QOS_THREAD is not set\n"
         b"CONFIG_CFI_CLANG=y\n"
         b"CONFIG_FUTEX=y\n")

class Tests(unittest.TestCase):
 def check(self,raw=None):
  data=config() if raw is None else raw
  return inspect(data,expected_ikconfig=hashlib.sha256(config()).hexdigest())
 def test_signed_option_states(self):
  result=self.check()
  flags=result["compiled_feature_status"]
  self.assertEqual(flags["CONFIG_HN_VIP_THREAD"],"y")
  self.assertEqual(flags["CONFIG_HN_QOS_THREAD"],"n")
  self.assertEqual(flags["CONFIG_HN_RTG"],"not_listed")
 def test_not_usable_as_c431_source_abi(self):
  x=self.check()
  self.assertFalse(x["actual_c431_task_struct_layout_fully_recovered"])
  self.assertTrue(x["generic_source_abi_is_not_automatically_c431"])
  self.assertFalse(x["userland_root_or_uaf_executed"])
 def test_wrong_config_digest_rejected(self):
  with self.assertRaises(ValueError):self.check(config()+b"changed")
 def test_conflicting_config_rejected(self):
  raw=config()+b"# CONFIG_HN_VIP_THREAD is not set\n"
  with self.assertRaises(ValueError):
   inspect(raw,expected_ikconfig=hashlib.sha256(raw).hexdigest())
 def test_only_config_not_runtime(self):
  result=self.check()
  self.assertEqual(result["device_operations"],0)
  self.assertTrue(result["source_declarations_do_not_prove_compiled_struct_offsets"])
if __name__=="__main__":unittest.main()
