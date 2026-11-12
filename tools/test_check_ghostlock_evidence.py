"""Synthetic-only, offline regression tests: no firmware files or device operations."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_ghostlock_evidence import BOOT_SHA,KERNEL_SHA,PREDICATES,grade

def sample():
 return {'stock_boot_sha256':BOOT_SHA,'extracted_kernel_sha256':KERNEL_SHA,
  'signed_original_proxy_rollback_direct_call_validated':True,
  'signed_original_remove_waiter_current_use_validated':True,
  'current_task_pi_blocked_on_clear_machine_code':'str xzr, [x20, #0x990]',
  'device_operations':0,'byte_verified_rollback_predicates':dict(PREDICATES),
  'orig_signed_functions':{
    'rt_mutex_start_proxy_lock':{'vaddr':'0xffffffc01037e2c0','instructions':[{'mnemonic':'stp'}]},
    'remove_waiter':{'vaddr':'0xffffffc01037e350','instructions':[{'mnemonic':'stp'}]}}}
class TestEvidence(unittest.TestCase):
 def test_exact_report_supports_static_only(self):
  result=grade(sample())
  self.assertTrue(result['verified_static_evidence'])
  self.assertEqual(result['evidence']['persistent_bootloader_unlock'],'not_established')
 def test_wrong_sha_fails(self):
  s=sample();s['stock_boot_sha256']='0'*64
  self.assertFalse(grade(s)['verified_static_evidence'])
 def test_missing_predicate_fails(self):
  s=sample();s['byte_verified_rollback_predicates'].pop('0xffffffc01037e344')
  self.assertFalse(grade(s)['verified_static_evidence'])
 def test_wrong_pi_clear_fails(self):
  s=sample();s['current_task_pi_blocked_on_clear_machine_code']='str xzr, [x23, #0x990]'
  self.assertFalse(grade(s)['verified_static_evidence'])
 def test_missing_disassembly_fails(self):
  s=sample();s['orig_signed_functions']['remove_waiter']['instructions']=[]
  self.assertFalse(grade(s)['verified_static_evidence'])
 def test_device_operations_fails(self):
  s=sample();s['device_operations']=1
  self.assertFalse(grade(s)['verified_static_evidence'])
 def test_claims_cannot_promote_unlock(self):
  s=sample();s['persistent_bootloader_unlock']=True;s['root_exploit']=True
  self.assertEqual(grade(s)['evidence']['persistent_bootloader_unlock'],'not_established')
if __name__=='__main__':unittest.main()
