"""Synthetic-only tests for stock C431 waiter attribution, no device I/O."""
import hashlib,unittest
from verify_exact_c431_inlined_waiter_provenance import BOOT_SHA,IMAGE_SHA,DO_FUTEX_SHA,SITES,CALLS,audit
SRC=b'''static int futex_wait_requeue_pi(void) {
 struct rt_mutex_waiter rt_waiter;
 struct futex_q q = futex_q_init;
 rt_mutex_init_waiter(&rt_waiter);
 q.rt_waiter = &rt_waiter;
 futex_wait_queue_me(hb, &q, to);
}'''

def fixture():
 ins=[{'address':a,'mnemonic':m,'operand':p,'bytes':'d503201f'} for a,m,p in SITES]
 calls=[{'at':addr,'symbols':[name],'preceding_instructions':list(ins)}
        for addr,name in CALLS.items()]
 return {'original_boot_sha256':BOOT_SHA,'original_image_sha256':IMAGE_SHA,
         'functions':{'do_futex':{'original_function_sha256':DO_FUTEX_SHA,
                                 'original_function_va':'0xffffffc0103c84e4',
                                 'prologue_instructions':ins,
                                 'sp_address_computation_samples':[],
                                 'direct_calls':calls}}}

class Tests(unittest.TestCase):
 def check(self,report=None,source=SRC):
  return audit(fixture() if report is None else report,source,
               expected_source=hashlib.sha256(SRC).hexdigest())
 def test_valid_evidence_not_an_exploit(self):
  r=self.check()
  self.assertEqual(r['instruction_sites_verified'],9)
  self.assertEqual(r['distinct_original_direct_helpers_verified'],5)
  self.assertFalse(r['actual_stack_overlap_confirmed'])
  self.assertFalse(r['ghostlock_root_or_unlock_demonstrated'])
 def test_wrong_image_digest(self):
  r=fixture();r['original_image_sha256']='0'*64
  with self.assertRaises(ValueError):self.check(r)
 def test_wrong_function_digest(self):
  r=fixture();r['functions']['do_futex']['original_function_sha256']='0'*64
  with self.assertRaises(ValueError):self.check(r)
 def test_wrong_frame_pointer_setup(self):
  r=fixture();r['functions']['do_futex']['prologue_instructions'][1]['operand']='x29, x0'
  with self.assertRaises(ValueError):self.check(r)
 def test_wrong_waiter_offset(self):
  r=fixture();r['functions']['do_futex']['prologue_instructions'][3]['operand']='x0, x29, #0xe0'
  with self.assertRaises(ValueError):self.check(r)
 def test_wrong_waiter_setup_call(self):
  r=fixture();r['functions']['do_futex']['direct_calls'][0]['symbols']=['other']
  with self.assertRaises(ValueError):self.check(r)
 def test_missing_source_waiter(self):
  with self.assertRaises(ValueError):
   self.check(source=SRC.replace(b'struct rt_mutex_waiter rt_waiter;',b''))
 def test_wrong_source_digest(self):
  with self.assertRaises(ValueError):self.check(source=SRC+b'modified')
 def test_mismatched_q_pointer(self):
  r=fixture();r['functions']['do_futex']['prologue_instructions'][5]['operand']='x3, sp, #0xa0'
  with self.assertRaises(ValueError):self.check(r)
if __name__=='__main__':unittest.main()
