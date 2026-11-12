"""Synthetic tests: no firmware loading, no syscall or vulnerable waiter creation."""
import unittest
from audit_c431_waiter_local_source_binary import (
    parse_nm,bounds,source_preflight,inspect_instructions
)

SRC=b'''static int futex_wait_requeue_pi(u32 *uaddr) {
 struct rt_mutex_waiter rt_waiter;
 struct futex_q q = futex_q_init;
 rt_mutex_init_waiter(&rt_waiter);
 q.rt_waiter = &rt_waiter;
 ret = futex_wait_setup(uaddr, val, flags, &q, &hb);
 futex_wait_queue_me(hb, &q, to);
}'''
SYM='''ffffffc0103c84e4 T do_futex
ffffffc0103c9e18 T other
ffffffc010562afc T core_sys_select
ffffffc010562d5c T other_select
ffffffc0105638fc T __arm64_sys_pselect6
ffffffc010563cd0 T other_pselect
ffffffc01037db00 T rt_mutex_init_waiter
'''
def ins(addr,op,operand):
 return {'address':hex(addr),'mnemonic':op,'operand':operand,'bytes':'d503201f'}

class Tests(unittest.TestCase):
 def test_source_stack_definition(self):
  m=source_preflight(SRC)
  self.assertTrue(m['source_waiter_allocated_on_kernel_stack'])
  self.assertTrue(m['source_is_not_exact_original_C431'])
 def test_missing_source_initializer(self):
  with self.assertRaises(ValueError):
   source_preflight(SRC.replace(b'rt_mutex_init_waiter(&rt_waiter);',b'other();'))
 def test_source_wrong_order(self):
  m=SRC.replace(b' rt_mutex_init_waiter(&rt_waiter);\n q.rt_waiter = &rt_waiter;',
                b' q.rt_waiter = &rt_waiter;\n rt_mutex_init_waiter(&rt_waiter);')
  with self.assertRaises(ValueError):source_preflight(m)
 def test_exact_symbol_bounds(self):
  a=parse_nm(SYM)
  self.assertEqual(bounds('do_futex',a),(0xffffffc0103c84e4,0xffffffc0103c9e18))
 def test_wrong_original_symbol(self):
  with self.assertRaises(ValueError):
   bounds('do_futex',parse_nm(SYM.replace('ffffffc0103c84e4','ffffffc0103c84e8')))
 def test_real_direct_bl_only(self):
  original=parse_nm(SYM)
  a=inspect_instructions('do_futex',[
   ins(0x100,'bl','#0xffffffc01037db00'),
   ins(0x104,'blr','x3')],original)
  self.assertEqual(a['direct_bl_count'],1)
  self.assertEqual(a['direct_calls'][0]['symbols'],['rt_mutex_init_waiter'])
  self.assertFalse(a['local_object_identity_verified'])
 def test_stack_evidence_not_claimed_as_object(self):
  a=inspect_instructions('do_futex',[
   ins(0x100,'sub','sp, sp, #0x1c0'),
   ins(0x104,'add','x19, sp, #0x100'),
   ins(0x108,'str','x0, [sp, #0xc8]'),
   ins(0x10c,'stp','x19, x21, [sp, #0x40]')],[])
  self.assertEqual(len(a['sp_address_computation_samples']),1)
  self.assertEqual(len(a['direct_sp_reference_samples']),2)
  self.assertTrue(a['instruction_count_is_not_a_stack_layout_proof'])
 def test_unsupported_arm64_tail_branch_not_call(self):
  a=inspect_instructions('do_futex',[ins(0x100,'b','#0xffffffc01037db00')],parse_nm(SYM))
  self.assertEqual(a['direct_bl_count'],0)

if __name__=='__main__':unittest.main()
