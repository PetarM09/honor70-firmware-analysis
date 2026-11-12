"""No-ELF, no-device tests of bounded C431 futex/select direct-call classification."""
import unittest
from audit_c431_futex_pselect_callgraph import parse_nm,bounds_for,find_call_targets,summarize
class Inst:
 def __init__(self,address,mnemonic,op_str):
  self.address=address;self.mnemonic=mnemonic;self.op_str=op_str
SYMS='''
ffffffc010000000 T __arm64_sys_futex
ffffffc010000100 T do_futex
ffffffc010000200 t futex_wait_requeue_pi
ffffffc010000300 t core_sys_select
ffffffc010000340 T end
'''
class Tests(unittest.TestCase):
 def test_call_graph(self):
  s=parse_nm(SYMS)
  a=summarize(s,{
   '__arm64_sys_futex':[Inst(0xffffffc010000020,'bl','#0xffffffc010000100')],
   'do_futex':[Inst(0xffffffc010000150,'bl','#0xffffffc010000200')]})
  self.assertEqual(a['function_count_present'],4)
  self.assertEqual(len(a['direct_watched_edges']),2)
  self.assertEqual(a['direct_watched_edges'][1]['callee_names'],['futex_wait_requeue_pi'])
  self.assertEqual(a['stack_overlay_feasibility'],'not established')
 def test_absent_symbol_not_falsely_inferred(self):
  a=summarize(parse_nm(SYMS),{})
  self.assertEqual(a['function_profiles']['__se_sys_futex']['status'],'missing')
  self.assertTrue(a['missing_symbols_do_not_prove_inlining_or_infeasibility'])
 def test_ambiguous_symbol_reports(self):
  x=parse_nm(SYMS+'ffffffc010000108 t do_futex\n')
  self.assertEqual(bounds_for('do_futex',x)['status'],'ambiguous')
 def test_cfi_trampoline_ignored(self):
  x=parse_nm(SYMS+'ffffffc010000018 t do_futex.cfi_jt\n')
  self.assertEqual(bounds_for('do_futex',x)['status'],'present')
 def test_unknown_indirect_not_labeled_direct(self):
  ins=[Inst(1,'blr','x0'),Inst(2,'ret',''),Inst(3,'bl','#0xffffffc010000350')]
  self.assertEqual(find_call_targets(ins,{0xffffffc010000100:['do_futex']}),[])
 def test_tail_call_supported(self):
  ins=[Inst(1,'b','#0xffffffc010000100')]
  e=find_call_targets(ins,{0xffffffc010000100:['do_futex']})
  self.assertEqual(e[0]['opcode'],'b')
 def test_clipped_function_not_complete(self):
  a=parse_nm('ffffffc010000000 T __arm64_sys_futex\nffffffc010010000 T other')
  self.assertFalse(bounds_for('__arm64_sys_futex',a)['complete'])
 def test_no_next_symbol(self):
  a=parse_nm('ffffffc010000000 t core_sys_select')
  self.assertEqual(bounds_for('core_sys_select',a)['status'],'missing_end_boundary')
if __name__=='__main__':unittest.main()
