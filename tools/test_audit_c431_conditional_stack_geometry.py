"""Synthetic original C431 frame-geometry tests. No phone, UAF or root code."""
import unittest
from audit_c431_conditional_stack_geometry import BOOT_SHA,IMAGE_SHA,DO_SHA,SELECT_SHA,PSELECT_SHA,STOCK_PROLOGUES,audit

def report():
 functions={}
 for name,sha in [('do_futex',DO_SHA),('core_sys_select',SELECT_SHA),('__arm64_sys_pselect6',PSELECT_SHA)]:
  functions[name]={
   'original_function_sha256':sha,
   'prologue_instructions':[{'address':a,'mnemonic':op,'operand':arg}
                            for a,op,arg in STOCK_PROLOGUES[name]],
   'sp_address_computation_samples':[],'direct_calls':[]}
 functions['core_sys_select']['sp_address_computation_samples'].append({
  'at':'0xffffffc010562bec','register':'x23','raw_offset':'0x50'})
 functions['core_sys_select']['direct_calls'].append({
  'at':'0xffffffc010562c34','symbols':['get_fd_set']})
 return {'original_boot_sha256':BOOT_SHA,'original_image_sha256':IMAGE_SHA,'functions':functions}

def graph():
 return {
  'boot_sha256':BOOT_SHA,'kernel_sha256':IMAGE_SHA,
  'function_profiles':{'__arm64_sys_futex':{
   'status':'present','entry_stack_adjustments':[{'mnemonic':'sub','operands':'sp, sp, #0x70'}]}},
  'direct_watched_edges':[
   {'caller':'__arm64_sys_futex','callee_names':['do_futex']},
   {'caller':'__arm64_sys_pselect6','callee_names':['core_sys_select']}]
 }

class Tests(unittest.TestCase):
 def test_conditional_overlap_not_exploitation(self):
  x=audit(report(),graph())
  self.assertEqual(x['arithmetic_intersection_bytes'],80)
  self.assertFalse(x['shared_kernel_stack_base_proven'])
  self.assertFalse(x['select_bytes_user_controllable_in_intersection_proven'])
  self.assertFalse(x['uaf_root_or_unlock_demonstrated'])
 def test_wrong_kernel_hash(self):
  g=graph();g['kernel_sha256']='0'*64
  with self.assertRaises(ValueError):audit(report(),g)
 def test_wrong_do_futex_hash(self):
  r=report();r['functions']['do_futex']['original_function_sha256']='0'*64
  with self.assertRaises(ValueError):audit(r,graph())
 def test_changed_pselect_prologue(self):
  r=report();r['functions']['__arm64_sys_pselect6']['prologue_instructions'][0]['operand']='sp, sp, #0x80'
  with self.assertRaises(ValueError):audit(r,graph())
 def test_missing_select_fd_base(self):
  r=report();r['functions']['core_sys_select']['sp_address_computation_samples']=[]
  with self.assertRaises(ValueError):audit(r,graph())
 def test_missing_select_copy_helper(self):
  r=report();r['functions']['core_sys_select']['direct_calls']=[]
  with self.assertRaises(ValueError):audit(r,graph())
 def test_wrong_futex_wrapper_frame(self):
  g=graph();g['function_profiles']['__arm64_sys_futex']['entry_stack_adjustments'][0]['operands']='sp, sp, #0x80'
  with self.assertRaises(ValueError):audit(report(),g)
 def test_missing_pselect_edge(self):
  g=graph();g['direct_watched_edges']=g['direct_watched_edges'][:1]
  with self.assertRaises(ValueError):audit(report(),g)
if __name__=='__main__':unittest.main()
