#!/usr/bin/env python3
"""Offline conditional stack-frame interval hypothesis for signed C431.

Does not assume actual stack reuse, user-controlled writes, UAF, or root.
No device access or exploit operation.
"""
import argparse,json
from pathlib import Path

BOOT_SHA='5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256'
IMAGE_SHA='bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece'
DO_SHA='dafc0e0138313ba88c2bbaad6fdd71509561325ce232bcbd19ea1e4f98a6108a'
SELECT_SHA='244a0f29b764672a7ec642a7dc469a156777dd352d12379fcf52ecc6b0d53fd2'
PSELECT_SHA='0f24235338d5ddb266220076c0cdf28fbf1346401fbd9655985b0903054cb4ca'
STOCK_PROLOGUES={
 'do_futex':[
  ('0xffffffc0103c84e4','stp','x29, x30, [sp, #-0x60]!'),
  ('0xffffffc0103c84fc','mov','x29, sp'),
  ('0xffffffc0103c8500','sub','sp, sp, #0x1c0')],
 '__arm64_sys_pselect6':[
  ('0xffffffc0105638fc','sub','sp, sp, #0x90')],
 'core_sys_select':[
  ('0xffffffc010562afc','sub','sp, sp, #0x1c0'),
  ('0xffffffc010562b34','stp','xzr, xzr, [sp, #0x140]')]
}

def check_sites(report,name,site_list):
 func=report['functions'][name]
 table={ins['address']:ins for ins in func['prologue_instructions']}
 for addr,op,operand in site_list:
  ins=table.get(addr)
  if not ins or (ins['mnemonic'],ins['operand'])!=(op,operand):
   raise ValueError('Exact original instruction mismatch '+name+' '+addr)

def check_select_fd_base(report):
 f=report['functions']['core_sys_select']
 hits=[x for x in f['sp_address_computation_samples']
       if x['at']=='0xffffffc010562bec' and x['register']=='x23' and x['raw_offset']=='0x50']
 if len(hits)!=1:raise ValueError('Original select stack buffer base missing')
 if not any(c['at']=='0xffffffc010562c34' and 'get_fd_set' in c['symbols']
            for c in f['direct_calls']):
  raise ValueError('Missing original select copy helper')

def audit(waiter_report,callgraph):
 if waiter_report.get('original_boot_sha256')!=BOOT_SHA or waiter_report.get('original_image_sha256')!=IMAGE_SHA:
  raise ValueError('Wrong original stock C431 identity')
 if callgraph.get('boot_sha256')!=BOOT_SHA or callgraph.get('kernel_sha256')!=IMAGE_SHA:
  raise ValueError('Wrong original C431 syscall graph identity')
 funcs=waiter_report.get('functions',{})
 for name,sha in [('do_futex',DO_SHA),('core_sys_select',SELECT_SHA),('__arm64_sys_pselect6',PSELECT_SHA)]:
  if funcs.get(name,{}).get('original_function_sha256')!=sha:
   raise ValueError('Original C431 function SHA mismatch '+name)
 for name,sites in STOCK_PROLOGUES.items():check_sites(waiter_report,name,sites)
 check_select_fd_base(waiter_report)
 wrapper=callgraph['function_profiles']['__arm64_sys_futex']
 if wrapper['status']!='present' or not any(
     i['mnemonic']=='sub' and i['operands']=='sp, sp, #0x70'
     for i in wrapper['entry_stack_adjustments']):
  raise ValueError('Missing exact original futex syscall entry frame')
 for caller,dest in [('__arm64_sys_futex','do_futex'),('__arm64_sys_pselect6','core_sys_select')]:
  if not any(e['caller']==caller and dest in e['callee_names']
             for e in callgraph['direct_watched_edges']):
   raise ValueError('Missing original syscall -> helper edge')
 # Hypothetical common syscall-entry SP = zero. This is purely static algebra.
 waiter_start= -0x70 - (0x60+0x1c0) + (0x1c0-0xd0)
 waiter_end=waiter_start+0x50  # minimum last verified waiter field end
 select_start= -0x90-0x1c0+0x50
 select_end= -0x90-0x1c0+0x150  # zeroed stack region; not proof of user writes
 lo=max(waiter_start,select_start);hi=min(waiter_end,select_end)
 return {
  'schema_version':1,'target':'original signed FNE-NX9 C431 Linux 5.4.295',
  'boot_sha256':BOOT_SHA,'kernel_sha256':IMAGE_SHA,
  'hypothesis':'both syscall paths begin with identical kernel-thread entry SP',
  'waiter_minimum_observed_region_entry_sp_relative':[waiter_start,waiter_end],
  'select_candidate_stack_region_entry_sp_relative':[select_start,select_end],
  'arithmetic_intersection_entry_sp_relative':[lo,hi] if hi>lo else None,
  'arithmetic_intersection_bytes':max(0,hi-lo),
  'shared_kernel_stack_base_proven':False,
  'select_bytes_user_controllable_in_intersection_proven':False,
  'waiter_reuse_after_live_uaf_proven':False,
  'static_interval_match_is_not_ghostlock_feasibility':True,
  'uaf_root_or_unlock_demonstrated':False,'device_operations':0
 }

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--waiter-report',required=True,type=Path)
 p.add_argument('--callgraph',required=True,type=Path)
 p.add_argument('--out',required=True,type=Path)
 a=p.parse_args()
 d=audit(json.loads(a.waiter_report.read_text()),json.loads(a.callgraph.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(d,indent=2)+'\n')
 print('CONDITIONAL_BYTE_INTERSECTION',d['arithmetic_intersection_bytes'])
 print('REAL_STACK_REUSE_OR_ROOT_PROVEN',False)
