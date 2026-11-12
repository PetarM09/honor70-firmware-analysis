#!/usr/bin/env python3
"""Original C431 waiter pointer provenance from signed kernel ARM64.

Offline source attribution and prologue-relative frame arithmetic only.
No UAF, stack-overlay proof, root or device operations.
"""
import argparse,hashlib,json
from pathlib import Path

BOOT_SHA='5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256'
IMAGE_SHA='bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece'
FUTEX_SHA='71b9c7591dc611e6f92e742858bcc044cf01b605208058498e31d444b7704106'
DO_FUTEX_SHA='dafc0e0138313ba88c2bbaad6fdd71509561325ce232bcbd19ea1e4f98a6108a'

SITES=(
 ('0xffffffc0103c84e4','stp','x29, x30, [sp, #-0x60]!'),
 ('0xffffffc0103c84fc','mov','x29, sp'),
 ('0xffffffc0103c8500','sub','sp, sp, #0x1c0'),
 ('0xffffffc0103c96dc','sub','x0, x29, #0xd0'),
 ('0xffffffc0103c96e0','sub','x26, x29, #0xd0'),
 ('0xffffffc0103c9708','add','x3, sp, #0x70'),
 ('0xffffffc0103c97f4','add','x1, sp, #0x70'),
 ('0xffffffc0103c9858','sub','x2, x29, #0xd0'),
 ('0xffffffc0103c987c','sub','x1, x29, #0xd0')
)
CALLS={
 '0xffffffc0103c96e4':'rt_mutex_init_waiter',
 '0xffffffc0103c9724':'futex_wait_setup',
 '0xffffffc0103c9800':'futex_wait_queue_me',
 '0xffffffc0103c9864':'rt_mutex_wait_proxy_lock',
 '0xffffffc0103c9884':'rt_mutex_cleanup_proxy_lock'
}

def audit(report,source,*,expected_source=FUTEX_SHA):
 if report.get('original_boot_sha256')!=BOOT_SHA or report.get('original_image_sha256')!=IMAGE_SHA:
  raise ValueError('Signed original FNE-NX9 C431 image hash mismatch')
 if hashlib.sha256(source).hexdigest()!=expected_source:
  raise ValueError('HONOR GPL source changed')
 text=source.decode('utf-8')
 for needle in ('struct rt_mutex_waiter rt_waiter;',
                'struct futex_q q = futex_q_init;',
                'rt_mutex_init_waiter(&rt_waiter);',
                'q.rt_waiter = &rt_waiter;',
                'futex_wait_queue_me(hb, &q, to);'):
  if needle not in text:raise ValueError('HONOR source role missing: '+needle)
 f=report.get('functions',{}).get('do_futex',{})
 if f.get('original_function_sha256')!=DO_FUTEX_SHA or f.get('original_function_va')!='0xffffffc0103c84e4':
  raise ValueError('Original do_futex function identity mismatch')
 inst={}
 for item in f.get('prologue_instructions',[]):
  inst.setdefault(item.get('address'),[]).append(item)
 for call in f.get('direct_calls',[]):
  for item in call.get('preceding_instructions',[]):
   inst.setdefault(item.get('address'),[]).append(item)
 for target in f.get('sp_address_computation_samples',[]):
  for item in target.get('surrounding',[]):
   inst.setdefault(item.get('address'),[]).append(item)
 for addr,op,operand in SITES:
  entries=inst.get(addr,[])
  if not entries or any((x.get('mnemonic'),x.get('operand'))!=(op,operand)
                        for x in entries):
   raise ValueError('Original C431 instruction mismatch '+addr)
 observed={call.get('at'):call for call in f.get('direct_calls',[])}
 for addr,callee in CALLS.items():
  call=observed.get(addr)
  if call is None or call.get('symbols')!=[callee]:
   raise ValueError('Expected original helper call missing '+addr)
 # x29 is SP after 0x60 save; SP then reserves another 0x1c0.
 # So x29-0xd0 equals final prologue SP+(0x1c0-0xd0) = SP+0xf0.
 return {
  'schema_version':1,'original_boot_sha256':BOOT_SHA,
  'original_image_sha256':IMAGE_SHA,'fennie_gpl_futex_sha256':expected_source,
  'original_do_futex_sha256':DO_FUTEX_SHA,
  'instruction_sites_verified':len(SITES),
  'distinct_original_direct_helpers_verified':len(CALLS),
  'waiter_pointer_expression':'x29 - 0xd0',
  'waiter_prologue_relative_sp_expression':'sp + 0xf0 (subject to unchanged SP on path)',
  'futex_q_pointer_expression':'sp + 0x70',
  'waiter_pointer_passed_to':['rt_mutex_init_waiter','rt_mutex_wait_proxy_lock','rt_mutex_cleanup_proxy_lock'],
  'q_pointer_passed_to':['futex_wait_setup','futex_wait_queue_me'],
  'source_supports_inlined_wait_requeue_pi':'yes; no separate original symbol and helper series in do_futex',
  'actual_stack_overlap_confirmed':False,
  'actual_kernel_uaf_confirmed':False,
  'ghostlock_root_or_unlock_demonstrated':False,
  'device_operations':0
 }

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--original-report',type=Path,required=True)
 p.add_argument('--fennie-futex',type=Path,required=True)
 p.add_argument('--out',type=Path,required=True)
 a=p.parse_args()
 d=audit(json.loads(a.original_report.read_text()),a.fennie_futex.read_bytes())
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(d,indent=2)+'\n')
 print('ORIGINAL_C431_WAITER_SP_PROVENANCE',d['waiter_prologue_relative_sp_expression'])
 print('ORIGINAL_C431_HELPERS',d['distinct_original_direct_helpers_verified'])
 print('REAL_UAF_OR_ROOT',False)
