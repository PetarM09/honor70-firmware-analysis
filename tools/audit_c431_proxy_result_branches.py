#!/usr/bin/env python3
"""Offline audited C431 rt_mutex_start_proxy_lock return-value branch classification.

Inputs: SHA-pinned original C431 ARM64 disassembly plus HONOR Fennie GPL
reference. Output is a read-only control-flow evidence report, NOT a PoC.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

BOOT_SHA = '5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256'
IMAGE_SHA = 'bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece'
RTMUTEX_SHA = '70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9'
PROXY = 'rt_mutex_start_proxy_lock'
BASE = '0xffffffc01037e2c0'
SITES = (
  ('0xffffffc01037e2d0', 'mov', 'x21, x2'),
  ('0xffffffc01037e2d4', 'mov', 'x20, x1'),
  ('0xffffffc01037e2d8', 'mov', 'x19, x0'),
  ('0xffffffc01037e2ec', 'bl', '#0xffffffc01037ddb8'),
  ('0xffffffc01037e2f0', 'cbz', 'w0, #0xffffffc01037e320'),
  ('0xffffffc01037e2f4', 'mov', 'w21, #1'),
  ('0xffffffc01037e2f8', 'mov', 'x0, x19'),
  ('0xffffffc01037e2fc', 'mov', 'x1, x20'),
  ('0xffffffc01037e300', 'bl', '#0xffffffc01037e350'),
  ('0xffffffc01037e304', 'mov', 'x0, x19'),
  ('0xffffffc01037e30c', 'mov', 'w0, w21'),
  ('0xffffffc01037e320', 'mov', 'w3, #1'),
  ('0xffffffc01037e324', 'mov', 'x0, x19'),
  ('0xffffffc01037e328', 'mov', 'x1, x20'),
  ('0xffffffc01037e32c', 'mov', 'x2, x21'),
  ('0xffffffc01037e330', 'bl', '#0xffffffc01037dfb4'),
  ('0xffffffc01037e334', 'mov', 'w21, w0'),
  ('0xffffffc01037e338', 'cbz', 'w0, #0xffffffc01037e304'),
  ('0xffffffc01037e33c', 'ldr', 'x8, [x19, #0x18]'),
  ('0xffffffc01037e340', 'cmp', 'x8, #2'),
  ('0xffffffc01037e344', 'b.hs', '#0xffffffc01037e2f8'),
  ('0xffffffc01037e348', 'mov', 'w21, wzr'),
  ('0xffffffc01037e34c', 'b', '#0xffffffc01037e304'),
)
def audit(binary, source: bytes, expected_source=RTMUTEX_SHA):
    if binary.get('boot_sha256') != BOOT_SHA or binary.get('kernel_image_sha256') != IMAGE_SHA:
        raise ValueError('Original retail C431 binary provenance mismatch')
    if hashlib.sha256(source).hexdigest() != expected_source:
        raise ValueError('Wrong HONOR GPL reference source digest')
    text = source.decode('utf-8')
    required = (
      r'if\s*\(try_to_take_rt_mutex\(lock,\s*task,\s*NULL\)\)\s*return\s+1\s*;',
      r'ret\s*=\s*task_blocks_on_rt_mutex\s*\(lock,\s*waiter,\s*task,',
      r'if\s*\(ret\s*&&\s*!rt_mutex_owner\(lock\)\)',
      r'if\s*\(unlikely\(ret\)\)\s*remove_waiter\(lock,\s*waiter\)\s*;',
      r'raw_spin_lock\(&current->pi_lock\)',
      r'current->pi_blocked_on\s*=\s*NULL\s*;'
    )
    for expression in required:
        if not re.search(expression, text, re.S):
            raise ValueError('Required HONOR source behavior missing: '+expression)
    f=binary.get('functions',{}).get(PROXY,{})
    if f.get('symbol_va') != BASE:
        raise ValueError('C431 original function entry address mismatch')
    by_addr={}
    for i in f.get('initial_instructions_for_register_flow',[]):
        by_addr.setdefault(i.get('address'),[]).append(i)
    for addr,opcode,operand in SITES:
        found=by_addr.get(addr,[])
        if len(found)!=1:
            raise ValueError('Missing/ambiguous C431 ARM64 site '+addr)
        inst=found[0]
        if (inst.get('mnemonic'),inst.get('operand'))!=(opcode,operand):
            raise ValueError('Wrong C431 branch or argument at '+addr)
        if not re.fullmatch('[0-9a-f]{8}',inst.get('bytes','')):
            raise ValueError('Original instruction bytes missing '+addr)
    return {
      'schema_version':1,
      'target':'FNE-NX9 C431 original Linux 5.4.295',
      'boot_sha256':BOOT_SHA,
      'kernel_sha256':IMAGE_SHA,
      'honor_fennie_reference_sha256':expected_source,
      'honor_fennie_base_version':'5.4.242; original binary above is 5.4.295',
      'original_arm64_instruction_assertions':len(SITES),
      'distinct_original_control_flow_cases':[
        {'case':'immediate_acquisition',
         'branch':'original try-to-take returned nonzero',
         'original_return_value':'1',
         'remove_waiter_called':True,
         'source_semantics':'1 means acquisition succeeded; waiter may not be enqueued',
         'related_upstream_issue':'CVE-2026-53163 code pattern; retail C431 exploitability not established'},
        {'case':'task_blocking',
         'branch':'try-to-take returned zero, task_blocks_on returned zero',
         'original_return_value':'0',
         'remove_waiter_called':False},
        {'case':'task_blocks_nonzero_owner_present',
         'branch':'try-to-take returned zero, task_blocks_on nonzero and owner remains',
         'original_return_value':'nonzero as produced by task_blocks_on',
         'remove_waiter_called':True,
         'source_semantics':'wrong-current cleanup matches CVE-2026-43499 source pattern'},
        {'case':'task_blocks_nonzero_owner_gone',
         'branch':'try-to-take returned zero, task_blocks_on nonzero, owner absent',
         'original_return_value':'0 (normalized)',
         'remove_waiter_called':False}
      ],
      'scope':'static function-local control-flow and reference-source concordance',
      'caller_can_force_any_case':'not established',
      'live_waiter_rollback_or_uaf':'not demonstrated',
      'kernel_physical_geometry':'not recovered',
      'temporary_root_or_bootloader_unlock':'not demonstrated',
      'device_operations':0
    }
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--arm64-report',type=Path,required=True)
    p.add_argument('--honor-rtmutex',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    result=audit(json.loads(a.arm64_report.read_text()),a.honor_rtmutex.read_bytes())
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print('EXACT_C431_BRANCHED_SITES_CONFIRMED',result['original_arm64_instruction_assertions'])
    for item in result['distinct_original_control_flow_cases']:
        print('C431_RETURN_CASE',item['case'],'CLEANUP',item['remove_waiter_called'])
    print('GHOSTLOCK_ROOT_TESTED',False)
