#!/usr/bin/env python3
"""Evidence-gated C431 rt_mutex_waiter field layout from signed machine code.

No exploit payloads, active kernel addresses, memory-map guesses or device I/O.
A reported field is established only by the exact verified ARM64 instructions
AND source declarations from the HASH-PINNED HONOR GPL rtmutex source.
"""
import argparse,hashlib,json,re
from pathlib import Path

BOOT_SHA='5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256'
KERNEL_SHA='bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece'
WAITER_SRC_SHA='c79353d84625e4d352be7d96193cf162fba7857a85171540996f499679ea3d08'
RTMUTEX_SRC_SHA='70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9'
CHECKS=[
 ('rt_mutex_init_waiter','0xffffffc01037db00','add','x8, x0, #0x18'),
 ('rt_mutex_init_waiter','0xffffffc01037db04','str','x0, [x0]'),
 ('rt_mutex_init_waiter','0xffffffc01037db08','str','x8, [x0, #0x18]'),
 ('rt_mutex_init_waiter','0xffffffc01037db0c','str','xzr, [x0, #0x30]'),
 ('task_blocks_on_rt_mutex','0xffffffc01037dfe0','mov','x19, x0'),
 ('task_blocks_on_rt_mutex','0xffffffc01037dfec','mov','x20, x2'),
 ('task_blocks_on_rt_mutex','0xffffffc01037dff0','mov','x22, x1'),
 ('task_blocks_on_rt_mutex','0xffffffc01037dff8','stp','x20, x19, [x22, #0x30]'),
 ('task_blocks_on_rt_mutex','0xffffffc01037dffc','ldr','w8, [x20, #0x11c]'),
 ('task_blocks_on_rt_mutex','0xffffffc01037e004','str','w8, [x22, #0x40]'),
 ('task_blocks_on_rt_mutex','0xffffffc01037e008','ldr','x10, [x20, #0x488]'),
 ('task_blocks_on_rt_mutex','0xffffffc01037e00c','str','x10, [x22, #0x48]'),
 ('task_blocks_on_rt_mutex','0xffffffc01037e0c0','str','x22, [x20, #0x990]'),
 ('rt_mutex_adjust_prio_chain','0xffffffc01037d398','ldr','x25, [x19, #0x990]'),
 ('rt_mutex_adjust_prio_chain','0xffffffc01037d3b0','ldr','x8, [x25, #0x38]'),
 ('rt_mutex_adjust_prio_chain','0xffffffc01037d3f0','ldr','w9, [x25, #0x40]'),
 ('rt_mutex_adjust_prio_chain','0xffffffc01037d40c','ldr','x9, [x25, #0x48]'),
 ('remove_waiter','0xffffffc01037e384','mrs','x20, sp_el0'),
 ('remove_waiter','0xffffffc01037e3cc','str','xzr, [x20, #0x990]'),
]
FIELDS={
 'rt_mutex_waiter.task':{'offset':'0x30','evidence':'direct original task_blocks_on_rt_mutex stp of task and lock, plus init nullification'},
 'rt_mutex_waiter.lock':{'offset':'0x38','evidence':'direct original task_blocks_on_rt_mutex stp and lock dereference'},
 'rt_mutex_waiter.prio':{'offset':'0x40','evidence':'direct original task_blocks_on_rt_mutex priority assignment and readback'},
 'rt_mutex_waiter.deadline':{'offset':'0x48','evidence':'direct original task_blocks_on_rt_mutex deadline assignment and readback'},
}

def verify(binary,waiter_source,rtmutex_source):
 if binary.get('boot_sha256')!=BOOT_SHA or binary.get('kernel_image_sha256')!=KERNEL_SHA:
  raise ValueError('Original signed C431 kernel source provenance failed')
 if hashlib.sha256(waiter_source).hexdigest()!=WAITER_SRC_SHA:
  raise ValueError('HONOR waiter source revision mismatch')
 if hashlib.sha256(rtmutex_source).hexdigest()!=RTMUTEX_SRC_SHA:
  raise ValueError('HONOR rtmutex source revision mismatch')
 waiter=waiter_source.decode('utf-8')
 m=re.search(r'struct\s+rt_mutex_waiter\s*\{(.+?)\n\};',waiter,re.S)
 if not m:raise ValueError('Published waiter struct absent')
 body=m.group(1)
 fields=('tree_entry','pi_tree_entry','task;','lock;','prio;','deadline;')
 at=-1
 for field in fields:
  nxt=body.find(field,at+1)
  if nxt<0:raise ValueError('Missing or out-of-order waiter source field '+field)
  at=nxt
 source=rtmutex_source.decode('utf-8')
 init=re.search(r'void\s+rt_mutex_init_waiter\s*\([^)]*\)\s*\{(.+?)\n\}',source,re.S)
 if not init or 'waiter->task = NULL;' not in init.group(1):
  raise ValueError('Source waiter task initialization not shown')
 for original in ('waiter->task = task;', 'waiter->lock = lock;',
                  'waiter->prio = task->prio;', 'waiter->deadline = task->dl.deadline;'):
  if original not in source:raise ValueError('HONOR GPL task_blocks_on assignment missing: '+original)
 functions=binary.get('functions',{})
 for fn,addr,mnemonic,operand in CHECKS:
  f=functions.get(fn)
  if not isinstance(f,dict):raise ValueError('Original function absent '+fn)
  instructions=f.get('initial_instructions_for_register_flow',[])
  exact=[i for i in instructions if i.get('address')==addr]
  if len(exact)!=1 or (exact[0].get('mnemonic'),exact[0].get('operand'))!=(mnemonic,operand):
   raise ValueError('Original instruction mismatch '+addr+' '+fn)
 return {
  'schema_version':1,
  'source_boot_sha256':BOOT_SHA,'source_kernel_sha256':KERNEL_SHA,
  'honor_waiter_header_sha256':WAITER_SRC_SHA,
  'honor_rtmutex_c_sha256':RTMUTEX_SRC_SHA,
  'source_and_machine_code_assertions_passed':len(CHECKS),
  'validated_source_compatible_waiter_fields':FIELDS,
  'task_pi_lock_already_independently_verified':'0x96c',
  'task_pi_blocked_on_already_independently_verified':'0x990',
  'source_revision_is_exact_running_kernel':False,
  'kernel_phys_load_verified':False,
  'full_ghostlock_profile_ready':False,
  'root_exploit_demonstrated':False,
  'persistent_bootloader_unlock_demonstrated':False,
  'device_operations':0,
  'interpretation':'Source declarations and actual binary instruction flow agree on four waiter fields; this is partial ABI evidence, not a working GhostLock profile.'
 }

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--arm64-report',required=True,type=Path)
 p.add_argument('--source-waiter-header',required=True,type=Path)
 p.add_argument('--source-rtmutex-c',required=True,type=Path)
 p.add_argument('--out',required=True,type=Path)
 a=p.parse_args()
 result=verify(json.loads(a.arm64_report.read_text()),a.source_waiter_header.read_bytes(),a.source_rtmutex_c.read_bytes())
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,indent=2)+'\n')
 print('ORIGINAL_RETAIL_WAITER_FIELD_EVIDENCE',json.dumps(result['validated_source_compatible_waiter_fields']))
 print('C431_ARM64_AND_HONOR_SOURCE_ASSERTIONS',len(CHECKS))
 print('WORKING_EXPLOIT_READY',False)
