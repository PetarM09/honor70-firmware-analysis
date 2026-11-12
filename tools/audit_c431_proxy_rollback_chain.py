#!/usr/bin/env python3
"""SHA-pinned, read-only C431 proxy-lock rollback path inspection.

Compares original signed ARM64 machine instructions with HONOR Fennie GPL
source. DOES NOT run futex operations, trigger a UAF, or construct a payload.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

BOOT_SHA = '5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256'
KERNEL_SHA = 'bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece'
RTMUTEX_SHA = '70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9'
FUTEX_SHA = '71b9c7591dc611e6f92e742858bcc044cf01b605208058498e31d444b7704106'
SITES = {
 'rt_mutex_start_proxy_lock': [
  ('0xffffffc01037e2d0','mov','x21, x2'),
  ('0xffffffc01037e2d4','mov','x20, x1'),
  ('0xffffffc01037e2d8','mov','x19, x0'),
  ('0xffffffc01037e330','bl','#0xffffffc01037dfb4'),
  ('0xffffffc01037e334','mov','w21, w0'),
  ('0xffffffc01037e338','cbz','w0, #0xffffffc01037e304'),
  ('0xffffffc01037e2f8','mov','x0, x19'),
  ('0xffffffc01037e2fc','mov','x1, x20'),
  ('0xffffffc01037e300','bl','#0xffffffc01037e350')
 ],
 'remove_waiter': [
  ('0xffffffc01037e36c','mov','x23, x1'),
  ('0xffffffc01037e384','mrs','x20, sp_el0'),
  ('0xffffffc01037e388','add','x21, x20, #0x96c'),
  ('0xffffffc01037e3cc','str','xzr, [x20, #0x990]')
 ],
 'task_blocks_on_rt_mutex': [
  ('0xffffffc01037dfe0','mov','x19, x0'),
  ('0xffffffc01037dfec','mov','x20, x2'),
  ('0xffffffc01037dff0','mov','x22, x1'),
  ('0xffffffc01037dff8','stp','x20, x19, [x22, #0x30]'),
  ('0xffffffc01037e0c0','str','x22, [x20, #0x990]')
 ]
}
def function_body(source, signature):
    source = re.sub(r'/\*.*?\*/|//[^\n]*','',source,flags=re.S)
    match=re.search(signature,source)
    if not match: raise ValueError('Missing GPL function '+signature)
    brace=source.find('{',match.end())
    if brace<0: raise ValueError('Function missing opening brace '+signature)
    depth=1
    for i in range(brace+1,len(source)):
        if source[i]=='{':depth+=1
        elif source[i]=='}':
            depth-=1
            if depth==0:return source[brace+1:i]
    raise ValueError('Unbalanced GPL function '+signature)

def check_source(futex,rtmutex):
    f,r=futex.decode('utf-8'),rtmutex.decode('utf-8')
    dispatch=function_body(f,r'\blong\s+do_futex\s*\(')
    if not re.search(r'case\s+FUTEX_CMP_REQUEUE_PI\s*:\s*return\s+futex_requeue\s*\(\s*uaddr\s*,\s*flags\s*,\s*uaddr2\s*,\s*val\s*,\s*val2\s*,\s*&val3\s*,\s*1\s*\)',dispatch):
        raise ValueError('PI requeue dispatcher edge missing')
    requeue=function_body(f,r'\bstatic\s+int\s+futex_requeue\s*\(')
    patterns=[
      r'if\s*\(\s*uaddr1\s*==\s*uaddr2\s*\)',
      r'if\s*\(\s*\(requeue_pi\s*&&\s*!this->rt_waiter\s*\)',
      r'get_pi_state\s*\(pi_state\s*\)',
      r'rt_mutex_start_proxy_lock\s*\(\s*&pi_state->pi_mutex\s*,\s*this->rt_waiter\s*,\s*this->task\s*\)',
      r'if\s*\(ret\s*==\s*1\)',
      r'else\s+if\s*\(ret\)'
    ]
    positions=[]
    for pattern in patterns:
        found=re.search(pattern,requeue,re.S)
        if not found:raise ValueError('Required requeue branch absent '+pattern)
        positions.append(found.start())
    if positions!=sorted(positions):raise ValueError('Requeue source ordering changed')
    wrapper=function_body(r,r'\bint\s+rt_mutex_start_proxy_lock\s*\(')
    if not re.search(r'ret\s*=\s*__rt_mutex_start_proxy_lock\s*\(\s*lock\s*,\s*waiter\s*,\s*task\s*\)',wrapper):
        raise ValueError('Missing proxy delegation')
    if not re.search(r'if\s*\(\s*unlikely\s*\(ret\)\s*\)\s*remove_waiter\s*\(\s*lock\s*,\s*waiter\s*\)',wrapper):
        raise ValueError('Missing nonzero result rollback')
    remove=function_body(r,r'\bstatic\s+void\s+remove_waiter\s*\(')
    if not re.search(r'raw_spin_lock\s*\(\s*&current->pi_lock\s*\)\s*;\s*rt_mutex_dequeue\s*\(lock\s*,\s*waiter\s*\)\s*;\s*current->pi_blocked_on\s*=\s*NULL',remove):
        raise ValueError('Wrong-task cleanup pattern not present')
    return True

def verify(report,futex,rtmutex,*,futex_sha=FUTEX_SHA,rtmutex_sha=RTMUTEX_SHA):
    if (report.get('boot_sha256'),report.get('kernel_image_sha256'))!=(BOOT_SHA,KERNEL_SHA):
        raise ValueError('Retail C431 binary provenance mismatch')
    if hashlib.sha256(futex).hexdigest()!=futex_sha or hashlib.sha256(rtmutex).hexdigest()!=rtmutex_sha:
        raise ValueError('HONOR GPL source digest mismatch')
    check_source(futex,rtmutex)
    n=0
    for name,checks in SITES.items():
        f=report.get('functions',{}).get(name,{})
        by_addr={}
        for ins in f.get('initial_instructions_for_register_flow',[]):
            by_addr.setdefault(ins.get('address'),[]).append(ins)
        for addr,op,operand in checks:
            hits=by_addr.get(addr,[])
            if len(hits)!=1:raise ValueError('Original instruction missing/ambiguous '+name+' '+addr)
            i=hits[0]
            if (i.get('mnemonic'),i.get('operand'))!=(op,operand):
                raise ValueError('Incorrect original instruction '+name+' '+addr)
            if not re.fullmatch('[0-9a-f]{8}',i.get('bytes','')):
                raise ValueError('Original instruction bytes missing '+addr)
            n+=1
    return {
      'schema_version':1,'target':'FNE-NX9 C431 signed Linux 5.4.295',
      'boot_sha256':BOOT_SHA,'kernel_sha256':KERNEL_SHA,
      'fennie_gpl_base':'Linux 5.4.242, not exact retail 5.4.295',
      'futex_gpl_sha256':futex_sha,'rtmutex_gpl_sha256':rtmutex_sha,
      'original_arm64_assertions':n,
      'source_dispatch_cmp_requeue_pi_to_futex_requeue':True,
      'source_futex_requeue_to_proxy_lock_with_other_task':True,
      'source_proxy_nonzero_return_to_remove_waiter':True,
      'original_binary_proxy_wrapper_to_remove_waiter':True,
      'original_binary_remove_waiter_uses_current':True,
      'original_binary_direct_futex_requeue_proxy_call':'pending_direct_caller_audit',
      'owner_photographed_invalid_cmp_requeue_pi_einval':True,
      'queue_processing_or_rollback_executed_on_phone':False,
      'uaf_or_root_or_unlock_demonstrated':False,'device_operations':0
    }

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--arm64-report',type=Path,required=True)
    p.add_argument('--fennie-futex',type=Path,required=True)
    p.add_argument('--fennie-rtmutex',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    result=verify(json.loads(a.arm64_report.read_text()),a.fennie_futex.read_bytes(),a.fennie_rtmutex.read_bytes())
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print('STOCK_C431_ARM64_ASSERTIONS',result['original_arm64_assertions'])
    print('PROXY_ROLLBACK_WRONG_CURRENT_CONFIRMED',True)
    print('EXECUTED_UAF_OR_ROOT',False)
