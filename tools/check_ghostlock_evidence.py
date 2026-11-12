#!/usr/bin/env python3
"""Fail-closed, read-only grading of exact-stock ARM64 proxy rollback evidence."""
import argparse,hashlib,json
from pathlib import Path

BOOT_SHA='5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256'
KERNEL_SHA='bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece'
PREDICATES={
 '0xffffffc01037e2f0':'cbz w0, #0xffffffc01037e320',
 '0xffffffc01037e2f4':'mov w21, #1',
 '0xffffffc01037e2f8':'mov x0, x19',
 '0xffffffc01037e2fc':'mov x1, x20',
 '0xffffffc01037e338':'cbz w0, #0xffffffc01037e304',
 '0xffffffc01037e33c':'ldr x8, [x19, #0x18]',
 '0xffffffc01037e340':'cmp x8, #2',
 '0xffffffc01037e344':'b.hs #0xffffffc01037e2f8',
}
def grade(report):
 errors=[]
 def need(test,message):
  if not test:errors.append(message)
 need(isinstance(report,dict),'report is not an object')
 if not isinstance(report,dict):return {'verified_static_evidence':False,'errors':errors}
 need(report.get('stock_boot_sha256')==BOOT_SHA,'wrong stock boot SHA')
 need(report.get('extracted_kernel_sha256')==KERNEL_SHA,'wrong kernel SHA')
 need(report.get('signed_original_proxy_rollback_direct_call_validated') is True,'direct call not validated')
 need(report.get('signed_original_remove_waiter_current_use_validated') is True,'current-task use not validated')
 need(report.get('current_task_pi_blocked_on_clear_machine_code')=='str xzr, [x20, #0x990]','wrong PI clear')
 need(report.get('device_operations')==0,'device operations must be zero')
 need(report.get('byte_verified_rollback_predicates')==PREDICATES,'eight exact predicates mismatch')
 funcs=report.get('orig_signed_functions')
 need(isinstance(funcs,dict),'missing disassembly')
 if isinstance(funcs,dict):
  expected_functions={'rt_mutex_start_proxy_lock':'0xffffffc01037e2c0',
                      'remove_waiter':'0xffffffc01037e350'}
  instructions={}
  for name,addr in expected_functions.items():
   fn=funcs.get(name)
   valid=(isinstance(fn,dict) and fn.get('vaddr')==addr and
          isinstance(fn.get('instructions'),list) and len(fn['instructions'])>0)
   need(valid,'missing or incorrect disassembly '+name)
   if not valid:continue
   for ins in fn['instructions']:
    if not isinstance(ins,dict):errors.append('malformed instruction '+name);continue
    try:
     address=int(ins['addr'],16)
     mnemonic=ins['mnemonic']
     op_str=ins['op_str']
     if not isinstance(mnemonic,str) or not isinstance(op_str,str):
      raise TypeError('instruction not text')
     if address in instructions:errors.append('duplicate address '+hex(address))
     instructions[address]=(mnemonic,op_str,name)
    except (KeyError,ValueError,TypeError):
     errors.append('invalid instruction format '+name)
  for addr,source in PREDICATES.items():
   mnemonic,operand=source.split(' ',1)
   actual=instructions.get(int(addr,16))
   need(actual is not None and actual[:2]==(mnemonic,operand)
        and actual[2]=='rt_mutex_start_proxy_lock',
        'disassembly instruction mismatch '+addr)
  need(instructions.get(0xffffffc01037e300)==
       ('bl','#0xffffffc01037e350','rt_mutex_start_proxy_lock') or
       instructions.get(0xffffffc01037e300)==
       ('bl','0xffffffc01037e350','rt_mutex_start_proxy_lock'),
       'remove_waiter call instruction mismatch')
  current=instructions.get(0xffffffc01037e384)
  need(current is not None and current[0]=='mrs' and current[1].strip()=='x20, sp_el0'
       and current[2]=='remove_waiter','current task read instruction mismatch')
  clear=instructions.get(0xffffffc01037e3cc)
  need(clear is not None and clear[:2]==('str','xzr, [x20, #0x990]')
       and clear[2]=='remove_waiter','current PI clear instruction mismatch')

 return {
  'schema_version':1,
  'input_sha256':hashlib.sha256(json.dumps(report,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
  'verified_static_evidence':not errors,
  'evidence':{
   'signed_original_instruction_pattern':'supported' if not errors else 'invalid',
   'whole_kernel_call_graph':'not_evaluated_by_this_validator',
   'unprivileged_userspace_trigger':'not_established',
   'reliable_privilege_escalation':'not_established',
   'qsee_keymaster_rpmb_secure_state_change':'not_established',
   'persistent_bootloader_unlock':'not_established'
  },
  'errors':errors,'device_operations':0
 }
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('report',type=Path)
 p.add_argument('--out',type=Path)
 a=p.parse_args()
 try:result=grade(json.loads(a.report.read_text(encoding='utf-8')))
 except (OSError,ValueError,UnicodeError) as e:result={'verified_static_evidence':False,'errors':['invalid input: '+str(e)],'device_operations':0}
 payload=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
 if a.out:
  a.out.parent.mkdir(parents=True,exist_ok=True)
  a.out.write_text(payload,encoding='utf-8')
 print(payload,end='')
 raise SystemExit(0 if result['verified_static_evidence'] else 1)
if __name__=='__main__':main()
