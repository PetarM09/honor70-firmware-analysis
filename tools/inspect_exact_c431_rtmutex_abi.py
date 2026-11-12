#!/usr/bin/env python3
"""Audit exact signed FNE-NX9 C431 rtmutex ARM64 memory instructions.

Read-only; emits disassembly evidence, not a working GhostLock offset profile.
Does not derive physical kernel addresses or perform any handset operations.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from elftools.elf.elffile import ELFFile

BOOT_SHA='5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256'
IMAGE_SHA='bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece'
EXPECTED_REMOVE_WAITER=0xffffffc01037e350
FUNCS={
 'remove_waiter':0x250,
 'rt_mutex_start_proxy_lock':0x180,
 'rt_mutex_cleanup_proxy_lock':0x200,
 'rt_mutex_init_waiter':0x100,
 'rt_mutex_adjust_prio_chain':0x700,
 'rt_mutex_enqueue':0x200,
 'rt_mutex_dequeue':0x200,
 'rt_mutex_top_waiter':0x140,
 'futex_requeue':0x350
}
def parse_symbols(stdout):
 result={name:set() for name in FUNCS}
 for line in stdout.splitlines():
  m=re.fullmatch(r'([0-9a-fA-F]+)\s+([Tt])\s+(\S+)',line.strip())
  if not m:continue
  name=m.group(3)
  if '.cfi_jt' in name or name.startswith('__cfi_'):continue
  base=name.split('$',1)[0]
  if base in result:result[base].add(int(m.group(1),16))
 return result

def inspect(elf,symbols):
 if symbols['remove_waiter']!={EXPECTED_REMOVE_WAITER}:
  raise ValueError('Original C431 remove_waiter kallsyms anchor mismatch')
 md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
 segments=[(int(s['p_vaddr']),int(s['p_offset']),int(s['p_filesz']))
           for s in elf.iter_segments()
           if s['p_type']=='PT_LOAD' and int(s['p_flags'])&1]
 report={'schema_version':1,'functions':{},'missing':[],'ambiguous':[],
         'device_operations':0,'struct_field_offsets_verified':False,
         'usable_kernel_geometry_generated':False,
         'functional_root_exploit_proven':False,
         'persistent_unlock_proven':False}
 for name,window in FUNCS.items():
  addrs=symbols[name]
  if not addrs:report['missing'].append(name);continue
  if len(addrs)>1:report['ambiguous'].append(name);continue
  addr=next(iter(addrs))
  seg=next((s for s in segments if s[0]<=addr<s[0]+s[2]),None)
  if seg is None:report['missing'].append(name);continue
  elf.stream.seek(seg[1]+addr-seg[0])
  data=elf.stream.read(min(window,seg[2]-(addr-seg[0])))
  ins=[{'address':hex(i.address),'bytes':i.bytes.hex(),
        'mnemonic':i.mnemonic,'operand':i.op_str} for i in md.disasm(data,addr)]
  filtered=[i for i in ins if '[' in i['operand'] or i['mnemonic']=='bl'
            or 'sp_el0' in i['operand']]
  report['functions'][name]={
   'symbol_va':hex(addr),'byte_window':len(data),
   'window_sha256':hashlib.sha256(data).hexdigest(),
   'contains_possible_next_function':True,
   'initial_instructions_for_register_flow':ins[:180],
   'selected_source_machine_instructions':filtered
  }
 orig=report['functions']['remove_waiter']['selected_source_machine_instructions']
 if not any(x['address']==hex(0xffffffc01037e384) and x['mnemonic']=='mrs'
            and 'sp_el0' in x['operand'] for x in orig):
  raise ValueError('Exact retail C431 current read missing')
 if not any(x['address']==hex(0xffffffc01037e3cc) and x['mnemonic']=='str'
            and '[x20, #0x990]' in x['operand'] for x in orig):
  raise ValueError('Exact retail C431 current pi_blocked_on clear missing')
 report['anchored_original_current_clear_verified']=True
 report['inference_limit']='ARM64 memory instructions are displayed unclassified; register flow, field identity, and reliable exploitation require independent proof.'
 return report

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('boot','kernel','elf','out'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args()
 for path,expected in ((a.boot,BOOT_SHA),(a.kernel,IMAGE_SHA)):
  if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
   raise ValueError('Signed exact-stock C431 SHA256 mismatch')
 nm=subprocess.run(['nm','-n','--defined-only',str(a.elf)],
                   check=True,capture_output=True,text=True).stdout
 with a.elf.open('rb') as f:
  result=inspect(ELFFile(f),parse_symbols(nm))
 result['source']='Signed stock FNE-NX9 C431 MagicOS8.0.0.290'
 result['boot_sha256']=BOOT_SHA
 result['kernel_image_sha256']=IMAGE_SHA
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,indent=2)+'\n')
 print('ORIGINAL_C431_ANALYZED_FUNCTIONS',len(result['functions']))
 print('MISSING',result['missing'])
 print('AMBIGUOUS',result['ambiguous'])
 for name,func in result['functions'].items():
  print('FUNCTION',name,func['symbol_va'],
        'relevant_machine_instructions',len(func['selected_source_machine_instructions']))
  for i in func['selected_source_machine_instructions'][:45]:
   print('   ',i['address'],i['mnemonic'],i['operand'])
 print('NO_EXPLOIT_EXECUTED_OR_GENERATED')
if __name__=='__main__':main()
