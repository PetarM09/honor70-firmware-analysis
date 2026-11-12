#!/usr/bin/env python3
"""Read-only, SHA-pinned C431 ARM64 futex/select function map.

Does not infer stack overlap, physical addresses, exploit feasibility,
or generate a UAF/root payload. Missing symbols may simply be inlined.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path

BOOT_SHA='5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256'
KERNEL_SHA='bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece'
MAX_WINDOW=32768
WATCHED=(
 '__arm64_sys_futex','__se_sys_futex','do_futex',
 'futex_wait_requeue_pi','futex_requeue','rt_mutex_start_proxy_lock',
 '__arm64_sys_pselect6','__se_sys_pselect6',
 'core_sys_select','do_pselect','get_fd_set','set_fd_set'
)
PATTERN=re.compile(r'^([0-9a-fA-F]{8,16})\s+([TtWw])\s+(\S+)$')
CALL_TARGET=re.compile(r'^#(0x[0-9a-fA-F]+)$')

def parse_nm(output):
 result=[]
 for line in output.splitlines():
  m=PATTERN.fullmatch(line.strip())
  if not m:continue
  addr,kind,name=m.groups()
  if name.startswith('__cfi_') or '.cfi_jt' in name:continue
  result.append((int(addr,16),name.split('$',1)[0]))
 return sorted(set(result))

def bounds_for(name,symbols):
 addresses={v for v,n in symbols if n==name}
 if not addresses:return {'status':'missing'}
 if len(addresses)>1:return {'status':'ambiguous','count':len(addresses)}
 start=next(iter(addresses))
 greater=[addr for addr,n in symbols if addr>start]
 if not greater:return {'status':'missing_end_boundary','address':hex(start)}
 end=min(greater)
 cap=min(end-start,MAX_WINDOW)
 if cap<=0:return {'status':'invalid_bounds'}
 return {'status':'present','start':start,'end':end,'scan_size':cap,
         'complete':end-start<=MAX_WINDOW}

def find_call_targets(instructions,watched_addresses):
 direct=[]
 for inst in instructions:
  if inst.mnemonic not in ('bl','b'):continue
  m=CALL_TARGET.fullmatch(inst.op_str)
  if not m:continue
  dest=int(m.group(1),16)
  matches=watched_addresses.get(dest,())
  if matches:
   direct.append({'at':hex(inst.address),'opcode':inst.mnemonic,
                  'callee_names':list(matches),'target_va':hex(dest)})
 return direct

def summarize(symbols,sections):
 found={name:bounds_for(name,symbols) for name in WATCHED}
 addresses={}
 for name,item in found.items():
  if item['status']=='present':addresses.setdefault(item['start'],[]).append(name)
 results={}
 for name,item in found.items():
  profile={k:(hex(v) if k in ('start','end') and isinstance(v,int) else v)
           for k,v in item.items()}
  if item['status']=='present':
   instructions=sections.get(name,[])
   profile['decoded_instructions']=len(instructions)
   profile['direct_calls_to_watched_functions']=find_call_targets(instructions,addresses)
   profile['entry_stack_adjustments']=[
    {'at':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
    for i in instructions[:24]
    if 'sp' in i.op_str and i.mnemonic in ('sub','add','stp','ldp')
   ]
   profile['symbol_code_complete']=bool(item['complete'] and
                                        len(instructions)*4==item['scan_size'])
  results[name]=profile
 edges=[]
 for name,profile in results.items():
  for call in profile.get('direct_calls_to_watched_functions',[]):
   edges.append({'caller':name,**call})
 return {'function_profiles':results,'direct_watched_edges':edges,
         'function_count_present':sum(1 for x in results.values() if x['status']=='present'),
         'function_count_missing':sum(1 for x in results.values() if x['status']=='missing'),
         'missing_symbols_do_not_prove_inlining_or_infeasibility':True,
         'absence_of_direct_bl_does_not_prove_absence_of_inlined_path':True,
         'stack_overlay_feasibility':'not established',
         'kernel_physical_load':'not established',
         'root_or_bootloader_unlock':'not demonstrated','device_operations':0}

def scan_elf(path,symbols):
 from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
 from elftools.elf.elffile import ELFFile
 with path.open('rb') as fh:
  elf=ELFFile(fh)
  segments=[(int(s['p_vaddr']),int(s['p_offset']),int(s['p_filesz']))
            for s in elf.iter_segments()
            if s['p_type']=='PT_LOAD' and int(s['p_flags'])&1]
  md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
  output={}
  for name in WATCHED:
   profile=bounds_for(name,symbols)
   if profile['status']!='present':continue
   start,size=profile['start'],profile['scan_size']
   valid=[(va,off,fs) for va,off,fs in segments
          if va<=start and start+size<=va+fs]
   if len(valid)!=1:continue
   va,off,fs=valid[0]
   fh.seek(off+start-va)
   output[name]=list(md.disasm(fh.read(size),start))
  return output

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('boot','kernel','elf','out'):
  p.add_argument('--'+name,required=True,type=Path)
 a=p.parse_args()
 for path,sha in ((a.boot,BOOT_SHA),(a.kernel,KERNEL_SHA)):
  if hashlib.sha256(path.read_bytes()).hexdigest()!=sha:
   raise SystemExit('EXACT_C431_SIGNED_IMAGE_DIGEST_MISMATCH')
 nm=subprocess.run(['nm','-n','--defined-only',str(a.elf)],
                   check=True,capture_output=True,text=True).stdout
 symbols=parse_nm(nm)
 report=summarize(symbols,scan_elf(a.elf,symbols))
 report.update(schema_version=1,boot_sha256=BOOT_SHA,kernel_sha256=KERNEL_SHA,
               origin='Exact retail FNE-NX9 C431 signed Linux 5.4.295',
               external_input_paths_recorded=False)
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(report,indent=2)+'\n')
 print('PRESENT_FUNCTIONS',report['function_count_present'])
 print('DIRECT_WATCHED_EDGES',len(report['direct_watched_edges']))
 for edge in report['direct_watched_edges']:
  print('EDGE',edge['caller'],edge['at'],'->',','.join(edge['callee_names']))
 for name,info in report['function_profiles'].items():
  print('FUNCTION',name,info['status'])
 print('STACK_OVERLAY_PROVEN',False)
if __name__=='__main__':main()
