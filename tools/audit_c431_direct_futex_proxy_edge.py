#!/usr/bin/env python3
"""Original SHA-verified C431 futex_requeue -> proxy-lock direct BL site audit.

Read-only stock ARM64 ELF disassembly. Does not call futex, modify the phone,
infer kernel physical geometry, or create any GhostLock exploit payload.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path

BOOT_SHA='5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256'
IMAGE_SHA='bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece'
SOURCE_EXPECTED=0xffffffc0103ca4d8
PROXY_EXPECTED=0xffffffc01037e2c0
REMOVE_EXPECTED=0xffffffc01037e350
MAX_BYTES=0x10000

def parse_text_symbols(output):
    result=[]
    for line in output.splitlines():
        m=re.fullmatch(r'([0-9a-fA-F]{8,16})\s+([Tt])\s+(\S+)',line.strip())
        if not m:continue
        addr,kind,name=m.groups()
        if name.startswith('__cfi_') or '.cfi_jt' in name:continue
        result.append((int(addr,16),name))
    return sorted(set(result))

def scan_symbol_bounds(symbols):
    expected={'futex_requeue':SOURCE_EXPECTED,
              'rt_mutex_start_proxy_lock':PROXY_EXPECTED,
              'remove_waiter':REMOVE_EXPECTED}
    for name,addr in expected.items():
        values={v for v,n in symbols if n.split('$',1)[0]==name}
        if values!={addr}:raise ValueError('Exact-stock symbol identity mismatch '+name)
    nearest=min((v for v,n in symbols if v>SOURCE_EXPECTED),default=None)
    if nearest is None:raise ValueError('Next futex function symbol absent')
    size=nearest-SOURCE_EXPECTED
    if size<=0:raise ValueError('Invalid original function bound')
    return SOURCE_EXPECTED,nearest,min(size,MAX_BYTES),size<=MAX_BYTES

def summarize_disassembly(instructions):
    calls=[]
    for i,item in enumerate(instructions):
        if item['mnemonic']=='bl' and item['operand']=='#'+hex(PROXY_EXPECTED):
            calls.append({
              'site':item['address'],'mnemonic':'bl',
              'callee':'rt_mutex_start_proxy_lock',
              'before':instructions[max(0,i-7):i],
              'after':instructions[i+1:i+4]})
    return calls

def analyze(elf,nm_output):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    from elftools.elf.elffile import ELFFile
    symbols=parse_text_symbols(nm_output)
    start,end,size,complete=scan_symbol_bounds(symbols)
    with elf.open('rb') as f:
        obj=ELFFile(f)
        segs=[s for s in obj.iter_segments()
              if s['p_type']=='PT_LOAD' and int(s['p_flags'])&1
              and int(s['p_vaddr'])<=start<int(s['p_vaddr'])+int(s['p_filesz'])]
        if len(segs)!=1:raise ValueError('Expected exactly one executable segment')
        seg=segs[0]
        relative=start-int(seg['p_vaddr'])
        size=min(size,int(seg['p_filesz'])-relative)
        if size<=0:raise ValueError('Invalid code region')
        f.seek(int(seg['p_offset'])+relative)
        code=f.read(size)
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    instructions=[{'address':hex(i.address),'mnemonic':i.mnemonic,
                   'operand':i.op_str,'bytes':i.bytes.hex()}
                  for i in md.disasm(code,start)]
    if not instructions or instructions[0]['address']!=hex(start):
        raise ValueError('C431 ARM64 disassembly not anchored')
    if len(instructions)*4!=len(code):
        raise ValueError('Original ARM64 function not completely decoded')
    calls=summarize_disassembly(instructions)
    return {
      'schema_version':1,
      'target':'signed stock FNE-NX9 C431 MagicOS8 5.4.295',
      'boot_sha256':BOOT_SHA,'kernel_sha256':IMAGE_SHA,
      'futex_requeue_va':hex(start),
      'next_text_symbol_va':hex(end),
      'byte_count':len(code),
      'exact_function_code_sha256':hashlib.sha256(code).hexdigest(),
      'complete_to_next_text_symbol':complete and len(code)==end-start,
      'independent_proxy_function_va':hex(PROXY_EXPECTED),
      'direct_call_sites':calls,'direct_call_count':len(calls),
      'direct_call_verified':bool(calls),
      'no_direct_call_does_not_prove_no_reachable_proxy':True,
      'kernel_physical_address_not_derived':True,
      'ghostlock_runtime_trigger_tested':False,
      'root_or_unlock_demonstrated':False,
      'device_operations':0
    }

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--boot',type=Path,required=True)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--elf',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    for file,sha in ((a.boot,BOOT_SHA),(a.kernel,IMAGE_SHA)):
        if hashlib.sha256(file.read_bytes()).hexdigest()!=sha:
            raise SystemExit('STOCK_FIRMWARE_DIGEST_MISMATCH')
    nm=subprocess.run(['nm','-n','--defined-only',str(a.elf)],
                      check=True,capture_output=True,text=True).stdout
    result=analyze(a.elf,nm)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print('ORIGINAL_C431_FUTEX_FUNCTION_BYTES',result['byte_count'])
    print('ORIGINAL_C431_DIRECT_PROXY_CALLS',result['direct_call_count'])
    print('FULL_FUNCTION_BOUNDED',result['complete_to_next_text_symbol'])
    for site in result['direct_call_sites']:
        print('ORIGINAL_C431_DIRECT_PROXY_BL',site['site'])
    print('NO_ROOT_OR_UAF_EXECUTED')
