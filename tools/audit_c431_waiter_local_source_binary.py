#!/usr/bin/env python3
"""Read-only SHA-verified original C431 futex local-stack evidence scanner.

Reports call sites and syntactic stack references. Does NOT identify a
kernel waiter slot, infer stack overlap, execute a futex, or build an exploit.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

BOOT_SHA='5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256'
IMAGE_SHA='bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece'
FUTEX_SOURCE_SHA='71b9c7591dc611e6f92e742858bcc044cf01b605208058498e31d444b7704106'
EXPECTED={
 'do_futex':0xffffffc0103c84e4,
 'core_sys_select':0xffffffc010562afc,
 '__arm64_sys_pselect6':0xffffffc0105638fc,
}
MAX_FUNCTION=0x8000
SYM=re.compile(r'^([0-9a-fA-F]{8,16})\s+([TtWw])\s+(\S+)$')
DIRECT=re.compile(r'^#(0x[0-9a-f]+)$')
SP_REF=re.compile(r'\[sp(?:,\s*#(-?(?:0x[0-9a-f]+|\d+)))?\]')
LEA_SP=re.compile(r'^([wx]\d+),\s*sp,\s*#(0x[0-9a-f]+|\d+)$')

def parse_nm(content):
    results=[]
    for line in content.splitlines():
        m=SYM.fullmatch(line.strip())
        if not m:continue
        va,kind,name=m.groups()
        if '.cfi_jt' in name or name.startswith('__cfi_'):continue
        results.append((int(va,16),name.split('$',1)[0]))
    return sorted(set(results))

def bounds(name,symbols):
    expected=EXPECTED[name]
    found={va for va,n in symbols if n==name}
    if found!={expected}:
        raise ValueError('Wrong or ambiguous exact C431 '+name+' address')
    end=min((va for va,_ in symbols if va>expected),default=None)
    if end is None or not 0<end-expected<=MAX_FUNCTION:
        raise ValueError('Missing or oversized exact function boundary for '+name)
    return expected,end

def source_preflight(source):
    content=source.decode('utf-8')
    signature=re.search(r'\bstatic\s+int\s+futex_wait_requeue_pi\s*\(',content)
    if not signature:raise ValueError('Published HONOR wait-requeue source missing')
    tail=content[signature.end():]
    markers=(
        'struct rt_mutex_waiter rt_waiter;',
        'struct futex_q q = futex_q_init;',
        'rt_mutex_init_waiter(&rt_waiter);',
        'q.rt_waiter = &rt_waiter;',
        'ret = futex_wait_setup(',
        'futex_wait_queue_me(hb, &q, to);',
    )
    positions=[tail.find(s) for s in markers]
    if min(positions)<0 or positions!=sorted(positions):
        raise ValueError('Published HONOR waiter setup source sequence altered')
    return {'source_markers':list(markers),
            'source_waiter_allocated_on_kernel_stack':True,
            'source_is_not_exact_original_C431':True}

def inspect_instructions(function_name,instructions,all_symbols):
    syms={}
    for addr,name in all_symbols:syms.setdefault(addr,[]).append(name)
    calls=[]
    sp_direct=[]
    sp_addresses=[]
    for i,ins in enumerate(instructions):
        op=ins['mnemonic'];operand=ins['operand']
        if op=='bl':
            target=DIRECT.fullmatch(operand)
            if target:
                dst=int(target.group(1),16)
                calls.append({
                  'at':ins['address'],'target_va':hex(dst),
                  'symbols':sorted(syms.get(dst,[])),
                  'preceding_instructions':instructions[max(0,i-5):i],
                })
        if '[sp' in operand:
            m=SP_REF.search(operand)
            if m and len(sp_direct)<200:
                sp_direct.append({'at':ins['address'],'mnemonic':op,
                                  'operand':operand,'base':'sp',
                                  'raw_offset':m.group(1) if m.group(1) is not None else '0'})
        if op=='add':
            a=LEA_SP.fullmatch(operand)
            if a and len(sp_addresses)<100:
                sp_addresses.append({'at':ins['address'],'register':a.group(1),
                                     'raw_offset':a.group(2),
                                     'surrounding':instructions[max(0,i-2):min(len(instructions),i+4)]})
    return {
      'name':function_name,
      'decoded_instruction_count':len(instructions),
      'prologue_instructions':instructions[:32],
      'direct_bl_count':len(calls),
      'direct_calls':calls,
      'direct_sp_reference_samples':sp_direct,
      'sp_address_computation_samples':sp_addresses,
      'sp_references_truncated':len([i for i in instructions if '[sp' in i['operand']])>200,
      'local_object_identity_verified':False,
      'instruction_count_is_not_a_stack_layout_proof':True,
    }

def scan_elf(path,symbols):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    from elftools.elf.elffile import ELFFile
    with path.open('rb') as f:
        obj=ELFFile(f)
        segments=[s for s in obj.iter_segments() if s['p_type']=='PT_LOAD' and int(s['p_flags'])&1]
        md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
        result={}
        for name in EXPECTED:
            start,end=bounds(name,symbols)
            valid=[s for s in segments if int(s['p_vaddr'])<=start and
                   end<=int(s['p_vaddr'])+int(s['p_filesz'])]
            if len(valid)!=1:raise ValueError('Cannot locate unique original executable function '+name)
            seg=valid[0]
            f.seek(int(seg['p_offset'])+start-int(seg['p_vaddr']))
            data=f.read(end-start)
            ins=[{'address':hex(i.address),'mnemonic':i.mnemonic,'operand':i.op_str,
                  'bytes':i.bytes.hex()} for i in md.disasm(data,start)]
            if len(ins)*4!=len(data):raise ValueError('C431 function disassembly incomplete '+name)
            result[name]=inspect_instructions(name,ins,symbols)
            result[name]['original_function_va']=hex(start)
            result[name]['original_function_byte_size']=len(data)
            result[name]['original_function_sha256']=hashlib.sha256(data).hexdigest()
        return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('boot','kernel','elf','fennie_futex','out'):
        p.add_argument('--'+name.replace('_','-'),required=True,type=Path)
    a=p.parse_args()
    for path,sha in ((a.boot,BOOT_SHA),(a.kernel,IMAGE_SHA),(a.fennie_futex,FUTEX_SOURCE_SHA)):
        if hashlib.sha256(path.read_bytes()).hexdigest()!=sha:
            raise SystemExit('REQUIRED_VERIFIED_ORIGINAL_INPUT_SHA256_MISMATCH')
    source=source_preflight(a.fennie_futex.read_bytes())
    nm=subprocess.run(['nm','-n','--defined-only',str(a.elf)],
                      check=True,capture_output=True,text=True).stdout
    symbols=parse_nm(nm)
    funcs=scan_elf(a.elf,symbols)
    result={
      'schema_version':1,'source':'original signed C431 Image + Fennie reference',
      'original_boot_sha256':BOOT_SHA,'original_image_sha256':IMAGE_SHA,
      'fennie_futex_sha256':FUTEX_SOURCE_SHA,'source_preflight':source,
      'functions':funcs,
      'futex_waiter_inlining_confirmed':False,
      'exact_c431_waiter_stack_slot_confirmed':False,
      'pselect_overlay_proven':False,
      'working_ghostlock_root_proven':False,
      'device_operations':0,
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    for name,info in funcs.items():
        print('ORIGINAL_FUNC',name,'CALLS',info['direct_bl_count'],
              'SP_REFS',len(info['direct_sp_reference_samples']),
              'SP_LEAS',len(info['sp_address_computation_samples']))
        for call in info['direct_calls']:
            if any(term in n for n in call['symbols'] for term in
                   ('futex','rt_mutex','hrtimer','wake_q','get_fd_set','set_fd_set')):
                print('ORIGINAL_CALL',name,call['at'],call['symbols'])
    print('NOT_A_GHOSTLOCK_ROOT_OR_STACK_OVERLAP_PROOF')
if __name__=='__main__':main()
