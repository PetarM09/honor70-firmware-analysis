#!/usr/bin/env python3
"""Offline, read-only devinfo backup inspector for FNE-NX9.

NO device access or writes. Does not generate unlock images.
Avoid publicly sharing raw partition images or full hex dumps.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

MAGIC=b'ANDROID-BOOT!'


def sha256(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('backup',type=Path,help='EDL backup of devinfo partition')
    p.add_argument('--output',type=Path,default=Path('HONOR70_DEVINFO_STRUCTURE_ONLY.json'))
    args=p.parse_args()
    b=args.backup.expanduser().read_bytes()
    if not b:raise SystemExit('Backup is empty')
    hits=[]
    st=0
    while len(hits)<20:
        idx=b.find(MAGIC,st)
        if idx<0:break
        hits.append(idx);st=idx+1
    out={'partition':'devinfo','size':len(b),'sha256':sha256(args.backup.expanduser()),
      'magic_ascii':'ANDROID-BOOT!', 'magic_offsets':hits,
      'magic_at_partition_start': b.startswith(MAGIC),
      'note':'These are possible layouts only. No assertion that ABL is using this partition as its secure device-state backend.'}
    if b.startswith(MAGIC) and len(b)>=64:
        out['possible_packed13_flags']={'offset_0xd':b[0xd],'offset_0xe':b[0xe]}
        out['possible_aligned_flags']={'offset_0x10':b[0x10],'offset_0x18':b[0x18]}
        out['warning']='Both layouts exist on Qualcomm devices; do NOT patch one without verifying firmware-specific structure.'
    args.output.expanduser().write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
    print('Structure metadata only:',args.output,'- no changes made to device or backup')
    print(json.dumps(out,indent=2))

if __name__=='__main__':main()
