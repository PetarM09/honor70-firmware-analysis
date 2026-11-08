#!/usr/bin/env python3
"""Honor70 targeted, read-only OEM lock HAL and boot support diagnostic.
Only query state and public service metadata. No fastboot, writes, root, partitions, or binder transactions.
"""
import pathlib
import re
import shutil
import subprocess
import sys

QUERIES = [
  ("model", "getprop ro.product.model"),
  ("build", "getprop ro.build.version.incremental"),
  ("supported", "getprop ro.oem_unlock_supported"),
  ("permission_prop", "getprop sys.oem_unlock_allowed"),
  ("flash_locked", "getprop ro.boot.flash.locked"),
  ("verifiedboot", "getprop ro.boot.verifiedbootstate"),
  ("device_state", "getprop ro.boot.vbmeta.device_state"),
  ("service_names", "service list"),
  ("hidl_hal_names", "lshal"),
  ("vintf_oemlock", "grep -i -r -n -E 'android\\.hardware\\.oemlock|oemlock' /vendor/etc/vintf /odm/etc/vintf 2>&1"),
  ("oemlock_log", "logcat -b system -d -s OemLock:I -t 500 2>&1"),
]
REDACT = re.compile(r'(?i)(?:[0-9a-f]{16,}|[A-Za-z0-9+/]{28,}={0,2})')
FILTER = re.compile(r'(?i)oem.?lock|oemunlock|vendorlock|persistent.?data.?block|permission|denied|hal|error|not found')
MAXLINES=55

def adb_shell(command):
  try:
    p=subprocess.run(['adb','shell',command],capture_output=True,text=True,errors='replace',timeout=26)
    return p.returncode,(p.stdout+'\n'+p.stderr).strip()
  except Exception as exc:
    return 99,type(exc).__name__+': '+str(exc)

def main():
  if shutil.which('adb') is None:
    print('ADB executable not found');return 2
  p=subprocess.run(['adb','get-state'],capture_output=True,text=True,timeout=12)
  if p.returncode or p.stdout.strip()!='device':
    print('ADB device is not connected and authorized');return 3
  result=['HONOR70_HALS_OEM_PERMISSION_READONLY','No binder calls, flashing, file modification or partition reads.','']
  for label,cmd in QUERIES:
    status,output=adb_shell(cmd)
    result.append('=== '+label+' rc='+str(status)+' ===')
    lines=output.splitlines()
    if label in ('service_names','hidl_hal_names','vintf_oemlock','oemlock_log'):
      lines=[s for s in lines if FILTER.search(s)]
    if not lines:lines=['(empty or no relevant entry)']
    for line in lines[:MAXLINES]:
      result.append(REDACT.sub('[REDACTED]',line[:240]))
    if len(lines)>MAXLINES:result.append('(further matching lines omitted)')
    result.append('')
  file=pathlib.Path.cwd()/'HONOR70_OEMLOCK_HAL_READONLY.txt'
  file.write_text('\n'.join(result)+'\n',encoding='utf-8')
  print('Saved read-only report:',file)
  print('Inspect before sharing privately; do not publish device reports to a public repository.')
  return 0

if __name__ == '__main__':
  sys.exit(main())
