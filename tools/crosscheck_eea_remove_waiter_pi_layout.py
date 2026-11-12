#!/usr/bin/env python3
"""Read-only comparison of exact EEA remove_waiter machine code with FNE 5.4 struct.

Only identifies two stack/PI lock layout fields. DOES NOT generate usable
GhostLock config, write to memory, or execute any exploit.
"""
import argparse,hashlib,json,re
from pathlib import Path
EXPECTED_KERNEL="bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
POINTS={
 "0xffffffc01037e384":("mrs","x20, sp_el0"),
 "0xffffffc01037e388":("add","x21, x20, #0x96c"),
 "0xffffffc01037e3cc":("str","xzr, [x20, #0x990]"),
}
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--machine-code",required=True,type=Path)
 p.add_argument("--upstream-structs",required=True,type=Path)
 p.add_argument("--out",required=True,type=Path)
 a=p.parse_args()
 b=a.machine_code.read_bytes();c=a.upstream_structs.read_bytes()
 data=json.loads(b)
 if data["stock_kernel_sha256"]!=EXPECTED_KERNEL:raise ValueError("Not matching EEA kernel source")
 funcs=data["interesting_exact_symbol_instances"]
 hits=[x for x in funcs if x["symbol"]=="remove_waiter"]
 if len(hits)!=1 or hits[0]["vaddr"]!=0xffffffc01037e350:
  raise ValueError("Exact source remove_waiter address changed")
 dis={x["addr"]:(x["mnemonic"],x["operands"]) for x in hits[0]["decoded_instructions"]}
 for addr,expected in POINTS.items():
  if dis.get(addr)!=expected:raise ValueError("Unexpected ARM64 machine code at "+addr+" actual "+str(dis.get(addr)))
 src=c.decode("utf8","replace")
 if not re.search(r"(?s)#define STRUCT_OFFSETS_5_4\\s*\\\\.*?task_pi_lock=0x96C",src):
  raise ValueError("Original 5.4 FNE struct offset source changed")
 if ".task_pi_blocked_on=0x990" not in src:
  raise ValueError("Original FNE struct blocked-on field changed")
 result={
  "signed_exact_EEA_kernel_sha256":EXPECTED_KERNEL,
  "original_source_disasm_report_sha256":hashlib.sha256(b).hexdigest(),
  "chinese_FNE_5_4_common_struct_source_sha256":hashlib.sha256(c).hexdigest(),
  "original_remove_waiter_symbol":"0xffffffc01037e350",
  "machine_code_assertions":{addr:{"instruction":" ".join(parts)} for addr,parts in POINTS.items()},
  "source_matching_fields":{
   "current_task_pointer":"mrs x20,sp_el0",
   "task_pi_lock_offset":"0x96c",
   "task_pi_blocked_on_offset":"0x990"
  },
  "important_limitations":[
   "These two offsets are not sufficient for constructing a valid kernel exploit profile.",
   "No BTF task/cred/waiter geometry, kernel_phys_load on phone or exploit success was established.",
   "Temporary root would not directly bypass QSEE Keymaster protected bootloader state.",
   "The user device remains last observed LOCKED and no phone operation was performed."
  ],
  "safe_executable_ghostlock_profile":False,
  "permanent_unlock_achieved":False
 }
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,indent=2)+"\n")
 print("RETAIL_EEA_EXACT_REMOVE_WAITER_CURRENT_TASK_CODE_CONFIRMED")
 print("ORIGINAL_EEA_TASK_PI_LOCK_OFFSET",hex(0x96c))
 print("ORIGINAL_EEA_TASK_PI_BLOCKED_ON_OFFSET",hex(0x990))
 print("EXACT_EEA_GHOSTLOCK_PROFILE_STILL_UNSAFE")
if __name__=="__main__":main()
