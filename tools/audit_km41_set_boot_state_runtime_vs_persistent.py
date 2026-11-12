#!/usr/bin/env python3
"""Source-pinned secondary Keymaster command audit, offline only.

Separates in-TEE boot-state reporting (km_set_boot_state) and
root-of-trust initialization from persistent RPMB device-state write.
Consumes original KM41 Ghidra output and 67-slot signed callback inventory.
"""
import argparse,hashlib,re,json,csv
from pathlib import Path
HANDLERS={
 "201":"0x10d4e4","208":"0x10d064","211":"0x10d6d0",
 "200":"0x10e184","205":"0x117ed4","207":"0x10e270",
 "215":"0x10e110","210e":"0x107c48"
}
def get(s,command,addr):
    m=re.search(r"(?m)^===== COMMAND 0x"+command+r" HANDLER "+addr+r" =====$",s)
    if not m:raise RuntimeError("Missing signed source function "+command)
    n=re.search(r"(?m)^===== COMMAND ",s[m.end():])
    return s[m.end():m.end()+n.start() if n else len(s)]

def check(pattern,body,label):
    if not re.search(pattern,body,re.S):
        raise RuntimeError("Signed KM41 expected evidence missing: "+label)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--handlers",required=True,type=Path)
    ap.add_argument("--inventory",required=True,type=Path)
    ap.add_argument("--out",required=True,type=Path)
    a=ap.parse_args()
    h=a.handlers.read_bytes(); i=a.inventory.read_bytes()
    src=h.decode("utf8","replace"); inv=i.decode("utf8","replace")
    funcs={cmd:get(src,cmd,addr) for cmd,addr in HANDLERS.items()}
    entries=list(csv.DictReader((x for x in inv.splitlines() if not x.startswith("#")),delimiter="\t"))
    if len(entries)!=67:raise RuntimeError("Original KM41 registered callback table no longer 67 entries")
    table={int(e["CMD"],16):e for e in entries}
    for cmd in HANDLERS:
      if int(cmd,16) not in table:raise RuntimeError("Handler missing from original 67-slot registry")
    for cmd in ("201","208","211"):
      f=funcs[cmd]
      check("FUN_00117980",f,cmd+" software fuse check")
      check("km_check_is_sw_fuse_blown failed or fuse already blown",f,cmd+" denial diagnostic")
    boot=funcs["208"]
    check("km_set_boot_state",boot,"boot-state handler identifier")
    check('qsee_log\\(8,"is_unlocked:',boot,"boot status is_unlocked log")
    check(re.escape("DAT_00139518 = '\\x01'"),boot,"runtime init flag set")
    check(re.escape("FUN_0012d130(&DAT_0013955c,0x30,local_48,0x30)"),boot,"runtime 48-byte boot state copy")
    check(re.escape("if (DAT_00139518 == '\\0')"),boot,"initialize only once in trustlet")
    setrot=funcs["201"]
    check("KM_ERROR_ROOT_OF_TRUST_ALREADY_SET",setrot,"ROT already-set check")
    check(re.escape("DAT_00138b14 = '\\x01'"),setrot,"in-memory initialized flag")
    rand=funcs["211"]
    check(re.escape("FUN_0012d130(&DAT_00138b19,0x20,param_1 + 4,0x20)"),rand,"internal 32-byte input copy")
    check("km_get_auth_token_key",funcs["205"],"auth-token key handler")
    check("ta_major_version",funcs["207"],"TA version report handler")
    check(r"return 0;",funcs["215"],"noop command")
    check("func_0x001184d4",funcs["210e"],"delete all keys storage helper")
    for cmd,body in funcs.items():
      if "qsee_stor_write_sectors" in body:
        raise RuntimeError("Unexpected direct persistent storage writer in "+cmd)
    direct=[e["CMD"] for e in entries if e["CALL_QSEE_STOR_WRITE"]=="true"]
    if direct!=["0x203"]:
      raise RuntimeError("Alternative direct storage-writer callback discovered: "+str(direct))
    guarded=[e["CMD"] for e in entries if e["CALL_FUSE"]=="true"]
    if set(guarded)!={"0x201","0x202","0x203","0x208","0x211"}:
      raise RuntimeError("FUSE caller set differs: "+str(guarded))
    report={
       "source":"Original signed FNE-NX9 EEA KM41 67 registered callbacks and separately decompiled source",
       "source_handlers_sha256":hashlib.sha256(h).hexdigest(),
       "source_registry_sha256":hashlib.sha256(i).hexdigest(),
       "registered_callback_count":len(entries),
       "direct_software_fuse_caller_commands":guarded,
       "direct_qsee_stor_write_sectors_registered_handlers":direct,
       "discovered_secondary_functions":{
          "0x201":"set root of trust for current Keymaster session; fuse gated, current initialization flag",
          "0x208":"set boot state from incoming 0x30-byte structure; contains is_unlocked field; in-trustlet state, not direct RPMB writer, fuse gated",
          "0x211":"copy 0x20-byte input into trustlet data; fuse gated, no direct persistent storage write",
          "0x200":"version report, no direct state write",
          "0x205":"get auth-token key, no direct state write",
          "0x207":"TA API version negotiation, no direct state write",
          "0x215":"trivial success-return handler",
          "0x210e":"DELETE_ALL_KEYS (shares callback 0x10e), indirect protected key storage writes, not device lock-state API"
       },
       "significant_limitations":[
         "Direct pseudocode call inventory does NOT prove absence of indirect or hidden protected writes.",
         "In-memory Keymaster boot state is not proof of persistent device unlock.",
         "No Keymaster command was executed, no client authorization was tested.",
         "No evidence of permanent bootloader unlock or accepted software-fuse bypass."
       ],
       "permanent_unlock_demonstrated":False
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print("ORIGINAL_KM41_67_REGISTRATIONS_CONFIRMED")
    print("FUSE_GUARDED_HANDLER_IDS",guarded)
    print("DIRECT_PERSISTENT_STORAGE_HANDLER_IDS",direct)
    print("KM_0x208_SET_BOOT_STATE_IS_RUNTIME_STATE_NOT_0x203")
    print("UNLOCK_UNPROVEN")
if __name__=="__main__": main()
