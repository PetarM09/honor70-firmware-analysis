#!/usr/bin/env python3
"""Read-only HONOR70 kernel-policy snapshot. No futex calls and no device writes.

Requires Python 3.9+ and adb on PATH. Uses adb shell only for reads.
Note: seccomp/SELinux context sampled here belongs to the adb shell process,
not an arbitrary Android application. Data is sanitized; no phone identifiers.
"""
import argparse,datetime,json,re,subprocess
from pathlib import Path

PROPERTIES=("ro.product.model","ro.product.device","ro.build.version.release","ro.build.version.security_patch","ro.build.fingerprint","ro.boot.verifiedbootstate","ro.boot.flash.locked","ro.boot.vbmeta.device_state")
LIMIT=16384
def execute(*args,timeout=12):
 try:
  r=subprocess.run(["adb",*args],text=True,stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE,timeout=timeout,check=False)
  return {"ok":r.returncode==0,"text":r.stdout[:LIMIT],"error":r.stderr[:350]}
 except (OSError,subprocess.TimeoutExpired) as e:
  return {"ok":False,"text":"","error":type(e).__name__}
def read_shell(command):
 return execute("shell",command)
def clean(value):
 # Retain only kernel-policy-relevant lines, not full process environment.
 return [s for s in value.splitlines() if re.match(r"^(Name|State|Uid|Gid|NoNewPrivs|Seccomp|Seccomp_filters|Cap(Prm|Eff|Bnd)|TracerPid):",s)]
def gather():
 report={"schema_version":1,"target":"HONOR 70 FNE-NX9 (user verify identity locally)",
         "captured_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
         "scope":"non-invasive adb-shell environment; not app-policy proof",
         "device_operations":"read-only","futex_calls":0,
         "observations":{},"limitations":[]}
 status=execute("get-state")
 if not status["ok"] or status["text"].strip()!="device":
  raise RuntimeError("One authorized adb device must be online: "+status["error"])
 for key in PROPERTIES:
  r=execute("shell","getprop",key)
  value=r["text"].strip()
  if key=="ro.build.fingerprint":
   # Avoid storing device-specific build fingerprint strings in shared artifacts.
   report["observations"]["fingerprint_present"]=bool(value)
  else:
   report["observations"][key]=value if r["ok"] else None
 report["observations"]["kernel_release"]=read_shell("uname -r")["text"].strip()
 for label,cmd in {
  "shell_context":"id -Z 2>/dev/null",
  "shell_child_proc_status":"cat /proc/self/status 2>/dev/null",
  "kernel_config_readability":"if test -r /proc/config.gz; then echo readable; else echo unavailable; fi",
  "selinux_enforcing":"cat /sys/fs/selinux/enforce 2>/dev/null",
 }.items():
  r=read_shell(cmd)
  val=r["text"].strip()
  if label=="shell_child_proc_status":
   report["observations"][label]=clean(val)
  else:
   report["observations"][label]=val if r["ok"] else None
 report["limitations"]=[
  "The observed shell-child seccomp state does NOT establish application permissions.",
  "This tool does not exercise PI futex operations or try to trigger CVE-2026-43499.",
  "This tool does not establish root, kernel read/write or bootloader unlock.",
  "If multiple adb devices are connected, select one with ANDROID_SERIAL before running."
 ]
 return report
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--out",type=Path,default=Path("HONOR70_READONLY_POLICY_SNAPSHOT.json"))
 args=p.parse_args()
 result=gather()
 args.out.parent.mkdir(parents=True,exist_ok=True)
 args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
 print("Saved read-only policy snapshot:",args.out)
 print("No futex syscall, exploit or device write was performed.")
if __name__=="__main__":main()
