#!/usr/bin/env python3
"""Read-only FNE-NX9 C431 profile validator and optional ADB identity preflight.

Never invokes futex, UAF, kernel address probes, root, EDL, flashing, or writes
to the Android device. A match checks model/kernel/SDK, NOT C431 provenance.
"""
from __future__ import annotations
import argparse, hashlib, json, re, subprocess
from pathlib import Path

REPO_ROOT=Path(__file__).resolve().parents[1]
DEFAULT_PROFILE=REPO_ROOT/"profiles/fne-nx9-c431-8.0.0.290.profile.json"
BOOT_SHA="5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"
IMAGE_SHA="bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
KERNEL="5.4.295-qgki-ga2d8945339ca"
FIELDS={
 "rt_mutex_waiter.task":0x30,
 "rt_mutex_waiter.lock":0x38,
 "rt_mutex_waiter.prio":0x40,
 "rt_mutex_waiter.deadline":0x48,
 "task_struct.prio":0x11c,
 "task_struct.dl.deadline":0x488,
 "task_struct.pi_lock":0x96c,
 "task_struct.pi_waiters.rb_root":0x978,
 "task_struct.pi_waiters.rb_leftmost":0x980,
 "task_struct.pi_blocked_on":0x990,
}
ADB_COMMANDS={
 "model":["shell","getprop","ro.product.model"],
 "device":["shell","getprop","ro.product.device"],
 "kernel":["shell","uname","-r"],
 "android_sdk":["shell","getprop","ro.build.version.sdk"],
 "android_release":["shell","getprop","ro.build.version.release"],
 "build_incremental":["shell","getprop","ro.build.version.incremental"],
 "selinux_enforcing":["shell","getenforce"],
 "verified_boot_state":["shell","getprop","ro.boot.verifiedbootstate"],
 "flash_locked":["shell","getprop","ro.boot.flash.locked"],
 "shell_uid":["shell","id","-u"]
}
def validate_profile(profile):
 if not isinstance(profile,dict) or profile.get("schema_version")!=1:
  raise ValueError("Invalid C431 profile schema")
 target=profile.get("target",{})
 require={"model":"FNE-NX9","device":"HNFNE","region":"C431",
          "magicos":"8.0.0.290","android_major":14,
          "android_sdk":34,"kernel_uname_release":KERNEL}
 if any(target.get(k)!=v for k,v in require.items()):
  raise ValueError("Wrong target identity or kernel release")
 prov=profile.get("provenance",{})
 if prov.get("boot_img_sha256")!=BOOT_SHA or prov.get("extracted_kernel_image_sha256")!=IMAGE_SHA:
  raise ValueError("C431 stock firmware SHA mismatch")
 if profile.get("confirmed_binary_offsets_bytes")!=FIELDS:
  raise ValueError("Original C431 structure fields changed unexpectedly")
 stack=profile.get("confirmed_stack_evidence",{})
 if stack.get("do_futex_waiter_pointer_expression")!="x29 - 0xd0":
  raise ValueError("Waiter pointer not independently established")
 if stack.get("select_overlap_is_dynamic_proof") is not False:
  raise ValueError("Static overlap cannot claim live object control")
 unresolved=profile.get("unresolved_required_fields",{})
 required_unknown=("kernel_phys_load","actual_runtime_kernel_slide",
                   "reliable_dangling_waiter_lifetime",
                   "proven_kernel_memory_primitive","controlled_privilege_transition")
 if not all(k in unresolved and unresolved[k] is None for k in required_unknown):
  raise ValueError("Unverified dangerous runtime fields must remain unknown")
 flags=profile.get("checks",{})
 for key in ("exploit_loader_enabled","active_uaf_trigger_enabled",
             "kernel_memory_write_enabled","root_installation_enabled",
             "persistent_unlock_enabled"):
  if flags.get(key) is not False:raise ValueError("Profile is not a read-only preflight")
 if not str(profile.get("status","")).startswith("experimental_static_verified_non_executable"):
  raise ValueError("Not the verified diagnostic-only profile")
 return True

def evaluate_identity(profile,live):
 target=profile["target"]
 expected={"model":target["model"],"device":target["device"],
           "kernel":target["kernel_uname_release"],
           "android_sdk":str(target["android_sdk"])}
 individual={k:{"expected":v,"observed":live.get(k,""),
                 "matches":live.get(k,"")==v}
             for k,v in expected.items()}
 exact=all(c["matches"] for c in individual.values())
 return {
  "identity_result":"MODEL_KERNEL_ANDROID_MATCH" if exact else "MODEL_KERNEL_ANDROID_MISMATCH",
  "identity_checks":individual,
  "device_reported_runtime":{
   "android_release":live.get("android_release",""),
   "build_incremental":live.get("build_incremental",""),
   "selinux_enforcing":live.get("selinux_enforcing",""),
   "verified_boot_state":live.get("verified_boot_state",""),
   "flash_locked":live.get("flash_locked",""),
   "shell_uid":live.get("shell_uid","")
  },
  "firmware_region_c431_live_attested":False,
  "stock_boot_sha_matches_running_kernel_live":False,
  "exploit_compatible":None,
  "temporary_root_proven":False,
  "persistent_bootloader_unlock_proven":False,
  "note":"A model/kernel/Android match is not root, UAF, C431 region attestation or proof of byte-identical running kernel."
 }

def run_adb(*,adb="adb",serial=None,runner=subprocess.run):
 prefix=[adb]
 if serial:prefix.extend(["-s",serial])
 observed={}
 for key,cmd in ADB_COMMANDS.items():
  try:
   result=runner(prefix+cmd,check=False,capture_output=True,text=True,timeout=15)
  except (OSError,subprocess.TimeoutExpired) as err:
   raise RuntimeError("ADB read-only command unavailable: "+key) from err
  if result.returncode!=0:
   raise RuntimeError("ADB read-only command failed: "+key+"; "+result.stderr.strip()[:150])
  observed[key]=result.stdout.strip()
 return observed

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--profile",type=Path,default=DEFAULT_PROFILE)
 p.add_argument("--device",action="store_true",help="Read only ADB getprop/uname/id/getenforce checks")
 p.add_argument("--serial",help="Optional ADB device selector (never stored in report)")
 p.add_argument("--out",type=Path)
 a=p.parse_args()
 contents=a.profile.read_bytes()
 profile=json.loads(contents)
 validate_profile(profile)
 output={
  "schema_version":1,"profile_id":profile["profile_id"],
  "profile_version":profile["profile_version"],
  "profile_sha256":hashlib.sha256(contents).hexdigest(),
  "profile_integrity_verified":True,
  "device_operations":0,
  "adb_read_only_commands":list(ADB_COMMANDS) if a.device else [],
  "runtime_identity_checked":a.device,
  "preflight_only":True,
  "active_futex_requeue_or_uaf":False,
  "runtime":evaluate_identity(profile,run_adb(serial=a.serial)) if a.device else None
 }
 if a.out:
  a.out.parent.mkdir(parents=True,exist_ok=True)
  a.out.write_text(json.dumps(output,indent=2,ensure_ascii=False)+"\n")
 print(json.dumps(output,indent=2,ensure_ascii=False))
if __name__=="__main__":main()
