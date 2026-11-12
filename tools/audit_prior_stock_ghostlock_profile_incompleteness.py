#!/usr/bin/env python3
"""Read-only original HONOR70 FNE-NX9 GhostLock candidate profile safety audit.

The source kernel and profile are from the signed EEA stock 8.0.0.290
firmware. Upstream FNE-AN00 kernel offsets are a DIFFERENT release.
This never builds or executes a kernel exploit.
"""
import argparse,hashlib,json,re
from pathlib import Path

EEA_RELEASE="5.4.295-qgki-ga2d8945339ca"
CHINA_RELEASE="5.4.295-qgki-g0fb2656b2b50"
PROBLEMATIC_PHYS=4294963200 # 0xfffff000, derived from CI HOST /proc/iomem
REQUIRED=[
 "task_struct.prio",
 "task_struct.pi_lock",
 "task_struct.pi_waiters",
 "task_struct.pi_blocked_on",
 "task_struct.real_cred",
 "task_struct.cred",
 "task_struct.seccomp",
 "route.multicast_waiter.task_offset",
 "route.multicast_waiter.lock_offset",
 "cred.caps_offset",
 "cred.securebits_offset",
 "cred.security_offset",
]

def val(src,key):
    parts=key.split(".")
    if len(parts)==1:
        m=re.search(r"(?m)^\s*"+re.escape(key)+r"\s*=\s*(\S+)",src)
        return m.group(1) if m else None
    group=parts[0]
    m=re.search(r"(?ms)^\s*"+re.escape(group)+r"\s*\{(?P<block>.*?)^\s*\}",src)
    if not m:return None
    return val(m.group("block"),".".join(parts[1:]))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile",required=True,type=Path)
    p.add_argument("--extractor-log",required=True,type=Path)
    p.add_argument("--upstream-offsets",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    pb=a.profile.read_bytes();lb=a.extractor_log.read_bytes();ub=a.upstream_offsets.read_bytes()
    conf=pb.decode("utf8","replace")
    log=lb.decode("utf8","replace")
    upstream=ub.decode("utf8","replace")
    exact=val(conf,"release")
    if exact!='"'+EEA_RELEASE+'"':
        raise RuntimeError("This is NOT the user's original signed EEA kernel profile")
    if "CVE-2026-43499 primitive present (remove_waiter" not in log:
        raise RuntimeError("Original extractor did not observe the presumed kernel primitive")
    if 'OFFSETS_ENTRY("'+CHINA_RELEASE+'"' not in upstream:
        raise RuntimeError("Original upstream FNE profile changed / missing")
    if 'OFFSETS_ENTRY("'+EEA_RELEASE+'"' in upstream:
        raise RuntimeError("Upstream now has an exact EEA profile: re-evaluate before reporting missing")
    phys=val(conf,"kernel_phys_load")
    if phys is None or int(phys,0)!=PROBLEMATIC_PHYS:
        raise RuntimeError("Previous unsafe CI-host /proc/iomem inference changed")
    missing={key:val(conf,key) for key in REQUIRED if val(conf,key) in (None,"null")}
    other_null=len(re.findall(r"(?m)^\s*[a-z][a-z0-9_]*\s*=\s*null\s*$",conf))
    if len(missing)<8 or other_null<20:
        raise RuntimeError("Original profile completeness expectation has changed")
    out={
      "target":"Original HONOR70 FNE-NX9 8.0.0.290 EEA kernel",
      "exact_user_kernel_release":EEA_RELEASE,
      "original_profile_sha256":hashlib.sha256(pb).hexdigest(),
      "original_extractor_log_sha256":hashlib.sha256(lb).hexdigest(),
      "original_upstream_FNE_offsets_sha256":hashlib.sha256(ub).hexdigest(),
      "upstream_chinese_5_4_295_example":CHINA_RELEASE,
      "exact_EEA_kernel_in_upstream_FNE_table":False,
      "stock_extractor_indicates_unpatched_remove_waiter_pattern":True,
      "CVE_exploitability_or_success_proven":False,
      "profile_total_null_fields":other_null,
      "critical_required_fields_null_or_absent":missing,
      "kernel_phys_load":phys,
      "kernel_phys_load_warning":"0xfffff000 is inferred from GitHub Actions HOST /proc/iomem and NOT a trustworthy phone kernel physical load",
      "safe_to_execute_or_port_directly":False,
      "permanent_bootloader_unlock_established":False,
      "decisive_next_technical_prerequisites":[
        "Rebuild full C431 EEA kernel struct geometry from matching source/BTF/disassembly",
        "Determine correct phone-side kernel_phys_load from authenticated original boot chain or properly measured device value",
        "Validate resulting temporary root under controlled recovery conditions",
        "Even if temporary root works, separately address Keymaster software-fuse/milestone and protected RPMB lock state"
      ],
      "no_phone_or_edl_operations":True
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n")
    print("EXACT_EEA_KERNEL_SOURCE",EEA_RELEASE)
    print("GHOSTLOCK_PRIMITIVE_SUSPECTED_FROM_OFFLINE_KERNEL_CODE",True)
    print("PROFILE_INCOMPLETE_NULL_FIELDS",other_null)
    print("HOST_MEMORY_ADDRESS_NOT_TARGET_KERNEL_PHYSICAL_BASE",hex(PROBLEMATIC_PHYS))
    print("EXACT_KERNEL_PROFILE_SAFE_TO_EXECUTE",False)
    print("NO_BOOTLOADER_UNLOCK_PROVEN")
if __name__=="__main__":main()
