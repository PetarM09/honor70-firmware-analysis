#!/usr/bin/env python3
"""Read-only cross-version HONOR 70 kernel source proof report.

Consumes source files copied from SHA-verified official GPL Release archives.
Does not fabricate a runtime exploit geometry or execute any kernel operations.
"""
import argparse
import difflib
import hashlib
import json
import re
from pathlib import Path

REQUIRED=("kernel_rtmutex_c","kernel_rtmutex_common_h",
          "kernel_futex_c","include_sched_h",
          "source_root_makefile","merge_lahaina_defconfig")
FLAGS=("CONFIG_FUTEX","CONFIG_FUTEX_PI","CONFIG_RT_MUTEXES",
       "CONFIG_DEBUG_RT_MUTEXES","CONFIG_IKCONFIG","CONFIG_IKCONFIG_PROC",
       "CONFIG_SECCOMP_FILTER","CONFIG_HN_VIP_THREAD",
       "CONFIG_HN_VIP_RUNNABLE_TIME_LIMIT",
       "CONFIG_HN_SET_ASYNC_BINDER_RT","CONFIG_SCHED_ENHANCEMENT_INTRUSIVE")
VERSION_FIELDS=("VERSION","PATCHLEVEL","SUBLEVEL","EXTRAVERSION")


def load_one(path):
    manifest=json.loads((path/"SOURCE_FILE_MANIFEST.json").read_text())
    result={}
    for role, info in manifest["selected_sources"].items():
        if "output_name" not in info:
            continue
        data=(path/info["output_name"]).read_bytes()
        if hashlib.sha256(data).hexdigest()!=info["sha256"]:
            raise ValueError("Source provenance SHA mismatch: "+role)
        result[role]=data.decode("utf8",errors="replace")
    return manifest,result


def config_options(text):
    result={}
    for line in text.splitlines():
        yes=re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(y|m|n)",line)
        no=re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set",line)
        if yes:result[yes.group(1)]=yes.group(2)
        if no:result[no.group(1)]="n"
    return {key:result.get(key,"not_listed") for key in FLAGS}


def version(text):
    output={}
    for key in VERSION_FIELDS:
        m=re.search(r"(?m)^"+key+r"\s*=\s*([^\n]*)$",text)
        output[key]=m.group(1).strip() if m else None
    return output


def function_evidence(text):
    start=re.search(r"(?m)^static void remove_waiter\s*\(",text)
    if not start: return {"present":False}
    brace=text.find("{",start.end())
    if brace<0 or brace-start.start()>500:return {"present":False}
    depth=0
    stop=None
    for i in range(brace,len(text)):
        if text[i]=="{":depth+=1
        if text[i]=="}":
            depth-=1
            if depth==0:
                stop=i+1
                break
    if stop is None:return {"present":False}
    body=text[start.start():stop]
    return {"present":True,
            "sha256":hashlib.sha256(body.encode()).hexdigest(),
            "line_number":text[:start.start()].count("\n")+1,
            "current_pi_lock":bool(re.search(r"raw_spin_lock\s*\(\s*&current->pi_lock\s*\)",body)),
            "current_pi_blocked_on_clear":bool(re.search(r"current->pi_blocked_on\s*=\s*NULL",body)),
            "waiter_task_pi_blocked_on_clear":bool(re.search(r"waiter->task->pi_blocked_on\s*=\s*NULL",body))}


def compare(a_dir,b_dir):
    a_meta,a=load_one(a_dir)
    b_meta,b=load_one(b_dir)
    for label,src in (("Fennie",a),("AN00",b)):
        missing=[k for k in REQUIRED if k not in src]
        if missing:raise ValueError(label+" lacks required core sources: "+", ".join(missing))
    comparisons={}
    for key in sorted(set(a)&set(b)):
        sha_a=hashlib.sha256(a[key].encode()).hexdigest()
        sha_b=hashlib.sha256(b[key].encode()).hexdigest()
        comparisons[key]={"same_sha256":sha_a==sha_b,"fennie_sha256":sha_a,
                          "an00_sha256":sha_b,
                          "unified_diff_line_count":len(list(difflib.unified_diff(
                              b[key].splitlines(),a[key].splitlines()))) if sha_a!=sha_b else 0}
    fa=function_evidence(a["kernel_rtmutex_c"])
    ab=function_evidence(b["kernel_rtmutex_c"])
    options={key:{"fennie":config_options(a["merge_lahaina_defconfig"])[key],
                  "an00":config_options(b["merge_lahaina_defconfig"])[key]} for key in FLAGS}
    return {
        "schema_version":1,
        "sources":["MagicOS8.0-ROM-Fennie_MagicOS8.0_Opensource",
                   "FNE-AN00_MagicUI6.1_Code_Opensource"],
        "fennie_kernel_tree_makefile":version(a["source_root_makefile"]),
        "an00_kernel_tree_makefile":version(b["source_root_makefile"]),
        "selected_source_comparisons":comparisons,
        "fennie_remove_waiter":fa,"an00_remove_waiter":ab,
        "remove_waiter_function_identical":(fa.get("sha256")==ab.get("sha256") and fa.get("present") and ab.get("present")),
        "merged_lahaina_config_options":options,
        "fennie_config_is_exact_running_C431_kernel":"not_proven",
        "signed_C431_binary_match_proven_by_this_source_comparison":False,
        "runtime_ghostlock_trigger_or_root_demonstrated":False,
        "bootloader_unlock_demonstrated":False,
        "device_operations":0,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fennie-dir",type=Path,required=True)
    p.add_argument("--an00-dir",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    result=compare(a.fennie_dir,a.an00_dir)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
    print("FENNIE_LINUX_MAKEFILE_SUBLEVEL",result["fennie_kernel_tree_makefile"]["SUBLEVEL"])
    print("AN00_LINUX_MAKEFILE_SUBLEVEL",result["an00_kernel_tree_makefile"]["SUBLEVEL"])
    print("RTMUTEX_C_IDENTICAL",result["selected_source_comparisons"]["kernel_rtmutex_c"]["same_sha256"])
    print("REMOVE_WAITER_FUNCTION_IDENTICAL",result["remove_waiter_function_identical"])
    print("FENNIE_CURRENT_PI_BLOCKED_ON_CLEAR",result["fennie_remove_waiter"]["current_pi_blocked_on_clear"])
    for key in FLAGS:
        v=result["merged_lahaina_config_options"][key]
        print("CONFIG_COMPARE",key,v["fennie"],v["an00"])
    print("WORKING_EXPLOIT_NOT_PROVEN")


if __name__=="__main__":
    main()
