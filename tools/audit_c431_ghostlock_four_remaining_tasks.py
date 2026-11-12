#!/usr/bin/env python3
"""Fail-closed four-task GhostLock evidence assessment for original FNE-NX9 C431.

Reads signed-source-derived JSON audit artifacts. No device, futex, EDL, UAF,
kernel-memory access, or exploit payload. A static result cannot count as root.
"""
import argparse,json
from pathlib import Path

BOOT="5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256"
IMAGE="bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece"
IKCONFIG="99107cb0eb989d1381321f560664c78bf4b47ebdecb2cc33e9a7d430e1e973c4"
DO_FUTEX="dafc0e0138313ba88c2bbaad6fdd71509561325ce232bcbd19ea1e4f98a6108a"

def require(ok,reason):
    if not ok: raise ValueError(reason)

def audit(chain,direct,stack,waiter,hardening):
    for label,item in (("chain",chain),("direct",direct),("stack",stack)):
        require(item.get("boot_sha256")==BOOT,"wrong stock boot in "+label)
        require(item.get("kernel_sha256")==IMAGE,"wrong stock Image in "+label)
        require(item.get("device_operations")==0,"unexpected device operation in "+label)
    require(waiter.get("original_boot_sha256")==BOOT and
            waiter.get("original_image_sha256")==IMAGE,"wrong signed waiter source")
    require(waiter.get("original_do_futex_sha256")==DO_FUTEX,"do_futex identity mismatch")
    require(waiter.get("device_operations")==0,"waiter report contains device operations")
    require(hardening.get("kernel_image_sha256")==IMAGE and
            hardening.get("kernel_ikconfig_sha256")==IKCONFIG,"wrong signed IKCONFIG provenance")
    require(hardening.get("source_image_verified") is True and
            hardening.get("source_sha256_verified") is True,"unverified IKCONFIG")
    require(hardening.get("device_operations")==0,"hardening report contains device operations")

    require(chain.get("original_arm64_assertions",0)>=18,"missing original C431 ARM64 checks")
    for key in ("original_binary_proxy_wrapper_to_remove_waiter",
                "original_binary_remove_waiter_uses_current",
                "source_futex_requeue_to_proxy_lock_with_other_task"):
        require(chain.get(key) is True,"missing original rollback evidence "+key)
    require(direct.get("direct_call_verified") is True and
            direct.get("complete_to_next_text_symbol") is True and
            direct.get("direct_call_count",0)>=1,"signed futex->proxy direct BL missing")
    require(waiter.get("instruction_sites_verified",0)>=9 and
            waiter.get("distinct_original_direct_helpers_verified",0)>=5,
            "unverified local waiter and helper instructions")
    require(waiter.get("waiter_pointer_expression")=="x29 - 0xd0","unknown original waiter")
    require(stack.get("arithmetic_intersection_bytes")==80,"unexpected conditional interval")
    require(stack.get("static_interval_match_is_not_ghostlock_feasibility") is True,
            "static overlap overclaimed as exploit")
    for key in ("shared_kernel_stack_base_proven",
                "select_bytes_user_controllable_in_intersection_proven",
                "waiter_reuse_after_live_uaf_proven"):
        require(stack.get(key) is False,"unsupported live stack control claim: "+key)
    expected={
        "memory_layout":{"CONFIG_RANDOMIZE_BASE":"y","CONFIG_VMAP_STACK":"y"},
        "control_flow_and_stack":{"CONFIG_CFI_CLANG":"y","CONFIG_CFI_PERMISSIVE":"n",
                                  "CONFIG_STACKPROTECTOR_STRONG":"y"},
        "kernel_memory_policy":{"CONFIG_HARDENED_USERCOPY":"y"},
        "relevant_os_gates":{"CONFIG_FUTEX_PI":"y","CONFIG_RT_MUTEXES":"y"}
    }
    flags=hardening.get("flags",{})
    for section,settings in expected.items():
        for name,val in settings.items():
            require(flags.get(section,{}).get(name)==val,"original kernel CONFIG mismatch "+name)
    for item,key in ((chain,"queue_processing_or_rollback_executed_on_phone"),
                     (chain,"uaf_or_root_or_unlock_demonstrated"),
                     (waiter,"actual_kernel_uaf_confirmed"),
                     (waiter,"ghostlock_root_or_unlock_demonstrated"),
                     (hardening,"ghostlock_root_demonstrated")):
        require(item.get(key) is False,"unverified runtime claim in old static report: "+key)
    return {
        "schema_version":1,
        "target":"HONOR 70 FNE-NX9 C431 MagicOS 8.0.0.290, kernel 5.4.295-qgki-ga2d8945339ca",
        "original_boot_sha256":BOOT,"original_kernel_sha256":IMAGE,
        "verified_report_types":["original_proxy_chain","direct_proxy_edge",
                                 "conditional_stack_intervals","waiter_pointer_provenance",
                                 "original_kernel_hardening"],
        "tasks":{
          "1_actual_uaf_trigger":{
            "state":"not_demonstrated",
            "established":"Verified original wrong-task rollback code and direct futex-to-proxy call",
            "missing":"Independent live actual UAF/rollback evidence. Prior EINVAL test exits before waiters."},
          "2_live_stack_reuse_and_user_control":{
            "state":"not_demonstrated",
            "established":"Conditional 80-byte overlap in original C431 ARM64 under shared-entry-SP hypothesis",
            "missing":"Same live kernel-stack reuse and user-controlled data at the actual freed object"},
          "3_complete_c431_profile_and_mitigations":{
            "state":"partial",
            "established":"Exact kernel sections, selected struct fields, source checks, IKCONFIG and CFI/KASLR/VMAP_STACK",
            "missing":"Complete build profile and trustworthy runtime layout under original mitigations"},
          "4_reproducible_temporary_root":{
            "state":"not_demonstrated",
            "established":"No original device root evidence in audited source artifacts",
            "missing":"Verified reproducible on-device privilege transition on this build"}
        },
        "ready_to_claim_working_c431_ghostlock":False,
        "temporary_root_reproduced":False,
        "persistent_bootloader_unlock_reproduced":False,
        "device_operations":0,
        "scope":"read-only static evidence grading; no exploit, UAF or root commands"
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("chain","direct","stack","waiter","hardening","out"):
        p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args()
    records=[json.loads(getattr(a,name).read_text()) for name in
             ("chain","direct","stack","waiter","hardening")]
    result=audit(*records)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
    for key,value in result["tasks"].items():print(key,value["state"])
    print("C431_GHOSTLOCK_ROOT_VERIFIED",False)

if __name__=="__main__":main()
