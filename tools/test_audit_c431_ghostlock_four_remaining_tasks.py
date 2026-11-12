"""Synthetic-only fail-closed tests for four C431 GhostLock research tasks."""
import unittest
from audit_c431_ghostlock_four_remaining_tasks import BOOT,IMAGE,IKCONFIG,DO_FUTEX,audit

def fixtures():
 chain={"boot_sha256":BOOT,"kernel_sha256":IMAGE,"device_operations":0,
        "original_arm64_assertions":18,
        "original_binary_proxy_wrapper_to_remove_waiter":True,
        "original_binary_remove_waiter_uses_current":True,
        "source_futex_requeue_to_proxy_lock_with_other_task":True,
        "queue_processing_or_rollback_executed_on_phone":False,
        "uaf_or_root_or_unlock_demonstrated":False}
 direct={"boot_sha256":BOOT,"kernel_sha256":IMAGE,"device_operations":0,
         "direct_call_verified":True,"complete_to_next_text_symbol":True,
         "direct_call_count":1}
 stack={"boot_sha256":BOOT,"kernel_sha256":IMAGE,"device_operations":0,
        "arithmetic_intersection_bytes":80,
        "static_interval_match_is_not_ghostlock_feasibility":True,
        "shared_kernel_stack_base_proven":False,
        "select_bytes_user_controllable_in_intersection_proven":False,
        "waiter_reuse_after_live_uaf_proven":False}
 waiter={"original_boot_sha256":BOOT,"original_image_sha256":IMAGE,
         "original_do_futex_sha256":DO_FUTEX,"device_operations":0,
         "instruction_sites_verified":9,"distinct_original_direct_helpers_verified":5,
         "waiter_pointer_expression":"x29 - 0xd0","actual_kernel_uaf_confirmed":False,
         "ghostlock_root_or_unlock_demonstrated":False}
 hardening={"kernel_image_sha256":IMAGE,"kernel_ikconfig_sha256":IKCONFIG,
            "source_image_verified":True,"source_sha256_verified":True,
            "device_operations":0,"ghostlock_root_demonstrated":False,
            "flags":{
             "memory_layout":{"CONFIG_RANDOMIZE_BASE":"y","CONFIG_VMAP_STACK":"y"},
             "control_flow_and_stack":{"CONFIG_CFI_CLANG":"y","CONFIG_CFI_PERMISSIVE":"n",
                                       "CONFIG_STACKPROTECTOR_STRONG":"y"},
             "kernel_memory_policy":{"CONFIG_HARDENED_USERCOPY":"y"},
             "relevant_os_gates":{"CONFIG_FUTEX_PI":"y","CONFIG_RT_MUTEXES":"y"}}}
 return [chain,direct,stack,waiter,hardening]

class Tests(unittest.TestCase):
 def test_status_not_fake_root(self):
  r=audit(*fixtures())
  self.assertEqual([x["state"] for x in r["tasks"].values()],
                   ["not_demonstrated","not_demonstrated","partial","not_demonstrated"])
  self.assertFalse(r["ready_to_claim_working_c431_ghostlock"])
  self.assertEqual(r["device_operations"],0)
 def test_wrong_original_boot_rejected(self):
  a=fixtures();a[0]["boot_sha256"]="0"*64
  with self.assertRaises(ValueError):audit(*a)
 def test_wrong_original_kernel_rejected(self):
  a=fixtures();a[1]["kernel_sha256"]="0"*64
  with self.assertRaises(ValueError):audit(*a)
 def test_wrong_ikconfig_rejected(self):
  a=fixtures();a[4]["kernel_ikconfig_sha256"]="0"*64
  with self.assertRaises(ValueError):audit(*a)
 def test_missing_direct_edge_rejected(self):
  a=fixtures();a[1]["direct_call_verified"]=False
  with self.assertRaises(ValueError):audit(*a)
 def test_wrong_waiter_pointer_rejected(self):
  a=fixtures();a[3]["waiter_pointer_expression"]="not verified"
  with self.assertRaises(ValueError):audit(*a)
 def test_static_overlap_not_runtime(self):
  a=fixtures();a[2]["shared_kernel_stack_base_proven"]=True
  with self.assertRaises(ValueError):audit(*a)
 def test_changed_interval_rejected(self):
  a=fixtures();a[2]["arithmetic_intersection_bytes"]=128
  with self.assertRaises(ValueError):audit(*a)
 def test_unverified_uaf_assertion_rejected(self):
  a=fixtures();a[0]["queue_processing_or_rollback_executed_on_phone"]=True
  with self.assertRaises(ValueError):audit(*a)
 def test_unverified_root_assertion_rejected(self):
  a=fixtures();a[4]["ghostlock_root_demonstrated"]=True
  with self.assertRaises(ValueError):audit(*a)
 def test_cfi_flag_mismatch_rejected(self):
  a=fixtures();a[4]["flags"]["control_flow_and_stack"]["CONFIG_CFI_CLANG"]="n"
  with self.assertRaises(ValueError):audit(*a)
 def test_device_operations_forbidden(self):
  a=fixtures();a[2]["device_operations"]=1
  with self.assertRaises(ValueError):audit(*a)

if __name__=="__main__":unittest.main()
