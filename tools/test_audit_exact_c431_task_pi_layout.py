"""Offline-only tests for exact-C431 task PI evidence checker."""
import hashlib
import unittest
from audit_exact_c431_task_pi_layout import BOOT_SHA, KERNEL_SHA, SITES, verify

SCHED = b"""struct task_struct {
    int prio;
    struct sched_dl_entity dl;
    raw_spinlock_t pi_lock;
    struct rb_root_cached pi_waiters;
    struct rt_mutex_waiter *pi_blocked_on;
};
"""
RTMUTEX = b"""void task_blocks_on_rt_mutex(void) {
    waiter->prio = task->prio;
    waiter->deadline = task->dl.deadline;
}
"""

def valid_report():
    funcs = {}
    for fn, addr, mnemonic, operand in SITES:
        f = funcs.setdefault(fn, {"initial_instructions_for_register_flow": []})
        f["initial_instructions_for_register_flow"].append(
            {"address": addr, "mnemonic": mnemonic, "operand": operand, "bytes": "d503201f"})
    return {"boot_sha256": BOOT_SHA, "kernel_image_sha256": KERNEL_SHA, "functions": funcs}

class Tests(unittest.TestCase):
    def check(self, report=None, sched=SCHED, rtmutex=RTMUTEX):
        return verify(
            valid_report() if report is None else report, sched, rtmutex,
            expected_sched=hashlib.sha256(SCHED).hexdigest(),
            expected_rtmutex=hashlib.sha256(RTMUTEX).hexdigest())

    def test_exact_sites_with_synthetic_fixture(self):
        result = self.check()
        self.assertEqual(result["independent_original_arm64_instruction_sites_confirmed"], len(SITES))
        self.assertEqual(len(result["task_struct_fields"]), 6)
        self.assertFalse(result["kernel_root_demonstrated"])

    def test_modified_instruction_fails(self):
        report = valid_report()
        ins = report["functions"]["task_blocks_on_rt_mutex"]["initial_instructions_for_register_flow"]
        ins[4]["operand"] = "x20, x1"
        with self.assertRaises(ValueError):
            self.check(report)

    def test_duplicate_instruction_address_fails(self):
        report = valid_report()
        ins = report["functions"]["remove_waiter"]["initial_instructions_for_register_flow"]
        ins.append(dict(ins[0]))
        with self.assertRaises(ValueError):
            self.check(report)

    def test_wrong_kernel_hash_fails(self):
        report = valid_report()
        report["kernel_image_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.check(report)

    def test_missing_source_field_fails(self):
        with self.assertRaises(ValueError):
            self.check(sched=SCHED.replace(b"pi_waiters;", b"pi_waiters2;"))

    def test_gpl_source_digest_mismatch_fails(self):
        with self.assertRaises(ValueError):
            self.check(sched=SCHED + b"altered")

    def test_mismatched_source_role_fails(self):
        with self.assertRaises(ValueError):
            self.check(rtmutex=RTMUTEX.replace(b"waiter->prio = task->prio;",
                                               b"waiter->prio = current->prio;"))

    def test_missing_instruction_bytes_fails(self):
        report = valid_report()
        report["functions"]["remove_waiter"]["initial_instructions_for_register_flow"][0]["bytes"] = ""
        with self.assertRaises(ValueError):
            self.check(report)

if __name__ == "__main__":
    unittest.main()
