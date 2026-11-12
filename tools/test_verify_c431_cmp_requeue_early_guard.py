"""Strict synthetic tests for original-C431 futex equal-address guard audit."""
import hashlib
import unittest
from verify_c431_cmp_requeue_early_guard import BOOT_SHA, IMAGE_SHA, SITES, verify

SOURCE = b"""static int futex_requeue(u32 *uaddr1, int flags, u32 *uaddr2, int nr_wake, int nr_requeue, u32 *cmpval, int requeue_pi)
{
 if (nr_wake < 0 || nr_requeue < 0) return -EINVAL;
 if (!IS_ENABLED(CONFIG_FUTEX_PI) && requeue_pi) return -ENOSYS;
 if (uaddr1 == uaddr2) return -EINVAL;
 if (refill_pi_state_cache()) return -ENOMEM;
 if (nr_wake != 1) return -EINVAL;
 retry:
 ret = get_futex_key(uaddr1, flags & FLAGS_SHARED, &key1, FUTEX_READ);
}
"""
def sample():
    return {
        "boot_sha256": BOOT_SHA,
        "kernel_image_sha256": IMAGE_SHA,
        "functions": {
            "futex_requeue": {
                "symbol_va": "0xffffffc0103ca4d8",
                "initial_instructions_for_register_flow": [
                    {"address": a, "mnemonic": m, "operand": o, "bytes": "d503201f"}
                    for a, m, o in SITES
                ],
            }
        },
    }

class GuardTests(unittest.TestCase):
    def audit(self, report=None, source=SOURCE):
        return verify(
            sample() if report is None else report, source,
            expected_source=hashlib.sha256(SOURCE).hexdigest())

    def test_valid_early_guard(self):
        r = self.audit()
        self.assertTrue(r["equal_addresses_branch_before_kernel_queue_operations"])
        self.assertEqual(r["app_test_request"]["expected_error"], "EINVAL (22)")
        self.assertFalse(r["ghostlock_rollback_uaf_triggered"])

    def test_missing_sameaddr_guard(self):
        with self.assertRaises(ValueError):
            self.audit(source=SOURCE.replace(
                b"if (uaddr1 == uaddr2)", b"if (uaddr1 != uaddr2)"))

    def test_wrong_source_digest(self):
        with self.assertRaises(ValueError):
            self.audit(source=SOURCE + b"changed")

    def test_wrong_kernel(self):
        r=sample()
        r["kernel_image_sha256"]="0"*64
        with self.assertRaises(ValueError):
            self.audit(report=r)

    def test_wrong_branch_target(self):
        r=sample()
        ins=r["functions"]["futex_requeue"]["initial_instructions_for_register_flow"]
        next(x for x in ins if x["mnemonic"]=="b.eq")["operand"]="#0xffffffc0103ca580"
        with self.assertRaises(ValueError):
            self.audit(report=r)

    def test_duplicate_instruction_site(self):
        r=sample()
        ins=r["functions"]["futex_requeue"]["initial_instructions_for_register_flow"]
        ins.append(dict(ins[0]))
        with self.assertRaises(ValueError):
            self.audit(report=r)

    def test_invalid_bytes(self):
        r=sample()
        ins=r["functions"]["futex_requeue"]["initial_instructions_for_register_flow"]
        ins[0]["bytes"]="bad"
        with self.assertRaises(ValueError):
            self.audit(report=r)

    def test_guard_moved_after_futex_key_access(self):
        broken=SOURCE.replace(
            b"if (uaddr1 == uaddr2) return -EINVAL;",
            b"if (uaddr1 == uaddr2) return -EINVAL;") # only change required source order
        broken=broken.replace(
            b" if (uaddr1 == uaddr2) return -EINVAL;\n",
            b"")
        broken=broken.replace(
            b" ret = get_futex_key",
            b" if (uaddr1 == uaddr2) return -EINVAL;\n ret = get_futex_key")
        with self.assertRaises(ValueError):
            self.audit(source=broken)

if __name__ == "__main__":
    unittest.main()
