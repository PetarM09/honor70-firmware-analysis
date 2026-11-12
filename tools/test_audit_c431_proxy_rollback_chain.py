"""No-device tests of the exact C431 proxy rollback source-to-binary audit."""
import hashlib,unittest
from audit_c431_proxy_rollback_chain import BOOT_SHA,KERNEL_SHA,SITES,verify

FUTEX=b"""long do_futex(void) {
 switch(cmd){ case FUTEX_CMP_REQUEUE_PI:
 return futex_requeue(uaddr, flags, uaddr2, val, val2, &val3, 1);
 }
}
static int futex_requeue(void) {
 if (uaddr1 == uaddr2) return -EINVAL;
 if ((requeue_pi && !this->rt_waiter) || (!requeue_pi && this->rt_waiter)) return -EINVAL;
 get_pi_state(pi_state);
 ret = rt_mutex_start_proxy_lock(&pi_state->pi_mutex, this->rt_waiter, this->task);
 if (ret == 1) { return 1; } else if (ret) { return ret; }
}
"""
RTMUTEX=b"""int rt_mutex_start_proxy_lock(void) {
 ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
 if (unlikely(ret)) remove_waiter(lock, waiter);
 return ret;
}
static void remove_waiter(void) {
 raw_spin_lock(&current->pi_lock);
 rt_mutex_dequeue(lock, waiter);
 current->pi_blocked_on = NULL;
}
"""

def binary():
    return {
        'boot_sha256':BOOT_SHA,'kernel_image_sha256':KERNEL_SHA,
        'functions': {
            name:{'initial_instructions_for_register_flow':[
                {'address':addr,'mnemonic':op,'operand':arg,'bytes':'d503201f'}
                for addr,op,arg in checks]}
            for name,checks in SITES.items()
        }
    }

class Tests(unittest.TestCase):
    def report(self,arm64=None,futex=FUTEX,rtmutex=RTMUTEX):
        return verify(binary() if arm64 is None else arm64,futex,rtmutex,
                      futex_sha=hashlib.sha256(FUTEX).hexdigest(),
                      rtmutex_sha=hashlib.sha256(RTMUTEX).hexdigest())

    def test_positive(self):
        r=self.report()
        self.assertEqual(r['original_arm64_assertions'],18)
        self.assertTrue(r['original_binary_proxy_wrapper_to_remove_waiter'])
        self.assertFalse(r['queue_processing_or_rollback_executed_on_phone'])

    def test_dispatch_must_select_pi(self):
        with self.assertRaises(ValueError):
            self.report(futex=FUTEX.replace(b'&val3, 1',b'&val3, 0'))

    def test_proxy_called_with_waiter_task(self):
        with self.assertRaises(ValueError):
            self.report(futex=FUTEX.replace(b'this->rt_waiter, this->task',
                                            b'this->rt_waiter, current'))

    def test_negative_result_rollback_required(self):
        with self.assertRaises(ValueError):
            self.report(rtmutex=RTMUTEX.replace(b'if (unlikely(ret))',b'if (!ret)'))

    def test_source_digest_mismatch(self):
        with self.assertRaises(ValueError):
            self.report(futex=FUTEX+b'other')

    def test_wrong_boot(self):
        m=binary();m['boot_sha256']='0'*64
        with self.assertRaises(ValueError):self.report(arm64=m)

    def test_wrong_signed_caller(self):
        m=binary()
        items=m['functions']['rt_mutex_start_proxy_lock']['initial_instructions_for_register_flow']
        next(i for i in items if i['operand']=='#0xffffffc01037e350')['operand']='#0xffffffc01037e354'
        with self.assertRaises(ValueError):self.report(arm64=m)

    def test_missing_instruction_bytes(self):
        m=binary()
        m['functions']['remove_waiter']['initial_instructions_for_register_flow'][0]['bytes']=''
        with self.assertRaises(ValueError):self.report(arm64=m)

    def test_duplicate_site_fails_closed(self):
        m=binary()
        items=m['functions']['remove_waiter']['initial_instructions_for_register_flow']
        items.append(dict(items[0]))
        with self.assertRaises(ValueError):self.report(arm64=m)

    def test_fixed_waiter_task_cleanup_is_not_marked_vulnerable(self):
        with self.assertRaises(ValueError):
            self.report(rtmutex=RTMUTEX.replace(b'&current->pi_lock',
                                                 b'&waiter->task->pi_lock'))

if __name__=="__main__":unittest.main()
