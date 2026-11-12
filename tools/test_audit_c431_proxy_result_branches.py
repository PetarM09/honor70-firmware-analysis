"""Synthetic no-device regression tests for exact C431 proxy-result branches."""
import hashlib
import unittest

from audit_c431_proxy_result_branches import BOOT_SHA,IMAGE_SHA,SITES,BASE,audit

SRC=b'''
int __rt_mutex_start_proxy_lock(struct rt_mutex *lock, struct rt_mutex_waiter *waiter, struct task_struct *task) {
 if (try_to_take_rt_mutex(lock, task, NULL)) return 1;
 ret = task_blocks_on_rt_mutex(lock, waiter, task, 1);
 if (ret && !rt_mutex_owner(lock)) ret = 0;
 return ret;
}
int rt_mutex_start_proxy_lock(struct rt_mutex *lock, struct rt_mutex_waiter *waiter, struct task_struct *task) {
 ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
 if (unlikely(ret)) remove_waiter(lock, waiter);
 return ret;
}
static void remove_waiter(struct rt_mutex *lock, struct rt_mutex_waiter *waiter) {
 raw_spin_lock(&current->pi_lock);
 current->pi_blocked_on = NULL;
}
'''
def sample():
    return {'boot_sha256':BOOT_SHA,'kernel_image_sha256':IMAGE_SHA,
      'functions':{'rt_mutex_start_proxy_lock':{
        'symbol_va':BASE,
        'initial_instructions_for_register_flow':[
          {'address':addr,'mnemonic':op,'operand':operand,'bytes':'d503201f'}
          for addr,op,operand in SITES]}}}

class BranchTests(unittest.TestCase):
    def check(self,report=None,src=SRC):
        return audit(sample() if report is None else report,src,
                     expected_source=hashlib.sha256(SRC).hexdigest())
    def test_classifies_four_paths(self):
        r=self.check()
        self.assertEqual(r['original_arm64_instruction_assertions'],23)
        self.assertEqual([x['remove_waiter_called'] for x in r['distinct_original_control_flow_cases']],
                         [True,False,True,False])
        self.assertEqual(r['temporary_root_or_bootloader_unlock'],'not demonstrated')
    def test_incorrect_branch_target_rejected(self):
        x=sample();sites=x['functions']['rt_mutex_start_proxy_lock']['initial_instructions_for_register_flow']
        next(i for i in sites if i['address']=='0xffffffc01037e2f0')['operand']='w0, #0xffffffc01037e300'
        with self.assertRaises(ValueError):self.check(x)
    def test_wrong_result_value_rejected(self):
        x=sample();sites=x['functions']['rt_mutex_start_proxy_lock']['initial_instructions_for_register_flow']
        next(i for i in sites if i['address']=='0xffffffc01037e2f4')['operand']='w21, #0'
        with self.assertRaises(ValueError):self.check(x)
    def test_cleanup_target_must_match(self):
        x=sample();sites=x['functions']['rt_mutex_start_proxy_lock']['initial_instructions_for_register_flow']
        next(i for i in sites if i['address']=='0xffffffc01037e300')['operand']='#0xffffffc01037e354'
        with self.assertRaises(ValueError):self.check(x)
    def test_reject_fixed_return_condition_source(self):
        with self.assertRaises(ValueError):
            self.check(src=SRC.replace(b'if (unlikely(ret))',b'if (ret < 0)'))
    def test_reject_source_not_using_current(self):
        with self.assertRaises(ValueError):
            self.check(src=SRC.replace(b'&current->pi_lock',b'&waiter->task->pi_lock'))
    def test_reject_untrusted_binary(self):
        x=sample();x['kernel_image_sha256']='0'*64
        with self.assertRaises(ValueError):self.check(x)
    def test_reject_wrong_source_sha(self):
        with self.assertRaises(ValueError):self.check(src=SRC+b'changed')
    def test_reject_ambiguous_site(self):
        x=sample();sites=x['functions']['rt_mutex_start_proxy_lock']['initial_instructions_for_register_flow']
        sites.append(dict(sites[0]))
        with self.assertRaises(ValueError):self.check(x)
    def test_reject_missing_instruction_bytes(self):
        x=sample();sites=x['functions']['rt_mutex_start_proxy_lock']['initial_instructions_for_register_flow']
        sites[0]['bytes']=''
        with self.assertRaises(ValueError):self.check(x)
if __name__=='__main__':unittest.main()
