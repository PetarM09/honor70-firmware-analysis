"""Offline synthetic tests; no phone, root or firmware files."""
import hashlib,unittest
from audit_oem_c431_struct_drift import audit,option_value,positions

def example(new=False):
    prefix='struct task_struct {\n void *stack;\n'
    if new:prefix+='#ifdef CONFIG_HN_VIP_RUNNABLE_TIME_LIMIT\n u64 hn_vip_last_queued;\n#endif\n'
    sched=prefix+'const struct cred __rcu *real_cred;\nconst struct cred __rcu *cred;\nraw_spinlock_t pi_lock;\nstruct rt_mutex_waiter *pi_blocked_on;\n};\n'
    cfg='CONFIG_HN_VIP_THREAD=y\nCONFIG_HN_VIP_RUNNABLE_TIME_LIMIT='+('y' if new else 'n')+'\n'
    src={'include_sched_h':sched,'merge_lahaina_defconfig':cfg,
         'kernel_rtmutex_common_h':'struct rt_mutex_waiter { int prio; };',
         'kernel_makefile':'VERSION = 5\nPATCHLEVEL = 4\n'}
    return {k:{'text':v,'sha256':hashlib.sha256(v.encode()).hexdigest()}
            for k,v in src.items()}

class TestAudit(unittest.TestCase):
    def test_source_drift(self):
        r=audit(example(),example(True))
        self.assertEqual(r['source_level_struct_layout_drift_risk'],'supported')
        self.assertFalse(r['ghostlock_profile_ready'])
        self.assertEqual(r['effect_on_real_C431_field_offsets'],'not_established')
    def test_no_drift(self):
        self.assertEqual(audit(example(),example())['source_level_struct_layout_drift_risk'],'inconclusive')
    def test_unset(self):
        self.assertEqual(option_value('# CONFIG_FUTEX_PI is not set','CONFIG_FUTEX_PI'),'n')
    def test_conflict(self):
        self.assertEqual(option_value('CONFIG_FUTEX_PI=y\nCONFIG_FUTEX_PI=n','CONFIG_FUTEX_PI'),'conflicting')
    def test_field_absence(self):
        self.assertIsNone(positions(example()['include_sched_h']['text'])['vip_last_queued']['line'])
    def test_incomplete(self):
        bad=example(True);bad.pop('kernel_rtmutex_common_h')
        with self.assertRaises(ValueError):audit(example(),bad)
    def test_early_vs_late_field(self):
        b=example(True)
        raw=b['include_sched_h']['text'].replace('u64 hn_vip_last_queued;','')
        raw=raw.replace('raw_spinlock_t pi_lock;', 'raw_spinlock_t pi_lock;\nu64 hn_vip_last_queued;')
        b['include_sched_h']={'text':raw,'sha256':hashlib.sha256(raw.encode()).hexdigest()}
        self.assertEqual(audit(example(),b)['source_level_struct_layout_drift_risk'],'inconclusive')

if __name__=='__main__':unittest.main()
