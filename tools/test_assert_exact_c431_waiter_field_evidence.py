"""Synthetic-only tests for C431 source/ARM64 evidence binding."""
import hashlib,unittest
from unittest.mock import patch
import assert_exact_c431_waiter_field_evidence as checker

WAITER=b"""struct rt_mutex_waiter {
 struct rb_node tree_entry;
 struct rb_node pi_tree_entry;
 struct task_struct *task;
 struct rt_mutex *lock;
 int prio;
 u64 deadline;
};
"""
RTMUTEX=b"""void rt_mutex_init_waiter(struct rt_mutex_waiter *waiter)
{
 waiter->task = NULL;
}
void task_blocks_on_rt_mutex(struct rt_mutex_waiter *waiter, struct task_struct *task, struct rt_mutex *lock)
{
 waiter->task = task;
 waiter->lock = lock;
 waiter->prio = task->prio;
 waiter->deadline = task->dl.deadline;
}
"""

def binary():
 functions={}
 for name,addr,mnem,op in checker.CHECKS:
  entry=functions.setdefault(name,{'initial_instructions_for_register_flow':[]})
  entry['initial_instructions_for_register_flow'].append(
   {'address':addr,'mnemonic':mnem,'operand':op})
 return {'boot_sha256':checker.BOOT_SHA,
         'kernel_image_sha256':checker.KERNEL_SHA,'functions':functions}

class TestEvidence(unittest.TestCase):
 def verify_fixture(self,data=None,w=WAITER,r=RTMUTEX):
  with patch.object(checker,'WAITER_SRC_SHA',hashlib.sha256(WAITER).hexdigest()),\
       patch.object(checker,'RTMUTEX_SRC_SHA',hashlib.sha256(RTMUTEX).hexdigest()):
   return checker.verify(data if data is not None else binary(),w,r)
 def test_all_ten_instruction_sites_pass(self):
  report=self.verify_fixture()
  self.assertEqual(report['source_and_machine_code_assertions_passed'],19)
  self.assertFalse(report['full_ghostlock_profile_ready'])
 def test_wrong_waiter_lock_read_fails(self):
  data=binary()
  entries=data['functions']['rt_mutex_adjust_prio_chain']['initial_instructions_for_register_flow']
  next(i for i in entries if i['address']=='0xffffffc01037d3b0')['operand']='x8, [x25, #0x58]'
  with self.assertRaises(ValueError):self.verify_fixture(data)
 def test_missing_source_field_fails(self):
  with self.assertRaises(ValueError):self.verify_fixture(w=WAITER.replace(b' int prio;',b''))
 def test_source_hash_mismatch_fails(self):
  with self.assertRaises(ValueError):self.verify_fixture(w=WAITER+b'changed')
 def test_binary_provenance_fails(self):
  data=binary();data['kernel_image_sha256']='0'*64
  with self.assertRaises(ValueError):self.verify_fixture(data)
 def test_source_semantics_fails(self):
  with self.assertRaises(ValueError):
   self.verify_fixture(r=RTMUTEX.replace(b'waiter->task = NULL;',b'waiter->task = current;'))

if __name__=='__main__':unittest.main()
