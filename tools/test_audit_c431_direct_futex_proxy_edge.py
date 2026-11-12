"""Synthetic tests for fail-closed exact C431 direct branch scanning."""
import unittest
from audit_c431_direct_futex_proxy_edge import (
    parse_text_symbols,scan_symbol_bounds,summarize_disassembly
)

SYMBOLS="""
ffffffc01037e2c0 T rt_mutex_start_proxy_lock
ffffffc01037e350 t remove_waiter
ffffffc0103ca4d8 t futex_requeue
ffffffc0103cb900 t next_func
"""
class Tests(unittest.TestCase):
    def test_next_symbol_bounds(self):
        start,end,size,complete=scan_symbol_bounds(parse_text_symbols(SYMBOLS))
        self.assertEqual(start,0xffffffc0103ca4d8)
        self.assertEqual(end,0xffffffc0103cb900)
        self.assertTrue(complete)
        self.assertEqual(size,end-start)
    def test_wrong_original_symbol_fails(self):
        with self.assertRaises(ValueError):
            scan_symbol_bounds(parse_text_symbols(
                SYMBOLS.replace('ffffffc0103ca4d8','ffffffc0103ca4dc')))
    def test_missing_next_symbol_fails(self):
        with self.assertRaises(ValueError):
            scan_symbol_bounds(parse_text_symbols(
                SYMBOLS.replace('ffffffc0103cb900 t next_func','')))
    def test_ambiguous_symbol_fails(self):
        with self.assertRaises(ValueError):
            scan_symbol_bounds(parse_text_symbols(
                SYMBOLS+'ffffffc0103ca4dc t futex_requeue\n'))
    def test_direct_call_site(self):
        ins=[{'address':'0x1','mnemonic':'mov','operand':'x0, x1'},
             {'address':'0x2','mnemonic':'bl','operand':'#0xffffffc01037e2c0'},
             {'address':'0x3','mnemonic':'bl','operand':'#0xffffffc01037e2c4'}]
        sites=summarize_disassembly(ins)
        self.assertEqual(len(sites),1)
        self.assertEqual(sites[0]['site'],'0x2')
    def test_indirect_call_not_claimed(self):
        self.assertEqual(summarize_disassembly([
            {'address':'0x1','mnemonic':'blr','operand':'x8'}]),[])
    def test_bounded_when_too_large(self):
        x=scan_symbol_bounds(parse_text_symbols(
            SYMBOLS.replace('ffffffc0103cb900','ffffffc0103f0000')))
        self.assertFalse(x[3])
        self.assertEqual(x[2],0x10000)

if __name__=='__main__':unittest.main()
