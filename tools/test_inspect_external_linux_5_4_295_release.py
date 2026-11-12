"""Regression tests for read-only inspection of third-party kernel archives."""
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from inspect_external_linux_5_4_295_release import (
    collect_sources, extract_function, inspect, name_of_interest,
    normalized_path, version_from_makefile,
)

class Tests(unittest.TestCase):
    def test_path_selection(self):
        self.assertEqual(name_of_interest("linux-5.4.295/kernel/futex.c"),
                         "kernel/futex.c")
        self.assertIsNone(name_of_interest("random/dir/irrelevant.txt"))
        self.assertIsNone(normalized_path("../../etc/passwd"))
    def test_version_detect(self):
        self.assertEqual(version_from_makefile(
            b"VERSION = 5\nPATCHLEVEL = 4\nSUBLEVEL = 295\nNAME = Test\n")["SUBLEVEL"],
            "295")
    def test_empty_extra_version_does_not_capture_next_line(self):
        values=version_from_makefile(
            b"VERSION = 5\nPATCHLEVEL = 4\nSUBLEVEL = 295\nEXTRAVERSION =\nNAME = Kleptomaniac Octopus\n")
        self.assertEqual(values["EXTRAVERSION"],"")
        self.assertEqual(values["NAME"],"Kleptomaniac Octopus")
    def test_honor_scheduler_vendor_extensions_are_not_generic(self):
        entries={
            "Makefile":{"archive_path":"linux/Makefile","data":b"VERSION = 5\n"},
            "include/linux/sched.h":{"archive_path":"linux/include/linux/sched.h",
                                     "data":b"struct task_struct {};\n"}
        }
        reference={"include/linux/sched.h":
            b"ANDROID_KABI_RESERVE(1);\n#ifdef CONFIG_HN_VIP_THREAD\n"
            b"#endif\n#ifdef CONFIG_HONOR_SCHED_VIP\n#endif\n"}
        result=inspect(entries,reference)
        checks=result["oem_scheduler_layout_warnings"]
        self.assertTrue(checks["honor_has_ANDROID_KABI_RESERVE"])
        self.assertFalse(checks["generic_has_ANDROID_KABI_RESERVE"])
        self.assertFalse(checks["unmodified_struct_task_layout_usable_as_C431_ABI"])
    def test_single_function_extraction(self):
        source="static void remove_waiter(struct x *a) {\n if (a) { current->pi_blocked_on = NULL; }\n}"
        result=extract_function(source,"remove_waiter")
        self.assertIn("current->pi_blocked_on", result)
    def test_missing_function(self):
        self.assertIsNone(extract_function("int unrelated(void) { return 1; }",
                                           "remove_waiter"))
    def test_different_function_not_claimed_identical(self):
        entries={
            "Makefile":{"archive_path":"linux/Makefile","data":b"VERSION=5\n"},
            "kernel/futex.c":{"archive_path":"linux/kernel/futex.c",
                              "data":b"int futex_requeue(void){return 0;}\n"},
            "kernel/locking/rtmutex.c":{"archive_path":"linux/kernel/locking/rtmutex.c",
                                        "data":b"void remove_waiter(void){return;}\n"}}
        r=inspect(entries,{
            "kernel/futex.c":b"int futex_requeue(void){return 7;}\n",
            "kernel/locking/rtmutex.c":b"void remove_waiter(void){return;}\n"})
        self.assertFalse(r["fennie_comparison"]["kernel/futex.c"]["exact_byte_match"])
        self.assertTrue(r["fennie_comparison"]["kernel/locking/rtmutex.c"]["exact_byte_match"])
        self.assertFalse(r["exact_c431_binary_ABI_validated_by_generic_source"])
        self.assertEqual(r["unresolved_profile_fields_auto_filled"],0)
    def test_archive_reader_selects_without_extracting(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"test.tar.xz"
            with tarfile.open(path,"w:xz") as archive:
                for name,data in [
                        ("linux-5.4.295/Makefile",b"VERSION = 5\n"),
                        ("linux-5.4.295/kernel/futex.c",b"int hello;\n"),
                        ("linux-5.4.295/include/linux/cred.h",b"struct cred {};\n"),
                        ("linux-5.4.295/README",b"ignore\n")]:
                    info=tarfile.TarInfo(name)
                    info.size=len(data)
                    archive.addfile(info,io.BytesIO(data))
            result,count,skipped,dups=collect_sources(path)
            self.assertEqual(count,4)
            self.assertIn("kernel/futex.c",result)
            self.assertIn("include/linux/cred.h",result)
            self.assertNotIn("README",result)
    def test_compare_marks_runtime_not_proven(self):
        r=inspect({"Makefile":{"archive_path":"linux/Makefile","data":b"VERSION=5\n"}},
                  {})
        self.assertFalse(r["root_or_uaf_triggered"])
        self.assertEqual(r["device_operations"],0)

if __name__=="__main__":
    unittest.main()
