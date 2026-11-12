"""Synthetic tests for release source scanner; no network or handset."""
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from audit_honor_fennie_release_sources import Auditor


class Tests(unittest.TestCase):
    def test_find_real_core_source_in_zip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Fennie.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("kernel/locking/rtmutex.c",
                           "void remove_waiter(void) { current->pi_blocked_on = NULL; }")
                z.writestr("kernel/futex.c", "void futex_requeue(void) {}")
            a = Auditor()
            with zipfile.ZipFile(p) as z:
                a.visit(p.name, z)
            r = a.report({"asset": p.name})
            self.assertEqual(r["statistics"]["files_matched"], 2)
            self.assertTrue(r["term_index"]["remove_waiter"])
            self.assertFalse(r["exact_c431_source_revision_proven"])

    def test_detect_nested_zip_and_source(self):
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as z:
            z.writestr("kernel/locking/rtmutex.c", "remove_waiter")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Fennie.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("kernel_src.zip", nested.getvalue())
            a = Auditor()
            with zipfile.ZipFile(p) as z:
                a.visit(p.name, z)
            self.assertEqual(a.stats["files_matched"], 1)
            self.assertTrue(a.nested[0]["inspected"])

    def test_detect_nested_tar(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tf:
            raw = b"CONFIG_FUTEX_PI=y\n"
            ti = tarfile.TarInfo("arch/arm64/configs/fennie_defconfig")
            ti.size = len(raw)
            tf.addfile(ti, io.BytesIO(raw))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Fennie.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("kernel_source.tar.gz", archive.getvalue())
            a = Auditor()
            with zipfile.ZipFile(p) as z:
                a.visit(p.name, z)
            self.assertEqual(a.stats["files_matched"], 1)

    def test_non_source_files_are_skipped(self):
        a = Auditor()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "not-source.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("irrelevant.bin", b"AAAA")
            with zipfile.ZipFile(p) as z:
                a.visit(p.name, z)
        self.assertEqual(a.stats["files_matched"], 0)


if __name__ == "__main__":
    unittest.main()
