"""No-device tests for filename-only HONOR source archive inventory."""
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from inventory_honor_opensource_archive import classify, inventory


class HonorInventoryTests(unittest.TestCase):
    def test_relevant_kernel_paths(self):
        data = classify([
            "src/kernel/locking/rtmutex.c",
            "src/kernel/futex.c",
            "src/include/linux/rtmutex.h",
            "src/arch/arm64/configs/vendor/fennie_defconfig",
            "src/kernel/Makefile",
        ])
        self.assertEqual(data["entries"], 5)
        self.assertEqual(len(data["matches"]["rtmutex_source"]), 2)
        self.assertEqual(len(data["matches"]["futex_source"]), 1)
        self.assertEqual(len(data["matches"]["kernel_config"]), 1)

    def test_nested_package_not_opened(self):
        result = classify(["MagicOS8.0-ROM-Fennie/kernel.tar.gz", "README.md"])
        self.assertEqual(result["entries"], 2)
        self.assertEqual(len(result["nested_archives"]), 1)
        self.assertEqual(result["matches"]["futex_source"], [])

    def test_zip_without_extract(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "source.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("kernel/locking/rtmutex.c", "dummy source")
            kind, result = inventory(p)
            self.assertEqual(kind, "zip")
            self.assertEqual(result["entries"], 1)
            self.assertEqual(len(result["matches"]["rtmutex_source"]), 1)

    def test_tar_without_extract(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "source.tar.gz"
            with tarfile.open(p, "w:gz") as t:
                content = b"dummy source"
                info = tarfile.TarInfo("kernel/futex.c")
                info.size = len(content)
                t.addfile(info, io.BytesIO(content))
            kind, result = inventory(p)
            self.assertEqual(kind, "tar")
            self.assertEqual(len(result["matches"]["futex_source"]), 1)

    def test_invalid_archive_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.zip"
            p.write_bytes(b"not an archive")
            with self.assertRaises(ValueError):
                inventory(p)


if __name__ == "__main__":
    unittest.main()
