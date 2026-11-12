"""Offline synthetic tests; no ADB or phone required."""
import gzip
import unittest
from collect_fne_live_ikconfig_readonly import parse_config


def example(**flags):
    base = [f"CONFIG_TEST_{i:03}=y" for i in range(120)]
    base.extend(f"{key}={value}" for key, value in flags.items())
    return gzip.compress(("\n".join(base) + "\n").encode())


class Tests(unittest.TestCase):
    def test_enabled(self):
        result = parse_config(example(CONFIG_FUTEX="y", CONFIG_FUTEX_PI="y", CONFIG_RT_MUTEXES="y"))
        self.assertEqual(result["pi_futex_compile_prerequisites"], "confirmed_config_enabled")
        self.assertEqual(result["relevant_options"]["CONFIG_FUTEX_PI"], "y")

    def test_disabled(self):
        result = parse_config(example(CONFIG_FUTEX="y", CONFIG_FUTEX_PI="n", CONFIG_RT_MUTEXES="y"))
        self.assertEqual(result["pi_futex_compile_prerequisites"], "configuration_incomplete_or_disabled")

    def test_unknown(self):
        self.assertEqual(parse_config(example())["pi_futex_compile_prerequisites"], "inconclusive")

    def test_reject_plaintext(self):
        with self.assertRaises(ValueError):
            parse_config(b"not gzip")

    def test_reject_corrupt_gzip(self):
        with self.assertRaises(ValueError):
            parse_config(b"\x1f\x8b\x08broken")

    def test_reject_short_configuration(self):
        with self.assertRaises(ValueError):
            parse_config(gzip.compress(b"CONFIG_FUTEX_PI=y\n"))

    def test_unset_format(self):
        data = "\n".join([f"CONFIG_TEST_{i:03}=y" for i in range(120)] + ["# CONFIG_FUTEX_PI is not set"])
        result = parse_config(gzip.compress(data.encode()))
        self.assertEqual(result["relevant_options"]["CONFIG_FUTEX_PI"], "n")


if __name__ == "__main__":
    unittest.main()
