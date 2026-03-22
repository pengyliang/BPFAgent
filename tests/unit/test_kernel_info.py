# Unit test for kernel_info_collector.py
import json
import unittest
from pathlib import Path
from scripts.setup.kernel_info_collector import collect_kernel_info


class TestKernelInfoCollector(unittest.TestCase):
    def test_collect_kernel_info(self):
        logs_dir = Path("tests/logs")
        logs_dir.mkdir(parents=True, exist_ok=True)
        profile_path = logs_dir / "kernel_profile.json"

        collect_kernel_info(output_path=str(profile_path), artifacts_dir=str(logs_dir))
        self.assertTrue(profile_path.exists())

        with open(profile_path, "r", encoding="utf-8") as f:
            data = json.load(f)

            # Core sections from plan
            self.assertIn("kernel_version", data)
            self.assertIn("config", data)
            self.assertIn("btf", data)
            self.assertIn("helper_whitelist", data)
            self.assertIn("map_type_support", data)
            self.assertIn("program_type_support", data)
            self.assertIn("verifier_limits", data)
            self.assertIn("clang", data)
            self.assertIn("bpftool_feature_probe", data)

            # Kernel version split fields
            self.assertIn("major", data["kernel_version"])
            self.assertIn("minor", data["kernel_version"])
            self.assertIn("patch", data["kernel_version"])
            self.assertIn("distro_suffix", data["kernel_version"])

            # Type checks
            self.assertIsInstance(data["helper_whitelist"], list)
            self.assertIsInstance(data["map_type_support"], list)
            self.assertIsInstance(data["program_type_support"], list)
            self.assertIn("config", data)
            self.assertIsInstance(data["config"]["bpf_flags"], dict)

        # Keep all generated outputs in tests/logs.
        self.assertTrue((logs_dir / "kernel_profile.json").exists())

if __name__ == "__main__":
    unittest.main()