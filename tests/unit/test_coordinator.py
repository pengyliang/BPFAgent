import json
import tempfile
import unittest
from pathlib import Path

from src.core.coordinator import Coordinator, CoordinatorConfig


class TestCoordinator(unittest.TestCase):
    def test_run_static_check_can_be_disabled(self):
        coordinator = Coordinator(config=CoordinatorConfig(enable_static_check=False))

        with tempfile.TemporaryDirectory() as td:
            output_path = Path(td) / "static_check.json"
            report = coordinator.run_static_check(
                summaries=[{"source_file": "dummy.bpf.c"}],
                kernel_profile={},
                output_path=str(output_path),
            )

            self.assertTrue(report["success"])
            self.assertTrue(report["skipped"])
            self.assertEqual(report["reason"], "disabled")
            self.assertEqual(report["error_warning_count"], {"error": 0, "warning": 0})
            self.assertEqual(report["issues"], [])

            persisted = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted, report)


if __name__ == "__main__":
    unittest.main()
