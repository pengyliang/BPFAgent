import tempfile
import unittest
from pathlib import Path

from src.util.deploy.runtime_tester import run_case_runtime_validation


class TestRuntimeTester(unittest.TestCase):
    def _make_runner(self, responses):
        state = {"idx": 0}

        def _runner(cmd, timeout=60, cwd=None):
            _ = timeout, cwd
            if state["idx"] >= len(responses):
                raise RuntimeError("unexpected command: %s" % " ".join(cmd))
            resp = responses[state["idx"]]
            state["idx"] += 1
            merged = {
                "command": cmd,
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            }
            merged.update(resp)
            merged["command"] = cmd
            return merged

        return _runner

    def test_runtime_validation_min_pass(self):
        with tempfile.TemporaryDirectory() as td:
            case_dir = Path(td)
            (case_dir / "workload.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            (case_dir / "validator.yaml").write_text(
                "type: min\nmap: counter\nkey: 0\nvalue: 3\n",
                encoding="utf-8",
            )

            runner = self._make_runner(
                [
                    {},
                    {"stdout": '{"id": 11, "map_ids": [101]}'},
                    {"stdout": '{"id": 101, "name": "counter"}'},
                    {"stdout": '{"key": [0, 0, 0, 0], "value": [4, 0, 0, 0, 0, 0, 0, 0]}'},
                ]
            )

            result = run_case_runtime_validation(
                case_dir=case_dir,
                pin_path="/sys/fs/bpf/ebpf_agent_test",
                run_command=runner,
            )

            self.assertTrue(result["success"])
            self.assertFalse(result["skipped"])
            self.assertEqual(result["reason"], "validator_passed")
            self.assertEqual(result["actual_value"], 4)

    def test_runtime_validation_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            case_dir = Path(td)
            (case_dir / "workload.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            (case_dir / "validator.yaml").write_text(
                "type: min\nmap: counter\nkey: 0\nvalue: 3\n",
                encoding="utf-8",
            )

            runner = self._make_runner(
                [
                    {},
                    {"stdout": '{"id": 11, "map_ids": [101]}'},
                    {"stdout": '{"id": 101, "name": "counter"}'},
                    {"stdout": '{"key": [0, 0, 0, 0], "value": [2, 0, 0, 0, 0, 0, 0, 0]}'},
                ]
            )

            result = run_case_runtime_validation(
                case_dir=case_dir,
                pin_path="/sys/fs/bpf/ebpf_agent_test",
                run_command=runner,
            )

            self.assertFalse(result["success"])
            self.assertEqual(result["reason"], "validator_mismatch")
            self.assertEqual(result["actual_value"], 2)

    def test_runtime_validation_skips_when_workload_missing(self):
        with tempfile.TemporaryDirectory() as td:
            case_dir = Path(td)
            (case_dir / "validator.yaml").write_text(
                "type: min\nmap: counter\nkey: 0\nvalue: 3\n",
                encoding="utf-8",
            )

            result = run_case_runtime_validation(
                case_dir=case_dir,
                pin_path="/sys/fs/bpf/ebpf_agent_test",
            )

            self.assertTrue(result["success"])
            self.assertTrue(result["skipped"])
            self.assertEqual(result["reason"], "workload_not_found")

    def test_runtime_validation_supports_pinned_link(self):
        with tempfile.TemporaryDirectory() as td:
            case_dir = Path(td)
            (case_dir / "workload.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            (case_dir / "validator.yaml").write_text(
                "type: min\nmap: counter\nkey: 0\nvalue: 3\n",
                encoding="utf-8",
            )

            runner = self._make_runner(
                [
                    {},
                    {"stdout": '{"error":"incorrect object type: link"}'},
                    {"stdout": '{"id": 7, "prog_id": 11}'},
                    {"stdout": '{"id": 11, "map_ids": [101]}'},
                    {"stdout": '{"id": 101, "name": "counter"}'},
                    {"stdout": '{"key": [0, 0, 0, 0], "value": [3, 0, 0, 0, 0, 0, 0, 0]}'},
                ]
            )

            result = run_case_runtime_validation(
                case_dir=case_dir,
                pin_path="/sys/fs/bpf/ebpf_agent_test",
                run_command=runner,
            )

            self.assertTrue(result["success"])
            self.assertEqual(result["reason"], "validator_passed")


if __name__ == "__main__":
    unittest.main()
