import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import platform

from src.util.deploy.executor import (
    compile_bpf_program,
    deploy_bpf_program,
    load_bpf_program,
    load_bpf_program_with_libbpf_loader,
    make_deploy_result_summary,
    parse_verifier_log,
)


class TestDeployExecutor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bpf_sources = sorted(Path("tests/data").glob("*.bpf.c"))
        if not cls.bpf_sources:
            raise RuntimeError("No .bpf.c test files found in tests/data")

    def test_parse_verifier_log_classification(self):
        log = """
invalid mem access 'scalar'
R1 type=scalar expected=map_ptr
program too large
"""
        parsed = parse_verifier_log(log)
        self.assertEqual(parsed["primary_error_type"], "invalid_mem_access")
        self.assertIn("invalid_mem_access", parsed["error_types"])
        self.assertIn("reg_type_mismatch", parsed["error_types"])
        self.assertIn("insn_limit_exceeded", parsed["error_types"])
        self.assertGreater(len(parsed["key_lines"]), 0)

    def test_make_deploy_result_summary_marks_skipped_as_unknown(self):
        summary = make_deploy_result_summary(
            {
                "success": False,
                "stage": "static_check_failed",
                "static_check": {
                    "success": False,
                    "error_warning_count": {"error": 1, "warning": 0},
                    "issues": [{"message": "core requires btf"}],
                },
                "compile": {"success": True, "stage": "compile", "skipped": True, "reason": "static_check_failed"},
                "load": {"success": True, "stage": "load", "skipped": True, "reason": "static_check_failed"},
                "attach": {"success": True, "stage": "attach", "skipped": True, "reason": "static_check_failed"},
                "runtime": {"success": True, "stage": "runtime_test", "skipped": True, "reason": "static_check_failed"},
                "detach": {"success": False, "stage": "detach", "reason": "unpin_failed"},
            }
        )

        self.assertEqual(summary["stage"], "static_check_failed")
        self.assertNotIn("static_check", summary)
        self.assertNotIn("detach", summary["steps"])
        self.assertEqual(summary["steps"]["static_check"]["status"], "failed")
        self.assertEqual(summary["steps"]["compile"]["status"], "unknown")
        self.assertIsNone(summary["steps"]["compile"]["success"])
        self.assertEqual(summary["steps"]["compile"]["reason"], "static_check_failed")

    @patch("src.util.deploy.executor._build_libbpf_loader")
    @patch("src.util.deploy.executor._safe_remove_tree")
    @patch("src.util.deploy.executor._safe_unpin")
    @patch("src.util.deploy.executor._run_command")
    def test_deploy_uses_loader_for_load_and_attach(
        self,
        run_cmd_mock,
        safe_unpin_mock,
        safe_remove_tree_mock,
        build_mock,
    ):
        safe_unpin_mock.return_value = True
        safe_remove_tree_mock.return_value = True
        build_mock.return_value = {
            "success": True,
            "loader_bin": "/tmp/loader",
            "command": ["make"],
            "stdout": "",
            "stderr": "",
            "returncode": 0,
            "timed_out": False,
        }
        run_cmd_mock.side_effect = [
            {
                "command": [],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            },
            {
                "command": [],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            },
            {
                "command": [],
                "returncode": 0,
                "stdout": "loaded_and_attached=1\n",
                "stderr": "",
                "timed_out": False,
            },
        ]

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "trace_case.bpf.c"
            src.write_text(
                '#include <bpf/bpf_helpers.h>\nSEC("tracepoint/syscalls/sys_enter_openat") int x(void *ctx){return 0;}\n',
                encoding="utf-8",
            )

            report = deploy_bpf_program(
                source_file=str(src),
                pin_path=str(Path(td) / "pin_prog"),
                object_file=str(Path(td) / "trace_case.bpf.o"),
            )

        self.assertTrue(report["success"])
        self.assertTrue(report["load"]["via_libbpf_loader"])
        self.assertEqual(report["attach"]["reason"], "attached_with_libbpf_loader")

    @patch("src.util.deploy.executor._build_libbpf_loader")
    @patch("src.util.deploy.executor._safe_remove_tree")
    @patch("src.util.deploy.executor._safe_unpin")
    @patch("src.util.deploy.executor._run_command")
    def test_load_with_libbpf_loader_success(self, run_cmd_mock, safe_unpin_mock, safe_remove_tree_mock, build_mock):
        build_mock.return_value = {
            "success": True,
            "loader_bin": "/tmp/loader",
            "command": ["make"],
            "stdout": "",
            "stderr": "",
            "returncode": 0,
            "timed_out": False,
        }
        safe_unpin_mock.return_value = True
        safe_remove_tree_mock.return_value = True
        run_cmd_mock.side_effect = [
            {
                "command": [],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            },
            {
                "command": [],
                "returncode": 0,
                "stdout": "loaded_and_attached=1\n",
                "stderr": "",
                "timed_out": False,
            },
        ]

        with tempfile.TemporaryDirectory() as td:
            pin = Path(td) / "prog_pin"
            result = load_bpf_program_with_libbpf_loader(
                object_file="tests/logs/test_ebpf.bpf.o",
                pin_path=str(pin),
            )

        self.assertTrue(result["success"])
        self.assertTrue(result["via_libbpf_loader"])
        self.assertIn("--obj", result["command"])
        self.assertIn("--pin-path", result["command"])

    @patch("src.util.deploy.executor._build_libbpf_loader")
    @patch("src.util.deploy.executor._safe_remove_tree")
    @patch("src.util.deploy.executor._safe_unpin")
    @patch("src.util.deploy.executor.run_case_runtime_validation")
    @patch("src.util.deploy.executor._run_command")
    def test_deploy_uses_libbpf_loader(
        self,
        run_cmd_mock,
        runtime_mock,
        safe_unpin_mock,
        safe_remove_tree_mock,
        build_mock,
    ):
        safe_unpin_mock.return_value = True
        safe_remove_tree_mock.return_value = True
        build_mock.return_value = {
            "success": True,
            "loader_bin": "/tmp/loader",
            "command": ["make"],
            "stdout": "",
            "stderr": "",
            "returncode": 0,
            "timed_out": False,
        }
        runtime_mock.return_value = {
            "success": True,
            "stage": "runtime_test",
            "skipped": False,
            "reason": "validator_passed",
        }
        run_cmd_mock.side_effect = [
            {
                "command": [],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            },
            {
                "command": [],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            },
            {
                "command": [],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            },
            {
                "command": [],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            },
        ]

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "trace_case.bpf.c"
            src.write_text(
                '#include <bpf/bpf_helpers.h>\nSEC("tracepoint/syscalls/sys_enter_openat") int x(void *ctx){return 0;}\n',
                encoding="utf-8",
            )

            report = deploy_bpf_program(
                source_file=str(src),
                pin_path=str(Path(td) / "pin_prog"),
                object_file=str(Path(td) / "trace_case.bpf.o"),
            )

        self.assertTrue(report["success"])
        self.assertTrue(report["load"]["via_libbpf_loader"])
        self.assertEqual(report["attach"]["reason"], "attached_with_libbpf_loader")

    @patch("src.util.deploy.executor._run_command")
    def test_compile_command_and_success(self, run_cmd_mock):
        run_cmd_mock.return_value = {
            "command": [],
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
        }

        for src in self.bpf_sources:
            stem = src.name.replace(".bpf.c", "")
            result = compile_bpf_program(
                source_file=str(src),
                object_file=f"tests/logs/{stem}.bpf.o",
                mcpu="v3",
                extra_cflags=["-DTEST=1"],
            )

            self.assertTrue(result["success"])
            self.assertEqual(result["compile_mode"], "non-core")
            self.assertIn("-target", result["command"])
            self.assertIn("bpf", result["command"])
            self.assertIn(f"-I/usr/include/{platform.machine()}-linux-gnu", result["command"])
            self.assertIn("-mcpu", result["command"])
            self.assertIn("v3", result["command"])
            self.assertIn("-DTEST=1", result["command"])

    @patch("src.util.deploy.executor._run_command")
    def test_compile_auto_detects_core_mode(self, run_cmd_mock):
        run_cmd_mock.side_effect = [
            {
                "command": [],
                "returncode": 0,
                "stdout": "/* fake vmlinux.h */\nstruct task_struct {};\n",
                "stderr": "",
                "timed_out": False,
            },
            {
                "command": [],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            },
        ]

        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "core_case.bpf.c"
            source.write_text(
                '#include "vmlinux.h"\nint x(void *ctx){return BPF_CORE_READ(ctx, pid);}\n',
                encoding="utf-8",
            )
            result = compile_bpf_program(
                source_file=str(source),
                object_file=str(Path(td) / "core_case.bpf.o"),
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["compile_mode"], "core")
        cmd = result["command"]
        self.assertTrue(any(part.startswith("-D__TARGET_ARCH_") for part in cmd))
        self.assertIn(f"-I{source.parent}", cmd)
        self.assertTrue(result["vmlinux_header"].endswith("vmlinux.h"))
        self.assertIn(f"-I{Path(result['vmlinux_header']).parent}", cmd)

    @patch("src.util.deploy.executor._run_command")
    def test_compile_core_generation_failure(self, run_cmd_mock):
        run_cmd_mock.side_effect = [
            {
                "command": [],
                "returncode": 1,
                "stdout": "",
                "stderr": "bpftool failed",
                "timed_out": False,
            },
            {
                "command": [],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            },
        ]

        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "core_case_fail.bpf.c"
            source.write_text('#include "vmlinux.h"\nint x(void *ctx){return 0;}\n', encoding="utf-8")
            result = compile_bpf_program(
                source_file=str(source),
                object_file=str(Path(td) / "core_case_fail.bpf.o"),
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["compile_mode"], "non-core")
        self.assertIsNone(result["vmlinux_header"])
        self.assertFalse(result["vmlinux_generation"]["success"])
        self.assertIn(f"-I/usr/include/{platform.machine()}-linux-gnu", result["command"])

    @patch("src.util.deploy.executor.load_bpf_program_with_libbpf_loader")
    @patch("src.util.deploy.executor._run_command")
    def test_deploy_flow_load_fail_with_structured_verifier(self, run_cmd_mock, loader_load_mock):
        loader_load_mock.return_value = {
            "success": False,
            "stage": "load",
            "object_file": "tests/logs/test_ebpf.bpf.o",
            "pin_path": "/sys/fs/bpf/ebpf_agent_test",
            "links_dir": "/sys/fs/bpf/ebpf_agent_test.links",
            "via_libbpf_loader": True,
            "error_message": "unknown func bpf_ringbuf_submit\nstack depth 600",
            "pre_unpinned_existing": True,
            "command": ["sudo", "/tmp/loader"],
            "stdout": "",
            "stderr": "unknown func bpf_ringbuf_submit\\nstack depth 600",
            "returncode": 1,
            "timed_out": False,
            "verifier": {
                "primary_error_type": "unknown_func",
                "error_types": ["unknown_func", "stack_depth_exceeded"],
                "key_lines": ["unknown func bpf_ringbuf_submit", "stack depth 600"],
                "raw_log": "unknown func bpf_ringbuf_submit\\nstack depth 600",
            },
            "cleanup_unpinned": True,
        }
        for src in self.bpf_sources:
            with tempfile.TemporaryDirectory() as td:
                pin = Path(td) / "prog_pin"
                stem = src.name.replace(".bpf.c", "")

                run_cmd_mock.side_effect = [
                    {
                        "command": [],
                        "returncode": 0,
                        "stdout": "",
                        "stderr": "",
                        "timed_out": False,
                    },
                ]

                report = deploy_bpf_program(
                    source_file=str(src),
                    pin_path=str(pin),
                    object_file=f"tests/logs/{stem}.bpf.o",
                )

                self.assertFalse(report["success"])
                self.assertEqual(report["stage"], "load_failed")
                self.assertEqual(report["compile"]["stage"], "compile")
                self.assertEqual(report["load"]["stage"], "load")
                self.assertIn("unknown_func", report["load"]["verifier"]["error_types"])
                self.assertIn("stack_depth_exceeded", report["load"]["verifier"]["error_types"])

    @patch("src.util.deploy.executor._build_libbpf_loader")
    @patch("src.util.deploy.executor._safe_remove_tree")
    @patch("src.util.deploy.executor._safe_unpin")
    @patch("src.util.deploy.executor._run_command")
    def test_loader_attach_failure_surfaces_in_attach_result(
        self,
        run_cmd_mock,
        safe_unpin_mock,
        safe_remove_tree_mock,
        build_mock,
    ):
        safe_unpin_mock.return_value = True
        safe_remove_tree_mock.return_value = True
        build_mock.return_value = {
            "success": True,
            "loader_bin": "/tmp/loader",
            "command": ["make"],
            "stdout": "",
            "stderr": "",
            "returncode": 0,
            "timed_out": False,
        }
        # run_cmd: [0]=compile, [1]=loader (failure)
        run_cmd_mock.side_effect = [
            {"command": [], "returncode": 0, "stdout": "", "stderr": "", "timed_out": False},
            {"command": [], "returncode": 1, "stdout": "", "stderr": "attach failed: prog0\n", "timed_out": False},
        ]

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "trace_case.bpf.c"
            src.write_text(
                '#include <bpf/bpf_helpers.h>\nSEC("tracepoint/syscalls/sys_enter_openat") int x(void *ctx){return 0;}\n',
                encoding="utf-8",
            )

            report = deploy_bpf_program(
                source_file=str(src),
                pin_path=str(Path(td) / "pin_prog"),
                object_file=str(Path(td) / "trace_case.bpf.o"),
            )

        self.assertFalse(report["success"])
        self.assertEqual(report["stage"], "attach_failed")
        self.assertEqual(report["attach"]["reason"], "libbpf_loader_attach_failed")
        self.assertIn("attach failed", report["attach"]["error_log"])

    @patch("src.util.deploy.executor._run_command")
    def test_load_adds_program_type_flag(self, run_cmd_mock):
        run_cmd_mock.return_value = {
            "command": [],
            "returncode": 0,
            "stdout": "loaded",
            "stderr": "",
            "timed_out": False,
        }

        with tempfile.TemporaryDirectory() as td:
            pin = Path(td) / "prog_pin"
            result = load_bpf_program(
                object_file="tests/logs/test_ebpf.bpf.o",
                pin_path=str(pin),
                program_type="kprobe",
            )
            self.assertTrue(result["success"])
            self.assertIn("type", result["command"])
            self.assertIn("kprobe", result["command"])

    @patch("src.util.deploy.pipeline.safe_remove_tree")
    @patch("src.util.deploy.pipeline.run_case_runtime_validation")
    @patch("src.util.deploy.pipeline.start_libbpf_loader_daemon")
    @patch("src.util.deploy.pipeline.compile_bpf_program")
    def test_deploy_daemon_returncode_20_means_attach_failed_after_load(
        self,
        compile_mock,
        daemon_mock,
        runtime_mock,
        safe_remove_tree_mock,
    ):
        compile_mock.return_value = {
            "success": True,
            "stage": "compile",
            "object_file": "tests/logs/test_ebpf.bpf.o",
        }
        daemon_mock.return_value = {
            "success": False,
            "stage": "attach",
            "via_libbpf_loader_daemon": True,
            "command": ["sudo", "/tmp/loader"],
            "pid": 1234,
            "ready_line": None,
            "stdout": (
                'PHASE_JSON {"phase":"load","ok":true,"stdout":"loaded obj=x\\npinned maps_dir=y\\n",'
                '"stderr":"","error_message":""}\n'
                'PHASE_JSON {"phase":"attach","ok":false,"stdout":"","stderr":"attach failed: prog0\\n",'
                '"error_message":"attach failed: prog0"}\n'
            ),
            "stderr": "",
            "returncode": 20,
            "error_message": "attach failed: prog0",
            "load_success": True,
            "attach_success": False,
            "phase_details": {
                "load": {"phase": "load", "ok": True, "stdout": "loaded obj=x\npinned maps_dir=y\n", "stderr": "", "error_message": ""},
                "attach": {
                    "phase": "attach",
                    "ok": False,
                    "stdout": "",
                    "stderr": "attach failed: prog0\n",
                    "error_message": "attach failed: prog0",
                },
            },
        }
        runtime_mock.return_value = {"success": True, "stage": "runtime_test", "skipped": True, "reason": "attach_not_active"}
        safe_remove_tree_mock.return_value = True

        report = deploy_bpf_program(
            source_file="tests/data/test.bpf.c",
            pin_path="/sys/fs/bpf/ebpf_agent_test",
            object_file="tests/logs/test_ebpf.bpf.o",
        )

        self.assertFalse(report["success"])
        self.assertEqual(report["stage"], "attach_failed")
        self.assertTrue(report["load"]["success"])
        self.assertEqual(report["load"]["stage"], "load")
        self.assertFalse(report["attach"]["success"])
        self.assertEqual(report["attach"]["reason"], "libbpf_loader_attach_failed")
        self.assertIn("attach failed", report["attach"]["error_message"])
        runtime_mock.assert_not_called()

    @patch("src.util.deploy.pipeline.detach_bpf_program")
    @patch("src.util.deploy.pipeline.run_case_runtime_validation")
    @patch("src.util.deploy.pipeline.attach_bpf_program")
    @patch("src.util.deploy.pipeline.load_bpf_program_with_libbpf_loader")
    @patch("src.util.deploy.pipeline.compile_bpf_program")
    def test_deploy_ignores_detach_failure_for_final_result(
        self,
        compile_mock,
        loader_mock,
        attach_mock,
        runtime_mock,
        detach_mock,
    ):
        compile_mock.return_value = {
            "success": True,
            "stage": "compile",
            "object_file": "tests/logs/test_ebpf.bpf.o",
        }
        loader_mock.return_value = {
            "success": True,
            "stage": "load",
            "object_file": "tests/logs/test_ebpf.bpf.o",
            "pin_path": "/sys/fs/bpf/ebpf_agent_test",
            "via_libbpf_loader": True,
        }
        attach_mock.return_value = {
            "success": True,
            "stage": "attach",
            "attached": True,
            "skipped": False,
            "reason": "attached",
            "plan": {"program_type": "tracepoint"},
        }
        runtime_mock.return_value = {
            "success": True,
            "stage": "runtime_test",
            "skipped": False,
            "reason": "validator_passed",
        }
        detach_mock.return_value = {
            "success": False,
            "stage": "detach",
            "detached": False,
            "skipped": False,
            "reason": "unpin_failed",
        }

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "trace_case.bpf.c"
            src.write_text(
                '#include <bpf/bpf_helpers.h>\nSEC("tracepoint/syscalls/sys_enter_openat") int x(void *ctx){return 0;}\n',
                encoding="utf-8",
            )

            report = deploy_bpf_program(
                source_file=str(src),
                pin_path=str(Path(td) / "pin_prog"),
                object_file=str(Path(td) / "trace_case.bpf.o"),
                load_backend="libbpf_once",
            )

        self.assertTrue(report["success"])
        self.assertEqual(report["stage"], "success")
        self.assertFalse(report["detach"]["success"])

    @patch("src.util.deploy.pipeline.safe_remove_tree")
    @patch("src.util.deploy.pipeline.run_case_runtime_validation")
    @patch("src.util.deploy.pipeline.start_libbpf_loader_daemon")
    @patch("src.util.deploy.pipeline.compile_bpf_program")
    def test_deploy_daemon_returncode_10_means_load_failed(
        self,
        compile_mock,
        daemon_mock,
        runtime_mock,
        safe_remove_tree_mock,
    ):
        compile_mock.return_value = {
            "success": True,
            "stage": "compile",
            "object_file": "tests/logs/test_ebpf.bpf.o",
        }
        daemon_mock.return_value = {
            "success": False,
            "stage": "load",
            "via_libbpf_loader_daemon": True,
            "command": ["sudo", "/tmp/loader"],
            "pid": 1234,
            "ready_line": None,
            "stdout": (
                'PHASE_JSON {"phase":"load","ok":false,"stdout":"","stderr":"load failed: -22\\n",'
                '"error_message":"load failed: -22"}\n'
            ),
            "stderr": "load failed: -22",
            "returncode": 10,
            "error_message": "load failed: -22",
            "load_success": False,
            "attach_success": False,
            "phase_details": {
                "load": {
                    "phase": "load",
                    "ok": False,
                    "stdout": "",
                    "stderr": "load failed: -22\n",
                    "error_message": "load failed: -22",
                }
            },
        }
        runtime_mock.return_value = {"success": True, "stage": "runtime_test", "skipped": True, "reason": "attach_not_active"}
        safe_remove_tree_mock.return_value = True

        report = deploy_bpf_program(
            source_file="tests/data/test.bpf.c",
            pin_path="/sys/fs/bpf/ebpf_agent_test",
            object_file="tests/logs/test_ebpf.bpf.o",
        )

        self.assertFalse(report["success"])
        self.assertEqual(report["stage"], "load_failed")
        self.assertFalse(report["load"]["success"])
        self.assertEqual(report["load"]["stage"], "load")
        self.assertFalse(report["attach"]["success"])
        self.assertTrue(report["attach"]["skipped"])
        self.assertEqual(report["attach"]["reason"], "load_failed")
        runtime_mock.assert_not_called()

    @patch("src.util.deploy.executor._safe_unpin")
    @patch("src.util.deploy.executor._safe_remove_tree")
    @patch("src.util.deploy.executor.load_bpf_program_with_libbpf_loader")
    @patch("src.util.deploy.executor.run_case_runtime_validation")
    @patch("src.util.deploy.executor._run_command")
    def test_deploy_runtime_failure_updates_stage(self, run_cmd_mock, runtime_mock, loader_load_mock, safe_remove_tree_mock, safe_unpin_mock):
        safe_remove_tree_mock.return_value = True
        safe_unpin_mock.return_value = True
        loader_load_mock.return_value = {
            "success": True,
            "stage": "load",
            "object_file": "tests/logs/test_ebpf.bpf.o",
            "pin_path": "/sys/fs/bpf/ebpf_agent_test",
            "links_dir": "/sys/fs/bpf/ebpf_agent_test.links",
            "via_libbpf_loader": True,
            "pre_unpinned_existing": True,
            "command": ["sudo", "/tmp/loader"],
            "stdout": "loaded_and_attached=1",
            "stderr": "",
            "returncode": 0,
            "timed_out": False,
            "verifier": {"primary_error_type": "unknown", "error_types": [], "key_lines": [], "raw_log": ""},
            "cleanup_unpinned": False,
        }
        runtime_mock.return_value = {
            "success": False,
            "stage": "runtime_test",
            "skipped": False,
            "reason": "validator_mismatch",
        }
        run_cmd_mock.side_effect = [
            {
                "command": [],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            },
        ]

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "runtime_case.bpf.c"
            src.write_text(
                '#include <bpf/bpf_helpers.h>\nSEC("kprobe/do_sys_openat2") int x(void *ctx){return 0;}\n',
                encoding="utf-8",
            )

            report = deploy_bpf_program(
                source_file=str(src),
                pin_path=str(Path(td) / "pin_prog"),
                object_file=str(Path(td) / "runtime_case.bpf.o"),
            )

        self.assertFalse(report["success"])
        self.assertEqual(report["stage"], "runtime_test_failed")
        self.assertEqual(report["runtime"]["reason"], "validator_mismatch")
        self.assertTrue(report["detach"]["success"])


if __name__ == "__main__":
    unittest.main()
