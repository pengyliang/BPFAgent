import json
import unittest
from pathlib import Path

from src.agent.base import default_can_fix, static_check_requires_environment_change
from src.agent.analysis.static_checker import analyze_project_static_checks
from scripts.setup.ast_parser import parse_ebpf_source


class TestStaticChecker(unittest.TestCase):
    def test_static_check_attach_constraints_are_not_fixable(self):
        payload = {
            "issues": [
                {
                    "check": "program_type_attach_availability",
                    "level": "warning",
                    "code": "attach_target_not_found",
                    "message": "Attach target do_sys_openat2 not found in /proc/kallsyms on current host.",
                },
                {
                    "check": "program_type_attach_availability",
                    "level": "error",
                    "code": "program_type_min_kernel",
                    "message": 'SEC("fentry/__x64_sys_execve") requires kernel >= 5.5.',
                },
            ]
        }

        self.assertTrue(static_check_requires_environment_change(payload))
        self.assertFalse(default_can_fix("static_check_failed", payload))

    def test_static_checks_cover_required_rules(self):
        logs_dir = Path("tests/logs")
        logs_dir.mkdir(parents=True, exist_ok=True)

        bpf_sources = sorted(Path("tests/data").glob("*.bpf.c"))
        self.assertGreater(len(bpf_sources), 0, "No .bpf.c test files found in tests/data")

        ast_summary_path = logs_dir / "static_ast_summary.json"
        kernel_profile_path = logs_dir / "static_kernel_profile.json"
        report_path = logs_dir / "static_check_report_test.json"

        summaries = []
        for src in bpf_sources:
            base_name = src.stem
            parser_log = logs_dir / f"{base_name}.static.parser.log"
            parser_summary = parse_ebpf_source(
                str(src),
                output_path=str(logs_dir / f"{base_name}.static.summary.json"),
                log_path=str(parser_log),
            )
            summaries.append(parser_summary)

        ast_payload = {
            "total_files": len(summaries),
            "summaries": summaries,
        }
        kernel_payload = {
            "kernel_version": {"raw": "5.4.0-test", "major": 5, "minor": 4, "patch": 0, "distro_suffix": "-test"},
            "btf": {"available": False},
            "helper_whitelist": ["bpf_map_lookup_elem"],
            "map_type_support": ["BPF_MAP_TYPE_HASH"],
            # tests/data: kprobe + tracepoint samples
            "program_type_support": ["kprobe", "kretprobe", "tracepoint"],
        }

        with open(ast_summary_path, "w", encoding="utf-8") as f:
            json.dump(ast_payload, f, indent=2, ensure_ascii=True)
        with open(kernel_profile_path, "w", encoding="utf-8") as f:
            json.dump(kernel_payload, f, indent=2, ensure_ascii=True)

        report = analyze_project_static_checks(
            ast_summary_path=str(ast_summary_path),
            kernel_profile_path=str(kernel_profile_path),
            output_path=str(report_path),
        )

        self.assertTrue(report_path.exists())
        self.assertEqual(len(report["results"]), len(bpf_sources))

        all_checks = set()
        all_codes = set()
        for item in report["results"]:
            src = Path(item["source_file"])
            self.assertTrue(src.name.endswith(".bpf.c"))
            for issue in item["issues"]:
                all_checks.add(issue["check"])
                all_codes.add(issue["code"])

        # Ensure core static checks are actually exercised by tests/data samples.
        self.assertIn("helper_availability", all_checks)
        self.assertIn("map_type_availability", all_checks)

        # Ringbuf sample on synthetic 5.4: min-kernel codes only if enabled; else probe/whitelist.
        from src.util.static_check import static_checker as _sc

        if _sc.ENABLE_MIN_KERNEL_CHECKS:
            self.assertTrue(
                "helper_min_kernel" in all_codes
                or "map_type_not_in_probe" in all_codes
                or "map_type_min_kernel" in all_codes
            )
        else:
            self.assertTrue(
                "helper_not_in_probe" in all_codes or "map_type_not_in_probe" in all_codes
            )


if __name__ == "__main__":
    unittest.main()
