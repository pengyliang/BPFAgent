# Unit test for ast_parser.py
import os
import json
import unittest
from pathlib import Path
from scripts.setup.ast_parser import parse_ebpf_source


class TestASTParser(unittest.TestCase):
    def test_parse_ebpf_source(self):
        data_dir = Path("tests/data")
        logs_dir = Path("tests/logs")
        logs_dir.mkdir(parents=True, exist_ok=True)

        bpf_sources = sorted(data_dir.glob("*.bpf.c"))
        self.assertGreater(len(bpf_sources), 0, "No .bpf.c test files found in tests/data")

        all_summaries = []
        for src in bpf_sources:
            base_name = src.stem  # e.g., test_ebpf.bpf
            summary_path = logs_dir / f"{base_name}.summary.json"
            log_path = logs_dir / f"{base_name}.parser.log"

            summary = parse_ebpf_source(
                str(src),
                output_path=str(summary_path),
                log_path=str(log_path),
            )
            all_summaries.append(summary)

            self.assertTrue(summary_path.exists())
            self.assertTrue(log_path.exists())
            self.assertIsInstance(summary, dict)
            self.assertIn("ast_fallback", summary)
            self.assertIn("bpf_helper_calls", summary)
            self.assertIn("struct_field_access_paths", summary)
            self.assertIn("map_operation_sequence", summary)
            self.assertIsInstance(summary["bpf_helper_calls"], list)
            self.assertIsInstance(summary["struct_field_access_paths"], list)
            self.assertIsInstance(summary["map_operation_sequence"], list)

        aggregate_path = logs_dir / "ast_summary.json"
        aggregate_payload = {
            "total_files": len(all_summaries),
            "summaries": all_summaries,
        }
        with open(aggregate_path, "w", encoding="utf-8") as f:
            json.dump(aggregate_payload, f, indent=2, ensure_ascii=True)

        self.assertTrue(aggregate_path.exists())
        with open(aggregate_path, "r", encoding="utf-8") as f:
            merged = json.load(f)
        self.assertEqual(merged["total_files"], len(bpf_sources))
        self.assertEqual(len(merged["summaries"]), len(bpf_sources))

        all_helpers = []
        all_map_ops = []
        for item in merged["summaries"]:
            if item.get("ast_fallback"):
                continue
            all_helpers.extend([x["helper"] for x in item["bpf_helper_calls"]])
            all_map_ops.extend([x["operation"] for x in item["map_operation_sequence"]])

        # 无 clang 或全部 AST 失败时允许为空；有成功解析的样本则应提取到 helper / map 操作
        if any(not s.get("ast_fallback") for s in merged["summaries"]):
            self.assertGreater(len(all_helpers), 0)
            self.assertGreater(len(all_map_ops), 0)

if __name__ == "__main__":
    unittest.main()