import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from src.agent.base import load_knowledge_rules
from src.agent.refiner import (
    RefinerAgent,
    _collect_successful_stage_advances,
    _merge_rule,
    _normalize_method_text,
    _normalize_repair_method_updates,
)


class TestAgentKnowledge(unittest.TestCase):
    def test_load_knowledge_rules_supports_stage_mapping_format(self):
        payload = {
            "static_check_failed": {
                "attach_target_not_found": ["不要继续自动修改源码，直接报告目标符号不存在。"],
                "core_requires_btf": ["移除 CO-RE 依赖并改用非 CO-RE 读取方式。"],
            },
            "load_failed": {
                "verifier_reject": ["根据 verifier 日志补边界检查和分支约束。"],
            },
        }

        with tempfile.TemporaryDirectory() as td:
            kb_path = Path(td) / "repair_method.yaml"
            kb_path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")

            with patch("src.agent.base.knowledge_base_path", return_value=kb_path):
                selected = load_knowledge_rules("static_check_failed", "static_check_failed:attach_target_not_found")

        loaded = yaml.safe_load(selected)
        self.assertEqual(
            loaded,
            {
                "static_check_failed": {
                    "attach_target_not_found": ["不要继续自动修改源码，直接报告目标符号不存在。"],
                }
            },
        )

    def test_merge_rule_only_adds_new_entries(self):
        norm_a = _normalize_method_text("根据 verifier 日志补边界检查。", default_can_fix=True)
        db: dict = {
            "load_failed": {
                "verifier_reject": [norm_a],
            }
        }
        updates = _normalize_repair_method_updates(
            {
                "load_failed": {
                    "verifier_reject": "根据 verifier 日志补边界检查。",
                    "unknown_func": "替换为当前内核支持的 helper 或降级实现。",
                }
            }
        )

        merged, added = _merge_rule(db, updates)

        self.assertEqual(merged["load_failed"]["verifier_reject"], [norm_a])
        norm_b = _normalize_method_text("替换为当前内核支持的 helper 或降级实现。", default_can_fix=True)
        self.assertEqual(merged["load_failed"]["unknown_func"], [norm_b])
        self.assertEqual(
            added,
            {
                "load_failed": {
                    "unknown_func": [norm_b],
                }
            },
        )

    def test_collect_successful_stage_advances_only_records_stage_progress(self):
        state = {
            "repair_attempts": [
                {
                    "attempt_index": 1,
                    "stage": "static_check_failed",
                    "error_type": "core_requires_btf",
                    "can_fix": True,
                    "patched": True,
                    "repair_method": "移除 CO-RE 依赖。具体步骤：1. 改成非 CO-RE 读取方式。2. 删除相关头文件。",
                },
                {
                    "attempt_index": 2,
                    "stage": "load_failed",
                    "error_type": "verifier_reject",
                    "can_fix": True,
                    "patched": True,
                    "repair_method": "补充边界检查并简化分支。",
                },
            ],
            "workflow_events": [
                {"node": "deploy_tool", "node_index": 1, "key_results": {"deploy_state": False, "failed_stage": "static_check_failed"}},
                {"node": "deploy_tool", "node_index": 2, "key_results": {"deploy_state": False, "failed_stage": "compile_failed"}},
                {"node": "deploy_tool", "node_index": 3, "key_results": {"deploy_state": False, "failed_stage": "load_failed"}},
            ],
        }

        advances = _collect_successful_stage_advances(state)

        self.assertEqual(len(advances), 1)
        self.assertEqual(advances[0]["stage"], "static_check_failed")
        self.assertEqual(advances[0]["error_type"], "core_requires_btf")
        self.assertEqual(
            advances[0]["repair_method"],
            "can_fix=true+移除 CO-RE 依赖。",
        )

    def test_refiner_build_rule_updates_returns_empty_without_stage_progress(self):
        agent = RefinerAgent(llm=None)
        state = {
            "repair_attempts": [
                {
                    "attempt_index": 1,
                    "stage": "static_check_failed",
                    "error_type": "core_requires_btf",
                    "can_fix": True,
                    "patched": True,
                    "repair_method": "移除 CO-RE 依赖并改成非 CO-RE 读取方式。",
                }
            ],
            "workflow_events": [
                {"node": "deploy_tool", "node_index": 1, "key_results": {"deploy_state": False, "failed_stage": "static_check_failed"}},
                {"node": "deploy_tool", "node_index": 2, "key_results": {"deploy_state": False, "failed_stage": "static_check_failed"}},
            ],
            "failed_stage": "static_check_failed",
            "deploy": {"stage": "static_check_failed"},
            "last_error_signature": "static_check_failed:core_requires_btf",
            "repair_action": {"repair_method": "移除 CO-RE 依赖并改成非 CO-RE 读取方式。"},
        }
        signal = type("Signal", (), {"error_types": ["core_requires_btf"]})()

        updates = agent._build_rule_updates(state, "{}", signal)

        self.assertEqual(updates, [])

    def test_normalize_method_text_uses_required_format(self):
        normalized = _normalize_method_text(
            "补充边界检查并简化 verifier 难以推理的分支。具体步骤：1. 删除多余分支。2. 增加空指针判断。",
            default_can_fix=True,
        )
        self.assertEqual(normalized, "can_fix=true+补充边界检查并简化 verifier 难以推理的分支。")


if __name__ == "__main__":
    unittest.main()
