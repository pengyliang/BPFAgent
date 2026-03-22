import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

if "openai" not in sys.modules:
    openai_stub = types.ModuleType("openai")

    class _DummyOpenAI:  # pragma: no cover - test import stub only
        def __init__(self, *args, **kwargs):
            pass

    openai_stub.OpenAI = _DummyOpenAI
    sys.modules["openai"] = openai_stub

from src.agent.base import load_knowledge_rules, normalize_repair_knowledge_obj
from src.agent.refiner import (
    RefinerAgent,
    _collect_successful_stage_advances,
    _normalize_method_text,
)


class TestAgentKnowledge(unittest.TestCase):
    def test_load_knowledge_rules_returns_empty_when_knowledge_base_disabled(self):
        with patch("src.agent.base.knowledge_base_enabled", return_value=False):
            selected = load_knowledge_rules("static_check_failed", "static_check_failed:attach_target_not_found")

        self.assertEqual(selected, "")

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
        self.assertEqual(loaded["version"], 2)
        self.assertIn("attach_target_missing", loaded["patterns"])
        self.assertEqual(loaded["patterns"]["attach_target_missing"]["can_fix"], False)
        self.assertIn("attach_target_not_found", loaded["patterns"]["attach_target_missing"]["aliases"])

    def test_load_knowledge_rules_prefers_alias_match_in_pattern_schema(self):
        payload = {
            "version": 2,
            "patterns": {
                "helper_unsupported": {
                    "aliases": ["unknown_func"],
                    "stage_hints": ["load_failed"],
                    "can_fix": True,
                    "repair_methods": ["替换为当前内核支持的 helper。"],
                },
                "header_dependency_missing": {
                    "aliases": ["missing_header_include"],
                    "stage_hints": ["compile_failed"],
                    "can_fix": True,
                    "repair_methods": ["补齐头文件依赖。"],
                },
            },
        }

        with tempfile.TemporaryDirectory() as td:
            kb_path = Path(td) / "repair_method.yaml"
            kb_path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")
            with patch("src.agent.base.knowledge_base_path", return_value=kb_path):
                selected = load_knowledge_rules("load_failed", "load_failed:unknown_func")

        loaded = yaml.safe_load(selected)
        self.assertEqual(list(loaded["patterns"].keys()), ["helper_unsupported"])

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
        self.assertEqual(advances[0]["observed_error_type"], "core_requires_btf")
        self.assertEqual(advances[0]["pattern_id"], "core_requires_btf")
        self.assertEqual(advances[0]["entry"]["repair_methods"], ["移除 CO-RE 依赖。"])

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
        self.assertEqual(normalized, "补充边界检查并简化 verifier 难以推理的分支。")

    def test_normalize_repair_knowledge_obj_migrates_legacy_can_fix_prefix(self):
        normalized = normalize_repair_knowledge_obj(
            {
                "static_check_failed": {
                    "attach_target_not_found": ["can_fix=false+停止自动源码修复并提示更换目标符号。"],
                }
            }
        )
        rule = normalized["patterns"]["attach_target_missing"]
        self.assertEqual(rule["can_fix"], False)
        self.assertEqual(rule["repair_methods"], ["停止自动源码修复并提示更换目标符号。"])


if __name__ == "__main__":
    unittest.main()
