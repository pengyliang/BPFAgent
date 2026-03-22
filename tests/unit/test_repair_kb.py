import sys
import types
import unittest

if "openai" not in sys.modules:
    openai_stub = types.ModuleType("openai")

    class _DummyOpenAI:  # pragma: no cover - test import stub only
        def __init__(self, *args, **kwargs):
            pass

    openai_stub.OpenAI = _DummyOpenAI
    sys.modules["openai"] = openai_stub

from src.agent.refiner import _merge_rule, _normalize_method_text, _normalize_repair_method_updates


class TestRepairKnowledgeBase(unittest.TestCase):
    def test_normalize_repair_method_updates(self):
        triples = _normalize_repair_method_updates(
            {
                "patterns": {
                    "verifier_memory_bounds": {
                        "aliases": ["invalid_mem_access"],
                        "stage_hints": ["load_failed"],
                        "can_fix": True,
                        "repair_methods": ["补边界检查并收紧 verifier 可证明的分支条件。"],
                    }
                }
            }
        )

        norm = _normalize_method_text("补边界检查并收紧 verifier 可证明的分支条件。", default_can_fix=True)
        self.assertEqual(
            triples,
            [
                (
                    "verifier_memory_bounds",
                    {
                        "summary": "",
                        "aliases": ["invalid_mem_access"],
                        "stage_hints": ["load_failed"],
                        "can_fix": True,
                        "evidence_hint": [],
                        "repair_methods": [norm],
                    },
                )
            ],
        )

    def test_merge_rule_only_adds_new_experience(self):
        norm_v = _normalize_method_text("补边界检查并收紧 verifier 可证明的分支条件。", default_can_fix=True)
        db = {
            "verifier_memory_bounds": {
                "summary": "",
                "aliases": ["invalid_mem_access"],
                "stage_hints": ["load_failed"],
                "can_fix": True,
                "evidence_hint": [],
                "repair_methods": [norm_v],
            }
        }
        updates = _normalize_repair_method_updates(
            {
                "patterns": {
                    "verifier_memory_bounds": {
                        "aliases": ["out_of_bounds"],
                        "stage_hints": ["load_failed"],
                        "can_fix": True,
                        "repair_methods": ["补边界检查并收紧 verifier 可证明的分支条件。"],
                    },
                    "helper_unsupported": {
                        "aliases": ["unknown_func"],
                        "stage_hints": ["load_failed"],
                        "can_fix": True,
                        "repair_methods": ["替换目标内核不支持的 helper 或改写为等价逻辑。"],
                    },
                }
            }
        )

        merged, added = _merge_rule(db, updates)

        norm_u = _normalize_method_text("替换目标内核不支持的 helper 或改写为等价逻辑。", default_can_fix=True)
        self.assertEqual(
            merged,
            {
                "verifier_memory_bounds": {
                    "summary": "",
                    "aliases": ["invalid_mem_access", "out_of_bounds"],
                    "stage_hints": ["load_failed"],
                    "can_fix": True,
                    "evidence_hint": [],
                    "repair_methods": [norm_v],
                },
                "helper_unsupported": {
                    "summary": "",
                    "aliases": ["unknown_func"],
                    "stage_hints": ["load_failed"],
                    "can_fix": True,
                    "evidence_hint": [],
                    "repair_methods": [norm_u],
                },
            },
        )
        self.assertEqual(
            added,
            {
                "verifier_memory_bounds": {
                    "summary": "",
                    "aliases": ["invalid_mem_access", "out_of_bounds"],
                    "stage_hints": ["load_failed"],
                    "can_fix": True,
                    "evidence_hint": [],
                    "repair_methods": [norm_v],
                },
                "helper_unsupported": {
                    "summary": "",
                    "aliases": ["unknown_func"],
                    "stage_hints": ["load_failed"],
                    "can_fix": True,
                    "evidence_hint": [],
                    "repair_methods": [norm_u],
                },
            },
        )

    def test_merge_rule_preserves_cannot_fix_handoff(self):
        merged, added = _merge_rule(
            {},
            _normalize_repair_method_updates(
                {
                    "patterns": {
                        "attach_type_unsupported": {
                            "aliases": ["program_type_min_kernel"],
                            "stage_hints": ["static_check_failed"],
                            "can_fix": False,
                            "handoff": "需要更换内核或切换 attach 方式。",
                        }
                    }
                },
            ),
        )

        self.assertEqual(merged["attach_type_unsupported"]["can_fix"], False)
        self.assertEqual(merged["attach_type_unsupported"]["handoff"], "需要更换内核或切换 attach 方式。")
        self.assertEqual(added["attach_type_unsupported"]["can_fix"], False)


if __name__ == "__main__":
    unittest.main()
