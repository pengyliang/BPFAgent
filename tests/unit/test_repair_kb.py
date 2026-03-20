import unittest

from src.agent.refiner import _merge_rule, _normalize_method_text, _normalize_repair_method_updates


class TestRepairKnowledgeBase(unittest.TestCase):
    def test_normalize_repair_method_updates(self):
        triples = _normalize_repair_method_updates(
            {
                "load_failed": {
                    "verifier_reject": "补边界检查并收紧 verifier 可证明的分支条件。",
                    "": "ignored",
                },
                "invalid_stage": {"foo": "bar"},
            }
        )

        norm = _normalize_method_text("补边界检查并收紧 verifier 可证明的分支条件。", default_can_fix=True)
        self.assertEqual(triples, [("load_failed", "verifier_reject", norm)])

    def test_merge_rule_only_adds_new_experience(self):
        norm_v = _normalize_method_text("补边界检查并收紧 verifier 可证明的分支条件。", default_can_fix=True)
        db = {
            "load_failed": {
                "verifier_reject": [norm_v],
            }
        }
        updates = _normalize_repair_method_updates(
            {
                "load_failed": {
                    "verifier_reject": "补边界检查并收紧 verifier 可证明的分支条件。",
                    "unknown_func": "替换目标内核不支持的 helper 或改写为等价逻辑。",
                },
                "compile_failed": {
                    "core_not_supported": "移除 CO-RE 依赖，改成非 CO-RE 头文件与字段读取方式。",
                },
            }
        )

        merged, added = _merge_rule(db, updates)

        norm_u = _normalize_method_text("替换目标内核不支持的 helper 或改写为等价逻辑。", default_can_fix=True)
        norm_c = _normalize_method_text("移除 CO-RE 依赖，改成非 CO-RE 头文件与字段读取方式。", default_can_fix=True)
        self.assertEqual(
            merged,
            {
                "load_failed": {
                    "verifier_reject": [norm_v],
                    "unknown_func": [norm_u],
                },
                "compile_failed": {
                    "core_not_supported": [norm_c],
                },
            },
        )
        self.assertEqual(
            added,
            {
                "load_failed": {
                    "unknown_func": [norm_u],
                },
                "compile_failed": {
                    "core_not_supported": [norm_c],
                },
            },
        )


if __name__ == "__main__":
    unittest.main()
