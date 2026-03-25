import sys
import types
import unittest

# The production code imports `openai` via src/core/llm/openai_compat.py.
# In this test environment the dependency may be missing; we stub it to
# allow importing pure functions like extract_critical_block.
if "openai" not in sys.modules:
    m = types.ModuleType("openai")
    setattr(m, "OpenAI", object)
    sys.modules["openai"] = m

from src.agent.inspector import extract_critical_block


class TestInspectorCriticalBlockExtract(unittest.TestCase):
    def test_extract_between_markers(self):
        code = "\n".join(
            [
                "int x = 0;",
                "/* Crutial block */",
                "int a = 1;",
                "int b = 2;",
                "/* Crutial block end */",
                "int y = 3;",
            ]
        )
        out = extract_critical_block(code)
        self.assertEqual(out, "int a = 1;\nint b = 2;")

    def test_missing_start_marker_returns_none(self):
        code = "\n".join(
            [
                "int x = 0;",
                "int a = 1;",
                "/* Crutial block end */",
                "int y = 3;",
            ]
        )
        out = extract_critical_block(code)
        self.assertIsNone(out)

    def test_missing_end_marker_returns_none(self):
        code = "\n".join(
            [
                "int x = 0;",
                "/* Crutial block */",
                "int a = 1;",
                "int y = 3;",
            ]
        )
        out = extract_critical_block(code)
        self.assertIsNone(out)

    def test_extract_uses_first_end_after_start(self):
        code = "\n".join(
            [
                "/* Crutial block */",
                "int a = 1;",
                "/* Crutial block end */",
                "int mid = 0;",
                "/* Crutial block */",
                "int a2 = 2;",
                "/* Crutial block end */",
            ]
        )
        out = extract_critical_block(code)
        # Only the first block is extracted.
        self.assertEqual(out, "int a = 1;")


if __name__ == "__main__":
    unittest.main()

