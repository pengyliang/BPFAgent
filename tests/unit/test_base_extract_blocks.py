import unittest

from src.agent.base import extract_code_block, extract_json_block, extract_yaml_block


class TestBaseExtractBlocks(unittest.TestCase):
    def test_extract_json_block_with_unclosed_fence(self):
        text = '```json\n{"patched_code":"int x;","rationale":"ok"}'
        obj = extract_json_block(text)
        self.assertEqual(obj, {"patched_code": "int x;", "rationale": "ok"})

    def test_extract_code_block_with_unclosed_fence(self):
        text = "```c\nint main(void) {\n    return 0;\n}"
        code = extract_code_block(text)
        self.assertEqual(code, "int main(void) {\n    return 0;\n}\n")

    def test_extract_yaml_block_with_unclosed_fence(self):
        text = "```yaml\nfoo: bar\nbaz:\n  - qux"
        yml = extract_yaml_block(text)
        self.assertEqual(yml, "foo: bar\nbaz:\n  - qux\n")


if __name__ == "__main__":
    unittest.main()
