import tempfile
import textwrap
import unittest
from pathlib import Path

from src.core.config_loader import load_app_config


class TestConfigLoading(unittest.TestCase):
    def test_load_app_config_from_python_file(self):
        content = textwrap.dedent(
            """
            CONFIG = {
                "max_retry": 3,
                "log_level": 1,
                "agent_mode": True,
                "analyzer": False,
                "refiner": True,
                "knowledge_base": False,
                "agent_max_patches": 5,
                "static_check": {
                    "enabled": False,
                },
                "llm": {
                    "enabled": True,
                    "provider": "openai",
                    "model": "gpt-4.1",
                    "base_url": "https://example.com/v1",
                    "api_key": "test-key",
                    "timeout_s": 90,
                    "extra_body": ["vendor-specific", {"raw": True}],
                    "show_terminal_output": False,
                },
            }
            """
        ).strip()

        with tempfile.TemporaryDirectory() as td:
            config_path = Path(td) / "app_config.py"
            config_path.write_text(content, encoding="utf-8")

            app_config = load_app_config(str(config_path))

        self.assertEqual(app_config.max_retry, 3)
        self.assertEqual(app_config.log_level, 1)
        self.assertTrue(app_config.agent.agent_mode)
        self.assertFalse(app_config.agent.analyzer_enabled)
        self.assertTrue(app_config.agent.refiner_enabled)
        self.assertFalse(app_config.agent.knowledge_base_enabled)
        self.assertEqual(app_config.agent.agent_max_patches, 5)
        self.assertFalse(app_config.static_check.enabled)
        self.assertEqual(app_config.llm.provider, "openai")
        self.assertEqual(app_config.llm.model, "gpt-4.1")
        self.assertEqual(app_config.llm.base_url, "https://example.com/v1")
        self.assertEqual(app_config.llm.api_key, "test-key")
        self.assertEqual(app_config.llm.timeout_s, 90)
        self.assertEqual(app_config.llm.api_key_env, "OPENAI_API_KEY")
        self.assertEqual(app_config.llm.extra_body, ["vendor-specific", {"raw": True}])
        self.assertFalse(app_config.llm.show_terminal_output)


if __name__ == "__main__":
    unittest.main()
