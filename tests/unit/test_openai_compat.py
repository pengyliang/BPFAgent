import unittest

from src.core.llm.openai_compat import _build_stream_response, _merge_stream_text


class TestOpenAICompatStreamMerge(unittest.TestCase):
    def test_merge_incremental_chunks(self):
        merged, delta = _merge_stream_text("", "hel")
        self.assertEqual((merged, delta), ("hel", "hel"))

        merged, delta = _merge_stream_text(merged, "lo")
        self.assertEqual((merged, delta), ("hello", "lo"))

    def test_merge_cumulative_chunks(self):
        merged, delta = _merge_stream_text("hel", "hello")
        self.assertEqual((merged, delta), ("hello", "lo"))

    def test_merge_duplicate_chunk(self):
        merged, delta = _merge_stream_text("hello", "hello")
        self.assertEqual((merged, delta), ("hello", ""))

    def test_merge_overlapping_chunk(self):
        merged, delta = _merge_stream_text("hello", "lo world")
        self.assertEqual((merged, delta), ("hello world", " world"))

    def test_merge_older_shorter_cumulative_chunk(self):
        merged, delta = _merge_stream_text("hello world", "hello")
        self.assertEqual((merged, delta), ("hello worldhello", "hello"))

    def test_merge_trailing_closing_fence_chunk(self):
        merged, delta = _merge_stream_text("```json\n{}\n", "```")
        self.assertEqual((merged, delta), ("```json\n{}\n```", "```"))

    def test_merge_long_stale_prefix_chunk(self):
        current = "```json\n{\"patched_code\":\"abc\"}\n```"
        stale = "```json\n{\"patched"
        merged, delta = _merge_stream_text(current, stale)
        self.assertEqual((merged, delta), (current, ""))

    def test_build_stream_response_contains_finish_reason_meta(self):
        resp = _build_stream_response(content="", reasoning="thinking", finish_reason="length")
        self.assertEqual(resp["finish_reason"], "length")
        self.assertEqual(
            resp["stream_meta"],
            {
                "finish_reason": "length",
                "content_length": 0,
                "reasoning_length": 8,
                "content_empty": True,
                "reasoning_only": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
