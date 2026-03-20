"""
Reflect agent prompt (template).

This prompt is designed to output ONE YAML rule object that can be merged into
repair_method.yaml deterministically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional


@dataclass(frozen=True)
class PromptTemplate:
    name: str
    parts: Mapping[str, str]

    def render(self, variables: Mapping[str, str], *, order: Optional[list[str]] = None) -> str:
        ordered_keys = order or list(self.parts.keys())
        merged = "\n\n".join(self.parts[k].strip("\n") for k in ordered_keys if k in self.parts)
        return merged.format(**variables)


_STRICT_OUTPUT = r"""
你必须只输出一段 YAML fenced code block（且只输出这一段，不要有任何多余字符）：

```yaml
id: "<stable_id>"
stage: "<static_check_failed|compile_failed|load_failed|attach_failed|runtime_test_failed|detach_failed>"
error_signature: "<stable_signature_or_empty>"
thought: "<llm_abstract_thought>"
rationale: "<llm_abstract_rationale>"
symptoms:
  - pattern: "<regex_or_substring_1>"
root_cause: "<one_sentence>"
fix_strategy:
  - "<bullet_1>"
constraints:
  kernel_min: null
  requires_btf: null
examples:
  - case: "<category>/<case_rel>"
    report: "<reflect_report_json_path>"
```

要求：
- `id` 必须稳定（建议基于 stage+error_signature 生成 slug）。
- `symptoms.pattern` 要尽量短且可匹配关键报错行（可用子串即可，不强制 regex）。
- `fix_strategy` 必须可复用（避免 case 专有变量名/路径）。
""".strip(
    "\n"
)


REFLECT_AGENT_PROMPT = PromptTemplate(
    name="ReflectAgent",
    parts={
        "role": r"""
你是 eBPF 兼容性修复的反思/总结专家。你的目标是把一次 case 的失败与修复尝试，提炼成可复用的“修复模式规则”，用于更新 repair_method.yaml。
""",
        "context": r"""
case: {case_display}
kernel: {kernel_version}
final_stage: {final_stage}
final_success: {final_success}
error_signature_counts:
{error_signature_counts}

recent_key_lines:
{key_lines}

attempts_summary:
{attempts_summary}
""",
        "output": _STRICT_OUTPUT,
    },
)

