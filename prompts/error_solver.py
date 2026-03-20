"""
Error Solver agent prompt (template).

This module intentionally keeps the prompt as structured, nestable fragments so
callers can compose or swap sections without editing a single giant string.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping, Optional


@dataclass(frozen=True)
class PromptTemplate:
    """
    A very small prompt template container.

    - parts: nestable fragments (header/context/instructions/formatters/etc.)
    - render: simple `.format(**vars)` substitution
    """

    name: str
    parts: Mapping[str, str]

    def render(self, variables: Mapping[str, str], *, order: Optional[list[str]] = None) -> str:
        ordered_keys = order or list(self.parts.keys())
        merged = "\n\n".join(self.parts[k].strip("\n") for k in ordered_keys if k in self.parts)
        return merged.format(**variables)


# -------------------------
# Tool call format (strict)
# -------------------------
_OUTPUT_JSON_SPEC = r"""
你必须严格按以下格式输出【且只输出这一段 JSON fenced code block】，不要有任何多余字符：

```json
{{
  "thought": "你的思考过程（用自然语言概述推理链路与关键证据，不要省略导致无法复盘）",
  "rationale": "你做出该修改的理由（要点式）",
  "patched_code": "完整的修复后 eBPF C 源码（字符串，保留换行）"
}}
```
""".strip("\n")


# -------------------------
# Patch output format (strict)
# -------------------------
_FILE_EDITOR_FORMAT_SPEC = r"""
注意：你的输出会被程序解析并写入到 {new_code_path}。不要输出 file_editor 块；只输出一个 JSON code block。
""".strip("\n")


ERROR_SOLVER_PROMPT = PromptTemplate(
    name="ErrorSolverAgent",
    parts={
        "role": r"""
你是一个 eBPF 专家，擅长 eBPF 代码的撰写和报错处理。
""",
        "pipeline": r"""
我的 eBPF 代码处理流程是：
source code(prog.bpf.c) -> static_check -> compile -> load_and_attach -> test
其中可能存在一些兼容性错误需要你帮我解决。
""",
        "incident": r"""
现在在 {error_state} 阶段出现了问题，请你解决该问题。
该阶段生成的结果文件为 {state_result_json}，报错信息为 {error_message_json}。
""",
        "repair_methods": r"""
常见 eBPF 兼容性问题修复方法如下，仅供参考：
{repair_method}
""",
        "more_info": r"""
如果需要更多信息，你还可以查看的文件有：
{usable_files}
""",
        "tools": r"""
你可以使用的工具包括：
{tool_info}
""",
        "strict_output": "\n\n".join([_FILE_EDITOR_FORMAT_SPEC, _OUTPUT_JSON_SPEC]),
    },
)


def build_error_solver_variables(
    *,
    error_state: str,
    state_result_json: str,
    error_message_json: str,
    repair_method: str,
    usable_files: str,
    tool_info: str,
    new_code_path: str,
) -> Dict[str, str]:
    """
    Helper to build the variables map for ERROR_SOLVER_PROMPT.render().
    All values are strings to keep formatting predictable for LLM prompts.
    """

    return {
        "error_state": error_state,
        "state_result_json": state_result_json,
        "error_message_json": error_message_json,
        "repair_method": repair_method,
        "usable_files": usable_files,
        "tool_info": tool_info,
        "new_code_path": new_code_path,
    }

