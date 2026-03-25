from __future__ import annotations

from prompts.common import PromptTemplate


_STRICT_OUTPUT = r"""
你必须严格只输出一段 JSON fenced code block：

```json
{
  "thought": "概括性的思考过程，说明依据了哪些输入",
  "rationale": "为什么这样修改",
  "patched_code": "完整的修复后 eBPF C 源码字符串"
}
```
""".strip("\n")


REPAIRER_PROMPT = PromptTemplate(
    name="RepairerAgent",
    parts={
        "role": r"""
你是 BPFAgent（跨内核eBPF代码部署工具） workflow 中的 Repairer，负责在尽量不改变原始语义的前提下做最小必要修复。
""",
        "context": r"""
上一个节点: {previous_node}

统一历史摘要:
```json
{shared_history}
```

上一个节点提供的上下文:
```json
{repair_context}
```

关键报错行:
{key_lines}

当前源码:
```c
{source_code}
```
""",
        "rules": r"""
修复要求：
- 必须结合统一 history 理解前几轮修改是如何演进到当前状态的，避免重复引入已被 Inspector 否定的改法
- 保留`/* Crutial block */` 和`/* Crutial block end */` 的代码注释。
- 如果上一个节点是 Inspector，必须优先修复 Inspector 指出的语义偏差
- 不要输出解释性文本，只输出规定的 JSON 代码块
- `patched_code` 必须是完整源码，不是 diff
- 特别注意，和(*val)++相关的条件判断逻辑要保留, 不可删除。可以部分修改，但不能完全偏移原有逻辑（如删除相关判断或改为其他类型的判断）。
""",
        "output": _STRICT_OUTPUT,
    },
)
