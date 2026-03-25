from __future__ import annotations

from prompts.common import PromptTemplate


_STRICT_OUTPUT = r"""
你必须严格只输出一段 JSON fenced code block：

```json
{
  "equivalent": true | false,
  "report": "对修改前后语义差异的分析",
  "suggestion": "给 Repairer 的下一步建议(equivalent为false时填写)"
}
```
""".strip("\n")


INSPECTOR_PROMPT = PromptTemplate(
    name="InspectorAgent",
    parts={
        "role": r"""
你是 BPFAgent（跨内核eBPF代码部署工具） workflow 中的 Inspector，负责检查修复前后代码是否符合“修复方向约束”：
1) 若存在上一轮 Inspector 给出的 repair 建议（equivalent=false 时的 suggestion），则以它为主要约束，判断本轮 repair 是否仍偏离；
2) 若上一轮 Inspector 未提供建议，则以 Analyzer 给出的修复建议为主要约束；
满足主要约束的视为 `equivalent=true`。
""",
        "context": r"""
Analyzer 给出的修复建议（当上一轮 Inspector 未提供建议时使用）:
```json
{analyzer_context}
```

上一轮 Inspector 的修复建议（equivalent=false 时用于 Repairer 的 suggestion）:
```json
{previous_inspector_suggestion}
```

统一历史摘要:
```json
{shared_history}
```

修改前代码:
```c
{before_code}
```

修改后代码:
```c
{after_code}
```

代码修改摘要:
{code_change_summary}
""",
        "rules": r"""
判断要求：
- 必须结合统一 history，理解之前每轮 repair/inspect 的演进，避免只根据本轮代码片段做孤立判断
- 当 `previous_inspector_suggestion` 非空时：必须以其中的建议为主要约束判断；仅当本轮修改与上一轮 Inspector 建议一致、且没有引入其建议之外的明显偏差时，才允许 `equivalent=true`。
- 当 `previous_inspector_suggestion` 为空时：必须结合 Analyzer 给出的 `analysis_report` 与 `repair_action` 判断当前修改是否符合预期修复方向。
- 只要修改与“主要约束”一致，且没有主要约束之外的其他部分, 就视为 `equivalent=true`. 不需要考虑其他因素
- 特别注意，和(*val)++相关的条件判断逻辑要保留, 不可删除。可以部分修改，但如果完全偏移原有逻辑（如删除相关判断或改为其他类型的判断），则视为 `equivalent=false`。
""",
        "output": _STRICT_OUTPUT,
    },
)


_STRICT_CRITICAL_BLOCK_OUTPUT = r"""
你必须严格只输出一段 JSON fenced code block：

```json
{
  "critical_ok": true | false,
  "report": "说明关键块功能是否被删除；允许的重命名/格式变化/代码替换不应导致 critical_ok=false"
}
```
""".strip("\n")


INSPECTOR_CRITICAL_BLOCK_PROMPT = PromptTemplate(
    name="InspectorCriticalBlockAgent",
    parts={
        "role": r"""
你是 eBPF workflow 中的 Inspector 的辅助判断器，只关注关键块（由注释标记）是否发生了功能删除。其他的变化不用关注。
""",
        "context": r"""
代码修改摘要：
{code_change_summary}

关键块修改前（来自初始源码，/* Crutial block */ 范围）：
```c
{critical_before_code}
```

关键块修改后（来自 after_repair 源码，/* Crutial block */ 范围）：
```c
{critical_after_code}
```
""",
        "rules": r"""
判断要求：
- 你不需要判断逻辑是否等价；只需判断关键块“功能/逻辑”是否被删除。
- 允许：变量名/缩进/空白变化；格式重排；允许宽松的代码替换，如替换等价 helper 或类似的读取方式（例如 bpf_get_current_task_btf vs 其他返回 task 指针的方案， MAP_TYPE替换等）；。
- 不允许：相关功能被完全删除。
- 输出必须严格满足 JSON 格式，并给出 report。
""",
        "output": _STRICT_CRITICAL_BLOCK_OUTPUT,
    },
)
