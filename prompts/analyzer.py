from __future__ import annotations

from prompts.common import PromptTemplate


_STRICT_OUTPUT = r"""
你必须严格只输出一段 JSON fenced code block：

```json
{
  "can_fix": true,
  "error_type": "error_type_name",
  "analysis_report": "对失败原因的可复盘分析",
  "repair_method": "给 Repairer 的具体修复建议"
}
```
""".strip("\n")


ANALYZER_PROMPT = PromptTemplate(
    name="AnalyzerAgent",
    parts={
        "role": r"""
你是 BPFAgent（跨内核eBPF代码部署工具） workflow 中的 Analyzer，负责分析 deploy 失败结果，判断是否能通过修改源码解决。注意如果当前内核版本不支持，可替换为相同功能的实现方式。
""",
        "context": r"""
失败阶段: {failed_stage}
错误签名: {error_signature}

统一历史摘要:
```json
{shared_history}
```

知识库规则（repair_method.yaml 摘取片段）:
{knowledge_rules}

知识库解读要点：
- 规则按「pattern_id → 根因摘要/aliases/stage_hints/can_fix/repair_methods/handoff」组织；`pattern_id` 是更稳定的根因类型，不一定等于当前表面的报错名
- 请优先根据当前 `error_signature` 命中的 `pattern_id` 或 `aliases` 选规则，再用 `failed_stage`、关键报错行和上下文做确认
- 输出 JSON 中的 `error_type` 应优先填写你最终判定的 `pattern_id`；若知识库无匹配，再退回最贴近的现象名
- 若命中 `can_fix=true` 的 pattern，请从 `repair_methods` 中选择最贴合的一条（必要时可简短综合）写入 `repair_method`
- 若命中 `can_fix=false` 的 pattern，请优先参考 `handoff`，并明确停止自动源码修复
- 如果没有合适的条目，则由你自行分析，并写入你输出 JSON 中的 `repair_method`

关键报错行:
{key_lines}

失败上下文（包含 failed_stage_result 与 deploy_summary）:
```json
{failed_payload}
```
""",
        "rules": r"""
判断标准：
- 需要参考统一 history，理解前几轮 analysis/repair/inspect 是如何演进到当前失败的
- 如果问题主要来自源码逻辑、字段访问、边界检查、helper/声明使用、attach 逻辑或运行时语义偏差，则 `can_fix=true`
- `error_type` 应尽量输出稳定的根因 pattern 名，而不是仅描述当前阶段症状
- `repair_method` 只能包含对源码的修改方案, 不要包含"检查","验证"等描述性文本或非源码方面的其他建议。以"修改代码"为开头.
- 特别注意，和(*val)++相关的条件判断逻辑要保留, 不可删除。
""",
        "output": _STRICT_OUTPUT,
    },
)
