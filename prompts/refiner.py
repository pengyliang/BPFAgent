from __future__ import annotations

from prompts.common import PromptTemplate


_STRICT_OUTPUT = r"""
你必须只输出一段 YAML fenced code block。

**层级约定**：`patterns` → `<pattern_id>` → pattern 元信息。

示例（新经验可只写本次要追加的条目）：

```yaml
patterns:
  "<pattern_id>":
    summary: "<根因摘要>"
    aliases:
      - "<本次观测到的 error_type 或 issue code>"
    stage_hints:
      - compile_failed
    can_fix: true
    repair_methods:
      - "<可复用的源码修复策略>"
```

对于不可自动修复的 pattern：

```yaml
patterns:
  "<pattern_id>":
    aliases:
      - "<本次观测到的 error_type 或 issue code>"
    stage_hints:
      - static_check_failed
    can_fix: false
    handoff: "<交给人工/环境处理的最小建议>"
```
""".strip("\n")


REFINER_PROMPT = PromptTemplate(
    name="RefinerAgent",
    parts={
        "role": r"""
你是 eBPF workflow 中的 Refiner，负责总结一次修复过程中的经验，并产出可写入知识库的规则。
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

shared_history:
{shared_history}

existing_repair_method:
{existing_repair_method}
""",
        "rules": r"""
要求：
- 只有当某次修复后，先前失败的 `fail_stage` 不再出现（即后续 deploy 进入了新 stage 或直接成功）时，才记录这条经验
- 回顾整个修复过程，而不是只看最终失败阶段；如果某次修复虽然没有最终 deploy 成功，但确实消除了某个 stage 的报错，也应提炼这条经验
- **先判断可修性**：必须先判断“是否仅通过源码修改即可解决当前问题并使后续阶段推进/成功”。判断依据仅来自本轮修复中对源码的修改与其效果（忽略/不假设部署环境或内核能力会额外改变）。
  - 若结论为“可以仅靠源码修复”，则输出 `can_fix: true`，并在 `repair_methods` 中给出**可复用**的源码修复策略。
  - 若结论为“不可以仅靠源码修复”（例如根因主要是部署环境/内核能力缺失/目标符号或 attach target 不存在/外部依赖约束等），则输出 `can_fix: false`，并使用 `handoff` 给出最小必要的人工/环境处理建议；此时不要写具体源码修改步骤。
- 知识库 YAML 结构为：`patterns:` 其下每个 `<pattern_id>:` 是一个稳定根因 pattern
- `pattern_id` 应尽量表达“根因类型”，而不是某个阶段暴露出的偶发现象；优先复用已有 pattern_id
- 若当前 case 看到的是旧 `error_type` / issue code / verifier type，而你把它归并到某个更稳定的 `pattern_id`，请把原始名字写入 `aliases`
- `stage_hints` 只能使用 deploy_summary 中已有的失败阶段：`static_check_failed`、`compile_failed`、`load_failed`、`attach_failed`、`runtime_test_failed`
- `repair_methods` 必须简洁，不超过 2 句话，不要有额外解释、背景或复盘描述
- `repair_methods` 必须是可复用的修复方式，避免写死 case 路径、具体文件名或一次性常量
- `handoff` 必须简洁，说明为何应停止自动源码修复以及建议的下一步
- **增量写入**：合并逻辑会按 `pattern_id` 合并，并对 `aliases`、`stage_hints`、`repair_methods` 做精确去重
- **与已有知识去重（完全由你在本提示内判断）：**
  - 对照 `existing_repair_method` 中该 `pattern_id` 下已有的 `aliases`、`stage_hints`、`repair_methods` 与 `handoff`
  - 若本次经验与已有内容**语义等价**（仅换说法、无新增可操作信息），则不要输出重复内容
  - 若是**实质不同**的修复角度、更精确的 pattern 命名或新增 alias/stage_hint，则输出对应条目
- 若没有值得新增的经验，输出空 YAML 映射：`{}`
""",
        "output": _STRICT_OUTPUT,
    },
)
