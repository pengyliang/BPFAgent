from __future__ import annotations

from prompts.common import PromptTemplate


_STRICT_OUTPUT = r"""
你必须只输出一段 YAML fenced code block。

**层级约定**：`<fail_stage>` → `<error_type>` → **methods 列表**（一条或多条 `repair_method` 字符串）。

示例（新经验可只写本次要追加的条目；亦可用列表一次写多条）：

```yaml
compile_failed:
  "<error_type>":
    - "<repair_method>"
load_failed:
  "<error_type>": "<单条 repair_method 亦可>"
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
  - 若结论为“可以仅靠源码修复”，则对该 `<error_type>` 的 `repair_method` 输出 `can_fix=true+...`，并给出**可复用**的源码修复策略。
  - 若结论为“不可以仅靠源码修复”（例如根因主要是部署环境/内核能力缺失/目标符号或 attach target 不存在/外部依赖约束等），则对该 `<error_type>` 的 `repair_method` 必须输出 `can_fix=false+...`，并且 `repair_method` **不要**写具体源码修改步骤（只给出最小必要的不可修提示/下一步建议，例如“需要更换内核或调整部署目标，停止自动源码修复”等）。
- 知识库 YAML 结构为：`<fail_stage>:` 其下每个 `<error_type>:` 对应 **若干条** `repair_method`（YAML 中写作**列表**；仅一条时可写单个字符串，下游仍会归一为列表的一项）
- `fail_stage` 只能使用 deploy_summary 中已有的失败阶段：`static_check_failed`、`compile_failed`、`load_failed`、`attach_failed`、`runtime_test_failed`
- `error_type` 应尽量稳定，优先使用已有 error_type / issue code / verifier error type；不要发明和 case 强绑定的名字
- `repair_method` 必须使用严格格式：`can_fix=true/false+具体修复策略`
- `repair_method` 必须简洁，不超过 2 句话，不要有额外解释、背景或复盘描述
- `repair_method` 必须是可复用的修复方式，避免写死 case 路径、具体文件名或一次性常量
- **增量写入**：合并逻辑会在同一 `error_type` **末尾追加**新条目，不会在代码侧做「语义相似」合并
- **与已有知识去重（完全由你在本提示内判断）：**
  - 对照 `existing_repair_method` 中该 `fail_stage` + `error_type` 下**已有列表中的每一项**
  - 若本次经验与其中任一条**语义等价**（仅换说法、无新增可操作信息），则**不要**输出该 `error_type` 或不要输出重复条目
  - 若是**实质不同**的修复角度、更精确的步骤，则输出对应条目；会作为新一项追加到该 `error_type` 下
- 若没有值得新增的经验，输出空 YAML 映射：`{}`
""",
        "output": _STRICT_OUTPUT,
    },
)
