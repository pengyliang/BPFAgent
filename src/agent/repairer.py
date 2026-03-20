from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from prompts.repairer import REPAIRER_PROMPT
from src.agent.base import BaseAgent, advance_pipeline_paths, build_error_signal, code_change_summary, program_name, read_text
from src.agent.repair.patterns import semantic_diff_signature
from src.agent.repair.single_agent import LLMFirstSingleAgentRepair
from src.core.state import CaseState

# 单次进入 Repairer 节点时，LLM 未给出可解析源码则重试生成（避免一次空回复就失败）。
MAX_REPAIRER_LLM_ATTEMPTS = 6
# 补丁与原文被判为无实质差异（no_change）时，额外让 LLM 重试生成。
MAX_REPAIRER_NO_CHANGE_LLM_ATTEMPTS = 6
# 内层 no_change 重试仍失败时，整轮重新生成（等同再次进入 Repairer 策略）；仅在有 LLM 时进行。
MAX_REPAIRER_NO_CHANGE_OUTER_ROUNDS = 3


class RepairerAgent(BaseAgent):
    agent_name = "Repairer"
    thought_field = "repairer_thought"

    def __init__(self, *, llm):
        super().__init__(llm=llm)
        self.rule_repair = LLMFirstSingleAgentRepair(llm=llm)

    def run(self, state: CaseState, *, use_pipeline_dirs: bool) -> CaseState:
        previous_node = str(state.get("last_node") or "")
        repair_idx = self.node_index(state, self.agent_name)
        repair_dir = self.node_base_dir(state, self.agent_name, repair_idx)
        if previous_node == "Analyzer":
            state["fixed_time"] = int(state.get("fixed_time") or 0) + 1
        state["last_node"] = self.agent_name

        inspector_context = state.get("last_inspector_context") or {}
        before_path = str(inspector_context.get("source_after") or state["current_source_file"])
        before_code = read_text(before_path)
        signal = build_error_signal(state)

        repair_context: dict[str, Any] = {
            "source_file": before_path,
            "source_code": before_code,
            "analysis_report": state.get("analysis_report"),
            "repair_action": state.get("repair_action"),
            "error_signal": {
                "stage": signal.stage,
                "error_types": signal.error_types,
                "key_lines": signal.key_lines,
            },
        }
        if previous_node == "Inspector":
            repair_context = {
                "source_file": before_path,
                "source_code": before_code,
                "inspector_input": inspector_context,
                "inspector_report": state.get("inspector_report"),
                "last_code_change_summary": state.get("last_code_change_summary"),
                "previous_node": "Inspector",
                "error_signal": {
                    "stage": signal.stage,
                    "error_types": signal.error_types,
                    "key_lines": signal.key_lines,
                },
            }
        shared_history = self.render_shared_history(state)

        patched_code: str | None = None
        rationale = ""
        raw_output = ""
        any_llm_nonempty = False
        repair_system_prompt: str | None = None
        diff_sig = "no_change"

        no_change_feedback = ""
        patch_resolved = False

        for outer_round in range(MAX_REPAIRER_NO_CHANGE_OUTER_ROUNDS):
            effective_context: dict[str, Any] = {**repair_context}
            if no_change_feedback:
                effective_context["outer_no_change_round"] = outer_round + 1
                effective_context["outer_no_change_hint"] = no_change_feedback

            repair_system_prompt = None
            patched_code = None
            if self.llm is not None:
                repair_system_prompt = REPAIRER_PROMPT.render(
                    {
                        "previous_node": previous_node or "Analyzer",
                        "shared_history": shared_history,
                        "repair_context": json.dumps(effective_context, ensure_ascii=False, indent=2),
                        "key_lines": "\n".join(signal.key_lines[:20]) or "(none)",
                        "source_code": before_code,
                    }
                )
                base_user = "请输出最小必要修改后的完整源码，并严格遵守 JSON 输出格式。"
                for attempt_i in range(MAX_REPAIRER_LLM_ATTEMPTS):
                    retry_hint = ""
                    if attempt_i > 0:
                        retry_hint = (
                            "\n\n上一次输出无法解析出有效的 patched_code（JSON 中 patched_code 字段或单独代码块）。"
                            "请重新输出：必须包含可编译的完整 .bpf.c 文件内容；"
                            "若用 JSON，则 patched_code 必须为非空字符串且为完整源码。"
                        )
                    user_prompt = base_user + retry_hint
                    temperature = min(0.2 + 0.1 * attempt_i, 0.52)
                    raw_output = self.call_llm(
                        system_prompt=repair_system_prompt,
                        user_prompt=user_prompt,
                        temperature=temperature,
                        max_tokens=1800,
                    )
                    if (raw_output or "").strip():
                        any_llm_nonempty = True
                    obj = self.extract_json(raw_output)
                    cand: str | None = None
                    if obj and isinstance(obj.get("patched_code"), str):
                        cand = str(obj.get("patched_code") or "").strip()
                        rationale = str(obj.get("rationale") or "")
                    elif raw_output:
                        extracted = self.extract_code(raw_output)
                        cand = str(extracted).strip() if extracted else None
                    if cand:
                        patched_code = cand
                        break
                    patched_code = None

            if not patched_code:
                attempt = self.rule_repair.repair(
                    current_code=before_code,
                    signal=signal,
                    patch_history=state.get("patch_history") or [],
                )
                if attempt.success:
                    patched_code = attempt.patched_code
                    rationale = attempt.rationale

            if not patched_code:
                if self.llm is None:
                    wf_reason = "llm_disabled"
                elif not any_llm_nonempty:
                    wf_reason = "llm_empty_response"
                else:
                    wf_reason = "llm_no_extractable_patch"
                return self._record_no_patch(
                    state=state,
                    repair_idx=repair_idx,
                    repair_dir=repair_dir,
                    previous_node=previous_node,
                    repair_context=repair_context,
                    before_path=before_path,
                    rationale=rationale,
                    raw_output=raw_output,
                    workflow_reason=wf_reason,
                )

            if not patched_code.endswith("\n"):
                patched_code += "\n"

            diff_sig = semantic_diff_signature(before_code, patched_code)
            if diff_sig == "no_change" and repair_system_prompt is not None:
                no_change_hint = (
                    "上一轮补丁与原始代码对比被判定为无实质差异（语义/规模等价）。"
                    "必须重新修改：产生**可观测的**源码差异，并针对当前失败阶段与 repair_context 中的建议；"
                    "禁止只改注释、空白或等价重排；patched_code 必须为完整 .bpf.c 文件。"
                )
                for nc_i in range(MAX_REPAIRER_NO_CHANGE_LLM_ATTEMPTS):
                    user_prompt = (
                        "请输出最小必要修改后的完整源码，并严格遵守 JSON 输出格式。\n\n"
                        + no_change_hint
                        + f"\n\n（无实质差异重试 {nc_i + 1}/{MAX_REPAIRER_NO_CHANGE_LLM_ATTEMPTS}）"
                    )
                    temperature = min(0.26 + 0.09 * nc_i, 0.55)
                    raw_output = self.call_llm(
                        system_prompt=repair_system_prompt,
                        user_prompt=user_prompt,
                        temperature=temperature,
                        max_tokens=1800,
                    )
                    if (raw_output or "").strip():
                        any_llm_nonempty = True
                    obj = self.extract_json(raw_output)
                    cand_nc: str | None = None
                    if obj and isinstance(obj.get("patched_code"), str):
                        cand_nc = str(obj.get("patched_code") or "").strip()
                        rationale = str(obj.get("rationale") or "") or rationale
                    elif raw_output:
                        extracted_nc = self.extract_code(raw_output)
                        cand_nc = str(extracted_nc).strip() if extracted_nc else None
                    if not cand_nc:
                        continue
                    patched_code = cand_nc
                    if not patched_code.endswith("\n"):
                        patched_code += "\n"
                    diff_sig = semantic_diff_signature(before_code, patched_code)
                    if diff_sig != "no_change":
                        break

            if diff_sig != "no_change":
                patch_resolved = True
                break

            # 仍为 no_change：无 LLM 时无法「再进一轮 Repairer」，直接结束外层。
            if repair_system_prompt is None:
                break

            no_change_feedback = (
                f"已连续 {outer_round + 1} 轮完整生成后仍被判定为与原始代码无实质差异。"
                "请改变修复策略：检查 map/counter、BPF_CORE_READ 与结构体字段、条件与 helper，"
                "禁止重复等价改写；必须产出与上一轮明显不同的实现。"
            )

        if not patch_resolved:
            state["candidate_source_file"] = None
            state["final_decision"] = "failed_no_patch"
            self.set_thought(state, raw_output or rationale or "补丁与原代码无差异。")
            state["last_code_change_summary"] = "补丁与原代码无差异。"
            return self._write_repair_record(
                state=state,
                repair_idx=repair_idx,
                repair_dir=repair_dir,
                previous_node=previous_node,
                repair_context=repair_context,
                patched=False,
                patched_path=None,
                rationale=rationale,
                next_deploy_index=None,
                workflow_outcome="failed_no_patch",
                workflow_reason="no_effective_change",
                workflow_note=rationale or "补丁与原始代码语义上等价，无实质改动",
            )

        next_pipeline = int(state.get("pipeline_index") or 1) + 1
        patched_path = repair_dir / f"{program_name(state)}_repair_{repair_idx}.bpf.c"
        patched_path.write_text(patched_code, encoding="utf-8")

        state["candidate_source_file"] = str(patched_path)
        state["current_source_file"] = str(patched_path)
        state["has_repaired"] = True
        state["final_decision"] = ""
        self.set_thought(state, raw_output or rationale or "已生成补丁。")
        state["last_code_change_summary"] = code_change_summary(before_code, patched_code)
        state.setdefault("patch_history", []).append(diff_sig)
        state.setdefault("retry_code_paths", []).append(str(patched_path))
        state.setdefault("repair_attempts", []).append(
            {
                "attempt_index": repair_idx,
                "stage": state.get("failed_stage"),
                "error_type": (state.get("repair_action") or {}).get("error_type"),
                "can_fix": state.get("can_fix"),
                "source_before": before_path,
                "patched": True,
                "patched_path": str(patched_path),
                "analysis_report": state.get("analysis_report"),
                "repair_method": (state.get("repair_action") or {}).get("repair_method"),
                "rationale": rationale or "生成补丁并进入 Inspector。",
            }
        )
        self.append_error_record(
            state,
            {
                "stage": state.get("failed_stage"),
                "patched": True,
                "source_before": before_path,
                "patched_path": str(patched_path),
                "diff_sig": diff_sig,
                "rationale": rationale,
            },
        )

        if use_pipeline_dirs:
            advance_pipeline_paths(state, next_pipeline=next_pipeline)
        else:
            state["attempt_index"] = next_pipeline

        return self._write_repair_record(
            state=state,
            repair_idx=repair_idx,
            repair_dir=repair_dir,
            previous_node=previous_node,
            repair_context=repair_context,
            patched=True,
            patched_path=str(patched_path),
            rationale=rationale,
            next_deploy_index=next_pipeline,
            workflow_outcome="patched",
            workflow_reason="patch_written",
            workflow_note=rationale or "已写出候选补丁，进入 Inspector",
        )

    def _record_no_patch(
        self,
        *,
        state: CaseState,
        repair_idx: int,
        repair_dir: Path,
        previous_node: str,
        repair_context: dict[str, Any],
        before_path: str,
        rationale: str,
        raw_output: str,
        workflow_reason: str,
    ) -> CaseState:
        state["candidate_source_file"] = None
        state["final_decision"] = "failed_no_patch"
        self.set_thought(state, raw_output or rationale or "未生成有效补丁。")
        state["last_code_change_summary"] = "未生成有效代码修改。"
        state.setdefault("repair_attempts", []).append(
            {
                "attempt_index": repair_idx,
                "stage": state.get("failed_stage"),
                "error_type": (state.get("repair_action") or {}).get("error_type"),
                "can_fix": state.get("can_fix"),
                "source_before": before_path,
                "patched": False,
                "patched_path": None,
                "analysis_report": state.get("analysis_report"),
                "repair_method": (state.get("repair_action") or {}).get("repair_method"),
                "rationale": rationale or "未生成有效补丁。",
            }
        )
        self.append_error_record(
            state,
            {
                "stage": state.get("failed_stage"),
                "patched": False,
                "source_before": before_path,
                "reason": rationale or "no_patch",
            },
        )
        note = rationale or "LLM 与规则均未产生可用补丁"
        return self._write_repair_record(
            state=state,
            repair_idx=repair_idx,
            repair_dir=repair_dir,
            previous_node=previous_node,
            repair_context=repair_context,
            patched=False,
            patched_path=None,
            rationale=rationale,
            next_deploy_index=None,
            workflow_outcome="failed_no_patch",
            workflow_reason=workflow_reason,
            workflow_note=note,
        )

    def _write_repair_record(
        self,
        *,
        state: CaseState,
        repair_idx: int,
        repair_dir: Path,
        previous_node: str,
        repair_context: dict[str, Any],
        patched: bool,
        patched_path: str | None,
        rationale: str,
        next_deploy_index: int | None,
        workflow_outcome: str,
        workflow_reason: str,
        workflow_note: str = "",
    ) -> CaseState:
        record_path = repair_dir / f"repair_record_{repair_idx}.json"
        outputs: dict[str, Any] = {
            "patched": patched,
            "patched_path": patched_path,
            "code_change_summary": state.get("last_code_change_summary"),
        }
        if patched_path:
            outputs["patched_code_file"] = patched_path
            outputs["rationale"] = rationale
        result_params: dict[str, Any] = {
            "fixed_time": state.get("fixed_time"),
        }
        if next_deploy_index is not None:
            result_params["next_deploy_index"] = next_deploy_index
        else:
            result_params["final_decision"] = state.get("final_decision")

        self.write_record(
            record_path,
            {
                "generated_at": self.now(),
                "node": self.agent_name,
                "node_index": repair_idx,
                "from_node": previous_node,
                "inputs": {
                    "shared_history": state.get("shared_history") or [],
                    "repair_context": repair_context,
                },
                "thought_process": state.get(self.thought_field),
                "outputs": outputs,
                "result_params": result_params,
            },
        )
        self.append_shared_history(
            state,
            node_name=self.agent_name,
            node_index=repair_idx,
            from_node=previous_node,
            inputs={
                "previous_node": previous_node,
                "repair_context": repair_context,
            },
            outputs=outputs,
            thought_process=state.get(self.thought_field),
            summary=(
                f"生成修复补丁，patched={patched}，"
                f"next={result_params.get('next_deploy_index') or result_params.get('final_decision')}"
            ),
        )
        event_result: dict[str, Any] = {
            "outcome": workflow_outcome,
            "reason": workflow_reason,
            "llm_enabled": self.llm is not None,
            "patched": patched,
        }
        if workflow_note:
            event_result["note"] = workflow_note
        if patched_path:
            event_result["next_deploy_index"] = next_deploy_index
        else:
            event_result["final_decision"] = state.get("final_decision")
        self.append_workflow_event(
            state,
            node_name=self.agent_name,
            node_index=repair_idx,
            from_node=previous_node,
            key_results=event_result,
        )
        return state
