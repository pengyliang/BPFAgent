from __future__ import annotations

import json

from prompts.analyzer import ANALYZER_PROMPT
from src.agent.base import (
    BaseAgent,
    build_error_signal,
    canonical_pattern_id,
    default_can_fix,
    deploy_summary_payload,
    load_knowledge_rules,
    read_text,
    static_check_requires_environment_change,
    static_issue_codes,
)
from src.core.state import CaseState


class AnalyzerAgent(BaseAgent):
    agent_name = "Analyzer"
    thought_field = "analyzer_thought"

    def run(self, state: CaseState) -> CaseState:
        previous_node = str(state.get("last_node") or "")
        analyzer_idx = self.node_index(state, self.agent_name)
        analyzer_dir = self.node_base_dir(state, self.agent_name, analyzer_idx)
        state["last_node"] = self.agent_name

        deploy = state.get("deploy") or {}
        failed_stage = str(state.get("failed_stage") or deploy.get("stage") or "")
        failed_payload = state.get("failed_stage_result") or {}
        deploy_summary = deploy_summary_payload(state)
        shared_history = self.render_shared_history(state)
        analyzer_context = {
            "failed_stage": failed_stage,
            "failed_stage_result": failed_payload,
            "deploy_summary": deploy_summary,
        }
        signal = build_error_signal(state)
        kb_text = load_knowledge_rules(failed_stage, state.get("last_error_signature"), signal.key_lines[:20])
        current_code = read_text(state["current_source_file"])

        can_fix = default_can_fix(failed_stage, failed_payload)
        force_cannot_fix = failed_stage == "static_check_failed" and static_check_requires_environment_change(
            failed_payload
        )
        analysis_report = (
            f"阶段 `{failed_stage}` 失败；"
            f"识别到错误类型：{', '.join(signal.error_types) or 'unknown'}；"
            "建议优先做最小必要修复。"
        )
        repair_action: dict[str, object] = {
            "error_type": signal.error_types[0] if signal.error_types else "unknown",
            "repair_method": "最小改动修复当前失败阶段，并避免改变原始语义。",
            "key_lines": signal.key_lines[:10],
        }

        raw_output = ""
        if self.llm is not None:
            system_prompt = ANALYZER_PROMPT.render(
                {
                    "failed_stage": failed_stage,
                    "error_signature": str(state.get("last_error_signature") or ""),
                    "shared_history": shared_history,
                    "knowledge_rules": kb_text or "[]",
                    "key_lines": "\n".join(signal.key_lines[:20]) or "(none)",
                    "failed_payload": json.dumps(analyzer_context, ensure_ascii=False, indent=2),
                }
            )
            user_prompt = "请输出可复盘的分析结论，并严格遵守 JSON 输出格式。"
            raw_output = self.call_llm(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.1,
                max_tokens=900,
            )
            obj = self.extract_json(raw_output)
            if obj:
                can_fix = False if force_cannot_fix else bool(obj.get("can_fix"))
                analysis_report = str(obj.get("analysis_report") or analysis_report)
                repair_action = {
                    "error_type": str(obj.get("error_type") or repair_action["error_type"]),
                    "repair_method": str(obj.get("repair_method") or repair_action["repair_method"]),
                    "key_lines": signal.key_lines[:10],
                }

        if force_cannot_fix:
            can_fix = False
            forced_error_type = canonical_pattern_id((static_issue_codes(failed_payload) or [repair_action.get("error_type")])[0])
            if not analysis_report or analysis_report.startswith("阶段 `static_check_failed` 失败"):
                analysis_report = (
                    "静态检查失败，根因属于目标内核能力或部署环境约束，无法仅通过修改当前源码解决。"
                    "关键证据显示 attach type/attach target 在当前内核不受支持，或目标符号在部署内核上不存在。"
                    "此类问题应停止自动修复，改为提示更换内核、调整部署目标，或由人工重新设计挂载方式。"
                )
            repair_action = {
                "error_type": forced_error_type,
                "repair_method": "不要继续自动修复源码；直接报告目标内核/attach 目标不支持，结束修复流程。",
                "key_lines": signal.key_lines[:10],
            }

        state["can_fix"] = can_fix
        state["analysis_report"] = analysis_report
        state["repair_action"] = repair_action
        self.set_thought(state, raw_output or analysis_report)

        record_path = analyzer_dir / f"analyzer_record_{analyzer_idx}.json"
        self.write_record(
            record_path,
            {
                "generated_at": self.now(),
                "node": self.agent_name,
                "node_index": analyzer_idx,
                "from_node": previous_node,
                "inputs": {
                    "source_file": state.get("current_source_file"),
                    "source_code": current_code,
                    "failed_stage": failed_stage,
                    "failed_stage_result_path": state.get("failed_stage_result_path"),
                    "failed_stage_result": failed_payload,
                    "deploy_summary_path": state.get("deploy_result_path"),
                    "deploy_summary": deploy_summary,
                    "shared_history": state.get("shared_history") or [],
                    "error_signature": state.get("last_error_signature"),
                    "knowledge_rules": kb_text,
                    "error_signal": {
                        "stage": signal.stage,
                        "error_types": signal.error_types,
                        "key_lines": signal.key_lines,
                    },
                },
                "thought_process": state.get(self.thought_field),
                "outputs": {
                    "can_fix": can_fix,
                    "analysis_report": analysis_report,
                    "repair_action": repair_action,
                },
                "result_params": {
                    "fixed_time": state.get("fixed_time"),
                    "max_fix_time": state.get("max_fix_time"),
                },
            },
        )
        self.append_shared_history(
            state,
            node_name=self.agent_name,
            node_index=analyzer_idx,
            from_node=previous_node,
            inputs={
                "failed_stage": failed_stage,
                "failed_stage_result": failed_payload,
                "deploy_summary": deploy_summary,
            },
            outputs={
                "can_fix": can_fix,
                "analysis_report": analysis_report,
                "repair_action": repair_action,
            },
            thought_process=state.get(self.thought_field),
            summary=f"分析阶段 {failed_stage}，can_fix={can_fix}，建议={repair_action.get('repair_method') or ''}",
        )
        self.append_workflow_event(
            state,
            node_name=self.agent_name,
            node_index=analyzer_idx,
            from_node=previous_node,
            key_results={
                "can_fix": can_fix,
                "failed_stage": failed_stage,
                "error_type": str(repair_action.get("error_type") or ""),
                # 这是 Analyzer 给出的“建议修复方式”，用于 workflow_summary 直观展示。
                "repair_method": self._clip_text(str(repair_action.get("repair_method") or ""), limit=240),
                "analysis_report": self._clip_text(analysis_report, limit=320),
            },
        )
        return state
