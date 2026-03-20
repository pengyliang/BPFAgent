from __future__ import annotations

import json

from prompts.inspector import INSPECTOR_PROMPT
from src.agent.base import BaseAgent, read_text, rough_semantic_equivalent
from src.core.state import CaseState


class InspectorAgent(BaseAgent):
    agent_name = "Inspector"
    thought_field = "inspector_thought"

    def run(self, state: CaseState) -> CaseState:
        previous_node = str(state.get("last_node") or "")
        inspector_idx = self.node_index(state, self.agent_name)
        inspector_dir = self.node_base_dir(state, self.agent_name, inspector_idx)
        state["last_node"] = self.agent_name

        candidate_path = state.get("candidate_source_file")
        attempts = state.get("repair_attempts") or []
        source_before = ""
        if attempts:
            source_before = str((attempts[-1] or {}).get("source_before") or "")
        before_code = read_text(source_before)
        after_code = read_text(candidate_path or "")
        analyzer_context = {
            "analysis_report": state.get("analysis_report") or "",
            "repair_action": state.get("repair_action") or {},
        }
        shared_history = self.render_shared_history(state)

        equivalent = rough_semantic_equivalent(before_code, after_code)
        inspector_report = (
            "Fallback 检查通过：SEC 段一致且改动规模可接受。"
            if equivalent
            else "Fallback 检查未通过：修改前后 SEC 段或改动规模差异过大。"
        )

        raw_output = ""
        if self.llm is not None and before_code and after_code:
            system_prompt = INSPECTOR_PROMPT.render(
                {
                    "analyzer_context": json.dumps(analyzer_context, ensure_ascii=False, indent=2),
                    "shared_history": shared_history,
                    "before_code": before_code,
                    "after_code": after_code,
                    "code_change_summary": state.get("last_code_change_summary") or "",
                }
            )
            user_prompt = "请判断是否保持语义等价，并严格遵守 JSON 输出格式。"
            raw_output = self.call_llm(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.1,
                max_tokens=900,
            )
            obj = self.extract_json(raw_output)
            if obj:
                equivalent = bool(obj.get("equivalent"))
                report = str(obj.get("report") or "")
                suggestion = str(obj.get("suggestion") or "")
                inspector_report = "\n".join(x for x in [report, suggestion] if x).strip() or inspector_report

        state["semantic_equivalent"] = equivalent
        state["inspector_report"] = inspector_report
        self.set_thought(state, raw_output or inspector_report)
        state["last_inspector_context"] = {
            "source_before": source_before,
            "source_after": candidate_path,
            "analyzer_context": analyzer_context,
            "before_code": before_code,
            "after_code": after_code,
            "code_change_summary": state.get("last_code_change_summary"),
            "inspector_report": inspector_report,
            "semantic_equivalent": equivalent,
        }

        record_path = inspector_dir / f"inspector_record_{inspector_idx}.json"
        self.write_record(
            record_path,
            {
                "generated_at": self.now(),
                "node": self.agent_name,
                "node_index": inspector_idx,
                "from_node": previous_node,
                "inputs": {
                    "source_before": source_before,
                    "source_after": candidate_path,
                    "analyzer_context": analyzer_context,
                    "shared_history": state.get("shared_history") or [],
                    "before_code": before_code,
                    "after_code": after_code,
                    "code_change_summary": state.get("last_code_change_summary"),
                },
                "thought_process": state.get(self.thought_field),
                "outputs": {
                    "semantic_equivalent": equivalent,
                    "inspector_report": inspector_report,
                },
                "result_params": {
                    "will_next_go_to": "deploy_tool" if equivalent else "repairer",
                },
            },
        )
        self.append_shared_history(
            state,
            node_name=self.agent_name,
            node_index=inspector_idx,
            from_node=previous_node,
            inputs={
                "source_before": source_before,
                "source_after": candidate_path,
                "analyzer_context": analyzer_context,
                "code_change_summary": state.get("last_code_change_summary"),
            },
            outputs={
                "semantic_equivalent": equivalent,
                "inspector_report": inspector_report,
            },
            thought_process=state.get(self.thought_field),
            summary=f"检查补丁语义，equivalent={equivalent}，结论={inspector_report}",
        )
        self.append_workflow_event(
            state,
            node_name=self.agent_name,
            node_index=inspector_idx,
            from_node=previous_node,
            key_results={
                "semantic_equivalent": equivalent,
                # 这是 Inspector 的“检查结论”，用于 workflow_summary 直观展示。
                "inspector_report": self._clip_text(inspector_report, limit=320),
            },
        )
        return state
