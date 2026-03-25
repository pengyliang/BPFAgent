from __future__ import annotations

import json
import difflib

from prompts.inspector import INSPECTOR_PROMPT
from prompts.inspector import INSPECTOR_CRITICAL_BLOCK_PROMPT
from src.agent.base import BaseAgent, read_text, rough_semantic_equivalent
from src.core.state import CaseState


def extract_critical_block(
    code: str,
    *,
    start_marker: str = "/* Crutial block */",
    end_marker: str = "/* Crutial block end */",
) -> str | None:
    """
    Extract the text between:
      start_marker (exclusive) ... end_marker (exclusive)
    Return None when either marker is missing.
    """
    if not code:
        return None
    start_idx = code.find(start_marker)
    if start_idx < 0:
        return None
    end_idx = code.find(end_marker, start_idx + len(start_marker))
    if end_idx < 0:
        return None
    block = code[start_idx + len(start_marker) : end_idx]
    block = block.strip("\n")
    if not block.strip():
        return None
    return block


def _normalize_for_similarity(s: str) -> str:
    # Collapse whitespace to reduce false negatives due to formatting-only changes.
    return "\n".join(line.strip() for line in (s or "").splitlines() if line.strip())


def _critical_block_similarity(a: str, b: str) -> float:
    aa = _normalize_for_similarity(a)
    bb = _normalize_for_similarity(b)
    if not aa or not bb:
        return 0.0
    return float(difflib.SequenceMatcher(a=aa, b=bb).ratio())


class InspectorAgent(BaseAgent):
    agent_name = "Inspector"
    thought_field = "inspector_thought"

    def run(self, state: CaseState) -> CaseState:
        previous_node = str(state.get("last_node") or "")
        # 保存上一轮 Inspector 的输出，用于本轮“主要约束”判断。
        prior_inspector_context = state.get("last_inspector_context") or {}
        prior_inspector_suggestion = str(prior_inspector_context.get("inspector_suggestion") or "").strip()
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
        initial_before_code = read_text(state.get("original_source_file") or "")
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
        inspector_suggestion = ""
        if self.llm is not None and before_code and after_code:
            system_prompt = INSPECTOR_PROMPT.render(
                {
                    "analyzer_context": json.dumps(analyzer_context, ensure_ascii=False, indent=2),
                    "previous_inspector_suggestion": prior_inspector_suggestion,
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
                inspector_suggestion = str(obj.get("suggestion") or "").strip()
                inspector_report = "\n".join(x for x in [report, inspector_suggestion] if x).strip() or inspector_report

        # Critical block check:
        # - Compare initial_source vs after_repair_code inside /* Crutial block */ ... /* Crutial block end */
        # - If the critical block changed too much, force fail (equivalent=false).
        critical_before = extract_critical_block(initial_before_code or "")
        critical_after = extract_critical_block(after_code or "")
        critical_ok: bool | None = None
        critical_reason: str = ""
        if critical_before and critical_after:
            sim = _critical_block_similarity(critical_before, critical_after)
            # Heuristic thresholds:
            # - high similarity => pass
            # - very low similarity => fail (force_fail, even when LLM is unavailable)
            # - mid similarity => defer to LLM when available
            if sim >= 0.9:
                critical_ok = True
                critical_reason = f"启发式通过：关键块相似度={sim:.3f} >= 0.9"
            elif sim <= 0.65:
                critical_ok = False
                critical_reason = f"启发式不通过：关键块相似度={sim:.3f} <= 0.65"
            else:
                if self.llm is not None:
                    system_prompt = INSPECTOR_CRITICAL_BLOCK_PROMPT.render(
                        {
                            "critical_before_code": critical_before,
                            "critical_after_code": critical_after,
                            "code_change_summary": state.get("last_code_change_summary") or "",
                        }
                    )
                    user_prompt = "请判断关键块的功能是否发生过大变化，并严格遵守 JSON 输出格式。"
                    raw_output_cb = self.call_llm(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        temperature=0.1,
                        max_tokens=700,
                    )
                    obj_cb = self.extract_json(raw_output_cb)
                    if obj_cb:
                        critical_ok = bool(obj_cb.get("critical_ok"))
                        critical_reason = str(obj_cb.get("report") or "") or f"LLM 判断 critical_ok={critical_ok}"

        if critical_before and critical_after and critical_ok is False:
            # Force fail: this check is specifically about limiting functional change in the marked block.
            equivalent = False
            if critical_reason:
                inspector_report = f"{inspector_report}\n\nCritical block check failed: {critical_reason}"
            else:
                inspector_report = f"{inspector_report}\n\nCritical block check failed: critical_ok=false"

        # 确保当判定不等价时（equivalent=false），也能给出可供 Repairer 参考的修复建议。
        if not equivalent:
            if not inspector_suggestion:
                # 优先沿用上一轮 Inspector 的建议要点，让 Repairer 能“在原方向上继续修”。
                if prior_inspector_suggestion:
                    inspector_suggestion = (
                        "Inspector 判定等价性失败：请对照上一轮 Inspector 的建议要点修复，并避免引入偏离建议之外的新改动。"
                    )
                else:
                    inspector_suggestion = (
                        "Inspector 判定等价性失败：请按 Analyzer 的 repair_action 做最小必要修复，并保持关键控制流/条件判断逻辑不被删除或彻底改写。"
                    )
            # 若 critical block 明确失败，更强调需要恢复关键功能，而不是泛化改动。
            if critical_ok is False:
                inspector_suggestion = (
                    inspector_suggestion
                    + "\n"
                    + "关键块校验失败：请在 /* Crutial block */ 范围内恢复关键逻辑/读取路径，禁止删除相关功能；"
                    + "允许变量名/缩进/空白/格式重排。"
                ).strip()
            # Repairer 侧主要通过 inspector_report 字符串读取；确保 suggestion 一定能呈现在报告里。
            if inspector_suggestion and inspector_suggestion not in (inspector_report or ""):
                inspector_report = "\n".join(x for x in [inspector_report, inspector_suggestion] if x).strip()

        state["semantic_equivalent"] = equivalent
        state["inspector_report"] = inspector_report
        self.set_thought(state, raw_output or inspector_report)
        state["last_inspector_context"] = {
            "source_before": source_before,
            "source_after": candidate_path,
            "critical_before": self._clip_text(critical_before, limit=4000) if critical_before else "",
            "critical_after": self._clip_text(critical_after, limit=4000) if critical_after else "",
            "critical_ok": critical_ok,
            "critical_reason": critical_reason,
            "analyzer_context": analyzer_context,
            "inspector_suggestion": inspector_suggestion,
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
                    "inspector_suggestion": inspector_suggestion,
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
