from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from src.agent.repair.patterns import ErrorSignal, semantic_diff_signature
from src.core.llm.openai_compat import OpenAICompatClient, extract_first_message_content


def _has_include(text: str, header: str) -> bool:
    needle1 = f"#include <{header}>"
    needle2 = f"#include \"{header}\""
    return needle1 in (text or "") or needle2 in (text or "")


def _inject_includes(text: str, headers: List[str]) -> Tuple[str, bool]:
    src = text or ""
    lines = src.splitlines()

    # Insert after last existing include, otherwise at top.
    insert_at = 0
    for i, ln in enumerate(lines):
        if ln.strip().startswith("#include"):
            insert_at = i + 1

    added = False
    to_add = []
    for h in headers:
        if not _has_include(src, h):
            to_add.append(f"#include <{h}>")
    if to_add:
        lines[insert_at:insert_at] = to_add + [""]
        added = True
    return "\n".join(lines) + ("\n" if src.endswith("\n") else ""), added


@dataclass
class RepairAttempt:
    success: bool
    patched_code: str
    diff_sig: str
    confidence: float
    rationale: str


@dataclass
class RuleBasedSingleAgentRepair:
    """Stage-2 MVP: deterministic, rule-based repairer.

    This intentionally does not modify original files under data/. It returns
    patched source text; caller decides where to write it.
    """

    def repair(self, *, current_code: str, signal: ErrorSignal, patch_history: Optional[List[str]] = None) -> RepairAttempt:
        patch_history = patch_history or []
        before = current_code or ""
        after = before
        rationale_parts: List[str] = []
        confidence = 0.2

        if "missing_header" in signal.error_types or "missing_declaration" in signal.error_types:
            # Common libbpf skeleton headers for SEC()/helpers.
            after, changed1 = _inject_includes(after, ["linux/bpf.h", "bpf/bpf_helpers.h", "bpf/bpf_tracing.h"])
            if changed1:
                rationale_parts.append("注入常用 eBPF 头文件以解决缺失声明/SEC 宏等编译错误。")
                confidence = 0.55

        # If verifier complains about unknown helper, often missing bpf_helpers.h (already handled above),
        # otherwise we avoid risky semantic changes in MVP.
        if "unknown_func" in signal.error_types and after == before:
            after, changed2 = _inject_includes(after, ["bpf/bpf_helpers.h"])
            if changed2:
                rationale_parts.append("尝试补全 bpf_helpers.h 以解决 unknown func/宏声明缺失。")
                confidence = max(confidence, 0.5)

        diff_sig = semantic_diff_signature(before, after)
        if diff_sig == "no_change":
            return RepairAttempt(
                success=False,
                patched_code=before,
                diff_sig=diff_sig,
                confidence=0.0,
                rationale="未找到安全的规则修复动作（保持源码不变）。",
            )

        # Loop prevention: do not apply same diff signature repeatedly.
        if diff_sig in patch_history:
            return RepairAttempt(
                success=False,
                patched_code=before,
                diff_sig=diff_sig,
                confidence=0.0,
                rationale="检测到重复补丁（可能进入循环），停止本次修复。",
            )

        return RepairAttempt(
            success=True,
            patched_code=after,
            diff_sig=diff_sig,
            confidence=confidence,
            rationale="".join(rationale_parts) if rationale_parts else "应用了最小规则补丁。",
        )


def _extract_code_block(text: str) -> Optional[str]:
    """Extract first fenced code block; prefer ```c or plain ```."""
    if not text:
        return None
    m = re.search(r"```(?:c)?\s*\n([\s\S]*?)```", text, flags=re.IGNORECASE)
    if not m:
        return None
    code = m.group(1)
    return code.strip("\n") + "\n"


@dataclass
class LLMFirstSingleAgentRepair:
    """LLM-first repair with rule fallback."""

    llm: Optional[OpenAICompatClient] = None
    rule_fallback: RuleBasedSingleAgentRepair = field(default_factory=RuleBasedSingleAgentRepair)

    def repair(self, *, current_code: str, signal: ErrorSignal, patch_history: Optional[List[str]] = None) -> RepairAttempt:
        patch_history = patch_history or []
        before = current_code or ""

        if self.llm is not None:
            sys_prompt = (
                "你是资深 eBPF 开发专家。你的任务是修复给定的 eBPF C 源码，使其在目标内核上更可能通过编译/Verifier。"
                "只做最小必要改动；不要改业务语义；不要添加与修复无关的功能。"
                "输出必须只包含一段 fenced code block（```c ... ```），内容为完整修复后的源码。"
            )
            user_prompt = (
                "失败阶段：{stage}\n"
                "错误类型：{types}\n"
                "关键报错行：\n{key}\n\n"
                "源码如下：\n```c\n{code}\n```\n"
            ).format(
                stage=signal.stage,
                types=", ".join(signal.error_types),
                key="\n".join(signal.key_lines[:30]),
                code=before,
            )
            resp = self.llm.chat_completions(
                messages=[{"role": "system", "content": sys_prompt}, {"role": "user", "content": user_prompt}],
                temperature=0.2,
                max_tokens=1400,
            )
            content = extract_first_message_content(resp) or ""
            patched = _extract_code_block(content)
            if patched:
                diff_sig = semantic_diff_signature(before, patched)
                if diff_sig != "no_change" and diff_sig not in patch_history:
                    return RepairAttempt(
                        success=True,
                        patched_code=patched,
                        diff_sig=diff_sig,
                        confidence=0.7,
                        rationale="LLM 生成补丁（OpenAI-compatible chat.completions）。",
                    )

        # fallback to deterministic rules
        return self.rule_fallback.repair(current_code=before, signal=signal, patch_history=patch_history)


def write_patched_source(
    *,
    original_source_path: str,
    patched_code: str,
    output_dir: str,
    case_name: str,
    attempt_index: int,
) -> str:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{case_name}.{attempt_index}.bpf.c"
    out_path.write_text(patched_code or "", encoding="utf-8")
    return str(out_path)

