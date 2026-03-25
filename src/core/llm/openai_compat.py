from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from openai import OpenAI  # pyright: ignore[reportMissingImports]


def _print_llm_error(*, model: str, error_type: str, error_message: str) -> None:
    print(f"[LLM ERROR] model={model} type={error_type}")
    if error_message:
        print(f"[LLM ERROR] message={error_message}", flush=True)
    else:
        print("[LLM ERROR] message=<empty>", flush=True)


@dataclass(frozen=True)
class OpenAICompatConfig:
    base_url: str
    model: str
    api_key: str
    timeout_s: int = 20
    extra_body: Any = None
    show_terminal_output: bool = True


class OpenAICompatClient:
    """OpenAI-compatible client backed by the official OpenAI SDK."""

    def __init__(self, cfg: OpenAICompatConfig):
        self._cfg = cfg
        self._client = OpenAI(
            api_key=cfg.api_key,
            base_url=cfg.base_url,
            timeout=float(cfg.timeout_s),
            max_retries=0,
        )

    @property
    def show_terminal_output(self) -> bool:
        return bool(self._cfg.show_terminal_output)

    def chat_completions(
        self,
        *,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 1200,
        stream: bool = False,
        on_delta: Optional[Callable[[str], None]] = None,
        on_reasoning_delta: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self._cfg.model,
            "messages": messages,
            "temperature": float(temperature),
            "max_tokens": int(max_tokens),
        }
        if stream:
            payload["stream"] = True
        if self._cfg.extra_body is not None:
            payload["extra_body"] = self._cfg.extra_body
        try:
            if stream:
                return self._stream_chat_completions(
                    payload,
                    on_delta=on_delta,
                    on_reasoning_delta=on_reasoning_delta,
                )
            resp = self._client.chat.completions.create(**payload)
            return resp.model_dump()
        except Exception as exc:
            # 即使关闭实时终端输出，也要显式打印 LLM 错误，
            # 避免出现“无反馈”而难以定位问题。
            _print_llm_error(
                model=self._cfg.model,
                error_type=exc.__class__.__name__,
                error_message=str(exc),
            )
            return {
                "error": True,
                "error_type": exc.__class__.__name__,
                "error_message": str(exc),
            }

    def _stream_chat_completions(
        self,
        payload: Dict[str, Any],
        *,
        on_delta: Optional[Callable[[str], None]] = None,
        on_reasoning_delta: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        content = ""
        reasoning = ""
        finish_reason: Optional[str] = None
        stream = self._client.chat.completions.create(**payload)
        for chunk in stream:
            chunk_dict = chunk.model_dump()
            chunk_finish_reason = _extract_finish_reason(chunk_dict)
            if chunk_finish_reason:
                finish_reason = chunk_finish_reason
            reasoning_piece, content_piece = _extract_stream_delta_parts(chunk_dict)
            if reasoning_piece:
                reasoning, reasoning_delta = _merge_stream_text(reasoning, reasoning_piece)
                if reasoning_delta and on_reasoning_delta is not None:
                    on_reasoning_delta(reasoning_delta)
            if content_piece:
                content, content_delta = _merge_stream_text(content, content_piece)
                if content_delta and on_delta is not None:
                    on_delta(content_delta)
        if self.show_terminal_output and finish_reason == "length" and not content.strip() and reasoning.strip():
            print("[LLM WARNING] thinking 阶段耗尽输出预算，未产生最终 content。", flush=True)
        return _build_stream_response(content=content, reasoning=reasoning, finish_reason=finish_reason)


def _coerce_message_content(content: Any) -> Optional[str]:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if isinstance(text, str):
                parts.append(text)
        merged = "".join(parts)
        return merged or None
    return None


def _merge_stream_text(existing: str, incoming: str) -> tuple[str, str]:
    current = str(existing or "")
    piece = str(incoming or "")
    if not piece:
        return current, ""
    if not current:
        return piece, piece
    if piece == current:
        return current, ""
    if piece.startswith(current):
        return piece, piece[len(current) :]
    # Ignore obviously stale cumulative chunks that are just an older long prefix
    # of the current content. Keep short pieces like trailing ``` / } / \n so they
    # can still be appended as genuine incremental output.
    if len(piece) >= 16 and current.startswith(piece):
        return current, ""

    max_overlap = min(len(current), len(piece))
    for overlap in range(max_overlap, 1, -1):
        if current.endswith(piece[:overlap]):
            delta = piece[overlap:]
            return current + delta, delta

    return current + piece, piece


def _extract_finish_reason(item: Dict[str, Any]) -> Optional[str]:
    choices = item.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    choice = choices[0] if isinstance(choices[0], dict) else {}
    finish_reason = choice.get("finish_reason") if isinstance(choice, dict) else None
    return str(finish_reason) if finish_reason else None


def _build_stream_response(*, content: str, reasoning: str, finish_reason: Optional[str]) -> Dict[str, Any]:
    content_text = str(content or "")
    reasoning_text = str(reasoning or "")
    return {
        "choices": [
            {
                "message": {
                    "content": content_text,
                }
            }
        ],
        "finish_reason": finish_reason,
        "stream_meta": {
            "finish_reason": finish_reason,
            "content_length": len(content_text),
            "reasoning_length": len(reasoning_text),
            "content_empty": not bool(content_text.strip()),
            "reasoning_only": bool(reasoning_text.strip()) and not bool(content_text.strip()),
        },
    }


def _extract_stream_delta_parts(item: Dict[str, Any]) -> tuple[str, str]:
    choices = item.get("choices")
    if not isinstance(choices, list) or not choices:
        return "", ""
    choice = choices[0] if isinstance(choices[0], dict) else {}
    delta = choice.get("delta") if isinstance(choice, dict) else {}
    if not isinstance(delta, dict):
        delta = {}
    reasoning_content = _coerce_message_content(delta.get("reasoning_content"))
    if not reasoning_content:
        reasoning = delta.get("reasoning")
        if isinstance(reasoning, dict):
            reasoning_content = _coerce_message_content(reasoning.get("content"))
        elif reasoning is not None:
            reasoning_content = _coerce_message_content(reasoning)
    content = _coerce_message_content(delta.get("content"))
    message = choice.get("message") if isinstance(choice, dict) else {}
    fallback = ""
    if isinstance(message, dict):
        fallback = _coerce_message_content(message.get("content")) or ""
    return reasoning_content or "", content or fallback


def extract_first_message_content(resp: Dict[str, Any]) -> Optional[str]:
    if not isinstance(resp, dict) or resp.get("error"):
        return None
    choices = resp.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return None
    return _coerce_message_content(msg.get("content"))

