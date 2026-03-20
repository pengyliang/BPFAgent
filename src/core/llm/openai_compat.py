from __future__ import annotations

import json
import socket
import http.client
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


import socket
import urllib3.util.connection as urllib3_conn

# 强制 DNS 解析只返回 IPv4，避免连接阶段优先尝试 IPv6 卡住
urllib3_conn.allowed_gai_family = lambda: socket.AF_INET


@dataclass(frozen=True)
class OpenAICompatConfig:
    base_url: str
    model: str
    api_key: str
    timeout_s: int = 60


class OpenAICompatClient:
    """Minimal OpenAI-compatible chat.completions client via stdlib urllib.

    Works for DeepSeek (OpenAI-compatible) and can be reused for other providers.
    """

    def __init__(self, cfg: OpenAICompatConfig):
        self._cfg = cfg

    def chat_completions(
        self,
        *,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 1200,
    ) -> Dict[str, Any]:
        url = self._cfg.base_url.rstrip("/") + "/v1/chat/completions"
        payload = {
            "model": self._cfg.model,
            "messages": messages,
            "temperature": float(temperature),
            "max_tokens": int(max_tokens),
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._cfg.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=float(self._cfg.timeout_s)) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                return json.loads(text) if text else {}
        except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout, http.client.IncompleteRead) as exc:
            # Normalize errors into a dict so callers can decide fallback.
            return {
                "error": True,
                "error_type": exc.__class__.__name__,
                "error_message": str(exc),
            }


def extract_first_message_content(resp: Dict[str, Any]) -> Optional[str]:
    if not isinstance(resp, dict) or resp.get("error"):
        return None
    choices = resp.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return None
    content = msg.get("content")
    return str(content) if content is not None else None

