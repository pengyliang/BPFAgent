from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import tomllib  # py3.11+
except Exception:  # pragma: no cover
    tomllib = None


def _read_toml(path: str) -> Dict[str, Any]:
    if tomllib is None:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _get(d: Dict[str, Any], *keys: str, default=None):
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


@dataclass(frozen=True)
class LLMConfig:
    provider: str = "deepseek"  # deepseek|openai|anthropic (future)
    model: str = "deepseek-chat"
    base_url: str = "https://api.deepseek.com"
    timeout_s: int = 60
    enabled: bool = True

    # If provided, api_key takes precedence over env (less secure).
    api_key: Optional[str] = None
    api_key_env: str = "DEEPSEEK_API_KEY"


@dataclass(frozen=True)
class AgentConfig:
    enable_agent: bool = True
    agent_max_patches: int = 2


@dataclass(frozen=True)
class AppConfig:
    max_retry: int = 1
    log_level: int = 2
    agent: AgentConfig = AgentConfig()
    llm: LLMConfig = LLMConfig()


def load_app_config(config_path: str) -> AppConfig:
    data = _read_toml(config_path)

    max_retry = int(_get(data, "max_retry", default=1) or 1)
    log_level = int(_get(data, "log_level", default=2) or 2)

    agent_enable = bool(_get(data, "agent", "enable", default=True))
    agent_max_patches = int(_get(data, "agent", "max_patches", default=2) or 2)

    llm_enabled = bool(_get(data, "llm", "enabled", default=True))
    llm_provider = str(_get(data, "llm", "provider", default="deepseek") or "deepseek")
    llm_model = str(_get(data, "llm", "model", default="deepseek-chat") or "deepseek-chat")
    llm_base_url = str(_get(data, "llm", "base_url", default="https://api.deepseek.com") or "https://api.deepseek.com")
    llm_timeout_s = int(_get(data, "llm", "timeout_s", default=60) or 60)
    llm_api_key = _get(data, "llm", "api_key", default=None)
    if isinstance(llm_api_key, str):
        llm_api_key = llm_api_key.strip() or None
    else:
        llm_api_key = None

    # env mapping (no secrets in file)
    api_key_env = str(_get(data, "llm", "api_key_env", default="DEEPSEEK_API_KEY") or "DEEPSEEK_API_KEY")
    # Allow provider-specific sensible defaults.
    if llm_provider == "openai" and api_key_env == "DEEPSEEK_API_KEY":
        api_key_env = "OPENAI_API_KEY"
    if llm_provider == "anthropic" and api_key_env == "DEEPSEEK_API_KEY":
        api_key_env = "ANTHROPIC_API_KEY"

    return AppConfig(
        max_retry=max_retry,
        log_level=log_level,
        agent=AgentConfig(enable_agent=agent_enable, agent_max_patches=agent_max_patches),
        llm=LLMConfig(
            provider=llm_provider,
            model=llm_model,
            base_url=llm_base_url,
            timeout_s=llm_timeout_s,
            enabled=llm_enabled,
            api_key=llm_api_key,
            api_key_env=api_key_env,
        ),
    )


def get_api_key(llm_cfg: LLMConfig) -> Optional[str]:
    if llm_cfg.api_key:
        return str(llm_cfg.api_key).strip() or None
    key = os.environ.get(llm_cfg.api_key_env)
    if key:
        return key.strip()
    return None

