from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "app_config.py"


def _load_python_module(path: Path) -> Optional[ModuleType]:
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location("ebpf_agent_runtime_config", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _module_to_dict(module: Optional[ModuleType]) -> Dict[str, Any]:
    if module is None:
        return {}
    data = getattr(module, "CONFIG", None)
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
    provider: str = "deepseek"
    model: str = "deepseek-chat"
    base_url: str = "https://api.deepseek.com"
    timeout_s: int = 60
    enabled: bool = True
    api_key: Optional[str] = None
    api_key_env: str = "DEEPSEEK_API_KEY"
    extra_body: Any = None
    show_terminal_output: bool = True


@dataclass(frozen=True)
class AgentConfig:
    agent_mode: bool = True
    analyzer_enabled: bool = True
    inspector_enabled: bool = True
    refiner_enabled: bool = True
    knowledge_base_enabled: bool = True
    agent_max_patches: int = 2

    @property
    def enable_agent(self) -> bool:
        return self.agent_mode and self.analyzer_enabled


@dataclass(frozen=True)
class StaticCheckConfig:
    enabled: bool = True


@dataclass(frozen=True)
class AppConfig:
    max_retry: int = 1
    log_level: int = 2
    agent: AgentConfig = field(default_factory=AgentConfig)
    static_check: StaticCheckConfig = field(default_factory=StaticCheckConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)


def load_app_config(config_path: Optional[str] = None) -> AppConfig:
    path = Path(config_path or DEFAULT_CONFIG_PATH)
    data = _module_to_dict(_load_python_module(path))

    max_retry = int(_get(data, "max_retry", default=1) or 1)
    log_level = int(_get(data, "log_level", default=2) or 2)

    agent_mode = bool(_get(data, "agent_mode", default=True))
    analyzer_enabled = bool(_get(data, "analyzer", default=True))
    inspector_enabled = bool(_get(data, "inspector", default=True))
    refiner_enabled = bool(_get(data, "refiner", default=True))
    knowledge_base_enabled = bool(_get(data, "knowledge_base", default=True))
    agent_max_patches = int(_get(data, "agent_max_patches", default=2) or 2)
    raw_static_check = _get(data, "static_check", default=True)
    if isinstance(raw_static_check, dict):
        static_check_enabled = bool(raw_static_check.get("enabled", True))
    else:
        static_check_enabled = bool(raw_static_check)

    llm_enabled = bool(_get(data, "llm", "enabled", default=True))
    llm_provider = str(_get(data, "llm", "provider", default="deepseek") or "deepseek")
    llm_model = str(_get(data, "llm", "model", default="deepseek-chat") or "deepseek-chat")
    llm_base_url = str(_get(data, "llm", "base_url", default="https://api.deepseek.com") or "https://api.deepseek.com")
    llm_timeout_s = int(_get(data, "llm", "timeout_s", default=60) or 60)
    llm_extra_body = _get(data, "llm", "extra_body", default=None)
    llm_show_terminal_output = bool(_get(data, "llm", "show_terminal_output", default=True))
    llm_api_key = _get(data, "llm", "api_key", default=None)
    if isinstance(llm_api_key, str):
        llm_api_key = llm_api_key.strip() or None
    else:
        llm_api_key = None

    api_key_env = str(_get(data, "llm", "api_key_env", default="DEEPSEEK_API_KEY") or "DEEPSEEK_API_KEY")
    if llm_provider == "openai" and api_key_env == "DEEPSEEK_API_KEY":
        api_key_env = "OPENAI_API_KEY"
    if llm_provider == "anthropic" and api_key_env == "DEEPSEEK_API_KEY":
        api_key_env = "ANTHROPIC_API_KEY"

    return AppConfig(
        max_retry=max_retry,
        log_level=log_level,
        agent=AgentConfig(
            agent_mode=agent_mode,
            analyzer_enabled=analyzer_enabled,
            inspector_enabled=inspector_enabled,
            refiner_enabled=refiner_enabled,
            knowledge_base_enabled=knowledge_base_enabled,
            agent_max_patches=agent_max_patches,
        ),
        static_check=StaticCheckConfig(enabled=static_check_enabled),
        llm=LLMConfig(
            provider=llm_provider,
            model=llm_model,
            base_url=llm_base_url,
            timeout_s=llm_timeout_s,
            enabled=llm_enabled,
            api_key=llm_api_key,
            api_key_env=api_key_env,
            extra_body=llm_extra_body,
            show_terminal_output=llm_show_terminal_output,
        ),
    )


def get_api_key(llm_cfg: LLMConfig) -> Optional[str]:
    if llm_cfg.api_key:
        return str(llm_cfg.api_key).strip() or None
    key = os.environ.get(llm_cfg.api_key_env)
    if key:
        return key.strip()
    return None
