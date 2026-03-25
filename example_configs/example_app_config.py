provider = "deepseek"

enable_agent = True

enable_static_check = True

enable_analyzer = True
enable_inspector = True
enable_refiner = True

enable_knowledge_base = True

show_terminal_output = False

max_repair_attempts = 4
# 并发线程数：0 表示自动（当前策略：case 数量的一半，最少 1）
concurrent_workers = 0


model = ""
base_url = ""
api_key = ""

extra_body = {"enable_thinking": False}

if provider == "deepseek":
    model = "deepseek-chat"
    base_url = "https://api.deepseek.com"
    api_key = "your-api-key"


CONFIG = {
    "max_retry": 1,
    "log_level": 2,
    "max_repair_attempts": max_repair_attempts,
    "concurrent_workers": concurrent_workers,
    "agent_mode": enable_agent,
    "analyzer": enable_analyzer,
    "inspector": enable_inspector,
    "refiner": enable_refiner,
    "knowledge_base": enable_knowledge_base,
    "agent_max_patches": 2,
    "static_check": enable_static_check,
    "llm": {
        "enabled": True,
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "api_key": api_key,
        "timeout_s": 60,
        "extra_body": extra_body,
        "show_terminal_output": show_terminal_output,
    },
}
