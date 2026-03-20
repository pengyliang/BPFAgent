from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional


@dataclass(frozen=True)
class PromptTemplate:
    name: str
    parts: Mapping[str, str]

    def render(self, variables: Mapping[str, str], *, order: Optional[list[str]] = None) -> str:
        ordered_keys = order or list(self.parts.keys())
        merged = "\n\n".join(self.parts[k].strip("\n") for k in ordered_keys if k in self.parts)
        placeholder_tokens: dict[str, str] = {}
        for idx, key in enumerate(variables.keys()):
            token = f"__PROMPT_VAR_{idx}__"
            merged = merged.replace(f"{{{key}}}", token)
            placeholder_tokens[token] = key
        merged = merged.replace("{", "{{").replace("}", "}}")
        for token, key in placeholder_tokens.items():
            merged = merged.replace(token, f"{{{key}}}")
        return merged.format(**variables)
