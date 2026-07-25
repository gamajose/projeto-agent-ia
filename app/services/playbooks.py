from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.core.settings import get_settings


@dataclass(frozen=True)
class Playbook:
    id: str
    title: str
    priority: int
    profiles: tuple[str, ...]
    patterns: tuple[str, ...]
    steps: tuple[dict[str, Any], ...]
    allowed_corrections: tuple[str, ...]
    validation_tools: tuple[dict[str, Any], ...]
    source: str

    def score(self, objective: str, profile: str) -> int:
        text = objective.casefold()
        score = self.priority
        if self.profiles and profile in self.profiles:
            score += 20
        elif self.profiles and "any" not in self.profiles:
            score -= 15
        matches = 0
        for pattern in self.patterns:
            try:
                if re.search(pattern, text, flags=re.IGNORECASE):
                    matches += 1
            except re.error:
                if pattern.casefold() in text:
                    matches += 1
        return score + matches * 30 if matches else -1


def _playbook_dir() -> Path:
    return Path(get_settings().agent_playbook_dir).expanduser()


@lru_cache(maxsize=1)
def load_playbooks() -> tuple[Playbook, ...]:
    result: list[Playbook] = []
    directory = _playbook_dir()
    if not directory.exists():
        return ()
    for path in sorted(directory.glob("*.yml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        match = payload.get("match") or {}
        result.append(
            Playbook(
                id=str(payload.get("id") or path.stem),
                title=str(payload.get("title") or path.stem),
                priority=int(payload.get("priority") or 0),
                profiles=tuple(str(item) for item in payload.get("profiles") or ("any",)),
                patterns=tuple(str(item) for item in match.get("any") or ()),
                steps=tuple(dict(item) for item in payload.get("steps") or ()),
                allowed_corrections=tuple(str(item) for item in payload.get("allowed_corrections") or ()),
                validation_tools=tuple(dict(item) for item in payload.get("validation") or ()),
                source=str(path),
            )
        )
    return tuple(result)


def reload_playbooks() -> tuple[Playbook, ...]:
    load_playbooks.cache_clear()
    return load_playbooks()


def select_playbook(objective: str, profile: str) -> Playbook | None:
    scored = sorted(
        ((playbook.score(objective, profile), playbook) for playbook in load_playbooks()),
        key=lambda item: item[0],
        reverse=True,
    )
    return scored[0][1] if scored and scored[0][0] >= 0 else None


def _render(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        result = value
        for key, replacement in context.items():
            result = result.replace("{{" + key + "}}", str(replacement or ""))
        return result
    if isinstance(value, dict):
        return {key: _render(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [_render(item, context) for item in value]
    return value


def render_steps(playbook: Playbook | None, context: dict[str, Any]) -> list[dict[str, Any]]:
    if not playbook:
        return []
    return [_render(dict(step), context) for step in playbook.steps]


def playbook_summary(playbook: Playbook | None) -> dict[str, Any] | None:
    if not playbook:
        return None
    return {
        "id": playbook.id,
        "title": playbook.title,
        "source": playbook.source,
        "allowed_corrections": list(playbook.allowed_corrections),
        "validation": list(playbook.validation_tools),
    }
