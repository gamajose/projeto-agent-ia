from __future__ import annotations

import ipaddress
import os
import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

import yaml

from app.core.settings import get_settings
from app.services.operational_memory import (
    playbook_effectiveness_bonus,
    playbook_learning_summary,
    recommended_playbook_id,
)


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
    ssh_port: int | None = None

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


_PLAYBOOK_OVERRIDE: ContextVar[tuple[str, str | None]] = ContextVar(
    "agent_playbook_override",
    default=("auto", None),
)
_CURRENT_OBJECTIVE: ContextVar[str] = ContextVar(
    "agent_playbook_objective",
    default="",
)
_CURRENT_PROFILE: ContextVar[str] = ContextVar(
    "agent_playbook_profile",
    default="unknown",
)


def _playbook_dir() -> Path:
    return Path(get_settings().agent_playbook_dir).expanduser()


def _ssh_port(payload: dict[str, Any], path: Path) -> int | None:
    raw_port = payload.get("ssh_port")
    target = payload.get("target") or {}
    if raw_port in (None, "") and isinstance(target, dict):
        port_env = str(target.get("port_env") or "").strip()
        raw_port = os.getenv(port_env) if port_env else None
        if raw_port in (None, ""):
            raw_port = target.get("ssh_port")
        if raw_port in (None, ""):
            raw_port = target.get("default_port")
    if raw_port in (None, ""):
        return None
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"porta SSH inválida no playbook {path}: {raw_port!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"porta SSH fora do intervalo 1..65535 no playbook {path}: {port}")
    return port


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
                ssh_port=_ssh_port(payload, path),
            )
        )
    return tuple(result)


def reload_playbooks() -> tuple[Playbook, ...]:
    load_playbooks.cache_clear()
    return load_playbooks()


def list_playbooks() -> tuple[Playbook, ...]:
    return load_playbooks()


def get_playbook(playbook_id: str) -> Playbook:
    selected = (playbook_id or "").strip()
    for playbook in load_playbooks():
        if playbook.id == selected:
            return playbook
    raise LookupError(f"playbook '{selected}' não foi encontrado em {_playbook_dir()}")


@contextmanager
def use_playbook(mode: str = "auto", playbook_id: str | None = None) -> Iterator[None]:
    """Seleciona playbook automático, manual ou nenhum apenas na operação atual."""
    normalized = (mode or "auto").strip().lower()
    if normalized not in {"auto", "manual", "none"}:
        raise ValueError("modo de playbook deve ser auto, manual ou none")
    if normalized == "manual" and not playbook_id:
        raise ValueError("playbook_id é obrigatório no modo manual")
    if normalized == "manual":
        get_playbook(str(playbook_id))
    token = _PLAYBOOK_OVERRIDE.set((normalized, playbook_id))
    try:
        yield
    finally:
        _PLAYBOOK_OVERRIDE.reset(token)


def current_playbook_selection() -> tuple[str, str | None]:
    return _PLAYBOOK_OVERRIDE.get()


def select_playbook(objective: str, profile: str) -> Playbook | None:
    """Seleciona o playbook estático e usa o histórico do banco como reforço.

    As regras declaradas no YAML continuam sendo a fonte principal. O banco apenas
    desempata playbooks que já tiveram bons resultados e permite recuperar um
    playbook comprovado quando não existe correspondência textual suficiente.
    """
    _CURRENT_OBJECTIVE.set(objective or "")
    _CURRENT_PROFILE.set(profile or "unknown")
    mode, playbook_id = current_playbook_selection()
    if mode == "none":
        return None
    if mode == "manual":
        return get_playbook(str(playbook_id))

    scored: list[tuple[int, Playbook]] = []
    for playbook in load_playbooks():
        static_score = playbook.score(objective, profile)
        if static_score >= 0:
            static_score += playbook_effectiveness_bonus(playbook.id, profile)
        scored.append((static_score, playbook))
    scored.sort(key=lambda item: item[0], reverse=True)
    if scored and scored[0][0] >= 0:
        return scored[0][1]

    learned_id = recommended_playbook_id(objective, profile)
    if learned_id:
        try:
            return get_playbook(learned_id)
        except LookupError:
            return None
    return None


def selected_playbook_ssh_port(objective: str, profile: str = "unknown") -> tuple[int | None, str | None]:
    """Retorna a porta do playbook selecionado antes da conexão, quando declarada."""
    playbook = select_playbook(objective, profile)
    if not playbook or playbook.ssh_port is None:
        return None, playbook.id if playbook else None
    return playbook.ssh_port, playbook.id


def _objective_addresses(objective: str) -> list[str]:
    addresses: list[str] = []
    for candidate in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", objective or ""):
        try:
            address = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


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

    render_context = dict(context)
    addresses = _objective_addresses(_CURRENT_OBJECTIVE.get())
    render_context.setdefault("objective_ip", addresses[0] if addresses else "")
    render_context.setdefault("objective_ips", ",".join(addresses))

    rendered: list[dict[str, Any]] = []
    for source_step in playbook.steps:
        required_context = source_step.get("requires_context")
        required_keys = (
            [str(required_context)]
            if isinstance(required_context, str)
            else [str(item) for item in (required_context or [])]
        )
        if any(not str(render_context.get(key) or "").strip() for key in required_keys):
            continue
        step = {key: value for key, value in source_step.items() if key != "requires_context"}
        rendered.append(_render(step, render_context))
    return rendered


def playbook_summary(playbook: Playbook | None) -> dict[str, Any] | None:
    if not playbook:
        return None
    return {
        "id": playbook.id,
        "title": playbook.title,
        "source": playbook.source,
        "ssh_port": playbook.ssh_port,
        "allowed_corrections": list(playbook.allowed_corrections),
        "validation": list(playbook.validation_tools),
        "database_learning": playbook_learning_summary(
            playbook.id,
            _CURRENT_PROFILE.get(),
        ),
    }
