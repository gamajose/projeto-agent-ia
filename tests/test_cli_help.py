from __future__ import annotations

import io
import sys

from rich.console import Console

from app.cli import entrypoint
from app.cli.help_screen import render_full_help, should_show_full_help, should_show_version


def _rendered_help() -> str:
    stream = io.StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=180)
    render_full_help(console, version="1.1.1")
    return stream.getvalue()


def test_full_help_lists_all_operational_commands() -> None:
    output = _rendered_help()
    required = (
        "agent --menu",
        "agent ALVO [PROBLEMA...]",
        "agent replay UUID",
        "agent approve UUID TOKEN",
        "agent --version",
        "--ambiente, -a",
        "--porta, -p",
        "--modo",
        "--somente-validar",
        "investigar",
        "propor",
        "corrigir",
        "/status",
        "/evidencias",
        "/proposta",
        "/trocar-servidor IP",
        "arrume",
        "agent-worker run",
        "agent-worker run --once",
        "agent-worker job UUID",
        "python -m app.db.init_db",
        "uvicorn app.main:app",
        "docker compose -f docker-compose.lab.yml",
        "Nunca executa reboot",
    )
    for item in required:
        assert item in output


def test_top_level_help_aliases() -> None:
    assert should_show_full_help([])
    assert should_show_full_help(["--help"])
    assert should_show_full_help(["-h"])
    assert should_show_full_help(["help"])
    assert not should_show_full_help(["replay", "--help"])
    assert not should_show_full_help(["approve", "--help"])


def test_version_aliases() -> None:
    assert should_show_version(["--version"])
    assert should_show_version(["-V"])
    assert should_show_version(["version"])
    assert not should_show_version(["replay", "--version"])


def test_entrypoint_routes_only_top_level_help(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(entrypoint, "render_full_help", lambda console: calls.append("help"))
    monkeypatch.setattr(entrypoint, "legacy_main", lambda: calls.append("legacy"))

    monkeypatch.setattr(sys, "argv", ["agent", "--help"])
    entrypoint.main()
    assert calls == ["help"]

    calls.clear()
    monkeypatch.setattr(sys, "argv", ["agent", "replay", "--help"])
    entrypoint.main()
    assert calls == ["legacy"]
