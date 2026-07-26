from __future__ import annotations

import io
import os
from pathlib import Path
import subprocess
import sys

import pytest
from rich.console import Console

from app.cli import entrypoint
from app.cli.help_screen import render_full_help, should_show_full_help, should_show_version


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _rendered_help() -> str:
    stream = io.StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=180)
    render_full_help(console, version="1.2.0")
    return stream.getvalue()


def test_full_help_lists_all_operational_commands() -> None:
    output = _rendered_help()
    required = (
        "agent --menu",
        "agent ALVO [PROBLEMA...]",
        "agent replay UUID",
        "agent approve UUID TOKEN",
        "agent doctor ai",
        "agent --version",
        "--ambiente, -a",
        "--porta, -p",
        "--modo",
        "--somente-validar",
        "investigar",
        "propor",
        "corrigir",
        "OmniRoute — gateway centralizado",
        "Provedores diretos",
        "Ollama local",
        "OMNIROUTE_API_KEY",
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
    monkeypatch.setattr(entrypoint, "_run_legacy_cli", lambda: calls.append("legacy"))

    monkeypatch.setattr(sys, "argv", ["agent", "--help"])
    entrypoint.main()
    assert calls == ["help"]

    calls.clear()
    monkeypatch.setattr(sys, "argv", ["agent", "replay", "--help"])
    entrypoint.main()
    assert calls == ["legacy"]


def test_entrypoint_routes_ai_doctor_before_legacy_parser(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(entrypoint, "_run_ai_doctor", lambda: calls.append("doctor"))
    monkeypatch.setattr(entrypoint, "_run_legacy_cli", lambda: calls.append("legacy"))
    monkeypatch.setattr(sys, "argv", ["agent", "doctor", "ai"])

    entrypoint.main()

    assert calls == ["doctor"]


def test_entrypoint_routes_ai_doctor_help(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(entrypoint, "_run_ai_doctor_help", lambda: calls.append("doctor-help"))
    monkeypatch.setattr(entrypoint, "_run_legacy_cli", lambda: calls.append("legacy"))
    monkeypatch.setattr(sys, "argv", ["agent", "doctor", "ai", "--help"])

    entrypoint.main()

    assert calls == ["doctor-help"]


@pytest.mark.parametrize(
    ("argument", "expected"),
    [
        ("--version", "Agent IA Infra 1.2.1"),
        ("--help", "AGENT IA INFRA"),
    ],
)
def test_help_and_version_do_not_require_database_configuration(argument: str, expected: str) -> None:
    environment = os.environ.copy()
    environment.pop("POSTGRES_DSN", None)
    environment.pop("postgres_dsn", None)
    environment["PYTHONPATH"] = str(PROJECT_ROOT)

    result = subprocess.run(
        [sys.executable, "-m", "app.cli.entrypoint", argument],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert expected in result.stdout
    assert "postgres_dsn" not in result.stderr.lower()
