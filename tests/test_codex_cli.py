from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.core.settings import Settings
from app.services.codex_cli import (
    CodexCLIStatus,
    codex_cli_status,
    launch_codex,
    resolve_codex_command,
)


def _settings(**overrides):
    values = {
        "postgres_dsn": "sqlite+pysqlite:///:memory:",
        "codex_cli_path": None,
        "codex_workdir": None,
        "codex_home": None,
    }
    values.update(overrides)
    return Settings(**values)


def test_resolve_codex_accepts_installation_directory(tmp_path: Path):
    binary = tmp_path / "node_modules" / ".bin" / "codex"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o700)

    assert resolve_codex_command(str(tmp_path)) == str(binary.resolve())


def test_codex_status_reads_version(tmp_path: Path):
    binary = tmp_path / "codex"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o700)
    settings = _settings(codex_cli_path=str(binary), codex_workdir=str(tmp_path))

    completed = SimpleNamespace(stdout="codex-cli 1.2.3\n", stderr="", returncode=0)
    with patch("app.services.codex_cli.subprocess.run", return_value=completed) as runner:
        status = codex_cli_status(settings)

    assert status.available is True
    assert status.version == "codex-cli 1.2.3"
    runner.assert_called_once_with(
        [str(binary.resolve()), "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_launch_codex_uses_configured_workdir_without_shell(tmp_path: Path):
    binary = tmp_path / "codex"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o700)
    settings = _settings(codex_cli_path=str(binary), codex_workdir=str(tmp_path))
    status = CodexCLIStatus(True, str(binary.resolve()), "codex-cli 1.2.3", str(tmp_path))
    completed = SimpleNamespace(returncode=0)

    with patch("app.services.codex_cli.codex_cli_status", return_value=status), patch(
        "app.services.codex_cli.subprocess.run", return_value=completed
    ) as runner:
        result = launch_codex(settings)

    assert result == 0
    args, kwargs = runner.call_args
    assert args[0] == [str(binary.resolve())]
    assert kwargs["cwd"] == str(tmp_path)
    assert kwargs["check"] is False
    assert "shell" not in kwargs
    assert kwargs["env"]["PATH"] == os.environ["PATH"]
