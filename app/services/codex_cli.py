from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.core.settings import PROJECT_ROOT, Settings, get_settings


class CodexCLIError(RuntimeError):
    """Erro esperado ao localizar ou iniciar o Codex CLI."""


@dataclass(frozen=True)
class CodexCLIStatus:
    available: bool
    command: str | None
    version: str
    workdir: str


def _is_executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _directory_candidates(directory: Path) -> tuple[Path, ...]:
    return (
        directory / "codex",
        directory / "bin" / "codex",
        directory / "node_modules" / ".bin" / "codex",
        directory / "target" / "release" / "codex",
        directory / "codex-rs" / "target" / "release" / "codex",
    )


def resolve_codex_command(configured_path: str | None = None) -> str | None:
    """Localiza o executável sem usar shell nem interpretar argumentos livres."""
    if configured_path:
        configured = Path(configured_path).expanduser()
        if configured.is_dir():
            for candidate in _directory_candidates(configured):
                if _is_executable(candidate):
                    return str(candidate.resolve())
        elif _is_executable(configured):
            return str(configured.resolve())
        elif os.sep not in configured_path:
            found = shutil.which(configured_path)
            if found:
                return found

    return shutil.which("codex")


def _resolve_workdir(configured_workdir: str | None) -> Path:
    return Path(configured_workdir).expanduser() if configured_workdir else PROJECT_ROOT


def codex_cli_status(settings: Settings | None = None) -> CodexCLIStatus:
    settings = settings or get_settings()
    command = resolve_codex_command(settings.codex_cli_path)
    workdir = _resolve_workdir(settings.codex_workdir)
    version = "não identificado"

    if command:
        try:
            completed = subprocess.run(
                [command, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            output = (completed.stdout or completed.stderr or "").strip()
            if output:
                version = output.splitlines()[0]
        except (OSError, subprocess.SubprocessError):
            version = "instalado, versão indisponível"

    return CodexCLIStatus(
        available=bool(command),
        command=command,
        version=version,
        workdir=str(workdir),
    )


def launch_codex(settings: Settings | None = None) -> int:
    """Abre o Codex CLI interativo herdando o terminal atual."""
    settings = settings or get_settings()
    status = codex_cli_status(settings)
    if not status.command:
        raise CodexCLIError(
            "Codex CLI não encontrado. Configure CODEX_CLI_PATH com o executável "
            "ou com a pasta onde ele foi instalado."
        )

    workdir = Path(status.workdir)
    if not workdir.is_dir():
        raise CodexCLIError(f"Diretório do Codex não existe: {workdir}")

    environment = os.environ.copy()
    if settings.codex_home:
        environment["CODEX_HOME"] = str(Path(settings.codex_home).expanduser())

    try:
        completed = subprocess.run(
            [status.command],
            cwd=str(workdir),
            env=environment,
            check=False,
        )
    except OSError as exc:
        raise CodexCLIError(f"Não foi possível iniciar o Codex CLI: {exc}") from exc

    return int(completed.returncode)
