from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.panel import Panel

from app.core.settings import get_settings
from app.db.base import ensure_database_schema
from app.services.jobs import get_job, run_worker_once, worker_loop
from app.services.secrets import secret_backend_status


app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("run")
def run(
    once: bool = typer.Option(False, "--once", help="Processa no máximo um job e encerra."),
    block_seconds: int | None = typer.Option(None, "--bloqueio", help="Tempo de espera por job."),
) -> None:
    """Executa jobs da fila Redis usando a conectividade deste worker."""
    settings = get_settings()
    ensure_database_schema()
    console.print(Panel(
        f"Worker: {settings.agent_worker_name}\n"
        f"Fila: {settings.agent_queue_name}\n"
        f"Redis: configurado\n"
        f"Segredos: {secret_backend_status(settings).get('backend')}\n"
        f"StrictHostKeyChecking: {settings.ssh_strict_host_key_checking}",
        title="Agent IA Worker",
    ))
    if once:
        result = run_worker_once(settings=settings, block_seconds=block_seconds)
        console.print(json.dumps(result or {"status": "empty"}, ensure_ascii=False, indent=2, default=str))
        return
    worker_loop(settings=settings)


@app.command("job")
def job(job_id: str = typer.Argument(..., help="UUID do job.")) -> None:
    """Consulta o estado de um job distribuído."""
    result = get_job(job_id)
    if not result:
        console.print(Panel("Job não encontrado ou expirado.", title="Job", border_style="yellow"))
        raise typer.Exit(2)
    console.print(Panel(json.dumps(result, ensure_ascii=False, indent=2, default=str), title="Job distribuído"))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
