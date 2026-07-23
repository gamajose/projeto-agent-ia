from __future__ import annotations

import ipaddress

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.services.persistence import resolve_saved_target
from app.services.smart_agent import run_adaptive_diagnosis
from app.services.ssh import SSHExecutor

app = typer.Typer(no_args_is_help=True)
console = Console()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _short(value: str, limit: int = 5000) -> str:
    value = (value or "").strip()
    if not value:
        return "(sem saída)"
    return value if len(value) <= limit else value[-limit:]


@app.callback(invoke_without_command=True)
def command(
    ctx: typer.Context,
    target: str | None = typer.Argument(None, help="IP, hostname, site OMD, container ou alias conhecido."),
    context: list[str] | None = typer.Argument(None, help="Sintoma ou objetivo em linguagem natural."),
    environment: EnvironmentType = typer.Option(
        EnvironmentType.UNKNOWN,
        "--environment",
        "-e",
        help="Ambiente conhecido: production, standby, monitoring ou unknown.",
    ),
    ssh_port: int | None = typer.Option(None, "--port", "-p", help="Porta SSH para host novo."),
    read_only: bool = typer.Option(False, "--read-only", help="Coleta e análise sem aplicar correções."),
) -> None:
    """Agente adaptativo para diagnóstico e correção segura de infraestrutura.

    Exemplos:
      agent 172.27.225.31
      agent omn automation helper parado
      agent checkmk-omn-25 validar serviços OMD
      agent bsi servidor lento
    """
    if ctx.invoked_subcommand is not None:
        return
    if not target:
        console.print(ctx.get_help())
        raise typer.Exit(0)

    settings = get_settings()
    saved = resolve_saved_target(
        target,
        None if environment == EnvironmentType.UNKNOWN else environment.value,
    )
    if saved:
        ip = str(saved["vpn_ip"])
        port = int(saved["ssh_port"])
        if environment == EnvironmentType.UNKNOWN:
            environment = EnvironmentType(saved.get("environment") or EnvironmentType.UNKNOWN.value)
    elif _is_ip(target):
        ip = target
        port = int(ssh_port or settings.ssh_default_port)
    else:
        console.print(
            f"[red]Alvo '{target}' não existe no inventário. Na primeira execução, informe o IP VPN.[/red]"
        )
        raise typer.Exit(2)

    if not settings.ssh_default_user or not settings.ssh_default_password:
        console.print("[red]SSH_DEFAULT_USER e SSH_DEFAULT_PASSWORD precisam estar configurados no .env.[/red]")
        raise typer.Exit(2)

    symptom = " ".join(context or []).strip()
    executor = SSHExecutor(
        ip,
        port,
        settings.ssh_default_user,
        settings.ssh_default_password,
        settings.ssh_connect_timeout,
    )

    console.print("[bold cyan]AGENT IA — EXECUÇÃO ADAPTATIVA[/bold cyan]")
    console.print(f"[cyan]Referência:[/cyan] {target}")
    console.print(f"[cyan]Conexão:[/cyan] {ip}:{port}")
    console.print(f"[cyan]Contexto:[/cyan] {symptom or 'descobrir o ambiente e corrigir falhas seguras'}")
    console.print(f"[cyan]Modo:[/cyan] {'somente leitura' if read_only else 'diagnóstico, correção segura e validação'}")

    try:
        executor.connect()
        result = run_adaptive_diagnosis(
            executor=executor,
            target=target,
            context=symptom,
            environment=environment,
            read_only=read_only,
        )
    finally:
        executor.close()

    table = Table(title="Ambiente descoberto")
    table.add_column("Item", style="bold")
    table.add_column("Valor")
    table.add_row("Hostname real", str(result.get("hostname") or "não identificado"))
    table.add_row("Containers Checkmk", ", ".join(item["name"] for item in result["containers"]) or "nenhum")
    resolved = [
        f"{item['container']}/{item['site']} → {item.get('resolved_checkmk_host')}"
        for item in result["findings"]
        if item.get("resolved_checkmk_host")
    ]
    table.add_row("Hosts Checkmk resolvidos", "\n".join(resolved) or "nenhuma correspondência automática")
    console.print(table)

    for finding in result["findings"]:
        stopped = finding.get("stopped_services") or []
        console.print(
            Panel(
                _short(finding["omd_status"].get("stdout") or finding["omd_status"].get("stderr") or ""),
                title=f"{finding['container']} / site {finding['site']} / OMD"
                + (f" / parados: {', '.join(stopped)}" if stopped else ""),
            )
        )

    if result["actions"]:
        action_table = Table(title="Ações aplicadas e validadas")
        action_table.add_column("Ação")
        action_table.add_column("Status")
        action_table.add_column("Validação")
        for action in result["actions"]:
            validation = action.get("validation") or {}
            action_table.add_row(
                action["command"],
                action["status"],
                _short(validation.get("stdout") or validation.get("stderr") or "", 1000),
            )
        console.print(action_table)
    elif read_only:
        console.print("[yellow]Nenhuma ação executada porque --read-only foi informado.[/yellow]")
    else:
        console.print("[green]Nenhum serviço OMD parado e autorizado para inicialização foi encontrado.[/green]")

    analysis = result["analysis"]
    console.print(Panel(str(analysis.get("summary") or "Sem resumo"), title="Análise da IA"))
    console.print(f"[bold]Causa provável:[/bold] {analysis.get('probable_cause', 'inconclusiva')}")
    console.print(f"[bold]Conclusão:[/bold] {analysis.get('conclusion', 'inconclusiva')}")
    console.print(Panel(str(analysis.get("ticket_report") or ""), title="Texto para ticket"))


def main() -> None:
    """Entrypoint do comando único ``agent``."""
    app()


if __name__ == "__main__":
    main()
