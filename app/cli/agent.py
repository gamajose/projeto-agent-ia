from __future__ import annotations

import ipaddress

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.services.dynamic_agent import run_dynamic_investigation
from app.services.persistence import resolve_saved_target
from app.services.ssh import SSHExecutor

app = typer.Typer(no_args_is_help=True)
console = Console()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _short(value: str, limit: int = 6000) -> str:
    value = (value or "").strip()
    if not value:
        return "(sem saída)"
    return value if len(value) <= limit else value[-limit:]


@app.callback(invoke_without_command=True)
def command(
    ctx: typer.Context,
    target: str | None = typer.Argument(None, help="IP, hostname ou alias conhecido."),
    context: list[str] | None = typer.Argument(None, help="Objetivo da investigação em linguagem natural."),
    environment: EnvironmentType = typer.Option(
        EnvironmentType.UNKNOWN,
        "--environment",
        "-e",
        help="Ambiente conhecido: production, standby, monitoring ou unknown.",
    ),
    ssh_port: int | None = typer.Option(None, "--port", "-p", help="Porta SSH para host novo."),
) -> None:
    """Agente AIOps com planejamento dinâmico por IA.

    Exemplos:
      agent 172.27.225.28 valide memória, disco e cpu
      agent bsi identifique por que o servidor está lento
      agent omn investigue o automation-helper parado
      agent 172.27.225.31 valide comunicação e DNS
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
        console.print(f"[red]Alvo '{target}' não existe no inventário. Na primeira execução, informe o IP VPN.[/red]")
        raise typer.Exit(2)

    if not settings.ssh_default_user or not settings.ssh_default_password:
        console.print("[red]SSH_DEFAULT_USER e SSH_DEFAULT_PASSWORD precisam estar configurados no .env.[/red]")
        raise typer.Exit(2)

    objective = " ".join(context or []).strip()
    executor = SSHExecutor(
        ip,
        port,
        settings.ssh_default_user,
        settings.ssh_default_password,
        settings.ssh_connect_timeout,
    )

    console.print("[bold cyan]AGENT IA — PLANEJAMENTO DINÂMICO[/bold cyan]")
    console.print(f"[cyan]Referência:[/cyan] {target}")
    console.print(f"[cyan]Conexão:[/cyan] {ip}:{port}")
    console.print(f"[cyan]Objetivo:[/cyan] {objective or 'validar a saúde geral do servidor'}")

    try:
        executor.connect()
        result = run_dynamic_investigation(
            executor=executor,
            target=target,
            context=objective,
            environment=environment,
        )
    finally:
        executor.close()

    identity = result.get("identity") or {}
    table = Table(title="Ambiente identificado")
    table.add_column("Item", style="bold")
    table.add_column("Valor")
    table.add_row("Hostname", str(result.get("hostname") or "não identificado"))
    table.add_row("Sistema", str(identity.get("os_name") or "não identificado"))
    table.add_row("Objetivo", str(result.get("context") or ""))
    console.print(table)

    for index, plan in enumerate(result.get("plans") or [], 1):
        commands = plan.get("commands") or []
        plan_text = str(plan.get("reasoning_summary") or "Plano criado pela IA.")
        if commands:
            plan_text += "\n\n" + "\n".join(
                f"• {item.get('command')} — {item.get('purpose', '')}" for item in commands
            )
        console.print(Panel(plan_text, title=f"Plano da IA — rodada {index}"))

    for index, item in enumerate(result.get("evidence") or [], 1):
        status = item.get("status", "")
        title = f"{index}. {item.get('purpose') or item.get('command')} — {status}"
        body = (
            f"Comando: {item.get('command')}\n"
            f"Sudo: {'sim' if item.get('sudo') else 'não'}\n"
            f"Retorno: {item.get('exit_code')}\n\n"
            f"STDOUT:\n{_short(str(item.get('stdout') or ''))}"
        )
        if item.get("stderr"):
            body += f"\n\nSTDERR:\n{_short(str(item.get('stderr') or ''))}"
        if item.get("reason"):
            body += f"\n\nMotivo: {item.get('reason')}"
        console.print(Panel(body, title=title, border_style="green" if status == "executed" else "yellow"))

    analysis = result.get("analysis") or {}
    console.print(Panel(str(analysis.get("summary") or "Sem resumo"), title="Análise da IA"))
    facts = analysis.get("facts") or []
    if facts:
        console.print("[bold]Fatos comprovados:[/bold]")
        for fact in facts:
            console.print(f"  • {fact}")
    console.print(f"[bold]Causa provável:[/bold] {analysis.get('probable_cause', 'inconclusiva')}")
    console.print(f"[bold]Conclusão:[/bold] {analysis.get('conclusion', 'inconclusiva')}")
    recommendations = analysis.get("recommendations") or []
    if recommendations:
        console.print("[bold]Recomendações:[/bold]")
        for recommendation in recommendations:
            console.print(f"  • {recommendation}")
    console.print(Panel(str(analysis.get("ticket_report") or ""), title="Texto para ticket"))


def main() -> None:
    """Entrypoint do comando único ``agent``."""
    app()


if __name__ == "__main__":
    main()
