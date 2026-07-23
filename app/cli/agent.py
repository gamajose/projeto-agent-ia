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
    environment: EnvironmentType = typer.Option(EnvironmentType.UNKNOWN, "--environment", "-e"),
    ssh_port: int | None = typer.Option(None, "--port", "-p", help="Porta SSH para host novo."),
    mode: str = typer.Option("investigate", "--mode", "-m", help="investigate ou correct"),
    approve: bool = typer.Option(False, "--approve", help="Autoriza correções seguras propostas no modo correct."),
) -> None:
    """Agente AIOps com planejamento, análise e correção controlada por IA."""
    if ctx.invoked_subcommand is not None:
        return
    if not target:
        console.print(ctx.get_help())
        raise typer.Exit(0)
    if mode not in {"investigate", "correct"}:
        console.print("[red]--mode deve ser investigate ou correct.[/red]")
        raise typer.Exit(2)

    settings = get_settings()
    saved = resolve_saved_target(target, None if environment == EnvironmentType.UNKNOWN else environment.value)
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
    executor = SSHExecutor(ip, port, settings.ssh_default_user, settings.ssh_default_password, settings.ssh_connect_timeout)

    console.print("[bold cyan]AGENT IA — INVESTIGAÇÃO ORIENTADA A HIPÓTESES[/bold cyan]")
    console.print(f"[cyan]Referência:[/cyan] {target}")
    console.print(f"[cyan]Conexão:[/cyan] {ip}:{port}")
    console.print(f"[cyan]Objetivo:[/cyan] {objective or 'validar a saúde geral do servidor'}")
    console.print(f"[cyan]Modo:[/cyan] {mode}{' com aprovação' if approve else ''}")

    try:
        executor.connect()
        result = run_dynamic_investigation(executor=executor, target=target, context=objective, environment=environment, mode=mode, approve=approve)
    finally:
        executor.close()

    identity = result.get("identity") or {}
    table = Table(title="Ambiente identificado")
    table.add_column("Item", style="bold")
    table.add_column("Valor")
    table.add_row("Hostname", str(result.get("hostname") or "não identificado"))
    table.add_row("Sistema", str(identity.get("os_name") or "não identificado"))
    table.add_row("Perfil", str(result.get("profile") or "linux_generic"))
    table.add_row("Objetivo", str(result.get("context") or ""))
    table.add_row("Investigação", str(result.get("investigation_id") or "não persistida"))
    table.add_row("Duração", f"{result.get('duration_ms', 0)} ms")
    console.print(table)

    history = result.get("history") or []
    if history:
        console.print(Panel("\n".join(f"• {item.get('created_at')} | {item.get('status')} | {item.get('confidence')}% | {item.get('objective')}" for item in history), title="Histórico recente utilizado pela IA"))

    assessments = result.get("round_assessments") or []
    for index, plan in enumerate(result.get("plans") or [], 1):
        commands = plan.get("commands") or []
        text = str(plan.get("reasoning_summary") or "Plano criado pela IA.")
        if plan.get("hypotheses"):
            text += "\n\nHipóteses:\n" + "\n".join(f"• {value}" for value in plan["hypotheses"])
        if commands:
            text += "\n\nComandos:\n" + "\n".join(f"• {item.get('command')} — {item.get('purpose', '')}" for item in commands)
        console.print(Panel(text, title=f"Plano da IA — rodada {index}"))
        if len(assessments) >= index:
            assessment = assessments[index - 1]
            body = str(assessment.get("round_summary") or "")
            findings = assessment.get("findings") or []
            if findings:
                body += "\n\n" + "\n".join(f"• [{item.get('status')}] {item.get('statement')} ({item.get('evidence_command')})" for item in findings)
            console.print(Panel(body, title=f"Interpretação da IA — rodada {index}"))

    for index, item in enumerate(result.get("evidence") or [], 1):
        status = item.get("status", "")
        body = f"Comando: {item.get('command')}\nCategoria: {item.get('category', 'n/a')}\nSudo: {'sim' if item.get('sudo') else 'não'}\nRetorno: {item.get('exit_code')}\n\nSTDOUT:\n{_short(str(item.get('stdout') or ''))}"
        if item.get("normalized"):
            body += f"\n\nDados normalizados:\n{item.get('normalized')}"
        if item.get("stderr"):
            body += f"\n\nSTDERR:\n{_short(str(item.get('stderr') or ''))}"
        if item.get("reason"):
            body += f"\n\nMotivo: {item.get('reason')}"
        console.print(Panel(body, title=f"{index}. {item.get('purpose') or item.get('command')} — {status}", border_style="green" if status == "executed" else "yellow"))

    analysis = result.get("analysis") or {}
    status = str(analysis.get("status") or "inconclusive").upper()
    confidence = int(analysis.get("confidence") or 0)
    console.print(Panel(f"STATUS: {status}\nCONFIANÇA: {confidence}%\n\n{analysis.get('summary') or 'Sem resumo'}", title="Validação final da IA"))
    for label, key in (("Fatos comprovados", "facts"), ("Recomendações", "recommendations")):
        values = analysis.get(key) or []
        if values:
            console.print(f"[bold]{label}:[/bold]")
            for value in values:
                console.print(f"  • {value}")
    console.print(f"[bold]Causa provável:[/bold] {analysis.get('probable_cause', 'inconclusiva')}")
    console.print(f"[bold]Conclusão:[/bold] {analysis.get('conclusion', 'inconclusiva')}")

    evidence_map = analysis.get("evidence_map") or []
    if evidence_map:
        console.print(Panel("\n".join(f"• {item.get('conclusion')}\n  Comando: {item.get('command')}\n  Evidência: {item.get('evidence')}" for item in evidence_map), title="Rastreabilidade"))

    corrections = result.get("corrections") or []
    if corrections:
        console.print(Panel("\n\n".join(f"{item.get('description')}\nComando: {item.get('command')}\nStatus: {item.get('status')}\nImpacto: {item.get('impact', '')}" for item in corrections), title="Correções controladas"))

    console.print(Panel(str(analysis.get("ticket_report") or ""), title="Texto para ticket"))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
