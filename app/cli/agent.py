from __future__ import annotations

import ipaddress

import paramiko
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.db.base import ensure_database_schema
from app.services.dynamic_agent import run_dynamic_investigation
from app.services.operation_intent import infer_operation_intent
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
    context: list[str] | None = typer.Argument(None, help="Problema ou objetivo operacional em português."),
    environment: EnvironmentType = typer.Option(EnvironmentType.UNKNOWN, "--ambiente", "-a", help="Ambiente do host."),
    ssh_port: int | None = typer.Option(None, "--porta", "-p", help="Porta SSH para host novo."),
    somente_validar: bool = typer.Option(False, "--somente-validar", help="Força investigação sem executar correções."),
) -> None:
    """Agente AIOps autônomo: investiga, corrige com segurança e valida o resultado."""
    if ctx.invoked_subcommand is not None:
        return
    if not target:
        console.print(ctx.get_help())
        raise typer.Exit(0)

    try:
        created_tables = ensure_database_schema()
    except Exception as exc:
        console.print(
            Panel(
                f"Não foi possível preparar o banco de dados do agente.\n\n"
                f"Erro: {type(exc).__name__}: {exc}\n\n"
                "Verifique POSTGRES_DSN, conectividade e permissão CREATE no banco.",
                title="Falha na inicialização do banco",
                border_style="red",
            )
        )
        raise typer.Exit(2) from exc

    if created_tables:
        console.print(
            f"[green]Banco preparado automaticamente. Tabelas criadas: {', '.join(created_tables)}[/green]"
        )

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

    if not settings.ssh_default_user:
        console.print("[red]SSH_DEFAULT_USER precisa estar configurado no .env.[/red]")
        raise typer.Exit(2)

    objective = " ".join(context or []).strip()
    intent = infer_operation_intent(objective)
    if somente_validar:
        mode, approve = "investigate", False
        intent_reason = "modo somente validação solicitado por --somente-validar"
    else:
        mode, approve = intent.mode, intent.approve
        intent_reason = intent.reason

    executor = SSHExecutor(
        ip,
        port,
        settings.ssh_default_user,
        settings.ssh_default_password,
        settings.ssh_connect_timeout,
        private_key_path=settings.ssh_private_key_path,
        private_key_passphrase=settings.ssh_private_key_passphrase,
        allow_agent=settings.ssh_allow_agent,
        look_for_keys=settings.ssh_look_for_keys,
    )

    console.print("[bold cyan]AGENT IA — OPERAÇÃO AUTÔNOMA[/bold cyan]")
    console.print(f"[cyan]Referência:[/cyan] {target}")
    console.print(f"[cyan]Conexão:[/cyan] {ip}:{port}")
    console.print(f"[cyan]Objetivo:[/cyan] {objective or 'resolver o problema informado'}")
    console.print(f"[cyan]Comportamento:[/cyan] {'somente validar' if mode == 'investigate' else 'investigar, corrigir e validar'}")
    console.print(f"[dim]{intent_reason}[/dim]")

    try:
        executor.connect()
        result = run_dynamic_investigation(
            executor=executor,
            target=target,
            context=objective,
            environment=environment,
            mode=mode,
            approve=approve,
        )
    except paramiko.BadAuthenticationType as exc:
        allowed = ", ".join(exc.allowed_types or [])
        console.print(
            Panel(
                "O servidor recusou autenticação por senha.\n\n"
                f"Métodos permitidos pelo servidor: {allowed or 'não informados'}.\n\n"
                "Configure SSH_PRIVATE_KEY_PATH no .env ou carregue a chave no ssh-agent. "
                "O usuário definido em SSH_DEFAULT_USER também precisa ter a chave pública autorizada no host.",
                title="Falha de autenticação SSH",
                border_style="red",
            )
        )
        raise typer.Exit(3) from exc
    except paramiko.AuthenticationException as exc:
        console.print(
            Panel(
                "Não foi possível autenticar no servidor. Verifique SSH_DEFAULT_USER, "
                "SSH_PRIVATE_KEY_PATH, permissões da chave e a chave pública cadastrada no host.",
                title="Falha de autenticação SSH",
                border_style="red",
            )
        )
        raise typer.Exit(3) from exc
    except (paramiko.SSHException, OSError) as exc:
        console.print(
            Panel(
                f"Não foi possível estabelecer a conexão SSH com {ip}:{port}.\n\n"
                f"Erro: {type(exc).__name__}: {exc}",
                title="Falha de conexão SSH",
                border_style="red",
            )
        )
        raise typer.Exit(3) from exc
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

    if status == "INCONCLUSIVE":
        diagnostics = result.get("ai_diagnostics") or []
        lines: list[str] = []
        for diagnostic in diagnostics:
            purpose = diagnostic.get("purpose", "chamada_ia")
            if diagnostic.get("error"):
                lines.append(f"{purpose}: {diagnostic.get('error')}")
            for attempt in diagnostic.get("attempts") or []:
                error = attempt.get("error") or attempt.get("parse_error")
                if error:
                    lines.append(f"{purpose} / {attempt.get('model')}: {error}")
                excerpt = attempt.get("response_excerpt")
                if excerpt:
                    lines.append(f"Resposta de {attempt.get('model')}: {excerpt}")
        if lines:
            console.print(Panel("\n\n".join(dict.fromkeys(lines)), title="Erro real da API de IA", border_style="red"))

    evidence_map = analysis.get("evidence_map") or []
    if evidence_map:
        console.print(Panel("\n".join(f"• {item.get('conclusion')}\n  Comando: {item.get('command')}\n  Evidência: {item.get('evidence')}" for item in evidence_map), title="Rastreabilidade"))

    corrections = result.get("corrections") or []
    if corrections:
        console.print(Panel("\n\n".join(f"{item.get('description')}\nComando: {item.get('command')}\nStatus: {item.get('status')}\nImpacto: {item.get('impact', '')}" for item in corrections), title="Correções automáticas controladas"))

    console.print(Panel(str(analysis.get("ticket_report") or ""), title="Texto para ticket"))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
