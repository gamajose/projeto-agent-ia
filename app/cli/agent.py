from __future__ import annotations

import json

import paramiko
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.core.operation import OperationMode
from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.db.base import ensure_database_schema
from app.services.ai_providers import ProviderError
from app.services.approved_execution import ApprovedExecutionError, execute_approved_investigation
from app.services.approvals import ApprovalError
from app.services.codex_cli import CodexCLIError, codex_cli_status, launch_codex
from app.services.operation_intent import infer_operation_intent
from app.services.provider_preflight import preflight_all
from app.services.replay import replay_investigation
from app.services.runner import resolve_target, run_target


app = typer.Typer(no_args_is_help=True)
doctor_app = typer.Typer(help="Diagnósticos seguros da configuração do Agent IA.")
app.add_typer(doctor_app, name="doctor")
console = Console()


def _short(value: str, limit: int = 6000) -> str:
    value = (value or "").strip()
    if not value:
        return "(sem saída)"
    return value if len(value) <= limit else value[-limit:]


def _prepare_database() -> None:
    try:
        created_tables = ensure_database_schema()
    except Exception as exc:
        console.print(Panel(
            f"Não foi possível preparar o banco de dados do agente.\n\nErro: {type(exc).__name__}: {exc}\n\nVerifique POSTGRES_DSN, conectividade e permissão CREATE no banco.",
            title="Falha na inicialização do banco",
            border_style="red",
        ))
        raise typer.Exit(2) from exc
    if created_tables:
        console.print(f"[green]Banco preparado. Tabelas criadas: {', '.join(created_tables)}[/green]")


def _show_menu() -> None:
    settings = get_settings()
    rows = [
        {
            "kind": "provider",
            "name": item.provider,
            "label": item.label,
            "model": item.model,
            "configured": item.selectable,
            "selectable": item.selectable,
            "state": item.state_label,
            "detail": item.detail,
        }
        for item in preflight_all(settings)
    ]
    codex = codex_cli_status(settings)
    rows.append({
        "kind": "tool",
        "name": "codex-cli",
        "label": "OpenAI Codex CLI",
        "model": codex.version,
        "configured": codex.available,
        "selectable": codex.available,
        "state": "available" if codex.available else "unavailable",
        "detail": "Executável localizado." if codex.available else "Executável não encontrado.",
        "workdir": codex.workdir,
    })

    table = Table(title="Provedores e ferramentas de IA")
    table.add_column("#")
    table.add_column("Tipo")
    table.add_column("Provedor/Ferramenta")
    table.add_column("Modelo/Versão")
    table.add_column("Estado")
    for index, item in enumerate(rows, 1):
        is_tool = item.get("kind") == "tool"
        table.add_row(
            str(index),
            "ferramenta" if is_tool else "provedor",
            item["label"],
            item["model"],
            ("disponível" if item["configured"] else "não encontrado")
            if is_tool
            else f"{item['state']} — {item['detail']}",
        )
    console.print(table)

    choice = typer.prompt("Escolha o número", type=int)
    if choice < 1 or choice > len(rows):
        console.print("[red]Seleção inválida.[/red]")
        raise typer.Exit(2)
    selected = rows[choice - 1]
    if selected.get("kind") == "tool" and selected["name"] == "codex-cli":
        console.print(f"[green]Selecionado: {selected['label']} — {selected['model']}[/green]")
        console.print(f"[cyan]Diretório de trabalho:[/cyan] {selected['workdir']}")
        console.print("Nenhuma conexão SSH foi iniciada pelo Agent IA.")
        try:
            raise typer.Exit(launch_codex(settings))
        except CodexCLIError as exc:
            console.print(Panel(str(exc), title="Codex CLI indisponível", border_style="red"))
            raise typer.Exit(2) from exc

    if not selected.get("selectable"):
        console.print(Panel(
            str(selected.get("detail") or "O provedor não passou no diagnóstico."),
            title="Provedor indisponível",
            border_style="yellow",
        ))
        raise typer.Exit(2)
    console.print(f"[green]Selecionado: {selected['label']} — {selected['model']}[/green]")
    console.print(f"Para usar nesta sessão: [cyan]export AI_PROVIDER={selected['name']}[/cyan]")
    console.print("Nenhuma conexão remota foi iniciada.")
    raise typer.Exit(0)


def _show_result(result: dict) -> None:
    identity = result.get("identity") or {}
    environment = result.get("environment_classification") or {}
    table = Table(title="Ambiente identificado")
    table.add_column("Item", style="bold")
    table.add_column("Valor")
    table.add_row("Hostname", str(result.get("hostname") or "não identificado"))
    table.add_row("Sistema", str(identity.get("os_name") or "não identificado"))
    table.add_row("Perfil", str(result.get("profile") or "linux_generic"))
    table.add_row("Ambiente", str(environment.get("environment") or "unknown"))
    table.add_row("Origem", str(environment.get("source") or "unclassified"))
    table.add_row("Confiança ambiente", f"{environment.get('confidence', 0)}%")
    table.add_row("Investigação", str(result.get("investigation_id") or "não persistida"))
    table.add_row("Duração", f"{result.get('duration_ms', 0)} ms")
    console.print(table)

    playbook = result.get("playbook")
    if playbook:
        console.print(Panel(
            f"{playbook.get('title')}\nID: {playbook.get('id')}\nCorreções permitidas: {', '.join(playbook.get('allowed_corrections') or []) or 'nenhuma'}",
            title="Playbook selecionado",
        ))

    similar = result.get("similar_history") or []
    if similar:
        console.print(Panel(
            "\n".join(f"• {item.get('similarity', 0):.0%} | {item.get('status')} | {item.get('objective')} | causa: {(item.get('analysis') or {}).get('probable_cause', 'n/a')}" for item in similar),
            title="Casos semelhantes utilizados",
        ))

    assessments = result.get("round_assessments") or []
    for index, plan in enumerate(result.get("plans") or [], 1):
        tools = plan.get("tools") or plan.get("commands") or []
        text = str(plan.get("reasoning_summary") or "Plano criado pela IA.")
        if plan.get("hypotheses"):
            text += "\n\nHipóteses:\n" + "\n".join(f"• {value}" for value in plan["hypotheses"])
        if tools:
            text += "\n\nFerramentas:\n" + "\n".join(f"• {item.get('tool') or item.get('command')} {json.dumps(item.get('arguments') or {}, ensure_ascii=False)} — {item.get('purpose', '')}" for item in tools)
        console.print(Panel(text, title=f"Plano — rodada {index}"))
        if len(assessments) >= index:
            assessment = assessments[index - 1]
            body = str(assessment.get("round_summary") or "")
            findings = assessment.get("findings") or []
            if findings:
                body += "\n\n" + "\n".join(f"• [{item.get('status')}] {item.get('statement')} ({item.get('evidence_command')})" for item in findings)
            console.print(Panel(body, title=f"Interpretação — rodada {index}"))

    for index, item in enumerate(result.get("evidence") or [], 1):
        status = item.get("status", "")
        body = (
            f"Ferramenta: {item.get('tool') or 'comando legado'}\n"
            f"Comando gerado: {item.get('command')}\n"
            f"Categoria: {item.get('category', 'n/a')}\n"
            f"Retorno: {item.get('exit_code')}\n\nSTDOUT:\n{_short(str(item.get('stdout') or ''))}"
        )
        if item.get("validations"):
            body += "\n\nPós-validação:\n" + json.dumps(item["validations"], ensure_ascii=False, indent=2)
        if item.get("stderr"):
            body += f"\n\nSTDERR:\n{_short(str(item.get('stderr') or ''))}"
        if item.get("reason"):
            body += f"\n\nMotivo: {item.get('reason')}"
        console.print(Panel(body, title=f"{index}. {item.get('purpose') or item.get('tool') or item.get('command')} — {status}", border_style="green" if status in {"executed", "validated"} else "yellow"))

    analysis = result.get("analysis") or {}
    status = str(analysis.get("status") or "inconclusive").upper()
    confidence = int(analysis.get("confidence") or 0)
    console.print(Panel(f"STATUS: {status}\nCONFIANÇA: {confidence}%\n\n{analysis.get('summary') or 'Sem resumo'}", title="Validação final da IA"))
    console.print(f"[bold]Causa provável:[/bold] {analysis.get('probable_cause', 'inconclusiva')}")
    console.print(f"[bold]Conclusão:[/bold] {analysis.get('conclusion', 'inconclusiva')}")

    proposals = analysis.get("proposed_actions") or []
    if proposals:
        console.print(Panel(
            "\n\n".join(f"{item.get('description')}\nFerramenta: {item.get('tool')} {json.dumps(item.get('arguments') or {}, ensure_ascii=False)}\nStatus: {item.get('status')}\nValidações: {item.get('validations')}" for item in proposals),
            title="Correções propostas",
        ))
    review = result.get("review") or analysis.get("review") or {}
    if review:
        console.print(Panel(
            f"Status: {review.get('status')}\nAprovado: {'sim' if review.get('approved') else 'não'}\nConfiança: {review.get('confidence', 0)}%\nMotivo: {review.get('reason', '')}",
            title="Revisão da segunda IA",
        ))
    corrections = result.get("corrections") or []
    if corrections:
        console.print(Panel(
            "\n\n".join(f"{item.get('description') or item.get('purpose')}\nFerramenta: {item.get('tool')}\nStatus: {item.get('status')}\nValidações: {item.get('validations')}" for item in corrections),
            title="Execução corretiva controlada",
        ))
    if result.get("approval_token"):
        console.print(Panel(
            f"A proposta foi revisada e pode ser aprovada dentro do prazo configurado.\n\nagent approve {result['investigation_id']} '{result['approval_token']}'",
            title="Aprovação humana necessária",
            border_style="yellow",
        ))
    console.print(Panel(str(analysis.get("ticket_report") or ""), title="Texto para ticket"))


@app.callback(invoke_without_command=True)
def command(
    ctx: typer.Context,
    target: str | None = typer.Argument(None, help="IP, hostname ou alias conhecido."),
    context: list[str] | None = typer.Argument(None, help="Problema ou objetivo operacional em português."),
    environment: EnvironmentType = typer.Option(EnvironmentType.UNKNOWN, "--ambiente", "-a", help="production, standby, monitoring, training ou unknown."),
    ssh_port: int | None = typer.Option(
        None,
        "--porta",
        "-p",
        help="Porta SSH; sobrescreve playbook, inventário e padrão.",
        min=1,
        max=65535,
    ),
    mode: str | None = typer.Option(None, "--modo", help="investigar, propor ou corrigir."),
    somente_validar: bool = typer.Option(False, "--somente-validar", help="Compatibilidade: equivale a --modo investigar."),
    menu: bool = typer.Option(False, "--menu", help="Seleciona um provedor ou abre ferramenta local."),
) -> None:
    """Agente AIOps: investiga, propõe e corrige com políticas verificáveis."""
    if ctx.invoked_subcommand is not None:
        return
    if menu:
        _show_menu()
    if not target:
        console.print(ctx.get_help())
        raise typer.Exit(0)

    _prepare_database()
    settings = get_settings()
    objective = " ".join(context or []).strip()
    try:
        if somente_validar:
            selected_mode = OperationMode.INVESTIGATE
            reason = "modo somente validação solicitado"
        elif mode:
            selected_mode = OperationMode.from_cli(mode)
            reason = "modo definido explicitamente pelo operador"
        else:
            intent = infer_operation_intent(objective)
            selected_mode = OperationMode(intent.mode)
            reason = intent.reason
        resolved = resolve_target(target, environment, ssh_port, settings=settings)
    except (ValueError, LookupError) as exc:
        console.print(Panel(str(exc), title="Parâmetro inválido", border_style="red"))
        raise typer.Exit(2) from exc

    console.print("[bold cyan]AGENT IA — OPERAÇÃO CONTROLADA[/bold cyan]")
    console.print(f"[cyan]Referência:[/cyan] {target}")
    console.print(f"[cyan]Conexão:[/cyan] {resolved.host}:{resolved.port}")
    console.print(f"[cyan]Objetivo:[/cyan] {objective or 'validar a saúde geral do servidor'}")
    console.print(f"[cyan]Modo:[/cyan] {selected_mode.label}")
    console.print(f"[dim]{reason}[/dim]")

    try:
        result = run_target(
            target,
            objective,
            environment=environment,
            mode=selected_mode.value,
            approve=selected_mode == OperationMode.CORRECT,
            ssh_port=ssh_port,
            settings=settings,
        )
    except ProviderError as exc:
        console.print(Panel(str(exc), title="Provedor de IA indisponível", border_style="red"))
        raise typer.Exit(4) from exc
    except paramiko.BadAuthenticationType as exc:
        allowed = ", ".join(exc.allowed_types or [])
        console.print(Panel(f"O servidor recusou o método de autenticação. Métodos permitidos: {allowed or 'não informados'}.", title="Falha de autenticação SSH", border_style="red"))
        raise typer.Exit(3) from exc
    except paramiko.BadHostKeyException as exc:
        console.print(Panel(f"A chave SSH apresentada pelo servidor mudou ou não corresponde ao known_hosts.\n\n{exc}", title="Chave SSH divergente", border_style="red"))
        raise typer.Exit(3) from exc
    except paramiko.AuthenticationException as exc:
        console.print(Panel("Não foi possível autenticar. Verifique usuário, chave, ssh-agent e bastion configurados.", title="Falha de autenticação SSH", border_style="red"))
        raise typer.Exit(3) from exc
    except (paramiko.SSHException, OSError) as exc:
        console.print(Panel(f"Não foi possível estabelecer a conexão SSH.\n\n{type(exc).__name__}: {exc}\n\nCom StrictHostKeyChecking ativo, cadastre primeiro a chave do host no known_hosts.", title="Falha de conexão SSH", border_style="red"))
        raise typer.Exit(3) from exc

    _show_result(result)


@doctor_app.command("ai")
def doctor_ai() -> None:
    """Valida provedores e modelos sem exibir credenciais."""
    rows = preflight_all(get_settings())
    table = Table(title="Diagnóstico dos provedores de IA")
    table.add_column("Provider")
    table.add_column("Estado")
    table.add_column("Modelo/Rota")
    table.add_column("Latência")
    table.add_column("Detalhe")
    for item in rows:
        table.add_row(
            item.label,
            item.state_label,
            item.model or "-",
            f"{item.latency_ms} ms" if item.latency_ms is not None else "-",
            item.detail,
        )
    console.print(table)
    console.print(
        "[dim]Nenhuma senha, token ou API key é exibida por este diagnóstico.[/dim]"
    )


@app.command("replay")
def replay_command(
    investigation_id: str = typer.Argument(..., help="UUID da investigação gravada."),
    provider: str | None = typer.Option(None, "--provedor", help="Provedor usado na reanálise."),
) -> None:
    """Reanalisa evidências persistidas sem abrir SSH."""
    _prepare_database()
    try:
        result = replay_investigation(investigation_id, provider_name=provider)
    except Exception as exc:
        console.print(Panel(f"{type(exc).__name__}: {exc}", title="Replay não executado", border_style="red"))
        raise typer.Exit(2) from exc
    analysis = result.get("analysis") or {}
    console.print(Panel(
        f"Provedor: {result.get('provider')}\nModelo: {result.get('model')}\nConexão remota: não\n\nSTATUS: {str(analysis.get('status') or 'inconclusive').upper()}\nCONFIANÇA: {analysis.get('confidence', 0)}%\n\n{analysis.get('summary', '')}\n\nCausa provável: {analysis.get('probable_cause', '')}",
        title="Replay da investigação",
    ))


@app.command("approve")
def approve_command(
    investigation_id: str = typer.Argument(..., help="UUID da investigação proposta."),
    token: str = typer.Argument(..., help="Token de aprovação assinado."),
    requested_by: str | None = typer.Option(None, "--por", help="Identidade de quem aprovou."),
) -> None:
    """Executa uma proposta previamente revisada e aprovada."""
    _prepare_database()
    try:
        result = execute_approved_investigation(investigation_id, token, requested_by=requested_by)
    except (ApprovalError, ApprovedExecutionError, paramiko.SSHException, OSError) as exc:
        console.print(Panel(f"{type(exc).__name__}: {exc}", title="Aprovação não executada", border_style="red"))
        raise typer.Exit(3) from exc
    console.print(Panel(json.dumps(result, ensure_ascii=False, indent=2, default=str), title="Resultado da execução aprovada"))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
