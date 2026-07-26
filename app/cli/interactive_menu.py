from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.core.policies import EnvironmentType
from app.core.settings import Settings, get_settings
from app.services.ai_providers import (
    direct_provider_status,
    gateway_status,
    use_provider,
)
from app.services.codex_cli import CodexCLIError, codex_cli_status, launch_codex
from app.services.interactive_session import OperationalSession
from app.services.playbooks import (
    list_playbooks,
    selected_playbook_ssh_port,
    use_playbook,
)
from app.services.provider_preflight import (
    ProviderPreflight,
    preflight_all,
    preflight_provider,
)
from app.services.runner import run_target


ShowResult = Callable[[dict[str, Any]], None]
PrepareDatabase = Callable[[], None]


@dataclass(frozen=True)
class AISelection:
    source: str
    provider: str
    model: str
    label: str


def _choose_number(console: Console, prompt: str, *, minimum: int, maximum: int) -> int:
    while True:
        try:
            value = typer.prompt(prompt, type=int)
        except (ValueError, typer.Abort):
            console.print("[red]Informe um número válido.[/red]")
            continue
        if minimum <= value <= maximum:
            return value
        console.print(f"[red]Escolha uma opção entre {minimum} e {maximum}.[/red]")


def _choose_direct_provider(
    console: Console,
    settings: Settings,
    preflights: dict[str, ProviderPreflight],
) -> AISelection | None:
    rows = direct_provider_status(settings)
    table = Table(title="Provedores configurados diretamente no Agent IA")
    table.add_column("#", justify="right")
    table.add_column("Provedor")
    table.add_column("Modelo")
    table.add_column("Estado")
    table.add_row("0", "Voltar", "-", "-")
    for index, item in enumerate(rows, 1):
        diagnostic = preflights[str(item["name"])]
        table.add_row(
            str(index),
            str(item["label"]),
            str(item["model"]),
            f"{diagnostic.state_label} — {diagnostic.detail}",
        )
    console.print(table)
    choice = _choose_number(console, "Provedor", minimum=0, maximum=len(rows))
    if choice == 0:
        return None
    selected = rows[choice - 1]
    diagnostic = preflights[str(selected["name"])]
    if not diagnostic.selectable:
        console.print(Panel(
            diagnostic.detail,
            title="Provedor indisponível",
            border_style="yellow",
        ))
        return None
    return AISelection(
        source="direct",
        provider=str(selected["name"]),
        model=str(selected["model"]),
        label=str(selected["label"]),
    )


def _prompt_gateway_route() -> str:
    while True:
        route = typer.prompt("Nome da rota, modelo ou combo configurado no OmniRoute").strip()
        if route:
            return route


def _choose_omniroute(
    console: Console,
    settings: Settings,
    diagnostic: ProviderPreflight,
) -> AISelection | None:
    status = gateway_status(settings)
    if not diagnostic.selectable:
        console.print(Panel(
            f"Motivo: {diagnostic.detail}\n\n"
            "O Agent usa um token local do endpoint. As credenciais dos provedores "
            "e ao menos um modelo/rota precisam estar configurados no próprio OmniRoute.\n"
            "Para usar uma IA local sem chave, escolha Ollama.",
            title="OmniRoute — indisponível",
            border_style="yellow",
        ))
        return None

    valid_routes = set(diagnostic.valid_routes)
    routes = [
        route
        for route in list(status.get("routes") or [])
        if route.model in valid_routes
    ]
    if not routes:
        console.print(Panel(
            "Nenhuma rota configurada no Agent passou na validação de /v1/models.",
            title="OmniRoute — sem rota utilizável",
            border_style="yellow",
        ))
        return None

    table = Table(title="Rotas, modelos e combos do OmniRoute")
    table.add_column("#", justify="right")
    table.add_column("Nome")
    table.add_column("Identificador enviado ao gateway")
    table.add_column("Padrão")
    table.add_row("0", "Voltar", "-", "-")
    for index, route in enumerate(routes, 1):
        table.add_row(
            str(index),
            route.label,
            route.model,
            "sim" if route.is_default else "",
        )
    manual_option = len(routes) + 1
    table.add_row(str(manual_option), "Informar outra rota manualmente", "-", "-")
    console.print(table)
    choice = _choose_number(console, "Rota do OmniRoute", minimum=0, maximum=manual_option)
    if choice == 0:
        return None
    if choice == manual_option:
        route_name = _prompt_gateway_route()
        route_diagnostic = preflight_provider("omniroute", settings, route_name)
        if not route_diagnostic.selectable:
            console.print(Panel(
                route_diagnostic.detail,
                title="Rota do OmniRoute indisponível",
                border_style="yellow",
            ))
            return None
        return AISelection(
            source="gateway",
            provider="omniroute",
            model=route_name,
            label=f"OmniRoute → {route_name}",
        )
    route = routes[choice - 1]
    return AISelection(
        source="gateway",
        provider="omniroute",
        model=route.model,
        label=f"OmniRoute → {route.label}",
    )


def _choose_local_model(
    console: Console,
    settings: Settings,
    diagnostic: ProviderPreflight,
) -> AISelection | None:
    console.print(Panel(
        f"Estado: {diagnostic.state_label}\n"
        f"Modelo: {diagnostic.model or '-'}\n"
        f"Endpoint: {settings.ollama_base_url}\n"
        f"Detalhe: {diagnostic.detail}",
        title="Ollama local",
    ))
    if not diagnostic.selectable:
        return None
    return AISelection(
        source="local",
        provider="ollama",
        model=diagnostic.model,
        label="Ollama local",
    )


def _choose_ai(console: Console, settings: Settings) -> AISelection | None:
    console.print("[dim]Validando conectividade, modelos e rotas dos provedores...[/dim]")
    diagnostics = {item.provider: item for item in preflight_all(settings)}
    omni = diagnostics["omniroute"]
    direct_names = ("gemini", "groq", "openrouter")
    direct_count = sum(1 for name in direct_names if diagnostics[name].selectable)
    local = diagnostics["ollama"]

    while True:
        table = Table(title="Como o Agent IA acessará o modelo")
        table.add_column("#", justify="right")
        table.add_column("Origem")
        table.add_column("Comportamento")
        table.add_column("Estado")
        table.add_row(
            "1",
            "OmniRoute — gateway centralizado",
            "Usa um token do gateway e uma rota/modelo configurada nele",
            f"{omni.state_label} — {omni.detail}",
        )
        table.add_row(
            "2",
            "Provedores diretos",
            "Usa as API keys individuais configuradas no Agent IA",
            f"{direct_count}/{len(direct_names)} disponíveis",
        )
        table.add_row(
            "3",
            "Ollama local",
            f"Usa o modelo local {local.model or '-'}",
            f"{local.state_label} — {local.detail}",
        )
        table.add_row("0", "Voltar", "-", "-")
        console.print(table)
        choice = _choose_number(console, "Origem da IA", minimum=0, maximum=3)
        if choice == 0:
            return None
        if choice == 1:
            selected = _choose_omniroute(console, settings, omni)
        elif choice == 2:
            selected = _choose_direct_provider(console, settings, diagnostics)
        else:
            selected = _choose_local_model(console, settings, local)
        if selected:
            return selected


def _choose_environment(console: Console) -> EnvironmentType:
    rows = [
        (EnvironmentType.UNKNOWN, "Identificar automaticamente / desconhecido"),
        (EnvironmentType.MONITORING, "Monitoramento"),
        (EnvironmentType.TRAINING, "Treinamento"),
        (EnvironmentType.PRODUCTION, "Produção"),
        (EnvironmentType.STANDBY, "Standby"),
    ]
    table = Table(title="Ambiente informado pelo operador")
    table.add_column("#")
    table.add_column("Ambiente")
    for index, (_, label) in enumerate(rows, 1):
        table.add_row(str(index), label)
    console.print(table)
    choice = _choose_number(console, "Ambiente", minimum=1, maximum=len(rows))
    return rows[choice - 1][0]


def _choose_playbook(console: Console) -> tuple[str, str | None]:
    books = list_playbooks()
    table = Table(title="Como o playbook será escolhido")
    table.add_column("#", justify="right")
    table.add_column("Opção")
    table.add_row("1", "Escolha automática pelo Agent IA")
    table.add_row("2", "Selecionar um playbook manualmente")
    table.add_row("0", "Continuar sem playbook — somente validação inicial")
    console.print(table)
    choice = _choose_number(console, "Playbook", minimum=0, maximum=2)
    if choice == 0:
        return "none", None
    if choice == 1:
        return "auto", None
    if not books:
        console.print("[yellow]Nenhum playbook foi encontrado. A sessão seguirá sem playbook.[/yellow]")
        return "none", None

    book_table = Table(title="Playbooks disponíveis")
    book_table.add_column("#", justify="right")
    book_table.add_column("Título")
    book_table.add_column("ID")
    book_table.add_column("Perfis")
    book_table.add_column("Porta SSH")
    book_table.add_row("0", "Voltar", "-", "-", "-")
    for index, book in enumerate(books, 1):
        book_table.add_row(
            str(index),
            book.title,
            book.id,
            ", ".join(book.profiles),
            str(book.ssh_port) if book.ssh_port is not None else "automática",
        )
    console.print(book_table)
    selected = _choose_number(console, "Número do playbook", minimum=0, maximum=len(books))
    if selected == 0:
        return _choose_playbook(console)
    return "manual", books[selected - 1].id


def _choose_automatic_mode(console: Console, playbook_mode: str) -> str:
    if playbook_mode == "none":
        console.print("[yellow]Sem playbook, a operação inicial fica obrigatoriamente em modo investigar.[/yellow]")
        return "investigate"
    table = Table(title="Modo da validação automática")
    table.add_column("#")
    table.add_column("Modo")
    table.add_column("Comportamento")
    table.add_row("1", "Investigar", "Coleta e analisa; não gera execução")
    table.add_row("2", "Propor", "Coleta, analisa e gera proposta revisada")
    console.print(table)
    return "investigate" if _choose_number(console, "Modo", minimum=1, maximum=2) == 1 else "propose"


def _choose_ssh_port(
    console: Console,
    *,
    settings: Settings,
    playbook_mode: str,
    playbook_id: str | None,
    objective: str,
) -> tuple[int | None, str]:
    with use_playbook(playbook_mode, playbook_id):
        playbook_port, selected_playbook_id = selected_playbook_ssh_port(objective)
    if playbook_port is not None:
        default_description = f"{playbook_port} do playbook {selected_playbook_id}"
        summary = f"{playbook_port} (playbook {selected_playbook_id})"
    else:
        default_description = f"inventário do alvo ou padrão {settings.ssh_default_port}"
        summary = f"automática (inventário ou padrão {settings.ssh_default_port})"

    while True:
        raw_port = str(
            typer.prompt(
                f"Porta SSH (Enter = {default_description})",
                default="",
                show_default=False,
            )
        ).strip()
        if not raw_port:
            return None, summary
        try:
            port = int(raw_port)
        except ValueError:
            console.print("[red]Informe uma porta SSH numérica entre 1 e 65535.[/red]")
            continue
        if 1 <= port <= 65535:
            return port, f"{port} (informada pelo operador)"
        console.print("[red]A porta SSH deve estar entre 1 e 65535.[/red]")


def _operation_summary(
    console: Console,
    *,
    flow: str,
    selection: AISelection,
    target: str,
    environment: EnvironmentType,
    playbook_mode: str,
    playbook_id: str | None,
    ssh_port_summary: str,
    objective: str,
    mode: str,
) -> None:
    source_labels = {"gateway": "gateway", "direct": "provedor direto", "local": "modelo local"}
    body = (
        f"Fluxo: {flow}\n"
        f"Origem da IA: {source_labels.get(selection.source, selection.source)}\n"
        f"Seleção: {selection.label}\n"
        f"Modelo/rota: {selection.model}\n"
        f"Servidor: {target}\n"
        f"Porta SSH: {ssh_port_summary}\n"
        f"Ambiente informado: {environment.value}\n"
        f"Playbook: {playbook_id or playbook_mode}\n"
        f"Modo inicial: {mode}\n"
        f"Problema: {objective or 'validar saúde geral'}\n\n"
        "Reboot da máquina, banco de cliente e ciclo de vida de container continuam bloqueados."
    )
    console.print(Panel(body, title="Resumo da operação", border_style="cyan"))


def _automatic_flow(
    console: Console,
    *,
    settings: Settings,
    show_result: ShowResult,
    prepare_database: PrepareDatabase,
) -> None:
    selection = _choose_ai(console, settings)
    if not selection:
        return
    playbook_mode, playbook_id = _choose_playbook(console)
    target = typer.prompt("IP, hostname ou alias do servidor").strip()
    objective = typer.prompt("Problema ou objetivo", default="validar a saúde geral do servidor").strip()
    ssh_port, ssh_port_summary = _choose_ssh_port(
        console,
        settings=settings,
        playbook_mode=playbook_mode,
        playbook_id=playbook_id,
        objective=objective,
    )
    environment = _choose_environment(console)
    mode = _choose_automatic_mode(console, playbook_mode)
    _operation_summary(
        console,
        flow="validação automática",
        selection=selection,
        target=target,
        environment=environment,
        playbook_mode=playbook_mode,
        playbook_id=playbook_id,
        ssh_port_summary=ssh_port_summary,
        objective=objective,
        mode=mode,
    )
    if not typer.confirm("Iniciar a validação?", default=True):
        return
    prepare_database()
    try:
        with use_provider(selection.provider, selection.model), use_playbook(playbook_mode, playbook_id):
            result = run_target(
                target,
                objective,
                environment=environment,
                mode=mode,
                approve=False,
                ssh_port=ssh_port,
                settings=settings,
            )
        show_result(result)
    except Exception as exc:
        console.print(Panel(f"{type(exc).__name__}: {exc}", title="Validação não concluída", border_style="red"))


def _session_header(console: Console, session: OperationalSession) -> None:
    state = session.status()
    console.print(
        f"[bold cyan][{state['provider_label']}][/bold cyan] "
        f"[bold][{state['target']}][/bold] "
        f"[porta: {state.get('ssh_port') or 'automática'}] "
        f"[{state.get('environment')}] "
        f"[playbook: {state.get('playbook_id') or state.get('playbook_mode')}] "
        f"[sessão: {session.session_id[:8]}]"
    )


def _show_session_help(console: Console) -> None:
    console.print(Panel(
        "/status — resumo da sessão\n"
        "/evidencias — reapresenta as evidências atuais\n"
        "/proposta — mostra a proposta atual\n"
        "/trocar-servidor IP — muda o alvo e permite informar outra porta SSH\n"
        "/exit, exit, sair — encerra a sessão e volta ao menu\n\n"
        "Também é possível escrever naturalmente: 'veja os logs', 'faça outra validação', "
        "'reinicie o serviço X' ou 'arrume'. Ações continuam sujeitas às políticas e à confirmação.",
        title="Comandos da sessão",
    ))


def _show_status(console: Console, session: OperationalSession) -> None:
    state = session.status()
    analysis = state.get("last_analysis") or {}
    console.print(Panel(
        f"Servidor: {state.get('target')}\n"
        f"Porta SSH: {state.get('ssh_port') or 'automática (playbook/inventário/padrão)'}\n"
        f"Ambiente: {state.get('environment')}\n"
        f"Origem/IA: {state.get('provider_label')}\n"
        f"Modelo/rota: {state.get('provider_model')}\n"
        f"Playbook: {state.get('playbook_id') or state.get('playbook_mode')}\n"
        f"Investigação: {state.get('last_investigation_id') or 'ainda não executada'}\n"
        f"Status: {analysis.get('status') or 'n/a'}\n"
        f"Confiança: {analysis.get('confidence') or 0}%\n"
        f"Causa provável: {analysis.get('probable_cause') or 'inconclusiva'}",
        title="Estado da sessão",
    ))


def _show_proposal(console: Console, session: OperationalSession) -> None:
    result = session.last_result or {}
    actions = ((result.get("analysis") or {}).get("proposed_actions") or [])
    if not actions:
        console.print("[yellow]Não existe proposta estruturada na investigação atual.[/yellow]")
        return
    console.print(Panel(json.dumps(actions, ensure_ascii=False, indent=2, default=str), title="Proposta atual"))


def _switch_target(console: Console, session: OperationalSession, target: str | None) -> dict[str, Any] | None:
    new_target = (target or typer.prompt("Novo IP, hostname ou alias")).strip()
    if not new_target:
        console.print("[yellow]Troca cancelada: alvo vazio.[/yellow]")
        return None
    console.print(f"Servidor atual: [cyan]{session.target}[/cyan]")
    console.print(f"Novo servidor: [cyan]{new_target}[/cyan]")
    if not typer.confirm("Salvar o contexto lógico e trocar de servidor?", default=True):
        return None
    environment = _choose_environment(console)
    objective = typer.prompt("Problema inicial no novo servidor", default="validar a saúde geral do servidor").strip()
    ssh_port, _ = _choose_ssh_port(
        console,
        settings=session.settings,
        playbook_mode=session.playbook_mode,
        playbook_id=session.playbook_id,
        objective=objective,
    )
    session.switch_target(new_target, environment=environment, ssh_port=ssh_port)
    result = session.start(objective)
    console.print(Panel("Servidor alterado. O histórico da sessão foi preservado.", title="Troca concluída"))
    return result


def _interactive_flow(
    console: Console,
    *,
    settings: Settings,
    show_result: ShowResult,
    prepare_database: PrepareDatabase,
) -> None:
    selection = _choose_ai(console, settings)
    if not selection:
        return
    playbook_mode, playbook_id = _choose_playbook(console)
    target = typer.prompt("IP, hostname ou alias do servidor").strip()
    objective = typer.prompt("Problema ou objetivo inicial", default="validar a saúde geral do servidor").strip()
    ssh_port, ssh_port_summary = _choose_ssh_port(
        console,
        settings=settings,
        playbook_mode=playbook_mode,
        playbook_id=playbook_id,
        objective=objective,
    )
    environment = _choose_environment(console)
    initial_mode = "investigate" if playbook_mode == "none" else "propose"
    _operation_summary(
        console,
        flow="sessão operacional interativa",
        selection=selection,
        target=target,
        environment=environment,
        playbook_mode=playbook_mode,
        playbook_id=playbook_id,
        ssh_port_summary=ssh_port_summary,
        objective=objective,
        mode=initial_mode,
    )
    if not typer.confirm("Abrir a sessão?", default=True):
        return

    prepare_database()
    session = OperationalSession(
        target=target,
        provider_name=selection.provider,
        provider_model=selection.model,
        provider_label=selection.label,
        environment=environment,
        playbook_mode=playbook_mode,
        playbook_id=playbook_id,
        ssh_port=ssh_port,
        settings=settings,
    )
    try:
        result = session.start(objective)
        show_result(result)
    except Exception as exc:
        console.print(Panel(f"{type(exc).__name__}: {exc}", title="Não foi possível iniciar a sessão", border_style="red"))
        return

    console.print(Panel(
        "A investigação inicial terminou, mas a sessão continua aberta. Escreva a próxima solicitação ou use /ajuda.",
        title="Chat operacional ativo",
        border_style="green",
    ))
    while session.active:
        _session_header(console, session)
        try:
            message = typer.prompt("Você").strip()
        except (EOFError, typer.Abort, KeyboardInterrupt):
            session.close()
            break
        intent = session.interpret(message)

        try:
            if intent.name == "empty":
                continue
            if intent.name == "exit":
                session.close()
                break
            if intent.name == "help":
                _show_session_help(console)
                continue
            if intent.name == "show_status":
                _show_status(console, session)
                continue
            if intent.name == "show_evidence":
                if session.last_result:
                    show_result(session.last_result)
                else:
                    console.print("[yellow]Ainda não existem evidências nesta sessão.[/yellow]")
                continue
            if intent.name == "show_proposal":
                _show_proposal(console, session)
                continue
            if intent.name == "switch_target":
                switched = _switch_target(console, session, intent.target)
                if switched:
                    show_result(switched)
                continue
            if intent.name == "execute_proposal":
                _show_proposal(console, session)
                if not typer.confirm("Executar somente a proposta revisada exibida acima?", default=False):
                    console.print("[yellow]Execução cancelada. A sessão permanece ativa.[/yellow]")
                    continue
                requested_by = typer.prompt("Identificação do aprovador", default="operador-menu").strip()
                execution = session.execute_last_proposal(requested_by=requested_by)
                console.print(Panel(json.dumps(execution, ensure_ascii=False, indent=2, default=str), title="Execução aprovada"))
                continue
            if intent.name in {"investigate_more", "propose_specific_action"}:
                result = session.investigate_more(
                    message,
                    specific_action=intent.name == "propose_specific_action",
                )
                show_result(result)
                continue
            if intent.name == "general_question":
                reply = intent.reply or session.answer_general_question(message)
                console.print(Panel(reply, title="Agent IA"))
                continue

            result = session.investigate_more(message)
            show_result(result)
        except Exception as exc:
            console.print(Panel(
                f"{type(exc).__name__}: {exc}\n\nA sessão lógica foi preservada. Você pode tentar outra validação, trocar de servidor ou sair.",
                title="Solicitação não concluída",
                border_style="red",
            ))

    console.print(Panel(
        f"Sessão {session.session_id[:8]} encerrada. O Agent IA voltou ao menu principal.",
        title="Sessão finalizada",
    ))


def _launch_codex_flow(console: Console, settings: Settings) -> None:
    status = codex_cli_status(settings)
    console.print(Panel(
        f"Versão: {status.version}\nDisponível: {'sim' if status.available else 'não'}\nDiretório: {status.workdir}\n\n"
        "O Codex CLI é aberto como ferramenta de desenvolvimento. Ele não herda automaticamente uma sessão SSH do Agent IA.",
        title="OpenAI Codex CLI",
    ))
    if not status.available or not typer.confirm("Abrir o Codex CLI?", default=False):
        return
    try:
        launch_codex(settings)
    except CodexCLIError as exc:
        console.print(Panel(str(exc), title="Codex CLI indisponível", border_style="red"))


def run_main_menu(
    *,
    console: Console,
    show_result: ShowResult,
    prepare_database: PrepareDatabase,
    settings: Settings | None = None,
) -> None:
    settings = settings or get_settings()
    while True:
        table = Table(title="AGENT IA INFRA — MENU PRINCIPAL")
        table.add_column("#", justify="right")
        table.add_column("Operação")
        table.add_column("Comportamento")
        table.add_row("1", "Validação automática", "Executa o fluxo atual e retorna ao menu")
        table.add_row("2", "Sessão interativa com servidor", "Mantém o chat e o contexto até sair ou trocar de servidor")
        table.add_row("3", "Abrir OpenAI Codex CLI", "Ferramenta local de desenvolvimento")
        table.add_row("0", "Sair", "Encerra o menu")
        console.print(table)
        choice = _choose_number(console, "Opção", minimum=0, maximum=3)
        if choice == 0:
            return
        if choice == 1:
            _automatic_flow(console, settings=settings, show_result=show_result, prepare_database=prepare_database)
        elif choice == 2:
            _interactive_flow(console, settings=settings, show_result=show_result, prepare_database=prepare_database)
        else:
            _launch_codex_flow(console, settings)
