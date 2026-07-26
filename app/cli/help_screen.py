from __future__ import annotations

from importlib import metadata
from typing import Sequence

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table


TOP_LEVEL_HELP_INVOCATIONS = {
    (),
    ("--help",),
    ("-h",),
    ("help",),
}

VERSION_INVOCATIONS = {
    ("--version",),
    ("-V",),
    ("version",),
}


def should_show_full_help(args: Sequence[str]) -> bool:
    return tuple(args) in TOP_LEVEL_HELP_INVOCATIONS


def should_show_version(args: Sequence[str]) -> bool:
    return tuple(args) in VERSION_INVOCATIONS


def current_version() -> str:
    try:
        return metadata.version("agent-ia-infra")
    except metadata.PackageNotFoundError:
        return "desenvolvimento"


def _command_table() -> Table:
    table = Table(title="Comandos principais", show_lines=True)
    table.add_column("Comando", style="bold cyan", no_wrap=True)
    table.add_column("Finalidade")
    table.add_row("agent --menu", "Abre o menu com validação automática, sessão interativa e Codex CLI.")
    table.add_row(
        escape("agent ALVO [PROBLEMA...]"),
        "Executa uma investigação direta no IP, hostname ou alias informado.",
    )
    table.add_row(
        escape("agent replay UUID [--provedor IA]"),
        "Reanalisa evidências já gravadas sem abrir uma nova conexão SSH.",
    )
    table.add_row(
        escape("agent approve UUID TOKEN [--por NOME]"),
        "Executa uma proposta assinada, revisada e ainda válida.",
    )
    table.add_row("agent doctor ai", "Valida conectividade, modelos e rotas dos provedores sem exibir segredos.")
    table.add_row("agent --help | -h | help", "Exibe este guia operacional completo.")
    table.add_row("agent --version | -V | version", "Exibe a versão instalada do Agent IA.")
    return table


def _direct_options_table() -> Table:
    table = Table(title="Opções da execução direta", show_lines=True)
    table.add_column("Opção", style="bold green", no_wrap=True)
    table.add_column("Valores e comportamento")
    table.add_row(
        "--ambiente, -a",
        "production | standby | monitoring | training | unknown. O padrão é unknown.",
    )
    table.add_row(
        "--porta, -p",
        "Porta SSH informada pelo operador; sobrescreve playbook, inventário e padrão do .env.",
    )
    table.add_row(
        "--modo",
        "investigar | propor | corrigir. Sem esta opção, o Agent interpreta a intenção do texto.",
    )
    table.add_row(
        "--somente-validar",
        "Compatibilidade: força o modo investigar e impede execução corretiva.",
    )
    table.add_row("--menu", "Abre o menu operacional em vez da execução direta.")
    table.add_row("--help, -h", "Exibe a ajuda. Não inicia SSH nem executa validações.")
    table.add_row("--version, -V", "Exibe somente a versão instalada.")
    return table


def _mode_table() -> Table:
    table = Table(title="Modos operacionais", show_lines=True)
    table.add_column("Modo", style="bold magenta")
    table.add_column("O que faz")
    table.add_column("Executa alteração?")
    table.add_row("investigar", "Coleta evidências e apresenta diagnóstico.", "Não")
    table.add_row("propor", "Investiga, cria proposta estruturada e solicita aprovação.", "Não")
    table.add_row(
        "corrigir",
        "Tenta executar somente ações autorizadas quando ambiente, política, evidência e revisão permitem.",
        "Somente sob todas as proteções",
    )
    return table


def _menu_table() -> Table:
    table = Table(title="Fluxos disponíveis em agent --menu", show_lines=True)
    table.add_column("Opção", style="bold yellow")
    table.add_column("Fluxo")
    table.add_column("Comportamento")
    table.add_row("1", "Validação automática", "Executa a investigação, mostra o resultado e volta ao menu.")
    table.add_row(
        "2",
        "Sessão interativa com servidor",
        "Mantém servidor, histórico, evidências e proposta no chat até sair ou trocar o alvo.",
    )
    table.add_row("3", "OpenAI Codex CLI", "Abre a ferramenta local de desenvolvimento; não herda a sessão SSH.")
    table.add_row("0", "Sair", "Encerra o menu sem executar outra operação.")
    return table


def _ai_sources_table() -> Table:
    table = Table(title="Origem dos modelos no menu", show_lines=True)
    table.add_column("Origem", style="bold cyan")
    table.add_column("O que representa")
    table.add_column("Configuração no Agent IA")
    table.add_row(
        "OmniRoute — gateway centralizado",
        "Encaminha para modelos, rotas e combos configurados no próprio gateway.",
        "OMNIROUTE_API_KEY e OMNIROUTE_BASE_URL. A rota é escolhida no menu.",
    )
    table.add_row(
        "Provedores diretos",
        "Gemini, Groq e OpenRouter acessados sem gateway.",
        "Exigem as API keys individuais correspondentes.",
    )
    table.add_row(
        "Ollama local",
        "Modelo executado localmente.",
        "OLLAMA_MODEL e OLLAMA_BASE_URL.",
    )
    return table


def _chat_table() -> Table:
    table = Table(title="Comandos da sessão interativa", show_lines=True)
    table.add_column("Comando ou frase", style="bold blue", no_wrap=True)
    table.add_column("Ação")
    table.add_row("/ajuda", "Mostra os comandos disponíveis dentro do chat operacional.")
    table.add_row("/status", "Mostra servidor, ambiente, origem/modelo, playbook e investigação atual.")
    table.add_row("/evidencias", "Reapresenta a última investigação e as evidências coletadas.")
    table.add_row("/proposta", "Mostra a proposta estruturada mais recente.")
    table.add_row(
        "/trocar-servidor IP",
        "Salva o contexto lógico, solicita a porta SSH e inicia uma validação no novo servidor.",
    )
    table.add_row("/exit | exit | sair", "Encerra a sessão e volta ao menu principal.")
    table.add_row("arrume", "Solicita a execução da última proposta revisada e exige confirmação explícita.")
    table.add_row(
        "reinicie o serviço X",
        "Primeiro valida e propõe a ação. Não executa restart imediatamente.",
    )
    table.add_row(
        "veja os logs / faça outra validação",
        "Continua investigando no servidor atual usando o contexto existente.",
    )
    return table


def _support_table() -> Table:
    table = Table(title="Comandos auxiliares e serviços", show_lines=True)
    table.add_column("Comando", style="bold cyan", no_wrap=True)
    table.add_column("Finalidade")
    table.add_row("agent replay --help", "Ajuda específica do replay de investigação.")
    table.add_row("agent approve --help", "Ajuda específica da aprovação assinada.")
    table.add_row("agent-worker --help", "Lista os comandos do worker distribuído.")
    table.add_row("agent-worker run", "Consome continuamente jobs da fila Redis.")
    table.add_row("agent-worker run --once", "Processa no máximo um job e encerra.")
    table.add_row("agent-worker run --bloqueio SEGUNDOS", "Define o tempo de espera por um job da fila.")
    table.add_row("agent-worker job UUID", "Consulta o estado de um job distribuído.")
    table.add_row("agent doctor ai", "Diagnostica provedores, modelos e rotas antes de abrir SSH.")
    table.add_row("python -m app.db.init_db", "Cria ou atualiza as estruturas necessárias no banco do Agent IA.")
    table.add_row(
        "uvicorn app.main:app --host 0.0.0.0 --port 8080",
        "Inicia API, webhook do Checkmk, endpoints administrativos e métricas.",
    )
    table.add_row(
        "docker compose -f docker-compose.lab.yml up -d --build",
        "Inicia o laboratório controlado. Use somente com ambiente training.",
    )
    return table


def _examples_table() -> Table:
    table = Table(title="Exemplos", show_lines=True)
    table.add_column("Objetivo")
    table.add_column("Comando", style="cyan")
    table.add_row("Abrir o aplicativo interativo", "agent --menu")
    table.add_row(
        "Investigar sem alterar",
        'agent 172.27.225.31 "Systemd Socket Summary CRITICAL" --ambiente monitoring --modo investigar',
    )
    table.add_row(
        "Usar porta SSH diferente de 22",
        'agent 192.168.28.10 "validar saúde geral" --porta 2222 --modo investigar',
    )
    table.add_row(
        "Investigar e propor",
        'agent checkmk-cliente "automation-helper parado" --ambiente monitoring --modo propor',
    )
    table.add_row(
        "Compatibilidade somente leitura",
        'agent 10.45.0.149 "validar porta 6556" --somente-validar',
    )
    table.add_row(
        "Reanalisar sem SSH",
        "agent replay UUID_DA_INVESTIGACAO --provedor groq",
    )
    table.add_row(
        "Executar proposta aprovada",
        "agent approve UUID_DA_INVESTIGACAO 'TOKEN_ASSINADO' --por jose",
    )
    return table


def render_full_help(console: Console, *, version: str | None = None) -> None:
    resolved_version = version or current_version()
    console.print(Panel(
        "Agente AIOps para investigação segura de infraestrutura, uso de playbooks, "
        "sessões conversacionais com servidores, propostas revisadas e execução controlada.\n\n"
        "A ajuda nunca abre SSH e nunca executa comandos remotos.",
        title=f"AGENT IA INFRA — versão {resolved_version}",
        border_style="cyan",
    ))

    usage = (
        "agent --menu\n"
        "agent ALVO [PROBLEMA...] [--ambiente AMBIENTE] [--porta PORTA] [--modo MODO]\n"
        "agent replay UUID [--provedor IA]\n"
        "agent approve UUID TOKEN [--por NOME]\n"
        "agent doctor ai"
    )
    console.print(Panel(escape(usage), title="Uso rápido"))

    console.print(_command_table())
    console.print(_direct_options_table())
    console.print(_mode_table())
    console.print(_menu_table())
    console.print(_ai_sources_table())

    console.print(Panel(
        "No menu, o playbook pode ser escolhido automaticamente, selecionado manualmente ou ignorado.\n"
        "A opção 0 segue sem playbook e inicia obrigatoriamente em modo investigar.\n"
        "A porta SSH pode ser digitada no menu; Enter usa playbook, inventário ou SSH_DEFAULT_PORT, nessa ordem.\n"
        "Novos arquivos .yml da pasta configurada em AGENT_PLAYBOOK_DIR aparecem no menu após o processo recarregar os playbooks.",
        title="Seleção de playbooks",
        border_style="yellow",
    ))

    console.print(_chat_table())
    console.print(_support_table())
    console.print(_examples_table())

    console.print(Panel(
        "• Nunca acessa banco de dados de cliente.\n"
        "• Nunca executa reboot, shutdown, poweroff ou halt do servidor.\n"
        "• Nunca controla start, stop, restart, kill ou remoção de containers.\n"
        "• Produção, standby e ambiente desconhecido não recebem correção automática.\n"
        "• Correções ficam limitadas a monitoramento e treinamento, com ferramenta autorizada, "
        "evidência, segunda IA, token assinado e confirmação humana.\n"
        "• Reinício de serviço solicitado no chat é primeiro investigado e proposto.",
        title="Proteções obrigatórias",
        border_style="red",
    ))

    console.print(Panel(
        "Ajuda específica:\n"
        "  agent replay --help\n"
        "  agent approve --help\n"
        "  agent doctor ai --help\n"
        "  agent-worker --help\n"
        "  agent-worker run --help\n"
        "  agent-worker job --help",
        title="Mais detalhes",
        border_style="green",
    ))


def render_version(console: Console) -> None:
    console.print(f"Agent IA Infra {current_version()}")
