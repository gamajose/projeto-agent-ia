from __future__ import annotations

from getpass import getpass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.services.ssh import SSHExecutor
from app.services.workflow import run_full_diagnosis

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.callback()
def main() -> None:
    """Agent IA para troubleshooting seguro de ambientes Checkmk."""


def ask_environment() -> EnvironmentType:
    console.print("\n1 - Produção\n2 - Standby\n3 - Monitoramento")
    option = IntPrompt.ask("Ambiente", choices=["1", "2", "3"])
    return {1: EnvironmentType.PRODUCTION, 2: EnvironmentType.STANDBY, 3: EnvironmentType.MONITORING}[option]


def _credentials(default_user: str, default_password: str | None, label: str = "") -> tuple[str, str]:
    use_default = Confirm.ask(f"Usar credencial do .env{label}?", default=True)
    username = default_user if use_default else Prompt.ask(f"Usuário SSH{label}")
    password = default_password if use_default else getpass(f"Senha{label}: ")
    if not password:
        password = getpass(f"Senha SSH{label}: ")
    return username, password


@app.command()
def run() -> None:
    settings = get_settings()
    console.print("[bold]AGENT IA — CHECKMK[/bold]")
    console.print("0 - Linux\n1 - pfSense")
    host_option = IntPrompt.ask("Tipo", choices=["0", "1"])
    host_type = "linux" if host_option == 0 else "pfsense"
    affected_ip = Prompt.ask("IP VPN do host")
    affected_port = IntPrompt.ask("Porta SSH", default=settings.ssh_default_port)
    environment = ask_environment()
    username, password = _credentials(settings.ssh_default_user, settings.ssh_default_password)

    affected = SSHExecutor(affected_ip, affected_port, username, password, settings.ssh_connect_timeout)
    monitor: SSHExecutor | None = None
    monitor_owned = False
    try:
        console.print("\n[cyan]1/4 Conectando ao host...[/cyan]")
        affected.connect()

        # Ao escolher Monitoramento, o próprio host informado já é o servidor Checkmk.
        # Para Produção ou Standby, ainda é necessário confirmar se o Checkmk está
        # no mesmo servidor ou solicitar os dados do servidor de monitoramento.
        if environment == EnvironmentType.MONITORING:
            same_server = True
            monitor_ip, monitor_port = affected_ip, affected_port
            monitor = affected
            console.print("[dim]Ambiente de monitoramento selecionado: utilizando este host como servidor Checkmk.[/dim]")
        else:
            same_server = Confirm.ask("O Checkmk está neste mesmo servidor?", default=False)
            monitor_ip, monitor_port = affected_ip, affected_port
            monitor = affected
            if not same_server:
                monitor_ip = Prompt.ask("IP VPN do servidor Checkmk")
                monitor_port = IntPrompt.ask("Porta SSH do Checkmk", default=settings.ssh_default_port)
                if Confirm.ask("Usar a mesma credencial?", default=True):
                    monitor_user, monitor_password = username, password
                else:
                    monitor_user, monitor_password = _credentials(
                        settings.ssh_default_user,
                        settings.ssh_default_password,
                        " do Checkmk",
                    )
                monitor = SSHExecutor(
                    monitor_ip,
                    monitor_port,
                    monitor_user,
                    monitor_password,
                    settings.ssh_connect_timeout,
                )
                monitor.connect()
                monitor_owned = True

        console.print("[cyan]2/4 Coletando evidências...[/cyan]")
        console.print("[cyan]3/4 Analisando e aplicando somente ajustes seguros...[/cyan]")
        result = run_full_diagnosis(
            affected=affected,
            monitor=monitor,
            affected_ip=affected_ip,
            affected_port=affected_port,
            monitor_ip=monitor_ip,
            monitor_port=monitor_port,
            host_type=host_type,
            environment=environment,
            same_server=same_server,
        )
        console.print("[cyan]4/4 Validando o resultado...[/cyan]\n")

        analysis = result["analysis"]
        table = Table(title="Resultado")
        table.add_column("Item", style="bold")
        table.add_column("Valor")
        table.add_row("Host", result["hostname"])
        table.add_row("Container", result["container"] or "não localizado")
        table.add_row("Site OMD", result["site"] or "não localizado")
        table.add_row("Estado inicial", result["state"])
        table.add_row("Estado após validação", result["validated_state"])
        table.add_row("Recorrências", str(result["recurrences"]))
        table.add_row("Incidente", result["incident_id"])
        console.print(table)

        console.print(Panel(str(analysis.get("summary", "Sem resumo")), title="Diagnóstico"))
        console.print(f"[bold]Causa provável:[/bold] {analysis.get('probable_cause', 'inconclusiva')}")
        console.print(f"[bold]Confiança:[/bold] {analysis.get('confidence', 0)}")

        actions = result.get("actions") or []
        if actions:
            action_table = Table(title="Ações")
            action_table.add_column("Status")
            action_table.add_column("Alvo")
            action_table.add_column("Ação")
            for action in actions:
                action_table.add_row(
                    action.get("status", ""),
                    action.get("target", ""),
                    action.get("description") or action.get("command", ""),
                )
            console.print(action_table)
        else:
            console.print("[yellow]Nenhum ajuste seguro foi necessário ou recomendado.[/yellow]")

        if analysis.get("ai_error"):
            console.print(f"[yellow]Aviso IA: {analysis['ai_error']}[/yellow]")
        console.print(Panel(str(analysis.get("ticket_report", "")), title="Texto para ticket"))
    finally:
        if monitor_owned and monitor:
            monitor.close()
        affected.close()


if __name__ == "__main__":
    app()
