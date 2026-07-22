from __future__ import annotations

from getpass import getpass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt

from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.services.discovery import discover_checkmk_on_monitor, discover_host, validate_affected_host
from app.services.ssh import SSHExecutor

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.callback()
def main() -> None:
    """Agent IA para troubleshooting seguro de ambientes Checkmk."""


def ask_environment() -> EnvironmentType:
    console.print("\nAmbiente do host:")
    console.print("1 - Produção")
    console.print("2 - Standby")
    console.print("3 - Monitoramento")
    option = IntPrompt.ask("Escolha", choices=["1", "2", "3"])
    return {
        1: EnvironmentType.PRODUCTION,
        2: EnvironmentType.STANDBY,
        3: EnvironmentType.MONITORING,
    }[option]


def show_value(title: str, value: str, ok_when_present: bool = True) -> None:
    present = bool(value.strip())
    marker = "[green]✓[/green]" if present == ok_when_present else "[yellow]![/yellow]"
    console.print(f"{marker} [bold]{title}[/bold]")
    if value.strip():
        console.print(value.strip())


@app.command()
def run() -> None:
    settings = get_settings()
    console.print("[bold]AGENT IA — TROUBLESHOOTING CHECKMK[/bold]")
    console.print("0 - Linux")
    console.print("1 - pfSense")
    IntPrompt.ask("Tipo do host", choices=["0", "1"])
    affected_ip = Prompt.ask("IP VPN do host afetado")
    port = IntPrompt.ask("Porta SSH", default=settings.ssh_default_port)
    environment = ask_environment()

    use_default = Confirm.ask("Usar credencial padrão do .env?", default=True)
    username = settings.ssh_default_user if use_default else Prompt.ask("Usuário SSH")
    password = settings.ssh_default_password if use_default else getpass("Senha temporária: ")
    if not password:
        password = getpass("Senha SSH: ")

    affected = SSHExecutor(affected_ip, port, username, password, settings.ssh_connect_timeout)
    monitor = None
    monitor_owned = False

    try:
        affected.connect()
        info = discover_host(affected, environment)
        console.print(f"\n✓ Hostname: {info.hostname}")
        console.print(f"✓ Sistema: {info.os_name}")
        console.print(f"✓ Ambiente: {environment.value}")

        console.print("\n[bold cyan]Validações no host afetado[/bold cyan]")
        validations = validate_affected_host(affected, environment)
        show_value("Unidades ativas do agente", validations["service_status"])
        show_value("Porta 6556 em escuta", validations["listener"])
        show_value("Resposta local do agente Checkmk", validations["agent_output"])
        show_value("Estado do sudo", validations["sudo_access"])
        show_value("Firewall relacionado", validations["firewall"])

        same = Confirm.ask("O servidor de monitoramento está neste mesmo host?", default=False)
        monitor = affected
        if not same:
            monitor_ip = Prompt.ask("IP VPN do servidor de monitoramento")
            monitor_port = IntPrompt.ask("Porta SSH do monitoramento", default=settings.ssh_default_port)
            monitor_use_default = Confirm.ask("Usar a mesma credencial?", default=True)
            monitor_user = username if monitor_use_default else Prompt.ask("Usuário SSH do monitoramento")
            monitor_password = password if monitor_use_default else getpass("Senha temporária do monitoramento: ")
            monitor = SSHExecutor(monitor_ip, monitor_port, monitor_user, monitor_password, settings.ssh_connect_timeout)
            monitor.connect()
            monitor_owned = True

        discovery = discover_checkmk_on_monitor(monitor, environment, info.hostname)
        console.print("\n[bold cyan]Validações no servidor de monitoramento[/bold cyan]")
        show_value("Containers Checkmk", discovery["containers"])

        if not discovery["details"]:
            console.print("[yellow]! Não foi possível localizar sites OMD nos containers encontrados.[/yellow]")
        else:
            for detail in discovery["details"]:
                console.print(
                    Panel.fit(
                        f"[bold]Container:[/bold] {detail['container']}\n"
                        f"[bold]Site:[/bold] {detail['site']}\n\n"
                        f"[bold]OMD status[/bold]\n{detail['omd_status'] or 'Sem retorno'}\n\n"
                        f"[bold]Localização do host no Checkmk[/bold]\n{detail['host_check']}",
                        title="Checkmk",
                    )
                )

        console.print("\n[bold green]Validação inicial concluída.[/bold green]")
        console.print(
            "A próxima camada será consultar o estado atual dos serviços do host com cmk -vvn, "
            "correlacionar o alerta e registrar o incidente no PostgreSQL."
        )
    finally:
        if monitor_owned and monitor is not None:
            monitor.close()
        affected.close()


if __name__ == "__main__":
    app()
