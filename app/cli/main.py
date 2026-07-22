from __future__ import annotations

from getpass import getpass

import typer
from rich.console import Console
from rich.prompt import Confirm, IntPrompt, Prompt

from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.services.discovery import discover_checkmk_on_monitor, discover_host
from app.services.ssh import SSHExecutor

app = typer.Typer(no_args_is_help=False)
console = Console()


def ask_environment() -> EnvironmentType:
    console.print("\nAmbiente do host:")
    console.print("1 - Produção")
    console.print("2 - Standby")
    console.print("3 - Treinamento")
    option = IntPrompt.ask("Escolha", choices=["1", "2", "3"])
    return {1: EnvironmentType.PRODUCTION, 2: EnvironmentType.STANDBY, 3: EnvironmentType.TRAINING}[option]


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
    try:
        affected.connect()
        info = discover_host(affected, environment)
        console.print(f"\n✓ Hostname: {info.hostname}")
        console.print(f"✓ Sistema: {info.os_name}")
        console.print(f"✓ Ambiente: {environment.value}")
        console.print("✓ Agente Checkmk identificado" if info.checkmk_agent_units else "! Unidade do agente Checkmk não identificada")

        same = Confirm.ask("O servidor de monitoramento está neste mesmo host?", default=False)
        monitor = affected
        monitor_owned = False
        if not same:
            monitor_ip = Prompt.ask("IP VPN do servidor de monitoramento")
            monitor_port = IntPrompt.ask("Porta SSH do monitoramento", default=settings.ssh_default_port)
            monitor_use_default = Confirm.ask("Usar a mesma credencial?", default=True)
            monitor_user = username if monitor_use_default else Prompt.ask("Usuário SSH do monitoramento")
            monitor_password = password if monitor_use_default else getpass("Senha temporária do monitoramento: ")
            monitor = SSHExecutor(monitor_ip, monitor_port, monitor_user, monitor_password, settings.ssh_connect_timeout)
            monitor.connect()
            monitor_owned = True

        discovery = discover_checkmk_on_monitor(monitor, environment)
        console.print("\n[bold]Descoberta no servidor de monitoramento[/bold]")
        console.print(discovery["containers"] or "Nenhum container Checkmk localizado.")
        console.print("\nPróxima etapa: mapear site OMD, localizar o host no Checkmk e consultar os alertas ativos.")

        if monitor_owned:
            monitor.close()
    finally:
        affected.close()


if __name__ == "__main__":
    app()
