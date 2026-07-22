from __future__ import annotations

from getpass import getpass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt

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
    console.print("\nAmbiente do host:")
    console.print("1 - Produção")
    console.print("2 - Standby")
    console.print("3 - Monitoramento")
    option = IntPrompt.ask("Escolha", choices=["1", "2", "3"])
    return {1: EnvironmentType.PRODUCTION, 2: EnvironmentType.STANDBY, 3: EnvironmentType.MONITORING}[option]


def _credentials(default_user: str, default_password: str | None, label: str = "") -> tuple[str, str]:
    use_default = Confirm.ask(f"Usar credencial padrão do .env{label}?", default=True)
    username = default_user if use_default else Prompt.ask(f"Usuário SSH{label}")
    password = default_password if use_default else getpass(f"Senha temporária{label}: ")
    if not password:
        password = getpass(f"Senha SSH{label}: ")
    return username, password


@app.command()
def run() -> None:
    settings = get_settings()
    console.print("[bold]AGENT IA — TROUBLESHOOTING CHECKMK[/bold]")
    console.print("0 - Linux")
    console.print("1 - pfSense")
    host_option = IntPrompt.ask("Tipo do host", choices=["0", "1"])
    host_type = "linux" if host_option == 0 else "pfsense"
    affected_ip = Prompt.ask("IP VPN do host afetado")
    affected_port = IntPrompt.ask("Porta SSH", default=settings.ssh_default_port)
    environment = ask_environment()
    username, password = _credentials(settings.ssh_default_user, settings.ssh_default_password)

    affected = SSHExecutor(affected_ip, affected_port, username, password, settings.ssh_connect_timeout)
    monitor: SSHExecutor | None = None
    monitor_owned = False
    try:
        console.print("\n[cyan]Conectando ao host afetado...[/cyan]")
        affected.connect()
        same_server = Confirm.ask("O servidor de monitoramento está neste mesmo host?", default=False)
        monitor_ip, monitor_port = affected_ip, affected_port
        monitor = affected
        if not same_server:
            monitor_ip = Prompt.ask("IP VPN do servidor de monitoramento")
            monitor_port = IntPrompt.ask("Porta SSH do monitoramento", default=settings.ssh_default_port)
            same_credentials = Confirm.ask("Usar a mesma credencial?", default=True)
            if same_credentials:
                monitor_user, monitor_password = username, password
            else:
                monitor_user, monitor_password = _credentials(settings.ssh_default_user, settings.ssh_default_password, " do monitoramento")
            monitor = SSHExecutor(monitor_ip, monitor_port, monitor_user, monitor_password, settings.ssh_connect_timeout)
            monitor.connect()
            monitor_owned = True

        console.print("[cyan]Coletando host, agente, rede, Docker, OMD, Checkmk, logs e histórico...[/cyan]")
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
        analysis = result["analysis"]
        console.print("\n[bold green]Diagnóstico concluído[/bold green]")
        console.print(f"Incidente: {result['incident_id']}")
        console.print(f"Host: {result['hostname']}")
        console.print(f"Container: {result['container'] or 'não localizado'}")
        console.print(f"Site OMD: {result['site'] or 'não localizado'}")
        console.print(f"Estado: {result['state']}")
        console.print(f"Ocorrências anteriores: {result['recurrences']}")
        console.print(Panel(str(analysis.get("summary", "Sem resumo")), title="Resumo Gemini"))
        console.print(f"[bold]Classificação:[/bold] {analysis.get('classification', 'inconclusive')}")
        console.print(f"[bold]Causa provável:[/bold] {analysis.get('probable_cause', 'inconclusiva')}")
        console.print(f"[bold]Confiança:[/bold] {analysis.get('confidence', 0)}")
        checks = analysis.get("recommended_read_only_checks") or []
        if checks:
            console.print("\n[bold]Verificações adicionais sugeridas:[/bold]")
            for check in checks:
                console.print(f" • {check}")
        remediations = analysis.get("remediation") or []
        if remediations:
            console.print("\n[yellow]Ações sugeridas, não executadas automaticamente:[/yellow]")
            for action in remediations:
                console.print(f" • {action.get('description', '')}: {action.get('command', '')}")
        console.print(Panel(str(analysis.get("ticket_report", "")), title="Relatório para ticket"))
    finally:
        if monitor_owned and monitor:
            monitor.close()
        affected.close()


if __name__ == "__main__":
    app()
