from __future__ import annotations

import ipaddress
from getpass import getpass
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.services.filesystem import run_filesystem_diagnosis
from app.services.persistence import resolve_saved_target
from app.services.ssh import SSHExecutor
from app.services.workflow import run_full_diagnosis

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.callback()
def main() -> None:
    """Agent IA para troubleshooting seguro de infraestrutura."""


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


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _short(text: str, limit: int = 4000) -> str:
    value = (text or "").strip()
    if not value:
        return "(sem saída)"
    if len(value) <= limit:
        return value
    return value[-limit:] + f"\n[... saída limitada aos últimos {limit} caracteres ...]"


def _print_command_result(title: str, result: dict[str, Any] | None) -> None:
    if not isinstance(result, dict) or "command" not in result:
        return
    exit_code = result.get("exit_code", "?")
    status = "OK" if exit_code == 0 else "FALHA"
    sudo = " | sudo: sim" if result.get("sudo") else ""
    color = "green" if exit_code == 0 else "red"
    console.print(f"\n[bold]{title}[/bold] — [{color}]{status}[/] | retorno: {exit_code}{sudo}")
    console.print(f"[cyan]Comando:[/cyan] {result.get('command', '')}")
    stdout = _short(str(result.get("stdout") or ""))
    stderr = _short(str(result.get("stderr") or ""))
    console.print(Panel(stdout, title="STDOUT", border_style="green" if exit_code == 0 else "yellow"))
    if stderr != "(sem saída)":
        console.print(Panel(stderr, title="STDERR", border_style="red"))


def _print_collection_details(evidence: dict[str, Any]) -> None:
    console.rule("[bold cyan]Evidências coletadas — comandos e retornos[/bold cyan]")
    affected = evidence.get("affected_host") or {}
    for key in (
        "agent_units", "agent_controller", "port_6556", "agent_local_output",
        "agent_sample", "firewall", "routes", "resources", "recent_agent_logs", "privileges",
    ):
        _print_command_result(f"Host afetado / {key}", affected.get(key))

    monitor = evidence.get("monitor") or {}
    _print_command_result("Monitoramento / Docker", monitor.get("docker"))
    _print_command_result("Monitoramento / Containers localizados", monitor.get("containers_raw"))
    for detail in monitor.get("container_details") or []:
        name = (detail.get("container") or {}).get("name", "container")
        for key in ("inspect", "sites", "events", "logs"):
            _print_command_result(f"{name} / {key}", detail.get(key))

    checkmk = evidence.get("checkmk") or {}
    for finding in checkmk.get("findings") or []:
        prefix = f"{finding.get('container', '?')} / site {finding.get('site', '?')}"
        for key in ("omd_status", "cmk_D", "cmk_vvn", "agent_fetch", "nagios_logs", "site_logs"):
            _print_command_result(f"{prefix} / {key}", finding.get(key))


def _print_action_details(actions: list[dict[str, Any]]) -> None:
    console.rule("[bold cyan]Ações executadas e validações[/bold cyan]")
    if not actions:
        console.print("[yellow]Nenhuma ação foi executada.[/yellow]")
        return
    for index, action in enumerate(actions, start=1):
        console.print(Panel(
            f"Status: {action.get('status', '')}\n"
            f"Alvo: {action.get('target', '')}\n"
            f"Descrição: {action.get('description', '')}\n"
            f"Comando: {action.get('command', '')}\n"
            f"Retorno: {action.get('exit_code', '-')}\n"
            f"Saída: {_short(str(action.get('output') or ''))}",
            title=f"Ação {index}",
            border_style="green" if action.get("status") == "validated" else "yellow",
        ))
        _print_command_result(f"Ação {index} / validação", action.get("validation"))
        for diagnostic_index, diagnostic in enumerate(action.get("failure_diagnostics") or [], start=1):
            _print_command_result(f"Ação {index} / diagnóstico de falha {diagnostic_index}", diagnostic)


def _print_post_validation(evidence: dict[str, Any]) -> None:
    post = evidence.get("post_validation") or {}
    if not post:
        return
    console.rule("[bold cyan]Validação completa após a ação[/bold cyan]")
    _print_collection_details({
        "affected_host": post.get("affected_host") or {},
        "monitor": {},
        "checkmk": post.get("checkmk") or {},
    })


def _print_analysis(analysis: dict[str, Any]) -> None:
    console.rule("[bold cyan]Conclusão técnica[/bold cyan]")
    console.print(Panel(str(analysis.get("summary", "Sem resumo")), title="Diagnóstico"))
    console.print(f"[bold]Causa provável:[/bold] {analysis.get('probable_cause', 'inconclusiva')}")
    console.print(f"[bold]Confiança:[/bold] {analysis.get('confidence', 0)}")
    evidence_used = analysis.get("evidence_used") or []
    if evidence_used:
        console.print("[bold]Evidências usadas na conclusão:[/bold]")
        for item in evidence_used:
            console.print(f"  • {item}")
    recommended = analysis.get("recommended_read_only_checks") or []
    if recommended:
        console.print("[bold]Validações adicionais somente leitura:[/bold]")
        for item in recommended:
            console.print(f"  • {item}")
    if analysis.get("ai_error"):
        console.print(f"[yellow]Aviso IA externa: {analysis['ai_error']}[/yellow]")
    console.print(Panel(str(analysis.get("ticket_report", "")), title="Texto para ticket"))


def _resolve_host_reference(reference: str, environment: EnvironmentType, default_port: int) -> tuple[str, int]:
    saved = resolve_saved_target(reference, environment.value)
    if saved and saved.get("source") == "host":
        ip = str(saved["vpn_ip"])
        port = int(saved["ssh_port"])
        console.print(f"[green]Host localizado no banco:[/green] {ip}:{port}")
        return ip, port
    if _is_ip(reference):
        return reference, IntPrompt.ask("Porta SSH", default=default_port)
    console.print(
        f"[red]Host '{reference}' não foi localizado no banco e não é um IP válido. "
        "Use o IP VPN na primeira execução para cadastrá-lo.[/red]"
    )
    raise typer.Exit(2)


def _run_filesystem_module(
    *,
    settings: Any,
    host_type: str,
    reference: str,
    environment: EnvironmentType,
) -> None:
    affected_ip, affected_port = _resolve_host_reference(reference, environment, settings.ssh_default_port)
    mountpoint = Prompt.ask("Filesystem ou ponto de montagem", default="/").strip() or "/"
    username, password = _credentials(settings.ssh_default_user, settings.ssh_default_password)
    executor = SSHExecutor(affected_ip, affected_port, username, password, settings.ssh_connect_timeout)

    try:
        console.print(f"\n[cyan]1/4 Conectando ao host {affected_ip}:{affected_port}...[/cyan]")
        executor.connect()
        console.print(f"[cyan]2/4 Coletando evidências do filesystem {mountpoint}...[/cyan]")
        console.print("[cyan]3/4 Analisando blocos, inodes, montagem, consumo, LVM e erros de I/O...[/cyan]")
        result = run_filesystem_diagnosis(
            executor=executor,
            vpn_ip=affected_ip,
            ssh_port=affected_port,
            host_type=host_type,
            environment=environment,
            mountpoint=mountpoint,
        )
        console.print("[cyan]4/4 Organizando resultado e persistindo evidências...[/cyan]\n")

        table = Table(title="Resultado — File System")
        table.add_column("Item", style="bold")
        table.add_column("Valor")
        table.add_row("Host", result["hostname"])
        table.add_row("Filesystem", result["mountpoint"])
        table.add_row("Estado", result["state"])
        table.add_row("Uso de blocos", f"{result['block_usage_percent']}%")
        table.add_row("Uso de inodes", f"{result['inode_usage_percent']}%")
        table.add_row("Recorrências", str(result["recurrences"]))
        table.add_row("Incidente salvo no banco", result["incident_id"])
        console.print(table)

        console.rule("[bold cyan]Validações de File System — comandos e retornos[/bold cyan]")
        labels = {
            "df_blocks": "Uso de espaço em blocos",
            "df_inodes": "Uso de inodes",
            "findmnt": "Origem, tipo e opções de montagem",
            "lsblk": "Discos, partições e filesystems",
            "top_directories": "Maiores diretórios no mesmo filesystem",
            "top_files": "Maiores arquivos no mesmo filesystem",
            "deleted_open_files": "Arquivos removidos ainda abertos",
            "kernel_filesystem_errors": "Erros de filesystem/I/O no kernel",
            "journal_filesystem_errors": "Erros de filesystem/I/O no journal",
            "fstab": "Configuração persistente em /etc/fstab",
            "lvm": "Estado de PV, VG e LV",
        }
        for key, value in result.get("checks", {}).items():
            _print_command_result(labels.get(key, key), value)

        console.print(Panel(
            "Nenhuma exclusão, limpeza, desmontagem, formatação, fsck online, "
            "redimensionamento ou reboot foi executado automaticamente.",
            title="Política de segurança",
            border_style="yellow",
        ))
        _print_analysis(result["analysis"])
    finally:
        executor.close()


def _run_checkmk_module(
    *,
    settings: Any,
    host_type: str,
    reference: str,
    environment: EnvironmentType,
) -> None:
    saved = resolve_saved_target(reference, environment.value)
    monitor_saved = saved if saved and saved.get("source") == "monitoring_mapping" else None

    if monitor_saved:
        console.print(
            f"[green]Site localizado no banco:[/green] {monitor_saved.get('site_name')} → "
            f"{monitor_saved.get('vpn_ip')}:{monitor_saved.get('ssh_port')} | "
            f"container {monitor_saved.get('container_name') or 'não informado'}"
        )

    if environment == EnvironmentType.MONITORING and monitor_saved:
        affected_ip = str(monitor_saved["vpn_ip"])
        affected_port = int(monitor_saved["ssh_port"])
    elif saved and saved.get("source") == "host":
        affected_ip = str(saved["vpn_ip"])
        affected_port = int(saved["ssh_port"])
        console.print(f"[green]Host localizado no banco:[/green] {affected_ip}:{affected_port}")
    elif _is_ip(reference):
        affected_ip = reference
        affected_port = IntPrompt.ask("Porta SSH", default=settings.ssh_default_port)
    elif monitor_saved:
        affected_reference = Prompt.ask("IP VPN ou hostname do host afetado").strip()
        affected_saved = resolve_saved_target(affected_reference, environment.value)
        if affected_saved:
            affected_ip = str(affected_saved["vpn_ip"])
            affected_port = int(affected_saved["ssh_port"])
            console.print(f"[green]Host afetado localizado no banco:[/green] {affected_ip}:{affected_port}")
        elif _is_ip(affected_reference):
            affected_ip = affected_reference
            affected_port = IntPrompt.ask("Porta SSH do host afetado", default=settings.ssh_default_port)
        else:
            console.print(f"[red]Referência '{affected_reference}' não localizada no banco e não é um IP válido.[/red]")
            raise typer.Exit(2)
    else:
        console.print(
            f"[red]Site/host '{reference}' ainda não está cadastrado no banco. "
            "Informe o IP VPN na primeira execução para criar o vínculo.[/red]"
        )
        raise typer.Exit(2)

    username, password = _credentials(settings.ssh_default_user, settings.ssh_default_password)
    affected = SSHExecutor(affected_ip, affected_port, username, password, settings.ssh_connect_timeout)
    monitor: SSHExecutor | None = None
    monitor_owned = False

    try:
        console.print(f"\n[cyan]1/4 Conectando ao host {affected_ip}:{affected_port}...[/cyan]")
        affected.connect()

        if environment == EnvironmentType.MONITORING:
            same_server = True
            monitor_ip, monitor_port = affected_ip, affected_port
            monitor = affected
            console.print("[dim]Ambiente de monitoramento: este host será usado como servidor Checkmk.[/dim]")
        else:
            same_server = Confirm.ask("O Checkmk está neste mesmo servidor?", default=False)
            monitor_ip, monitor_port = affected_ip, affected_port
            monitor = affected
            if not same_server:
                if monitor_saved:
                    monitor_ip = str(monitor_saved["vpn_ip"])
                    monitor_port = int(monitor_saved["ssh_port"])
                    console.print(f"[green]Servidor Checkmk recuperado do banco:[/green] {monitor_ip}:{monitor_port}")
                else:
                    monitor_reference = Prompt.ask("IP VPN ou site OMD do servidor Checkmk").strip()
                    resolved_monitor = resolve_saved_target(monitor_reference, EnvironmentType.MONITORING.value)
                    if resolved_monitor:
                        monitor_ip = str(resolved_monitor["vpn_ip"])
                        monitor_port = int(resolved_monitor["ssh_port"])
                    elif _is_ip(monitor_reference):
                        monitor_ip = monitor_reference
                        monitor_port = IntPrompt.ask("Porta SSH do Checkmk", default=settings.ssh_default_port)
                    else:
                        console.print(f"[red]Servidor Checkmk '{monitor_reference}' não localizado.[/red]")
                        raise typer.Exit(2)

                if Confirm.ask("Usar a mesma credencial?", default=True):
                    monitor_user, monitor_password = username, password
                else:
                    monitor_user, monitor_password = _credentials(
                        settings.ssh_default_user, settings.ssh_default_password, " do Checkmk"
                    )
                monitor = SSHExecutor(
                    monitor_ip, monitor_port, monitor_user, monitor_password, settings.ssh_connect_timeout
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
        table = Table(title="Resultado — Checkmk")
        table.add_column("Item", style="bold")
        table.add_column("Valor")
        table.add_row("Host", result["hostname"])
        table.add_row("Container", result["container"] or "não localizado")
        table.add_row("Site OMD", result["site"] or "não localizado")
        table.add_row("Resultado inicial do cmk", result["state"])
        table.add_row("Resultado do cmk após validação", result["validated_state"])
        table.add_row("Recorrências", str(result["recurrences"]))
        table.add_row("Incidente salvo no banco", result["incident_id"])
        console.print(table)

        _print_collection_details(result.get("evidence") or {})
        _print_action_details(result.get("actions") or [])
        _print_post_validation(result.get("evidence") or {})
        _print_analysis(analysis)
    finally:
        if monitor_owned and monitor:
            monitor.close()
        affected.close()


@app.command()
def run() -> None:
    settings = get_settings()
    console.print("[bold]AGENT IA — INFRAESTRUTURA[/bold]")
    console.print("0 - Linux\n1 - pfSense")
    host_option = IntPrompt.ask("Tipo", choices=["0", "1"])
    host_type = "linux" if host_option == 0 else "pfsense"

    if host_type == "linux":
        console.print("\n1 - Checkmk\n2 - File System")
        module_option = IntPrompt.ask("Módulo de validação", choices=["1", "2"])
        module = "checkmk" if module_option == 1 else "filesystem"
    else:
        module = "checkmk"
        console.print("[dim]pfSense: utilizando o fluxo de validação Checkmk disponível.[/dim]")

    reference_label = "IP VPN ou site OMD" if module == "checkmk" else "IP VPN ou hostname do servidor"
    reference = Prompt.ask(reference_label).strip()
    environment = ask_environment()

    if module == "filesystem":
        _run_filesystem_module(
            settings=settings,
            host_type=host_type,
            reference=reference,
            environment=environment,
        )
    else:
        _run_checkmk_module(
            settings=settings,
            host_type=host_type,
            reference=reference,
            environment=environment,
        )


if __name__ == "__main__":
    app()
