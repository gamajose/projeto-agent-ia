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
    return value if len(value) <= limit else value[-limit:] + f"\n[... últimos {limit} caracteres ...]"


def _print_command_result(title: str, result: dict[str, Any] | None) -> None:
    if not isinstance(result, dict) or "command" not in result:
        return
    exit_code = result.get("exit_code", "?")
    color = "green" if exit_code == 0 else "red"
    sudo = " | sudo: sim" if result.get("sudo") else ""
    console.print(f"\n[bold]{title}[/bold] — [{color}]{'OK' if exit_code == 0 else 'FALHA'}[/] | retorno: {exit_code}{sudo}")
    console.print(f"[cyan]Comando:[/cyan] {result.get('command', '')}")
    console.print(Panel(_short(str(result.get("stdout") or "")), title="STDOUT"))
    if result.get("stderr"):
        console.print(Panel(_short(str(result["stderr"])), title="STDERR", border_style="red"))


def _print_collection_details(evidence: dict[str, Any]) -> None:
    console.rule("[bold cyan]Evidências coletadas — comandos e retornos[/bold cyan]")
    affected = evidence.get("affected_host") or {}
    for key in (
        "agent_units", "agent_controller", "port_6556", "agent_local_output", "agent_sample",
        "firewall", "routes", "resources", "recent_agent_logs", "privileges",
    ):
        _print_command_result(f"Host afetado / {key}", affected.get(key))

    monitor = evidence.get("monitor") or {}
    _print_command_result("Monitoramento / Docker", monitor.get("docker"))
    _print_command_result("Monitoramento / Containers", monitor.get("containers_raw"))
    for detail in monitor.get("container_details") or []:
        name = (detail.get("container") or {}).get("name", "container")
        for key in ("inspect", "sites", "events", "logs"):
            _print_command_result(f"{name} / {key}", detail.get(key))

    for finding in (evidence.get("checkmk") or {}).get("findings") or []:
        prefix = f"{finding.get('container', '?')} / site {finding.get('site', '?')}"
        for key in ("omd_status", "cmk_D", "cmk_vvn", "agent_fetch", "nagios_logs", "site_logs"):
            _print_command_result(f"{prefix} / {key}", finding.get(key))


def _print_action_details(actions: list[dict[str, Any]]) -> None:
    console.rule("[bold cyan]Ações executadas e validações[/bold cyan]")
    if not actions:
        console.print("[yellow]Nenhuma ação foi executada.[/yellow]")
        return
    for index, action in enumerate(actions, 1):
        console.print(Panel(
            f"Status: {action.get('status', '')}\nAlvo: {action.get('target', '')}\n"
            f"Descrição: {action.get('description', '')}\nComando: {action.get('command', '')}\n"
            f"Retorno: {action.get('exit_code', '-')}\nSaída: {_short(str(action.get('output') or ''))}",
            title=f"Ação {index}",
            border_style="green" if action.get("status") == "validated" else "yellow",
        ))
        _print_command_result(f"Ação {index} / validação", action.get("validation"))
        for number, diagnostic in enumerate(action.get("failure_diagnostics") or [], 1):
            _print_command_result(f"Ação {index} / diagnóstico {number}", diagnostic)


def _print_service_state_report(analysis: dict[str, Any]) -> None:
    report = analysis.get("service_state_report") or {}
    console.rule("[bold cyan]Comparação dos serviços Checkmk[/bold cyan]")
    console.print(f"[bold]Resultado da resolução:[/bold] {report.get('resolution', 'inconclusive')}")

    before = report.get("before") or []
    after = report.get("after") or []
    if before or after:
        table = Table(title="Estados antes e depois")
        table.add_column("Serviço")
        table.add_column("Antes")
        table.add_column("Depois")
        table.add_column("Saída posterior")
        before_map = {str(item.get('service', '')).casefold(): item for item in before}
        after_map = {str(item.get('service', '')).casefold(): item for item in after}
        for key in sorted(set(before_map) | set(after_map)):
            old = before_map.get(key, {})
            new = after_map.get(key, {})
            table.add_row(
                str((new or old).get("service", key)),
                str(old.get("state", "não visto")),
                str(new.get("state", "não visto")),
                _short(str(new.get("output") or ""), 180),
            )
        console.print(table)

    groups = (
        ("Normalizados", report.get("normalized") or [], "green"),
        ("Ainda afetados", report.get("still_affected") or [], "red"),
        ("Novos problemas", report.get("new_issues") or [], "red"),
    )
    for title, items, color in groups:
        if items:
            console.print(f"[bold {color}]{title}:[/bold {color}]")
            for item in items:
                console.print(f"  • {item.get('service')} — {item.get('before')} → {item.get('after')}")


def _print_analysis(analysis: dict[str, Any]) -> None:
    console.rule("[bold cyan]Conclusão técnica[/bold cyan]")
    console.print(Panel(str(analysis.get("summary", "Sem resumo")), title="Diagnóstico"))
    console.print(f"[bold]Causa provável:[/bold] {analysis.get('probable_cause', 'inconclusiva')}")
    console.print(f"[bold]Confiança:[/bold] {analysis.get('confidence', 0)}")

    for title, field in (("Fatos observados", "facts_observed"), ("Hipóteses", "hypotheses")):
        items = analysis.get(field) or []
        if items:
            console.print(f"[bold]{title}:[/bold]")
            for item in items:
                console.print(f"  • {item}")
    if analysis.get("conclusion"):
        console.print(Panel(str(analysis["conclusion"]), title="Conclusão suportada pelas evidências"))

    if analysis.get("evidence_used"):
        console.print("[bold]Evidências usadas:[/bold]")
        for item in analysis["evidence_used"]:
            console.print(f"  • {item}")
    if analysis.get("recommended_read_only_checks"):
        console.print("[bold]Validações adicionais somente leitura:[/bold]")
        for item in analysis["recommended_read_only_checks"]:
            console.print(f"  • {item}")
    if analysis.get("ai_error"):
        console.print(f"[yellow]Aviso IA externa: {analysis['ai_error']}[/yellow]")
    console.print(Panel(str(analysis.get("ticket_report", "")), title="Texto para ticket"))


def _resolve_host(reference: str, environment: EnvironmentType, default_port: int) -> tuple[str, int]:
    saved = resolve_saved_target(reference, environment.value)
    if saved and saved.get("source") == "host":
        console.print(f"[green]Host localizado no banco:[/green] {saved['vpn_ip']}:{saved['ssh_port']}")
        return str(saved["vpn_ip"]), int(saved["ssh_port"])
    if _is_ip(reference):
        return reference, IntPrompt.ask("Porta SSH", default=default_port)
    console.print(f"[red]Host '{reference}' não localizado. Use o IP VPN na primeira execução.[/red]")
    raise typer.Exit(2)


def _run_filesystem(settings: Any, host_type: str, reference: str, environment: EnvironmentType) -> None:
    ip, port = _resolve_host(reference, environment, settings.ssh_default_port)
    mountpoint = Prompt.ask("Filesystem ou ponto de montagem", default="/").strip() or "/"
    username, password = _credentials(settings.ssh_default_user, settings.ssh_default_password)
    executor = SSHExecutor(ip, port, username, password, settings.ssh_connect_timeout)
    try:
        console.print(f"\n[cyan]1/4 Conectando ao host {ip}:{port}...[/cyan]")
        executor.connect()
        console.print(f"[cyan]2/4 Coletando evidências do filesystem {mountpoint}...[/cyan]")
        result = run_filesystem_diagnosis(
            executor=executor, vpn_ip=ip, ssh_port=port, host_type=host_type,
            environment=environment, mountpoint=mountpoint,
        )
        console.print("[cyan]3/4 Analisando evidências com IA...[/cyan]")
        table = Table(title="Resultado — File System")
        table.add_column("Item", style="bold")
        table.add_column("Valor")
        for label, value in (
            ("Host", result["hostname"]), ("Filesystem", result["mountpoint"]),
            ("Estado", result["state"]), ("Uso de blocos", f"{result['block_usage_percent']}%"),
            ("Uso de inodes", f"{result['inode_usage_percent']}%"),
            ("Incidente", result["incident_id"]),
        ):
            table.add_row(label, str(value))
        console.print(table)
        for key, value in result.get("checks", {}).items():
            _print_command_result(key, value)
        _print_analysis(result["analysis"])
        console.print("[cyan]4/4 Resultado concluído e persistido.[/cyan]")
    finally:
        executor.close()


def _run_checkmk(settings: Any, host_type: str, reference: str, environment: EnvironmentType) -> None:
    saved = resolve_saved_target(reference, environment.value)
    monitor_saved = saved if saved and saved.get("source") == "monitoring_mapping" else None
    if environment == EnvironmentType.MONITORING and monitor_saved:
        affected_ip, affected_port = str(monitor_saved["vpn_ip"]), int(monitor_saved["ssh_port"])
    elif saved and saved.get("source") == "host":
        affected_ip, affected_port = str(saved["vpn_ip"]), int(saved["ssh_port"])
    elif _is_ip(reference):
        affected_ip, affected_port = reference, IntPrompt.ask("Porta SSH", default=settings.ssh_default_port)
    elif monitor_saved:
        affected_reference = Prompt.ask("IP VPN ou hostname do host afetado").strip()
        affected_ip, affected_port = _resolve_host(affected_reference, environment, settings.ssh_default_port)
    else:
        console.print(f"[red]Site/host '{reference}' ainda não está cadastrado. Use o IP VPN na primeira execução.[/red]")
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
            monitor_ip, monitor_port, monitor = affected_ip, affected_port, affected
        else:
            same_server = Confirm.ask("O Checkmk está neste mesmo servidor?", default=False)
            monitor_ip, monitor_port, monitor = affected_ip, affected_port, affected
            if not same_server:
                if monitor_saved:
                    monitor_ip, monitor_port = str(monitor_saved["vpn_ip"]), int(monitor_saved["ssh_port"])
                else:
                    monitor_reference = Prompt.ask("IP VPN ou site OMD do servidor Checkmk").strip()
                    resolved = resolve_saved_target(monitor_reference, EnvironmentType.MONITORING.value)
                    if resolved:
                        monitor_ip, monitor_port = str(resolved["vpn_ip"]), int(resolved["ssh_port"])
                    elif _is_ip(monitor_reference):
                        monitor_ip = monitor_reference
                        monitor_port = IntPrompt.ask("Porta SSH do Checkmk", default=settings.ssh_default_port)
                    else:
                        raise typer.Exit(2)
                monitor_user, monitor_password = (username, password)
                if not Confirm.ask("Usar a mesma credencial?", default=True):
                    monitor_user, monitor_password = _credentials(settings.ssh_default_user, settings.ssh_default_password, " do Checkmk")
                monitor = SSHExecutor(monitor_ip, monitor_port, monitor_user, monitor_password, settings.ssh_connect_timeout)
                monitor.connect()
                monitor_owned = True

        console.print("[cyan]2/4 Coletando evidências e estados de serviços...[/cyan]")
        console.print("[cyan]3/4 Analisando, aplicando ajustes seguros e validando...[/cyan]")
        result = run_full_diagnosis(
            affected=affected, monitor=monitor, affected_ip=affected_ip, affected_port=affected_port,
            monitor_ip=monitor_ip, monitor_port=monitor_port, host_type=host_type,
            environment=environment, same_server=same_server,
        )
        console.print("[cyan]4/4 Organizando resultado detalhado...[/cyan]\n")
        analysis = result["analysis"]
        table = Table(title="Resultado — Checkmk")
        table.add_column("Item", style="bold")
        table.add_column("Valor")
        for label, value in (
            ("Host", result["hostname"]), ("Container", result["container"] or "não localizado"),
            ("Site OMD", result["site"] or "não localizado"),
            ("Resultado inicial do cmk", result["state"]),
            ("Resultado após validação", result["validated_state"]),
            ("Resolução real dos serviços", analysis.get("resolution", "inconclusive")),
            ("Recorrências", result["recurrences"]), ("Incidente", result["incident_id"]),
        ):
            table.add_row(label, str(value))
        console.print(table)
        _print_collection_details(result.get("evidence") or {})
        _print_action_details(result.get("actions") or [])
        _print_service_state_report(analysis)
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
        module = "checkmk" if IntPrompt.ask("Módulo de validação", choices=["1", "2"]) == 1 else "filesystem"
    else:
        module = "checkmk"
    reference = Prompt.ask("IP VPN ou site OMD" if module == "checkmk" else "IP VPN ou hostname do servidor").strip()
    environment = ask_environment()
    if module == "filesystem":
        _run_filesystem(settings, host_type, reference, environment)
    else:
        _run_checkmk(settings, host_type, reference, environment)


if __name__ == "__main__":
    app()
