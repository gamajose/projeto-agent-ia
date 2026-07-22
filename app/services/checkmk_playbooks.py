from __future__ import annotations

import re
import shlex
from typing import Any, Callable

from app.core.policies import EnvironmentType
from app.services.discovery import _clean
from app.services.ssh import SSHExecutor

PROBLEM_STATES = {"WARN", "CRIT", "UNKNOWN", "PENDING"}


def _run(executor: SSHExecutor, command: str) -> dict[str, Any]:
    try:
        result = executor.run(command, EnvironmentType.MONITORING)
        return {
            "command": command,
            "exit_code": result.exit_code,
            "stdout": _clean(result.stdout),
            "stderr": _clean(result.stderr),
            "sudo": False,
        }
    except Exception as exc:
        return {
            "command": command,
            "exit_code": 255,
            "stdout": "",
            "stderr": str(exc),
            "sudo": False,
        }


def classify_service(service_name: str) -> str:
    name = service_name.casefold()
    if "automation helper" in name or "automation-helper" in name or name.startswith("process "):
        return "process"
    if "docker" in name and ("health" in name or "container" in name):
        return "docker_health"
    if name.startswith("omd ") or "omd status" in name:
        return "omd"
    if "check_mk" in name or "checkmk agent" in name or "cmk agent" in name:
        return "agent"
    if "filesystem" in name or "mount" in name or "inode" in name:
        return "filesystem"
    if "interface" in name or "packet" in name or "network" in name or "tcp" in name:
        return "network"
    if "memory" in name or "swap" in name:
        return "memory"
    if "cpu" in name or "load" in name:
        return "cpu"
    return "generic"


def _inside(container: str, site: str, inner: str) -> str:
    return f"docker exec {shlex.quote(container)} su - {shlex.quote(site)} -c {shlex.quote(inner)}"


def commands_for_service(service: dict[str, Any], container: str, site: str, hostname: str) -> list[tuple[str, str]]:
    category = classify_service(str(service.get("service") or ""))
    qhost = shlex.quote(hostname)
    common = [
        ("Estado atual do serviço no Checkmk", _inside(container, site, f"cmk -vvn {qhost}")),
        ("Últimos estados registrados", _inside(container, site, f"grep -F ';{hostname};' ~/var/log/nagios.log 2>/dev/null | tail -n 80")),
    ]

    catalog: dict[str, list[tuple[str, str]]] = {
        "process": [
            ("Estado global do site OMD", f"docker exec {shlex.quote(container)} omd status {shlex.quote(site)}"),
            ("Processos relacionados", _inside(container, site, "ps -ef | grep -Ei 'automation-helper|automation.*helper|agent-receiver|xinetd' | grep -v grep || true")),
            ("PGREP de processos relacionados", _inside(container, site, "pgrep -af 'automation-helper|automation.*helper|agent-receiver|xinetd' || true")),
            ("Log do automation-helper", _inside(container, site, "tail -n 150 ~/var/log/automation-helper.log 2>/dev/null || true")),
        ],
        "docker_health": [
            ("Estado e health do container", f"docker inspect {shlex.quote(container)} --format 'Status={{{{.State.Status}}}} Health={{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{else}}}}none{{{{end}}}} StartedAt={{{{.State.StartedAt}}}} RestartCount={{{{.RestartCount}}}} OOMKilled={{{{.State.OOMKilled}}}}'"),
            ("Detalhes do healthcheck", f"docker inspect {shlex.quote(container)} --format '{{{{json .State.Health}}}}'"),
            ("Logs recentes do container", f"docker logs --tail 150 {shlex.quote(container)} 2>&1"),
            ("Estado global do site OMD", f"docker exec {shlex.quote(container)} omd status {shlex.quote(site)}"),
        ],
        "omd": [
            ("Estado global do site OMD", f"docker exec {shlex.quote(container)} omd status {shlex.quote(site)}"),
            ("Processos do site", _inside(container, site, "ps -ef --forest | head -n 160")),
            ("Logs principais do site", _inside(container, site, "tail -n 100 ~/var/log/automation-helper.log ~/var/log/agent-receiver/error.log ~/var/log/web.log 2>/dev/null || true")),
        ],
        "agent": [
            ("Coleta bruta do agente", _inside(container, site, f"cmk -d {qhost} | head -n 160")),
            ("Diagnóstico verbose do host", _inside(container, site, f"cmk -vvn {qhost}")),
        ],
        "filesystem": [
            ("Uso de blocos", _inside(container, site, "df -hTP")),
            ("Uso de inodes", _inside(container, site, "df -iP")),
            ("Montagens", _inside(container, site, "findmnt -rno TARGET,SOURCE,FSTYPE,OPTIONS")),
        ],
        "network": [
            ("Endereços e rotas do container", f"docker exec {shlex.quote(container)} sh -c 'ip -br address; echo ---; ip route'"),
            ("Resolução explícita do hostname", f"docker exec {shlex.quote(container)} getent hosts {qhost}"),
            ("Teste de porta do agente", f"docker exec {shlex.quote(container)} sh -c 'timeout 10 bash -c \"</dev/tcp/{qhost}/6556\"; echo RC:$?'"),
        ],
        "memory": [
            ("Memória do site/container", f"docker exec {shlex.quote(container)} sh -c 'free -h; echo ---; cat /proc/meminfo | head -n 25'"),
        ],
        "cpu": [
            ("Carga e CPU do container", f"docker exec {shlex.quote(container)} sh -c 'uptime; nproc; ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%cpu | head -n 20'"),
        ],
        "generic": [],
    }
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for title, command in catalog.get(category, []) + common:
        if command not in seen:
            result.append((title, command))
            seen.add(command)
    return result


def collect_targeted_diagnostics(
    executor: SSHExecutor,
    services: list[dict[str, Any]],
    container: str | None,
    site: str | None,
    hostname: str,
) -> list[dict[str, Any]]:
    if not container or not site:
        return []

    output: list[dict[str, Any]] = []
    for service in services:
        if str(service.get("state") or "").upper() not in PROBLEM_STATES:
            continue
        checks = []
        for title, command in commands_for_service(service, container, site, hostname):
            checks.append({"title": title, "result": _run(executor, command)})
        output.append(
            {
                "service": service.get("service"),
                "state": service.get("state"),
                "output": service.get("output"),
                "category": classify_service(str(service.get("service") or "")),
                "checks": checks,
            }
        )
    return output


def build_targeted_plan(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "service": item.get("service"),
            "state": item.get("state"),
            "category": classify_service(str(item.get("service") or "")),
            "purpose": "coleta direcionada somente leitura antes de qualquer conclusão ou ação",
        }
        for item in services
        if str(item.get("state") or "").upper() in PROBLEM_STATES
    ]
