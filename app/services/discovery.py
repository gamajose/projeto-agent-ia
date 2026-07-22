from __future__ import annotations

from dataclasses import dataclass
import re

from app.core.policies import EnvironmentType
from app.services.ssh import SSHExecutor

ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


@dataclass
class HostDiscovery:
    hostname: str
    os_name: str
    ip_brief: str
    checkmk_agent_units: str


def _clean(text: str) -> str:
    return ANSI_RE.sub("", text).strip()


def discover_host(executor: SSHExecutor, environment: EnvironmentType) -> HostDiscovery:
    hostname = _clean(executor.run("hostname -f 2>/dev/null || hostname", environment).stdout)
    os_name = _clean(executor.run(". /etc/os-release 2>/dev/null; echo \"${PRETTY_NAME:-unknown}\"", environment).stdout)
    ip_brief = _clean(executor.run("ip -br a 2>/dev/null || ifconfig -a", environment).stdout)
    units = _clean(
        executor.run(
            "systemctl list-unit-files 2>/dev/null | grep -E 'check-mk-agent|check_mk|xinetd|cmk-agent' || true",
            environment,
        ).stdout
    )
    return HostDiscovery(hostname, os_name, ip_brief, units)


def discover_checkmk_on_monitor(executor: SSHExecutor, environment: EnvironmentType) -> dict:
    command = "docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null | grep -Ei 'checkmk|check-mk' || true"

    result = executor.run(command, environment)
    containers = _clean(result.stdout)

    if not containers:
        sudo_result = executor.run_sudo(command, environment)
        sudo_containers = _clean(sudo_result.stdout)
        if sudo_containers:
            result = sudo_result
            containers = sudo_containers

    return {
        "containers": containers,
        "stderr": _clean(result.stderr),
        "exit_code": result.exit_code,
    }
