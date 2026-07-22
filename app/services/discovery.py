from __future__ import annotations

from dataclasses import dataclass

from app.core.policies import EnvironmentType
from app.services.ssh import SSHExecutor


@dataclass
class HostDiscovery:
    hostname: str
    os_name: str
    ip_brief: str
    checkmk_agent_units: str


def discover_host(executor: SSHExecutor, environment: EnvironmentType) -> HostDiscovery:
    hostname = executor.run("hostname -f 2>/dev/null || hostname", environment).stdout.strip()
    os_name = executor.run(". /etc/os-release 2>/dev/null; echo \"${PRETTY_NAME:-unknown}\"", environment).stdout.strip()
    ip_brief = executor.run("ip -br a 2>/dev/null || ifconfig -a", environment).stdout.strip()
    units = executor.run(
        "systemctl list-unit-files 2>/dev/null | grep -E 'check-mk-agent|check_mk|xinetd|cmk-agent' || true",
        environment,
    ).stdout.strip()
    return HostDiscovery(hostname, os_name, ip_brief, units)


def discover_checkmk_on_monitor(executor: SSHExecutor, environment: EnvironmentType) -> dict:
    containers = executor.run(
        "docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null | grep -Ei 'checkmk|check-mk' || true",
        environment,
    ).stdout.strip()
    return {"containers": containers}
