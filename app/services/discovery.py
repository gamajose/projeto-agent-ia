from __future__ import annotations

from dataclasses import dataclass
import re
import shlex

from app.core.policies import EnvironmentType
from app.services.ssh import CommandResult, SSHExecutor

ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


@dataclass
class HostDiscovery:
    hostname: str
    os_name: str
    ip_brief: str
    checkmk_agent_units: str


def _clean(text: str) -> str:
    return ANSI_RE.sub("", text).replace("\r", "").strip()


def _run_with_sudo_fallback(
    executor: SSHExecutor,
    command: str,
    environment: EnvironmentType,
) -> CommandResult:
    result = executor.run(command, environment)
    if result.exit_code != 0 or not _clean(result.stdout):
        sudo_result = executor.run_sudo(command, environment)
        if sudo_result.exit_code == 0 or _clean(sudo_result.stdout):
            return sudo_result
    return result


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


def validate_affected_host(executor: SSHExecutor, environment: EnvironmentType) -> dict[str, str]:
    service_status = _clean(
        executor.run(
            "for u in check-mk-agent.socket check_mk.socket xinetd.socket xinetd.service; do "
            "systemctl is-active \"$u\" 2>/dev/null && echo \"$u=active\"; done; true",
            environment,
        ).stdout
    )
    listener = _clean(
        executor.run(
            "ss -lntp 2>/dev/null | grep -E '(:|\\])6556[[:space:]]' || "
            "netstat -lntp 2>/dev/null | grep ':6556 ' || true",
            environment,
        ).stdout
    )
    agent_output = _clean(
        executor.run(
            "timeout 12 sh -c 'exec 3<>/dev/tcp/127.0.0.1/6556; head -n 8 <&3' 2>/dev/null || true",
            environment,
            timeout=20,
        ).stdout
    )
    sudo_access = _clean(
        executor.run("sudo -n true >/dev/null 2>&1 && echo sem_senha || echo requer_senha", environment).stdout
    )
    firewall = _clean(
        executor.run(
            "(firewall-cmd --state 2>/dev/null && firewall-cmd --list-ports 2>/dev/null) || "
            "(iptables -S 2>/dev/null | grep -E '6556|INPUT' | head -n 20) || true",
            environment,
        ).stdout
    )
    return {
        "service_status": service_status,
        "listener": listener,
        "agent_output": agent_output,
        "sudo_access": sudo_access,
        "firewall": firewall,
    }


def discover_checkmk_on_monitor(
    executor: SSHExecutor,
    environment: EnvironmentType,
    affected_hostname: str,
) -> dict:
    container_command = (
        "docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null "
        "| grep -Ei 'checkmk|check-mk' || true"
    )
    result = _run_with_sudo_fallback(executor, container_command, environment)
    containers = _clean(result.stdout)

    details: list[dict[str, str]] = []
    short_hostname = affected_hostname.split(".", 1)[0]

    for line in containers.splitlines():
        if not line.strip():
            continue
        container = line.split("|", 1)[0].strip()
        sites_cmd = (
            f"docker exec {shlex.quote(container)} bash -lc "
            + shlex.quote("omd sites --bare 2>/dev/null || ls -1 /omd/sites 2>/dev/null")
        )
        sites_result = _run_with_sudo_fallback(executor, sites_cmd, environment)
        sites = [s.strip() for s in _clean(sites_result.stdout).splitlines() if s.strip() and " " not in s.strip()]

        for site in sites:
            host_checks: list[str] = []
            for candidate in dict.fromkeys([affected_hostname, short_hostname]):
                cmk_inner = f"su - {shlex.quote(site)} -c {shlex.quote(f'cmk -D {candidate}')}"
                cmk_cmd = f"docker exec {shlex.quote(container)} bash -lc {shlex.quote(cmk_inner)}"
                cmk_result = _run_with_sudo_fallback(executor, cmk_cmd, environment)
                output = _clean(cmk_result.stdout)
                if cmk_result.exit_code == 0 and output:
                    host_checks.append(f"Host localizado como {candidate}\n{output}")
                    break

            status_inner = f"su - {shlex.quote(site)} -c {shlex.quote('omd status')}"
            status_cmd = f"docker exec {shlex.quote(container)} bash -lc {shlex.quote(status_inner)}"
            status_result = _run_with_sudo_fallback(executor, status_cmd, environment)

            details.append(
                {
                    "container": container,
                    "site": site,
                    "omd_status": _clean(status_result.stdout),
                    "host_check": "\n".join(host_checks) if host_checks else "Host não localizado neste site.",
                }
            )

    return {
        "containers": containers,
        "details": details,
        "stderr": _clean(result.stderr),
        "exit_code": result.exit_code,
    }
