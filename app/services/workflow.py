from __future__ import annotations

import re
import shlex
from dataclasses import asdict
from typing import Any

from app.core.policies import EnvironmentType
from app.services.ai import analyze_with_gemini
from app.services.discovery import _clean, discover_host
from app.services.persistence import recurrence_history, save_incident, upsert_host, upsert_mapping
from app.services.ssh import SSHExecutor


def _run(executor: SSHExecutor, command: str, environment: EnvironmentType, sudo: bool = False) -> dict[str, Any]:
    try:
        result = executor.run_sudo(command, environment) if sudo else executor.run(command, environment)
        return {
            "command": command,
            "exit_code": result.exit_code,
            "stdout": _clean(result.stdout),
            "stderr": _clean(result.stderr),
            "sudo": sudo,
        }
    except Exception as exc:
        return {"command": command, "exit_code": 255, "stdout": "", "stderr": str(exc), "sudo": sudo}


def _run_with_sudo_fallback(executor: SSHExecutor, command: str, environment: EnvironmentType) -> dict[str, Any]:
    result = _run(executor, command, environment)
    permission_error = result["exit_code"] != 0 or any(
        marker in (result["stderr"] + result["stdout"]).lower()
        for marker in ["permission denied", "got permission denied", "access denied", "not permitted"]
    )
    return _run(executor, command, environment, sudo=True) if permission_error else result


def collect_affected_host(executor: SSHExecutor, environment: EnvironmentType) -> dict[str, Any]:
    info = discover_host(executor, environment)
    checks = {
        "identity": asdict(info),
        "agent_units": _run(executor, "systemctl --no-pager -l status check-mk-agent.socket check_mk.socket xinetd 2>&1 || true", environment),
        "agent_controller": _run(executor, "cmk-agent-ctl status 2>&1 || true", environment),
        "port_6556": _run_with_sudo_fallback(executor, "ss -lntp 2>/dev/null | grep -E '(:|\\])6556\\b' || true", environment),
        "agent_local_output": _run(executor, "timeout 15 sh -c 'cat < /dev/null > /dev/tcp/127.0.0.1/6556' 2>&1; echo RC:$?", environment),
        "agent_sample": _run(executor, "timeout 15 sh -c 'exec 3<>/dev/tcp/127.0.0.1/6556; head -n 30 <&3' 2>&1 || true", environment),
        "firewall": _run_with_sudo_fallback(executor, "(firewall-cmd --list-all 2>/dev/null || nft list ruleset 2>/dev/null || iptables -S 2>/dev/null) | grep -E '6556|check.?mk' || true", environment),
        "routes": _run(executor, "ip -br address; echo '---'; ip route", environment),
        "resources": _run(executor, "uptime; free -h; df -hT / /var 2>/dev/null || df -hT", environment),
        "recent_agent_logs": _run_with_sudo_fallback(executor, "journalctl --no-pager -n 120 -u check-mk-agent.socket -u check_mk.socket -u xinetd 2>/dev/null || true", environment),
        "privileges": _run(executor, "sudo -n -l 2>&1 || true", environment),
    }
    return checks


def discover_monitor(executor: SSHExecutor, environment: EnvironmentType) -> dict[str, Any]:
    containers_result = _run_with_sudo_fallback(
        executor,
        "docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' | grep -Ei 'checkmk|check-mk' || true",
        environment,
    )
    containers = []
    for line in containers_result["stdout"].splitlines():
        parts = line.split("|", 3)
        if len(parts) >= 3:
            containers.append({"name": parts[0], "image": parts[1], "status": parts[2], "ports": parts[3] if len(parts) > 3 else ""})

    result: dict[str, Any] = {
        "docker": _run_with_sudo_fallback(executor, "docker info --format '{{json .ServerVersion}}' 2>/dev/null || docker info 2>&1 | head -n 30", environment),
        "containers_raw": containers_result,
        "containers": containers,
        "container_details": [],
    }
    for container in containers:
        name = container["name"]
        qname = shlex.quote(name)
        detail = {
            "container": container,
            "inspect": _run_with_sudo_fallback(executor, f"docker inspect {qname} --format 'StartedAt={{{{.State.StartedAt}}}} RestartCount={{{{.RestartCount}}}} OOMKilled={{{{.State.OOMKilled}}}} ExitCode={{{{.State.ExitCode}}}} Health={{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{end}}}}'", environment),
            "sites": _run_with_sudo_fallback(executor, f"docker exec {qname} omd sites 2>&1 || true", environment),
            "events": _run_with_sudo_fallback(executor, f"docker events --since 24h --until 0s --filter container={qname} 2>/dev/null | tail -n 100 || true", environment),
            "logs": _run_with_sudo_fallback(executor, f"docker logs --since 24h --tail 150 {qname} 2>&1 || true", environment),
        }
        result["container_details"].append(detail)
    return result


def _parse_sites(text: str) -> list[str]:
    sites: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("SITE") or line.startswith("-"):
            continue
        first = line.split()[0]
        if re.fullmatch(r"[A-Za-z0-9_-]+", first):
            sites.append(first)
    return sites


def inspect_checkmk_host(executor: SSHExecutor, environment: EnvironmentType, monitor_data: dict[str, Any], hostname: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    qhost = shlex.quote(hostname)
    for detail in monitor_data.get("container_details", []):
        container = detail["container"]["name"]
        qcontainer = shlex.quote(container)
        for site in _parse_sites(detail["sites"]["stdout"]):
            qsite = shlex.quote(site)
            prefix = f"docker exec {qcontainer} su - {qsite} -c"
            cmk_d = _run_with_sudo_fallback(executor, f"{prefix} {shlex.quote(f'cmk -D {qhost}')} 2>&1", environment)
            found = cmk_d["exit_code"] == 0 and bool(cmk_d["stdout"].strip()) and "not found" not in cmk_d["stdout"].lower()
            item = {
                "container": container,
                "site": site,
                "omd_status": _run_with_sudo_fallback(executor, f"docker exec {qcontainer} omd status {qsite} 2>&1 || true", environment),
                "cmk_D": cmk_d,
                "found": found,
            }
            if found:
                item["cmk_vvn"] = _run_with_sudo_fallback(executor, f"{prefix} {shlex.quote(f'cmk -vvn {qhost}')} 2>&1", environment)
                item["agent_fetch"] = _run_with_sudo_fallback(executor, f"{prefix} {shlex.quote(f'cmk -d {qhost} | head -n 120')} 2>&1", environment)
                item["nagios_logs"] = _run_with_sudo_fallback(executor, f"docker exec {qcontainer} su - {qsite} -c {shlex.quote(f\"grep -F ';{hostname};' ~/var/log/nagios.log 2>/dev/null | tail -n 120\")} 2>&1 || true", environment)
                item["site_logs"] = _run_with_sudo_fallback(executor, f"docker exec {qcontainer} su - {qsite} -c {shlex.quote(\"tail -n 80 ~/var/log/automation-helper.log ~/var/log/agent-receiver/error.log ~/var/log/web.log 2>/dev/null\")} 2>&1 || true", environment)
            findings.append(item)
    return {"hostname": hostname, "findings": findings}


def _service_summary(checkmk_data: dict[str, Any]) -> tuple[str, str, str | None, str | None]:
    for item in checkmk_data.get("findings", []):
        if item.get("found"):
            output = item.get("cmk_vvn", {}).get("stdout", "")
            state = "OK" if item.get("cmk_vvn", {}).get("exit_code") == 0 else "CRIT"
            return "Checkmk active check", state, item.get("site"), output[-8000:]
    return "Host discovery", "UNKNOWN", None, "Host não localizado em nenhum site OMD descoberto."


def run_full_diagnosis(*, affected: SSHExecutor, monitor: SSHExecutor, affected_ip: str,
                       affected_port: int, monitor_ip: str, monitor_port: int,
                       host_type: str, environment: EnvironmentType, same_server: bool) -> dict[str, Any]:
    affected_data = collect_affected_host(affected, environment)
    hostname = affected_data["identity"]["hostname"]
    monitor_identity = discover_host(monitor, EnvironmentType.MONITORING)
    monitor_data = discover_monitor(monitor, EnvironmentType.MONITORING)
    checkmk_data = inspect_checkmk_host(monitor, EnvironmentType.MONITORING, monitor_data, hostname)

    affected_row = upsert_host(
        host_type=host_type,
        vpn_ip=affected_ip,
        ssh_port=affected_port,
        hostname=hostname,
        os_name=affected_data["identity"]["os_name"],
        environment=environment.value,
        internal_ips=affected_data["identity"]["ip_brief"].splitlines(),
    )
    monitor_row = affected_row if same_server else upsert_host(
        host_type="monitoring",
        vpn_ip=monitor_ip,
        ssh_port=monitor_port,
        hostname=monitor_identity.hostname,
        os_name=monitor_identity.os_name,
        environment=EnvironmentType.MONITORING.value,
        internal_ips=monitor_identity.ip_brief.splitlines(),
    )

    service_name, state, site_name, normalized_output = _service_summary(checkmk_data)
    found_item = next((x for x in checkmk_data["findings"] if x.get("found")), None)
    container_name = found_item.get("container") if found_item else None
    upsert_mapping(
        affected_host_id=affected_row.id,
        monitoring_host_id=monitor_row.id,
        same_server=same_server,
        container_name=container_name,
        site_name=site_name,
        checkmk_hostname=hostname,
        checkmk_version=(next(iter(monitor_data.get("containers", [])), {}).get("image") if monitor_data.get("containers") else None),
    )

    history = recurrence_history(checkmk_host=hostname, service_name=service_name)
    evidence = {
        "affected_host": affected_data,
        "monitor": monitor_data,
        "checkmk": checkmk_data,
        "history": history,
        "security_policy": {
            "allowed_environments": ["production", "standby", "monitoring"],
            "host_reboot": "always_denied",
            "customer_database_access": "always_denied",
            "impact_actions": "explicit_approval_required",
        },
    }
    analysis = analyze_with_gemini(evidence)
    incident_id = save_incident(
        affected_host_id=affected_row.id,
        site_name=site_name,
        checkmk_host=hostname,
        service_name=service_name,
        state=state,
        normalized_output=normalized_output or "",
        evidence=evidence,
        analysis=analysis,
    )
    return {
        "incident_id": incident_id,
        "hostname": hostname,
        "service": service_name,
        "state": state,
        "container": container_name,
        "site": site_name,
        "recurrences": len(history),
        "analysis": analysis,
        "evidence": evidence,
    }
