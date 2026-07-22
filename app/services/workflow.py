from __future__ import annotations

import re
import shlex
from dataclasses import asdict
from typing import Any

from app.core.policies import EnvironmentType, classify_command, evaluate_action
from app.services.ai import analyze_with_gemini
from app.services.discovery import _clean, discover_host
from app.services.persistence import recurrence_history, save_incident, upsert_host, upsert_mapping
from app.services.ssh import SSHExecutor


def _run(executor: SSHExecutor, command: str, environment: EnvironmentType, sudo: bool = False) -> dict[str, Any]:
    try:
        result = executor.run_sudo(command, environment) if sudo else executor.run(command, environment)
        return {"command": command, "exit_code": result.exit_code, "stdout": _clean(result.stdout),
                "stderr": _clean(result.stderr), "sudo": sudo}
    except Exception as exc:
        return {"command": command, "exit_code": 255, "stdout": "", "stderr": str(exc), "sudo": sudo}


def _run_with_sudo_fallback(executor: SSHExecutor, command: str, environment: EnvironmentType) -> dict[str, Any]:
    result = _run(executor, command, environment)
    combined = (result["stderr"] + result["stdout"]).lower()
    denied = result["exit_code"] != 0 or any(x in combined for x in (
        "permission denied", "got permission denied", "access denied", "not permitted"
    ))
    return _run(executor, command, environment, sudo=True) if denied else result


def collect_affected_host(executor: SSHExecutor, environment: EnvironmentType) -> dict[str, Any]:
    info = discover_host(executor, environment)
    return {
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


def discover_monitor(executor: SSHExecutor, environment: EnvironmentType) -> dict[str, Any]:
    containers_result = _run_with_sudo_fallback(
        executor, "docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' | grep -Ei 'checkmk|check-mk' || true", environment)
    containers: list[dict[str, str]] = []
    for line in containers_result["stdout"].splitlines():
        parts = line.split("|", 3)
        if len(parts) >= 3:
            containers.append({"name": parts[0], "image": parts[1], "status": parts[2], "ports": parts[3] if len(parts) > 3 else ""})

    data: dict[str, Any] = {
        "docker": _run_with_sudo_fallback(executor, "docker info --format '{{json .ServerVersion}}' 2>/dev/null || docker info 2>&1 | head -n 30", environment),
        "containers_raw": containers_result, "containers": containers, "container_details": [],
    }
    for container in containers:
        qname = shlex.quote(container["name"])
        data["container_details"].append({
            "container": container,
            "inspect": _run_with_sudo_fallback(executor, f"docker inspect {qname} --format 'StartedAt={{{{.State.StartedAt}}}} RestartCount={{{{.RestartCount}}}} OOMKilled={{{{.State.OOMKilled}}}} ExitCode={{{{.State.ExitCode}}}}'", environment),
            "sites": _run_with_sudo_fallback(executor, f"docker exec {qname} omd sites 2>&1 || true", environment),
            "events": _run_with_sudo_fallback(executor, f"docker events --since 24h --until 0s --filter container={qname} 2>/dev/null | tail -n 100 || true", environment),
            "logs": _run_with_sudo_fallback(executor, f"docker logs --since 24h --tail 150 {qname} 2>&1 || true", environment),
        })
    return data


def _parse_sites(text: str) -> list[str]:
    sites: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("SITE") or stripped.startswith("-"):
            continue
        first = stripped.split()[0]
        if re.fullmatch(r"[A-Za-z0-9_-]+", first):
            sites.append(first)
    return sites


def inspect_checkmk_host(executor: SSHExecutor, environment: EnvironmentType, monitor_data: dict[str, Any], hostname: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for detail in monitor_data.get("container_details", []):
        container = detail["container"]["name"]
        qcontainer = shlex.quote(container)
        for site in _parse_sites(detail["sites"]["stdout"]):
            qsite = shlex.quote(site)
            cmk_d_inner = f"cmk -D {shlex.quote(hostname)}"
            cmk_d = _run_with_sudo_fallback(executor, f"docker exec {qcontainer} su - {qsite} -c {shlex.quote(cmk_d_inner)} 2>&1", environment)
            found = cmk_d["exit_code"] == 0 and bool(cmk_d["stdout"].strip()) and "not found" not in cmk_d["stdout"].lower()
            item: dict[str, Any] = {
                "container": container, "site": site,
                "omd_status": _run_with_sudo_fallback(executor, f"docker exec {qcontainer} omd status {qsite} 2>&1 || true", environment),
                "cmk_D": cmk_d, "found": found,
            }
            if found:
                qhost = shlex.quote(hostname)
                item["cmk_vvn"] = _run_with_sudo_fallback(executor, f"docker exec {qcontainer} su - {qsite} -c {shlex.quote(f'cmk -vvn {qhost}')} 2>&1", environment)
                item["agent_fetch"] = _run_with_sudo_fallback(executor, f"docker exec {qcontainer} su - {qsite} -c {shlex.quote(f'cmk -d {qhost} | head -n 120')} 2>&1", environment)
                item["nagios_logs"] = _run_with_sudo_fallback(executor, f"docker exec {qcontainer} su - {qsite} -c {shlex.quote(f\"grep -F ';{hostname};' ~/var/log/nagios.log 2>/dev/null | tail -n 120\")} 2>&1 || true", environment)
                item["site_logs"] = _run_with_sudo_fallback(executor, f"docker exec {qcontainer} su - {qsite} -c {shlex.quote('tail -n 80 ~/var/log/automation-helper.log ~/var/log/agent-receiver/error.log ~/var/log/web.log 2>/dev/null')} 2>&1 || true", environment)
            findings.append(item)
    return {"hostname": hostname, "findings": findings}


def _service_summary(checkmk_data: dict[str, Any]) -> tuple[str, str, str | None, str]:
    for item in checkmk_data.get("findings", []):
        if item.get("found"):
            output = item.get("cmk_vvn", {}).get("stdout", "")
            state = "OK" if item.get("cmk_vvn", {}).get("exit_code") == 0 else "CRIT"
            return "Checkmk active check", state, item.get("site"), output[-8000:]
    return "Host discovery", "UNKNOWN", None, "Host não localizado em nenhum site OMD descoberto."


SAFE_REMEDIATION_PATTERNS = [
    re.compile(r"^systemctl\s+(start|restart|reload|enable)\s+[A-Za-z0-9_.@:-]+$"),
    re.compile(r"^service\s+[A-Za-z0-9_.@:-]+\s+(start|restart|reload)$"),
    re.compile(r"^docker\s+(start|restart)\s+[A-Za-z0-9_.-]+$"),
    re.compile(r"^docker\s+exec\s+[A-Za-z0-9_.-]+\s+omd\s+(start|restart)\s+[A-Za-z0-9_-]+$"),
]


def _execute_remediations(analysis: dict[str, Any], affected: SSHExecutor, monitor: SSHExecutor,
                          environment: EnvironmentType) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in analysis.get("remediation") or []:
        command = str(item.get("command") or "").strip()
        target = str(item.get("target") or "affected").lower()
        if not command:
            continue
        action_type = classify_command(command)
        decision = evaluate_action(action_type, environment)
        safe_shape = any(pattern.fullmatch(command) for pattern in SAFE_REMEDIATION_PATTERNS)
        if not decision.allowed or decision.requires_approval or not safe_shape:
            results.append({"description": item.get("description", ""), "command": command, "target": target,
                            "status": "blocked", "reason": decision.reason if not decision.allowed else "Comando fora da lista segura."})
            continue
        executor = monitor if target == "monitor" else affected
        result = _run_with_sudo_fallback(executor, command, EnvironmentType.MONITORING if target == "monitor" else environment)
        results.append({"description": item.get("description", ""), "command": command, "target": target,
                        "status": "executed" if result["exit_code"] == 0 else "failed",
                        "exit_code": result["exit_code"], "output": (result["stdout"] or result["stderr"])[-1500:]})
    return results


def run_full_diagnosis(*, affected: SSHExecutor, monitor: SSHExecutor, affected_ip: str,
                       affected_port: int, monitor_ip: str, monitor_port: int,
                       host_type: str, environment: EnvironmentType, same_server: bool) -> dict[str, Any]:
    affected_data = collect_affected_host(affected, environment)
    hostname = affected_data["identity"]["hostname"]
    monitor_identity = discover_host(monitor, EnvironmentType.MONITORING)
    monitor_data = discover_monitor(monitor, EnvironmentType.MONITORING)
    checkmk_data = inspect_checkmk_host(monitor, EnvironmentType.MONITORING, monitor_data, hostname)

    affected_row = upsert_host(host_type=host_type, vpn_ip=affected_ip, ssh_port=affected_port, hostname=hostname,
                               os_name=affected_data["identity"]["os_name"], environment=environment.value,
                               internal_ips=affected_data["identity"]["ip_brief"].splitlines())
    monitor_row = affected_row if same_server else upsert_host(
        host_type="monitoring", vpn_ip=monitor_ip, ssh_port=monitor_port, hostname=monitor_identity.hostname,
        os_name=monitor_identity.os_name, environment=EnvironmentType.MONITORING.value,
        internal_ips=monitor_identity.ip_brief.splitlines())

    service_name, state, site_name, normalized_output = _service_summary(checkmk_data)
    found_item = next((x for x in checkmk_data["findings"] if x.get("found")), None)
    container_name = found_item.get("container") if found_item else None
    image = monitor_data["containers"][0]["image"] if monitor_data.get("containers") else None
    upsert_mapping(affected_host_id=affected_row.id, monitoring_host_id=monitor_row.id, same_server=same_server,
                   container_name=container_name, site_name=site_name, checkmk_hostname=hostname, checkmk_version=image)

    history = recurrence_history(checkmk_host=hostname, service_name=service_name)
    evidence = {
        "affected_host": affected_data, "monitor": monitor_data, "checkmk": checkmk_data, "history": history,
        "security_policy": {
            "allowed_environments": ["production", "standby", "monitoring"],
            "host_reboot": "always_denied", "customer_database_access": "always_denied",
            "safe_adjustments": "authorized", "delete_remove_stop": "specific_approval_required",
        },
    }
    analysis = analyze_with_gemini(evidence)
    actions = _execute_remediations(analysis, affected, monitor, environment)

    validation: dict[str, Any] = {}
    if any(x["status"] == "executed" for x in actions):
        validation["affected_host"] = collect_affected_host(affected, environment)
        refreshed_monitor = discover_monitor(monitor, EnvironmentType.MONITORING)
        validation["checkmk"] = inspect_checkmk_host(monitor, EnvironmentType.MONITORING, refreshed_monitor, hostname)
        _, validated_state, _, validated_output = _service_summary(validation["checkmk"])
    else:
        validated_state, validated_output = state, normalized_output

    evidence["remediation_actions"] = actions
    evidence["post_validation"] = validation
    incident_id = save_incident(
        affected_host_id=affected_row.id, site_name=site_name, checkmk_host=hostname, service_name=service_name,
        state=validated_state, normalized_output=validated_output, evidence=evidence, analysis=analysis)
    return {
        "incident_id": incident_id, "hostname": hostname, "service": service_name, "state": state,
        "validated_state": validated_state, "container": container_name, "site": site_name,
        "recurrences": len(history), "analysis": analysis, "actions": actions, "evidence": evidence,
    }
