from __future__ import annotations

import re
import shlex
from dataclasses import asdict
from typing import Any

from app.core.policies import EnvironmentType
from app.services.ai import analyze_with_gemini
from app.services.discovery import _clean, discover_host
from app.services.ssh import SSHExecutor


def _result(command: str, exit_code: int, stdout: str, stderr: str, sudo: bool) -> dict[str, Any]:
    return {
        "command": command,
        "exit_code": exit_code,
        "stdout": _clean(stdout),
        "stderr": _clean(stderr),
        "sudo": sudo,
    }


def run_command(
    executor: SSHExecutor,
    command: str,
    environment: EnvironmentType,
    *,
    sudo: bool = False,
    approved: bool = False,
    timeout: int = 90,
) -> dict[str, Any]:
    try:
        execution = (
            executor.run_sudo(command, environment, approved=approved, timeout=timeout)
            if sudo
            else executor.run(command, environment, approved=approved, timeout=timeout)
        )
        return _result(command, execution.exit_code, execution.stdout, execution.stderr, sudo)
    except Exception as exc:
        return _result(command, 255, "", str(exc), sudo)


def run_with_sudo_fallback(
    executor: SSHExecutor,
    command: str,
    environment: EnvironmentType,
    *,
    approved: bool = False,
    timeout: int = 90,
) -> dict[str, Any]:
    normal = run_command(executor, command, environment, approved=approved, timeout=timeout)
    combined = f"{normal['stdout']}\n{normal['stderr']}".casefold()
    permission_tokens = (
        "permission denied",
        "access denied",
        "operation not permitted",
        "not permitted",
        "a senha é necessária",
        "a password is required",
        "sufficient permissions",
        "failed to set supplementary group",
    )
    if normal["exit_code"] != 0 or any(token in combined for token in permission_tokens):
        elevated = run_command(
            executor,
            command,
            environment,
            sudo=True,
            approved=approved,
            timeout=timeout,
        )
        if elevated["exit_code"] == 0 or any(token in combined for token in permission_tokens):
            return elevated
    return normal


def _parse_sites(text: str) -> list[str]:
    sites: list[str] = []
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("SITE") or value.startswith("-"):
            continue
        candidate = value.split()[0]
        if re.fullmatch(r"[A-Za-z0-9_-]+", candidate):
            sites.append(candidate)
    return sites


def _parse_hosts(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("[")]


def _candidate_names(target: str, context: str, identity: dict[str, Any]) -> list[str]:
    values = [
        target,
        str(identity.get("hostname") or ""),
        str(identity.get("fqdn") or ""),
    ]
    values.extend(re.findall(r"\b[A-Za-z0-9][A-Za-z0-9_.-]{2,}\b", context))
    result: list[str] = []
    for value in values:
        value = value.strip()
        if value and value not in result:
            result.append(value)
        short = value.split(".", 1)[0]
        if short and short not in result:
            result.append(short)
    return result


def _best_host_match(available: list[str], candidates: list[str]) -> str | None:
    by_lower = {host.casefold(): host for host in available}
    for candidate in candidates:
        if candidate.casefold() in by_lower:
            return by_lower[candidate.casefold()]
    for candidate in candidates:
        needle = candidate.casefold()
        if len(needle) < 3:
            continue
        matches = [host for host in available if needle in host.casefold() or host.casefold() in needle]
        if len(matches) == 1:
            return matches[0]
    return None


def _stopped_services(status_text: str) -> list[str]:
    stopped: list[str] = []
    for line in status_text.splitlines():
        match = re.match(r"\s*([A-Za-z0-9_.-]+):\s+stopped\b", line, re.IGNORECASE)
        if match:
            stopped.append(match.group(1))
    return stopped


def run_adaptive_diagnosis(
    *,
    executor: SSHExecutor,
    target: str,
    context: str,
    environment: EnvironmentType,
    read_only: bool = False,
) -> dict[str, Any]:
    identity = asdict(discover_host(executor, environment))
    candidates = _candidate_names(target, context, identity)

    affected = {
        "identity": identity,
        "agent_units": run_with_sudo_fallback(
            executor,
            "systemctl --no-pager -l status check-mk-agent.socket check_mk.socket xinetd 2>&1 || true",
            environment,
        ),
        "agent_controller": run_with_sudo_fallback(
            executor,
            "cmk-agent-ctl status 2>&1 || true",
            environment,
        ),
        "port_6556": run_with_sudo_fallback(
            executor,
            "ss -lntp 2>/dev/null | grep -E '(:|\\])6556\\b' || true",
            environment,
        ),
        "resources": run_command(executor, "uptime; free -h; df -hT", environment),
    }

    containers_raw = run_with_sudo_fallback(
        executor,
        "docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' | grep -Ei 'checkmk|check-mk' || true",
        EnvironmentType.MONITORING,
    )
    containers: list[dict[str, str]] = []
    for line in containers_raw["stdout"].splitlines():
        parts = line.split("|", 3)
        if len(parts) >= 3:
            containers.append({
                "name": parts[0],
                "image": parts[1],
                "status": parts[2],
                "ports": parts[3] if len(parts) > 3 else "",
            })

    findings: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []

    for container in containers:
        qcontainer = shlex.quote(container["name"])
        sites_result = run_with_sudo_fallback(
            executor,
            f"docker exec {qcontainer} omd sites 2>&1 || true",
            EnvironmentType.MONITORING,
        )
        for site in _parse_sites(sites_result["stdout"]):
            qsite = shlex.quote(site)
            status = run_with_sudo_fallback(
                executor,
                f"docker exec {qcontainer} omd status {qsite} 2>&1 || true",
                EnvironmentType.MONITORING,
            )
            host_list = run_with_sudo_fallback(
                executor,
                f"docker exec {qcontainer} su - {qsite} -c 'cmk --list-hosts' 2>&1 || true",
                EnvironmentType.MONITORING,
            )
            available_hosts = _parse_hosts(host_list["stdout"])
            matched_host = _best_host_match(available_hosts, candidates)
            item: dict[str, Any] = {
                "container": container["name"],
                "site": site,
                "omd_status": status,
                "host_list": host_list,
                "available_host_count": len(available_hosts),
                "resolved_checkmk_host": matched_host,
                "found": bool(matched_host),
            }

            stopped = _stopped_services(status["stdout"])
            item["stopped_services"] = stopped
            item["service_diagnostics"] = {}
            for service in stopped:
                qservice = shlex.quote(service)
                item["service_diagnostics"][service] = {
                    "log": run_with_sudo_fallback(
                        executor,
                        f"docker exec {qcontainer} su - {qsite} -c 'tail -n 150 ~/var/log/{qservice}.log 2>/dev/null || true'",
                        EnvironmentType.MONITORING,
                    ),
                    "process": run_with_sudo_fallback(
                        executor,
                        f"docker exec {qcontainer} su - {qsite} -c 'ps -ef | grep -F {qservice} | grep -v grep || true'",
                        EnvironmentType.MONITORING,
                    ),
                }

            if matched_host:
                qhost = shlex.quote(matched_host)
                item["cmk_D"] = run_with_sudo_fallback(
                    executor,
                    f"docker exec {qcontainer} su - {qsite} -c {shlex.quote(f'cmk -D {qhost}')} 2>&1",
                    EnvironmentType.MONITORING,
                )
                item["cmk_vvn"] = run_with_sudo_fallback(
                    executor,
                    f"docker exec {qcontainer} su - {qsite} -c {shlex.quote(f'cmk -vvn {qhost}')} 2>&1 || true",
                    EnvironmentType.MONITORING,
                )

            findings.append(item)

    monitor = {
        "containers_raw": containers_raw,
        "containers": containers,
    }
    evidence: dict[str, Any] = {
        "user_context": context,
        "target_reference": target,
        "candidate_names": candidates,
        "affected_host": affected,
        "monitor": monitor,
        "checkmk": {"hostname": identity.get("hostname"), "findings": findings},
        "security_policy": {
            "host_reboot": "always_denied",
            "container_lifecycle": "always_denied",
            "safe_omd_service_start": "authorized_with_validation",
        },
    }

    initial_analysis = analyze_with_gemini(evidence)

    if not read_only:
        for finding in findings:
            container = finding["container"]
            site = finding["site"]
            for service in finding.get("stopped_services") or []:
                if service not in {"automation-helper", "rrdcached", "agent-receiver", "mkeventd", "redis", "npcd", "ui-job-scheduler", "nagios", "apache", "xinetd", "crontab"}:
                    continue
                command = f"docker exec {container} su - {site} -c 'omd start {service}'"
                validation_command = f"docker exec {container} su - {site} -c 'omd status {service}'"
                execution = run_with_sudo_fallback(
                    executor,
                    command,
                    EnvironmentType.MONITORING,
                    approved=True,
                )
                validation = run_with_sudo_fallback(
                    executor,
                    validation_command,
                    EnvironmentType.MONITORING,
                )
                actions.append({
                    "description": f"Iniciar o serviço OMD {service} no site {site}",
                    "target": "monitor",
                    "command": command,
                    "status": "validated" if validation["exit_code"] == 0 and "stopped" not in validation["stdout"].casefold() else "validation_failed",
                    "exit_code": execution["exit_code"],
                    "output": execution["stdout"] or execution["stderr"],
                    "validation": validation,
                })

    post_findings: list[dict[str, Any]] = []
    if actions:
        for finding in findings:
            container = finding["container"]
            site = finding["site"]
            post_status = run_with_sudo_fallback(
                executor,
                f"docker exec {shlex.quote(container)} omd status {shlex.quote(site)} 2>&1 || true",
                EnvironmentType.MONITORING,
            )
            post_findings.append({
                "container": container,
                "site": site,
                "omd_status": post_status,
                "stopped_services": _stopped_services(post_status["stdout"]),
            })

    evidence["remediation_actions"] = actions
    evidence["post_validation"] = {"findings": post_findings}
    final_analysis = analyze_with_gemini(evidence) if actions else initial_analysis

    return {
        "hostname": identity.get("hostname") or target,
        "target": target,
        "context": context,
        "containers": containers,
        "findings": findings,
        "actions": actions,
        "analysis": final_analysis,
        "evidence": evidence,
    }
