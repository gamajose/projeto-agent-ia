from __future__ import annotations

import ipaddress
from typing import Any

from app.core.policies import EnvironmentType, environment_allows_correction
from app.core.settings import Settings, get_settings
from app.services.approvals import token_digest, verify_approval_token
from app.services.persistence import (
    complete_approval_execution,
    create_approval_execution,
    get_investigation,
    resolve_saved_target,
)
from app.services.ssh import SSHExecutor
from app.services.tool_registry import execute_tool


class ApprovedExecutionError(RuntimeError):
    pass


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _executor(settings: Settings, host: str, port: int) -> SSHExecutor:
    return SSHExecutor(
        host,
        port,
        settings.ssh_default_user,
        settings.ssh_default_password,
        settings.ssh_connect_timeout,
        private_key_path=settings.ssh_private_key_path,
        private_key_passphrase=settings.ssh_private_key_passphrase,
        allow_agent=settings.ssh_allow_agent,
        look_for_keys=settings.ssh_look_for_keys,
        strict_host_key_checking=settings.ssh_strict_host_key_checking,
        known_hosts_path=settings.ssh_known_hosts_path,
        bastion_host=settings.ssh_bastion_host,
        bastion_port=settings.ssh_bastion_port,
        bastion_user=settings.ssh_bastion_user,
        bastion_password=settings.ssh_bastion_password,
        bastion_private_key_path=settings.ssh_bastion_private_key_path,
        bastion_private_key_passphrase=settings.ssh_bastion_private_key_passphrase,
    )


def execute_approved_investigation(
    investigation_id: str,
    token: str,
    *,
    requested_by: str | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    investigation = get_investigation(investigation_id, include_evidence=True)
    if not investigation:
        raise ApprovedExecutionError("investigação não encontrada")

    analysis = investigation.get("analysis") or {}
    actions = [item for item in analysis.get("proposed_actions") or [] if item.get("status") == "proposed"]
    payload = verify_approval_token(token, actions, settings=settings)
    if payload.get("investigation_id") != investigation_id:
        raise ApprovedExecutionError("o token pertence a outra investigação")
    if not (analysis.get("review") or {}).get("approved"):
        raise ApprovedExecutionError("a segunda IA não aprovou as ações")

    environment = EnvironmentType(investigation.get("environment") or EnvironmentType.UNKNOWN.value)
    if not environment_allows_correction(environment):
        raise ApprovedExecutionError(f"ambiente {environment.value} não permite correção automática")

    target = str(investigation.get("target") or "")
    saved = resolve_saved_target(target, environment.value)
    if saved:
        host, port = str(saved["vpn_ip"]), int(saved["ssh_port"])
    elif _is_ip(target):
        host, port = target, settings.ssh_default_port
    else:
        raise ApprovedExecutionError("alvo não está mais disponível no inventário")

    execution_id = create_approval_execution(
        investigation_id=investigation_id,
        token_digest=token_digest(token),
        requested_by=requested_by,
        actions=actions,
    )
    executor = _executor(settings, host, port)
    results: list[dict[str, Any]] = []
    try:
        executor.connect()
        for item in actions:
            results.append(
                {
                    **item,
                    **execute_tool(
                        executor,
                        environment,
                        str(item.get("tool")),
                        dict(item.get("arguments") or {}),
                        approved=True,
                    ),
                }
            )
        status = "validated" if results and all(item.get("status") == "validated" for item in results) else "failed"
        complete_approval_execution(execution_id, status=status, results=results)
        return {
            "execution_id": execution_id,
            "investigation_id": investigation_id,
            "target": target,
            "environment": environment.value,
            "status": status,
            "results": results,
        }
    except Exception:
        complete_approval_execution(execution_id, status="failed", results=results)
        raise
    finally:
        executor.close()
