from __future__ import annotations

from typing import Any

from app.core.policies import EnvironmentType, environment_allows_correction
from app.core.settings import Settings, get_settings
from app.services.approvals import token_digest, verify_approval_token
from app.services.persistence import (
    complete_approval_execution,
    create_approval_execution,
    get_investigation,
)
from app.services.runner import build_executor, resolve_target
from app.services.tool_registry import execute_tool


class ApprovedExecutionError(RuntimeError):
    pass


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

    target_reference = str(investigation.get("target") or "")
    approved_ssh_port = payload.get("ssh_port")
    try:
        target = resolve_target(
            target_reference,
            environment,
            int(approved_ssh_port) if approved_ssh_port is not None else None,
            settings=settings,
        )
    except LookupError as exc:
        raise ApprovedExecutionError("alvo não está mais disponível no inventário") from exc

    execution_id = create_approval_execution(
        investigation_id=investigation_id,
        token_digest=token_digest(token),
        requested_by=requested_by,
        actions=actions,
    )
    executor = build_executor(target, settings=settings)
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
            "target": target_reference,
            "environment": environment.value,
            "status": status,
            "results": results,
        }
    except Exception:
        complete_approval_execution(execution_id, status="failed", results=results)
        raise
    finally:
        executor.close()
