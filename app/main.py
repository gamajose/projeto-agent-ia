from __future__ import annotations

import hmac
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.db.base import ensure_database_schema
from app.services.approved_execution import execute_approved_investigation
from app.services.jobs import enqueue_investigation, get_job
from app.services.persistence import get_investigation, operational_metrics
from app.services.replay import replay_investigation
from app.services.runner import run_target
from app.services.secrets import get_secret, secret_backend_status


app = FastAPI(title="Agent IA Infra", version="1.2.2")


class CheckmkWebhookPayload(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    service: str = Field(min_length=1, max_length=255)
    state: str = Field(min_length=1, max_length=30)
    output: str = Field(default="", max_length=12000)
    site: str | None = Field(default=None, max_length=255)
    environment: EnvironmentType = EnvironmentType.UNKNOWN
    auto_correct: bool = False
    ssh_port: int | None = Field(default=None, ge=1, le=65535)


class ReplayPayload(BaseModel):
    provider: str | None = None


class ApprovalPayload(BaseModel):
    token: str = Field(min_length=20)
    requested_by: str | None = Field(default=None, max_length=255)


def _require_token(supplied: str | None, expected: str | None, name: str) -> None:
    if not expected:
        raise HTTPException(status_code=503, detail=f"{name} não configurado")
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="token inválido")


def _admin_token() -> str | None:
    settings = get_settings()
    return get_secret("AGENT_API_TOKEN", settings.agent_api_token, settings=settings)


@app.get("/health")
def health() -> dict[str, Any]:
    settings = get_settings()
    return {
        "status": "ok",
        "version": app.version,
        "default_mode": settings.agent_default_mode,
        "execution_mode": settings.agent_execution_mode,
        "worker_pool": settings.agent_worker_name,
        "strict_host_key_checking": settings.ssh_strict_host_key_checking,
        "review_required_for_corrections": settings.ai_reviewer_required_for_corrections,
        "secret_backend": secret_backend_status(settings),
    }


@app.post("/webhooks/checkmk")
def checkmk_webhook(
    payload: CheckmkWebhookPayload,
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
) -> dict[str, Any]:
    settings = get_settings()
    webhook_token = get_secret("CHECKMK_WEBHOOK_TOKEN", settings.checkmk_webhook_token, settings=settings)
    _require_token(x_agent_token, webhook_token, "CHECKMK_WEBHOOK_TOKEN")
    ensure_database_schema()
    mode = "correct" if payload.auto_correct and settings.checkmk_webhook_auto_correct else "propose"
    objective = (
        f"Alerta Checkmk no serviço '{payload.service}', estado {payload.state}. "
        f"Site: {payload.site or 'não informado'}. Saída do alerta: {payload.output}"
    )
    if settings.agent_execution_mode.strip().casefold() == "queue":
        try:
            return enqueue_investigation(
                payload.host,
                objective,
                environment=payload.environment,
                mode=mode,
                approve=False,
                ssh_port=payload.ssh_port,
                metadata={"source": "checkmk", "site": payload.site, "service": payload.service, "state": payload.state},
                settings=settings,
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"fila indisponível: {type(exc).__name__}: {exc}") from exc

    try:
        result = run_target(
            payload.host,
            objective,
            environment=payload.environment,
            mode=mode,
            approve=mode == "correct",
            ssh_port=payload.ssh_port,
            settings=settings,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"{type(exc).__name__}: {exc}") from exc
    analysis = result.get("analysis") or {}
    return {
        "investigation_id": result.get("investigation_id"),
        "host": result.get("hostname"),
        "mode": mode,
        "environment": result.get("environment_classification"),
        "playbook": result.get("playbook"),
        "status": analysis.get("status"),
        "confidence": analysis.get("confidence"),
        "probable_cause": analysis.get("probable_cause"),
        "conclusion": analysis.get("conclusion"),
        "ticket_report": analysis.get("ticket_report"),
        "proposed_actions": analysis.get("proposed_actions") or [],
        "review": result.get("review"),
        "corrections": result.get("corrections") or [],
        "approval_token": result.get("approval_token"),
    }


@app.get("/api/jobs/{job_id}")
def job_detail(
    job_id: str,
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
) -> dict[str, Any]:
    _require_token(x_agent_token, _admin_token(), "AGENT_API_TOKEN")
    try:
        result = get_job(job_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"fila indisponível: {type(exc).__name__}: {exc}") from exc
    if not result:
        raise HTTPException(status_code=404, detail="job não encontrado ou expirado")
    return result


@app.get("/api/investigations/{investigation_id}")
def investigation_detail(
    investigation_id: str,
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
) -> dict[str, Any]:
    _require_token(x_agent_token, _admin_token(), "AGENT_API_TOKEN")
    ensure_database_schema()
    result = get_investigation(investigation_id, include_evidence=True)
    if not result:
        raise HTTPException(status_code=404, detail="investigação não encontrada")
    return result


@app.post("/api/investigations/{investigation_id}/replay")
def investigation_replay(
    investigation_id: str,
    payload: ReplayPayload,
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
) -> dict[str, Any]:
    settings = get_settings()
    _require_token(x_agent_token, _admin_token(), "AGENT_API_TOKEN")
    ensure_database_schema()
    try:
        return replay_investigation(investigation_id, provider_name=payload.provider, settings=settings)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"{type(exc).__name__}: {exc}") from exc


@app.post("/api/investigations/{investigation_id}/approve")
def investigation_approve(
    investigation_id: str,
    payload: ApprovalPayload,
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
) -> dict[str, Any]:
    settings = get_settings()
    _require_token(x_agent_token, _admin_token(), "AGENT_API_TOKEN")
    ensure_database_schema()
    try:
        return execute_approved_investigation(
            investigation_id,
            payload.token,
            requested_by=payload.requested_by,
            settings=settings,
        )
    except Exception as exc:
        raise HTTPException(status_code=409, detail=f"{type(exc).__name__}: {exc}") from exc


@app.get("/api/metrics")
def metrics_json(
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
) -> dict[str, Any]:
    _require_token(x_agent_token, _admin_token(), "AGENT_API_TOKEN")
    ensure_database_schema()
    return operational_metrics()


@app.get("/metrics", response_class=PlainTextResponse)
def metrics_prometheus(
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
) -> str:
    _require_token(x_agent_token, _admin_token(), "AGENT_API_TOKEN")
    ensure_database_schema()
    metrics = operational_metrics()
    lines = [
        "# HELP agent_investigations_total Total de investigações persistidas.",
        "# TYPE agent_investigations_total gauge",
        f"agent_investigations_total {metrics['investigations_total']}",
        "# HELP agent_investigation_duration_ms_average Duração média das investigações.",
        "# TYPE agent_investigation_duration_ms_average gauge",
        f"agent_investigation_duration_ms_average {metrics['average_duration_ms']}",
    ]
    for status, count in metrics.get("by_status", {}).items():
        lines.append(f'agent_investigations_by_status{{status="{status}"}} {count}')
    for mode, count in metrics.get("by_mode", {}).items():
        lines.append(f'agent_investigations_by_mode{{mode="{mode}"}} {count}')
    for status, count in metrics.get("approval_executions", {}).items():
        lines.append(f'agent_approval_executions{{status="{status}"}} {count}')
    return "\n".join(lines) + "\n"
